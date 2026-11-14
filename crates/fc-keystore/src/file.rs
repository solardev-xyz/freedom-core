//! The profile's secrets file, `identity/secrets.json` (0013, "The secrets
//! file"): every secret of the profile, each AES-256-GCM under one of at
//! most two wrapping keys, one per policy, with the key-store items the
//! profile still names.
//!
//! ```json
//! {
//!   "version": 1,
//!   "keys": {
//!     "unattended": {
//!       "backend": "macos-keychain",
//!       "item": "<32 hex>",
//!       "sealed": null,
//!       "pending": null
//!     }
//!   },
//!   "forget": [
//!     { "backend": "macos-keychain", "policy": "user_presence", "item": "<32 hex>" }
//!   ],
//!   "entries": {
//!     "<name>": {
//!       "key": "unattended",
//!       "nonce": "<base64, 12 bytes>",
//!       "ciphertext": "<base64>",
//!       "binding": { "<member>": "<text>" }
//!     }
//!   }
//! }
//! ```
//!
//! - **The text** is `JSON.stringify(file, null, 2)` (as the catalog and the
//!   forget file are written), with no newline after it. The members come
//!   in the order above: `keys` by policy (`unattended`, then
//!   `user_presence`), `forget` in the order its records were added,
//!   `entries` by name, each binding by member name. A text other than the
//!   one the core writes for its contents is malformed
//!   ([`Malformed::NotCanonical`]): one file, one text.
//! - **A key** (`keys.<policy>`) is the committed item, if any (`item`,
//!   with DPAPI's blob as `sealed`; `null` for every other backend), and the
//!   item being made, if any (`pending`: `{ backend, item }`, written before
//!   `create` runs). A key with neither isn't written. A key with only a
//!   pending item has that item's backend. A committed key has at least one
//!   entry under it.
//! - **The `forget` list** holds the items the profile no longer uses until
//!   a `forget` of each succeeds. DPAPI keeps no item, so it has no record
//!   there: dropping its blob is the whole `forget`.
//! - **The items it names**, keys, pending items and the `forget` list
//!   together, are at most [`MAX_ITEMS`], each id once (0013, "The bounds").
//! - **An entry** is AES-256-GCM under its key's wrapping key, with a
//!   12-byte nonce and the 16-byte tag after the ciphertext. Its associated
//!   data ([`associated_data`]) is the label `freedom-secrets/1`, a zero
//!   byte, the entry's name, a zero byte, and its binding's canonical JSON,
//!   so an entry moved to another name or binding, or under another key,
//!   doesn't open. No two entries under one key share a nonce.
//!
//! Every change is a function from one file to the next, which the caller
//! writes in one atomic write (0001); a refused change leaves nothing to
//! write. None adds an item except [`SecretsFile::begin_create`], which is
//! refused with [`Refused::ForgetBacklog`] where it would name a fifth.

use std::collections::BTreeMap;
use std::fmt;

use aes_gcm::aead::{AeadInOut as _, KeyInit as _, Nonce};
use aes_gcm::{Aes256Gcm, Tag};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use fc_json::JsValue;
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::keystore::{Backend, Blob, ItemId, Policy, Sealed, WrapKey};

/// The file's `version`.
pub const VERSION: u32 = 1;
/// The most key-store items a file names: keys in use, pending items and
/// the `forget` list together (0013, "The bounds").
pub const MAX_ITEMS: usize = 4;
/// The most entries a file holds.
pub const MAX_ENTRIES: usize = 32;
/// The longest entry name, in bytes.
pub const MAX_NAME_BYTES: usize = 64;
/// The longest secret, in bytes.
pub const MAX_SECRET_BYTES: usize = 1024;
/// The most members a binding has.
pub const MAX_BINDING_MEMBERS: usize = 4;
/// The longest binding member name, in bytes.
pub const MAX_BINDING_NAME_BYTES: usize = 32;
/// The longest binding value, in bytes.
pub const MAX_BINDING_VALUE_BYTES: usize = 128;
/// The most bytes a file's text takes. The bounds above keep the largest
/// file the core writes under it (about 95 KiB).
pub const MAX_FILE_BYTES: usize = 128 * 1024;
/// An entry's nonce, in bytes.
pub const NONCE_BYTES: usize = 12;
/// An entry's tag, in bytes, after its ciphertext.
pub const TAG_BYTES: usize = 16;
/// The label that starts every entry's associated data.
pub const AAD_LABEL: &str = "freedom-secrets/1";
/// How many nonces a seal draws before it gives up on the RNG.
const NONCE_DRAWS: usize = 4;

// ---------------------------------------------------------------------------
// Names, bindings, secrets

/// An entry's name: a lowercase ASCII letter, then lowercase letters,
/// digits, `.`, `_` or `-`, at most [`MAX_NAME_BYTES`] in all.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryName(String);

impl EntryName {
    pub fn new(name: &str) -> Option<EntryName> {
        let bytes = name.as_bytes();
        let ok = (1..=MAX_NAME_BYTES).contains(&bytes.len())
            && bytes[0].is_ascii_lowercase()
            && bytes.iter().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            });
        ok.then(|| EntryName(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What an entry is bound to (the vault file's digest, for quick unlock):
/// at most [`MAX_BINDING_MEMBERS`] members, each named by a lowercase ASCII
/// letter then lowercase letters, digits or `_` (at most
/// [`MAX_BINDING_NAME_BYTES`]), with a value of 1 to
/// [`MAX_BINDING_VALUE_BYTES`] printable ASCII characters. Kept in order of
/// member name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Binding(Vec<(String, String)>);

impl Binding {
    /// The binding with no member.
    pub fn empty() -> Binding {
        Binding(Vec::new())
    }

    /// The binding with these members: `None` if one is out of form, or
    /// named twice, or there are too many.
    pub fn new<'a>(members: impl IntoIterator<Item = (&'a str, &'a str)>) -> Option<Binding> {
        let mut out: Vec<(String, String)> = Vec::new();
        for (name, value) in members {
            if out.len() == MAX_BINDING_MEMBERS || !binding_name(name) || !binding_value(value) {
                return None;
            }
            out.push((name.to_owned(), value.to_owned()));
        }
        out.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        if out.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return None;
        }
        Some(Binding(out))
    }

    /// A member's value.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The members, in order of name.
    pub fn members(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }

    fn value(&self) -> JsValue {
        let mut out = JsValue::Object(Vec::new());
        for (name, value) in &self.0 {
            out.set(name.as_str(), JsValue::string(value.as_str()));
        }
        out
    }

    /// Its canonical JSON: `JSON.stringify` of the members in order of
    /// name, with no space. Values are printable ASCII, so only `"` and `\`
    /// are escaped, each with a backslash.
    pub fn canonical(&self) -> String {
        self.value().stringify()
    }
}

fn binding_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=MAX_BINDING_NAME_BYTES).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

fn binding_value(value: &str) -> bool {
    (1..=MAX_BINDING_VALUE_BYTES).contains(&value.len())
        && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// An opened secret. Wiped on drop; no `Debug`, `Display`, `Serialize` or
/// `Clone` (AGENTS rule 3).
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// A secret to write: its name, its binding, and its bytes (1 to
/// [`MAX_SECRET_BYTES`]).
pub struct Put<'a> {
    pub name: EntryName,
    pub binding: Binding,
    pub secret: &'a [u8],
}

/// The associated data an entry is sealed with: the label
/// [`AAD_LABEL`], a zero byte, the name, a zero byte, and the binding's
/// canonical JSON. Neither the label nor a name holds a zero byte, so the
/// three parts never run together.
pub fn associated_data(name: &EntryName, binding: &Binding) -> Vec<u8> {
    let canonical = binding.canonical();
    let mut out = Vec::with_capacity(AAD_LABEL.len() + name.0.len() + canonical.len() + 2);
    out.extend_from_slice(AAD_LABEL.as_bytes());
    out.push(0);
    out.extend_from_slice(name.0.as_bytes());
    out.push(0);
    out.extend_from_slice(canonical.as_bytes());
    out
}

/// The cipher under `key`, read in place: no copy of the key is left on the
/// stack, and the expanded key is wiped on drop (`zeroize`).
fn cipher(key: &WrapKey) -> Aes256Gcm {
    Aes256Gcm::new(key.expose().into())
}

fn seal(
    key: &WrapKey,
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>, Refused> {
    let cipher = cipher(key);
    let mut buffer = Zeroizing::new(secret.to_vec());
    let tag = cipher
        .encrypt_inout_detached(
            &Nonce::<Aes256Gcm>::from(*nonce),
            aad,
            buffer.as_mut_slice().into(),
        )
        .map_err(|_| Refused::SecretSize)?;
    // The buffer holds ciphertext now: nothing secret is left in it.
    let mut out = buffer.to_vec();
    out.extend_from_slice(&tag);
    Ok(out)
}

fn open_raw(
    key: &WrapKey,
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    sealed: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let split = sealed.len().checked_sub(TAG_BYTES)?;
    let (ciphertext, tag) = sealed.split_at(split);
    let tag = Tag::try_from(tag).ok()?;
    let cipher = cipher(key);
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_inout_detached(
            &Nonce::<Aes256Gcm>::from(*nonce),
            aad,
            buffer.as_mut_slice().into(),
            &tag,
        )
        .ok()?;
    Some(buffer)
}

// ---------------------------------------------------------------------------
// The file

/// An item being made: written before `create` runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pending {
    backend: Backend,
    item: ItemId,
}

/// A key: its committed item, if any, and the item being made, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Key {
    backend: Backend,
    item: Option<ItemId>,
    blob: Option<Blob>,
    pending: Option<Pending>,
}

/// An item the profile no longer uses, kept until its `forget` succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Forget {
    pub(crate) backend: Backend,
    pub(crate) policy: Policy,
    pub(crate) item: ItemId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) key: Policy,
    pub(crate) nonce: [u8; NONCE_BYTES],
    /// The ciphertext with its tag after it.
    pub(crate) sealed: Vec<u8>,
    pub(crate) binding: Binding,
}

/// An item the file names, as a profile delete records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedItem {
    pub backend: Backend,
    pub policy: Policy,
    pub item: ItemId,
}

/// The secrets file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretsFile {
    keys: [Option<Key>; 2],
    pub(crate) forget: Vec<Forget>,
    pub(crate) entries: BTreeMap<EntryName, Entry>,
}

/// Why a file's text isn't accepted. Nothing it names is acted on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Malformed {
    #[error("the secrets file is over {MAX_FILE_BYTES} bytes")]
    TooLarge,
    #[error("the secrets file isn't JSON")]
    Json,
    #[error("the secrets file isn't version {VERSION}")]
    Version,
    #[error("a member of the secrets file is out of form")]
    Form,
    #[error("the secrets file names more than {MAX_ITEMS} items")]
    Items,
    #[error("the secrets file holds more than {MAX_ENTRIES} entries")]
    Entries,
    #[error("an item or a nonce appears twice in the secrets file")]
    Duplicate,
    #[error("an entry is under a key the secrets file doesn't hold")]
    KeyNotInUse,
    #[error("a key of the secrets file has no entry under it")]
    KeyUnused,
    #[error("the secrets file isn't in the text the core writes")]
    NotCanonical,
}

impl Malformed {
    /// The reason's name, as the vectors give it.
    pub fn code(&self) -> &'static str {
        match self {
            Malformed::TooLarge => "too_large",
            Malformed::Json => "json",
            Malformed::Version => "version",
            Malformed::Form => "form",
            Malformed::Items => "items",
            Malformed::Entries => "entries",
            Malformed::Duplicate => "duplicate",
            Malformed::KeyNotInUse => "key_not_in_use",
            Malformed::KeyUnused => "key_unused",
            Malformed::NotCanonical => "not_canonical",
        }
    }
}

/// Why a change is refused. The file is left as it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// A `create` would name a fifth item: the `forget` list is tried
    /// again first, and the secret takes its `Unavailable` path if that
    /// leaves no room (`key_store_unavailable`, `reason: "forget_backlog"`).
    #[error("the secrets file has no room for another item")]
    ForgetBacklog,
    /// The item's id is already named in the file.
    #[error("the item is already named in the secrets file")]
    Named,
    /// A commit for an item that isn't its policy's pending one.
    #[error("the item isn't pending under its policy")]
    NotPending,
    /// A secret under a policy with no committed key.
    #[error("no key is in use under that policy")]
    NoKey,
    /// A name held under the other policy's key.
    #[error("the entry is under the other key")]
    OtherKey,
    /// No such entry; or a first key committed with no entry to put.
    #[error("no such entry")]
    NoEntry,
    #[error("the secrets file holds {MAX_ENTRIES} entries already")]
    Entries,
    #[error("a secret is 1 to {MAX_SECRET_BYTES} bytes")]
    SecretSize,
    /// A replace whose entries need the old key, given none.
    #[error("the old key is needed to re-wrap its entries")]
    KeyNeeded,
    /// An entry didn't open under the old key during a re-wrap.
    #[error("an entry didn't open under the old key")]
    EntryRefused,
    #[error("the random number generator failed")]
    Randomness,
}

impl Refused {
    /// The refusal's name, as the vectors give it.
    pub fn code(&self) -> &'static str {
        match self {
            Refused::ForgetBacklog => "forget_backlog",
            Refused::Named => "named",
            Refused::NotPending => "not_pending",
            Refused::NoKey => "no_key",
            Refused::OtherKey => "other_key",
            Refused::NoEntry => "no_entry",
            Refused::Entries => "entries",
            Refused::SecretSize => "secret_size",
            Refused::KeyNeeded => "key_needed",
            Refused::EntryRefused => "entry_refused",
            Refused::Randomness => "randomness",
        }
    }
}

/// Why an entry doesn't open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    #[error("no such entry")]
    NoEntry,
    /// The entry is bound to something else (for quick unlock, another
    /// vault): nothing is decrypted.
    #[error("the entry is bound to something else")]
    OtherBinding,
    /// The entry doesn't open under this key with this name and binding:
    /// moved, changed, or under another key.
    #[error("the entry doesn't open")]
    Refused,
}

impl OpenError {
    /// The error's name, as the vectors give it.
    pub fn code(&self) -> &'static str {
        match self {
            OpenError::NoEntry => "no_entry",
            OpenError::OtherBinding => "other_binding",
            OpenError::Refused => "refused",
        }
    }
}

impl SecretsFile {
    /// A file with nothing in it.
    pub fn new() -> SecretsFile {
        SecretsFile::default()
    }

    // ----- Reading

    /// The committed key under `policy`, as `open` takes it.
    pub fn key(&self, policy: Policy) -> Option<Sealed> {
        let key = self.keys[policy.index()].as_ref()?;
        Some(Sealed::from_parts(
            key.backend,
            policy,
            key.item?,
            key.blob.clone(),
        ))
    }

    /// The item being made under `policy`.
    pub fn pending(&self, policy: Policy) -> Option<(Backend, ItemId)> {
        let pending = self.keys[policy.index()].as_ref()?.pending?;
        Some((pending.backend, pending.item))
    }

    /// The `forget` list, in order, as `forget` takes each.
    pub fn forget_list(&self) -> Vec<Sealed> {
        self.forget
            .iter()
            .map(|f| Sealed::from_parts(f.backend, f.policy, f.item, None))
            .collect()
    }

    /// Every item the file names, in its order: each key's committed item
    /// then its pending one, by policy, then the `forget` list.
    pub fn items(&self) -> Vec<NamedItem> {
        let mut out = Vec::new();
        for policy in Policy::ALL {
            let Some(key) = &self.keys[policy.index()] else {
                continue;
            };
            if let Some(item) = key.item {
                out.push(NamedItem {
                    backend: key.backend,
                    policy,
                    item,
                });
            }
            if let Some(pending) = key.pending {
                out.push(NamedItem {
                    backend: pending.backend,
                    policy,
                    item: pending.item,
                });
            }
        }
        out.extend(self.forget.iter().map(|f| NamedItem {
            backend: f.backend,
            policy: f.policy,
            item: f.item,
        }));
        out
    }

    /// How many items the file names.
    pub fn count(&self) -> usize {
        self.items().len()
    }

    fn names(&self, item: ItemId) -> bool {
        self.items().iter().any(|named| named.item == item)
    }

    /// The entries' names, in order.
    pub fn entry_names(&self) -> impl Iterator<Item = &EntryName> {
        self.entries.keys()
    }

    /// The policy whose key an entry is under.
    pub fn entry_key(&self, name: &EntryName) -> Option<Policy> {
        self.entries.get(name).map(|entry| entry.key)
    }

    /// An entry's binding.
    pub fn binding(&self, name: &EntryName) -> Option<&Binding> {
        self.entries.get(name).map(|entry| &entry.binding)
    }

    /// Whether an entry is under `policy`'s key.
    pub fn has_entries(&self, policy: Policy) -> bool {
        self.entries.values().any(|entry| entry.key == policy)
    }

    /// Opens the entry `name`, bound to `binding`, under `key`: the key of
    /// the policy [`SecretsFile::entry_key`] names. The associated data is
    /// built from the caller's name and binding, not from the file's.
    pub fn open(
        &self,
        name: &EntryName,
        binding: &Binding,
        key: &WrapKey,
    ) -> Result<Secret, OpenError> {
        let entry = self.entries.get(name).ok_or(OpenError::NoEntry)?;
        if entry.binding != *binding {
            return Err(OpenError::OtherBinding);
        }
        open_raw(
            key,
            &entry.nonce,
            &associated_data(name, binding),
            &entry.sealed,
        )
        .map(Secret)
        .ok_or(OpenError::Refused)
    }

    // ----- Changes

    /// Records `item` as `pending` under `policy`, before `create` runs.
    /// An earlier pending item of the policy, whose `create` never
    /// committed, moves into the `forget` list (dropped for DPAPI). Refused
    /// with [`Refused::ForgetBacklog`] where the file would name a fifth
    /// item.
    pub fn begin_create(
        &self,
        policy: Policy,
        backend: Backend,
        item: ItemId,
    ) -> Result<SecretsFile, Refused> {
        if self.names(item) {
            return Err(Refused::Named);
        }
        let mut next = self.clone();
        if let Some(earlier) = next.keys[policy.index()]
            .as_mut()
            .and_then(|key| key.pending.take())
        {
            next.retire(earlier.backend, policy, earlier.item);
        }
        if next.count() + 1 > MAX_ITEMS {
            return Err(Refused::ForgetBacklog);
        }
        let pending = Pending { backend, item };
        let slot = &mut next.keys[policy.index()];
        if let Some(key) = slot.as_mut() {
            if key.item.is_none() {
                key.backend = backend;
            }
            key.pending = Some(pending);
        } else {
            *slot = Some(Key {
                backend,
                item: None,
                blob: None,
                pending: Some(pending),
            });
        }
        Ok(next)
    }

    /// Makes the pending item `sealed` names its policy's key, once `create`
    /// has answered with `new_key`: every entry under the policy is opened
    /// with `old_key` and sealed again under `new_key` (in order of name),
    /// the old item moves into the `forget` list (dropped for DPAPI), and
    /// `put`, if any, is written under the new key. A first key needs a
    /// `put`: no key is committed with nothing under it.
    pub fn commit<R: TryCryptoRng + ?Sized>(
        &self,
        sealed: &Sealed,
        new_key: &WrapKey,
        old_key: Option<&WrapKey>,
        put: Option<Put<'_>>,
        rng: &mut R,
    ) -> Result<SecretsFile, Refused> {
        let policy = sealed.policy();
        let key = self.keys[policy.index()]
            .as_ref()
            .ok_or(Refused::NotPending)?;
        if key.pending
            != Some(Pending {
                backend: sealed.backend(),
                item: sealed.item(),
            })
        {
            return Err(Refused::NotPending);
        }
        if key.item.is_none() && put.is_none() {
            return Err(Refused::NoEntry);
        }
        let mut next = self.clone();
        let names: Vec<EntryName> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.key == policy)
            .map(|(name, _)| name.clone())
            .collect();
        if !names.is_empty() {
            let old_key = old_key.ok_or(Refused::KeyNeeded)?;
            for name in names {
                let Some(entry) = next.entries.get(&name) else {
                    continue;
                };
                let aad = associated_data(&name, &entry.binding);
                let secret = open_raw(old_key, &entry.nonce, &aad, &entry.sealed)
                    .ok_or(Refused::EntryRefused)?;
                let nonce = next.draw_nonce(policy, rng)?;
                let resealed = seal(new_key, &nonce, &aad, &secret)?;
                if let Some(entry) = next.entries.get_mut(&name) {
                    entry.nonce = nonce;
                    entry.sealed = resealed;
                }
            }
        }
        let old = next.keys[policy.index()].replace(Key {
            backend: sealed.backend(),
            item: Some(sealed.item()),
            blob: sealed.blob().cloned(),
            pending: None,
        });
        if let Some(Key {
            backend,
            item: Some(item),
            ..
        }) = old
        {
            next.retire(backend, policy, item);
        }
        if let Some(put) = put {
            next.put_into(policy, new_key, put, rng)?;
        }
        Ok(next)
    }

    /// Writes a secret under `policy`'s committed key, `key`: a new entry,
    /// or one of the same name under the same key replaced.
    pub fn put<R: TryCryptoRng + ?Sized>(
        &self,
        policy: Policy,
        key: &WrapKey,
        put: Put<'_>,
        rng: &mut R,
    ) -> Result<SecretsFile, Refused> {
        let mut next = self.clone();
        next.put_into(policy, key, put, rng)?;
        Ok(next)
    }

    fn put_into<R: TryCryptoRng + ?Sized>(
        &mut self,
        policy: Policy,
        key: &WrapKey,
        put: Put<'_>,
        rng: &mut R,
    ) -> Result<(), Refused> {
        if !(1..=MAX_SECRET_BYTES).contains(&put.secret.len()) {
            return Err(Refused::SecretSize);
        }
        if self.key(policy).is_none() {
            return Err(Refused::NoKey);
        }
        match self.entries.get(&put.name) {
            Some(entry) if entry.key != policy => return Err(Refused::OtherKey),
            Some(_) => {}
            None if self.entries.len() >= MAX_ENTRIES => return Err(Refused::Entries),
            None => {}
        }
        let nonce = self.draw_nonce(policy, rng)?;
        let sealed = seal(
            key,
            &nonce,
            &associated_data(&put.name, &put.binding),
            put.secret,
        )?;
        self.entries.insert(
            put.name,
            Entry {
                key: policy,
                nonce,
                sealed,
                binding: put.binding,
            },
        );
        Ok(())
    }

    /// Removes an entry. A key left with no entry under it moves into the
    /// `forget` list (dropped for DPAPI), in the same write.
    pub fn remove(&self, name: &EntryName) -> Result<SecretsFile, Refused> {
        let mut next = self.clone();
        let entry = next.entries.remove(name).ok_or(Refused::NoEntry)?;
        let policy = entry.key;
        if !next.has_entries(policy) {
            next.release(policy);
        }
        Ok(next)
    }

    /// At a profile's open: every pending item, whose `create` never
    /// committed, moves into the `forget` list (dropped for DPAPI).
    pub fn settle(&self) -> SecretsFile {
        let mut next = self.clone();
        for policy in Policy::ALL {
            let slot = &mut next.keys[policy.index()];
            let Some(pending) = slot.as_mut().and_then(|key| key.pending.take()) else {
                continue;
            };
            if slot.as_ref().is_some_and(|key| key.item.is_none()) {
                *slot = None;
            }
            next.retire(pending.backend, policy, pending.item);
        }
        next
    }

    /// Drops `item`'s `forget` record, once its `forget` answered `ok` or
    /// `not_found`. An item not in the list changes nothing.
    pub fn forgotten(&self, item: ItemId) -> SecretsFile {
        let mut next = self.clone();
        next.forget.retain(|f| f.item != item);
        next
    }

    /// Drops every `forget` record of a backend this OS doesn't have
    /// (`native`; `None` with no key store): its item isn't here (0013, "An
    /// item already gone").
    pub fn drop_foreign(&self, native: Option<Backend>) -> SecretsFile {
        let mut next = self.clone();
        next.forget.retain(|f| Some(f.backend) == native);
        next
    }

    /// Moves an item the file no longer uses into the `forget` list; a
    /// DPAPI item has no record.
    fn retire(&mut self, backend: Backend, policy: Policy, item: ItemId) {
        if backend.holds_item() {
            self.forget.push(Forget {
                backend,
                policy,
                item,
            });
        }
    }

    /// Retires `policy`'s committed item, keeping any pending one.
    fn release(&mut self, policy: Policy) {
        let slot = &mut self.keys[policy.index()];
        let Some(key) = slot.as_mut() else {
            return;
        };
        let (backend, item) = (key.backend, key.item.take());
        key.blob = None;
        match key.pending {
            Some(pending) => key.backend = pending.backend,
            None => *slot = None,
        }
        if let Some(item) = item {
            self.retire(backend, policy, item);
        }
    }

    /// A nonce no entry under `policy` holds as the file stands.
    fn draw_nonce<R: TryCryptoRng + ?Sized>(
        &self,
        policy: Policy,
        rng: &mut R,
    ) -> Result<[u8; NONCE_BYTES], Refused> {
        for _ in 0..NONCE_DRAWS {
            let mut nonce = [0u8; NONCE_BYTES];
            rng.try_fill_bytes(&mut nonce)
                .map_err(|_| Refused::Randomness)?;
            if !self
                .entries
                .values()
                .any(|entry| entry.key == policy && entry.nonce == nonce)
            {
                return Ok(nonce);
            }
        }
        Err(Refused::Randomness)
    }

    // ----- The text

    /// The file's text.
    pub fn text(&self) -> String {
        let mut keys = JsValue::Object(Vec::new());
        for policy in Policy::ALL {
            let Some(key) = &self.keys[policy.index()] else {
                continue;
            };
            let mut value = JsValue::Object(Vec::new());
            value.set("backend", JsValue::string(key.backend.name()));
            value.set("item", key.item.map_or(JsValue::Null, item_value));
            value.set(
                "sealed",
                key.blob
                    .as_ref()
                    .map_or(JsValue::Null, |blob| JsValue::string(blob.base64())),
            );
            value.set(
                "pending",
                key.pending.map_or(JsValue::Null, |pending| {
                    let mut out = JsValue::Object(Vec::new());
                    out.set("backend", JsValue::string(pending.backend.name()));
                    out.set("item", item_value(pending.item));
                    out
                }),
            );
            keys.set(policy.name(), value);
        }
        let forget = self
            .forget
            .iter()
            .map(|f| {
                let mut out = JsValue::Object(Vec::new());
                out.set("backend", JsValue::string(f.backend.name()));
                out.set("policy", JsValue::string(f.policy.name()));
                out.set("item", item_value(f.item));
                out
            })
            .collect();
        let mut entries = JsValue::Object(Vec::new());
        for (name, entry) in &self.entries {
            let mut value = JsValue::Object(Vec::new());
            value.set("key", JsValue::string(entry.key.name()));
            value.set("nonce", JsValue::string(STANDARD.encode(entry.nonce)));
            value.set(
                "ciphertext",
                JsValue::string(STANDARD.encode(&entry.sealed)),
            );
            value.set("binding", entry.binding.value());
            entries.set(name.as_str(), value);
        }
        let mut out = JsValue::Object(Vec::new());
        out.set("version", JsValue::Number(f64::from(VERSION)));
        out.set("keys", keys);
        out.set("forget", JsValue::Array(forget));
        out.set("entries", entries);
        out.stringify_pretty()
    }

    /// Reads a file's bytes: [`Malformed`] unless they are the text the core
    /// writes for a file in form and within every bound.
    pub fn parse(bytes: &[u8]) -> Result<SecretsFile, Malformed> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(Malformed::TooLarge);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Malformed::Json)?;
        let value = fc_json::parse(text).map_err(|_| Malformed::Json)?;
        if !matches!(value, JsValue::Object(_)) {
            return Err(Malformed::Form);
        }
        if !matches!(value.get("version"), Some(JsValue::Number(n)) if *n == f64::from(VERSION)) {
            return Err(Malformed::Version);
        }
        exactly(&value, &["version", "keys", "forget", "entries"])?;
        let mut file = SecretsFile::new();
        let Some(JsValue::Object(keys)) = value.get("keys") else {
            return Err(Malformed::Form);
        };
        for (name, key) in keys {
            let policy = Policy::parse(name.as_str())
                .filter(|_| name.is_well_formed())
                .ok_or(Malformed::Form)?;
            file.keys[policy.index()] = Some(key_of(key)?);
        }
        let Some(JsValue::Array(forget)) = value.get("forget") else {
            return Err(Malformed::Form);
        };
        // Past the bound, a record more can only be refused: none is read.
        if forget.len() > MAX_ITEMS {
            return Err(Malformed::Items);
        }
        file.forget = forget.iter().map(forget_of).collect::<Result<_, _>>()?;
        let Some(JsValue::Object(entries)) = value.get("entries") else {
            return Err(Malformed::Form);
        };
        if entries.len() > MAX_ENTRIES {
            return Err(Malformed::Entries);
        }
        for (name, entry) in entries {
            let name = EntryName::new(name.as_str())
                .filter(|_| name.is_well_formed())
                .ok_or(Malformed::Form)?;
            file.entries.insert(name, entry_of(entry)?);
        }
        let items = file.items();
        if items.len() > MAX_ITEMS {
            return Err(Malformed::Items);
        }
        for (index, named) in items.iter().enumerate() {
            if items[..index].iter().any(|other| other.item == named.item) {
                return Err(Malformed::Duplicate);
            }
        }
        for entry in file.entries.values() {
            if file.key(entry.key).is_none() {
                return Err(Malformed::KeyNotInUse);
            }
        }
        let nonces: Vec<_> = file.entries.values().map(|e| (e.key, e.nonce)).collect();
        for (index, nonce) in nonces.iter().enumerate() {
            if nonces[..index].contains(nonce) {
                return Err(Malformed::Duplicate);
            }
        }
        for policy in Policy::ALL {
            if file.key(policy).is_some() && !file.has_entries(policy) {
                return Err(Malformed::KeyUnused);
            }
        }
        if file.text().as_bytes() != bytes {
            return Err(Malformed::NotCanonical);
        }
        Ok(file)
    }
}

fn item_value(item: ItemId) -> JsValue {
    JsValue::string(item.hex())
}

/// An object with exactly `keys`, each once.
fn exactly(value: &JsValue, keys: &[&str]) -> Result<(), Malformed> {
    let JsValue::Object(members) = value else {
        return Err(Malformed::Form);
    };
    if members.len() != keys.len() || keys.iter().any(|key| value.get(key).is_none()) {
        return Err(Malformed::Form);
    }
    Ok(())
}

fn text(value: Option<&JsValue>) -> Result<&str, Malformed> {
    match value {
        Some(JsValue::String(s)) if s.is_well_formed() => Ok(s.as_str()),
        _ => Err(Malformed::Form),
    }
}

fn backend_of(value: Option<&JsValue>) -> Result<Backend, Malformed> {
    Backend::parse(text(value)?).ok_or(Malformed::Form)
}

fn item_of(value: Option<&JsValue>) -> Result<ItemId, Malformed> {
    ItemId::parse(text(value)?).ok_or(Malformed::Form)
}

fn key_of(value: &JsValue) -> Result<Key, Malformed> {
    exactly(value, &["backend", "item", "sealed", "pending"])?;
    let backend = backend_of(value.get("backend"))?;
    let item = match value.get("item") {
        Some(JsValue::Null) => None,
        item => Some(item_of(item)?),
    };
    // DPAPI's blob is there exactly when a DPAPI key is committed.
    let blob = match value.get("sealed") {
        Some(JsValue::Null) if !(backend.keeps_blob() && item.is_some()) => None,
        sealed if backend.keeps_blob() && item.is_some() => {
            Some(Blob::from_base64(text(sealed)?).ok_or(Malformed::Form)?)
        }
        _ => return Err(Malformed::Form),
    };
    let pending = match value.get("pending") {
        Some(JsValue::Null) => None,
        Some(pending) => {
            exactly(pending, &["backend", "item"])?;
            Some(Pending {
                backend: backend_of(pending.get("backend"))?,
                item: item_of(pending.get("item"))?,
            })
        }
        None => return Err(Malformed::Form),
    };
    match (item, pending) {
        (None, None) => return Err(Malformed::Form),
        (None, Some(pending)) if pending.backend != backend => return Err(Malformed::Form),
        _ => {}
    }
    Ok(Key {
        backend,
        item,
        blob,
        pending,
    })
}

fn forget_of(value: &JsValue) -> Result<Forget, Malformed> {
    exactly(value, &["backend", "policy", "item"])?;
    let backend = backend_of(value.get("backend"))?;
    if !backend.holds_item() {
        return Err(Malformed::Form);
    }
    Ok(Forget {
        backend,
        policy: Policy::parse(text(value.get("policy"))?).ok_or(Malformed::Form)?,
        item: item_of(value.get("item"))?,
    })
}

fn entry_of(value: &JsValue) -> Result<Entry, Malformed> {
    exactly(value, &["key", "nonce", "ciphertext", "binding"])?;
    let key = Policy::parse(text(value.get("key"))?).ok_or(Malformed::Form)?;
    let nonce: [u8; NONCE_BYTES] = decode(text(value.get("nonce"))?, NONCE_BYTES)?
        .try_into()
        .map_err(|_| Malformed::Form)?;
    let sealed = decode(text(value.get("ciphertext"))?, MAX_SECRET_BYTES + TAG_BYTES)?;
    if sealed.len() <= TAG_BYTES {
        return Err(Malformed::Form);
    }
    let Some(JsValue::Object(members)) = value.get("binding") else {
        return Err(Malformed::Form);
    };
    let mut pairs = Vec::with_capacity(members.len());
    for (name, member) in members {
        if !name.is_well_formed() {
            return Err(Malformed::Form);
        }
        pairs.push((name.as_str(), text(Some(member))?));
    }
    let binding = Binding::new(pairs).ok_or(Malformed::Form)?;
    Ok(Entry {
        key,
        nonce,
        sealed,
        binding,
    })
}

/// Standard base64, padded and canonical, of at most `max` bytes.
fn decode(text: &str, max: usize) -> Result<Vec<u8>, Malformed> {
    // A longer text can't decode within the bound: refused before decoding.
    if text.len() > max.div_ceil(3) * 4 {
        return Err(Malformed::Form);
    }
    let bytes = STANDARD.decode(text).map_err(|_| Malformed::Form)?;
    if bytes.len() > max {
        return Err(Malformed::Form);
    }
    Ok(bytes)
}
