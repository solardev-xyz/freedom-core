//! The profile's RPC API keys, once `core.hello` names `rpc_api_keys` in
//! `store_moved` (design 0013, "RPC API keys"; PRF-5h).
//!
//! - **Where a key lives:** a secrets-file entry, `rpc-api-key.<id>`, whose
//!   secret is the key, bound to `{}`, under the `Unattended` key, wherever
//!   the key store offers that policy; otherwise `rpc-api-keys.json` beside
//!   the permission files (the hello's `grant_root`), in the reference's
//!   text (`JSON.stringify(keys, null, 2)`, each key `{ apiKey, enabled:
//!   true, addedAt }`). The file also keeps, with a key store, what the
//!   secrets file can't hold: a key whose id isn't in the entry form, one
//!   past [`MAX_KEYS`], or one that isn't a string of 1 to
//!   [`MAX_SECRET_BYTES`] bytes.
//! - **The provider id** of a set is 1 to 52 bytes of lowercase letters,
//!   digits, `.`, `_` or `-` ([`entry_name`]; `rpc-key-provider-id`).
//! - **The bound:** at most [`MAX_KEYS`] entries; a set that would add one
//!   more is refused, a replace taken (`rpc-keys-bound`).
//! - **The file wins:** a provider with a key the reference counts in the
//!   file (`hasApiKey`: `apiKey` and `enabled` truthy) is answered from it.
//! - **The migration** runs once each start, before the first request that
//!   reads or writes a key ([`RpcKeys::migrate`]): every key in the file the
//!   secrets file can hold, in the file's order up to the bound, in one
//!   secrets write that replaces any entry the provider has; then the file
//!   is rewritten without them, or removed when nothing is left. A crash
//!   between the two leaves each key in both places, which the next start
//!   moves again. `rpc_api_key_status` answers the same before and after
//!   it, so it doesn't run it: it opens no key and asks the key store
//!   nothing.
//! - **A set** writes the entry first, then takes the provider out of the
//!   file; without a key store it writes the file. **A remove** takes the
//!   key from both places.
//! - **An unreadable file** (not a regular file the user owns, over 1 MiB,
//!   not JSON, or not an object) is renamed to `rpc-api-keys.json.unreadable`
//!   and logged (`rpc-keys-unreadable`); if the rename fails, nothing writes
//!   the file.
//! - **The commit** ([`Commit`]): a job claims the vault job's commit right
//!   before its first write that changes what the methods answer (the
//!   secrets write, or the file's where there is none), so a job abandoned
//!   before it (deadline, cancel, lock, shutdown) writes nothing that does.
//!   A write that changes no answer (a new key's `pending` record, an
//!   unreadable file set aside) is refused once the job is abandoned.
//! - **Durability:** the file loses a key only after the secrets write that
//!   holds it is durable. When that write's directory flush fails, the
//!   moved keys stay in the file (which wins, so the answers don't change,
//!   and the next start moves them again); a set over a key the file counts
//!   is then refused, the file's key still the one answered
//!   ([`Failure::NotDurable`]). Otherwise a set or a remove whose write
//!   isn't durable answers its result with `durable: false`.
//! - **Secret hygiene:** a key lives only in buffers sized once and wiped
//!   on drop. The file is read into one ([`fc_store::file::read_secret_file`])
//!   and indexed in place (`fc_json::index`); `JSON.parse`'s values
//!   (`JsString`, which isn't wiped) hold everything but the records'
//!   `apiKey` strings, which [`KeysFile`] keeps as UTF-16 units. Its text
//!   is counted, then written into a buffer of that size.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use fc_json::index::{Index, Kind, Value};
use fc_json::{JsString, JsValue};
use fc_keystore::{EntryName, MAX_SECRET_BYTES, Policy, SecretsFile};
use fc_store::file::{SecretRead, read_secret_file, set_aside};
use fc_store::fsx::{self, Done};
use zeroize::Zeroizing;

use crate::secrets::{self, Change, Gate, Secrets};

/// The file, at the Freedom root.
pub const FILE: &str = "rpc-api-keys.json";
/// An entry's name is this, then the provider id.
pub const PREFIX: &str = "rpc-api-key.";
/// At most this many RPC-key entries in the secrets file.
pub const MAX_KEYS: usize = 16;
/// A larger file is unreadable.
pub const MAX_FILE_BYTES: usize = 1 << 20;

/// The entry for provider `id`, when `rpc-api-key.<id>` is an entry name:
/// `id` is 1 to 52 bytes of lowercase letters, digits, `.`, `_` or `-`.
pub fn entry_name(id: &str) -> Option<EntryName> {
    if id.is_empty() {
        return None;
    }
    EntryName::new(&format!("{PREFIX}{id}"))
}

/// The provider an RPC-key entry is for.
pub fn provider_of(name: &EntryName) -> Option<&str> {
    name.as_str()
        .strip_prefix(PREFIX)
        .filter(|id| !id.is_empty())
}

/// A key the secrets file can hold: 1 to [`MAX_SECRET_BYTES`] bytes.
pub fn holdable(key: &str) -> bool {
    (1..=MAX_SECRET_BYTES).contains(&key.len())
}

/// A set's `api_key` parameter, the JSON string's own text: the key, in a
/// buffer sized once (never `serde_json`'s growing one). `None`: not a
/// string, or one with a lone surrogate.
pub fn key_param(raw: &str) -> Option<Zeroizing<String>> {
    let index = Index::new(raw).ok()?;
    let root = index.root();
    if root.kind() != Kind::String {
        return None;
    }
    let key = Key::of(root);
    key.well_formed().then(|| key.text())
}

/// A key as the file holds it: a JavaScript string's UTF-16 units, lone
/// surrogates kept as `JSON.parse` keeps them, in one buffer sized once and
/// wiped on drop. No `Debug`, no `Clone`.
struct Key(Zeroizing<Vec<u16>>);

impl Key {
    fn new(count: usize, units: impl Iterator<Item = u16>) -> Key {
        let mut buffer = Zeroizing::new(Vec::with_capacity(count));
        buffer.extend(units.take(count));
        Key(buffer)
    }

    /// An indexed string's units.
    fn of(value: Value<'_, '_>) -> Key {
        Key::new(value.units().count(), value.units())
    }

    fn of_str(text: &str) -> Key {
        Key::new(text.encode_utf16().count(), text.encode_utf16())
    }

    fn chars(&self) -> impl Iterator<Item = Result<char, u16>> + '_ {
        char::decode_utf16(self.0.iter().copied()).map(|c| c.map_err(|e| e.unpaired_surrogate()))
    }

    fn well_formed(&self) -> bool {
        self.chars().all(|c| c.is_ok())
    }

    /// `String(apiKey)` as Rust text (each lone surrogate as U+FFFD), in a
    /// buffer sized once.
    fn text(&self) -> Zeroizing<String> {
        let as_char = |c: Result<char, u16>| c.unwrap_or(char::REPLACEMENT_CHARACTER);
        let size = self.chars().map(|c| as_char(c).len_utf8()).sum();
        let mut text = Zeroizing::new(String::with_capacity(size));
        for c in self.chars() {
            text.push(as_char(c));
        }
        text
    }

    /// `JSON.stringify`'s quoting, as `JsString::quote_into` writes it.
    fn quote(&self, out: &mut dyn Out) {
        out.put("\"");
        for c in self.chars() {
            match c {
                Ok('"') => out.put("\\\""),
                Ok('\\') => out.put("\\\\"),
                Ok('\u{08}') => out.put("\\b"),
                Ok('\u{0c}') => out.put("\\f"),
                Ok('\n') => out.put("\\n"),
                Ok('\r') => out.put("\\r"),
                Ok('\t') => out.put("\\t"),
                Ok(c) if (c as u32) < 0x20 => escape(c as u16, out),
                Ok(c) => out.put(c.encode_utf8(&mut [0; 4])),
                Err(unit) => escape(unit, out),
            }
        }
        out.put("\"");
    }
}

/// `\uXXXX` in lowercase hex, as `JSON.stringify` writes it.
fn escape(unit: u16, out: &mut dyn Out) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digit = |shift: u16| char::from(HEX[usize::from((unit >> shift) & 0xf)]);
    let mut buffer = [0u8; 4];
    out.put("\\u");
    for shift in [12, 8, 4, 0] {
        out.put(digit(shift).encode_utf8(&mut buffer));
    }
}

/// Where [`KeysFile`]'s text goes: counted first, then written into a
/// buffer of exactly that size.
trait Out {
    fn put(&mut self, text: &str);
}

struct Count(usize);

impl Out for Count {
    fn put(&mut self, text: &str) {
        self.0 = self.0.saturating_add(text.len());
    }
}

impl Out for String {
    fn put(&mut self, text: &str) {
        self.push_str(text);
    }
}

/// A record's member: its `apiKey` string, or another value.
enum Field {
    Key(Key),
    Value(JsValue),
}

/// A provider's record: an object (its members), or another value.
enum Record {
    Object(Vec<(JsString, Field)>),
    Value(JsValue),
}

/// `rpc-api-keys.json` as the reference reads it: a JSON object, its
/// properties in JavaScript's order, each record's `apiKey` string kept as
/// a [`Key`]. No `Debug`, no `Clone`: compare [`KeysFile::text`].
#[derive(Default)]
pub struct KeysFile(Vec<(JsString, Record)>);

/// A key the reference counts in the file (`hasApiKey`).
pub struct Counted {
    pub id: String,
    /// `String(apiKey)`, as a URL template takes it.
    pub key: Zeroizing<String>,
    /// Whether the secrets file can hold it: a well-formed string of 1 to
    /// [`MAX_SECRET_BYTES`] bytes, under a well-formed id.
    pub holds: bool,
}

/// An array index: the canonical decimal form of an integer below 2^32 - 1
/// (`fc_json`'s rule).
fn array_index(key: &JsString) -> Option<u32> {
    let value: u32 = key.parse().ok()?;
    (value != u32::MAX && *key == value.to_string()).then_some(value)
}

/// Members as `JSON.parse` makes an object of them: a duplicate key's last
/// value at its first place, then array indices first, ascending, and the
/// other keys in their order.
fn ordered<T>(members: Vec<(JsString, T)>) -> Vec<(JsString, T)> {
    let mut props: Vec<(JsString, T)> = Vec::with_capacity(members.len());
    let mut at: BTreeMap<JsString, usize> = BTreeMap::new();
    for (key, value) in members {
        match at.get(&key).and_then(|&i| props.get_mut(i)) {
            Some(slot) => slot.1 = value,
            None => {
                at.insert(key.clone(), props.len());
                props.push((key, value));
            }
        }
    }
    props.sort_by_key(|(key, _)| array_index(key).map_or((1, 0), |i| (0, i)));
    props
}

/// `object[key] = value`, as `fc_json::JsValue::set` does it.
fn assign<T>(props: &mut Vec<(JsString, T)>, key: JsString, value: T) {
    if let Some(slot) = props.iter_mut().find(|(k, _)| *k == key) {
        slot.1 = value;
        return;
    }
    match array_index(&key) {
        Some(index) => {
            let at = props
                .iter()
                .position(|(k, _)| array_index(k).is_none_or(|other| other > index))
                .unwrap_or(props.len());
            props.insert(at, (key, value));
        }
        None => props.push((key, value)),
    }
}

fn js_string(value: Value<'_, '_>) -> JsString {
    let units: Vec<u16> = value.units().collect();
    JsString::from_units(&units)
}

/// The file's text as Node decodes its bytes (UTF-8, U+FFFD for each
/// invalid sequence), in a buffer sized once.
fn decode(bytes: &[u8]) -> Zeroizing<String> {
    let invalid = |chunk: &std::str::Utf8Chunk<'_>| !chunk.invalid().is_empty();
    let size = bytes
        .utf8_chunks()
        .map(|chunk| chunk.valid().len() + if invalid(&chunk) { 3 } else { 0 })
        .sum();
    let mut text = Zeroizing::new(String::with_capacity(size));
    for chunk in bytes.utf8_chunks() {
        text.push_str(chunk.valid());
        if invalid(&chunk) {
            text.push(char::REPLACEMENT_CHARACTER);
        }
    }
    text
}

fn quoted(text: &JsString, out: &mut dyn Out) {
    let mut quoted = String::new();
    text.quote_into(&mut quoted);
    out.put(&quoted);
}

/// `value` at `depth`, as `JSON.stringify(…, null, 2)` writes it there: its
/// own text, each line after the first indented by the depth (a newline in
/// that text is always between tokens: one in a string is escaped).
fn indented(value: &JsValue, depth: usize, out: &mut dyn Out) {
    for (i, line) in value.stringify_pretty().split('\n').enumerate() {
        if i > 0 {
            out.put("\n");
            for _ in 0..depth {
                out.put("  ");
            }
        }
        out.put(line);
    }
}

/// The record's `apiKey`, when the reference counts it (`hasApiKey`:
/// `apiKey` and `enabled` truthy) and it can be made a string.
fn counted_key(record: &Record) -> Option<&Field> {
    let Record::Object(fields) = record else {
        return None;
    };
    let get = |name: &str| fields.iter().find(|(k, _)| k == name).map(|(_, f)| f);
    let truthy = |field: &Field| match field {
        Field::Key(key) => !key.0.is_empty(),
        Field::Value(value) => value.truthy(),
    };
    let key = get("apiKey").filter(|f| truthy(f))?;
    get("enabled").filter(|f| truthy(f))?;
    match key {
        Field::Value(value) if value.js_string().is_err() => None,
        _ => Some(key),
    }
}

impl KeysFile {
    /// The file's bytes, as Node decodes them and `JSON.parse` reads them.
    /// `None`: unreadable (not JSON, or not an object).
    pub fn parse(bytes: &[u8]) -> Option<KeysFile> {
        let text = decode(bytes);
        let index = Index::new(&text).ok()?;
        let root = index.root();
        if root.kind() != Kind::Object {
            return None;
        }
        let mut members = Vec::new();
        for (id, value) in root.members() {
            let record = if value.kind() == Kind::Object {
                let mut fields = Vec::new();
                for (name, field) in value.members() {
                    let name = js_string(name);
                    let field = if name == "apiKey" && field.kind() == Kind::String {
                        Field::Key(Key::of(field))
                    } else {
                        Field::Value(fc_json::parse(field.raw()).ok()?)
                    };
                    fields.push((name, field));
                }
                Record::Object(ordered(fields))
            } else {
                Record::Value(fc_json::parse(value.raw()).ok()?)
            };
            members.push((js_string(id), record));
        }
        Some(KeysFile(ordered(members)))
    }

    /// `JSON.stringify(keys, null, 2)`, in a buffer sized once.
    pub fn text(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::with_capacity(self.text_len()));
        self.write(&mut *text);
        text
    }

    /// The length of [`KeysFile::text`].
    pub fn text_len(&self) -> usize {
        let mut count = Count(0);
        self.write(&mut count);
        count.0
    }

    fn write(&self, out: &mut dyn Out) {
        if self.0.is_empty() {
            return out.put("{}");
        }
        out.put("{\n");
        for (i, (id, record)) in self.0.iter().enumerate() {
            out.put(if i == 0 { "  " } else { ",\n  " });
            quoted(id, out);
            out.put(": ");
            match record {
                Record::Value(value) => indented(value, 1, out),
                Record::Object(fields) if fields.is_empty() => out.put("{}"),
                Record::Object(fields) => {
                    out.put("{\n");
                    for (j, (name, field)) in fields.iter().enumerate() {
                        out.put(if j == 0 { "    " } else { ",\n    " });
                        quoted(name, out);
                        out.put(": ");
                        match field {
                            Field::Key(key) => key.quote(out),
                            Field::Value(value) => indented(value, 2, out),
                        }
                    }
                    out.put("\n  }");
                }
            }
        }
        out.put("\n}");
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Each provider with a key the reference counts, in the file's order.
    /// A non-string `apiKey` (no writer's: a hand-edited file) is answered
    /// as `String(apiKey)`, never held.
    pub fn counted(&self) -> Vec<Counted> {
        self.0
            .iter()
            .filter_map(|(id, record)| {
                let (key, holds) = match counted_key(record)? {
                    Field::Key(key) => {
                        let text = key.text();
                        let holds = key.well_formed() && id.is_well_formed() && holdable(&text);
                        (text, holds)
                    }
                    Field::Value(value) => (Zeroizing::new(value.js_string().ok()?), false),
                };
                Some(Counted {
                    id: id.as_str().to_owned(),
                    key,
                    holds,
                })
            })
            .collect()
    }

    /// The providers [`KeysFile::counted`] lists, without their keys.
    pub fn counted_ids(&self) -> impl Iterator<Item = &str> {
        self.0
            .iter()
            .filter(|(_, record)| counted_key(record).is_some())
            .map(|(id, _)| id.as_str())
    }

    /// Whether the reference counts a key for `id`.
    pub fn counts(&self, id: &str) -> bool {
        self.0
            .iter()
            .any(|(k, record)| k == id && counted_key(record).is_some())
    }

    /// `keys[id] = { apiKey, enabled: true, addedAt }`.
    pub fn set(&mut self, id: &str, key: &str, added_at_ms: u64) {
        let record = Record::Object(vec![
            (JsString::from("apiKey"), Field::Key(Key::of_str(key))),
            (JsString::from("enabled"), Field::Value(JsValue::Bool(true))),
            (
                JsString::from("addedAt"),
                Field::Value(JsValue::Number(added_at_ms as f64)),
            ),
        ]);
        assign(&mut self.0, JsString::from(id), record);
    }

    /// `delete keys[id]`, where `only_truthy` is false or the record is
    /// truthy (the reference's remove takes only a truthy one). Whether it
    /// was there.
    pub fn delete(&mut self, id: &str, only_truthy: bool) -> bool {
        let truthy = |record: &Record| match record {
            Record::Object(_) => true,
            Record::Value(value) => value.truthy(),
        };
        match self.0.iter().position(|(k, _)| k == id) {
            Some(at) if !only_truthy || self.0.get(at).is_some_and(|(_, r)| truthy(r)) => {
                self.0.remove(at);
                true
            }
            _ => false,
        }
    }
}

/// Why an RPC-key request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The request asks for what the design refuses (`invalid_argument`).
    Invalid(&'static str),
    /// The secrets file or the key store; `Abandoned`: the job was
    /// abandoned before its commit, and nothing it would answer changed.
    Secrets(secrets::Error),
    /// `rpc-api-keys.json` couldn't be written, or set aside (a storage
    /// error's kind).
    File(&'static str),
    /// A set whose entry's write isn't durable, over a key the file counts
    /// for the provider: the file is left as it was, so the file's key is
    /// still the one answered, and the next start moves it over the entry.
    NotDurable,
}

const ABANDONED: Failure = Failure::Secrets(secrets::Error::Abandoned);

/// What a set or a remove is.
pub enum Op {
    Set {
        id: String,
        key: Zeroizing<String>,
        at_ms: u64,
    },
    Remove {
        id: String,
    },
}

impl Op {
    pub fn id(&self) -> &str {
        match self {
            Op::Set { id, .. } | Op::Remove { id } => id,
        }
    }
}

/// A job's commit (design 0001: the commit claim comes right before the
/// first write of a multi-file operation that counts). The claim is taken
/// once, at the first write that changes what the methods answer, and
/// holds for every write after it; until then, a write that changes no
/// answer is refused once the job is abandoned.
pub struct Commit<'a> {
    abandoned: &'a dyn Fn() -> bool,
    claim: &'a dyn Fn() -> bool,
    claimed: Cell<bool>,
}

impl<'a> Commit<'a> {
    /// `abandoned` and `claim`: the vault job's `JobControl`.
    pub fn new(abandoned: &'a dyn Fn() -> bool, claim: &'a dyn Fn() -> bool) -> Self {
        Commit {
            abandoned,
            claim,
            claimed: Cell::new(false),
        }
    }

    /// Whether the job was abandoned before its claim.
    fn abandoned(&self) -> bool {
        !self.claimed.get() && (self.abandoned)()
    }

    /// Claims the commit, the first time; true once claimed.
    fn claim(&self) -> bool {
        if !self.claimed.get() {
            self.claimed.set((self.claim)());
        }
        self.claimed.get()
    }
}

/// See the module documentation.
pub struct RpcKeys {
    root: PathBuf,
    secrets: Arc<Secrets>,
    /// Whether this start's migration has run.
    migrated: Mutex<bool>,
}

fn io_kind(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => "permission",
        std::io::ErrorKind::StorageFull => "no_space",
        _ => "other",
    }
}

/// The RPC-key entries in `secrets`.
fn rpc_entries(secrets: &SecretsFile) -> usize {
    secrets
        .entry_names()
        .filter(|n| provider_of(n).is_some())
        .count()
}

/// The migration's part of a secrets write: each key the file counts that
/// the secrets file can hold, in the file's order up to the bound, put over
/// any entry the provider has. The providers it moves.
fn migration(counted: &[Counted], secrets: &SecretsFile, change: &mut Change) -> Vec<String> {
    let mut entries = rpc_entries(secrets);
    let mut moved = Vec::new();
    for counted in counted {
        let Some(name) = entry_name(&counted.id).filter(|_| counted.holds) else {
            continue;
        };
        if secrets.entry_key(&name).is_none() {
            if entries >= MAX_KEYS {
                continue;
            }
            entries += 1;
        }
        change
            .put
            .push((name, Zeroizing::new(counted.key.as_bytes().to_vec())));
        moved.push(counted.id.clone());
    }
    moved
}

impl RpcKeys {
    pub fn new(root: PathBuf, secrets: Arc<Secrets>) -> Arc<RpcKeys> {
        Arc::new(RpcKeys {
            root,
            secrets,
            migrated: Mutex::new(false),
        })
    }

    fn path(&self) -> PathBuf {
        self.root.join(FILE)
    }

    /// Whether the key store offers the policy the entries go under.
    fn key_store(&self) -> bool {
        self.secrets.capabilities().offers(Policy::Unattended)
    }

    /// The migration's state, held for the request; at this start's first,
    /// the temp files a killed write left are removed.
    fn begin(&self) -> Result<MutexGuard<'_, bool>, Failure> {
        let migrated = self.migrated.lock().map_err(|_| Failure::File("other"))?;
        if !*migrated && let Err(e) = fsx::remove_temps(&self.root, FILE) {
            crate::log::warn(
                "cannot remove rpc-api-keys.json's temp files",
                serde_json::json!({ "kind": e.kind().to_string() }),
            );
        }
        Ok(migrated)
    }

    /// The file as it stands (`None` when there is none). An unreadable one
    /// is renamed aside first, unless the job was abandoned, and reads as
    /// none.
    fn load(&self, commit: &Commit<'_>) -> Result<Option<KeysFile>, Failure> {
        let parsed = match read_secret_file(&self.path(), MAX_FILE_BYTES) {
            SecretRead::Missing => return Ok(None),
            SecretRead::Bytes(bytes) => KeysFile::parse(&bytes),
            SecretRead::Unreadable => None,
        };
        if parsed.is_some() {
            return Ok(parsed);
        }
        // Not the commit: the file reads as none either way.
        if commit.abandoned() {
            return Err(ABANDONED);
        }
        let renamed = set_aside(&self.root, FILE);
        crate::log::warn(
            "rpc-api-keys.json can't be read: renamed aside",
            serde_json::json!({ "renamed": renamed.is_ok() }),
        );
        match renamed {
            Ok(_) => Ok(None),
            Err(e) => Err(Failure::File(io_kind(&e))),
        }
    }

    /// Writes `file`, or removes it when it is empty and `keep_empty` is
    /// false: 0001's single-file write, 0600, staged and read back, its
    /// rename (or the unlink) claimed through `commit`.
    fn save(
        &self,
        file: &KeysFile,
        keep_empty: bool,
        commit: &Commit<'_>,
    ) -> Result<Done, Failure> {
        crate::testhooks::secrets_step("before-rpc-file");
        if crate::testhooks::secrets_fails("rpc-file") {
            return Err(Failure::File("other"));
        }
        let path = self.path();
        let done = if file.is_empty() && !keep_empty {
            fsx::remove(&path, || commit.claim())
                .map_err(|e| Failure::File(io_kind(&e)))?
                .ok_or(ABANDONED)?
        } else {
            let text = file.text();
            fsx::replace(
                &path,
                text.as_bytes(),
                |staged| {
                    let bytes = fsx::read_secret_at_most(staged, MAX_FILE_BYTES as u64)
                        .map_err(|e| e.to_string())?
                        .ok_or("the staged rpc-api-keys.json grew")?;
                    if bytes[..] == *text.as_bytes() {
                        Ok(())
                    } else {
                        Err("the staged rpc-api-keys.json doesn't read back".into())
                    }
                },
                || commit.claim(),
                &crate::testhooks::SecretsWrite("rpc-file"),
            )
            .map_err(|e| match e {
                fsx::WriteError::Io(e) => Failure::File(io_kind(&e)),
                fsx::WriteError::Abandoned => ABANDONED,
                fsx::WriteError::Check(_) => Failure::File("other"),
            })?
        };
        if done == Done::NotDurable {
            crate::log::warn(
                "rpc-api-keys.json's directory flush failed",
                serde_json::json!({}),
            );
        }
        crate::testhooks::secrets_step("after-rpc-file");
        Ok(done)
    }

    /// This start's migration, once, if it hasn't run (see the module
    /// documentation). A failure leaves it to run again at the next
    /// request.
    fn migrate(&self, migrated: &mut bool, commit: &Commit<'_>) -> Result<(), Failure> {
        if *migrated {
            return Ok(());
        }
        if !self.key_store() {
            *migrated = true;
            return Ok(());
        }
        let Some(mut file) = self.load(commit)? else {
            *migrated = true;
            return Ok(());
        };
        let counted = file.counted();
        let gate = (|| commit.abandoned(), || commit.claim());
        let (moved, done) = self
            .secrets
            .change_entries(
                "rpc-migrate",
                &Gate {
                    abandoned: &gate.0,
                    claim: &gate.1,
                },
                |secrets| {
                    let mut change = Change::default();
                    let moved = migration(&counted, secrets, &mut change);
                    Ok((change, moved))
                },
            )
            .map_err(Failure::Secrets)?;
        // Not durable: every key stays in the file too, which wins.
        if done == Done::Durable && !moved.is_empty() {
            for id in &moved {
                file.delete(id, false);
            }
            let _ = self.save(&file, false, commit)?;
        }
        *migrated = true;
        Ok(())
    }

    /// The providers with a key: the entries' names and the file's counted
    /// keys. No key is opened, and the key store isn't asked.
    pub fn status(&self, commit: &Commit<'_>) -> Result<Vec<String>, Failure> {
        let mut ids: Vec<String> = self
            .secrets
            .entry_names(PREFIX)
            .map_err(Failure::Secrets)?
            .iter()
            .filter_map(|n| provider_of(n).map(str::to_owned))
            .collect();
        if let Some(file) = self.load(commit)? {
            ids.extend(file.counted_ids().map(str::to_owned));
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    /// Each provider's key, for main's own requests: from the file where it
    /// counts one, from the entry otherwise.
    pub fn keys(
        &self,
        commit: &Commit<'_>,
    ) -> Result<BTreeMap<String, Zeroizing<String>>, Failure> {
        let mut migrated = self.begin()?;
        self.migrate(&mut migrated, commit)?;
        let mut keys = BTreeMap::new();
        if self.key_store() {
            for (name, secret) in self
                .secrets
                .open_entries(PREFIX)
                .map_err(Failure::Secrets)?
            {
                let (Some(id), Ok(key)) =
                    (provider_of(&name), std::str::from_utf8(secret.expose()))
                else {
                    continue;
                };
                keys.insert(id.to_owned(), Zeroizing::new(key.to_owned()));
            }
        }
        if let Some(file) = self.load(commit)? {
            for counted in file.counted() {
                keys.insert(counted.id, counted.key);
            }
        }
        Ok(keys)
    }

    /// A set or a remove (see the module documentation): whether its
    /// change is durable.
    pub fn change(&self, op: &Op, commit: &Commit<'_>) -> Result<Done, Failure> {
        if let Op::Set { id, key, .. } = op {
            if entry_name(id).is_none() {
                return Err(Failure::Invalid("rpc-key-provider-id"));
            }
            if !holdable(key) {
                return Err(Failure::Invalid("rpc-key-size"));
            }
        }
        let mut migrated = self.begin()?;
        if !self.key_store() {
            *migrated = true;
            return match op {
                Op::Set { id, key, at_ms } => {
                    let mut file = self.load(commit)?.unwrap_or_default();
                    file.set(id, key, *at_ms);
                    if file.text_len() > MAX_FILE_BYTES {
                        return Err(Failure::Invalid("rpc-keys-file-size"));
                    }
                    self.save(&file, true, commit)
                }
                Op::Remove { id } => {
                    let Some(mut file) = self.load(commit)? else {
                        return Ok(Done::Durable);
                    };
                    if file.delete(id, true) {
                        self.save(&file, true, commit)
                    } else {
                        Ok(Done::Durable)
                    }
                }
            };
        }
        let file = self.load(commit)?;
        // This start's migration rides in the same secrets write.
        let counted = match &file {
            Some(file) if !*migrated => file.counted(),
            _ => Vec::new(),
        };
        let id = op.id();
        let name = entry_name(id);
        let step = match op {
            Op::Set { .. } => "rpc-set",
            Op::Remove { .. } => "rpc-remove",
        };
        let gate = (|| commit.abandoned(), || commit.claim());
        let ((moved, taken), written) = self
            .secrets
            .change_entries(
                step,
                &Gate {
                    abandoned: &gate.0,
                    claim: &gate.1,
                },
                |secrets| {
                    let mut change = Change::default();
                    let moved = migration(&counted, secrets, &mut change);
                    // `false`: a set refused at the bound.
                    let mut taken = true;
                    match (op, &name) {
                        (Op::Set { key, .. }, Some(name)) => {
                            let entries = rpc_entries(secrets)
                                + change
                                    .put
                                    .iter()
                                    .filter(|(n, _)| new_entry(secrets, n))
                                    .count();
                            let there = !new_entry(secrets, name)
                                || change.put.iter().any(|(n, _)| n == name);
                            if there || entries < MAX_KEYS {
                                change.put.retain(|(n, _)| n != name);
                                change
                                    .put
                                    .push((name.clone(), Zeroizing::new(key.as_bytes().to_vec())));
                            } else {
                                taken = false;
                            }
                        }
                        (Op::Remove { .. }, Some(name)) => {
                            change.put.retain(|(n, _)| n != name);
                            if !new_entry(secrets, name) {
                                change.remove.push(name.clone());
                            }
                        }
                        // A remove for an id outside the entry form: the
                        // file alone holds it.
                        _ => {}
                    }
                    Ok((change, (moved, taken)))
                },
            )
            .map_err(Failure::Secrets)?;
        *migrated = true;
        let durable = written == Done::Durable;
        let Some(mut file) = file else {
            return if taken {
                Ok(written)
            } else {
                Err(Failure::Invalid("rpc-keys-bound"))
            };
        };
        if !durable && taken && matches!(op, Op::Set { .. }) && file.counts(id) {
            return Err(Failure::NotDurable);
        }
        let mut changed = false;
        if durable {
            for moved in &moved {
                changed |= file.delete(moved, false);
            }
        }
        match op {
            Op::Set { .. } if taken && durable => changed |= file.delete(id, false),
            Op::Remove { .. } => changed |= file.delete(id, true),
            Op::Set { .. } => {}
        }
        let saved = if changed {
            self.save(&file, false, commit)?
        } else {
            Done::Durable
        };
        if !taken {
            return Err(Failure::Invalid("rpc-keys-bound"));
        }
        Ok(if durable && saved == Done::Durable {
            Done::Durable
        } else {
            Done::NotDurable
        })
    }
}

/// Whether `secrets` has no entry named `name`.
fn new_entry(secrets: &SecretsFile, name: &EntryName) -> bool {
    secrets.entry_key(name).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The file's text is `JSON.stringify(JSON.parse(text), null, 2)`, as
    /// fc-json's tree gives it, though the keys never enter that tree.
    #[test]
    fn the_text_is_the_references() {
        let texts = [
            "{}",
            "{\"a\":{}}",
            "{\"a\":[]}",
            "{\"b\":1,\"a\":{\"apiKey\":\"k\",\"enabled\":true,\"addedAt\":1700000000000}}",
            "{\"x\":{\"apiKey\":\"k1\",\"note\":{\"n\":[1,{\"m\":\"\\n\"}]},\"apiKey\":\"k2\"}}",
            "{\"2\":0,\"10\":1,\"01\":2,\"x\":{\"9\":true,\"apiKey\":\"\\u0001\\\"\\\\\\b\\f\\n\\r\\t\\ud800\\u001f\\u007f\u{e9}\"},\"1\":null}",
            "{\"x\":{\"apiKey\":12},\"y\":\"s\",\"z\":[1,[2,{}],{\"a\":[]}],\"\\ud800\":{\"apiKey\":\"\\udc00a\"}}",
            "{\"x\":1,\"x\":{\"apiKey\":\"q\",\"enabled\":1}}",
        ];
        for text in texts {
            let file = KeysFile::parse(text.as_bytes()).unwrap_or_else(|| panic!("{text}"));
            let reference = fc_json::parse(text).unwrap().stringify_pretty();
            assert_eq!(*file.text(), reference, "{text}");
            assert_eq!(file.text_len(), reference.len(), "{text}");
            assert_eq!(file.text().capacity(), reference.len(), "{text}");
        }
        for unreadable in ["", "[]", "null", "\"s\"", "{", "\u{feff}{}"] {
            assert!(
                KeysFile::parse(unreadable.as_bytes()).is_none(),
                "{unreadable}"
            );
        }
        // Invalid UTF-8: each sequence read as U+FFFD, as Node reads it.
        let file = KeysFile::parse(b"{\"a\xff\":{\"apiKey\":\"k\xc3\"}}").unwrap();
        assert_eq!(
            *file.text(),
            "{\n  \"a\u{fffd}\": {\n    \"apiKey\": \"k\u{fffd}\"\n  }\n}"
        );
    }

    /// What the reference counts, and a set and a delete as it does them.
    #[test]
    fn counted_set_and_delete() {
        let text = "{\"b\":{\"apiKey\":\"kb\",\"enabled\":true},\"a\":{\"apiKey\":\"ka\",\"enabled\":0},\"c\":{\"apiKey\":7,\"enabled\":\"y\"},\"d\":{\"apiKey\":\"\\ud800\",\"enabled\":true},\"e\":0,\"f\":{\"apiKey\":{\"toString\":1},\"enabled\":true}}";
        let mut file = KeysFile::parse(text.as_bytes()).unwrap();
        let counted: Vec<(String, String, bool)> = file
            .counted()
            .into_iter()
            .map(|c| (c.id, c.key.to_string(), c.holds))
            .collect();
        assert_eq!(
            counted,
            [
                ("b".into(), "kb".into(), true),
                ("c".into(), "7".into(), false),
                ("d".into(), "\u{fffd}".into(), false),
            ]
        );
        assert_eq!(file.counted_ids().collect::<Vec<_>>(), ["b", "c", "d"]);
        assert!(file.counts("b") && !file.counts("a") && !file.counts("e"));
        file.set("3", "k3", 5);
        file.set("b", "kb2", 6);
        assert!(!file.delete("e", true));
        assert!(file.delete("e", false));
        assert!(file.delete("a", true));
        let mut reference = fc_json::parse(text).unwrap();
        for (id, key, at) in [("3", "k3", 5.0), ("b", "kb2", 6.0)] {
            reference.set(
                id,
                fc_json::parse(&format!(
                    "{{\"apiKey\":\"{key}\",\"enabled\":true,\"addedAt\":{at}}}"
                ))
                .unwrap(),
            );
        }
        let reference = reference.stringify_pretty();
        let reference = reference.replace("  \"e\": 0,\n", "").replace(
            "  \"a\": {\n    \"apiKey\": \"ka\",\n    \"enabled\": 0\n  },\n",
            "",
        );
        assert_eq!(*file.text(), reference);
    }

    #[test]
    fn a_key_parameter_is_a_well_formed_string() {
        assert_eq!(key_param("\"a\\u0041\"").unwrap().as_str(), "aA");
        assert!(key_param("\"\\ud800\"").is_none());
        assert!(key_param("12").is_none());
        assert_eq!(key_param("\"\"").unwrap().as_str(), "");
    }
}
