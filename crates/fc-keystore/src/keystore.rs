//! The trait the OS key stores sit behind (0013, "The trait"), and the
//! values that cross it.
//!
//! Only wrapping keys go to the OS: 32 bytes, made where they are kept, at
//! most one in use per profile and policy. Every secret is sealed under one
//! of them in the profile's secrets file ([`crate::SecretsFile`]).

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

/// How a wrapping key is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Policy {
    /// Opened without asking the user (macOS: a login-keychain item whose
    /// access list is `freedom-cored`'s signature).
    Unattended,
    /// Opened only after the OS asks the user (macOS: the data protection
    /// keychain with `userPresence`, once the core carries the entitlement).
    UserPresence,
}

impl Policy {
    /// Both policies, in the order the file lists them.
    pub const ALL: [Policy; 2] = [Policy::Unattended, Policy::UserPresence];

    /// The policy's name in the file and on the wire.
    pub fn name(self) -> &'static str {
        match self {
            Policy::Unattended => "unattended",
            Policy::UserPresence => "user_presence",
        }
    }

    /// The policy a name spells, exactly.
    pub fn parse(name: &str) -> Option<Policy> {
        match name {
            "unattended" => Some(Policy::Unattended),
            "user_presence" => Some(Policy::UserPresence),
            _ => None,
        }
    }

    pub(crate) fn index(self) -> usize {
        match self {
            Policy::Unattended => 0,
            Policy::UserPresence => 1,
        }
    }
}

/// Where a wrapping key is kept. The names are fc-profile's, which reads
/// them from a deleted profile's secrets file (PRF-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Backend {
    /// The macOS Keychain: it keeps the item and finds it by its id.
    MacosKeychain,
    /// The Secret Service on Linux: it keeps the item and finds it by its id.
    SecretService,
    /// Windows DPAPI: it keeps nothing; its blob is the file's to keep
    /// (0013, "DPAPI's blob").
    Dpapi,
}

impl Backend {
    /// Every backend, in a fixed order.
    pub const ALL: [Backend; 3] = [
        Backend::MacosKeychain,
        Backend::SecretService,
        Backend::Dpapi,
    ];

    /// The backend's name in the file.
    pub fn name(self) -> &'static str {
        match self {
            Backend::MacosKeychain => "macos-keychain",
            Backend::SecretService => "secret-service",
            Backend::Dpapi => "dpapi",
        }
    }

    /// The backend a name spells, exactly.
    pub fn parse(name: &str) -> Option<Backend> {
        match name {
            "macos-keychain" => Some(Backend::MacosKeychain),
            "secret-service" => Some(Backend::SecretService),
            "dpapi" => Some(Backend::Dpapi),
            _ => None,
        }
    }

    /// Whether the file keeps a blob for a key of this backend: DPAPI's
    /// only. Every other backend's `sealed` is `null`.
    pub fn keeps_blob(self) -> bool {
        self == Backend::Dpapi
    }

    /// Whether the OS holds an item to forget: not for DPAPI, where
    /// dropping the blob from the file is the whole `forget`, so no record
    /// of it is made (0013, "Windows").
    pub fn holds_item(self) -> bool {
        self != Backend::Dpapi
    }
}

/// A key-store item's id: 16 random bytes, 32 lowercase hex digits in the
/// file and on the wire. Not a secret: it names the item, and DPAPI's
/// entropy is built from it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemId([u8; 16]);

impl ItemId {
    /// A fresh id from `rng`: each `create` draws one, so a record never
    /// names a later item of its profile.
    pub fn random<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<ItemId, Randomness> {
        let mut bytes = [0u8; 16];
        rng.try_fill_bytes(&mut bytes).map_err(|_| Randomness)?;
        Ok(ItemId(bytes))
    }

    /// The id with these bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> ItemId {
        ItemId(bytes)
    }

    /// The id 32 lowercase hex digits spell, exactly.
    pub fn parse(text: &str) -> Option<ItemId> {
        let digits = text.as_bytes();
        if digits.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (byte, [high, low]) in bytes.iter_mut().zip(digits.as_chunks::<2>().0) {
            *byte = (lower_hex_digit(*high)? << 4) | lower_hex_digit(*low)?;
        }
        Some(ItemId(bytes))
    }

    /// The id's 16 bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The id as 32 lowercase hex digits.
    pub fn hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(32);
        for byte in self.0 {
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        out
    }
}

fn lower_hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

impl fmt::Debug for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ItemId({})", self.hex())
    }
}

impl fmt::Display for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

/// The most bytes DPAPI's blob takes, decoded (0013, "The bound is 1 KiB").
pub const MAX_BLOB_BYTES: usize = 1024;

/// DPAPI's blob for a wrapping key: 1 to [`MAX_BLOB_BYTES`] bytes. It is
/// ciphertext that only the user's account opens, not a secret of the core's;
/// its `Debug` shows only its length.
#[derive(Clone, PartialEq, Eq)]
pub struct Blob(Vec<u8>);

impl Blob {
    /// The blob with these bytes, within its bound.
    pub fn new(bytes: Vec<u8>) -> Option<Blob> {
        (1..=MAX_BLOB_BYTES)
            .contains(&bytes.len())
            .then_some(Blob(bytes))
    }

    /// The blob a text spells: standard base64, padded, canonical, decoding
    /// to 1 to [`MAX_BLOB_BYTES`] bytes.
    pub fn from_base64(text: &str) -> Option<Blob> {
        // A longer text can't decode within the bound: refused before
        // decoding it.
        if text.len() > MAX_BLOB_BYTES.div_ceil(3) * 4 {
            return None;
        }
        Blob::new(STANDARD.decode(text).ok()?)
    }

    /// Its bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Standard base64, padded.
    pub fn base64(&self) -> String {
        STANDARD.encode(&self.0)
    }
}

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blob({} bytes)", self.0.len())
    }
}

/// What the secrets file keeps for a key, and what `open` and `forget`
/// take: the backend, the policy, the item's id, and DPAPI's blob, which
/// only a DPAPI key has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    backend: Backend,
    policy: Policy,
    item: ItemId,
    blob: Option<Blob>,
}

impl Sealed {
    /// A key's record. A DPAPI key needs its blob, and no other key has
    /// one: anything else is [`SealedForm`].
    pub fn new(
        backend: Backend,
        policy: Policy,
        item: ItemId,
        blob: Option<Blob>,
    ) -> Result<Sealed, SealedForm> {
        if backend.keeps_blob() != blob.is_some() {
            return Err(SealedForm);
        }
        Ok(Sealed {
            backend,
            policy,
            item,
            blob,
        })
    }

    /// A record the secrets file holds in form already.
    pub(crate) fn from_parts(
        backend: Backend,
        policy: Policy,
        item: ItemId,
        blob: Option<Blob>,
    ) -> Sealed {
        Sealed {
            backend,
            policy,
            item,
            blob,
        }
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    pub fn policy(&self) -> Policy {
        self.policy
    }

    pub fn item(&self) -> ItemId {
        self.item
    }

    /// DPAPI's blob; `None` for every other backend.
    pub fn blob(&self) -> Option<&Blob> {
        self.blob.as_ref()
    }
}

/// A [`Sealed`] whose blob doesn't match its backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a DPAPI key needs its blob, and no other key has one")]
pub struct SealedForm;

/// What `create` names the item by: the id the core drew for it and wrote
/// into the secrets file as `pending` before asking (0013, "The failure
/// contract").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Label {
    item: ItemId,
}

impl Label {
    pub fn new(item: ItemId) -> Label {
        Label { item }
    }

    pub fn item(&self) -> ItemId {
        self.item
    }
}

/// Why a `UserPresence` key is opened, from a fixed list; main supplies the
/// text the OS shows (0013, "The call").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    QuickUnlock,
    Export,
}

impl Reason {
    pub fn name(self) -> &'static str {
        match self {
            Reason::QuickUnlock => "quick_unlock",
            Reason::Export => "export",
        }
    }

    pub fn parse(name: &str) -> Option<Reason> {
        match name {
            "quick_unlock" => Some(Reason::QuickUnlock),
            "export" => Some(Reason::Export),
            _ => None,
        }
    }
}

/// What a device offers, asked once per profile open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// The backend keys are made in; `None` where the OS has no key store,
    /// or none answers. No backend is ever faked.
    pub backend: Option<Backend>,
    pub unattended: bool,
    pub user_presence: bool,
}

impl Capabilities {
    /// No key store: every secret stays where it is today.
    pub const NONE: Capabilities = Capabilities {
        backend: None,
        unattended: false,
        user_presence: false,
    };

    /// Whether a key can be made under `policy`: only with a backend.
    pub fn offers(&self, policy: Policy) -> bool {
        self.backend.is_some()
            && match policy {
                Policy::Unattended => self.unattended,
                Policy::UserPresence => self.user_presence,
            }
    }
}

/// A 32-byte wrapping key. Wiped on drop; no `Debug`, `Display`,
/// `Serialize` or `Clone` (AGENTS rule 3).
pub struct WrapKey(Zeroizing<[u8; 32]>);

impl WrapKey {
    /// A fresh key from `rng`. On desktop only the helper makes keys, from
    /// the OS's RNG, where the key is kept (0013, "Creating, not storing a
    /// given key").
    pub fn random<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<WrapKey, Randomness> {
        let mut key = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(&mut key[..]).map_err(|_| Randomness)?;
        Ok(WrapKey(key))
    }

    /// The key in `bytes`, which are wiped: a backend's or an opened seal's
    /// copy is never left behind.
    pub fn take(bytes: &mut [u8; 32]) -> WrapKey {
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(bytes);
        zeroize::Zeroize::zeroize(bytes);
        WrapKey(key)
    }

    /// The key's bytes, for a backend to keep or a seal to carry.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The RNG failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the random number generator failed")]
pub struct Randomness;

/// A backend's failure that isn't one of the others, with a fixed-form
/// reason (for the helper: `bad_request`, an answer out of form, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendError {
    reason: &'static str,
}

impl BackendError {
    pub fn new(reason: &'static str) -> BackendError {
        BackendError { reason }
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "key store backend: {}", self.reason)
    }
}

/// Why no key store answered, in a fixed form: `key_store_unavailable`'s
/// `data.reason` (0013, API). The helper's own (`unsupported`,
/// `no_keychain`, `read_only`), or the core's: `timeout` (main killed the
/// helper past its deadline, or no answer came in time), `closed` (the
/// core is exiting, or main closed the call), `no_executor` (main has no
/// `shell.keystore`), and `helper` for a reason the core doesn't know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnavailableReason {
    reason: &'static str,
}

impl UnavailableReason {
    pub const fn new(reason: &'static str) -> UnavailableReason {
        UnavailableReason { reason }
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for UnavailableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason)
    }
}

/// Why a key-store call failed (0013, "The trait").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyStoreError {
    /// No such item: a copy on another machine, an item removed by hand.
    #[error("no such key-store item")]
    NotFound,
    /// The user cancelled the OS's prompt.
    #[error("cancelled")]
    Cancelled,
    /// No key store answers, or the call ran past its deadline, and why.
    #[error("the key store is unavailable: {0}")]
    Unavailable(UnavailableReason),
    /// The OS refuses the item or blob as no longer valid.
    #[error("the key-store item is invalidated")]
    Invalidated,
    /// The OS denies this process the item.
    #[error("denied")]
    Denied,
    #[error("{0}")]
    Backend(BackendError),
}

impl KeyStoreError {
    /// The error's name on the wire (0013, "The answer").
    pub fn code(&self) -> &'static str {
        match self {
            KeyStoreError::NotFound => "not_found",
            KeyStoreError::Cancelled => "cancelled",
            KeyStoreError::Unavailable(_) => "unavailable",
            KeyStoreError::Invalidated => "invalidated",
            KeyStoreError::Denied => "denied",
            KeyStoreError::Backend(_) => "backend",
        }
    }
}

/// An OS key store (0013, "The trait"). On desktop the core's
/// implementation sends each call to main as `shell.keystore`, which runs
/// it in a one-shot helper (PRF-1b); mobile implements it in the app.
pub trait KeyStore {
    /// What this device offers, asked once per profile open.
    fn capabilities(&self) -> Capabilities;

    /// Makes a fresh 32-byte wrapping key where it is kept, under `policy`,
    /// named by `label`'s id, and returns it with what the secrets file
    /// stores: the item's id, and DPAPI's blob where the backend is DPAPI.
    fn create(&self, policy: Policy, label: &Label) -> Result<(WrapKey, Sealed), KeyStoreError>;

    /// Opens it. A `UserPresence` key asks the user, with `reason`; one
    /// asked without a reason is refused.
    fn open(&self, sealed: &Sealed, reason: Option<Reason>) -> Result<WrapKey, KeyStoreError>;

    /// Removes the item. A missing item is success.
    fn forget(&self, sealed: &Sealed) -> Result<(), KeyStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_ids_are_lowercase_hex() {
        let id = ItemId::parse("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(id.hex(), "00112233445566778899aabbccddeeff");
        assert_eq!(id.as_bytes()[15], 0xff);
        for bad in [
            "00112233445566778899AABBCCDDEEFF",
            "00112233445566778899aabbccddeef",
            "00112233445566778899aabbccddeeff0",
            "0011223344556677 899aabbccddeeff",
            "g0112233445566778899aabbccddeeff",
            "",
        ] {
            assert_eq!(ItemId::parse(bad), None, "{bad}");
        }
        // Multi-byte text of the right byte length isn't hex either.
        assert_eq!(ItemId::parse(&"é".repeat(16)), None);
    }

    #[test]
    fn blobs_are_bounded_canonical_base64() {
        assert_eq!(Blob::from_base64("AQ==").unwrap().as_bytes(), [1]);
        assert!(Blob::from_base64("").is_none());
        assert!(Blob::from_base64("AQ").is_none(), "unpadded");
        assert!(Blob::from_base64("AR==").is_none(), "trailing bits");
        assert!(Blob::from_base64("AQ==\n").is_none());
        let max = STANDARD.encode(vec![7u8; MAX_BLOB_BYTES]);
        assert_eq!(
            Blob::from_base64(&max).unwrap().as_bytes().len(),
            MAX_BLOB_BYTES
        );
        let over = STANDARD.encode(vec![7u8; MAX_BLOB_BYTES + 1]);
        assert!(Blob::from_base64(&over).is_none());
        assert_eq!(
            format!("{:?}", Blob::new(vec![1, 2]).unwrap()),
            "Blob(2 bytes)"
        );
    }

    #[test]
    fn sealed_needs_a_blob_only_for_dpapi() {
        let id = ItemId::from_bytes([1; 16]);
        let blob = Blob::new(vec![1]).unwrap();
        assert!(Sealed::new(Backend::Dpapi, Policy::Unattended, id, Some(blob.clone())).is_ok());
        assert_eq!(
            Sealed::new(Backend::Dpapi, Policy::Unattended, id, None),
            Err(SealedForm)
        );
        assert_eq!(
            Sealed::new(Backend::MacosKeychain, Policy::Unattended, id, Some(blob)),
            Err(SealedForm)
        );
        assert!(Sealed::new(Backend::SecretService, Policy::UserPresence, id, None).is_ok());
    }

    #[test]
    fn names_round_trip() {
        for policy in Policy::ALL {
            assert_eq!(Policy::parse(policy.name()), Some(policy));
        }
        for backend in Backend::ALL {
            assert_eq!(Backend::parse(backend.name()), Some(backend));
        }
        for reason in [Reason::QuickUnlock, Reason::Export] {
            assert_eq!(Reason::parse(reason.name()), Some(reason));
        }
        assert_eq!(Policy::parse("Unattended"), None);
        assert_eq!(Backend::parse("keychain"), None);
        assert!(!Capabilities::NONE.offers(Policy::Unattended));
        let no_backend = Capabilities {
            backend: None,
            unattended: true,
            user_presence: true,
        };
        assert!(!no_backend.offers(Policy::UserPresence));
    }

    #[test]
    fn unavailable_carries_its_reason() {
        let error = KeyStoreError::Unavailable(UnavailableReason::new("timeout"));
        assert_eq!(error.code(), "unavailable");
        assert_eq!(error.to_string(), "the key store is unavailable: timeout");
        match error {
            KeyStoreError::Unavailable(why) => assert_eq!(why.reason(), "timeout"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn take_wipes_the_source() {
        let mut bytes = [9u8; 32];
        let key = WrapKey::take(&mut bytes);
        assert_eq!(bytes, [0u8; 32]);
        assert_eq!(key.expose(), &[9u8; 32]);
    }
}
