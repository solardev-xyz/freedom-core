//! The node's identity for this process (design 0008, "Keys"): the X25519
//! key the service makes for one start, and `rad.identity`.
//!
//! - **At spawn,** after the gate, the service makes an X25519 key pair from
//!   the OS's randomness ([`fc_seal::RecipientKey`]); `rad.hello`'s reply
//!   names its public half as `recipient`.
//! - **`rad.identity { sealed: { enc, ciphertext } }`** opens the node key
//!   the core sealed to it (`nodes.seal_radicle_key`), once: the private
//!   half is consumed by the attempt, whether the ciphertext opened or not.
//! - **`rad.identity { ephemeral: true }`,** on a profile without a vault,
//!   makes a throwaway key from the OS's randomness, never written.
//! - **Either way,** `keys/radicle` is checked first (0008, "The switch"):
//!   anything there, as `lstat` sees it, is `key_file_present`. The reply
//!   is `{ did, nid, ephemeral }`.
//! - **The key is held** as its 32-byte seed, in zeroizing memory, until the
//!   node's start takes it: reconciliation signs with it first (0008: "The
//!   key in the service: reconciliation signs with it"), each signer it
//!   makes wiping itself on drop. `rad.start` then moves it into the
//!   [`libradicle::HostKey`] for `Embedded::start_with_key`
//!   ([`Identity::take_key`]), and the service keeps no copy after that.
//! - **Once per process,** within 30 s of `rad.hello`'s reply. Every failure
//!   ends the process after its reply, a second `rad.identity` included.

use std::io;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_seal::RecipientKey;
use serde::Deserialize;
use zeroize::Zeroizing;

/// `rad.identity` must follow `rad.hello`'s reply within this.
pub const DEADLINE: Duration = Duration::from_secs(30);

/// `rad.identity`'s params: exactly one of the two forms.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    #[serde(default)]
    sealed: Option<Sealed>,
    #[serde(default)]
    ephemeral: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    enc: String,
    ciphertext: String,
}

/// The node's identity, once `rad.identity` has succeeded.
pub struct NodeIdentity {
    /// The key's seed, until the node's start takes it. It wipes on drop.
    seed: Option<Zeroizing<[u8; 32]>>,
    /// The node ID, as reconciliation names it.
    pub id: radicle::prelude::NodeId,
    pub did: String,
    pub nid: String,
    pub ephemeral: bool,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("nid", &self.nid)
            .field("ephemeral", &self.ephemeral)
            .finish_non_exhaustive()
    }
}

impl NodeIdentity {
    /// Whether the key is still held: until the node's start takes it.
    #[cfg(test)]
    pub fn holds_key(&self) -> bool {
        self.seed.is_some()
    }

    /// The key for `Embedded::start_with_key`, once: `rad.start` takes it,
    /// and the service keeps no copy after (0008, "The key in the service").
    /// The seed is moved into the [`libradicle::HostKey`], which zeroes what
    /// it copies from, and the seed's own buffer wipes as it drops here.
    /// `None` once taken.
    pub fn take_key(&mut self) -> Option<libradicle::HostKey> {
        let mut seed = self.seed.take()?;
        libradicle::HostKey::from_bytes(seed.as_mut_slice())
    }

    /// What signs for this identity before the node starts: reconciliation's
    /// re-signing of its own namespace (0008, "Reconciliation"). `None` for
    /// a throwaway key, which owns no namespace and signs nothing, or once
    /// the node's start has taken the key. The signer wipes itself on drop.
    pub fn signer(&self) -> Option<radicle::crypto::SigningKey> {
        if self.ephemeral {
            return None;
        }
        let seed = self.seed.as_ref()?;
        Some(radicle::crypto::SigningKey::from(
            ed25519_dalek::SigningKey::from_bytes(seed),
        ))
    }
}

enum State {
    /// Waiting for `rad.identity`, with the key for this start.
    Waiting(RecipientKey),
    /// An attempt was made and failed: the process is ending.
    Failed,
    /// `rad.identity` succeeded.
    Known(NodeIdentity),
}

/// Why `rad.identity` failed: its reply, after which the process ends.
#[derive(Debug, Clone, PartialEq)]
pub struct Failure(pub ErrorBody);

/// The process's identity state.
pub struct Identity {
    home: std::path::PathBuf,
    recipient: [u8; fc_seal::PUBLIC_KEY_LEN],
    state: Mutex<State>,
}

impl Identity {
    /// Makes the key for this start; `None` if the OS's randomness fails.
    pub fn new(home: &Path) -> Option<Self> {
        let key = RecipientKey::generate(&mut crate::identity::OsRng).ok()?;
        Some(Self {
            home: home.to_path_buf(),
            recipient: key.public_key(),
            state: Mutex::new(State::Waiting(key)),
        })
    }

    /// The `recipient` `rad.hello` names: the public half, base64.
    pub fn recipient(&self) -> String {
        STANDARD.encode(self.recipient)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether `rad.identity` has succeeded.
    pub fn known(&self) -> bool {
        matches!(*self.state(), State::Known(_))
    }

    /// Runs `f` on the identity, once known.
    pub fn with<R>(&self, f: impl FnOnce(&NodeIdentity) -> R) -> Option<R> {
        match &*self.state() {
            State::Known(identity) => Some(f(identity)),
            _ => None,
        }
    }

    /// The node's key, for its start ([`NodeIdentity::take_key`]): `None`
    /// before `rad.identity` has succeeded, or once taken.
    pub fn take_key(&self) -> Option<libradicle::HostKey> {
        match &mut *self.state() {
            State::Known(identity) => identity.take_key(),
            _ => None,
        }
    }

    /// `rad.identity`: its result, or the failure that ends the process.
    pub fn establish(&self, params: Option<&str>) -> Result<serde_json::Value, Failure> {
        let mut state = self.state();
        // Whatever happens next, this is the one attempt.
        let recipient = match std::mem::replace(&mut *state, State::Failed) {
            State::Waiting(recipient) => recipient,
            other @ (State::Failed | State::Known(_)) => {
                *state = other;
                return Err(Failure(ErrorBody::new(
                    ErrorCode::InvalidArgument,
                    "rad.identity was already called",
                )));
            }
        };
        let identity = establish(&self.home, recipient, params)?;
        let result = serde_json::json!({
            "did": identity.did,
            "nid": identity.nid,
            "ephemeral": identity.ephemeral,
        });
        *state = State::Known(identity);
        Ok(result)
    }
}

fn invalid(message: &str) -> Failure {
    Failure(ErrorBody::new(ErrorCode::InvalidArgument, message))
}

fn establish(
    home: &Path,
    recipient: RecipientKey,
    params: Option<&str>,
) -> Result<NodeIdentity, Failure> {
    let params: Params =
        serde_json::from_str(params.unwrap_or("{}")).map_err(|_| invalid("Invalid parameters"))?;
    // The form is checked before anything else, so a malformed request
    // never opens anything; the key file before the ciphertext (0008).
    let sealed = match (params.sealed, params.ephemeral) {
        (Some(sealed), None) => Some(sealed),
        (None, Some(true)) => None,
        _ => return Err(invalid("rad.identity takes sealed or ephemeral: true")),
    };
    if key_file_present(home) {
        drop(recipient);
        return Err(Failure(ErrorBody::new(
            ErrorCode::KeyFilePresent,
            "keys/radicle exists",
        )));
    }
    let ephemeral = sealed.is_none();
    let seed = match sealed {
        Some(sealed) => open(recipient, &sealed)?,
        None => {
            drop(recipient);
            throwaway()?
        }
    };
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    let id = radicle::prelude::NodeId::from_bytes(public);
    let nid = id.to_human();
    Ok(NodeIdentity {
        seed: Some(seed),
        id,
        did: format!("did:key:{nid}"),
        nid,
        ephemeral,
    })
}

/// Opens the sealed key with this start's key, which the attempt consumes.
fn open(recipient: RecipientKey, sealed: &Sealed) -> Result<Zeroizing<[u8; 32]>, Failure> {
    let bad = || {
        Failure(ErrorBody::new(
            ErrorCode::BadSealedKey,
            "the sealed key does not open",
        ))
    };
    let enc = STANDARD.decode(sealed.enc.as_bytes()).map_err(|_| bad());
    let ciphertext = STANDARD
        .decode(sealed.ciphertext.as_bytes())
        .map_err(|_| bad());
    // Consumed either way: a ciphertext opens in one process, once.
    let (Ok(enc), Ok(ciphertext)) = (enc, ciphertext) else {
        drop(recipient);
        return Err(bad());
    };
    let ciphertext = Zeroizing::new(ciphertext);
    recipient.open(&enc, &ciphertext).map_err(|_| bad())
}

/// A throwaway node key from the OS's randomness (0008, "Profiles without a
/// vault"): made in memory and never written.
fn throwaway() -> Result<Zeroizing<[u8; 32]>, Failure> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut_slice())
        .map_err(|_| Failure(ErrorBody::new(ErrorCode::Internal, "Internal error")))?;
    Ok(seed)
}

/// Whether anything exists at `keys/radicle`, as `lstat` sees it: a file, a
/// directory, or a symlink, even a dangling one. An answer the service
/// can't read counts as present: it never starts beside a key it couldn't
/// rule out.
pub fn key_file_present(home: &Path) -> bool {
    match std::fs::symlink_metadata(home.join("keys").join("radicle")) {
        Ok(_) => true,
        Err(e) => !matches!(
            e.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
        ),
    }
}

/// `getrandom`, as a fallible crypto RNG.
pub struct OsRng;

impl rand_core::TryRng for OsRng {
    type Error = getrandom::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst)
    }
}

impl rand_core::TryCryptoRng for OsRng {}

#[cfg(test)]
mod tests;
