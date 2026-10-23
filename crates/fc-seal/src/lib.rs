//! The sealed release of the Radicle node key (design 0008, "The sealed
//! release"): HPKE (RFC 9180) in base mode, single-shot, for exactly one
//! suite:
//!
//! - KEM: DHKEM(X25519, HKDF-SHA256), `0x0020`;
//! - KDF: HKDF-SHA256, `0x0001`;
//! - AEAD: AES-256-GCM, `0x0002`;
//! - `info`: [`INFO`]; `aad`: empty.
//!
//! The core seals the 32-byte Ed25519 secret seed with [`seal`], to the
//! public key the service made for that one start ([`RecipientKey`]). The
//! service opens it once with [`RecipientKey::open`], which consumes the
//! private half, so a ciphertext opens in one process, once, and one
//! captured from an earlier start opens nowhere.
//!
//! **The implementation is the `hpke` crate** (0.14.1, pinned exactly),
//! which resolves to the RustCrypto versions the workspace already uses
//! (`aead` 0.6, `aes-gcm` 0.11, `hmac` 0.13, `sha2` 0.11, `curve25519-dalek`
//! 5), so it adds no second version of any of them. It refuses an all-zero
//! X25519 shared secret on both sides, as RFC 9180 §7.1.4 requires, and
//! wipes its DH outputs, key schedule and AEAD keys. One residual: `hkdf`
//! computes HMAC with the `hmac` crate, which leaves its key pads unwiped
//! (fc-keys writes its own HMAC for that reason). Those pads hold this
//! seal's PRKs, which reach nothing beyond the one key sealed with them, and
//! the processes that compute them hold that key in plaintext anyway.
//!
//! **Randomness** is the caller's, through a fallible RNG: an RNG failure
//! is an error, never a panic, and no key is derived from fewer than 32
//! fresh bytes.

use hpke::aead::{AeadTag, AesGcm256};
use hpke::inout::InOutBuf;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use rand_core::{TryCryptoRng, TryRng};
use zeroize::{Zeroize, Zeroizing};

/// The KEM of the one suite.
pub type Kem = X25519HkdfSha256;
/// The KDF of the one suite.
pub type Kdf = HkdfSha256;
/// The AEAD of the one suite.
pub type Aead = AesGcm256;

/// The `info` every seal binds: the release's purpose and version.
pub const INFO: &[u8] = b"freedom-radicle-node-key/1";
/// The plaintext: the 32-byte Ed25519 secret seed (RFC 8032).
pub const KEY_LEN: usize = 32;
/// HPKE's encapsulated key (`enc`): an X25519 public key.
pub const ENC_LEN: usize = 32;
/// The ciphertext: the sealed key and its 16-byte tag.
pub const CIPHERTEXT_LEN: usize = KEY_LEN + TAG_LEN;
/// A public key the service names as the recipient.
pub const PUBLIC_KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
/// The keying material of one X25519 key pair (`Nsk`).
const IKM_LEN: usize = 32;

/// A sealed node key: what the core returns and main relays.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    pub enc: [u8; ENC_LEN],
    pub ciphertext: [u8; CIPHERTEXT_LEN],
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealed").finish_non_exhaustive()
    }
}

/// Why a seal failed. The key is wiped either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The recipient gives the all-zero shared secret: a low-order point.
    InvalidRecipient,
    /// The OS random number generator failed.
    Rng,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SealError::InvalidRecipient => "the recipient is not a usable X25519 public key",
            SealError::Rng => "the OS random number generator failed",
        })
    }
}

impl std::error::Error for SealError {}

/// Why an open failed: it doesn't open with this key, or doesn't hold a
/// key. One kind, so the answer says nothing about which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenError;

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the sealed key does not open")
    }
}

impl std::error::Error for OpenError {}

/// The OS random number generator failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngError;

impl std::fmt::Display for RngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the OS random number generator failed")
    }
}

impl std::error::Error for RngError {}

/// Seals `key` to `recipient`, with [`INFO`] and an empty `aad`.
///
/// The ephemeral key pair is derived from 32 bytes `rng` gives, as HPKE's
/// key generation does (`DeriveKeyPair` over random keying material).
pub fn seal<R: TryCryptoRng + ?Sized>(
    recipient: &[u8; PUBLIC_KEY_LEN],
    key: &[u8; KEY_LEN],
    rng: &mut R,
) -> Result<Sealed, SealError> {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(recipient)
        .map_err(|_| SealError::InvalidRecipient)?;
    let mut ikm = Zeroizing::new([0u8; IKM_LEN]);
    rng.try_fill_bytes(ikm.as_mut_slice())
        .map_err(|_| SealError::Rng)?;
    let mut fixed = FixedRng::new(&ikm);
    let mut buffer = Zeroizing::new(*key);
    let sealed = hpke::single_shot_seal_inout_detached_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        INFO,
        InOutBuf::from(buffer.as_mut_slice()),
        &[],
        &mut fixed,
    );
    let exhausted = fixed.overrun;
    let (encapped, tag) = sealed.map_err(|_| SealError::InvalidRecipient)?;
    if exhausted {
        // The KEM asked for more keying material than one key pair needs:
        // never seal with bytes this function didn't draw.
        return Err(SealError::Rng);
    }
    let mut enc = [0u8; ENC_LEN];
    enc.copy_from_slice(&encapped.to_bytes());
    let mut ciphertext = [0u8; CIPHERTEXT_LEN];
    ciphertext[..KEY_LEN].copy_from_slice(buffer.as_slice());
    ciphertext[KEY_LEN..].copy_from_slice(&tag.to_bytes());
    Ok(Sealed { enc, ciphertext })
}

/// The service's key pair for one start. The private half wipes on drop,
/// and [`RecipientKey::open`] consumes it: one attempt, whatever its result.
pub struct RecipientKey {
    secret: <Kem as hpke::Kem>::PrivateKey,
    public: [u8; PUBLIC_KEY_LEN],
}

impl std::fmt::Debug for RecipientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecipientKey").finish_non_exhaustive()
    }
}

impl RecipientKey {
    /// A new key pair, from 32 bytes `rng` gives (HPKE's `DeriveKeyPair`).
    pub fn generate<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, RngError> {
        let mut ikm = Zeroizing::new([0u8; IKM_LEN]);
        rng.try_fill_bytes(ikm.as_mut_slice())
            .map_err(|_| RngError)?;
        Ok(Self::from_ikm(&ikm))
    }

    /// The key pair HPKE's `DeriveKeyPair` gives for `ikm`.
    fn from_ikm(ikm: &[u8; IKM_LEN]) -> Self {
        let (secret, public) = <Kem as hpke::Kem>::derive_keypair(ikm);
        let mut bytes = [0u8; PUBLIC_KEY_LEN];
        bytes.copy_from_slice(&public.to_bytes());
        Self {
            secret,
            public: bytes,
        }
    }

    /// The public half, which `rad.hello` names as `recipient`.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public
    }

    /// Opens a sealed key: `enc` and `ciphertext` as main relayed them.
    /// Anything but a 32-byte `enc` and a 48-byte ciphertext that opens
    /// under this key, [`INFO`] and an empty `aad` is an [`OpenError`].
    /// The private half is dropped, and wiped, before this returns.
    pub fn open(
        self,
        enc: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, OpenError> {
        let Self { secret, .. } = self;
        if enc.len() != ENC_LEN || ciphertext.len() != CIPHERTEXT_LEN {
            return Err(OpenError);
        }
        let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| OpenError)?;
        let tag = AeadTag::<Aead>::from_bytes(&ciphertext[KEY_LEN..]).map_err(|_| OpenError)?;
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&ciphertext[..KEY_LEN]);
        let opened = hpke::single_shot_open_inout_detached::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &secret,
            &encapped,
            INFO,
            InOutBuf::from(key.as_mut_slice()),
            &[],
            &tag,
        );
        drop(secret);
        match opened {
            Ok(()) => Ok(key),
            Err(_) => Err(OpenError),
        }
    }
}

/// Hands the KEM exactly the keying material [`seal`] drew. Asked for
/// more, it gives zeros and records the overrun, and [`seal`] refuses the
/// result: hpke's `TryRng` here can't fail.
struct FixedRng<'a> {
    ikm: &'a [u8; IKM_LEN],
    used: usize,
    overrun: bool,
}

impl<'a> FixedRng<'a> {
    fn new(ikm: &'a [u8; IKM_LEN]) -> Self {
        Self {
            ikm,
            used: 0,
            overrun: false,
        }
    }
}

impl TryRng for FixedRng<'_> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        let value = u32::from_le_bytes(bytes);
        bytes.zeroize();
        Ok(value)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        let value = u64::from_le_bytes(bytes);
        bytes.zeroize();
        Ok(value)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let available = IKM_LEN - self.used;
        let n = dst.len().min(available);
        dst[..n].copy_from_slice(&self.ikm[self.used..self.used + n]);
        self.used += n;
        if n < dst.len() {
            dst[n..].fill(0);
            self.overrun = true;
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for FixedRng<'_> {}

#[cfg(test)]
mod tests;
