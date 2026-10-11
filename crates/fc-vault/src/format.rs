//! The `identity-vault.json` file, byte-compatible with freedom-browser's
//! `vault.js` and `@metamask/browser-passworder` 6:
//!
//! ```text
//! {
//!   "version": 1,
//!   "encrypted": "<payload JSON as a string>",
//!   "createdAt": "2026-10-11T19:47:02.123Z"
//! }
//! ```
//!
//! 2-space indentation and no trailing newline. The payload is compact JSON
//! `{"data","iv","keyMetadata","salt"}`:
//!
//! - **KDF:** PBKDF2-HMAC-SHA-256 over the password's UTF-8 bytes (no
//!   normalization), a 32-byte salt, and `keyMetadata.params.iterations`
//!   (900,000 when writing). Without `keyMetadata`, the legacy 10,000.
//! - **Cipher:** AES-256-GCM with a 16-byte IV (not the usual 12). `data` is
//!   ciphertext followed by the 16-byte tag.
//! - **Encoding:** `data`, `iv` and `salt` are standard padded base64.
//! - **Plaintext:** `JSON.stringify({ mnemonic })`.

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::aes::Aes256;
use aes_gcm::{AesGcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use fc_keys::Mnemonic;
use rand_core::TryCryptoRng;
use serde::Deserialize;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::Error;

type Aes256Gcm16 = AesGcm<Aes256, aes_gcm::aead::consts::U16>;

/// Iterations for newly written vaults (passworder's default).
pub const ITERATIONS: u32 = 900_000;
/// Iterations passworder assumes when `keyMetadata` is missing.
pub const LEGACY_ITERATIONS: u32 = 10_000;
/// The highest iteration count `open` accepts, so a crafted file can't make
/// unlock run for hours. Freedom only ever wrote 900,000.
pub const MAX_ITERATIONS: u32 = 10_000_000;

/// The random and time inputs of one vault file. Fixed values reproduce a
/// file exactly; [`SealParams::random`] is what new vaults use.
#[derive(Clone)]
pub struct SealParams {
    pub salt: [u8; 32],
    pub iv: [u8; 16],
    pub iterations: u32,
    /// `new Date().toISOString()` at creation; see [`iso_timestamp`].
    pub created_at: String,
}

impl SealParams {
    pub fn random<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
        created_at: String,
    ) -> Result<Self, Error> {
        let mut params = SealParams {
            salt: [0; 32],
            iv: [0; 16],
            iterations: ITERATIONS,
            created_at,
        };
        rng.try_fill_bytes(&mut params.salt)
            .map_err(|_| Error::Randomness)?;
        rng.try_fill_bytes(&mut params.iv)
            .map_err(|_| Error::Randomness)?;
        Ok(params)
    }
}

impl std::fmt::Debug for SealParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealParams")
            .field("iterations", &self.iterations)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// Writes a vault file for `mnemonic`, encrypted with `password` (its UTF-8
/// bytes, as `Buffer.from(password, 'utf8')` produces them).
pub fn seal(mnemonic: &Mnemonic, password: &[u8], params: &SealParams) -> Result<String, Error> {
    let key = derive_key(password, &params.salt, params.iterations)?;
    let cipher = Aes256Gcm16::new(&key);

    // JSON.stringify({ mnemonic }); sized up front so it never reallocates.
    let phrase = mnemonic.phrase();
    let mut buffer = Zeroizing::new(Vec::with_capacity(phrase.len() * 6 + 32));
    serde_json::to_writer(&mut *buffer, &Plaintext { mnemonic: phrase })
        .map_err(|_| Error::Internal("plaintext encoding"))?;
    cipher
        .encrypt_in_place(&Nonce::from(params.iv), b"", &mut *buffer)
        .map_err(|_| Error::Internal("AES-GCM encryption"))?;

    let payload = format!(
        r#"{{"data":"{}","iv":"{}","keyMetadata":{{"algorithm":"PBKDF2","params":{{"iterations":{}}}}},"salt":"{}"}}"#,
        STANDARD.encode(buffer.as_slice()),
        STANDARD.encode(params.iv),
        params.iterations,
        STANDARD.encode(params.salt),
    );
    let encrypted =
        serde_json::to_string(&payload).map_err(|_| Error::Internal("payload encoding"))?;
    let created_at = serde_json::to_string(&params.created_at)
        .map_err(|_| Error::Internal("timestamp encoding"))?;
    Ok(format!(
        "{{\n  \"version\": 1,\n  \"encrypted\": {encrypted},\n  \"createdAt\": {created_at}\n}}"
    ))
}

/// The result of opening a vault file.
pub struct Opened {
    pub mnemonic: Mnemonic,
    /// The PBKDF2 iteration count the file used.
    pub iterations: u32,
}

impl std::fmt::Debug for Opened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("iterations", &self.iterations)
            .finish_non_exhaustive()
    }
}

#[derive(serde::Serialize)]
struct Plaintext<'a> {
    mnemonic: &'a str,
}

#[derive(Deserialize)]
struct Envelope {
    /// `None` when the field is missing (`undefined` in JS); an explicit
    /// `null` stays `Some(Null)`.
    #[serde(default, deserialize_with = "present")]
    version: Option<serde_json::Value>,
    encrypted: Option<String>,
}

fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<serde_json::Value>, D::Error> {
    serde_json::Value::deserialize(d).map(Some)
}

#[derive(Deserialize)]
struct Payload {
    data: String,
    iv: String,
    salt: String,
    #[serde(rename = "keyMetadata")]
    key_metadata: Option<KeyMetadata>,
}

#[derive(Deserialize)]
struct KeyMetadata {
    algorithm: String,
    params: KeyParams,
}

#[derive(Deserialize)]
struct KeyParams {
    iterations: u32,
}

#[derive(Deserialize)]
struct DecryptedPlaintext {
    mnemonic: Zeroizing<String>,
}

/// Reads the envelope and returns the passworder payload string, with the
/// checks `vault.js` makes before decrypting (`version === 1`).
pub fn read_envelope(file: &str) -> Result<String, Error> {
    let envelope: Envelope =
        serde_json::from_str(file).map_err(|_| Error::Corrupt("vault file is not valid JSON"))?;
    match &envelope.version {
        // JS compares numbers, so `1.0` counts as 1 too.
        Some(version) if version.as_f64() == Some(1.0) => {}
        Some(version) => return Err(Error::UnsupportedVersion(js_string(version))),
        None => return Err(Error::UnsupportedVersion("undefined".into())),
    }
    envelope
        .encrypted
        .ok_or(Error::Corrupt("missing encrypted payload"))
}

/// Decrypts a vault file with `password` (UTF-8 bytes).
pub fn open(file: &str, password: &[u8]) -> Result<Opened, Error> {
    let payload_json = read_envelope(file)?;
    let payload: Payload = serde_json::from_str(&payload_json)
        .map_err(|_| Error::Corrupt("payload is not valid JSON"))?;
    let iterations = match &payload.key_metadata {
        None => LEGACY_ITERATIONS,
        Some(meta) if meta.algorithm == "PBKDF2" => meta.params.iterations,
        Some(_) => return Err(Error::Corrupt("unsupported key derivation algorithm")),
    };
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err(Error::Corrupt("iteration count out of range"));
    }
    let salt = decode(&payload.salt, "salt")?;
    let iv: [u8; 16] = decode(&payload.iv, "iv")?
        .try_into()
        .map_err(|_| Error::Corrupt("iv is not 16 bytes"))?;
    let mut buffer = Zeroizing::new(decode(&payload.data, "data")?);

    let key = derive_key(password, &salt, iterations)?;
    Aes256Gcm16::new(&key)
        .decrypt_in_place(&Nonce::from(iv), b"", &mut *buffer)
        // passworder reports every authentication failure this way.
        .map_err(|_| Error::IncorrectPassword)?;

    let plaintext: DecryptedPlaintext = serde_json::from_slice(buffer.as_slice())
        .map_err(|_| Error::Corrupt("decrypted data is not the expected JSON"))?;
    let mnemonic =
        Mnemonic::parse(&plaintext.mnemonic).map_err(|_| Error::InvalidDecryptedMnemonic)?;
    Ok(Opened {
        mnemonic,
        iterations,
    })
}

/// The JS `password.length >= 8` check: UTF-16 code units, not bytes or
/// characters.
pub fn is_strong_enough(password: &str) -> bool {
    password.encode_utf16().count() >= 8
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<aes_gcm::Key<Aes256Gcm16>>, Error> {
    let mut key = Zeroizing::new(aes_gcm::Key::<Aes256Gcm16>::default());
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, key.as_mut_slice());
    Ok(key)
}

fn decode(value: &str, field: &'static str) -> Result<Vec<u8>, Error> {
    STANDARD.decode(value).map_err(|_| Error::Corrupt(field))
}

/// `${value}` in JS, for the "Unsupported vault version: …" message.
fn js_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".into(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) => i.to_string(),
            // JS prints integral floats without a fraction: `${2.0}` is "2".
            (None, Some(f)) if f.fract() == 0.0 && f.abs() < 1e21 => format!("{f:.0}"),
            _ => n.to_string(),
        },
        serde_json::Value::Array(_) => "[array]".into(),
        serde_json::Value::Object(_) => "[object Object]".into(),
    }
}

/// `new Date(millis).toISOString()`, without reading a clock.
pub fn iso_timestamp(unix_millis: u64) -> String {
    let millis = unix_millis % 1000;
    let secs = unix_millis / 1000;
    let (hour, minute, second) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_timestamps() {
        assert_eq!(iso_timestamp(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_timestamp(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(iso_timestamp(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
        assert_eq!(iso_timestamp(4_102_444_799_999), "2099-12-31T23:59:59.999Z");
    }

    #[test]
    fn strength_counts_utf16_units() {
        assert!(!is_strong_enough("1234567"));
        assert!(is_strong_enough("12345678"));
        assert!(
            is_strong_enough(&"\u{1f510}".repeat(4)),
            "4 emoji = 8 UTF-16 units"
        );
        assert!(!is_strong_enough("ééééééé"));
    }

    #[test]
    fn unsupported_versions_render_like_js() {
        assert_eq!(
            read_envelope(r#"{"version": 2, "encrypted": "x"}"#).unwrap_err(),
            Error::UnsupportedVersion("2".into())
        );
        assert_eq!(
            read_envelope(r#"{"version": 1.0, "encrypted": "x"}"#).unwrap(),
            "x"
        );
        assert_eq!(
            read_envelope(r#"{"version": 2.0, "encrypted": "x"}"#).unwrap_err(),
            Error::UnsupportedVersion("2".into())
        );
        assert_eq!(
            read_envelope(r#"{"version": "1", "encrypted": "x"}"#).unwrap_err(),
            Error::UnsupportedVersion("1".into())
        );
        assert_eq!(
            read_envelope(r#"{"version": null, "encrypted": "x"}"#).unwrap_err(),
            Error::UnsupportedVersion("null".into())
        );
        assert_eq!(
            read_envelope(r#"{"encrypted": "x"}"#).unwrap_err(),
            Error::UnsupportedVersion("undefined".into())
        );
        assert!(matches!(read_envelope("{"), Err(Error::Corrupt(_))));
    }
}
