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
type Aes256Gcm12 = AesGcm<Aes256, aes_gcm::aead::consts::U12>;

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
    /// `None` when missing (legacy 10k); an explicit `null` stays
    /// `Some(Null)`, which passworder fails on.
    #[serde(rename = "keyMetadata", default, deserialize_with = "present")]
    key_metadata: Option<serde_json::Value>,
}

/// The decrypted plaintext, with the mnemonic kept as raw JSON so it is
/// unescaped into a `Zeroizing` buffer by [`unescape_json_string`], never
/// through serde_json's scratch buffer.
#[derive(Deserialize)]
struct DecryptedPlaintext<'a> {
    #[serde(borrow, default)]
    mnemonic: Option<&'a serde_json::value::RawValue>,
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

/// Decrypts a vault file with `password` (UTF-8 bytes), accepting what
/// passworder's reader accepts: Node's lenient base64, 12- or 16-byte IVs,
/// iteration counts as numbers or numeric strings, any algorithm label.
pub fn open(file: &str, password: &[u8]) -> Result<Opened, Error> {
    let payload_json = read_envelope(file)?;
    let payload: Payload = serde_json::from_str(&payload_json)
        .map_err(|_| Error::Corrupt("payload is not valid JSON"))?;
    let iterations = iterations_of(payload.key_metadata.as_ref())?;
    check_iterations(iterations)?;
    let salt = node_base64(&payload.salt, "salt")?;
    let iv = node_base64(&payload.iv, "iv")?;
    let mut buffer = Zeroizing::new(node_base64(&payload.data, "data")?);

    let key = derive_key(password, &salt, iterations)?;
    // passworder reports every authentication failure as a wrong password.
    match iv.len() {
        16 => Aes256Gcm16::new(&key)
            .decrypt_in_place(
                &Nonce::from(
                    <[u8; 16]>::try_from(iv.as_slice()).map_err(|_| Error::Internal("iv"))?,
                ),
                b"",
                &mut *buffer,
            )
            .map_err(|_| Error::IncorrectPassword)?,
        12 => Aes256Gcm12::new(&key)
            .decrypt_in_place(
                &Nonce::from(
                    <[u8; 12]>::try_from(iv.as_slice()).map_err(|_| Error::Internal("iv"))?,
                ),
                b"",
                &mut *buffer,
            )
            .map_err(|_| Error::IncorrectPassword)?,
        _ => return Err(Error::Corrupt("iv is neither 12 nor 16 bytes")),
    }

    // passworder parses inside the same try as decryption, so malformed
    // plaintext JSON is also "Incorrect password".
    let plaintext: DecryptedPlaintext<'_> =
        match serde_json::from_slice::<serde::de::IgnoredAny>(buffer.as_slice()) {
            Err(_) => return Err(Error::IncorrectPassword),
            // Valid JSON of another shape: `decrypted.mnemonic` is undefined.
            Ok(_) => serde_json::from_slice(buffer.as_slice())
                .map_err(|_| Error::InvalidDecryptedMnemonic)?,
        };
    let raw = plaintext.mnemonic.ok_or(Error::InvalidDecryptedMnemonic)?;
    let phrase = unescape_json_string(raw.get()).ok_or(Error::InvalidDecryptedMnemonic)?;
    let mnemonic = Mnemonic::parse(&phrase).map_err(|_| Error::InvalidDecryptedMnemonic)?;
    Ok(Opened {
        mnemonic,
        iterations,
    })
}

/// passworder's `keyMetadata.params.iterations`, converted as WebCrypto's
/// `unsigned long` would be: integral numbers, or numeric strings.
fn iterations_of(meta: Option<&serde_json::Value>) -> Result<u32, Error> {
    let Some(meta) = meta else {
        return Ok(LEGACY_ITERATIONS);
    };
    let value = meta
        .get("params")
        .and_then(|params| params.get("iterations"))
        .ok_or(Error::Corrupt("keyMetadata has no params.iterations"))?;
    let number = match value {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
    .ok_or(Error::Corrupt("iteration count is not a number"))?;
    if number.fract() != 0.0 || !(1.0..=f64::from(MAX_ITERATIONS)).contains(&number) {
        return Err(Error::Corrupt("iteration count out of range"));
    }
    // In range and integral, so the conversion is exact.
    Ok(number as u32)
}

fn check_iterations(iterations: u32) -> Result<(), Error> {
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err(Error::Corrupt("iteration count out of range"));
    }
    Ok(())
}

/// Unescapes a JSON string literal (with its quotes) into an exactly
/// bounded `Zeroizing` buffer. `None` for a lone surrogate, which JS would
/// keep and then reject as an ill-formed mnemonic.
fn unescape_json_string(raw: &str) -> Option<Zeroizing<String>> {
    let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
    // Unescaping never lengthens the text, so this never reallocates.
    let mut out = Zeroizing::new(String::with_capacity(inner.len()));
    let mut chars = inner.chars();
    let hex4 = |chars: &mut std::str::Chars<'_>| -> Option<u32> {
        let mut value = 0;
        for _ in 0..4 {
            value = value * 16 + chars.next()?.to_digit(16)?;
        }
        Some(value)
    };
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let unescaped = match chars.next()? {
            '"' => '"',
            '\\' => '\\',
            '/' => '/',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'u' => {
                let unit = hex4(&mut chars)?;
                if (0xD800..0xDC00).contains(&unit) {
                    if chars.next()? != '\\' || chars.next()? != 'u' {
                        return None;
                    }
                    let low = hex4(&mut chars)?;
                    if !(0xDC00..0xE000).contains(&low) {
                        return None;
                    }
                    char::from_u32(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00))?
                } else {
                    char::from_u32(unit)?
                }
            }
            _ => return None,
        };
        out.push(unescaped);
    }
    Some(out)
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
    let rounds = std::num::NonZeroU32::new(iterations)
        .filter(|rounds| rounds.get() <= MAX_ITERATIONS)
        .ok_or(Error::InvalidParams("iteration count out of range"))?;
    // fc-keys' PBKDF2 wipes its key pads and round buffers; the pbkdf2
    // crate doesn't.
    let derived = fc_keys::kdf::pbkdf2::<Sha256, 32>(password, salt, rounds);
    let mut key = Zeroizing::new(aes_gcm::Key::<Aes256Gcm16>::default());
    key.copy_from_slice(derived.as_slice());
    Ok(key)
}

/// `Buffer.from(value, 'base64')` as passworder uses it: whitespace is
/// ignored, the URL-safe alphabet is accepted, and padding is optional.
/// Other characters make the file corrupt.
fn node_base64(value: &str, field: &'static str) -> Result<Vec<u8>, Error> {
    let mut cleaned = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            c if c.is_ascii_whitespace() => {}
            '-' => cleaned.push('+'),
            '_' => cleaned.push('/'),
            c => cleaned.push(c),
        }
    }
    let unpadded = cleaned.trim_end_matches('=');
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(unpadded)
        .map_err(|_| Error::Corrupt(field))
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
        // Array.prototype.toString: elements joined by commas, null as "".
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| match item {
                serde_json::Value::Null => String::new(),
                other => js_string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        serde_json::Value::Object(_) => "[object Object]".into(),
    }
}

/// The latest time a JS `Date` can represent.
const MAX_DATE_MILLIS: u64 = 8_640_000_000_000_000;

/// `new Date(millis).toISOString()`, without reading a clock. Years after
/// 9999 use Date's `+YYYYYY` form; times a `Date` can't hold are an error.
pub fn iso_timestamp(unix_millis: u64) -> Result<String, Error> {
    if unix_millis > MAX_DATE_MILLIS {
        return Err(Error::InvalidParams("time beyond the JS Date range"));
    }
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
    let year = if year > 9999 {
        format!("+{year:06}")
    } else {
        format!("{year:04}")
    };
    Ok(format!(
        "{year}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// A vault file around arbitrary `plaintext`, at 1,000 iterations.
    fn file_with(plaintext: &[u8], password: &[u8], iv_len: usize, meta: &str) -> String {
        let salt = [3u8; 32];
        let key = derive_key(password, &salt, 1000).unwrap();
        let mut buffer = plaintext.to_vec();
        let iv: Vec<u8> = (0..iv_len as u8).collect();
        match iv_len {
            16 => Aes256Gcm16::new(&key)
                .encrypt_in_place(
                    &Nonce::from(<[u8; 16]>::try_from(iv.as_slice()).unwrap()),
                    b"",
                    &mut buffer,
                )
                .unwrap(),
            _ => Aes256Gcm12::new(&key)
                .encrypt_in_place(
                    &Nonce::from(<[u8; 12]>::try_from(iv.as_slice()).unwrap()),
                    b"",
                    &mut buffer,
                )
                .unwrap(),
        }
        let payload = format!(
            r#"{{"data":"{}","iv":"{}"{meta},"salt":"{}"}}"#,
            STANDARD.encode(&buffer),
            STANDARD.encode(&iv),
            STANDARD.encode(salt),
        );
        format!(
            r#"{{"version":1,"encrypted":{}}}"#,
            serde_json::to_string(&payload).unwrap()
        )
    }

    const META_1000: &str = r#","keyMetadata":{"algorithm":"PBKDF2","params":{"iterations":1000}}"#;

    #[test]
    fn opens_reference_compatible_variants() {
        let plaintext = format!(r#"{{"mnemonic":"{PHRASE}"}}"#);
        // 12-byte IV, as passworder can also read.
        let file = file_with(plaintext.as_bytes(), b"password", 12, META_1000);
        assert_eq!(open(&file, b"password").unwrap().mnemonic.phrase(), PHRASE);
        // Iterations as a numeric string and as an integral float; any label.
        for meta in [
            r#","keyMetadata":{"algorithm":"PBKDF2","params":{"iterations":"1000"}}"#,
            r#","keyMetadata":{"algorithm":"PBKDF2","params":{"iterations":1000.0}}"#,
            r#","keyMetadata":{"algorithm":"anything","params":{"iterations":1000}}"#,
        ] {
            let file = file_with(plaintext.as_bytes(), b"password", 16, meta);
            assert_eq!(open(&file, b"password").unwrap().iterations, 1000, "{meta}");
        }
        // An explicit null keyMetadata fails in passworder.
        let file = file_with(
            plaintext.as_bytes(),
            b"password",
            16,
            r#","keyMetadata":null"#,
        );
        assert!(matches!(open(&file, b"password"), Err(Error::Corrupt(_))));
    }

    #[test]
    fn node_base64_variants() {
        let canonical = STANDARD.encode([0xfbu8, 0xff, 0x01, 0x02]);
        assert_eq!(canonical, "+/8BAg==");
        for variant in ["+/8BAg==", "+/8BAg", "-_8BAg==", " +/8B\nAg== "] {
            assert_eq!(
                node_base64(variant, "x").unwrap(),
                [0xfb, 0xff, 0x01, 0x02],
                "{variant:?}"
            );
        }
        assert!(node_base64("+/8B*g==", "x").is_err());
    }

    #[test]
    fn decrypted_plaintext_edge_cases() {
        let open_plain = |plaintext: &[u8]| {
            open(
                &file_with(plaintext, b"password", 16, META_1000),
                b"password",
            )
        };
        // Escaped JSON decodes like JSON.parse would.
        let escaped = format!(
            r#"{{"mnemonic":"{}"}}"#,
            PHRASE.replacen('a', "BSu0061", 1).replace("BS", "\\")
        );
        assert_eq!(
            open_plain(escaped.as_bytes()).unwrap().mnemonic.phrase(),
            PHRASE
        );
        // A lone surrogate is an ill-formed mnemonic.
        let lone = format!(r#"{{"mnemonic":"BSud800{PHRASE}"}}"#).replace("BS", "\\");
        assert_eq!(
            open_plain(lone.as_bytes()).unwrap_err(),
            Error::InvalidDecryptedMnemonic
        );
        // Malformed JSON is reported as passworder does.
        assert_eq!(
            open_plain(b"{not json").unwrap_err(),
            Error::IncorrectPassword
        );
        // Valid JSON without a usable mnemonic.
        for plaintext in [
            &br#"{}"#[..],
            br#"{"mnemonic":5}"#,
            b"5",
            br#"{"mnemonic":"zoo"}"#,
        ] {
            assert_eq!(
                open_plain(plaintext).unwrap_err(),
                Error::InvalidDecryptedMnemonic
            );
        }
    }

    #[test]
    fn unescape_matches_json() {
        let escaped_unicode = format!("\"{}\"", "BSu00e9BSud83dBSudd10").replace("BS", "\\");
        for raw in [
            r#""plain""#,
            r#""a\"b\\c\/d\b\f\n\r\t""#,
            escaped_unicode.as_str(),
        ] {
            let ours = unescape_json_string(raw).unwrap();
            let reference: String = serde_json::from_str(raw).unwrap();
            assert_eq!(ours.as_str(), reference, "{raw}");
            assert!(ours.capacity() <= raw.len());
        }
        assert!(unescape_json_string(r#""\ud800""#).is_none());
        assert!(unescape_json_string(r#""\udc00""#).is_none());
    }

    #[test]
    fn seal_refuses_out_of_range_iterations() {
        let mnemonic = Mnemonic::parse(PHRASE).unwrap();
        for iterations in [0, MAX_ITERATIONS + 1] {
            let params = SealParams {
                salt: [0; 32],
                iv: [0; 16],
                iterations,
                created_at: "x".into(),
            };
            assert!(matches!(
                seal(&mnemonic, b"password", &params),
                Err(Error::InvalidParams(_))
            ));
        }
    }

    #[test]
    fn version_arrays_render_like_js() {
        assert_eq!(
            read_envelope(r#"{"version": [1], "encrypted": "x"}"#).unwrap_err(),
            Error::UnsupportedVersion("1".into())
        );
        assert_eq!(
            read_envelope(r#"{"version": [null, 2, [3, 4]], "encrypted": "x"}"#).unwrap_err(),
            Error::UnsupportedVersion(",2,3,4".into())
        );
    }

    #[test]
    fn iso_timestamps() {
        assert_eq!(iso_timestamp(0).unwrap(), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            iso_timestamp(951_782_400_000).unwrap(),
            "2000-02-29T00:00:00.000Z"
        );
        assert_eq!(
            iso_timestamp(1_700_000_000_123).unwrap(),
            "2023-11-14T22:13:20.123Z"
        );
        assert_eq!(
            iso_timestamp(4_102_444_799_999).unwrap(),
            "2099-12-31T23:59:59.999Z"
        );
        assert_eq!(
            iso_timestamp(253_402_300_799_999).unwrap(),
            "9999-12-31T23:59:59.999Z"
        );
        assert_eq!(
            iso_timestamp(253_402_300_800_000).unwrap(),
            "+010000-01-01T00:00:00.000Z"
        );
        assert_eq!(
            iso_timestamp(MAX_DATE_MILLIS).unwrap(),
            "+275760-09-13T00:00:00.000Z"
        );
        assert!(iso_timestamp(MAX_DATE_MILLIS + 1).is_err());
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
