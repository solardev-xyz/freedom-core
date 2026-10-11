//! Secret fields on the wire (design 0001, "Input validation and secret
//! fields"). Secrets travel as base64 (or hex) strings, which contain no JSON
//! escapes, so serde_json hands them over as slices of the frame buffer and
//! never copies them into its scratch buffer. They're decoded straight into
//! exactly sized `Zeroizing` buffers.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use zeroize::Zeroizing;

/// The largest decoded secret field: 256 KiB (design 0001).
pub const MAX_SECRET_BYTES: usize = 256 * 1024;

/// Secret bytes received as a base64 string field.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes as UTF-8, for fields that carry text (mnemonics).
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.0)
    }

    pub fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Self {
        SecretBytes(bytes)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Base64Visitor;

        impl<'de> Visitor<'de> for Base64Visitor {
            type Value = SecretBytes;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a base64 string without escapes")
            }

            fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<SecretBytes, E> {
                decode(value).map_err(E::custom)
            }

            // An escaped string would arrive here, through serde_json's
            // scratch buffer. Base64 never needs escapes, so refuse it.
            fn visit_str<E: de::Error>(self, _value: &str) -> Result<SecretBytes, E> {
                Err(E::custom("secret fields must be unescaped base64"))
            }
        }

        deserializer.deserialize_str(Base64Visitor)
    }
}

fn decode(value: &str) -> Result<SecretBytes, &'static str> {
    // Padded base64 of MAX_SECRET_BYTES is this long; anything longer can't
    // decode to an allowed size.
    if value.len() > MAX_SECRET_BYTES.div_ceil(3) * 4 {
        return Err("secret field too long");
    }
    let estimate = value.len() / 4 * 3 + 3;
    let mut buffer = Zeroizing::new(vec![0u8; estimate]);
    let len = STANDARD
        .decode_slice(value, buffer.as_mut_slice())
        .map_err(|_| "secret field is not valid base64")?;
    buffer.truncate(len);
    if len > MAX_SECRET_BYTES {
        return Err("secret field too long");
    }
    Ok(SecretBytes(buffer))
}

/// Secret bytes to send as a base64 string field. Serializing streams the
/// base64 into the serializer's writer without an intermediate `String`, so
/// the only copy is the caller's `Zeroizing` output buffer.
///
/// This is the one audited `Serialize` for secrets that AGENTS.md rule 3
/// allows. It is used only for the design's outgoing secrets: the onboarding
/// phrase, the backup exports and the temporary `compat.*` keys.
pub struct SecretOut<'a>(pub &'a [u8]);

impl Serialize for SecretOut<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&base64::display::Base64Display::new(self.0, &STANDARD))
    }
}

impl fmt::Debug for SecretOut<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretOut(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Params {
        password_b64: SecretBytes,
    }

    #[test]
    fn decodes_borrowed_base64() {
        let params: Params = serde_json::from_slice(br#"{"password_b64":"cGFzc3dvcmQ="}"#).unwrap();
        assert_eq!(params.password_b64.as_bytes(), b"password");
        assert_eq!(params.password_b64.as_str().unwrap(), "password");
        assert_eq!(
            format!("{:?}", params.password_b64),
            "SecretBytes(<redacted>)"
        );
    }

    #[test]
    fn refuses_escaped_and_invalid_input() {
        // An escaped "c" (backslash u0063) would go through the scratch buffer.
        let mut escaped = br#"{"password_b64":"XGFzc3dvcmQ="}"#.to_vec();
        let at = escaped.iter().position(|b| *b == b'X').unwrap();
        escaped.splice(at..=at, [0x5c, b'u', b'0', b'0', b'6', b'3']);
        assert!(serde_json::from_slice::<Params>(&escaped).is_err());
        assert!(serde_json::from_slice::<Params>(br#"{"password_b64":"not base64!"}"#).is_err());
        assert!(serde_json::from_slice::<Params>(br#"{"password_b64":12}"#).is_err());
    }

    #[test]
    fn enforces_the_size_limit() {
        let ok = STANDARD.encode(vec![1u8; MAX_SECRET_BYTES]);
        let json = format!(r#"{{"password_b64":"{ok}"}}"#);
        assert_eq!(
            serde_json::from_str::<Params>(&json)
                .unwrap()
                .password_b64
                .as_bytes()
                .len(),
            MAX_SECRET_BYTES
        );
        let too_long = STANDARD.encode(vec![1u8; MAX_SECRET_BYTES + 1]);
        let json = format!(r#"{{"password_b64":"{too_long}"}}"#);
        assert!(serde_json::from_str::<Params>(&json).is_err());
    }

    #[test]
    fn serializes_without_intermediate_string() {
        #[derive(Serialize)]
        struct Out<'a> {
            mnemonic_b64: SecretOut<'a>,
        }
        let mut buffer = Zeroizing::new(Vec::with_capacity(64));
        serde_json::to_writer(
            &mut *buffer,
            &Out {
                mnemonic_b64: SecretOut(b"abandon"),
            },
        )
        .unwrap();
        assert_eq!(buffer.as_slice(), br#"{"mnemonic_b64":"YWJhbmRvbg=="}"#);
    }
}
