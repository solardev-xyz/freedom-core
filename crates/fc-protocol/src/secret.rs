//! Secret fields on the wire (design 0001, "Input validation and secret
//! fields").
//!
//! **Incoming:** a secret field is a JSON string of standard base64. Method
//! parameter structs declare it as a borrowed **raw token**
//! (`#[serde(borrow)] field: &'a RawValue`) and parse their parameters only
//! from the frame's own bytes (a slice). The token is converted with
//! [`SecretBytes::from_raw`]: it must be a plain quoted string with no
//! backslash, and it's decoded from the frame buffer straight into a
//! `Zeroizing` buffer.
//!
//! `SecretBytes` deliberately has no `Deserialize` implementation. With a
//! generic one, a reader-backed parse (`serde_json::from_reader`) would
//! buffer the raw token into an unwiped `Vec` before any check could refuse
//! it.
//!
//! **Outgoing:** there is no `Serialize` for secrets at all. Responses that
//! carry secrets are assembled by [`SecretResponse`]: it computes the exact
//! size first, allocates one `Zeroizing` buffer, and base64-encodes the
//! secret directly into it. There's no intermediate string, no chunk buffer,
//! and no reallocation.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use serde_json::value::RawValue;
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

impl SecretBytes {
    /// Decodes a borrowed raw JSON token, which must be `"<base64>"` with no
    /// escapes, into a `Zeroizing` buffer.
    pub fn from_raw(raw: &RawValue) -> Result<Self, &'static str> {
        decode_token(raw.get())
    }
}

/// Decodes a raw JSON token that must be `"<base64>"` with no escapes.
fn decode_token(token: &str) -> Result<SecretBytes, &'static str> {
    let inner = token
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .ok_or("secret fields must be base64 strings")?;
    if inner.contains('\\') {
        return Err("secret fields must be unescaped base64");
    }
    // Padded base64 of MAX_SECRET_BYTES is this long; anything longer can't
    // decode to an allowed size.
    if inner.len() > MAX_SECRET_BYTES.div_ceil(3) * 4 {
        return Err("secret field too long");
    }
    let mut buffer = Zeroizing::new(vec![0u8; inner.len() / 4 * 3 + 3]);
    let len = STANDARD
        .decode_slice(inner, buffer.as_mut_slice())
        .map_err(|_| "secret field is not valid base64")?;
    if len > MAX_SECRET_BYTES {
        return Err("secret field too long");
    }
    buffer.truncate(len);
    Ok(SecretBytes(buffer))
}

/// Builds a response frame payload that carries secrets:
/// `{"type":"response","id":…,"result":{"<public…>","<secret>":"<base64>"}}`
/// (or `"0x<hex>"` for [`SecretResponse::secret_hex`]).
///
/// This is the one audited path that writes secrets (AGENTS.md rule 3): the
/// onboarding phrase and the backup exports.
pub struct SecretResponse<'a> {
    id: u64,
    public: Vec<(&'static str, String)>,
    secrets: Vec<(&'static str, &'a [u8], Encoding)>,
}

/// A secret field's bytes and how they are encoded.
type SecretField<'s> = (&'s [u8], Encoding);

#[derive(Clone, Copy)]
enum Encoding {
    Base64,
    /// `0x` and lowercase hex, as ethers formats private keys.
    Hex,
}

impl Encoding {
    fn len(self, bytes: usize) -> usize {
        match self {
            Encoding::Base64 => bytes.div_ceil(3) * 4,
            Encoding::Hex => 2 + 2 * bytes,
        }
    }
}

/// A hex digit without a table lookup indexed by secret data.
fn hex_digit(nibble: u8) -> u8 {
    // 0xFF when nibble > 9, else 0.
    let letter = ((9i16 - i16::from(nibble)) >> 8) as u8;
    b'0' + nibble + (letter & (b'a' - b'0' - 10))
}

impl fmt::Debug for SecretResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretResponse")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<'a> SecretResponse<'a> {
    pub fn new(id: u64) -> Self {
        SecretResponse {
            id,
            public: Vec::new(),
            secrets: Vec::new(),
        }
    }

    /// Adds a public field. Its JSON is built separately; it holds no
    /// secrets.
    pub fn public<T: Serialize>(
        mut self,
        name: &'static str,
        value: &T,
    ) -> serde_json::Result<Self> {
        self.public.push((name, serde_json::to_string(value)?));
        Ok(self)
    }

    /// Adds a secret field, base64-encoded into the output.
    pub fn secret(mut self, name: &'static str, bytes: &'a [u8]) -> Self {
        self.secrets.push((name, bytes, Encoding::Base64));
        self
    }

    /// Adds a secret field as `0x` and lowercase hex (private keys, in the
    /// form ethers' `wallet.privateKey` has).
    pub fn secret_hex(mut self, name: &'static str, bytes: &'a [u8]) -> Self {
        self.secrets.push((name, bytes, Encoding::Hex));
        self
    }

    /// The JSON payload, in one exactly sized `Zeroizing` buffer.
    pub fn finish(self) -> Result<Zeroizing<Vec<u8>>, crate::message::IdError> {
        crate::message::check_id(self.id)?;
        let head = format!(r#"{{"type":"response","id":{},"result":{{"#, self.id);
        let mut fields: Vec<(String, Option<SecretField<'_>>)> = Vec::new();
        for (name, json) in &self.public {
            fields.push((format!(r#""{}":{}"#, field_name(name), json), None));
        }
        for (name, bytes, encoding) in &self.secrets {
            fields.push((
                format!(r#""{}":""#, field_name(name)),
                Some((*bytes, *encoding)),
            ));
        }
        let mut capacity = head.len() + 2; // "}}"
        for (index, (prefix, secret)) in fields.iter().enumerate() {
            capacity += prefix.len() + usize::from(index > 0);
            if let Some((bytes, encoding)) = secret {
                capacity += encoding.len(bytes.len()) + 1; // encoded + closing quote
            }
        }
        let mut out = Zeroizing::new(Vec::with_capacity(capacity));
        out.extend_from_slice(head.as_bytes());
        for (index, (prefix, secret)) in fields.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.extend_from_slice(prefix.as_bytes());
            if let Some((bytes, encoding)) = secret {
                match encoding {
                    Encoding::Base64 => {
                        let start = out.len();
                        out.resize(start + encoding.len(bytes.len()), 0);
                        // The slot is exactly the encoded length, so this
                        // can't fail.
                        let written = STANDARD.encode_slice(bytes, &mut out[start..]).unwrap_or(0);
                        out.truncate(start + written);
                    }
                    Encoding::Hex => {
                        out.extend_from_slice(b"0x");
                        for byte in bytes.iter() {
                            out.push(hex_digit(byte >> 4));
                            out.push(hex_digit(byte & 0x0f));
                        }
                    }
                }
                out.push(b'"');
            }
        }
        out.extend_from_slice(b"}}");
        debug_assert_eq!(out.capacity(), capacity, "no reallocation");
        Ok(out)
    }
}

/// Field names are fixed identifiers chosen in code, never caller input.
fn field_name(name: &'static str) -> &'static str {
    debug_assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Params<'a> {
        #[serde(borrow)]
        password_b64: &'a RawValue,
    }

    fn password(json: &[u8]) -> Result<SecretBytes, String> {
        let params: Params<'_> = serde_json::from_slice(json).map_err(|e| e.to_string())?;
        SecretBytes::from_raw(params.password_b64).map_err(str::to_owned)
    }

    #[test]
    fn decodes_borrowed_base64() {
        let secret = password(br#"{"password_b64":"cGFzc3dvcmQ="}"#).unwrap();
        assert_eq!(secret.as_bytes(), b"password");
        assert_eq!(secret.as_str().unwrap(), "password");
        assert_eq!(format!("{secret:?}"), "SecretBytes(<redacted>)");
    }

    #[test]
    fn refuses_escaped_and_invalid_input() {
        // An escaped "c" (backslash u0063) is refused from the raw token,
        // before anything unescapes it.
        let mut escaped = br#"{"password_b64":"XGFzc3dvcmQ="}"#.to_vec();
        let at = escaped.iter().position(|b| *b == b'X').unwrap();
        escaped.splice(at..=at, [0x5c, b'u', b'0', b'0', b'6', b'3']);
        assert!(password(&escaped).is_err());
        assert!(password(br#"{"password_b64":"not base64!"}"#).is_err());
        assert!(password(br#"{"password_b64":12}"#).is_err());
    }

    #[test]
    fn enforces_the_size_limit() {
        let ok = STANDARD.encode(vec![1u8; MAX_SECRET_BYTES]);
        let json = format!(r#"{{"password_b64":"{ok}"}}"#);
        assert_eq!(
            password(json.as_bytes()).unwrap().as_bytes().len(),
            MAX_SECRET_BYTES
        );
        let too_long = STANDARD.encode(vec![1u8; MAX_SECRET_BYTES + 1]);
        let json = format!(r#"{{"password_b64":"{too_long}"}}"#);
        assert!(password(json.as_bytes()).is_err());
    }

    #[test]
    fn hex_secrets_match_ethers_format() {
        let key: Vec<u8> = (0u8..=255).step_by(9).collect();
        let out = SecretResponse::new(7)
            .public("account", &0)
            .unwrap()
            .secret_hex("private_key_hex", &key)
            .finish()
            .unwrap();
        assert_eq!(out.capacity(), out.len(), "exactly sized");
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let expected: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(value["result"]["private_key_hex"], format!("0x{expected}"));
        for nibble in 0..16u8 {
            assert_eq!(hex_digit(nibble), b"0123456789abcdef"[usize::from(nibble)]);
        }
    }

    #[test]
    fn secret_response_is_exact_and_valid() {
        let long = vec![0xabu8; 4000];
        let payload = SecretResponse::new(7)
            .public("addresses", &serde_json::json!({ "user_wallet": "0xabc" }))
            .unwrap()
            .secret("mnemonic_b64", b"abandon")
            .secret("blob_b64", &long)
            .finish()
            .unwrap();
        assert_eq!(payload.capacity(), payload.len(), "allocated once, exactly");
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(value["type"], "response");
        assert_eq!(value["id"], 7);
        assert_eq!(value["result"]["addresses"]["user_wallet"], "0xabc");
        assert_eq!(value["result"]["mnemonic_b64"], "YWJhbmRvbg==");
        assert_eq!(
            STANDARD
                .decode(value["result"]["blob_b64"].as_str().unwrap())
                .unwrap(),
            long
        );
        assert!(SecretResponse::new(0).finish().is_err());
        let empty = SecretResponse::new(1).finish().unwrap();
        assert_eq!(
            empty.as_slice(),
            br#"{"type":"response","id":1,"result":{}}"#
        );
    }
}
