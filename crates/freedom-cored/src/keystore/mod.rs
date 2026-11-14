//! The key store on desktop (design 0013, "The helper, `freedom-cored
//! keystore`"):
//!
//! - [`helper`]: the one-shot subcommand main runs for each `shell.keystore`
//!   request. It makes one call to the OS's key store, seals any wrapping
//!   key it hands back to the request's `reply_key`, writes one line, and
//!   exits.
//! - [`client`]: the core's [`fc_keystore::KeyStore`], which sends each call
//!   to main as `shell.keystore`, so `serve` never calls a key store itself.
//! - `macos`: the macOS Keychain's `Unattended` backend, the only one so
//!   far. Every other OS answers `unavailable` (`reason: "unsupported"`)
//!   until its backend lands (PRF-7): no backend is ever faked.
//!
//! What both sides share is here: the ops, the answer's form, and what its
//! seal binds.

pub mod client;
pub mod helper;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(test)]
mod vectors;

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use fc_keystore::{Backend, Blob, Capabilities, ItemId, KeyStoreError, UnavailableReason};
use sha2::{Digest, Sha256};

/// The HPKE `info` of every answer's seal, and the first part of its
/// associated data.
pub const LABEL: &[u8] = b"freedom-keystore/1";
/// The longest answer: one JSON line, its newline included (0013, "The
/// answer"). The core refuses a longer relayed answer.
pub const MAX_ANSWER_BYTES: usize = 4096;
/// A sealed wrapping key on the wire: HPKE's `enc`, then the ciphertext
/// and its tag.
pub const SEALED_KEY_BYTES: usize = fc_seal::ENC_LEN + fc_seal::CIPHERTEXT_LEN;
/// The longest `reason` an answer carries, in its fixed form.
pub const MAX_REASON_BYTES: usize = 32;

/// A key-store call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Create,
    Open,
    Forget,
}

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::Create => "create",
            Op::Open => "open",
            Op::Forget => "forget",
        }
    }

    pub fn parse(name: &str) -> Option<Op> {
        match name {
            "create" => Some(Op::Create),
            "open" => Some(Op::Open),
            "forget" => Some(Op::Forget),
            _ => None,
        }
    }

    /// Whether the call hands back a wrapping key, sealed to the request's
    /// `reply_key`: `create` and `open`.
    pub fn returns_key(self) -> bool {
        self != Op::Forget
    }

    /// How long main lets the helper run before it kills it (0013,
    /// "Deadlines"): `create` and `open` may wait on an unlock prompt or on
    /// Touch ID.
    pub fn deadline(self) -> Duration {
        match self {
            Op::Create | Op::Open => Duration::from_secs(60),
            Op::Forget => Duration::from_secs(10),
        }
    }
}

/// The backend this OS's helper calls; `None` where it has none yet.
pub fn native() -> Option<Backend> {
    if cfg!(target_os = "macos") {
        Some(Backend::MacosKeychain)
    } else {
        None
    }
}

/// What this OS offers: on macOS `Unattended` only, until the entitlement
/// spike (PRF-1c) shows the core can carry `UserPresence`; nothing
/// elsewhere yet.
pub fn capabilities() -> Capabilities {
    match native() {
        Some(backend) => Capabilities {
            backend: Some(backend),
            unattended: true,
            user_presence: false,
        },
        None => Capabilities::NONE,
    }
}

/// What an answer's seal binds (0013, "The secret transfer"): [`LABEL`],
/// `0x00`, the op's name, `0x00`, the item's 32 hex digits, and, for an
/// answer that carries DPAPI's blob, `0x00` and the blob's SHA-256. None of
/// the parts holds a zero byte, and the digest, when there is one, is
/// always the last 32 bytes.
pub fn associated_data(op: Op, item: ItemId, blob: Option<&Blob>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(LABEL.len() + 8 + 32 + 1 + 32);
    aad.extend_from_slice(LABEL);
    aad.push(0);
    aad.extend_from_slice(op.name().as_bytes());
    aad.push(0);
    aad.extend_from_slice(item.hex().as_bytes());
    if let Some(blob) = blob {
        aad.push(0);
        aad.extend_from_slice(&Sha256::digest(blob.as_bytes()));
    }
    aad
}

/// Whether `text` is in a reason's fixed form: 1 to [`MAX_REASON_BYTES`]
/// of `a`–`z`, `0`–`9` and `_`.
pub fn reason_in_form(text: &str) -> bool {
    (1..=MAX_REASON_BYTES).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The helper's answer (0013, "The answer").
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// `create` and `open`: the key sealed to the request's `reply_key`, and
    /// a Windows `create`'s new blob.
    Key {
        sealed_key: [u8; SEALED_KEY_BYTES],
        blob: Option<Blob>,
    },
    /// `forget`.
    Done,
    /// `{ ok: false, error, reason? }`.
    Failed {
        error: KeyStoreError,
        reason: Option<String>,
    },
}

impl Answer {
    /// A failure with a fixed-form reason.
    pub fn failed(error: KeyStoreError, reason: &'static str) -> Answer {
        Answer::Failed {
            error,
            reason: Some(reason.to_owned()),
        }
    }

    /// The answer's line, without its newline. Every field is fixed-form
    /// (base64 and names), so nothing needs escaping.
    pub fn text(&self) -> String {
        match self {
            Answer::Key { sealed_key, blob } => match blob {
                Some(blob) => format!(
                    r#"{{"ok":true,"sealed":"{}","key":"{}"}}"#,
                    blob.base64(),
                    STANDARD.encode(sealed_key)
                ),
                None => format!(r#"{{"ok":true,"key":"{}"}}"#, STANDARD.encode(sealed_key)),
            },
            Answer::Done => r#"{"ok":true}"#.to_owned(),
            Answer::Failed { error, reason } => match reason {
                Some(reason) if reason_in_form(reason) => format!(
                    r#"{{"ok":false,"error":"{}","reason":"{reason}"}}"#,
                    error.code()
                ),
                _ => format!(r#"{{"ok":false,"error":"{}"}}"#, error.code()),
            },
        }
    }

    /// The answer `text` holds: one JSON object of exactly the members its
    /// kind has, each in form, at most [`MAX_ANSWER_BYTES`]. `ok: true`
    /// with neither member is [`Answer::Done`]; which kind an op needs is
    /// the caller's to check. Anything else is refused, with a fixed
    /// reason.
    pub fn parse(text: &[u8]) -> Result<Answer, &'static str> {
        /// The members an answer may have, each at most once: a duplicate
        /// or an unknown member is refused, and a member present as `null`
        /// is out of form, not absent.
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(default, deserialize_with = "present")]
            ok: Option<serde_json::Value>,
            #[serde(default, deserialize_with = "present")]
            sealed: Option<serde_json::Value>,
            #[serde(default, deserialize_with = "present")]
            key: Option<serde_json::Value>,
            #[serde(default, deserialize_with = "present")]
            error: Option<serde_json::Value>,
            #[serde(default, deserialize_with = "present")]
            reason: Option<serde_json::Value>,
        }
        fn present<'de, D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<serde_json::Value>, D::Error> {
            serde::Deserialize::deserialize(deserializer).map(Some)
        }
        fn string(value: Option<&serde_json::Value>) -> Result<Option<&str>, &'static str> {
            match value {
                None => Ok(None),
                Some(serde_json::Value::String(text)) => Ok(Some(text)),
                Some(_) => Err("answer_form"),
            }
        }

        if text.len() > MAX_ANSWER_BYTES {
            return Err("answer_too_long");
        }
        let wire: Wire = serde_json::from_slice(text).map_err(|_| "answer_form")?;
        match wire.ok {
            Some(serde_json::Value::Bool(true)) => {
                if wire.error.is_some() || wire.reason.is_some() {
                    return Err("answer_form");
                }
                let blob = match string(wire.sealed.as_ref())? {
                    Some(text) => Some(Blob::from_base64(text).ok_or("answer_form")?),
                    None => None,
                };
                match string(wire.key.as_ref())? {
                    Some(text) => {
                        let bytes = STANDARD.decode(text).map_err(|_| "answer_form")?;
                        let sealed_key = <[u8; SEALED_KEY_BYTES]>::try_from(bytes.as_slice())
                            .map_err(|_| "answer_form")?;
                        Ok(Answer::Key { sealed_key, blob })
                    }
                    None if blob.is_none() => Ok(Answer::Done),
                    None => Err("answer_form"),
                }
            }
            Some(serde_json::Value::Bool(false)) => {
                if wire.key.is_some() || wire.sealed.is_some() {
                    return Err("answer_form");
                }
                let reason = match string(wire.reason.as_ref())? {
                    Some(text) if reason_in_form(text) => Some(text.to_owned()),
                    Some(_) => return Err("answer_form"),
                    None => None,
                };
                let error = match string(wire.error.as_ref())?.ok_or("answer_form")? {
                    "not_found" => KeyStoreError::NotFound,
                    "cancelled" => KeyStoreError::Cancelled,
                    "unavailable" => {
                        KeyStoreError::Unavailable(known_unavailable(reason.as_deref()))
                    }
                    "invalidated" => KeyStoreError::Invalidated,
                    "denied" => KeyStoreError::Denied,
                    "backend" => KeyStoreError::Backend(fc_keystore::BackendError::new(
                        known_reason(reason.as_deref()),
                    )),
                    _ => return Err("answer_form"),
                };
                Ok(Answer::Failed { error, reason })
            }
            _ => Err("answer_form"),
        }
    }
}

/// `Unavailable` with a fixed-form reason ([`UnavailableReason`]).
pub fn unavailable(reason: &'static str) -> KeyStoreError {
    KeyStoreError::Unavailable(UnavailableReason::new(reason))
}

/// An `unavailable` answer's reason, as one of the helper's own or main's
/// `timeout`: anything else, or none, is `helper`.
fn known_unavailable(reason: Option<&str>) -> UnavailableReason {
    UnavailableReason::new(match reason {
        Some("unsupported") => "unsupported",
        Some("no_keychain") => "no_keychain",
        Some("read_only") => "read_only",
        Some("timeout") => "timeout",
        _ => "helper",
    })
}

/// A `backend` answer's reason, as one of the helper's own: anything else
/// is `helper`.
fn known_reason(reason: Option<&str>) -> &'static str {
    match reason {
        Some("bad_request") => "bad_request",
        Some("duplicate") => "duplicate",
        Some("rng") => "rng",
        Some("status") => "status",
        Some("seal") => "seal",
        Some("confine") => "confine",
        _ => "helper",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item() -> ItemId {
        ItemId::parse("00112233445566778899aabbccddeeff").unwrap()
    }

    #[test]
    fn the_associated_data_is_label_op_item_and_the_blobs_digest() {
        assert_eq!(
            associated_data(Op::Open, item(), None),
            b"freedom-keystore/1\x00open\x0000112233445566778899aabbccddeeff".to_vec()
        );
        let blob = Blob::new(b"abc".to_vec()).unwrap();
        let aad = associated_data(Op::Create, item(), Some(&blob));
        let mut expected =
            b"freedom-keystore/1\x00create\x0000112233445566778899aabbccddeeff\x00".to_vec();
        // SHA-256("abc").
        expected.extend_from_slice(&[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]);
        assert_eq!(aad, expected);
        assert_ne!(
            associated_data(Op::Create, item(), None),
            associated_data(Op::Open, item(), None)
        );
    }

    #[test]
    fn answers_round_trip() {
        let blob = Blob::new(vec![7; 300]).unwrap();
        for answer in [
            Answer::Key {
                sealed_key: [3; SEALED_KEY_BYTES],
                blob: None,
            },
            Answer::Key {
                sealed_key: [4; SEALED_KEY_BYTES],
                blob: Some(blob),
            },
            Answer::Done,
            Answer::failed(unavailable("unsupported"), "unsupported"),
            Answer::Failed {
                error: KeyStoreError::NotFound,
                reason: None,
            },
            Answer::failed(
                KeyStoreError::Backend(fc_keystore::BackendError::new("bad_request")),
                "bad_request",
            ),
        ] {
            assert_eq!(Answer::parse(answer.text().as_bytes()), Ok(answer));
        }
        // A 1 KiB blob's create answer fits the cap (0013, "DPAPI's blob").
        let big = Answer::Key {
            sealed_key: [0; SEALED_KEY_BYTES],
            blob: Some(Blob::new(vec![0xff; fc_keystore::MAX_BLOB_BYTES]).unwrap()),
        };
        assert!(big.text().len() < MAX_ANSWER_BYTES);
    }

    #[test]
    fn answers_out_of_form_are_refused() {
        let key = STANDARD.encode([1u8; SEALED_KEY_BYTES]);
        let short = STANDARD.encode([1u8; SEALED_KEY_BYTES - 1]);
        let cases = [
            String::new(),
            "[]".to_owned(),
            "null".to_owned(),
            r#"{}"#.to_owned(),
            r#"{"ok":"true"}"#.to_owned(),
            format!(r#"{{"ok":true,"key":"{key}","extra":1}}"#),
            format!(r#"{{"ok":true,"key":"{short}"}}"#),
            format!(r#"{{"ok":true,"key":"{key}x"}}"#),
            r#"{"ok":true,"key":null}"#.to_owned(),
            r#"{"ok":true,"sealed":"AQ=="}"#.to_owned(),
            format!(r#"{{"ok":true,"sealed":null,"key":"{key}"}}"#),
            format!(r#"{{"ok":true,"sealed":"AQ","key":"{key}"}}"#),
            format!(r#"{{"ok":true,"sealed":"","key":"{key}"}}"#),
            r#"{"ok":false}"#.to_owned(),
            r#"{"ok":false,"error":"nope"}"#.to_owned(),
            r#"{"ok":false,"error":"backend","reason":"Bad"}"#.to_owned(),
            r#"{"ok":false,"error":"denied","reason":""}"#.to_owned(),
            format!(
                r#"{{"ok":false,"error":"denied","reason":"{}"}}"#,
                "a".repeat(33)
            ),
            r#"{"ok":false,"error":"denied","key":"AQ=="}"#.to_owned(),
            r#"{"ok":true,"ok":false,"error":"denied"}"#.to_owned(),
            r#"{"ok":false,"error":"denied","error":"denied"}"#.to_owned(),
            r#"{"ok":false,"error":"denied","reason":null}"#.to_owned(),
            r#"{"ok":true} x"#.to_owned(),
        ];
        for case in cases {
            assert!(Answer::parse(case.as_bytes()).is_err(), "{case}");
        }
        let long = format!(r#"{{"ok":true}}{}"#, " ".repeat(MAX_ANSWER_BYTES));
        assert_eq!(Answer::parse(long.as_bytes()), Err("answer_too_long"));
        // An unknown backend reason keeps its text, and maps to `helper`.
        let Ok(Answer::Failed { error, reason }) =
            Answer::parse(br#"{"ok":false,"error":"backend","reason":"weird_one"}"#)
        else {
            panic!("refused");
        };
        assert_eq!(error.code(), "backend");
        assert_eq!(reason.as_deref(), Some("weird_one"));
        let KeyStoreError::Backend(backend) = error else {
            panic!("not backend");
        };
        assert_eq!(backend.reason(), "helper");
    }

    #[test]
    fn this_os_offers_only_what_its_backend_has() {
        let caps = capabilities();
        assert!(!caps.offers(fc_keystore::Policy::UserPresence));
        if cfg!(target_os = "macos") {
            assert_eq!(caps.backend, Some(Backend::MacosKeychain));
            assert!(caps.offers(fc_keystore::Policy::Unattended));
        } else {
            assert_eq!(caps, Capabilities::NONE);
        }
    }
}
