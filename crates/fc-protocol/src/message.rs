//! Message envelopes (design 0001, "Messages"):
//!
//! ```jsonc
//! { "type": "request", "id": 7, "method": "vault.unlock", "params": {…}, "context": { "caller": "chrome" } }
//! { "type": "response", "id": 7, "result": {…} }        // or "error": { code, message, data? }
//! { "type": "event", "event": "vault.locked", "data": {…} }
//! { "type": "cancel", "id": 7 }
//! ```
//!
//! Decoding borrows `params`, `result` and `data` as raw JSON from the frame,
//! so each method parses its own typed parameters, secret fields included,
//! straight from the frame buffer. `Debug` never prints a body.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::error::ErrorBody;

/// The largest ID either side may use: `2^53 - 1`, so JS represents it
/// exactly.
pub const MAX_ID: u64 = (1 << 53) - 1;

/// An ID outside `1..=MAX_ID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("id {0} is zero or above 2^53 - 1")]
pub struct IdError(pub u64);

/// Checks that `id` is a valid message ID.
pub fn check_id(id: u64) -> Result<u64, IdError> {
    if id == 0 || id > MAX_ID {
        return Err(IdError(id));
    }
    Ok(id)
}

/// Who caused a request. Main fills this in, never the renderer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    pub caller: CallerKind,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "page_object"
    )]
    pub page: Option<PageContext>,
}

impl Context {
    pub fn chrome() -> Self {
        Context {
            caller: CallerKind::Chrome,
            page: None,
        }
    }

    pub fn shell() -> Self {
        Context {
            caller: CallerKind::Shell,
            page: None,
        }
    }
}

/// The caller kinds; shell-neutral so a Chromium browser process can fill
/// them in later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerKind {
    /// The browser UI.
    Chrome,
    /// Main-internal work with no IPC event (x402, background jobs).
    Shell,
    /// Web content (Phase 2).
    Page,
}

/// The attested page behind a `Page` caller (Phase 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageContext {
    pub origin: String,
    pub top_origin: String,
    pub frame: u64,
    pub navigation: u64,
}

/// A decoded message, borrowing its raw JSON parts from the frame.
pub enum Message<'a> {
    Request {
        id: u64,
        method: Cow<'a, str>,
        params: Option<&'a RawValue>,
        context: Context,
    },
    Response {
        id: u64,
        outcome: Result<&'a RawValue, RawError<'a>>,
    },
    Event {
        event: Cow<'a, str>,
        data: Option<&'a RawValue>,
    },
    Cancel {
        id: u64,
    },
}

/// A response's `error` member, a JSON object, kept as it was read: nothing
/// of it is allocated until its consumer reads it ([`RawError::parse`]),
/// so a consumer that charges what it holds can charge it first.
#[derive(Clone, Copy)]
pub struct RawError<'a>(&'a RawValue);

impl<'a> RawError<'a> {
    /// The error's JSON text.
    pub fn raw(&self) -> &'a RawValue {
        self.0
    }

    /// The error as an [`ErrorBody`]: a code, a message and, maybe, data,
    /// and no other member.
    pub fn parse(&self) -> Result<ErrorBody, MessageError> {
        ErrorBody::from_raw(self.0)
    }
}

impl ErrorBody {
    /// An `error` member's JSON, read whole: a code, a message and, maybe,
    /// data, and no other member.
    pub fn from_raw(raw: &RawValue) -> Result<Self, MessageError> {
        object(raw).map_err(MessageError::Malformed)
    }
}

/// Bodies (params, results, event data, error text) can carry secrets, so
/// `Debug` shows only the kind, ID, method or event name.
impl fmt::Debug for Message<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::Request {
                id,
                method,
                context,
                ..
            } => f
                .debug_struct("Request")
                .field("id", id)
                .field("method", method)
                .field("caller", &context.caller)
                .finish_non_exhaustive(),
            Message::Response { id, outcome } => f
                .debug_struct("Response")
                .field("id", id)
                .field("error", &outcome.is_err())
                .finish_non_exhaustive(),
            Message::Event { event, .. } => f
                .debug_struct("Event")
                .field("event", event)
                .finish_non_exhaustive(),
            Message::Cancel { id } => f.debug_struct("Cancel").field("id", id).finish(),
        }
    }
}

/// Why a frame isn't a valid message. Always a protocol error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    #[error("not a valid message envelope: {0}")]
    Malformed(String),
    #[error("unknown message type {0:?}")]
    UnknownType(String),
    #[error("missing field {0}")]
    Missing(&'static str),
    #[error(transparent)]
    BadId(#[from] IdError),
    #[error("a response needs exactly one of result and error")]
    ResultAndError,
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(rename = "type", borrow)]
    kind: Cow<'a, str>,
    id: Option<u64>,
    #[serde(default, borrow)]
    method: Option<Cow<'a, str>>,
    #[serde(default, borrow, deserialize_with = "present")]
    params: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    context: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    result: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    error: Option<&'a RawValue>,
    #[serde(default, borrow)]
    event: Option<Cow<'a, str>>,
    #[serde(default, borrow, deserialize_with = "present")]
    data: Option<&'a RawValue>,
}

/// A present field stays `Some`, even when its value is `null`.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<&'de RawValue>, D::Error> {
    <&'de RawValue>::deserialize(d).map(Some)
}

fn page_object<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<PageContext>, D::Error> {
    let raw = <Option<&'de RawValue>>::deserialize(d)?;
    raw.map(|raw| object(raw).map_err(serde::de::Error::custom))
        .transpose()
}

/// Parses `raw` as `T`, requiring a JSON object: serde's derived structs
/// would otherwise also accept arrays.
fn object<'a, T: Deserialize<'a>>(raw: &'a RawValue) -> Result<T, String> {
    if !raw.get().trim_start().starts_with('{') {
        return Err("expected a JSON object".into());
    }
    serde_json::from_str(raw.get()).map_err(|e| e.to_string())
}

impl<'a> Message<'a> {
    /// Decodes one JSON frame payload.
    pub fn decode(payload: &'a [u8]) -> Result<Self, MessageError> {
        let root =
            std::str::from_utf8(payload).map_err(|e| MessageError::Malformed(e.to_string()))?;
        if !root.trim_start().starts_with('{') {
            return Err(MessageError::Malformed(
                "a message must be a JSON object".into(),
            ));
        }
        let envelope: Envelope<'a> =
            serde_json::from_str(root).map_err(|e| MessageError::Malformed(e.to_string()))?;
        let id = |id: Option<u64>| -> Result<u64, MessageError> {
            Ok(check_id(id.ok_or(MessageError::Missing("id"))?)?)
        };
        match envelope.kind.as_ref() {
            "request" => {
                let context = envelope.context.ok_or(MessageError::Missing("context"))?;
                Ok(Message::Request {
                    id: id(envelope.id)?,
                    method: envelope.method.ok_or(MessageError::Missing("method"))?,
                    params: envelope.params,
                    context: object(context).map_err(MessageError::Malformed)?,
                })
            }
            "response" => {
                let outcome = match (envelope.result, envelope.error) {
                    (Some(result), None) => Ok(result),
                    // An object, read by its consumer.
                    (None, Some(error)) if error.get().trim_start().starts_with('{') => {
                        Err(RawError(error))
                    }
                    (None, Some(_)) => {
                        return Err(MessageError::Malformed(
                            "an error must be a JSON object".into(),
                        ));
                    }
                    _ => return Err(MessageError::ResultAndError),
                };
                Ok(Message::Response {
                    id: id(envelope.id)?,
                    outcome,
                })
            }
            "event" => Ok(Message::Event {
                event: envelope.event.ok_or(MessageError::Missing("event"))?,
                data: envelope.data,
            }),
            "cancel" => Ok(Message::Cancel {
                id: id(envelope.id)?,
            }),
            other => Err(MessageError::UnknownType(other.to_owned())),
        }
    }
}

fn id_error(error: IdError) -> serde_json::Error {
    <serde_json::Error as serde::ser::Error>::custom(error)
}

/// Writes a request envelope. Bodies passed here must not hold secrets.
pub fn write_request<W: std::io::Write, P: Serialize>(
    out: W,
    id: u64,
    method: &str,
    params: &P,
    context: &Context,
) -> serde_json::Result<()> {
    #[derive(Serialize)]
    struct Request<'a, P> {
        #[serde(rename = "type")]
        kind: &'static str,
        id: u64,
        method: &'a str,
        params: &'a P,
        context: &'a Context,
    }
    let id = check_id(id).map_err(id_error)?;
    serde_json::to_writer(
        out,
        &Request {
            kind: "request",
            id,
            method,
            params,
            context,
        },
    )
}

/// Writes a successful response envelope without secrets; responses that
/// carry secrets go through [`crate::secret::SecretResponse`].
pub fn write_result<W: std::io::Write, R: Serialize>(
    out: W,
    id: u64,
    result: &R,
) -> serde_json::Result<()> {
    #[derive(Serialize)]
    struct Response<'a, R> {
        #[serde(rename = "type")]
        kind: &'static str,
        id: u64,
        result: &'a R,
    }
    let id = check_id(id).map_err(id_error)?;
    serde_json::to_writer(
        out,
        &Response {
            kind: "response",
            id,
            result,
        },
    )
}

/// Writes an error response envelope.
pub fn write_error<W: std::io::Write>(
    out: W,
    id: u64,
    error: &ErrorBody,
) -> serde_json::Result<()> {
    #[derive(Serialize)]
    struct Response<'a> {
        #[serde(rename = "type")]
        kind: &'static str,
        id: u64,
        error: &'a ErrorBody,
    }
    let id = check_id(id).map_err(id_error)?;
    serde_json::to_writer(
        out,
        &Response {
            kind: "response",
            id,
            error,
        },
    )
}

/// Writes an event envelope. Event data must not hold secrets.
pub fn write_event<W: std::io::Write, D: Serialize>(
    out: W,
    event: &str,
    data: &D,
) -> serde_json::Result<()> {
    #[derive(Serialize)]
    struct Event<'a, D> {
        #[serde(rename = "type")]
        kind: &'static str,
        event: &'a str,
        data: &'a D,
    }
    serde_json::to_writer(
        out,
        &Event {
            kind: "event",
            event,
            data,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    #[test]
    fn decodes_each_kind() {
        let request = br#"{"type":"request","id":7,"method":"vault.unlock","params":{"password_b64":"eA=="},"context":{"caller":"chrome"}}"#;
        match Message::decode(request).unwrap() {
            Message::Request {
                id,
                method,
                params,
                context,
            } => {
                assert_eq!((id, method.as_ref()), (7, "vault.unlock"));
                assert_eq!(params.unwrap().get(), r#"{"password_b64":"eA=="}"#);
                assert_eq!(context, Context::chrome());
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            Message::decode(br#"{"type":"response","id":7,"result":{}}"#).unwrap(),
            Message::Response {
                id: 7,
                outcome: Ok(_)
            }
        ));
        match Message::decode(br#"{"type":"response","id":7,"error":{"code":"throttled","message":"x","data":{"retry_after_ms":10}}}"#).unwrap() {
            Message::Response { outcome: Err(error), .. } => assert_eq!(error.parse().unwrap().code, ErrorCode::Throttled),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            Message::decode(br#"{"type":"event","event":"vault.locked","data":{"reason":"auto"}}"#)
                .unwrap(),
            Message::Event { .. }
        ));
        assert!(matches!(
            Message::decode(br#"{"type":"cancel","id":3}"#).unwrap(),
            Message::Cancel { id: 3 }
        ));
    }

    #[test]
    fn result_and_error_presence() {
        // A present null is still a result, and counts as present.
        assert!(matches!(
            Message::decode(br#"{"type":"response","id":1,"result":null}"#).unwrap(),
            Message::Response { outcome: Ok(_), .. }
        ));
        for input in [
            &br#"{"type":"response","id":1,"result":{},"error":null}"#[..],
            br#"{"type":"response","id":1,"result":null,"error":{"code":"busy","message":"b"}}"#,
            br#"{"type":"response","id":1}"#,
        ] {
            assert_eq!(
                Message::decode(input).unwrap_err(),
                MessageError::ResultAndError
            );
        }
        // The unit result the writer produces round-trips.
        let mut out = Vec::new();
        write_result(&mut out, 1, &()).unwrap();
        assert!(Message::decode(&out).is_ok());
    }

    #[test]
    fn rejects_malformed_envelopes() {
        for (input, expected) in [
            (
                &br#"{"type":"request","id":0,"method":"m","context":{"caller":"chrome"}}"#[..],
                MessageError::BadId(IdError(0)),
            ),
            (
                br#"{"type":"cancel","id":9007199254740992}"#,
                MessageError::BadId(IdError(9_007_199_254_740_992)),
            ),
            (
                br#"{"type":"request","id":1,"context":{"caller":"chrome"}}"#,
                MessageError::Missing("method"),
            ),
            (
                br#"{"type":"request","id":1,"method":"m"}"#,
                MessageError::Missing("context"),
            ),
            (
                br#"{"type":"nope"}"#,
                MessageError::UnknownType("nope".into()),
            ),
        ] {
            assert_eq!(
                Message::decode(input).unwrap_err(),
                expected,
                "{}",
                String::from_utf8_lossy(input)
            );
        }
        for input in [
            &b"{"[..],
            br#"{"type":"request","id":1,"method":"m","context":{"caller":"robot"}}"#,
            // Arrays where objects belong (PR #7 review, finding 8).
            br#"["cancel",1,null,null,null,null,null,null,null]"#,
            br#"{"type":"request","id":1,"method":"m","context":["chrome",null]}"#,
            br#"{"type":"request","id":1,"method":"m","context":{"caller":"page","page":["o","t",1,1]}}"#,
            br#"{"type":"response","id":1,"error":["busy","b"]}"#,
        ] {
            assert!(matches!(Message::decode(input), Err(MessageError::Malformed(_))), "{}", String::from_utf8_lossy(input));
        }
    }

    #[test]
    fn an_error_is_read_by_its_consumer() {
        // Decoding keeps it raw; reading it checks its whole shape.
        for (input, ok) in [
            (
                &br#"{"type":"response","id":1,"error":{"code":"busy","message":"b"}}"#[..],
                true,
            ),
            (
                br#"{"type":"response","id":1,"error":{"code":"busy","message":"b","extra":1}}"#,
                false,
            ),
            (
                br#"{"type":"response","id":1,"error":{"code":"nope","message":"b"}}"#,
                false,
            ),
            (br#"{"type":"response","id":1,"error":{}}"#, false),
        ] {
            match Message::decode(input).unwrap() {
                Message::Response {
                    outcome: Err(error),
                    ..
                } => {
                    assert_eq!(
                        error.parse().is_ok(),
                        ok,
                        "{}",
                        String::from_utf8_lossy(input)
                    );
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn escaped_names_decode_like_plain_ones() {
        // "cancel" with its c escaped, built at runtime (backslash u0063).
        let json = format!(r#"{{"type":"{}ancel","id":3}}"#, "BSu0063").replace("BS", "\\");
        assert!(matches!(
            Message::decode(json.as_bytes()).unwrap(),
            Message::Cancel { id: 3 }
        ));
        let json = format!(r#"{{"type":"request","id":1,"method":"vault.{}nlock","context":{{"caller":"chrome"}}}}"#, "BSu0075")
            .replace("BS", "\\");
        match Message::decode(json.as_bytes()).unwrap() {
            Message::Request { method, .. } => assert_eq!(method, "vault.unlock"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn debug_never_prints_bodies() {
        let request = br#"{"type":"request","id":7,"method":"vault.unlock","params":{"password_b64":"cGFzc3dvcmQ="},"context":{"caller":"chrome"}}"#;
        let debug = format!("{:?}", Message::decode(request).unwrap());
        assert!(!debug.contains("cGFzc3dvcmQ="), "{debug}");
        let response = br#"{"type":"response","id":7,"result":{"mnemonic_b64":"YWJhbmRvbg=="}}"#;
        let debug = format!("{:?}", Message::decode(response).unwrap());
        assert!(!debug.contains("YWJhbmRvbg=="), "{debug}");
        let error =
            br#"{"type":"response","id":7,"error":{"code":"internal","message":"secret detail"}}"#;
        assert!(!format!("{:?}", Message::decode(error).unwrap()).contains("secret detail"));
    }

    #[test]
    fn writers_check_ids_and_round_trip() {
        let mut out = Vec::new();
        assert!(write_request(&mut out, 0, "m", &(), &Context::shell()).is_err());
        assert!(write_result(&mut out, MAX_ID + 1, &()).is_err());
        assert!(out.is_empty(), "nothing written for an invalid id");
        write_request(
            &mut out,
            MAX_ID,
            "vault.status",
            &serde_json::json!({}),
            &Context::shell(),
        )
        .unwrap();
        assert!(matches!(
            Message::decode(&out).unwrap(),
            Message::Request { id: MAX_ID, .. }
        ));
        out.clear();
        write_error(
            &mut out,
            5,
            &ErrorBody::new(ErrorCode::VaultLocked, "Vault is locked"),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out.clone()).unwrap(),
            r#"{"type":"response","id":5,"error":{"code":"vault_locked","message":"Vault is locked"}}"#
        );
        out.clear();
        write_event(
            &mut out,
            "vault.locked",
            &serde_json::json!({"reason":"auto","epoch":3}),
        )
        .unwrap();
        assert!(matches!(
            Message::decode(&out).unwrap(),
            Message::Event { .. }
        ));
    }
}
