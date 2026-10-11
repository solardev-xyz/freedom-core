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
//! straight from the frame buffer.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::error::ErrorBody;

/// The largest ID either side may use: `2^53 - 1`, so JS represents it
/// exactly.
pub const MAX_ID: u64 = (1 << 53) - 1;

/// Who caused a request. Main fills this in, never the renderer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    pub caller: CallerKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
#[derive(Debug)]
pub enum Message<'a> {
    Request {
        id: u64,
        method: &'a str,
        params: Option<&'a RawValue>,
        context: Context,
    },
    Response {
        id: u64,
        outcome: Result<&'a RawValue, ErrorBody>,
    },
    Event {
        event: &'a str,
        data: Option<&'a RawValue>,
    },
    Cancel {
        id: u64,
    },
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
    #[error("id {0} is zero or above 2^53 - 1")]
    BadId(u64),
    #[error("a response needs exactly one of result and error")]
    ResultAndError,
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(rename = "type", borrow)]
    kind: &'a str,
    id: Option<u64>,
    #[serde(borrow)]
    method: Option<&'a str>,
    #[serde(borrow)]
    params: Option<&'a RawValue>,
    context: Option<Context>,
    #[serde(borrow)]
    result: Option<&'a RawValue>,
    error: Option<ErrorBody>,
    #[serde(borrow)]
    event: Option<&'a str>,
    #[serde(borrow)]
    data: Option<&'a RawValue>,
}

impl<'a> Message<'a> {
    /// Decodes one JSON frame payload.
    pub fn decode(payload: &'a [u8]) -> Result<Self, MessageError> {
        let envelope: Envelope<'a> =
            serde_json::from_slice(payload).map_err(|e| MessageError::Malformed(e.to_string()))?;
        let id = |id: Option<u64>| -> Result<u64, MessageError> {
            let id = id.ok_or(MessageError::Missing("id"))?;
            if id == 0 || id > MAX_ID {
                return Err(MessageError::BadId(id));
            }
            Ok(id)
        };
        match envelope.kind {
            "request" => Ok(Message::Request {
                id: id(envelope.id)?,
                method: envelope.method.ok_or(MessageError::Missing("method"))?,
                params: envelope.params,
                context: envelope.context.ok_or(MessageError::Missing("context"))?,
            }),
            "response" => {
                let outcome = match (envelope.result, envelope.error) {
                    (Some(result), None) => Ok(result),
                    (None, Some(error)) => Err(error),
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

/// Writes a request envelope.
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

/// Writes a successful response envelope.
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
    serde_json::to_writer(
        out,
        &Response {
            kind: "response",
            id,
            error,
        },
    )
}

/// Writes an event envelope.
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
                assert_eq!((id, method), (7, "vault.unlock"));
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
            Message::Response { outcome: Err(error), .. } => assert_eq!(error.code, ErrorCode::Throttled),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            Message::decode(br#"{"type":"event","event":"vault.locked","data":{"reason":"auto"}}"#)
                .unwrap(),
            Message::Event {
                event: "vault.locked",
                ..
            }
        ));
        assert!(matches!(
            Message::decode(br#"{"type":"cancel","id":3}"#).unwrap(),
            Message::Cancel { id: 3 }
        ));
    }

    #[test]
    fn rejects_malformed_envelopes() {
        for (input, expected) in [
            (
                &br#"{"type":"response","id":1,"result":{},"error":{"code":"busy","message":""}}"#
                    [..],
                MessageError::ResultAndError,
            ),
            (
                br#"{"type":"response","id":1}"#,
                MessageError::ResultAndError,
            ),
            (
                br#"{"type":"request","id":0,"method":"m","context":{"caller":"chrome"}}"#,
                MessageError::BadId(0),
            ),
            (
                br#"{"type":"cancel","id":9007199254740992}"#,
                MessageError::BadId(9_007_199_254_740_992),
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
        assert!(matches!(
            Message::decode(b"{"),
            Err(MessageError::Malformed(_))
        ));
        assert!(matches!(
            Message::decode(
                br#"{"type":"request","id":1,"method":"m","context":{"caller":"robot"}}"#
            ),
            Err(MessageError::Malformed(_))
        ));
    }

    #[test]
    fn writers_round_trip() {
        let mut out = Vec::new();
        write_request(
            &mut out,
            5,
            "vault.status",
            &serde_json::json!({}),
            &Context::shell(),
        )
        .unwrap();
        assert!(matches!(
            Message::decode(&out).unwrap(),
            Message::Request {
                id: 5,
                method: "vault.status",
                ..
            }
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
            Message::Event {
                event: "vault.locked",
                ..
            }
        ));
    }
}
