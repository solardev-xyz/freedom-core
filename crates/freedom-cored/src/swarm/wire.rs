//! The swarm thread's messages (design 0015, "The protocol"), read
//! strictly and written: `swarm.request`'s params in main's typed form,
//! the core's asks of main (`shell.swarm_ready`, `shell.swarm_api`,
//! `shell.swarm_subscribe`, `shell.swarm_unsubscribe` and 0012's
//! `approval.recheck`), main's answers to them as the machines' events,
//! and a request's outcome as its typed answer (SWM-4's D5).
//!
//! - **Strict both ways** ("Requests the core makes"): an unknown member, a
//!   value of another type, a status outside 100–599 or base64 that doesn't
//!   decode is refused here, and the thread ends the connection (D5: a
//!   malformed reply from main is a protocol error, as 0001 and 0009 make
//!   it). The machines then hold what passed to their own bounds (a reply
//!   past its cap, a header past its size), which end it the same way.
//! - **The answer is always typed** (D5): `{ result_typed }` or `{
//!   error_typed }`, `vectors/swarm.json`'s `formats.typed`, which carries
//!   what JSON loses: bytes, BigInt, `undefined`, `-0`, lone surrogates and
//!   key order.

use fc_json::{JsString, JsValue, number_to_string};
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_swarm_provider::machine::{
    Approval, Body, Event, Failed, Failure, Head, NodeCall, OpenFailed, ReadyCheck, Reply, Rule,
    Subscription,
};
use fc_swarm_provider::value::{BytesKind, Source, Value, decode_base64, encode_base64};
use serde::Deserialize;

/// The largest integer JavaScript keeps exactly.
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

// ---------------------------------------------------------------------------
// swarm.request's params.

/// `swarm.request { method, params, approval, deadline_ms }`, read.
#[derive(Debug, Clone, PartialEq)]
pub struct Params {
    /// The method, in the typed form: the machine answers a missing or
    /// unknown one itself, as `executeSwarmMethod` does.
    pub method: Value,
    /// The params, in the typed form.
    pub params: Value,
    /// How main approved it: its prompt or a standing rule; none for a
    /// method without approval.
    pub approval: Option<Approval>,
    /// The page's own timer (60 s or 300 s by today's list), which the
    /// `swarm` deadline kind takes when shorter.
    pub deadline_ms: Option<u64>,
}

/// Reads `swarm.request`'s params: their message names what is wrong, a
/// fixed text, never input.
pub fn request_params(text: Option<&str>) -> Result<Params, &'static str> {
    let value = fc_json::parse(text.ok_or("swarm.request needs params")?)
        .map_err(|_| "swarm.request's params aren't JSON")?;
    let JsValue::Object(members) = &value else {
        return Err("swarm.request's params must be an object");
    };
    let (mut method, mut params, mut approval, mut deadline_ms) = (None, None, None, None);
    for (key, member) in members {
        match key.as_str() {
            "method" => {
                method = Some(Value::from_typed(member).map_err(|_| "method isn't a typed value")?);
            }
            "params" => {
                params = Some(Value::from_typed(member).map_err(|_| "params isn't a typed value")?);
            }
            "approval" => {
                approval = Some(match member.as_str() {
                    Some("user") => Approval::User,
                    Some("auto") => Approval::Auto,
                    _ => return Err("approval must be \"user\" or \"auto\""),
                });
            }
            "deadline_ms" => match member {
                JsValue::Number(n) if *n >= 1.0 && n.fract() == 0.0 && *n <= MAX_SAFE => {
                    #[expect(
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss,
                        reason = "a positive integer below 2^53"
                    )]
                    let ms = *n as u64;
                    deadline_ms = Some(ms);
                }
                _ => return Err("deadline_ms must be a positive integer"),
            },
            _ => return Err("swarm.request's params have an unknown member"),
        }
    }
    Ok(Params {
        method: method.ok_or("swarm.request needs a method")?,
        params: params.ok_or("swarm.request needs params")?,
        approval,
        deadline_ms,
    })
}

// ---------------------------------------------------------------------------
// The core's asks of main.

/// `shell.swarm_ready { for, check }`.
pub fn ready_params(parent: u64, check: ReadyCheck) -> Vec<u8> {
    format!(r#"{{"for":{parent},"check":"{}"}}"#, check.as_str()).into_bytes()
}

/// `shell.swarm_api { for, form, method, path, query, headers, body?,
/// max_bytes, stream, feed?, tree? }`. `query` and `headers` are `[name,
/// value]` pairs in order; `body` is absent, `{ base64 }` or `{ stream:
/// <bytes> }`; `feed` is `{ owner, index }`, the index a number up to 2^53
/// − 1 and its decimal text past it (a feed index is 64 bits, which a
/// JavaScript number can't hold); `tree` is `{ length, depth }`.
pub fn api_params(parent: u64, call: &NodeCall) -> Vec<u8> {
    let pairs = |pairs: &[(String, String)]| -> serde_json::Value {
        serde_json::Value::Array(
            pairs
                .iter()
                .map(|(name, value)| serde_json::json!([name, value]))
                .collect(),
        )
    };
    let mut params = serde_json::Map::new();
    params.insert("for".into(), parent.into());
    params.insert("form".into(), call.form.as_str().into());
    params.insert("method".into(), call.method().into());
    params.insert("path".into(), call.path.clone().into());
    params.insert("query".into(), pairs(&call.query));
    params.insert("headers".into(), pairs(&call.headers));
    match &call.body {
        None => {}
        Some(Body::Base64(bytes)) => {
            params.insert(
                "body".into(),
                serde_json::json!({ "base64": encode_base64(bytes) }),
            );
        }
        Some(Body::Stream { bytes }) => {
            params.insert("body".into(), serde_json::json!({ "stream": bytes }));
        }
    }
    params.insert("max_bytes".into(), call.max_bytes.into());
    params.insert("stream".into(), call.stream().into());
    if let Some(feed) = call.feed {
        let index = if feed.index <= MAX_SAFE as u64 {
            serde_json::Value::from(feed.index)
        } else {
            serde_json::Value::from(feed.index.to_string())
        };
        params.insert(
            "feed".into(),
            serde_json::json!({ "owner": hex(&feed.owner), "index": index }),
        );
    }
    if let Some(tree) = call.tree {
        params.insert(
            "tree".into(),
            serde_json::json!({ "length": tree.length, "depth": tree.depth }),
        );
    }
    serde_json::to_vec(&serde_json::Value::Object(params)).unwrap_or_default()
}

/// `shell.swarm_subscribe { for, kind, key }` (D16): `key` the 32 bytes the
/// subscription listens on, in lowercase hex.
pub fn subscribe_params(parent: u64, subscription: &Subscription) -> Vec<u8> {
    format!(
        r#"{{"for":{parent},"kind":"{}","key":"{}"}}"#,
        subscription.kind.as_str(),
        hex(&subscription.key)
    )
    .into_bytes()
}

/// `shell.swarm_unsubscribe { id }` (D16): main's id for the subscription,
/// as it gave it. No `for`: a close can outlive its request.
pub fn unsubscribe_params(id: &JsString) -> Vec<u8> {
    let mut out = String::from(r#"{"id":"#);
    id.quote_into(&mut out);
    out.push('}');
    out.into_bytes()
}

/// `approval.recheck { request, page }` (0012's APR-5, design 0015's D1):
/// `page` the request's `PageContext`, as JSON.
pub fn recheck_params(request: u64, page: &str) -> Vec<u8> {
    format!(r#"{{"request":{request},"page":{page}}}"#).into_bytes()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

// ---------------------------------------------------------------------------
// Main's answers.

/// `shell.swarm_ready`'s `{ ok: true }` or `{ ok: false, reason }`.
pub fn ready_reply(text: &str) -> Option<Result<(), JsString>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Ready {
        ok: bool,
        reason: Option<String>,
    }
    let ready: Ready = serde_json::from_str(text).ok()?;
    match (ready.ok, ready.reason) {
        (true, None) => Some(Ok(())),
        (false, Some(reason)) if !reason.is_empty() => Some(Err(JsString::from(reason))),
        _ => None,
    }
}

/// A status, a reason phrase and the reply headers main forwards.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiReply<'a> {
    status: u16,
    status_text: String,
    headers: Vec<(String, String)>,
    #[serde(borrow, default)]
    body_base64: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FailedReply {
    failed: String,
}

/// `shell.swarm_api`'s answer to a call that streams its reply (`stream`)
/// or not: a whole reply `{ status, status_text, headers, body_base64 }`
/// (for a streamed call only an error status, its body at most 8 KiB), a
/// streamed reply's head `{ status, status_text, headers }`, or `{ failed
/// }` before any reply. The machine holds each to its bounds.
pub fn api_reply(text: &str, stream: bool) -> Option<Event> {
    if let Ok(failed) = serde_json::from_str::<FailedReply>(text) {
        return failed_class(&failed.failed).map(Event::Failed);
    }
    let reply: ApiReply<'_> = serde_json::from_str(text).ok()?;
    if !(100..=599).contains(&reply.status) {
        return None;
    }
    match reply.body_base64 {
        Some(body) => {
            let body = decode_base64(body)?;
            Some(Event::Reply(Reply {
                status: reply.status,
                status_text: reply.status_text,
                headers: reply.headers,
                body,
            }))
        }
        None if stream => Some(Event::Head(Head {
            status: reply.status,
            status_text: reply.status_text,
            headers: reply.headers,
        })),
        None => None,
    }
}

/// `failed`'s closed set (design 0015, `shell.swarm_api`).
fn failed_class(name: &str) -> Option<Failed> {
    Some(match name {
        "unreachable" => Failed::Unreachable,
        "error" => Failed::Error,
        "aborted" => Failed::Aborted,
        "too_large" => Failed::TooLarge,
        "busy" => Failed::Busy,
        "stopped" => Failed::Stopped,
        _ => return None,
    })
}

/// `shell.swarm_subscribe`'s `{ id }` once the subscription is open, or `{
/// failed: { reason?, message } }` with the registry's reason and text
/// (D16).
pub fn subscribe_reply(text: &str) -> Option<Result<JsString, OpenFailed>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Open {
        id: Option<String>,
        failed: Option<Why>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Why {
        reason: Option<String>,
        message: String,
    }
    let open: Open = serde_json::from_str(text).ok()?;
    match (open.id, open.failed) {
        (Some(id), None) if !id.is_empty() => Some(Ok(JsString::from(id))),
        (None, Some(why)) => Some(Err(OpenFailed {
            reason: why.reason.map(JsString::from),
            message: JsString::from(why.message),
        })),
        _ => None,
    }
}

/// `shell.swarm_unsubscribe`'s `{}`: closed, or already gone.
pub fn unsubscribe_reply(text: &str) -> bool {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Closed {}
    serde_json::from_str::<Closed>(text).is_ok()
}

/// How main refused one of the core's asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `cancelled`: the answer to a cancel the core sent.
    Cancelled,
    /// `invalid_argument` with `data: { rule }`: main's grammar refused a
    /// call (or a part).
    Rule(Rule),
}

/// Main's error answer to one of the core's asks: one of the two forms it
/// gives, else `None` (a protocol error).
pub fn refusal(text: &str) -> Option<Refusal> {
    let raw: &serde_json::value::RawValue = serde_json::from_str(text).ok()?;
    let error = ErrorBody::from_raw(raw).ok()?;
    match error.code {
        ErrorCode::Cancelled if error.data.is_none() => Some(Refusal::Cancelled),
        ErrorCode::InvalidArgument => {
            let data = error.data?;
            let object = data.as_object()?;
            if object.len() != 1 {
                return None;
            }
            rule(object.get("rule")?.as_str()?).map(Refusal::Rule)
        }
        _ => None,
    }
}

/// The grammar's rule names (design 0015, "The operation grammar").
fn rule(name: &str) -> Option<Rule> {
    Some(match name {
        "form" => Rule::Form,
        "order" => Rule::Order,
        "count" => Rule::Count,
        "value" => Rule::Value,
        "header" => Rule::Header,
        "query" => Rule::Query,
        "body" => Rule::Body,
        "ended" => Rule::Ended,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// The answer.

/// `{ result_typed: <value> }`: a method's result, as JavaScript holds it.
pub fn result_typed(value: &Value) -> String {
    let mut out = String::from(r#"{"result_typed":"#);
    typed_into(value, &mut out);
    out.push('}');
    out
}

/// `{ error_typed: { code, message, data? } }`: a page's error (D5), the
/// admission's `busy` among them.
pub fn error_typed(failure: &Failure) -> String {
    let mut members = vec![
        (JsString::from("code"), Value::Number(f64::from(failure.code))),
        (
            JsString::from("message"),
            Value::String(failure.message.clone()),
        ),
    ];
    if let Some(data) = &failure.data {
        members.push((JsString::from("data"), data.clone()));
    }
    let mut out = String::from(r#"{"error_typed":"#);
    typed_into(&Value::Object(members), &mut out);
    out.push('}');
    out
}

/// A value in the typed form (`formats.typed`).
pub fn typed_into(value: &Value, out: &mut String) {
    match value {
        Value::Undefined => out.push_str(r#"{"undefined":true}"#),
        Value::Null => out.push_str(r#"{"null":true}"#),
        Value::Bool(b) => out.push_str(if *b {
            r#"{"boolean":true}"#
        } else {
            r#"{"boolean":false}"#
        }),
        Value::Number(n) => {
            out.push_str(r#"{"number":""#);
            if *n == 0.0 && n.is_sign_negative() {
                out.push_str("-0");
            } else {
                out.push_str(&number_to_string(*n));
            }
            out.push_str(r#""}"#);
        }
        Value::BigInt(digits) => {
            out.push_str(r#"{"bigint":""#);
            out.push_str(digits);
            out.push_str(r#""}"#);
        }
        Value::String(s) => {
            out.push_str(r#"{"string":"#);
            s.quote_into(out);
            out.push('}');
        }
        Value::Array(items) => {
            out.push_str(r#"{"array":["#);
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                match item {
                    Some(item) => typed_into(item, out),
                    None => out.push_str(r#"{"hole":true}"#),
                }
            }
            out.push_str("]}");
        }
        Value::Object(members) => {
            out.push_str(r#"{"object":["#);
            for (i, (key, member)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('[');
                key.quote_into(out);
                out.push(',');
                typed_into(member, out);
                out.push(']');
            }
            out.push_str("]}");
        }
        Value::Bytes(bytes) => {
            let tag = match (bytes.kind, bytes.data) {
                (BytesKind::String, _) => r#"{"string_bytes":"#,
                (_, true) => r#"{"bytes":"#,
                (_, false) => r#"{"bytes_elsewhere":"#,
            };
            out.push_str(tag);
            out.push_str(&bytes.len.to_string());
            let kind = match bytes.kind {
                BytesKind::Buffer => Some("Buffer"),
                BytesKind::Uint8Array => Some("Uint8Array"),
                BytesKind::ArrayBuffer => Some("ArrayBuffer"),
                BytesKind::BufferJson => Some("BufferJSON"),
                BytesKind::String => None,
            };
            if let Some(kind) = kind {
                out.push_str(r#","kind":""#);
                out.push_str(kind);
                out.push('"');
            }
            match &bytes.source {
                Source::Inline(data) => {
                    out.push_str(r#","base64":""#);
                    out.push_str(&encode_base64(data));
                    out.push('"');
                }
                Source::Part(part) => {
                    out.push_str(r#","part":"#);
                    out.push_str(&part.to_string());
                }
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use fc_swarm_provider::machine::{Form, SubscriptionKind};
    use fc_swarm_provider::value::Bytes;

    fn typed(value: &Value) -> String {
        let mut out = String::new();
        typed_into(value, &mut out);
        out
    }

    /// Every typed form reads back as it was written, as main reads it.
    #[test]
    fn a_typed_answer_reads_back_whole() {
        let lone = JsString::from_units(&[u16::from(b'a'), 0xd800]);
        let value = Value::Object(vec![
            (JsString::from("u"), Value::Undefined),
            (JsString::from("n"), Value::Null),
            (JsString::from("t"), Value::Bool(true)),
            (JsString::from("zero"), Value::Number(-0.0)),
            (JsString::from("nan"), Value::Number(f64::NAN)),
            (JsString::from("inf"), Value::Number(f64::NEG_INFINITY)),
            (JsString::from("x"), Value::Number(1e21)),
            (JsString::from("big"), Value::BigInt("-123".into())),
            (lone.clone(), Value::String(lone.clone())),
            (
                JsString::from("a"),
                Value::Array(vec![Some(Value::int(1)), None]),
            ),
            (
                JsString::from("b"),
                Value::Bytes(Bytes {
                    len: 3,
                    kind: BytesKind::Uint8Array,
                    source: Source::Inline(vec![1, 2, 3]),
                    data: true,
                }),
            ),
            (
                JsString::from("s"),
                Value::Bytes(Bytes {
                    len: 2,
                    kind: BytesKind::String,
                    source: Source::Inline(b"hi".to_vec()),
                    data: true,
                }),
            ),
        ]);
        let text = typed(&value);
        let back = Value::from_typed(&fc_json::parse(&text).unwrap()).unwrap();
        // NaN isn't equal to itself: compared by text.
        assert_eq!(typed(&back), text);
        assert!(text.contains(r#"{"number":"-0"}"#), "{text}");
        assert!(text.contains(r#"{"number":"NaN"}"#), "{text}");
        assert!(text.contains(r#"{"number":"1e+21"}"#), "{text}");
        assert!(text.contains(r#"\ud800"#), "{text}");
    }

    #[test]
    fn an_error_is_typed_with_its_data() {
        let text = error_typed(&Failure::busy());
        assert_eq!(
            text,
            r#"{"error_typed":{"object":[["code",{"number":"4900"}],["message",{"string":"busy"}],["data",{"object":[["reason",{"string":"busy"}]]}]]}}"#
        );
        assert_eq!(
            result_typed(&Value::str("ok")),
            r#"{"result_typed":{"string":"ok"}}"#
        );
    }

    #[test]
    fn swarm_request_params_are_read_strictly() {
        let ok = request_params(Some(
            r#"{"method":{"string":"swarm_readChunk"},"params":{"object":[]},"approval":"auto","deadline_ms":60000}"#,
        ))
        .unwrap();
        assert_eq!(ok.method, Value::str("swarm_readChunk"));
        assert_eq!(ok.params, Value::Object(Vec::new()));
        assert_eq!(ok.approval, Some(Approval::Auto));
        assert_eq!(ok.deadline_ms, Some(60_000));
        let bare =
            request_params(Some(r#"{"method":{"number":"1"},"params":{"undefined":true}}"#))
                .unwrap();
        assert_eq!(bare.approval, None);
        assert_eq!(bare.deadline_ms, None);
        for bad in [
            None,
            Some("[]"),
            Some("{"),
            Some(r#"{"params":{"null":true}}"#),
            Some(r#"{"method":{"string":"m"}}"#),
            Some(r#"{"method":"m","params":{"null":true}}"#),
            Some(r#"{"method":{"string":"m"},"params":{"null":true},"extra":1}"#),
            Some(r#"{"method":{"string":"m"},"params":{"null":true},"approval":"prompt"}"#),
            Some(r#"{"method":{"string":"m"},"params":{"null":true},"approval":null}"#),
            Some(r#"{"method":{"string":"m"},"params":{"null":true},"deadline_ms":0}"#),
            Some(r#"{"method":{"string":"m"},"params":{"null":true},"deadline_ms":1.5}"#),
            Some(r#"{"method":{"string":"m"},"params":{"null":true},"deadline_ms":"1"}"#),
        ] {
            assert!(request_params(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_node_call_is_written_as_its_row_reads_it() {
        let call = NodeCall::chunk(&[0xab; 32]).with_feed([0x11; 20], 7);
        let params: serde_json::Value = serde_json::from_slice(&api_params(9, &call)).unwrap();
        assert_eq!(
            params,
            serde_json::json!({
                "for": 9, "form": "chunk", "method": "GET",
                "path": format!("/chunks/{}", "ab".repeat(32)),
                "query": [], "headers": [], "max_bytes": 4201, "stream": false,
                "feed": { "owner": "11".repeat(20), "index": 7 },
            })
        );
        let far = NodeCall::chunk(&[0; 32]).with_feed([0; 20], u64::MAX);
        let params: serde_json::Value = serde_json::from_slice(&api_params(1, &far)).unwrap();
        assert_eq!(params["feed"]["index"], "18446744073709551615");
        let upload = NodeCall::upload(
            Form::ChunkUp,
            "/chunks",
            vec![("q".into(), "1".into())],
            vec![("content-type".into(), "application/octet-stream".into())],
            Body::Base64(vec![1, 2, 3]),
        );
        let params: serde_json::Value = serde_json::from_slice(&api_params(2, &upload)).unwrap();
        assert_eq!(params["body"], serde_json::json!({ "base64": "AQID" }));
        assert_eq!(params["query"], serde_json::json!([["q", "1"]]));
        assert_eq!(params["method"], "POST");
        let tree = NodeCall::chunk(&[0; 32]).with_tree(8192, 1);
        let params: serde_json::Value = serde_json::from_slice(&api_params(3, &tree)).unwrap();
        assert_eq!(
            params["tree"],
            serde_json::json!({ "length": 8192, "depth": 1 })
        );
        let subscription = Subscription {
            kind: SubscriptionKind::Pss,
            key: [0xcd; 32],
        };
        assert_eq!(
            String::from_utf8(subscribe_params(4, &subscription)).unwrap(),
            format!(r#"{{"for":4,"kind":"pss","key":"{}"}}"#, "cd".repeat(32))
        );
        assert_eq!(
            String::from_utf8(unsubscribe_params(&JsString::from("s\"1"))).unwrap(),
            r#"{"id":"s\"1"}"#
        );
    }

    #[test]
    fn mains_answers_are_read_strictly() {
        assert_eq!(ready_reply(r#"{"ok":true}"#), Some(Ok(())));
        assert_eq!(
            ready_reply(r#"{"ok":false,"reason":"node-stopped"}"#),
            Some(Err(JsString::from("node-stopped")))
        );
        for bad in [
            r#"{"ok":true,"reason":"x"}"#,
            r#"{"ok":false}"#,
            r#"{"ok":false,"reason":""}"#,
            r#"{"ok":1}"#,
            r#"{"ok":true,"more":1}"#,
        ] {
            assert_eq!(ready_reply(bad), None, "{bad}");
        }
        let whole = r#"{"status":200,"status_text":"OK","headers":[["content-type","x"]],"body_base64":"AQI="}"#;
        assert_eq!(
            api_reply(whole, false),
            Some(Event::Reply(Reply {
                status: 200,
                status_text: "OK".into(),
                headers: vec![("content-type".into(), "x".into())],
                body: vec![1, 2],
            }))
        );
        let head = r#"{"status":200,"status_text":"OK","headers":[]}"#;
        assert!(matches!(api_reply(head, true), Some(Event::Head(_))));
        assert_eq!(api_reply(head, false), None, "a whole call needs its body");
        assert_eq!(
            api_reply(r#"{"failed":"busy"}"#, false),
            Some(Event::Failed(Failed::Busy))
        );
        for bad in [
            r#"{"failed":"gone"}"#,
            r#"{"status":99,"status_text":"","headers":[],"body_base64":""}"#,
            r#"{"status":600,"status_text":"","headers":[],"body_base64":""}"#,
            r#"{"status":200,"status_text":"","headers":[],"body_base64":"AQ"}"#,
            r#"{"status":200,"status_text":"","headers":[["a"]],"body_base64":""}"#,
            r#"{"status":200,"status_text":"","headers":[],"body_base64":"","x":1}"#,
            r#"{"status":"200","status_text":"","headers":[],"body_base64":""}"#,
        ] {
            assert_eq!(api_reply(bad, false), None, "{bad}");
        }
        assert_eq!(
            subscribe_reply(r#"{"id":"sub-1"}"#),
            Some(Ok(JsString::from("sub-1")))
        );
        assert_eq!(
            subscribe_reply(r#"{"failed":{"reason":"too_many_subscriptions","message":"m"}}"#),
            Some(Err(OpenFailed {
                reason: Some(JsString::from("too_many_subscriptions")),
                message: JsString::from("m"),
            }))
        );
        for bad in [
            r#"{}"#,
            r#"{"id":""}"#,
            r#"{"id":"a","failed":{"message":"m"}}"#,
            r#"{"failed":{"reason":"x"}}"#,
        ] {
            assert_eq!(subscribe_reply(bad), None, "{bad}");
        }
        assert!(unsubscribe_reply("{}"));
        assert!(!unsubscribe_reply(r#"{"closed":true}"#));
        assert_eq!(
            refusal(r#"{"code":"cancelled","message":"Cancelled"}"#),
            Some(Refusal::Cancelled)
        );
        assert_eq!(
            refusal(r#"{"code":"invalid_argument","message":"m","data":{"rule":"ended"}}"#),
            Some(Refusal::Rule(Rule::Ended))
        );
        for bad in [
            r#"{"code":"invalid_argument","message":"m"}"#,
            r#"{"code":"invalid_argument","message":"m","data":{"rule":"other"}}"#,
            r#"{"code":"invalid_argument","message":"m","data":{"rule":"form","x":1}}"#,
            r#"{"code":"busy","message":"m"}"#,
        ] {
            assert_eq!(refusal(bad), None, "{bad}");
        }
    }
}
