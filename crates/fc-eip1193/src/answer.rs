//! What a request answers, `{ result }` or `{ error }` in JSON.stringify's
//! text, and a read through the core's chain machine with the answer its
//! outcome gives.

use fc_json::{JsString, JsValue};

use crate::World;

/// `-32603`: the reference's code for an error without a usable one.
const INTERNAL_ERROR_CODE: i64 = -32603;

/// A request's answer: `{ result }` or `{ error: { code, message, data? }
/// }`, as JSON text, which the daemon sends as `eip1193.request`'s result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer(String);

impl Answer {
    /// `{ result }`. JSON.stringify leaves out an `undefined` result: `{}`.
    pub(crate) fn result(result: &JsValue) -> Answer {
        let mut out = String::from("{");
        if !matches!(result, JsValue::Undefined) {
            out.push_str(r#""result":"#);
            out.push_str(&result.stringify());
        }
        out.push('}');
        Answer(out)
    }

    /// `{ error: { code, message } }`.
    pub(crate) fn error(code: i64, message: &str) -> Answer {
        let mut out = format!(r#"{{"error":{{"code":{code},"message":"#);
        JsString::from(message).quote_into(&mut out);
        out.push_str("}}");
        Answer(out)
    }

    /// `{ error: { code, message } }`, the message as JavaScript holds it
    /// (a `SyntaxError`'s may quote a lone surrogate).
    pub(crate) fn error_js(code: i64, message: &JsString) -> Answer {
        let mut out = format!(r#"{{"error":{{"code":{code},"message":"#);
        message.quote_into(&mut out);
        out.push_str("}}");
        Answer(out)
    }

    /// Every method while the Identity & Wallet switch is off.
    pub(crate) fn disconnected() -> Answer {
        Answer::error(4900, "Disconnected")
    }

    /// A method main's table doesn't list, or one without its route yet
    /// (`unknownMethodError('ethereum')`).
    pub(crate) fn unsupported() -> Answer {
        Answer::error(4200, "Method not supported")
    }

    /// The JSON text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

/// A read through the core's chain machine (design 0005's `chain.request`),
/// as the reference's `read` asks it: the page's chain, the method, the
/// page's params, and the key as the routing hint.
#[derive(Debug, Clone, PartialEq)]
pub struct Read {
    pub chain_id: u64,
    pub method: &'static str,
    /// The params' JSON text (`context.params || []`).
    pub params: String,
    /// The router's `origin`: the document's key; none for a keyless one.
    pub origin: Option<String>,
    /// The chrome's text for a chain with no source, when it has none
    /// (`readError`'s replacement); `None` when the error keeps its own.
    provider_text: Option<String>,
}

/// What the chain machine answered a read.
#[derive(Debug, Clone, Copy)]
pub enum ReadOutcome<'a> {
    /// The answer's raw JSON `result`; `None` for `undefined`.
    Result(Option<&'a str>),
    /// What it threw.
    Failed(Failure<'a>),
}

/// A thrown error, as main's chain driver rebuilds it: its own `code` and
/// `data` (raw JSON, `None` when it has none or it is `undefined`) and its
/// message. 0001's codes (a deadline, a full machine) throw their text
/// with neither.
#[derive(Debug, Clone, Copy)]
pub struct Failure<'a> {
    pub code: Option<&'a str>,
    pub message: &'a JsString,
    pub data: Option<&'a str>,
}

impl Read {
    pub(crate) fn new(
        chain_id: u64,
        method: &'static str,
        params: String,
        key: Option<&str>,
        world: &World,
    ) -> Read {
        // `readError`: a chain the registry says has no source gets the
        // chrome's text; one whose name doesn't convert keeps the error's.
        let provider_text = world
            .unavailable(chain_id)
            .then(|| world.chain_label(chain_id).ok())
            .flatten()
            .map(|label| {
                format!("{label} requires an RPC provider. Please configure one in Settings.")
            });
        Read {
            chain_id,
            method,
            params,
            origin: key.map(str::to_owned),
            provider_text,
        }
    }

    /// The request's answer from the read's outcome: `{ result }`, or the
    /// reference's `readError`.
    pub fn answer(&self, outcome: ReadOutcome<'_>) -> Answer {
        let failure = match outcome {
            ReadOutcome::Result(result) => {
                let mut out = String::with_capacity(result.map_or(2, |r| r.len() + 11));
                out.push('{');
                if let Some(result) = result {
                    out.push_str(r#""result":"#);
                    out.push_str(result);
                }
                out.push('}');
                return Answer(out);
            }
            ReadOutcome::Failed(failure) => failure,
        };
        // `err?.code || INTERNAL_ERROR_CODE`: a falsy code (0, "", null,
        // false) is none, as a node's code 0 is.
        let code = failure
            .code
            .filter(|code| fc_json::parse(code).is_ok_and(|value| value.truthy()));
        let mut out = String::from(r#"{"error":{"code":"#);
        match code {
            Some(code) => out.push_str(code),
            None => out.push_str(&INTERNAL_ERROR_CODE.to_string()),
        }
        out.push_str(r#","message":"#);
        match &self.provider_text {
            Some(text) => JsString::from(text.as_str()).quote_into(&mut out),
            None if failure.message.is_empty() => {
                let text = format!("All chain sources failed for chain {}", self.chain_id);
                JsString::from(text).quote_into(&mut out);
            }
            None => failure.message.quote_into(&mut out),
        }
        if let Some(data) = failure.data {
            out.push_str(r#","data":"#);
            out.push_str(data);
        }
        out.push_str("}}");
        Answer(out)
    }
}
