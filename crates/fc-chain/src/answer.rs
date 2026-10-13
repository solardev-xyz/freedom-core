//! An RPC answer read as the router's `requestRpcUrl` reads it: `HTTP
//! <status>` unless the status is 2xx; `response.json()`; then
//! `data.error`, thrown as an `Error`, or `data.result`.
//!
//! The router keeps parsed values; the core keeps the decoded text and the
//! spans of what it needs:
//! - **Decoding** is undici's: a leading UTF-8 BOM is dropped, and then
//!   `TextDecoder` drops another; the rest is UTF-8 with replacement.
//! - **JSON** is V8's grammar, nesting at most 512 levels (deviation
//!   `json-depth`). A parse failure gets a fixed text (deviation
//!   `json-parse-text`): V8's `SyntaxError` quotes the body.
//! - **The result** is the text of the last top-level `result` member, as
//!   `JSON.parse` keeps the last of duplicate keys; without one, it is
//!   `undefined`, as is any body that is not an object (or `null`, which
//!   throws a `TypeError`).
//! - **A node error** is a truthy `error` member: its message is
//!   `String(error.message)` when that is truthy, `RPC request failed`
//!   otherwise; `code` and `data` are kept as their text.

use std::ops::Range;

use fc_json::index::{Index, IndexError, Kind, Value};

use crate::js::{JsError, JsString, NOT_PRIMITIVE, js_string_of};

/// The core's text for a body that isn't JSON (deviation `json-parse-text`).
pub const JSON_PARSE_FAILURE: &str = "The RPC answer is not valid JSON";

/// The core's text for a body nested too deep (deviation `json-depth`).
pub const JSON_DEPTH_FAILURE: &str = "The RPC answer is nested deeper than 512 levels";

/// An answer the router would not return a result or node error for.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnswerError {
    /// A status outside 200 to 299; the body is not read.
    #[error("HTTP {0}")]
    Status(u16),
    /// Not JSON (V8: a `SyntaxError` quoting the body).
    #[error("{JSON_PARSE_FAILURE}")]
    Syntax,
    /// Nested deeper than 512 levels, where V8 has no limit.
    #[error("{JSON_DEPTH_FAILURE}")]
    TooDeep,
    /// Longer than an index addresses (4 GiB): beyond every cap.
    #[error("The RPC answer is too long")]
    TooLong,
    /// A `null` body: reading `data.error` throws.
    #[error("Cannot read properties of null (reading 'error')")]
    NullBody,
    /// The error's message is an object with its own `toString` key:
    /// `new Error(message)` throws.
    #[error("{NOT_PRIMITIVE}")]
    NotPrimitive,
}

impl AnswerError {
    /// The constructor's name of the error the router throws.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Status(_) | Self::TooDeep | Self::TooLong => "Error",
            Self::Syntax => "SyntaxError",
            Self::NullBody | Self::NotPrimitive => "TypeError",
        }
    }

    /// Whether the core's text differs from the router's by design: the
    /// deviation's ID.
    pub fn deviation(&self) -> Option<&'static str> {
        match self {
            Self::Syntax => Some("json-parse-text"),
            Self::TooDeep | Self::TooLong => Some("json-depth"),
            _ => None,
        }
    }
}

impl From<IndexError> for AnswerError {
    fn from(error: IndexError) -> Self {
        match error {
            IndexError::Syntax(_) => Self::Syntax,
            IndexError::TooDeep => Self::TooDeep,
            IndexError::TooLong(_) => Self::TooLong,
        }
    }
}

/// A decoded answer: its text, and what the router makes of it.
#[derive(Debug, Clone)]
pub struct Answer {
    /// The body as `TextDecoder` gives it, BOMs dropped.
    text: String,
    reply: Reply,
    /// The heap the body's index took while it was read.
    index_bytes: usize,
}

#[derive(Debug, Clone)]
enum Reply {
    Result(Option<Range<usize>>),
    NodeError {
        message: JsString,
        code: Option<Range<usize>>,
        data: Option<Range<usize>>,
    },
}

/// What the router returns or throws for an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome<'a> {
    /// `data.result`: its JSON text, or `None` for `undefined`.
    Result(Option<&'a str>),
    /// `data.error`, thrown.
    NodeError(NodeError<'a>),
}

/// The `Error` the router builds from a node's `error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeError<'a> {
    pub message: &'a JsString,
    /// `error.code`'s JSON text; `None` is `undefined`.
    pub code: Option<&'a str>,
    /// `error.data`'s JSON text; `None` is `undefined`.
    pub data: Option<&'a str>,
}

impl Answer {
    /// The decoded body, BOMs dropped.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The heap the body's index took while it was read (memory budgets
    /// charge it).
    pub fn index_bytes(&self) -> usize {
        self.index_bytes
    }

    /// The result's span in [`Answer::text`]: `Some(None)` for `undefined`,
    /// `None` for a node error.
    pub fn result_span(&self) -> Option<Option<Range<usize>>> {
        match &self.reply {
            Reply::Result(range) => Some(range.clone()),
            Reply::NodeError { .. } => None,
        }
    }

    /// The decoded body, kept whole.
    pub fn into_text(self) -> String {
        self.text
    }

    pub fn outcome(&self) -> Outcome<'_> {
        let span = |range: &Option<Range<usize>>| {
            range
                .as_ref()
                .and_then(|range| self.text.get(range.clone()))
        };
        match &self.reply {
            Reply::Result(range) => Outcome::Result(span(range)),
            Reply::NodeError {
                message,
                code,
                data,
            } => Outcome::NodeError(NodeError {
                message,
                code: span(code),
                data: span(data),
            }),
        }
    }
}

/// Reads an answer with HTTP status `status` and body `body`.
pub fn decode_answer(status: u16, body: Vec<u8>) -> Result<Answer, AnswerError> {
    if !(200..=299).contains(&status) {
        return Err(AnswerError::Status(status));
    }
    let text = decode_text(body);
    let (reply, index_bytes) = read(&text)?;
    Ok(Answer {
        text,
        reply,
        index_bytes,
    })
}

/// A body as undici's `text()` and `json()` decode it: UTF-8 with
/// replacement; undici drops a BOM's bytes, then `TextDecoder` drops a
/// decoded one.
pub(crate) fn decode_text(body: Vec<u8>) -> String {
    let mut text = String::from_utf8(body)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned());
    let boms = text
        .char_indices()
        .take(2)
        .take_while(|(_, c)| *c == '\u{FEFF}')
        .count();
    text.drain(..boms * '\u{FEFF}'.len_utf8());
    text
}

fn read(text: &str) -> Result<(Reply, usize), AnswerError> {
    let index = Index::new(text)?;
    let reply = reply(&index)?;
    Ok((reply, index.heap_bytes()))
}

fn reply(index: &Index<'_>) -> Result<Reply, AnswerError> {
    let root = index.root();
    let span = |value: Value<'_, '_>| value.start()..value.end();
    match root.kind() {
        Kind::Null => Err(AnswerError::NullBody),
        Kind::Object => match root.get("error").filter(|e| e.truthy()) {
            Some(error) if error.kind() == Kind::Object => {
                let message = match error.get("message").filter(|m| m.truthy()) {
                    Some(message) => {
                        js_string_of(message).map_err(|_: JsError| AnswerError::NotPrimitive)?
                    }
                    None => JsString::from("RPC request failed"),
                };
                Ok(Reply::NodeError {
                    message,
                    code: error.get("code").map(span),
                    data: error.get("data").map(span),
                })
            }
            // A string, number, `true` or array: none has a message.
            Some(_) => Ok(Reply::NodeError {
                message: JsString::from("RPC request failed"),
                code: None,
                data: None,
            }),
            None => Ok(Reply::Result(root.get("result").map(span))),
        },
        // `data.error` and `data.result` of a primitive or an array.
        _ => Ok(Reply::Result(None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(body: &[u8]) -> Option<String> {
        match decode_answer(200, body.to_vec()).unwrap().outcome() {
            Outcome::Result(text) => text.map(str::to_owned),
            Outcome::NodeError(error) => panic!("{error:?}"),
        }
    }

    #[test]
    fn results_and_errors() {
        assert_eq!(
            result(br#"{"result":1,"result": [ 2 ] }"#).as_deref(),
            Some("[ 2 ]")
        );
        assert_eq!(
            result(b"\xEF\xBB\xBF\xEF\xBB\xBF{\"result\":\"\xFF\"}").as_deref(),
            Some("\"\u{FFFD}\"")
        );
        assert_eq!(result(br#"{"__proto__":{"result":1}}"#), None);
        assert_eq!(result(b"[1]"), None);
        assert_eq!(
            decode_answer(200, b"\xEF\xBB\xBF\xEF\xBB\xBF\xEF\xBB\xBF1".to_vec()).unwrap_err(),
            AnswerError::Syntax
        );
        assert_eq!(
            decode_answer(404, b"{}".to_vec()).unwrap_err().to_string(),
            "HTTP 404"
        );
        assert_eq!(
            decode_answer(200, b"null".to_vec()).unwrap_err().name(),
            "TypeError"
        );
        let answer = decode_answer(
            200,
            br#"{"error":{"message":[1,null],"code":-32000,"data":{"a":1}}}"#.to_vec(),
        )
        .unwrap();
        let Outcome::NodeError(error) = answer.outcome() else {
            panic!()
        };
        assert_eq!(error.message.to_json(), r#""1,""#);
        assert_eq!(
            (error.code, error.data),
            (Some("-32000"), Some(r#"{"a":1}"#))
        );
    }
}
