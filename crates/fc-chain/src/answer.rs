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

use crate::js::{JsString, NOT_PRIMITIVE, js_string_len, js_string_of};

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
    read_answer(decode_body(body))
}

/// The buffer [`decode_body`] allocates for `body`: the length of its
/// replacement decoding, or `None` when the body is valid UTF-8 and is
/// decoded in place. A caller reserves it before decoding: an invalid
/// byte becomes U+FFFD's three bytes, so the text can be three times the
/// body.
pub fn replaced_len(body: &[u8]) -> Option<usize> {
    if std::str::from_utf8(body).is_ok() {
        return None;
    }
    Some(
        body.utf8_chunks()
            .map(|chunk| chunk.valid().len() + if chunk.invalid().is_empty() { 0 } else { 3 })
            .sum(),
    )
}

/// What the router makes of a decoded body (a 2xx answer's).
pub fn read_answer(text: String) -> Result<Answer, AnswerError> {
    match read_answer_reserving(text, |_| Ok::<(), std::convert::Infallible>(())) {
        Ok(read) => read,
        Err(never) => match never {},
    }
}

/// [`read_answer`], asking `reserve` for room before each allocation: the
/// index, before it is built, and a node error's message, before it is
/// made. An `Err` from `reserve` stops the read.
pub fn read_answer_reserving<E>(
    text: String,
    mut reserve: impl FnMut(usize) -> Result<(), E>,
) -> Result<Result<Answer, AnswerError>, E> {
    let needed = match Index::heap_needed(&text) {
        Ok(needed) => needed,
        Err(error) => return Ok(Err(error.into())),
    };
    reserve(needed)?;
    let reply = match Index::new(&text) {
        Ok(index) => reply(&index, &mut reserve)?,
        Err(error) => Err(error.into()),
    };
    Ok(reply.map(|reply| Answer { text, reply }))
}

/// A body as undici's `text()` and `json()` decode it: UTF-8 with
/// replacement (`String::from_utf8_lossy`'s, into a buffer of exactly
/// [`replaced_len`]); undici drops a BOM's bytes, then `TextDecoder` drops
/// a decoded one.
pub fn decode_body(body: Vec<u8>) -> String {
    let mut text = match String::from_utf8(body) {
        Ok(text) => text,
        Err(error) => {
            let bytes = error.into_bytes();
            let mut text = String::with_capacity(replaced_len(&bytes).unwrap_or(0));
            for chunk in bytes.utf8_chunks() {
                text.push_str(chunk.valid());
                if !chunk.invalid().is_empty() {
                    text.push('\u{FFFD}');
                }
            }
            text
        }
    };
    let boms = text
        .char_indices()
        .take(2)
        .take_while(|(_, c)| *c == '\u{FEFF}')
        .count();
    text.drain(..boms * '\u{FEFF}'.len_utf8());
    text
}

fn reply<E>(
    index: &Index<'_>,
    reserve: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<Result<Reply, AnswerError>, E> {
    let root = index.root();
    let span = |value: Value<'_, '_>| value.start()..value.end();
    Ok(match root.kind() {
        Kind::Null => Err(AnswerError::NullBody),
        Kind::Object => match root.get("error").filter(|e| e.truthy()) {
            Some(error) if error.kind() == Kind::Object => {
                let message = match error.get("message").filter(|m| m.truthy()) {
                    Some(message) => {
                        // Its UTF-16, reserved before it is made.
                        let Some(units) = js_string_len(message) else {
                            return Ok(Err(AnswerError::NotPrimitive));
                        };
                        reserve(units.saturating_mul(2))?;
                        match js_string_of(message) {
                            Ok(message) => message,
                            Err(_) => return Ok(Err(AnswerError::NotPrimitive)),
                        }
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
    })
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
    fn replacement_decoding_is_lossys_into_an_exact_buffer() {
        let bodies: [&[u8]; 5] = [
            b"plain",
            b"\xFF\xFE",
            b"a\xE2\x82b\xF0\x9F\x98",
            b"\xEF\xBB\xBF\xEF\xBB\xBFx\xC0",
            b"",
        ];
        for body in bodies {
            let lossy = String::from_utf8_lossy(body).into_owned();
            let decoded = decode_body(body.to_vec());
            let expected = lossy.trim_start_matches('\u{FEFF}');
            let boms = lossy.len() - expected.len();
            assert!(boms <= 6);
            assert_eq!(decoded, expected);
            match replaced_len(body) {
                None => assert!(std::str::from_utf8(body).is_ok()),
                Some(len) => assert_eq!((len, decoded.capacity()), (lossy.len(), len)),
            }
        }
        // Five thousand invalid bytes are fifteen thousand decoded.
        assert_eq!(replaced_len(&[0xFF; 5000]), Some(15_000));
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
