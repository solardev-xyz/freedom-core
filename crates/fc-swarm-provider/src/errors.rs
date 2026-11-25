//! A node's error answers, as each of the reference's call sites turns them
//! into an error (design 0015, `shell.swarm_api`, "Error texts"), and the
//! provider's mappings of the services' errors to a page's
//! (`nodeWriteError`, `mapChunkReadError`, `isBatchNotYetKnownError`).
//!
//! **The sites,** each its own text:
//! - **bee-js 13.2.0's `throwHttpError`**, for every bee-js call, an
//!   array-buffer download included: the body as `Response.text()` (a
//!   byte-order mark dropped), parsed as JSON when it parses.
//! - **#1057's `fetchNode`** (feed-service.js, the latest feed entry): the
//!   first 4,096 bytes as `Buffer.toString('utf8')` (the mark kept), then
//!   the same rule.
//! - **chunk-service.js's SOC upload:** `SOC upload failed (<status>): …`
//!   with the body's text as it came.
//! - **page-upload.js** (a page's `publishData` and `publishFiles`): the
//!   body as `Buffer.toString('utf8')`, its JSON in JSON's own form, and
//!   `HTTP <status>` when the status has no reason phrase.
//!
//! **The bound** (deviation `error-body-bound`): the core reads at most
//! [`ERROR_BODY_CAP`] bytes of an error body, where bee-js reads all of it,
//! so a longer body's text comes from its first 8 KiB.
//!
//! **JSON in its own form:** a body that parses is written back as
//! `JSON.stringify(JSON.parse(text))` by a transcoder ([`transcode`]) that
//! keeps only the text and each open object's members, never a parsed
//! value; nesting past [`crate::json::MAX_NESTING`] fails as
//! [`ReadError::TooDeep`].

use std::collections::HashMap;

use fc_json::{JsString, number_to_string};

use crate::js::{self, buffer_text, response_text, trimmed_lowercase_is};
use crate::json::{ReadError, Reader, Token};
use crate::stamps::{JsError, PostageError};

/// The most of an error body the core reads (design 0015, `shell.swarm_api`:
/// "its body read up to 8 KiB").
pub const ERROR_BODY_CAP: usize = 8192;

/// The most of an error body #1057's `fetchNode` reads.
const FETCH_NODE_ERROR_BYTES: usize = 4096;

/// Where a node's error answer is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Site {
    /// bee-js 13.2.0's `http`: every bee-js call, JSON or array buffer.
    BeeJs,
    /// #1057's latest-feed reader.
    FetchNode,
    /// chunk-service.js's `uploadSingleOwnerChunk`.
    SocUpload,
    /// page-upload.js's `post`.
    PageUpload,
}

/// The class of a node error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeErrorName {
    BeeResponseError,
    Error,
}

impl NodeErrorName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeeResponseError => "BeeResponseError",
            Self::Error => "Error",
        }
    }
}

/// A `BeeResponseError`'s `responseBody`: what its body parsed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorBody {
    /// An empty body: `undefined`.
    Undefined,
    /// A body that isn't JSON (its text), or one that is a JSON string.
    String(JsString),
    /// Any other JSON value, as `JSON.stringify` writes it, and its
    /// `message` when it is an object whose `message` is a string.
    Json {
        text: String,
        message: Option<JsString>,
    },
}

/// A node's error answer at a call site, as the reference throws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeError {
    pub name: NodeErrorName,
    pub message: JsString,
    /// `status`, where the site's error carries it.
    pub status: Option<u16>,
    /// `statusText`, where the site's error carries it.
    pub status_text: Option<String>,
    /// `responseBody`, for a `BeeResponseError`.
    pub body: Option<ErrorBody>,
}

/// The error a site throws for a node's answer `status` (outside 200–299)
/// with reason phrase `status_text` and `body` (of which the first
/// [`ERROR_BODY_CAP`] bytes are read).
pub fn http_error(
    site: Site,
    status: u16,
    status_text: &str,
    body: &[u8],
) -> Result<NodeError, ReadError> {
    let body = &body[..body.len().min(ERROR_BODY_CAP)];
    let reason = JsString::from(status_text);
    Ok(match site {
        Site::BeeJs | Site::FetchNode => {
            let text = if site == Site::BeeJs {
                response_text(body)
            } else {
                buffer_text(&body[..body.len().min(FETCH_NODE_ERROR_BYTES)])
            };
            let data = parse_body(&text)?;
            let message = match &data {
                ErrorBody::Undefined => reason.clone(),
                ErrorBody::String(s) if s.utf16_len() == 0 => reason.clone(),
                ErrorBody::String(s) => js::concat(&[&reason, &JsString::from(": "), s]),
                ErrorBody::Json { text, .. } => JsString::from(format!("{status_text}: {text}")),
            };
            NodeError {
                name: NodeErrorName::BeeResponseError,
                message,
                status: Some(status),
                status_text: Some(status_text.to_owned()),
                body: Some(data),
            }
        }
        Site::SocUpload => {
            let text = response_text(body);
            let shown = if !text.is_empty() {
                text.as_str()
            } else if !status_text.is_empty() {
                status_text
            } else {
                "Bee rejected request"
            };
            NodeError {
                name: NodeErrorName::Error,
                message: JsString::from(format!("SOC upload failed ({status}): {shown}")),
                status: None,
                status_text: None,
                body: None,
            }
        }
        Site::PageUpload => {
            let text = buffer_text(body);
            let shown = if text.is_empty() {
                JsString::default()
            } else {
                match transcode(text.as_bytes()) {
                    Ok(Parsed::String(s)) => s,
                    Ok(Parsed::Json { text, .. }) => JsString::from(text),
                    Err(ReadError::Syntax(_)) => JsString::from(text),
                    Err(e) => return Err(e),
                }
            };
            page_upload_error(status, status_text, &shown)
        }
    })
}

/// page-upload.js's error for a redirect, which it never follows.
pub fn page_upload_redirect(status: u16, status_text: &str) -> NodeError {
    page_upload_error(
        status,
        status_text,
        &JsString::from("Freedom uploads only to the node itself, and follows no redirect"),
    )
}

/// page-upload.js's `responseError(status, statusText, body)`.
fn page_upload_error(status: u16, status_text: &str, body: &JsString) -> NodeError {
    let message = if body.utf16_len() > 0 {
        js::concat(&[&JsString::from(status_text), &JsString::from(": "), body])
    } else if !status_text.is_empty() {
        JsString::from(status_text)
    } else {
        JsString::from(format!("HTTP {status}"))
    };
    NodeError {
        name: NodeErrorName::Error,
        message,
        status: Some(status),
        status_text: Some(status_text.to_owned()),
        body: None,
    }
}

/// bee-js's `readErrorBody`: `undefined` for an empty text, the parse when
/// the text is JSON, else the text.
fn parse_body(text: &str) -> Result<ErrorBody, ReadError> {
    if text.is_empty() {
        return Ok(ErrorBody::Undefined);
    }
    match transcode(text.as_bytes()) {
        Ok(Parsed::String(s)) => Ok(ErrorBody::String(s)),
        Ok(Parsed::Json { text, message }) => Ok(ErrorBody::Json { text, message }),
        Err(ReadError::Syntax(_)) => Ok(ErrorBody::String(JsString::from(text))),
        Err(e) => Err(e),
    }
}

impl NodeError {
    /// chunk-service.js's `isChunkNotFoundError`: a `BeeResponseError` with
    /// status 404, or 500 whose body's `message`, trimmed and lowercased, is
    /// `read chunk failed`.
    pub fn is_chunk_not_found(&self) -> bool {
        if self.name != NodeErrorName::BeeResponseError {
            return false;
        }
        match self.status {
            Some(404) => true,
            Some(500) => self
                .body_message()
                .is_some_and(|m| trimmed_lowercase_is(&m, "read chunk failed")),
            _ => false,
        }
    }

    /// chunk-service.js's `getBeeResponseBodyMessage`: an object body's
    /// string `message`, or that of a string body that parses as JSON.
    fn body_message(&self) -> Option<JsString> {
        match self.body.as_ref()? {
            ErrorBody::Undefined => None,
            ErrorBody::Json { message, .. } => message.clone(),
            ErrorBody::String(s) if s.utf16_len() == 0 => None,
            // `JSON.parse(String(body))?.message`. A lone surrogate, which
            // reads here as U+FFFD, can't make the message match.
            ErrorBody::String(s) => match transcode(s.as_bytes()) {
                Ok(Parsed::Json { message, .. }) => message,
                _ => None,
            },
        }
    }

    /// feed-service.js's `isNotFoundError`: a `BeeResponseError` with status
    /// 404 or 500.
    pub fn is_not_found(&self) -> bool {
        self.name == NodeErrorName::BeeResponseError && matches!(self.status, Some(404 | 500))
    }
}

/// What [`transcode`] read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// The text is a JSON string: the string.
    String(JsString),
    /// Any other value: `JSON.stringify` of it, and an object's string
    /// `message` (its last, as `JSON.parse` keeps).
    Json {
        text: String,
        message: Option<JsString>,
    },
}

enum Frame {
    Array {
        out: String,
        first: bool,
    },
    Object {
        members: Vec<(JsString, String)>,
        index: HashMap<JsString, usize>,
        key: Option<JsString>,
    },
}

/// `JSON.stringify(JSON.parse(text))`, written as the text is read. Each
/// open object keeps its members until it closes, so a repeated key keeps
/// its first place and its last value, and keys in JavaScript's property
/// order (array indices first, ascending); nothing else is kept but the
/// text. A JSON string is given back as the string.
pub fn transcode(text: &[u8]) -> Result<Parsed, ReadError> {
    let mut r = Reader::new(text);
    let first = r.token()?;
    if let Token::String(raw) = first {
        r.finish()?;
        return Ok(Parsed::String(raw.decode()));
    }
    let mut stack: Vec<Frame> = Vec::new();
    let mut message: Option<JsString> = None;
    let mut token = first;
    loop {
        // A value's start: a container opens, a scalar is complete.
        let mut done: Option<(String, Option<JsString>)> = match token {
            Token::Object => {
                stack.push(Frame::Object {
                    members: Vec::new(),
                    index: HashMap::new(),
                    key: None,
                });
                None
            }
            Token::Array => {
                stack.push(Frame::Array {
                    out: String::from("["),
                    first: true,
                });
                None
            }
            Token::String(raw) => {
                let s = raw.decode();
                let mut out = String::new();
                s.quote_into(&mut out);
                Some((out, Some(s)))
            }
            Token::Number(n) if n.is_finite() => Some((number_to_string(n), None)),
            // JSON.stringify(Infinity) is null.
            Token::Number(_) | Token::Null => Some((String::from("null"), None)),
            Token::Bool(b) => Some((String::from(if b { "true" } else { "false" }), None)),
        };
        // Attach each complete value to its container, closing what ends,
        // until the next value starts.
        loop {
            if let Some((text, string)) = done.take() {
                let root_object = stack.len() == 1;
                match stack.last_mut() {
                    None => {
                        r.finish()?;
                        return Ok(Parsed::Json { text, message });
                    }
                    Some(Frame::Array { out, first }) => {
                        if !*first {
                            out.push(',');
                        }
                        out.push_str(&text);
                        *first = false;
                    }
                    Some(Frame::Object {
                        members,
                        index,
                        key,
                    }) => {
                        let Some(key) = key.take() else {
                            return Err(ReadError::Syntax(0));
                        };
                        if root_object && key == "message" {
                            message = string;
                        }
                        match index.get(&key) {
                            Some(&i) => members[i].1 = text,
                            None => {
                                index.insert(key.clone(), members.len());
                                members.push((key, text));
                            }
                        }
                    }
                }
            }
            match stack.last_mut() {
                // Attaching to no container returned above.
                None => return Err(ReadError::Syntax(0)),
                Some(Frame::Array { .. }) => {
                    if r.next_element()? {
                        token = r.token()?;
                        break;
                    }
                    if let Some(Frame::Array { mut out, .. }) = stack.pop() {
                        out.push(']');
                        done = Some((out, None));
                    }
                }
                Some(Frame::Object { key, .. }) => match r.next_key()? {
                    Some(k) => {
                        *key = Some(k.decode());
                        token = r.token()?;
                        break;
                    }
                    None => {
                        if let Some(Frame::Object { members, .. }) = stack.pop() {
                            done = Some((write_object(members), None));
                        }
                    }
                },
            }
        }
    }
}

/// An object's members as `JSON.stringify` writes them: array-index keys
/// first, ascending, then the rest in their first places.
fn write_object(members: Vec<(JsString, String)>) -> String {
    let (mut indices, rest): (Vec<_>, Vec<_>) = members
        .into_iter()
        .partition(|(key, _)| array_index(key).is_some());
    indices.sort_by_key(|(key, _)| array_index(key));
    let mut out = String::from("{");
    for (i, (key, value)) in indices.into_iter().chain(rest).enumerate() {
        if i > 0 {
            out.push(',');
        }
        key.quote_into(&mut out);
        out.push(':');
        out.push_str(&value);
    }
    out.push('}');
    out
}

/// An array index: the canonical decimal text of an integer below
/// 2^32 - 1.
fn array_index(key: &JsString) -> Option<u32> {
    let s = key.as_str();
    if !key.is_well_formed() || s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    let value: u32 = s.parse().ok()?;
    (value != u32::MAX).then_some(value)
}

/// A page's error: `{ code, message, data: { reason } }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageError {
    pub code: i32,
    pub message: JsString,
    pub reason: Option<&'static str>,
}

/// `ERRORS.NODE_UNAVAILABLE`'s code.
pub const NODE_UNAVAILABLE: i32 = 4900;
/// `ERRORS.INVALID_PARAMS`'s code.
pub const INVALID_PARAMS: i32 = -32602;
/// `ERRORS.INTERNAL_ERROR`'s code.
pub const INTERNAL_ERROR: i32 = -32603;

/// The page's text for a node reply past its cap, outside a page's read
/// (design 0015, `shell.swarm_api`: `too_large`; deviation `reply-bounds`).
pub const REPLY_TOO_LARGE_MESSAGE: &str = "Swarm node reply too large";

/// A call that failed `too_large` outside a page's read: -32603
/// [`REPLY_TOO_LARGE_MESSAGE`]. (A page's read gets #1057's
/// `data_too_large` instead, which its machine gives.)
pub fn reply_too_large() -> PageError {
    PageError {
        code: INTERNAL_ERROR,
        message: JsString::from(REPLY_TOO_LARGE_MESSAGE),
        reason: None,
    }
}

/// ant-storage-api.js's text for a batch the network doesn't know yet.
pub const BATCH_NOT_YET_KNOWN_MESSAGE: &str =
    "Your storage is still reaching the Swarm network. Try again in a minute.";

/// batch-errors.js's `noUsableBatchError` message.
pub const NO_USABLE_BATCH_MESSAGE: &str = "No usable postage batch available. Your storage is full or expired: buy more storage to publish.";

/// An error the services throw, as the provider's mappings read it: its
/// message, `code` and `reason`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    pub message: JsString,
    pub code: Option<&'static str>,
    pub reason: Option<&'static str>,
}

impl ServiceError {
    fn plain(message: JsString) -> Self {
        Self {
            message,
            code: None,
            reason: None,
        }
    }

    fn with_reason(reason: &'static str, message: JsString) -> Self {
        Self {
            message,
            code: None,
            reason: Some(reason),
        }
    }

    /// batch-errors.js's `noUsableBatchError()`: what a write throws when
    /// `selectBestBatch` answers `null`.
    pub fn no_usable_batch() -> Self {
        Self {
            message: JsString::from(NO_USABLE_BATCH_MESSAGE),
            code: Some("no-usable-stamps"),
            reason: None,
        }
    }
}

impl From<&NodeError> for ServiceError {
    fn from(err: &NodeError) -> Self {
        Self::plain(err.message.clone())
    }
}

impl From<&JsError> for ServiceError {
    fn from(err: &JsError) -> Self {
        Self::plain(err.message.clone())
    }
}

impl From<&PostageError> for ServiceError {
    fn from(err: &PostageError) -> Self {
        Self {
            message: JsString::from(err.code.message()),
            code: Some(err.code.code()),
            reason: None,
        }
    }
}

/// ant-storage-api.js's `isBatchNotYetKnownError`:
/// `/rejected by \d+ peer\(s\) as not found on-chain/i`. Without the `u`
/// flag, `i` folds only ASCII letters onto ASCII letters.
pub fn is_batch_not_yet_known_error(message: &JsString) -> bool {
    const HEAD: &[u8] = b"rejected by ";
    const TAIL: &[u8] = b" peer(s) as not found on-chain";
    let s = message.as_bytes();
    let at = |i: usize, word: &[u8]| {
        s.get(i..i + word.len())
            .is_some_and(|part| part.eq_ignore_ascii_case(word))
    };
    (0..s.len()).any(|start| {
        if !at(start, HEAD) {
            return false;
        }
        let digits_start = start + HEAD.len();
        let digits = s[digits_start..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        digits > 0 && at(digits_start + digits, TAIL)
    })
}

/// swarm-provider-ipc.js's `nodeWriteError`: no batch with room is the
/// pre-flight's `no-usable-stamps`; a batch the network doesn't know yet is
/// `node-not-ready`; anything else -32603 with the node's message.
pub fn node_write_error(err: &ServiceError) -> PageError {
    if matches!(
        err.code,
        Some("no-usable-stamps" | "POSTAGE_UNAVAILABLE" | "POSTAGE_CAPACITY_INSUFFICIENT")
    ) {
        return PageError {
            code: NODE_UNAVAILABLE,
            message: err.message.clone(),
            reason: Some("no-usable-stamps"),
        };
    }
    if is_batch_not_yet_known_error(&err.message) {
        return PageError {
            code: NODE_UNAVAILABLE,
            message: JsString::from(BATCH_NOT_YET_KNOWN_MESSAGE),
            reason: Some("node-not-ready"),
        };
    }
    PageError {
        code: INTERNAL_ERROR,
        message: err.message.clone(),
        reason: None,
    }
}

/// swarm-provider-ipc.js's `mapChunkReadError`: a chunk not found or not
/// the one asked for is the page's -32602 with its reason; anything else
/// -32603.
pub fn map_chunk_read_error(err: &ServiceError) -> PageError {
    match err.reason {
        Some(reason @ ("chunk_not_found" | "chunk_type_mismatch")) => PageError {
            code: INVALID_PARAMS,
            message: err.message.clone(),
            reason: Some(reason),
        },
        _ => PageError {
            code: INTERNAL_ERROR,
            message: err.message.clone(),
            reason: None,
        },
    }
}

/// Which of chunk-service.js's reads a chunk download serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkRead {
    /// `readChunk`.
    Chunk,
    /// `readDataRoot` and `readData`.
    Data,
    /// `readSingleOwnerChunk`.
    SingleOwnerChunk,
}

/// A read's error for a node error on its download: `chunk_not_found` when
/// `isChunkNotFoundError`, else the node's error itself.
pub fn chunk_read_error(read: ChunkRead, reference: &str, err: &NodeError) -> ServiceError {
    if !err.is_chunk_not_found() {
        return ServiceError::from(err);
    }
    let message = match read {
        ChunkRead::Chunk => format!("Chunk not found: {reference}"),
        ChunkRead::Data => format!("Data not found: {reference}"),
        ChunkRead::SingleOwnerChunk => String::from("Single Owner Chunk not found"),
    };
    ServiceError::with_reason("chunk_not_found", JsString::from(message))
}

/// A read's error for bytes that aren't the chunk asked for.
pub fn chunk_type_mismatch(read: ChunkRead) -> ServiceError {
    let what = match read {
        ChunkRead::Chunk | ChunkRead::Data => "content-addressed chunk",
        ChunkRead::SingleOwnerChunk => "Single Owner Chunk",
    };
    ServiceError::with_reason(
        "chunk_type_mismatch",
        JsString::from(format!(
            "Downloaded bytes do not validate as the requested {what}"
        )),
    )
}

/// feed-service.js's `readFeedPayload` for a node error: a `BeeResponseError`
/// 404 or 500 is `entry_not_found` at an explicit index and `feed_empty`
/// for the latest entry; anything else goes on as it is (`None`).
pub fn feed_read_error(err: &NodeError, index: Option<u64>) -> Option<ServiceError> {
    if !err.is_not_found() {
        return None;
    }
    Some(match index {
        Some(index) => ServiceError::with_reason(
            "entry_not_found",
            JsString::from(format!("Feed entry not found at index {index}")),
        ),
        None => ServiceError::with_reason(
            "feed_empty",
            JsString::from("Feed is empty — no entries to read"),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> String {
        match transcode(text.as_bytes()).unwrap() {
            Parsed::Json { text, .. } => text,
            Parsed::String(s) => format!("string {s:?}"),
        }
    }

    #[test]
    fn transcoding_is_stringify_of_parse() {
        assert_eq!(
            json(" { \"b\" : 1 , \"a\" : [ 1 , 2 ] } "),
            r#"{"b":1,"a":[1,2]}"#
        );
        assert_eq!(
            json(r#"{"m":"first","m":"last","c":1}"#),
            r#"{"m":"last","c":1}"#
        );
        assert_eq!(
            json(r#"{"b":1,"2":2,"1":1,"01":0,"4294967295":5}"#),
            r#"{"1":1,"2":2,"b":1,"01":0,"4294967295":5}"#
        );
        assert_eq!(
            json(r#"[1e400,-0,1E2,0.0000001,12345678901234567890]"#),
            "[null,0,100,1e-7,12345678901234567000]"
        );
        assert_eq!(
            json(r#"{"s":"\ud800\u00e9\/\u0001"}"#),
            "{\"s\":\"\\ud800\u{e9}/\\u0001\"}"
        );
        assert_eq!(json("[[],{},[{}]]"), "[[],{},[{}]]");
        assert_eq!(json("null"), "null");
        assert_eq!(json("true"), "true");
        assert_eq!(
            transcode(b"\"x\"").unwrap(),
            Parsed::String(JsString::from("x"))
        );
        assert!(matches!(transcode(b"{\"a\":}"), Err(ReadError::Syntax(_))));
        assert!(matches!(transcode(b"[1] x"), Err(ReadError::Syntax(_))));
        assert!(matches!(transcode(b""), Err(ReadError::Syntax(_))));
    }

    #[test]
    fn the_root_message_is_kept() {
        let message = |text: &str| match transcode(text.as_bytes()).unwrap() {
            Parsed::Json { message, .. } => message,
            Parsed::String(_) => None,
        };
        assert_eq!(
            message(r#"{"message":"a","message":"b"}"#),
            Some(JsString::from("b"))
        );
        assert_eq!(message(r#"{"message":"a","message":1}"#), None);
        assert_eq!(message(r#"{"inner":{"message":"a"}}"#), None);
        assert_eq!(message(r#"[{"message":"a"}]"#), None);
    }

    #[test]
    fn each_site_reads_its_own_text() {
        let message = |site, status, text: &str, body: &[u8]| {
            http_error(site, status, text, body).unwrap().message
        };
        // fetchNode: Buffer.toString keeps the mark, so the JSON doesn't parse.
        let bom = b"\xEF\xBB\xBF{\"message\":\"x\"}";
        assert_eq!(
            message(Site::FetchNode, 503, "Service Unavailable", bom),
            "Service Unavailable: \u{FEFF}{\"message\":\"x\"}"
        );
        assert_eq!(
            message(Site::BeeJs, 503, "Service Unavailable", bom),
            "Service Unavailable: {\"message\":\"x\"}"
        );
        // fetchNode reads 4,096 bytes: a sequence cut there is U+FFFD.
        let mut long = vec![b'a'; 4095];
        long.extend_from_slice("é and more".as_bytes());
        assert_eq!(
            message(Site::FetchNode, 503, "S", &long),
            format!("S: {}\u{FFFD}", "a".repeat(4095))
        );
        // page-upload.js: no reason phrase and nothing to show.
        assert_eq!(message(Site::PageUpload, 502, "", b""), "HTTP 502");
        assert_eq!(message(Site::PageUpload, 502, "", b"\"\""), "HTTP 502");
        assert_eq!(message(Site::PageUpload, 502, "", b"[]"), ": []");
        assert_eq!(
            message(Site::BeeJs, 502, "Bad Gateway", b"\"\""),
            "Bad Gateway"
        );
        assert_eq!(
            page_upload_redirect(307, "Temporary Redirect").message,
            "Temporary Redirect: Freedom uploads only to the node itself, and follows no redirect"
        );
        // The SOC upload shows the text as it came.
        assert_eq!(
            message(
                Site::SocUpload,
                500,
                "Internal Server Error",
                b"{\"a\":1, \"a\":2}"
            ),
            "SOC upload failed (500): {\"a\":1, \"a\":2}"
        );
        // A JSON string holding JSON: isChunkNotFoundError parses it again.
        let err = http_error(
            Site::BeeJs,
            500,
            "Internal Server Error",
            br#""{\"message\":\" read chunk FAILED\"}""#,
        )
        .unwrap();
        assert!(err.is_chunk_not_found());
    }

    #[test]
    fn batch_not_yet_known_is_the_regex() {
        let is = |t: &str| is_batch_not_yet_known_error(&JsString::from(t));
        assert!(is(
            "pushsync: postage batch 0xab rejected by 3 peer(s) as not found on-chain"
        ));
        assert!(is("REJECTED BY 12 PEER(S) AS NOT FOUND ON-CHAIN"));
        assert!(!is("rejected by peer(s) as not found on-chain"));
        assert!(!is("rejected by 1 peers as not found on-chain"));
        assert!(!is("rejected by ١ peer(s) as not found on-chain"));
        assert!(is(
            "rejected by rejected by 2 peer(s) as not found on-chain"
        ));
    }
}
