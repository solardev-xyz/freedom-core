//! Node calls (design 0015, "Node access" > `shell.swarm_api`): the forms,
//! the call a machine asks for and what each costs the swarm thread's
//! memory ("The swarm thread's memory"), and main's answers, read strictly
//! (design 0015, "Requests the core makes").

use crate::chunks::hex;
use crate::errors::{self, ERROR_BODY_CAP, NodeError, Site};
use crate::json::ReadError;
use crate::stamps::{ELEMENT_BYTES, STAMPS_BATCH_CAP, STAMPS_REPLY_CAP};

const KIB: usize = 1024;

/// A whole chunk reply's cap: a SOC, 32 + 65 + 8 + 4,096 bytes.
pub const CHUNK_REPLY_CAP: usize = 4201;
/// A whole JSON reply's cap but `/stamps`'.
pub const JSON_REPLY_CAP: usize = 64 * KIB;
/// The least a whole call reserves: any call can bring an error body and
/// its transcoding (design 0015, "The swarm thread's memory").
pub const CHARGE_FLOOR: usize = 512 * KIB;
/// The serialized reply's room beside its body.
const ENVELOPE: usize = 16 * KIB;

/// Reply headers: at most this many, names and values and the reason
/// phrase within their bounds (design 0015, `shell.swarm_api`).
pub const MAX_REPLY_HEADERS: usize = 8;
pub const MAX_HEADER_NAME: usize = 64;
pub const MAX_HEADER_VALUE: usize = KIB;
pub const MAX_REASON: usize = KIB;

/// 0007's per-stream window, which credit extends.
pub const WINDOW: u64 = 128 * 1024;
/// A data frame's most bytes.
pub const MAX_FRAME: usize = 64 * 1024;

/// `shell.swarm_api`'s forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    Chunk,
    Bytes,
    FeedHead,
    FeedLatest,
    Tag,
    Addresses,
    Stamps,
    Stamp,
    BzzFile,
    BzzTar,
    BytesUp,
    ChunkUp,
    SocUp,
    FeedManifest,
    PssSend,
}

impl Form {
    /// The form's name on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Form::Chunk => "chunk",
            Form::Bytes => "bytes",
            Form::FeedHead => "feed_head",
            Form::FeedLatest => "feed_latest",
            Form::Tag => "tag",
            Form::Addresses => "addresses",
            Form::Stamps => "stamps",
            Form::Stamp => "stamp",
            Form::BzzFile => "bzz_file",
            Form::BzzTar => "bzz_tar",
            Form::BytesUp => "bytes_up",
            Form::ChunkUp => "chunk_up",
            Form::SocUp => "soc_up",
            Form::FeedManifest => "feed_manifest",
            Form::PssSend => "pss_send",
        }
    }

    /// Its HTTP method.
    pub fn method(self) -> &'static str {
        match self {
            Form::Chunk
            | Form::Bytes
            | Form::FeedHead
            | Form::FeedLatest
            | Form::Tag
            | Form::Addresses
            | Form::Stamps
            | Form::Stamp => "GET",
            Form::BzzFile
            | Form::BzzTar
            | Form::BytesUp
            | Form::ChunkUp
            | Form::SocUp
            | Form::FeedManifest
            | Form::PssSend => "POST",
        }
    }

    /// Whether its reply streams (under `max_bytes`).
    pub fn streams(self) -> bool {
        matches!(self, Form::Bytes | Form::FeedLatest)
    }

    /// A whole reply's cap (none for a streamed one: its `max_bytes`).
    pub fn cap(self) -> usize {
        match self {
            Form::Chunk | Form::FeedHead => CHUNK_REPLY_CAP,
            Form::Bytes | Form::FeedLatest => 0,
            Form::Stamps => STAMPS_REPLY_CAP,
            _ => JSON_REPLY_CAP,
        }
    }

    /// Whether its whole reply is JSON, read by a typed reader.
    pub fn json(self) -> bool {
        !matches!(
            self,
            Form::Chunk | Form::FeedHead | Form::Bytes | Form::FeedLatest
        )
    }

    /// The typed reader's element cap `E` (design 0015, "JSON replies").
    pub fn elements(self) -> usize {
        match self {
            Form::Stamps => STAMPS_BATCH_CAP,
            _ if self.json() => 1,
            _ => 0,
        }
    }
}

/// `b64(m)`: 4⌈m / 3⌉.
pub fn b64(m: usize) -> usize {
    m.div_ceil(3).saturating_mul(4)
}

/// What a whole call reserves before it goes (design 0015, "The swarm
/// thread's memory"): `m + 2 × b64(m) + 16 KiB` for a binary body,
/// `4m + 2 × b64(m) + 16 KiB + E × 256 B` for JSON, `m` the form's cap,
/// and never less than [`CHARGE_FLOOR`].
pub fn whole_charge(form: Form) -> usize {
    let m = form.cap();
    let base = if form.json() {
        m.saturating_mul(4)
            .saturating_add(b64(m).saturating_mul(2))
            .saturating_add(ENVELOPE)
            .saturating_add(form.elements().saturating_mul(ELEMENT_BYTES))
    } else {
        m.saturating_add(b64(m).saturating_mul(2))
            .saturating_add(ENVELOPE)
    };
    base.max(CHARGE_FLOOR)
}

/// What a streamed read for a page reserves: `n + 2 × b64(n) + 16 KiB`,
/// `n` what the read may hold, and at least [`CHARGE_FLOOR`] for an error.
pub fn stream_charge(n: usize) -> usize {
    n.saturating_add(b64(n).saturating_mul(2))
        .saturating_add(ENVELOPE)
        .max(CHARGE_FLOOR)
}

/// A feed update a `chunk` call asks for: main builds its address from
/// these and the row's topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedRef {
    pub owner: [u8; 20],
    pub index: u64,
}

/// The occurrence a `chunk` call under `readData` fetches: its logical
/// length and depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeRef {
    pub length: u64,
    pub depth: u8,
}

/// A request body: inline (at most 64 KiB), or a stream the core writes
/// through `swarm.body` (the Publish and write pieces).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Base64(Vec<u8>),
    Stream { bytes: u64 },
}

/// One `shell.swarm_api` call: `{ for, form, method, path, query, headers,
/// body, max_bytes, stream, feed?, tree? }` without `for`, which is the
/// request's own. `headers` are the row's; main adds bee-js's `accept`
/// and `accept-encoding: identity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCall {
    pub form: Form,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Option<Body>,
    pub max_bytes: usize,
    pub feed: Option<FeedRef>,
    pub tree: Option<TreeRef>,
}

impl NodeCall {
    fn get(form: Form, path: String, max_bytes: usize) -> NodeCall {
        NodeCall {
            form,
            path,
            query: Vec::new(),
            headers: Vec::new(),
            body: None,
            max_bytes,
            feed: None,
            tree: None,
        }
    }

    /// `GET /chunks/<a>`.
    pub fn chunk(address: &[u8; 32]) -> NodeCall {
        NodeCall::get(
            Form::Chunk,
            format!("/chunks/{}", hex(address)),
            CHUNK_REPLY_CAP,
        )
    }

    /// The feed update this `chunk` call asks for.
    pub fn with_feed(mut self, owner: [u8; 20], index: u64) -> NodeCall {
        self.feed = Some(FeedRef { owner, index });
        self
    }

    /// The tree occurrence this `chunk` call fetches.
    pub fn with_tree(mut self, length: u64, depth: u8) -> NodeCall {
        self.tree = Some(TreeRef { length, depth });
        self
    }

    /// `GET /bytes/<a>`, streamed, held to `max_bytes`, with `range:
    /// bytes=<s>-<e>` or none.
    pub fn bytes(address: &[u8; 32], range: Option<(u64, u64)>, max_bytes: usize) -> NodeCall {
        let mut call = NodeCall::get(Form::Bytes, format!("/bytes/{}", hex(address)), max_bytes);
        if let Some((start, end)) = range {
            call.headers
                .push(("range".to_owned(), format!("bytes={start}-{end}")));
        }
        call
    }

    /// `GET /feeds/<o>/<t>` with `swarm-only-root-chunk: true`: the index
    /// lookup, whose headers alone the core reads.
    pub fn feed_head(owner: &[u8; 20], topic: &[u8; 32]) -> NodeCall {
        let mut call = NodeCall::get(
            Form::FeedHead,
            format!("/feeds/{}/{}", hex(owner), hex(topic)),
            CHUNK_REPLY_CAP,
        );
        call.headers
            .push(("swarm-only-root-chunk".to_owned(), "true".to_owned()));
        call
    }

    /// `GET /feeds/<o>/<t>`, the latest entry, streamed.
    pub fn feed_latest(owner: &[u8; 20], topic: &[u8; 32], max_bytes: usize) -> NodeCall {
        NodeCall::get(
            Form::FeedLatest,
            format!("/feeds/{}/{}", hex(owner), hex(topic)),
            max_bytes,
        )
    }

    /// Its HTTP method.
    pub fn method(&self) -> &'static str {
        self.form.method()
    }

    /// Whether its reply streams.
    pub fn stream(&self) -> bool {
        self.form.streams()
    }
}

/// A whole reply: `{ status, status_text, headers, body_base64 }`, the
/// body decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A streamed reply's head: `{ status, status_text, headers }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
}

/// `headers.get(name)`: a name's values joined with `, `, case-insensitive.
pub fn header<'h>(headers: &'h [(String, String)], name: &str) -> Option<HeaderValue<'h>> {
    let mut found = headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name));
    let first = found.next()?;
    Some(HeaderValue {
        first: &first.1,
        rest: found.map(|(_, v)| v.as_str()).collect(),
    })
}

/// A header's value, as `Headers.get` joins it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderValue<'h> {
    first: &'h str,
    rest: Vec<&'h str>,
}

impl HeaderValue<'_> {
    pub fn text(&self) -> String {
        let mut out = self.first.to_owned();
        for more in &self.rest {
            out.push_str(", ");
            out.push_str(more);
        }
        out
    }
}

impl Reply {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The node's error at a call site, from at most 8 KiB of the body
    /// (deviation `error-body-bound`); an error body nested past the
    /// readers' bound fails the call `error`.
    pub fn error(&self, site: Site) -> Result<NodeError, Failed> {
        errors::http_error(site, self.status, &self.status_text, &self.body).map_err(|e| match e {
            ReadError::TooDeep | ReadError::Syntax(_) => Failed::Error,
        })
    }

    pub fn header(&self, name: &str) -> Option<HeaderValue<'_>> {
        header(&self.headers, name)
    }
}

impl Head {
    pub fn header(&self, name: &str) -> Option<HeaderValue<'_>> {
        header(&self.headers, name)
    }
}

/// Why a call failed before any reply (`{ failed }`): 0009's closed set
/// plus `busy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failed {
    Unreachable,
    Error,
    Aborted,
    TooLarge,
    Busy,
}

/// A streamed reply's end before its last byte: main's abort codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abort {
    Cancelled,
    Stalled,
    BodyStreamError,
    /// Past `max_bytes`.
    TooLarge,
}

/// The grammar's rule main refused a call by (`invalid_argument` with
/// `data: { rule }`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Form,
    Order,
    Count,
    Value,
    Header,
    Query,
    Body,
    Ended,
}

/// The text the reference gives a transport failure of each class
/// (deviation `transport-error-text`: one text a class, where undici's
/// message names its cause): `unreachable`, `error` and `aborted`. Each
/// call site answers `too_large` and `busy` itself; here they read as
/// `error`.
pub fn transport_text(failed: Failed) -> &'static str {
    match failed {
        Failed::Unreachable => UNREACHABLE_TEXT,
        Failed::Aborted => ABORTED_TEXT,
        Failed::Error | Failed::TooLarge | Failed::Busy => ERROR_TEXT,
    }
}

/// undici's text for a dial that found no node.
pub const UNREACHABLE_TEXT: &str = "fetch failed";
/// undici's text for a reply the node cut off, the reference's in every
/// such vector but one (`terminated`, a body that didn't decode).
pub const ERROR_TEXT: &str = "fetch failed: other side closed";
/// The `AbortError`'s.
pub const ABORTED_TEXT: &str = "This operation was aborted";

/// What strict reading refuses in a reply (a protocol error).
pub(crate) fn reply_in_bounds(
    status: u16,
    status_text: &str,
    headers: &[(String, String)],
) -> bool {
    (100..=599).contains(&status)
        && status_text.len() <= MAX_REASON
        && headers.len() <= MAX_REPLY_HEADERS
        && headers.iter().all(|(n, v)| {
            !n.is_empty() && n.len() <= MAX_HEADER_NAME && v.len() <= MAX_HEADER_VALUE
        })
}

/// The most of an error body main sends.
pub const ERROR_BODY: usize = ERROR_BODY_CAP;
