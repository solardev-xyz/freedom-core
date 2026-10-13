//! Response operations (design 0006, "Response operations"), as pure
//! functions over a response head, and the small-text decider over the
//! body's chunks. Main's existing code runs them in Electron; these carry
//! the same behavior, pinned by the same vectors, for Stage 2 and mobile.

use crate::headers::Headers;
use crate::js;
use crate::plan::{Backend, Fetch, Ipfs, Node, ResponseOp};
use crate::url;

/// A response's status and headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub headers: Headers,
}

/// What a head operation does with the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyAction {
    Keep,
    /// Cancel the upstream body and send none.
    Drop,
}

/// `PAGE_STATE_RESPONSE_HEADERS` (O-12).
pub const PAGE_STATE_RESPONSE_HEADERS: [&str; 3] =
    ["set-cookie", "set-cookie2", "service-worker-allowed"];

/// `DROPPED_UPSTREAM_RESPONSE_HEADERS`: the external gateway's body is
/// already decoded, and the rest describe the upstream connection.
pub const DECODED_ENCODING_HEADERS: [&str; 5] = [
    "content-encoding",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
];

/// `bzz-protocol.js` `REDIRECT_STATUSES`.
pub const BZZ_REDIRECT_STATUSES: [u16; 5] = [301, 302, 303, 307, 308];

/// `strip_page_state`; whether anything was removed.
pub fn strip_page_state(head: &mut ResponseHead) -> bool {
    let present = PAGE_STATE_RESPONSE_HEADERS
        .iter()
        .any(|name| head.headers.has(name));
    for name in PAGE_STATE_RESPONSE_HEADERS {
        head.headers.delete(name);
    }
    present
}

/// `strip_decoded_encoding`.
pub fn strip_decoded_encoding(head: &mut ResponseHead) {
    for name in DECODED_ENCODING_HEADERS {
        head.headers.delete(name);
    }
}

/// `rewriteGatewayLocation`: a gateway-space `Location` as a reference
/// relative to the request's directory, comparing decoded path segments.
/// `None` leaves the `Location` as the node wrote it: cross-origin, up out
/// of the directory, or the directory itself without its slash.
pub fn rewrite_gateway_location(location: &str, request_url: &str) -> Option<String> {
    let requested = url::parse(request_url)?;
    let target = url::join(&requested, location)?;
    if url::origin(&target) != url::origin(&requested) {
        return None;
    }
    let requested_path = url::pathname(&requested);
    if !requested_path.contains('/') {
        return None;
    }
    let mut directory: Vec<&str> = requested_path.split('/').collect();
    directory.pop();
    let target_path = url::pathname(&target);
    let segments: Vec<&str> = target_path.split('/').collect();
    if segments.len() <= directory.len() {
        return None;
    }
    if !directory
        .iter()
        .zip(&segments)
        .all(|(a, b)| same_segment(a, b))
    {
        return None;
    }
    let relative = segments
        .get(directory.len()..)
        .unwrap_or_default()
        .join("/");
    Some(format!(
        "./{relative}{}{}",
        url::search(&target),
        url::hash(&target)
    ))
}

/// `sameSegment`: equal, or equal once each is `decodeURIComponent`-ed.
pub fn same_segment(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    match js::decode_uri_component(a) {
        Some(decoded) => js::decode_uri_component(b).as_deref() == Some(decoded.as_str()),
        None => false,
    }
}

/// `canonicalize_redirect`, for the node that answered.
///
/// - Ant (`canonicalizeRedirect`): a 301, 302, 303, 307 or 308 whose
///   `Location` rewrites gets it, loses the length and encoding headers,
///   and its body is dropped.
/// - The IPFS gateway (`proxiedRedirectHeaders`): any 3xx's `Location` is
///   rewritten in place, and the body kept.
///
/// `request_url` is the URL the node was asked: its origin and the plan's
/// path.
pub fn canonicalize_redirect(head: &mut ResponseHead, request_url: &str, node: Node) -> BodyAction {
    let redirect = match node {
        Node::Ant => BZZ_REDIRECT_STATUSES.contains(&head.status),
        Node::Ipfs => (300..400).contains(&head.status),
    };
    if !redirect {
        return BodyAction::Keep;
    }
    let Some(location) = head.headers.get("location").filter(|l| !l.is_empty()) else {
        return BodyAction::Keep;
    };
    let Some(rewritten) = rewrite_gateway_location(&location, request_url) else {
        return BodyAction::Keep;
    };
    head.headers.set("location", &rewritten);
    match node {
        Node::Ant => {
            for name in ["content-length", "content-encoding", "transfer-encoding"] {
                head.headers.delete(name);
            }
            BodyAction::Drop
        }
        Node::Ipfs => BodyAction::Keep,
    }
}

/// The most a small-text body may declare and hold.
pub const SMALL_TEXT_MAX: usize = 4096;

/// `small_text`'s conditions on the response: a 200 with a body, a media
/// type of exactly `application/octet-stream`, an integer declared length
/// from 1 to 4096 (as `Number()` reads it), and no `Content-Disposition`,
/// `X-Content-Type-Options` or `Content-Range`. The declared length, when
/// they all hold. The request's (a `GET` navigation) are the plan's.
pub fn small_text_length(head: &ResponseHead, body_present: bool) -> Option<usize> {
    let media_type = head
        .headers
        .get("content-type")
        .map(|value| js::trim(value.split(';').next().unwrap_or("")).to_lowercase());
    let size = js::number(head.headers.get("content-length").as_deref().unwrap_or(""));
    let eligible = head.status == 200
        && body_present
        && media_type.as_deref() == Some("application/octet-stream")
        && js::is_integer(size)
        && size > 0.0
        && size <= SMALL_TEXT_MAX as f64
        && !head.headers.has("content-disposition")
        && !head.headers.has("x-content-type-options")
        && !head.headers.has("content-range");
    eligible.then_some(size as usize)
}

/// What the sniff decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmallTextDecision {
    /// `text/plain; charset=utf-8` with `nosniff`: see [`relabel`].
    Relabel,
    /// The buffered chunks, then the rest of the body, unchanged.
    ReplayAsIs,
}

/// The small-text sniff: it reads until it holds more than 4096 bytes or
/// the body ends. It holds at most 4096 bytes plus one upstream chunk, since
/// a lying length can deliver a whole chunk at once; every byte is replayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallText {
    declared: usize,
    length: usize,
    chunks: Vec<Vec<u8>>,
}

impl SmallText {
    pub fn new(declared: usize) -> Self {
        Self {
            declared,
            length: 0,
            chunks: Vec::new(),
        }
    }

    /// Takes a chunk. `Some` once it holds more than 4096 bytes: no more
    /// reads, replay what it holds and stream the rest.
    pub fn push(&mut self, chunk: Vec<u8>) -> Option<SmallTextDecision> {
        self.length += chunk.len();
        self.chunks.push(chunk);
        (self.length > SMALL_TEXT_MAX).then_some(SmallTextDecision::ReplayAsIs)
    }

    /// The decision at the end of the body: relabel when the length matches
    /// the declared one and the bytes are UTF-8 text without control
    /// characters other than tab, line feed, form feed and carriage return.
    pub fn finish(&self) -> SmallTextDecision {
        if self.length != self.declared || self.length > SMALL_TEXT_MAX {
            return SmallTextDecision::ReplayAsIs;
        }
        let bytes = self.chunks.concat();
        let text_ok = std::str::from_utf8(&bytes).is_ok_and(|text| {
            !text
                .chars()
                .any(|c| c == '\u{7f}' || (c < ' ' && !matches!(c, '\t' | '\n' | '\u{c}' | '\r')))
        });
        if text_ok {
            SmallTextDecision::Relabel
        } else {
            SmallTextDecision::ReplayAsIs
        }
    }

    /// The bytes held, to replay first.
    pub fn into_chunks(self) -> Vec<Vec<u8>> {
        self.chunks
    }
}

/// Relabels a small text response.
pub fn relabel(head: &mut ResponseHead) {
    head.headers
        .set("content-type", "text/plain; charset=utf-8");
    head.headers.set("x-content-type-options", "nosniff");
}

/// A response head after the plan's operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Responded {
    pub head: ResponseHead,
    /// Whether a body follows.
    pub body: bool,
    /// The declared length to sniff for small text, when it applies.
    pub small_text: Option<usize>,
}

/// Runs the head operations a fetch's answer gets: those every response
/// gets from its backend (`strip_page_state`, and `strip_decoded_encoding`
/// from the external gateway), then the plan's, in order. Small text is
/// left to [`SmallText`], with the declared length it needs.
pub fn respond(
    fetch: &Fetch,
    backend: Backend,
    mut head: ResponseHead,
    request_url: &str,
    body_present: bool,
) -> Responded {
    let mut ops = Vec::new();
    if backend == Backend::Ipfs(Ipfs::Gateway)
        && !fetch.response.contains(&ResponseOp::StripDecodedEncoding)
    {
        ops.push(ResponseOp::StripDecodedEncoding);
    }
    if !fetch.response.contains(&ResponseOp::StripPageState) {
        ops.push(ResponseOp::StripPageState);
    }
    ops.extend_from_slice(&fetch.response);
    let mut body = body_present;
    let mut small_text = None;
    for op in ops {
        match op {
            ResponseOp::StripDecodedEncoding => strip_decoded_encoding(&mut head),
            ResponseOp::StripPageState => {
                strip_page_state(&mut head);
            }
            ResponseOp::CanonicalizeRedirect => {
                if canonicalize_redirect(&mut head, request_url, fetch.node) == BodyAction::Drop {
                    body = false;
                }
            }
            ResponseOp::SmallText => small_text = small_text_length(&head, body),
        }
    }
    Responded {
        head,
        body,
        small_text,
    }
}
