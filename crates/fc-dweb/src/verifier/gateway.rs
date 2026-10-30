//! `GatewayCore`'s answers to `/ipfs` and `/ipns` (freedom-ipfs
//! `freedom-ipfs-gateway/src/lib.rs` at the commit `freedom-ipfsd` pins),
//! which a verified head reproduces header by header (design 0009, Heads):
//! the type by the served path's extension or the sniffed first bytes, the
//! `ETag`, the range and conditional rules, the listing, and the error
//! page.

type Headers = Vec<(String, String)>;

const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const MUTABLE: &str = "no-cache";
const HTML: &str = "text/html; charset=utf-8";
const OCTET_STREAM: &str = "application/octet-stream";
/// The most bytes the type is sniffed from: bytes 0 to 512.
pub(crate) const SNIFF_LAST: u64 = 512;

fn push(h: &mut Headers, name: &str, value: impl Into<String>) {
    h.push((name.to_owned(), value.into()));
}

/// The answer's caching: under `/ipfs/` immutable; through an IPNS name,
/// not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cache {
    Immutable,
    Mutable,
}

impl Cache {
    fn value(self) -> &'static str {
        match self {
            Self::Immutable => IMMUTABLE,
            Self::Mutable => MUTABLE,
        }
    }
}

/// `encode_gateway_path`: the segments, empty ones dropped, each byte
/// outside `A-Za-z0-9-._~` as `%XX`, joined with `/`; `.` for none.
pub(crate) fn encode_path<S: AsRef<str>>(segments: &[S]) -> String {
    let mut out = String::new();
    for s in segments.iter().map(AsRef::as_ref).filter(|s| !s.is_empty()) {
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(&encode_segment(s));
    }
    out
}

fn encode_segment(s: &str) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(DIGITS[usize::from(b >> 4)]));
            out.push(char::from(DIGITS[usize::from(b & 15)]));
        }
    }
    out
}

/// `file_etag`: `"fi1:<root>:<path, or .>:<length>"`.
pub(crate) fn etag<S: AsRef<str>>(root: &str, segments: &[S], len: u64) -> String {
    let path = encode_path(segments);
    let path = if path.is_empty() { "." } else { &path };
    format!("\"fi1:{root}:{path}:{len}\"")
}

/// `mime_guess::from_path(path).first()`, by the last segment's extension
/// as Rust's `Path::extension` reads it: none for a dotfile or a name
/// without a dot.
pub(crate) fn type_by_extension<S: AsRef<str>>(segments: &[S]) -> Option<String> {
    let last = segments
        .iter()
        .map(AsRef::as_ref)
        .rfind(|s| !s.is_empty())?;
    let (stem, ext) = last.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }
    mime_guess::from_ext(ext).first().map(|m| m.to_string())
}

/// `mime_sniff_end`: the last byte the type is sniffed through, when it is
/// sniffed at all: not for an empty file, nor a range that doesn't start at
/// byte 0.
pub(crate) fn sniff_end(len: u64, range: Option<(u64, u64)>) -> Option<u64> {
    if len == 0 {
        return None;
    }
    let last = (len - 1).min(SNIFF_LAST);
    match range {
        None => Some(last),
        Some((0, end)) => Some(end.min(last)),
        Some(_) => None,
    }
}

/// `looks_like_html`: after byte-order marks and ASCII whitespace, one of
/// four prefixes, in any case.
pub(crate) fn looks_like_html(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim_start_matches('\u{feff}');
    let text = text.trim_start_matches([' ', '\t', '\n', '\x0c', '\r']);
    let head: String = text
        .chars()
        .take(16)
        .collect::<String>()
        .to_ascii_lowercase();
    ["<!doctype html", "<html", "<head", "<body"]
        .iter()
        .any(|p| head.starts_with(p))
}

/// The sniffed type.
pub(crate) fn sniffed(bytes: &[u8]) -> String {
    if looks_like_html(bytes) {
        "text/html".to_owned()
    } else {
        OCTET_STREAM.to_owned()
    }
}

/// Why `parse_range_header` refuses a range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RangeError {
    /// 400, with this detail.
    BadRequest(&'static str),
    /// 416.
    NotSatisfiable,
}

/// `parse_range_header` and `parse_range_spec`: one range, inclusive, or
/// why not. Several ranges fail as their first fails to parse.
pub(crate) fn parse_range(value: &str, len: u64) -> Result<(u64, u64), RangeError> {
    let Some(spec) = value.strip_prefix("bytes=") else {
        return Err(RangeError::BadRequest("only bytes ranges are supported"));
    };
    if len == 0 {
        return Err(RangeError::NotSatisfiable);
    }
    let Some((start, end)) = spec.split_once('-') else {
        return Err(RangeError::BadRequest("invalid range syntax"));
    };
    if start.is_empty() {
        let n: u64 = end
            .parse()
            .map_err(|_| RangeError::BadRequest("invalid suffix range"))?;
        if n == 0 {
            return Err(RangeError::NotSatisfiable);
        }
        return Ok((len.saturating_sub(n), len - 1));
    }
    let start: u64 = start
        .parse()
        .map_err(|_| RangeError::BadRequest("invalid range start"))?;
    let end: u64 = if end.is_empty() {
        len - 1
    } else {
        end.parse()
            .map_err(|_| RangeError::BadRequest("invalid range end"))?
    };
    if start >= len || start > end {
        return Err(RangeError::NotSatisfiable);
    }
    Ok((start, end.min(len - 1)))
}

/// `if_none_match_matches`: `*`, the tag, or the tag weak, among the
/// comma-separated candidates.
pub(crate) fn if_none_match(value: &str, etag: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|c| c == "*" || c == etag || c.strip_prefix("W/").is_some_and(|t| t == etag))
}

/// A file's 200 (`insert_full_file_headers`).
pub(crate) fn whole(mime: &str, len: u64, etag: &str, cache: Cache) -> Headers {
    let mut h = Headers::new();
    push(&mut h, "content-type", mime);
    push(&mut h, "accept-ranges", "bytes");
    push(&mut h, "content-length", len.to_string());
    push(&mut h, "etag", etag);
    push(&mut h, "cache-control", cache.value());
    h
}

/// A file's 206.
pub(crate) fn partial(
    mime: &str,
    start: u64,
    end: u64,
    len: u64,
    etag: &str,
    cache: Cache,
) -> Headers {
    let mut h = Headers::new();
    push(&mut h, "content-type", mime);
    push(&mut h, "accept-ranges", "bytes");
    push(
        &mut h,
        "content-range",
        format!("bytes {start}-{end}/{len}"),
    );
    push(&mut h, "content-length", (end - start + 1).to_string());
    push(&mut h, "etag", etag);
    push(&mut h, "cache-control", cache.value());
    h
}

/// The 304: only the tag and the caching.
pub(crate) fn not_modified(etag: &str, cache: Cache) -> Headers {
    let mut h = Headers::new();
    push(&mut h, "etag", etag);
    push(&mut h, "cache-control", cache.value());
    h
}

/// `escape_html`.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// `html_error_response`: the status's page.
pub(crate) fn error_page(status: u16, detail: &str) -> (Headers, Vec<u8>) {
    let title = match status {
        400 => "Bad Request",
        404 => "Not Found",
        416 => "Range Not Satisfiable",
        _ => "Bad Gateway",
    };
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{status} {title}</title><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"></head><body><main><h1>{title}</h1><p>{}</p></main></body></html>",
        escape(detail)
    )
    .into_bytes();
    (sized(HTML, &body), body)
}

fn sized(content_type: &str, body: &[u8]) -> Headers {
    let mut h = Headers::new();
    push(&mut h, "content-type", content_type);
    push(&mut h, "content-length", body.len().to_string());
    h
}

/// A listing's entry: its name and its link's `Tsize`, borrowed from the
/// block it was read from, and its place among the links, so equal names
/// keep their order as a stable sort keeps them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry<'a> {
    pub name: std::borrow::Cow<'a, str>,
    pub size: Option<u64>,
    pub at: usize,
}

/// Where a page is written: counted first, then into a buffer of exactly
/// that length.
trait Out {
    fn put(&mut self, s: &[u8]);
}

struct Count(usize);

impl Out for Count {
    fn put(&mut self, s: &[u8]) {
        self.0 = self.0.saturating_add(s.len());
    }
}

impl Out for Vec<u8> {
    fn put(&mut self, s: &[u8]) {
        self.extend_from_slice(s);
    }
}

/// `escape`, written out.
fn put_escaped(out: &mut impl Out, s: &str) {
    let mut from = 0;
    for (i, b) in s.bytes().enumerate() {
        let rep: &[u8] = match b {
            b'&' => b"&amp;",
            b'<' => b"&lt;",
            b'>' => b"&gt;",
            b'"' => b"&quot;",
            b'\'' => b"&#39;",
            _ => continue,
        };
        out.put(&s.as_bytes()[from..i]);
        out.put(rep);
        from = i + 1;
    }
    out.put(&s.as_bytes()[from..]);
}

/// `encode_segment`, written out (its output needs no escaping).
fn put_encoded(out: &mut impl Out, s: &str) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.put(&[b]);
        } else {
            out.put(&[
                b'%',
                DIGITS[usize::from(b >> 4)],
                DIGITS[usize::from(b & 15)],
            ]);
        }
    }
}

fn put_u64(out: &mut impl Out, mut v: u64) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out.put(&digits[i..]);
}

fn put_listing(out: &mut impl Out, title: &str, href_base: &str, entries: &[Entry<'_>]) {
    out.put(b"<!doctype html><html><head><meta charset=\"utf-8\"><title>Index of ");
    put_escaped(out, title);
    out.put(b"</title><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"></head><body><main><h1>Index of ");
    put_escaped(out, title);
    out.put(b"</h1><ul>");
    let base = href_base.trim_end_matches('/');
    for e in entries {
        out.put(b"<li><a href=\"");
        put_escaped(out, base);
        out.put(b"/");
        put_encoded(out, &e.name);
        out.put(b"\">");
        put_escaped(out, &e.name);
        out.put(b"</a>");
        if let Some(size) = e.size {
            out.put(b" <small>");
            put_u64(out, size);
            out.put(b" bytes</small>");
        }
        out.put(b"</li>");
    }
    out.put(b"</ul></main></body></html>");
}

/// `directory_listing_response`'s order: by name, bytewise, equal names
/// in link order. Sorted in place, without allocating.
pub(crate) fn sort_listing(entries: &mut [Entry<'_>]) {
    entries.sort_unstable_by(|a, b| {
        a.name
            .as_bytes()
            .cmp(b.name.as_bytes())
            .then(a.at.cmp(&b.at))
    });
}

/// The listing page's length, to reserve before it is written.
pub(crate) fn listing_len(title: &str, href_base: &str, entries: &[Entry<'_>]) -> usize {
    let mut n = Count(0);
    put_listing(&mut n, title, href_base, entries);
    n.0
}

/// `directory_listing_response`: the page `title` names, each entry linked
/// below `href_base`, the entries already sorted ([`sort_listing`]),
/// written into a buffer of exactly `len` bytes ([`listing_len`]).
pub(crate) fn listing(
    title: &str,
    href_base: &str,
    entries: &[Entry<'_>],
    len: usize,
) -> (Headers, Vec<u8>) {
    let mut body = Vec::with_capacity(len);
    put_listing(&mut body, title, href_base, entries);
    (sized(HTML, &body), body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_as_gatewaycore_reads_them() {
        assert_eq!(parse_range("bytes=0-0", 10), Ok((0, 0)));
        assert_eq!(parse_range("bytes=5-", 10), Ok((5, 9)));
        assert_eq!(parse_range("bytes=2-100", 10), Ok((2, 9)));
        assert_eq!(parse_range("bytes=-3", 10), Ok((7, 9)));
        assert_eq!(parse_range("bytes=-30", 10), Ok((0, 9)));
        assert_eq!(
            parse_range("bytes=10-", 10),
            Err(RangeError::NotSatisfiable)
        );
        assert_eq!(parse_range("bytes=-0", 10), Err(RangeError::NotSatisfiable));
        assert_eq!(parse_range("bytes=0-", 0), Err(RangeError::NotSatisfiable));
        assert_eq!(
            parse_range("bytes=0-0,2-3", 10),
            Err(RangeError::BadRequest("invalid range end"))
        );
        assert_eq!(
            parse_range("bytes=abc", 10),
            Err(RangeError::BadRequest("invalid range syntax"))
        );
        assert_eq!(
            parse_range("items=0-1", 10),
            Err(RangeError::BadRequest("only bytes ranges are supported"))
        );
        assert!(if_none_match("\"a\", W/\"b\"", "\"b\""));
        assert!(if_none_match("*", "\"b\""));
        assert!(!if_none_match("W/*", "\"b\""));
    }

    #[test]
    fn types_and_tags() {
        assert_eq!(
            type_by_extension(&["docs", "page.html"]).as_deref(),
            Some("text/html")
        );
        assert_eq!(
            type_by_extension(&["IMG.JPG"]).as_deref(),
            Some("image/jpeg")
        );
        assert_eq!(type_by_extension(&[".bashrc"]), None);
        assert_eq!(type_by_extension(&["noext"]), None);
        assert_eq!(type_by_extension(&["a", ""]), None);
        assert!(looks_like_html(b"\xef\xbb\xbf  <!DOCTYPE HTML>"));
        assert!(looks_like_html(b"<header>"));
        assert!(!looks_like_html(b"x<html>"));
        assert_eq!(
            etag("bafy", &["", "  spaced"], 53),
            "\"fi1:bafy:%20%20spaced:53\""
        );
        assert_eq!(etag::<&str>("bafy", &[], 0), "\"fi1:bafy:.:0\"");
        assert_eq!(sniff_end(0, None), None);
        assert_eq!(sniff_end(1000, None), Some(512));
        assert_eq!(sniff_end(1000, Some((0, 99))), Some(99));
        assert_eq!(sniff_end(1000, Some((1, 99))), None);
    }
}
