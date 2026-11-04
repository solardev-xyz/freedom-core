//! Ant v0.5.71's answers to `/bzz` (ant-gateway `retrieval.rs`), which a
//! verified head reproduces header by header (design 0009, Heads): the
//! range parse Go's `ServeContent` makes, and each response builder's
//! headers in Ant's order. `server`, which describes the node, is left
//! out (`meta.ant.node_headers`).

const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const MUTABLE: &str = "no-cache";
const JSON: &str = "application/json; charset=utf-8";
const OCTET_STREAM: &str = "application/octet-stream";

/// `parse_go_ranges`: Go's `parseRange` and the decisions `serveContent`
/// makes on its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ranges {
    /// No range, or one Go serves whole: the empty resource, or a set
    /// that asks for more than the resource holds.
    Full,
    /// Not a range Go reads: 416 without `Content-Range`.
    Invalid,
    /// Every range starts past the end: 416 with `Content-Range`.
    NoOverlap,
    /// One range: `start` and `length`, which may be 0 (`bytes=-0`).
    Single { start: u64, length: u64 },
    /// Several: Ant's multipart answer, which the core answers whole
    /// (deviation `multi-range`).
    Multi,
}

fn go_trim(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

pub(crate) fn parse_ranges(raw: Option<&str>, total: u64) -> Ranges {
    let Some(s) = raw else {
        return Ranges::Full;
    };
    let Some(rest) = s.strip_prefix("bytes=") else {
        return Ranges::Invalid;
    };
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut no_overlap = false;
    for ra in rest.split(',') {
        let ra = go_trim(ra);
        if ra.is_empty() {
            continue;
        }
        let Some((start_s, end_s)) = ra.split_once('-') else {
            return Ranges::Invalid;
        };
        let (start_s, end_s) = (go_trim(start_s), go_trim(end_s));
        if start_s.is_empty() {
            // A suffix: the last N bytes.
            if end_s.is_empty() || end_s.starts_with('-') {
                return Ranges::Invalid;
            }
            let Ok(n) = end_s.parse::<i64>() else {
                return Ranges::Invalid;
            };
            let Ok(n) = u64::try_from(n) else {
                return Ranges::Invalid;
            };
            let n = n.min(total);
            ranges.push((total - n, n));
        } else {
            let Some(start) = start_s
                .parse::<i64>()
                .ok()
                .and_then(|s| u64::try_from(s).ok())
            else {
                return Ranges::Invalid;
            };
            if start >= total {
                no_overlap = true;
                continue;
            }
            let length = if end_s.is_empty() {
                total - start
            } else {
                let Ok(end) = end_s.parse::<i64>() else {
                    return Ranges::Invalid;
                };
                let Ok(end) = u64::try_from(end) else {
                    return Ranges::Invalid;
                };
                if start > end {
                    return Ranges::Invalid;
                }
                end.min(total.saturating_sub(1)) - start + 1
            };
            ranges.push((start, length));
        }
    }
    if no_overlap && ranges.is_empty() {
        return if total == 0 {
            Ranges::Full
        } else {
            Ranges::NoOverlap
        };
    }
    let sum = ranges
        .iter()
        .try_fold(0u64, |acc, r| acc.checked_add(r.1))
        .unwrap_or(u64::MAX);
    if sum > total {
        return Ranges::Full;
    }
    match ranges.as_slice() {
        [] => Ranges::Full,
        [(start, length)] => Ranges::Single {
            start: *start,
            length: *length,
        },
        _ => Ranges::Multi,
    }
}

/// `HeaderValue::from_str`'s rule: visible ASCII, obs-text and tab.
fn header_value_ok(value: &str) -> bool {
    value.bytes().all(|b| (b >= 32 && b != 127) || b == b'\t')
}

/// `content_disposition`: the base name, `\` and `"` escaped; none when
/// the value isn't a header value.
pub(crate) fn content_disposition(filename: &str) -> Option<String> {
    let base = filename.rsplit('/').next().unwrap_or(filename);
    let escaped = base.replace('\\', "\\\\").replace('"', "\\\"");
    let value = format!("inline; filename=\"{escaped}\"");
    header_value_ok(&value).then_some(value)
}

/// `derive_filename_from_path`: the decoded path's last segment.
pub(crate) fn filename_from_path(path: &str) -> Option<String> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    trimmed.rsplit('/').next().map(str::to_owned)
}

fn content_type(value: &str) -> String {
    if header_value_ok(value) {
        value.to_owned()
    } else {
        OCTET_STREAM.to_owned()
    }
}

/// A feed crossed on the way: the verified update's index and version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Feed {
    pub index: u64,
    pub v2: bool,
}

/// What an entry's head is built from: its metadata and the resolved file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// The `Content-Type` metadata, as written.
    pub content_type: Option<String>,
    /// From `Filename`, or the path's last segment.
    pub filename: Option<String>,
    /// The resolved file reference, for the `ETag`.
    pub reference: [u8; 32],
    pub feed: Option<Feed>,
}

type Headers = Vec<(String, String)>;

fn push(h: &mut Headers, name: &str, value: impl Into<String>) {
    h.push((name.to_owned(), value.into()));
}

/// `set_etag`, then `apply_bzz_feed_headers`: `Cache-Control` becomes
/// `no-cache` in its place, and the feed headers follow.
fn finish(h: &mut Headers, entry: &Entry) {
    push(h, "etag", format!("\"{}\"", hex(&entry.reference)));
    if let Some(feed) = entry.feed {
        for (name, value) in h.iter_mut() {
            if name == "cache-control" {
                *value = MUTABLE.to_owned();
            }
        }
        push(h, "swarm-feed-index", hex(&feed.index.to_be_bytes()));
        push(
            h,
            "swarm-feed-resolved-version",
            if feed.v2 { "v2" } else { "v1" },
        );
        push(h, "access-control-expose-headers", "Swarm-Feed-Index");
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    out
}

/// `streaming_response`: 200 with the whole body (a HEAD's has no
/// `Accept-Ranges`).
pub(crate) fn whole(entry: &Entry, total: u64, head_only: bool) -> Headers {
    let mut h = Headers::new();
    push(
        &mut h,
        "content-type",
        content_type(entry.content_type.as_deref().unwrap_or(OCTET_STREAM)),
    );
    push(&mut h, "content-length", total.to_string());
    if !head_only {
        push(&mut h, "accept-ranges", "bytes");
    }
    if let Some(cd) = entry.filename.as_deref().and_then(content_disposition) {
        push(&mut h, "content-disposition", cd);
    }
    push(&mut h, "cache-control", IMMUTABLE);
    finish(&mut h, entry);
    h
}

/// `partial_content_response`: 206 for `start..=end` of `total`.
pub(crate) fn partial(entry: &Entry, total: u64, start: u64, end: u64) -> Headers {
    let mut h = Headers::new();
    push(
        &mut h,
        "content-type",
        content_type(entry.content_type.as_deref().unwrap_or(OCTET_STREAM)),
    );
    push(&mut h, "content-length", (end - start + 1).to_string());
    push(&mut h, "accept-ranges", "bytes");
    push(
        &mut h,
        "content-range",
        format!("bytes {start}-{end}/{total}"),
    );
    if let Some(cd) = entry.filename.as_deref().and_then(content_disposition) {
        push(&mut h, "content-disposition", cd);
    }
    push(&mut h, "cache-control", IMMUTABLE);
    finish(&mut h, entry);
    h
}

/// `zero_length_partial_response`: Go's `bytes N-(N-1)/N`, and no
/// `Content-Disposition`.
pub(crate) fn zero_length(entry: &Entry, total: u64, start: u64) -> Headers {
    let mut h = Headers::new();
    let ct = entry.content_type.as_deref().unwrap_or(OCTET_STREAM);
    if header_value_ok(ct) {
        push(&mut h, "content-type", ct);
    }
    push(&mut h, "content-length", "0");
    push(&mut h, "accept-ranges", "bytes");
    let end = i128::from(start) - 1;
    push(
        &mut h,
        "content-range",
        format!("bytes {start}-{end}/{total}"),
    );
    push(&mut h, "cache-control", IMMUTABLE);
    finish(&mut h, entry);
    h
}

/// `go_range_not_satisfiable`: 416, with `Content-Range` for a range past
/// the end, and the entry's `Content-Disposition`. No feed headers.
pub(crate) fn not_satisfiable(
    total: Option<u64>,
    filename: Option<&str>,
) -> (Headers, &'static [u8]) {
    let body: &[u8] = if total.is_some() {
        b"invalid range: failed to overlap\n"
    } else {
        b"invalid range\n"
    };
    let mut h = Headers::new();
    push(&mut h, "content-type", "text/plain; charset=utf-8");
    push(&mut h, "x-content-type-options", "nosniff");
    if let Some(t) = total {
        push(&mut h, "content-range", format!("bytes */{t}"));
    }
    if let Some(cd) = filename.and_then(content_disposition) {
        push(&mut h, "content-disposition", cd);
    }
    push(&mut h, "content-length", body.len().to_string());
    (h, body)
}

/// Ant's 404s the walk proves: `json_error` and `status_text_error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotFound {
    /// An empty path and no index document.
    Root,
    /// A path the manifest doesn't hold, or one below raw bytes.
    Path,
    /// A manifest Ant refuses to read: bee's bare `Not Found`.
    Plain,
}

pub(crate) fn not_found(kind: NotFound) -> (Headers, Vec<u8>) {
    let message = match kind {
        NotFound::Root => "address not found or incorrect",
        NotFound::Path => "path address not found",
        NotFound::Plain => "Not Found",
    };
    let body = format!("{{\"code\":404,\"message\":\"{message}\"}}").into_bytes();
    let mut h = Headers::new();
    push(&mut h, "content-type", JSON);
    push(&mut h, "content-length", body.len().to_string());
    (h, body)
}

/// `go_encode_path`: Go's path escaping, uppercase.
fn go_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path.as_bytes() {
        let literal = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_'
                    | b'.'
                    | b'~'
                    | b'$'
                    | b'&'
                    | b'+'
                    | b','
                    | b'/'
                    | b':'
                    | b';'
                    | b'='
                    | b'@'
            );
        if literal {
            out.push(char::from(b));
        } else {
            const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
            out.push('%');
            out.push(char::from(DIGITS[usize::from(b >> 4)]));
            out.push(char::from(DIGITS[usize::from(b & 15)]));
        }
    }
    out
}

/// Go's `htmlEscape`, as `http.Redirect` writes the anchor.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// `directory_redirect`: 308 to `/bzz/<root>/<path>/` and the query; a GET
/// gets Go's anchor body.
pub(crate) fn redirect(root: &str, path: &str, query: &str, head_only: bool) -> (Headers, Vec<u8>) {
    let location = format!("/bzz/{root}/{}/{query}", go_encode_path(path));
    let mut h = Headers::new();
    let body = if head_only {
        Vec::new()
    } else {
        format!(
            "<a href=\"{}\">Permanent Redirect</a>.\n",
            html_escape(&location)
        )
        .into_bytes()
    };
    let location_ok = header_value_ok(&location);
    if location_ok {
        push(&mut h, "location", location);
    }
    if !head_only {
        push(&mut h, "content-type", "text/html; charset=utf-8");
    }
    push(&mut h, "content-length", body.len().to_string());
    (h, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_ranges() {
        assert_eq!(parse_ranges(None, 10), Ranges::Full);
        assert_eq!(parse_ranges(Some("bytes=abc"), 10), Ranges::Invalid);
        assert_eq!(parse_ranges(Some("items=0-1"), 10), Ranges::Invalid);
        assert_eq!(parse_ranges(Some("bytes=10-"), 10), Ranges::NoOverlap);
        assert_eq!(parse_ranges(Some("bytes=0-"), 0), Ranges::Full);
        assert_eq!(
            parse_ranges(Some("bytes=-1"), 0),
            Ranges::Single {
                start: 0,
                length: 0
            }
        );
        assert_eq!(
            parse_ranges(Some("bytes=2-100"), 10),
            Ranges::Single {
                start: 2,
                length: 8
            }
        );
        assert_eq!(
            parse_ranges(Some("bytes=-3"), 10),
            Ranges::Single {
                start: 7,
                length: 3
            }
        );
        assert_eq!(parse_ranges(Some("bytes=0-0,2-3"), 10), Ranges::Multi);
        // More than the resource holds is served whole.
        assert_eq!(parse_ranges(Some("bytes=0-9,0-9"), 10), Ranges::Full);
        assert_eq!(parse_ranges(Some("bytes=5-2"), 10), Ranges::Invalid);
        assert_eq!(parse_ranges(Some("bytes=-"), 10), Ranges::Invalid);
        assert_eq!(parse_ranges(Some("bytes=--1"), 10), Ranges::Invalid);
        assert_eq!(
            parse_ranges(Some("bytes= 1 - 2 ,"), 10),
            parse_ranges(Some("bytes=1-2"), 10)
        );
    }

    #[test]
    fn redirect_and_disposition() {
        let (h, body) = redirect("ab", "dä cs", "?x=1", false);
        assert_eq!(h[0].1, "/bzz/ab/d%C3%A4%20cs/?x=1");
        assert_eq!(
            body,
            b"<a href=\"/bzz/ab/d%C3%A4%20cs/?x=1\">Permanent Redirect</a>.\n"
        );
        assert_eq!(
            content_disposition("a/b\"c\\"),
            Some("inline; filename=\"b\\\"c\\\\\"".to_owned())
        );
        assert_eq!(content_disposition("a\nb"), None);
        assert_eq!(
            filename_from_path("/docs/x.html/"),
            Some("x.html".to_owned())
        );
        assert_eq!(filename_from_path("//"), None);
    }
}
