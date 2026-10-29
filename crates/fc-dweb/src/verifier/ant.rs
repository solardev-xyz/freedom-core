//! Ant v0.5.71's answers to `/bzz` (ant-gateway `retrieval.rs`), which a
//! verified head reproduces header by header (design 0009, Heads): each
//! response builder's headers in Ant's order. `server`, which describes
//! the node, is left out (`meta.ant.node_headers`).

const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const MUTABLE: &str = "no-cache";
const JSON: &str = "application/json; charset=utf-8";
const OCTET_STREAM: &str = "application/octet-stream";

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

/// `streaming_response`: 200 with the whole body.
pub(crate) fn whole(entry: &Entry, total: u64) -> Headers {
    let mut h = Headers::new();
    push(
        &mut h,
        "content-type",
        content_type(entry.content_type.as_deref().unwrap_or(OCTET_STREAM)),
    );
    push(&mut h, "content-length", total.to_string());
    push(&mut h, "accept-ranges", "bytes");
    if let Some(cd) = entry.filename.as_deref().and_then(content_disposition) {
        push(&mut h, "content-disposition", cd);
    }
    push(&mut h, "cache-control", IMMUTABLE);
    finish(&mut h, entry);
    h
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

/// `directory_redirect`: 308 to `/bzz/<root>/<path>/` and the query, with
/// Go's anchor body.
pub(crate) fn redirect(root: &str, path: &str, query: &str) -> (Headers, Vec<u8>) {
    let location = format!("/bzz/{root}/{}/{query}", go_encode_path(path));
    let mut h = Headers::new();
    let body = format!(
        "<a href=\"{}\">Permanent Redirect</a>.\n",
        html_escape(&location)
    )
    .into_bytes();
    if header_value_ok(&location) {
        push(&mut h, "location", location);
    }
    push(&mut h, "content-type", "text/html; charset=utf-8");
    push(&mut h, "content-length", body.len().to_string());
    (h, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_and_disposition() {
        let (h, body) = redirect("ab", "dä cs", "?x=1");
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
