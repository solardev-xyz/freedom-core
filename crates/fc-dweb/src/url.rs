//! `new URL` as the handlers' Node reads it (Ada, WHATWG URL Standard).
//!
//! The `url` crate implements the same standard. Two differences from
//! Node 24, found by comparing every printable ASCII character in every
//! component, are corrected here:
//!
//! - a `^` in a hierarchical path is percent-encoded (`%5E`), as the
//!   current path percent-encode set requires;
//! - a `\` in the port of a URL whose scheme isn't special is a failure,
//!   not the end of the port.

use url::Url;

const SPECIAL_SCHEMES: [&str; 6] = ["ftp", "file", "http", "https", "ws", "wss"];

/// `new URL(input)`, or `None` where it throws.
pub(crate) fn parse(input: &str) -> Option<Url> {
    if backslash_in_port(input) {
        return None;
    }
    Url::parse(input).ok()
}

/// `new URL(input, base)`, or `None` where it throws.
pub(crate) fn join(base: &Url, input: &str) -> Option<Url> {
    if backslash_in_port(input) {
        return None;
    }
    base.join(input).ok()
}

/// `url.hostname`.
pub(crate) fn hostname(url: &Url) -> &str {
    url.host_str().unwrap_or("")
}

/// `url.pathname`.
pub(crate) fn pathname(url: &Url) -> String {
    if url.cannot_be_a_base() {
        url.path().to_owned()
    } else {
        url.path().replace('^', "%5E")
    }
}

/// `url.search`: empty for no query or an empty one.
pub(crate) fn search(url: &Url) -> String {
    match url.query() {
        Some(query) if !query.is_empty() => format!("?{query}"),
        _ => String::new(),
    }
}

/// `url.hash`: empty for no fragment or an empty one.
pub(crate) fn hash(url: &Url) -> String {
    match url.fragment() {
        Some(fragment) if !fragment.is_empty() => format!("#{fragment}"),
        _ => String::new(),
    }
}

/// `url.origin`: `"null"` for an opaque origin.
pub(crate) fn origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

/// A node-relative request target as an HTTP client sends it: the target
/// appended to an origin and read back as `pathname + search`. Dot segments
/// are resolved, `\` is a separator, and characters outside the path and
/// query sets are percent-encoded. `None` only if the parser refuses it.
pub(crate) fn normalize_target(target: &str) -> Option<String> {
    let url = parse(&format!("http://node{target}"))?;
    Some(pathname(&url) + &search(&url))
}

/// The input as the URL parser first sees it: leading and trailing C0
/// controls and spaces removed, then every tab and newline.
fn preprocess(input: &str) -> String {
    input
        .trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect()
}

/// The URL's scheme, lowercased, as the parser's scheme state reads it.
pub(crate) fn scheme(input: &str) -> Option<String> {
    let input = preprocess(input);
    let (scheme, _) = input.split_once(':')?;
    let mut chars = scheme.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    valid.then(|| scheme.to_ascii_lowercase())
}

/// Whether the parser's port state meets a `\` in a URL whose scheme isn't
/// special: a failure in Node, a terminator in the `url` crate.
fn backslash_in_port(input: &str) -> bool {
    let Some(scheme) = scheme(input) else {
        return false;
    };
    if SPECIAL_SCHEMES.contains(&scheme.as_str()) {
        return false;
    }
    let input = preprocess(input);
    let Some(rest) = input
        .split_once(':')
        .and_then(|(_, rest)| rest.strip_prefix("//"))
    else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or("");
    let port = if host_port.starts_with('[') {
        host_port
            .split_once(']')
            .and_then(|(_, after)| after.strip_prefix(':'))
    } else {
        host_port.split_once(':').map(|(_, port)| port)
    };
    port.is_some_and(|port| port.contains('\\'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrections() {
        assert_eq!(parse("bzz://h.eth:\\/"), None);
        assert_eq!(parse("bzz://[::1]:1\\/"), None);
        assert!(parse("http://h:1\\x").is_some());
        let url = parse("bzz://h/a^b?^#^").unwrap();
        assert_eq!(pathname(&url), "/a%5Eb");
        assert_eq!(search(&url), "?^");
        assert_eq!(pathname(&parse("bzz:a^b").unwrap()), "a^b");
        assert_eq!(scheme(" \tBzZ://x"), Some("bzz".into()));
        assert_eq!(scheme("1bzz://x"), None);
    }

    #[test]
    fn targets() {
        assert_eq!(
            normalize_target("/bzz/r/a/..\\..\\..\\x?'").as_deref(),
            Some("/x?%27")
        );
        assert_eq!(normalize_target("/ipfs/c/#f").as_deref(), Some("/ipfs/c/"));
    }
}
