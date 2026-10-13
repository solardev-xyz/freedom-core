//! `bzz:` (`swarm/bzz-protocol.js`): a 64- or 128-hex reference or a name
//! host, an allowlist of request headers plus Swarm's own, and no encoded
//! separator in the path.

use crate::headers::Headers;
use crate::names::{has_empty_label, is_dweb_name_host, is_potential_ens_name};
use crate::open::{Opening, Pending, Request, absent, fetch_plan};
use crate::plan::{ErrorPlan, Plan, Scheme};
use crate::{js, url};

/// `FORWARDED_REQUEST_HEADERS`: what a page may send to the node.
pub const FORWARDED_REQUEST_HEADERS: [&str; 10] = [
    "accept",
    "accept-encoding",
    "accept-language",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "range",
    "user-agent",
];

/// The retrieval hints every request carries, with their fixed values.
pub const SWARM_HEADERS: [(&str, &str); 3] = [
    ("swarm-chunk-retrieval-timeout", "30s"),
    ("swarm-redundancy-strategy", "3"),
    ("swarm-redundancy-fallback-mode", "true"),
];

/// `sanitizeRequestHeaders`: the allowlist, then Swarm's headers.
pub fn request_headers(headers: &Headers) -> Vec<(String, String)> {
    let mut out = Headers::new();
    for (name, value) in headers.entries() {
        if FORWARDED_REQUEST_HEADERS.contains(&name.as_str()) {
            out.append(&name, &value);
        }
    }
    for (name, value) in SWARM_HEADERS {
        out.set(name, value);
    }
    out.entries()
}

/// `BZZ_HASH_RE`: 64 or 128 hex digits, either case.
pub fn is_reference(host: &str) -> bool {
    matches!(host.len(), 64 | 128) && host.bytes().all(|b| b.is_ascii_hexdigit())
}

/// An encoded `/` or `\` (`%2f`, `%5c`, either case).
pub(crate) fn has_encoded_separator(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("%2f") || lower.contains("%5c")
}

pub(crate) fn open(request: &Request<'_>, headers: &Headers) -> Opening {
    let error = |status, message: &str| Opening::Plan(Plan::Error(ErrorPlan::new(status, message)));
    if !matches!(js::method(request.method).as_str(), "GET" | "HEAD") {
        return error(405, "method not allowed");
    }
    let Some(parsed) = url::parse(request.url) else {
        return error(400, "invalid bzz reference");
    };
    let pathname = url::pathname(&parsed);
    if has_encoded_separator(&pathname) {
        return error(400, "invalid bzz path");
    }
    let host = url::hostname(&parsed);
    let search = url::search(&parsed);
    let absent_ant = request.backend.is_absent();
    if is_reference(host) {
        if absent_ant {
            return Opening::Plan(Plan::Error(absent(Scheme::Bzz)));
        }
        return Opening::Plan(fetch_plan(
            Scheme::Bzz,
            request.backend,
            &format!("/bzz/{host}{pathname}{search}"),
            request_headers(headers),
            false,
            None,
        ));
    }
    if (is_dweb_name_host(host) || is_potential_ens_name(host)) && !has_empty_label(host) {
        if absent_ant {
            return Opening::Plan(Plan::Error(absent(Scheme::Bzz)));
        }
        return Opening::Resolve(Pending {
            scheme: Scheme::Bzz,
            host: host.to_owned(),
            pathname,
            search,
            backend: request.backend,
            headers: request_headers(headers),
            small_text: false,
        });
    }
    error(400, "invalid bzz reference")
}
