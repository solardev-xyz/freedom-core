//! `ipfs:` and `ipns:` (`ipfs/ipfs-protocol.js`): CID and key hosts
//! canonicalized, gateway-form URLs redirected to their canonical form, a
//! strip-list of request headers, and the small-text rule for navigations.

use crate::cid::{cid_v0_to_v1_base32, cid_v1_b58btc_to_base32, ipns_mh_to_cid_v1_base36};
use crate::headers::Headers;
use crate::names::{has_empty_label, is_dweb_name_host, is_potential_ens_name};
use crate::open::{Opening, Pending, Request, fetch_plan};
use crate::plan::{ErrorPlan, Plan, Redirect, Scheme};
use crate::{js, url};

/// `STRIPPED_REQUEST_HEADERS`: what never reaches the node.
pub const STRIPPED_REQUEST_HEADERS: [&str; 13] = [
    "host",
    "origin",
    "referer",
    "cookie",
    "authorization",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// `KNOWN_GATEWAY_HOSTS`, besides any `*.localhost`.
pub const KNOWN_GATEWAY_HOSTS: [&str; 16] = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    "::1",
    "dweb.link",
    "ipfs.io",
    "gateway.ipfs.io",
    "cf-ipfs.com",
    "cloudflare-ipfs.com",
    "gateway.pinata.cloud",
    "nftstorage.link",
    "w3s.link",
    "4everland.io",
    "ipfs.fleek.co",
    "dweb.eu.org",
];

/// `sanitizeRequestHeaders`: everything but the strip-list.
pub fn request_headers(headers: &Headers) -> Vec<(String, String)> {
    headers
        .entries()
        .into_iter()
        .filter(|(name, _)| !STRIPPED_REQUEST_HEADERS.contains(&name.as_str()))
        .collect()
}

/// `isDocumentRequest`: the first `Accept` token, trimmed and lowercased,
/// is exactly `text/html`.
pub fn is_navigation(headers: &Headers) -> bool {
    let accept = headers.get("accept").unwrap_or_default();
    let first = accept.split(',').next().unwrap_or("");
    js::trim(first).to_lowercase() == "text/html"
}

// The handlers' regular expressions. With `/i` and no `u`, a class of ASCII
// letters matches both cases and nothing beyond ASCII.

fn prefix_ci(text: &str, prefix: &str) -> bool {
    text.as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

/// `[1-9A-HJ-NP-Za-km-z]` under `/i`: every letter, and digits but `0`.
fn base58_ci(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() && byte != b'0'
}

/// `[a-z2-7]` under `/i`.
fn base32_ci(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || (b'2'..=b'7').contains(&byte)
}

/// `/^Qm[1-9A-HJ-NP-Za-km-z]{44}$/i`.
fn is_qm(text: &str) -> bool {
    text.len() == 46 && prefix_ci(text, "qm") && text.bytes().skip(2).all(base58_ci)
}

/// `/^ba[a-z2-7]{49,}$/i`.
fn is_ba(text: &str) -> bool {
    text.len() >= 51 && prefix_ci(text, "ba") && text.bytes().skip(2).all(base32_ci)
}

/// `/^z[1-9A-HJ-NP-Za-km-z]{40,}$/i`.
fn is_z(text: &str) -> bool {
    text.len() >= 41 && prefix_ci(text, "z") && text.bytes().skip(1).all(base58_ci)
}

/// `/^k[a-z0-9]{40,}$/i`.
fn is_k(text: &str) -> bool {
    text.len() >= 41
        && prefix_ci(text, "k")
        && text.bytes().skip(1).all(|b| b.is_ascii_alphanumeric())
}

/// `CID_RE`.
fn is_cid(host: &str) -> bool {
    is_qm(host) || is_ba(host) || is_z(host)
}

/// `IPNS_HOST_RE`: `/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$/`.
fn is_ipns_host(host: &str) -> bool {
    host.as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `looksLikeContentKey`.
fn looks_like_content_key(reference: &str) -> bool {
    let peer = |prefix: &str, min: usize| {
        prefix_ci(reference, prefix)
            && reference.len() >= prefix.len() + min
            && reference
                .bytes()
                .skip(prefix.len())
                .all(|b| b.is_ascii_alphanumeric())
    };
    is_qm(reference)
        || is_ba(reference)
        || is_z(reference)
        || is_k(reference)
        || peer("12d3", 30)
        || peer("16uiu2h", 30)
}

/// `isLikelyDnsLinkName`: two or more dot-separated labels of letters,
/// digits and inner hyphens, at most 253 units.
fn is_likely_dnslink_name(reference: &str) -> bool {
    if reference.is_empty() || js::utf16_len(reference) > 253 {
        return false;
    }
    let label_ok = |label: &str| {
        let bytes = label.as_bytes();
        match (bytes.first(), bytes.last()) {
            (Some(first), Some(last)) => {
                first.is_ascii_alphanumeric()
                    && last.is_ascii_alphanumeric()
                    && bytes
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            }
            _ => false,
        }
    };
    reference.split('.').count() >= 2 && reference.split('.').all(label_ok)
}

/// `isKnownGatewayHost`.
fn is_known_gateway_host(host: &str) -> bool {
    let lower = host.to_lowercase();
    !host.is_empty()
        && (KNOWN_GATEWAY_HOSTS.contains(&lower.as_str()) || lower.ends_with(".localhost"))
}

/// `isCaseSafeCanonicalRef`.
fn is_case_safe_canonical_ref(namespace: &str, reference: &str) -> bool {
    is_ba(reference)
        || (namespace == "ipns" && (is_k(reference) || is_likely_dnslink_name(reference)))
}

/// `matchGatewayForm`: a known gateway host carrying `/<ns>/<ref>…`, with
/// the reference canonicalized where it can be.
fn match_gateway_form(host: &str, pathname: &str) -> Option<(&'static str, String, String)> {
    if !is_known_gateway_host(host) {
        return None;
    }
    let after = pathname.strip_prefix('/')?;
    let (namespace, after) = if let Some(rest) = after.strip_prefix("ipfs/") {
        ("ipfs", rest)
    } else {
        ("ipns", after.strip_prefix("ipns/")?)
    };
    let end = after.find('/').unwrap_or(after.len());
    let (reference, rest) = after.split_at(end);
    // `(.*)$`: `.` stops at a line terminator.
    if reference.is_empty() || rest.contains(['\n', '\r', '\u{2028}', '\u{2029}']) {
        return None;
    }
    let content_key = looks_like_content_key(reference);
    if !(content_key || (namespace == "ipns" && is_likely_dnslink_name(reference))) {
        return None;
    }
    let canonical = if namespace == "ipfs" {
        cid_v0_to_v1_base32(reference).or_else(|| cid_v1_b58btc_to_base32(reference))
    } else if content_key {
        ipns_mh_to_cid_v1_base36(reference).or_else(|| cid_v1_b58btc_to_base32(reference))
    } else {
        None
    };
    let rest = if rest.is_empty() { "/" } else { rest };
    Some((
        namespace,
        canonical.unwrap_or_else(|| reference.to_owned()),
        rest.to_owned(),
    ))
}

/// What `gatewayFormRedirect` makes of a gateway-form URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GatewayForm {
    /// Redirect to this canonical `ipfs://` or `ipns://` URL.
    Location(String),
    /// No case-safe canonical form: refuse it.
    Refuse,
}

/// `gatewayFormRedirect`; `None` when the URL isn't gateway-form.
pub(crate) fn gateway_form(url_text: &str) -> Option<GatewayForm> {
    let parsed = url::parse(url_text)?;
    let (namespace, reference, rest) =
        match_gateway_form(url::hostname(&parsed), &url::pathname(&parsed))?;
    if !is_case_safe_canonical_ref(namespace, &reference) {
        return Some(GatewayForm::Refuse);
    }
    Some(GatewayForm::Location(format!(
        "{namespace}://{}{rest}{}",
        reference.to_lowercase(),
        url::search(&parsed)
    )))
}

/// The redirect's own headers, besides `Location`.
pub(crate) const REDIRECT_HEADERS: [(&str, &str); 1] = [("access-control-allow-origin", "*")];

fn lowercased(kind: &str, host: &str, namespace: &str, encoding: &str, publish: &str) -> String {
    format!(
        "lowercased {kind} host \"{host}\" is not a valid {namespace} reference. \
         Chromium's standard-scheme URL parser lowercased the host segment and destroyed the \
         case-sensitive {encoding}. Publish the resource with its {publish} form for sub-resource use."
    )
}

pub(crate) fn open(scheme: Scheme, request: &Request<'_>, headers: &Headers) -> Opening {
    let namespace = scheme.as_str();
    let error =
        |status, message: String| Opening::Plan(Plan::Error(ErrorPlan::new(status, message)));
    let method = js::method(request.method);
    if !matches!(method.as_str(), "GET" | "HEAD") {
        return error(
            405,
            "freedom-ipfs native gateway supports GET and HEAD".to_owned(),
        );
    }
    match gateway_form(request.url) {
        Some(GatewayForm::Location(location)) => {
            return Opening::Plan(Plan::Redirect(Redirect {
                status: 307,
                location,
                headers: REDIRECT_HEADERS
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                    .collect(),
            }));
        }
        Some(GatewayForm::Refuse) => {
            return error(
                400,
                format!(
                    "gateway-form {namespace} URL has no canonical ipfs:// or ipns:// form; \
                     not serving it under the gateway host's origin"
                ),
            );
        }
        None => {}
    }
    let invalid = || error(400, format!("invalid {namespace} reference"));
    let Some(parsed) = url::parse(request.url) else {
        return invalid();
    };
    let mut host = url::hostname(&parsed).to_owned();
    let pathname = url::pathname(&parsed);
    let search = url::search(&parsed);
    let small_text = method == "GET" && is_navigation(headers);
    let sanitized = request_headers(headers);
    if scheme == Scheme::Ipfs && is_cid(&host) {
        if is_qm(&host) {
            match cid_v0_to_v1_base32(&host) {
                Some(canonical) => host = canonical,
                None => {
                    return error(
                        400,
                        lowercased(
                            "CIDv0",
                            &host,
                            "IPFS",
                            "base58btc encoding",
                            "CIDv1 base32 (bafy...)",
                        ),
                    );
                }
            }
        } else if is_z(&host) {
            match cid_v1_b58btc_to_base32(&host) {
                Some(canonical) => host = canonical,
                None => {
                    return error(
                        400,
                        lowercased(
                            "CIDv1 base58btc",
                            &host,
                            "IPFS",
                            "base58btc encoding",
                            "CIDv1 base32 (bafy...)",
                        ),
                    );
                }
            }
        }
        return Opening::Plan(fetch_plan(
            scheme,
            request.backend,
            &format!("/ipfs/{host}{pathname}{search}"),
            sanitized,
            small_text,
            None,
        ));
    }
    if scheme == Scheme::Ipns && !is_dweb_name_host(&host) && is_ipns_host(&host) {
        if prefix_ci(&host, "12d3") || prefix_ci(&host, "16uiu2h") || prefix_ci(&host, "qm") {
            match ipns_mh_to_cid_v1_base36(&host) {
                Some(canonical) => host = canonical,
                None => {
                    return error(
                        400,
                        lowercased(
                            "base58btc IPNS",
                            &host,
                            "IPNS",
                            "encoding",
                            "libp2p-key base36 (k51.../k2k4...)",
                        ),
                    );
                }
            }
        } else if is_z(&host) {
            match cid_v1_b58btc_to_base32(&host) {
                Some(canonical) => host = canonical,
                None => {
                    return error(
                        400,
                        lowercased(
                            "CIDv1 base58btc IPNS",
                            &host,
                            "IPNS",
                            "base58btc encoding",
                            "libp2p-key base36 (k51.../k2k4...) or CIDv1 base32 (bafy...)",
                        ),
                    );
                }
            }
        }
        return Opening::Plan(fetch_plan(
            scheme,
            request.backend,
            &format!("/ipns/{host}{pathname}{search}"),
            sanitized,
            small_text,
            None,
        ));
    }
    if (is_dweb_name_host(&host) || (scheme == Scheme::Ipfs && is_potential_ens_name(&host)))
        && !has_empty_label(&host)
    {
        return Opening::Resolve(Pending {
            scheme,
            host,
            pathname,
            search,
            backend: request.backend,
            headers: sanitized,
            small_text,
        });
    }
    invalid()
}
