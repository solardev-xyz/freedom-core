//! Plan validation (design 0006, "Validation before any dial"): a plan is
//! input to check, not permission to dial. Main refuses a plan that fails
//! here with a 502 and logs a core fault. It checks the plan as JSON, as
//! main receives it; the browser's executor mirrors it, with the same
//! vectors.

use fc_json::{JsString, JsValue};

use crate::bzz::{FORWARDED_REQUEST_HEADERS, SWARM_HEADERS, has_encoded_separator, is_reference};
use crate::ipfs::{GatewayForm, REDIRECT_HEADERS, STRIPPED_REQUEST_HEADERS, gateway_form};
use crate::open::{Opening, Request, open};
use crate::plan::{
    BODY_IDLE_MS, BZZ_HEADERS_MS, BZZ_RETRY_DELAYS_MS, BZZ_RETRY_STATUSES, Backend, Ipfs,
    NATIVE_QUEUE_MS, Plan, ResponseOp, Root, Scheme, Verification, content_trust,
};
use crate::verify::{STRICT_MESSAGES, STRICT_STATUS, VERIFY_HEADERS_ANT, VERIFY_HEADERS_IPFS};
use crate::{js, url};

/// The longest error message, in UTF-16 code units: twice the request's
/// 64 KiB URL bound, so a message naming the host always fits.
pub const MAX_MESSAGE_UNITS: usize = 131_072;

/// The statuses an error plan may carry: today's.
pub const ERROR_STATUSES: [u16; 6] = [400, 404, 405, 415, 502, 503];

/// The request a plan answers, as main admitted it.
#[derive(Debug, Clone, Copy)]
pub struct PlanRequest<'a> {
    pub url: &'a str,
    pub method: &'a str,
    pub backend: Backend,
}

/// Why a plan is refused: the first check it fails, in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// Not exactly one variant, or a field missing, extra or of the wrong
    /// container type.
    #[error("shape")]
    Shape,
    /// A fetch for a method other than GET or HEAD.
    #[error("method")]
    Method,
    /// `node` doesn't name the backend main admitted for the scheme, or
    /// that backend isn't up, or (a verify plan) its verification is off.
    #[error("node")]
    Node,
    /// A verify plan's root isn't the scheme's, isn't in its form (64 hex
    /// digits; a CIDv1 in lowercase base32; an IPNS name with an Ed25519
    /// or sha2-256 key), or isn't a hash host's own.
    #[error("root")]
    Root,
    /// The target leaves the node's namespace, isn't normalized, or (Ant)
    /// carries an encoded separator.
    #[error("path")]
    Path,
    /// A verify plan's query isn't the admitted URL's.
    #[error("query")]
    Query,
    /// A header outside the scheme's policy, a malformed one, or Swarm's
    /// headers missing, repeated or changed.
    #[error("header")]
    Header,
    #[error("retry")]
    Retry,
    #[error("timers")]
    Timers,
    /// An operation unknown, repeated, or not the backend's.
    #[error("response")]
    Response,
    #[error("trust")]
    Trust,
    #[error("redirect")]
    Redirect,
    #[error("error")]
    Error,
}

impl Refusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shape => "shape",
            Self::Method => "method",
            Self::Node => "node",
            Self::Root => "root",
            Self::Query => "query",
            Self::Path => "path",
            Self::Header => "header",
            Self::Retry => "retry",
            Self::Timers => "timers",
            Self::Response => "response",
            Self::Trust => "trust",
            Self::Redirect => "redirect",
            Self::Error => "error",
        }
    }
}

/// Checks a plan against the request it answers.
pub fn validate_plan(plan: &JsValue, request: &PlanRequest<'_>) -> Result<(), Refusal> {
    let JsValue::Object(variants) = plan else {
        return Err(Refusal::Shape);
    };
    let [(variant, body)] = variants.as_slice() else {
        return Err(Refusal::Shape);
    };
    let scheme = url::scheme(request.url).and_then(|name| Scheme::from_name(&name));
    match variant.as_str() {
        "fetch" => fetch(body, request, scheme),
        "verify" => verify(body, request, scheme),
        "redirect" => redirect(body, request, scheme),
        "error" => error(body, request),
        _ => Err(Refusal::Shape),
    }
}

/// An object with exactly these keys.
fn exact<'v>(value: &'v JsValue, keys: &[&str]) -> Result<&'v [(JsString, JsValue)], Refusal> {
    let JsValue::Object(props) = value else {
        return Err(Refusal::Shape);
    };
    let complete = props.len() == keys.len() && keys.iter().all(|key| value.get(key).is_some());
    if complete {
        Ok(props)
    } else {
        Err(Refusal::Shape)
    }
}

fn field<'v>(value: &'v JsValue, key: &str) -> Result<&'v JsValue, Refusal> {
    value.get(key).ok_or(Refusal::Shape)
}

/// `[[name, value], …]`, all strings.
fn string_pairs(value: &JsValue) -> Result<Vec<(&str, &str)>, Refusal> {
    let items = value.as_array().ok_or(Refusal::Shape)?;
    items
        .iter()
        .map(|item| match item.as_array() {
            Some([JsValue::String(name), JsValue::String(value)]) => {
                Ok((name.as_str(), value.as_str()))
            }
            _ => Err(Refusal::Shape),
        })
        .collect()
}

/// An integer from `min` to `max`.
fn integer_in(value: &JsValue, min: f64, max: f64) -> Option<f64> {
    match value {
        JsValue::Number(n) if js::is_integer(*n) && *n >= min && *n <= max => Some(*n),
        _ => None,
    }
}

fn fetch(body: &JsValue, request: &PlanRequest<'_>, scheme: Option<Scheme>) -> Result<(), Refusal> {
    exact(
        body,
        &[
            "node", "path", "headers", "retry", "timers", "response", "trust",
        ],
    )?;
    let path = field(body, "path")?.as_str().ok_or(Refusal::Shape)?;
    let headers = string_pairs(field(body, "headers")?)?;
    let retry = field(body, "retry")?;
    exact(retry, &["statuses", "on_error", "attempts", "delays_ms"])?;
    let timers = field(body, "timers")?;
    exact(timers, &["queue_ms", "headers_ms", "body_idle_ms"])?;
    let response = field(body, "response")?.as_array().ok_or(Refusal::Shape)?;
    let trust = field(body, "trust")?;
    exact(trust, &["name", "content"])?;

    if !matches!(js::method(request.method).as_str(), "GET" | "HEAD") {
        return Err(Refusal::Method);
    }
    let backend = request.backend;
    let node = field(body, "node")?.as_str();
    // The node must be the backend main admitted, and up.
    let node_ok = backend.up()
        && matches!(
            (node, scheme, backend),
            (Some("ant"), Some(Scheme::Bzz), Backend::Ant { .. })
                | (
                    Some("ipfs"),
                    Some(Scheme::Ipfs | Scheme::Ipns),
                    Backend::Ipfs { .. }
                )
        );
    let Some(scheme) = scheme.filter(|_| node_ok) else {
        return Err(Refusal::Node);
    };
    check_path(path, scheme)?;
    // A hash host needs no lookup: the target is the request's own, rebuilt
    // here, and no name stands behind it (#97). One the core verifies has
    // no fetch target: a fetch there would downgrade it (0009).
    let host = request_target(request);
    match &host {
        Host::Hash(expected) if path != expected => return Err(Refusal::Path),
        Host::NoFetch | Host::Verified(_) => return Err(Refusal::Path),
        // A name's result the core verifies has no fetch either: with
        // verification on, only 0009's three unverified forms stay one.
        Host::Name
            if backend.verification() == Verification::On
                && !crate::verify::stays_unverified(node_of(scheme), path) =>
        {
            return Err(Refusal::Path);
        }
        Host::Hash(_) | Host::Name => {}
    }
    check_headers(&headers, scheme)?;
    check_retry(retry, backend)?;
    check_timers(timers, backend)?;
    check_response(response, backend)?;
    // A strict backend never gets a fetch: its content would be unverified.
    if backend.strict() {
        return Err(Refusal::Trust);
    }
    check_trust(trust, backend, matches!(host, Host::Name))
}

/// A verify plan (0009, Verify plans): 0006's checks, applied to the root,
/// the path below it and the query, and the bundled node's headers and
/// operations.
fn verify(
    body: &JsValue,
    request: &PlanRequest<'_>,
    scheme: Option<Scheme>,
) -> Result<(), Refusal> {
    exact(
        body,
        &[
            "node", "root", "path", "query", "headers", "retry", "timers", "response", "trust",
        ],
    )?;
    let Some(JsValue::Object(root)) = body.get("root") else {
        return Err(Refusal::Shape);
    };
    let [(root_key, JsValue::String(reference))] = root.as_slice() else {
        return Err(Refusal::Shape);
    };
    let (root_key, reference) = (root_key.as_str(), reference.as_str());
    let path = field(body, "path")?.as_str().ok_or(Refusal::Shape)?;
    let query = field(body, "query")?.as_str().ok_or(Refusal::Shape)?;
    let headers = string_pairs(field(body, "headers")?)?;
    let retry = field(body, "retry")?;
    exact(retry, &["statuses", "on_error", "attempts", "delays_ms"])?;
    let timers = field(body, "timers")?;
    exact(timers, &["queue_ms", "headers_ms", "body_idle_ms"])?;
    let response = field(body, "response")?.as_array().ok_or(Refusal::Shape)?;
    let trust = field(body, "trust")?;
    exact(trust, &["name", "content"])?;

    if !matches!(js::method(request.method).as_str(), "GET" | "HEAD") {
        return Err(Refusal::Method);
    }
    let backend = request.backend;
    let node = field(body, "node")?.as_str();
    let node_ok = backend.up()
        && backend.verification() == Verification::On
        && matches!(
            (node, scheme, backend),
            (Some("ant"), Some(Scheme::Bzz), Backend::Ant { .. })
                | (
                    Some("ipfs"),
                    Some(Scheme::Ipfs | Scheme::Ipns),
                    Backend::Ipfs { .. }
                )
        );
    let Some(scheme) = scheme.filter(|_| node_ok) else {
        return Err(Refusal::Node);
    };

    // The root: the scheme's kind, in its form, and a hash host's own.
    let host = request_target(request);
    let own = match &host {
        Host::Verified(own) => Some(own),
        _ => None,
    };
    let root = match (scheme, root_key) {
        (Scheme::Bzz, "swarm") => Some(Root::Swarm(reference.to_owned())),
        (Scheme::Ipfs, "ipfs") => Some(Root::Ipfs(reference.to_owned())),
        (Scheme::Ipns, "ipns") => Some(Root::Ipns(reference.to_owned())),
        _ => None,
    };
    let in_form = root.as_ref().is_some_and(crate::verify::root_in_form);
    let tied = own.is_none_or(|v| v.root.key() == root_key && v.root.reference() == reference);
    if !in_form || !tied || matches!(host, Host::NoFetch | Host::Hash(_)) {
        return Err(Refusal::Root);
    }

    // The path below it: 0006's checks on /<namespace>/<root><path>, and a
    // hash host's own.
    if !(path.is_empty() || path.starts_with('/')) || path.contains(['?', '#']) {
        return Err(Refusal::Path);
    }
    check_path(&format!("/{}/{reference}{path}", scheme.as_str()), scheme)?;
    if own.is_some_and(|v| v.path != path) {
        return Err(Refusal::Path);
    }

    // The query: the admitted URL's, as a fetch plan's target carries it
    // (normalized as an HTTP client sends it).
    let admitted = admitted_query(request.url);
    if query != admitted || own.is_some_and(|v| v.query != query) {
        return Err(Refusal::Query);
    }

    check_verify_headers(&headers, scheme)?;
    check_retry(retry, backend)?;
    check_timers(timers, backend)?;
    let allowed: &[ResponseOp] = match scheme {
        Scheme::Bzz => &[ResponseOp::CanonicalizeRedirect, ResponseOp::StripPageState],
        Scheme::Ipfs | Scheme::Ipns => &[ResponseOp::StripPageState, ResponseOp::SmallText],
    };
    check_ops(response, allowed)?;
    let name_ok = match trust.get("name") {
        Some(JsValue::Null) => true,
        Some(JsValue::String(_)) => matches!(host, Host::Name),
        _ => false,
    };
    if !name_ok || trust.get("content").and_then(JsValue::as_str) != Some("verified") {
        return Err(Refusal::Trust);
    }
    Ok(())
}

/// The request URL's query, with its `?`, as a fetch plan's target carries
/// it: normalized as an HTTP client sends it, which encodes more than the
/// URL's own scheme does (a `'`, say). Empty when there is none.
fn admitted_query(url_text: &str) -> String {
    let search = url::parse(url_text)
        .map(|u| url::search(&u))
        .unwrap_or_default();
    if search.is_empty() {
        return search;
    }
    url::normalize_target(&format!("/{search}"))
        .and_then(|t| t.find('?').map(|at| t[at..].to_owned()))
        .unwrap_or(search)
}

/// A verify plan's headers: only those the bundled node reads, each at most
/// once, lowercase, with 0006's value rules.
pub(crate) fn check_verify_headers(
    headers: &[(&str, &str)],
    scheme: Scheme,
) -> Result<(), Refusal> {
    let allowed: &[&str] = match scheme {
        Scheme::Bzz => &VERIFY_HEADERS_ANT,
        Scheme::Ipfs | Scheme::Ipns => &VERIFY_HEADERS_IPFS,
    };
    for (i, (name, value)) in headers.iter().enumerate() {
        let repeated = headers[..i].iter().any(|(n, _)| n == name);
        if !is_header_name(name) || !is_header_value(value) || !allowed.contains(name) || repeated {
            return Err(Refusal::Header);
        }
    }
    Ok(())
}

fn node_of(scheme: Scheme) -> crate::plan::Node {
    match scheme {
        Scheme::Bzz => crate::plan::Node::Ant,
        Scheme::Ipfs | Scheme::Ipns => crate::plan::Node::Ipfs,
    }
}

/// What the request's host means for a plan.
enum Host {
    /// A hash host (a Swarm reference, a CID, an IPNS key): the target the
    /// request plans to, with no lookup.
    Hash(String),
    /// A hash host the core verifies: the verify plan it plans to.
    Verified(Box<crate::plan::Verify>),
    /// A name host: the target comes from the name's resolution.
    Name,
    /// No fetch answers this request (a gateway-form URL, an invalid host).
    NoFetch,
}

/// The request's target, as `dweb.open` plans it, with fc-dweb's own code:
/// for a hash host it depends on the URL alone. Strict mode is left out:
/// it is checked on its own, and the target is the same either way.
fn request_target(request: &PlanRequest<'_>) -> Host {
    let opening = open(&Request {
        url: request.url,
        method: request.method,
        headers: &[],
        backend: request.backend.without_strict(),
    });
    match opening {
        Ok(Opening::Plan(Plan::Fetch(fetch))) => Host::Hash(fetch.path),
        Ok(Opening::Plan(Plan::Verify(verify))) => Host::Verified(Box::new(verify)),
        Ok(Opening::Resolve(_)) => Host::Name,
        Ok(Opening::Plan(Plan::Redirect(_) | Plan::Error(_))) | Err(_) => Host::NoFetch,
    }
}

/// The target: normalized, in the request's namespace, with a reference.
pub(crate) fn check_path(path: &str, scheme: Scheme) -> Result<(), Refusal> {
    if url::normalize_target(path).as_deref() != Some(path) {
        return Err(Refusal::Path);
    }
    let pathname = path.split('?').next().unwrap_or("");
    let mut segments = pathname.split('/');
    let (Some(""), Some(namespace), Some(reference)) =
        (segments.next(), segments.next(), segments.next())
    else {
        return Err(Refusal::Path);
    };
    let ok = match scheme {
        Scheme::Bzz => {
            namespace == "bzz" && is_reference(reference) && !has_encoded_separator(pathname)
        }
        Scheme::Ipfs | Scheme::Ipns => {
            namespace == scheme.as_str()
                && !reference.is_empty()
                && reference
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        }
    };
    if ok && stays_beneath(pathname, namespace, reference) {
        Ok(())
    } else {
        Err(Refusal::Path)
    }
}

/// The path judged as decoded, not only as serialized: once `%2E`, `%2F`
/// and `%5C` are decoded (in any case, a single pass) and `/` and `\` both
/// separate, no segment is `.` or `..`, and the path still begins with
/// `/<namespace>/<reference>`. A normalized path has no literal dot
/// segments, so any found here came from escapes. Encoded separators that
/// don't climb, such as `a%2Fb` in a file name, pass.
fn stays_beneath(pathname: &str, namespace: &str, reference: &str) -> bool {
    let decoded = decode_dots_and_separators(pathname);
    let mut segments = decoded.split(['/', '\\']);
    let prefix_ok = segments.next() == Some("")
        && segments.next() == Some(namespace)
        && segments.next() == Some(reference);
    prefix_ok
        && !decoded
            .split(['/', '\\'])
            .any(|segment| segment == "." || segment == "..")
}

/// `%2E`, `%2F` and `%5C`, in any case, decoded in one pass; every other
/// escape left as it is (`%252F` stays `%252F`).
fn decode_dots_and_separators(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        let escape = rest.get(at..at + 3).unwrap_or("");
        let decoded = match escape.to_ascii_lowercase().as_str() {
            "%2e" => Some('.'),
            "%2f" => Some('/'),
            "%5c" => Some('\\'),
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[at + 3..];
            }
            None => {
                out.push('%');
                rest = &rest[at + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// RFC 9110 `tchar`, lowercase letters only.
fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)
        })
}

/// An RFC 9110 field value (section 5.5): visible ASCII, spaces and tabs,
/// and `obs-text` (0x80 to 0xFF), with no other control character (C0 or
/// DEL) and no space or tab at either end.
fn is_header_value(value: &str) -> bool {
    value.chars().all(|c| {
        let code = u32::from(c);
        c == '\t' || ((0x20..=0xff).contains(&code) && code != 0x7f)
    }) && !value.starts_with([' ', '\t'])
        && !value.ends_with([' ', '\t'])
}

fn check_headers(headers: &[(&str, &str)], scheme: Scheme) -> Result<(), Refusal> {
    if !headers
        .iter()
        .all(|(name, value)| is_header_name(name) && is_header_value(value))
    {
        return Err(Refusal::Header);
    }
    match scheme {
        Scheme::Bzz => {
            let allowed = headers.iter().all(|(name, _)| {
                FORWARDED_REQUEST_HEADERS.contains(name)
                    || SWARM_HEADERS.iter().any(|(n, _)| n == name)
            });
            let swarm = SWARM_HEADERS.iter().all(|(swarm, fixed)| {
                let mut values = headers.iter().filter(|(name, _)| name == swarm);
                matches!((values.next(), values.next()), (Some((_, value)), None) if value == fixed)
            });
            if allowed && swarm {
                Ok(())
            } else {
                Err(Refusal::Header)
            }
        }
        Scheme::Ipfs | Scheme::Ipns => {
            if headers
                .iter()
                .any(|(name, _)| STRIPPED_REQUEST_HEADERS.contains(name))
            {
                Err(Refusal::Header)
            } else {
                Ok(())
            }
        }
    }
}

fn check_retry(retry: &JsValue, backend: Backend) -> Result<(), Refusal> {
    let bad = Err(Refusal::Retry);
    let (Some(statuses), Some(JsValue::Bool(on_error)), Some(delays)) = (
        retry.get("statuses").and_then(JsValue::as_array),
        retry.get("on_error"),
        retry.get("delays_ms").and_then(JsValue::as_array),
    ) else {
        return bad;
    };
    let max_attempts = 1.0 + BZZ_RETRY_DELAYS_MS.len() as f64;
    let Some(attempts) = retry
        .get("attempts")
        .and_then(|a| integer_in(a, 1.0, max_attempts))
    else {
        return bad;
    };
    let mut seen = Vec::new();
    for status in statuses {
        match integer_in(status, 0.0, 999.0) {
            Some(code)
                if BZZ_RETRY_STATUSES.iter().any(|&s| f64::from(s) == code)
                    && !seen.contains(&code) =>
            {
                seen.push(code);
            }
            _ => return bad,
        }
    }
    let max_delay = BZZ_RETRY_DELAYS_MS
        .iter()
        .copied()
        .max()
        .map_or(0.0, f64::from);
    if delays.len() as f64 != attempts - 1.0
        || delays
            .iter()
            .any(|d| integer_in(d, 0.0, max_delay).is_none())
    {
        return bad;
    }
    // IPFS has no retry today.
    if matches!(backend, Backend::Ipfs { .. })
        && (attempts != 1.0 || !statuses.is_empty() || *on_error)
    {
        return bad;
    }
    Ok(())
}

fn check_timers(timers: &JsValue, backend: Backend) -> Result<(), Refusal> {
    let bounded = |key: &str, max: u32, null_ok: bool| match timers.get(key) {
        Some(JsValue::Null) => null_ok,
        Some(value) => integer_in(value, 1.0, f64::from(max)).is_some(),
        None => false,
    };
    let gateway = backend.is_gateway();
    if bounded("queue_ms", NATIVE_QUEUE_MS, true)
        && bounded("headers_ms", BZZ_HEADERS_MS, gateway)
        && bounded("body_idle_ms", BODY_IDLE_MS, false)
    {
        Ok(())
    } else {
        Err(Refusal::Timers)
    }
}

/// The operations each backend allows.
fn allowed_ops(backend: Backend) -> &'static [ResponseOp] {
    match backend {
        Backend::Ant { .. } => &[ResponseOp::CanonicalizeRedirect, ResponseOp::StripPageState],
        Backend::Ipfs {
            mode: Ipfs::Gateway,
            ..
        } => &ResponseOp::ALL,
        Backend::Ipfs {
            mode: Ipfs::Native, ..
        } => &[ResponseOp::StripPageState, ResponseOp::SmallText],
    }
}

fn check_response(response: &[JsValue], backend: Backend) -> Result<(), Refusal> {
    check_ops(response, allowed_ops(backend))
}

/// Known operations, each at most once, all of them `allowed`.
fn check_ops(response: &[JsValue], allowed: &[ResponseOp]) -> Result<(), Refusal> {
    let mut seen = Vec::new();
    for item in response {
        let op = item
            .as_str()
            .and_then(ResponseOp::from_name)
            .ok_or(Refusal::Response)?;
        if !allowed.contains(&op) || seen.contains(&op) {
            return Err(Refusal::Response);
        }
        seen.push(op);
    }
    Ok(())
}

/// The content label is the backend's; a name label only behind a lookup
/// (`named`): a hash host's is `null` (#97).
fn check_trust(trust: &JsValue, backend: Backend, named: bool) -> Result<(), Refusal> {
    let name_ok = match trust.get("name") {
        Some(JsValue::Null) => true,
        Some(JsValue::String(_)) => named,
        _ => false,
    };
    let content_ok =
        trust.get("content").and_then(JsValue::as_str) == Some(content_trust(backend).as_str());
    if name_ok && content_ok {
        Ok(())
    } else {
        Err(Refusal::Trust)
    }
}

/// A 307 to the request's canonical `ipfs:` or `ipns:` form, with only
/// `Access-Control-Allow-Origin: *`.
fn redirect(
    body: &JsValue,
    request: &PlanRequest<'_>,
    scheme: Option<Scheme>,
) -> Result<(), Refusal> {
    exact(body, &["status", "location", "headers"])?;
    let bad = Err(Refusal::Redirect);
    if !matches!(scheme, Some(Scheme::Ipfs | Scheme::Ipns)) {
        return bad;
    }
    if body.get("status") != Some(&JsValue::Number(307.0)) {
        return bad;
    }
    let Some(GatewayForm::Location(expected)) = gateway_form(request.url) else {
        return bad;
    };
    if body.get("location").and_then(JsValue::as_str) != Some(expected.as_str()) {
        return bad;
    }
    let headers = body.get("headers").and_then(|h| string_pairs(h).ok());
    let expected_headers: Vec<(&str, &str)> = REDIRECT_HEADERS.to_vec();
    if headers.as_deref() != Some(expected_headers.as_slice()) {
        return bad;
    }
    Ok(())
}

/// One of today's statuses, the same code, and a bounded message; or,
/// against a strict backend, strict mode's 403 with one of its fixed
/// messages (0009, Strict mode).
fn error(body: &JsValue, request: &PlanRequest<'_>) -> Result<(), Refusal> {
    exact(body, &["status", "code", "message"])?;
    let status = body.get("status");
    let strict = matches!(status, Some(JsValue::Number(n)) if *n == f64::from(STRICT_STATUS));
    let status_ok = matches!(status, Some(JsValue::Number(n)) if ERROR_STATUSES.iter().any(|&s| f64::from(s) == *n));
    let code_ok = body.get("code") == status;
    let message = body.get("message").and_then(JsValue::as_str);
    let message_ok = if strict {
        message.is_some_and(|m| STRICT_MESSAGES.contains(&m))
    } else {
        message.is_some_and(|m| js::utf16_len(m) <= MAX_MESSAGE_UNITS)
    };
    let kind_ok = if strict {
        request.backend.strict()
    } else {
        status_ok
    };
    if kind_ok && code_ok && message_ok {
        Ok(())
    } else {
        Err(Refusal::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding_dots_and_separators() {
        for (path, decoded) in [
            ("/a%2Fb%2f%5C%5c%2E%2e", "/a/b/\\\\.."),
            ("/%252F%2", "/%252F%2"),
            ("/%", "/%"),
            ("/%zz%2F", "/%zz/"),
            ("/caf%C3%A9", "/caf%C3%A9"),
        ] {
            assert_eq!(decode_dots_and_separators(path), decoded, "{path}");
        }
        assert!(stays_beneath("/ipfs/c/a%2Fb", "ipfs", "c"));
        assert!(stays_beneath("/ipfs/c", "ipfs", "c"));
        assert!(!stays_beneath("/ipfs/c/a%2F..%2F..", "ipfs", "c"));
        assert!(!stays_beneath("/ipfs/c/%2E%5Cx", "ipfs", "c"));
    }

    #[test]
    fn field_values() {
        for value in ["", "a\tb", "a b", "caf\u{e9}\u{80}\u{ff}"] {
            assert!(is_header_value(value), "{value:?}");
        }
        for value in [
            "\tx", "x ", "a\u{b}b", "a\u{7f}", "a\u{1f}", "\u{0}", "a\u{100}",
        ] {
            assert!(!is_header_value(value), "{value:?}");
        }
    }
}
