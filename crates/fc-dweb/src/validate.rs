//! Plan validation (design 0006, "Validation before any dial"): a plan is
//! input to check, not permission to dial. Main refuses a plan that fails
//! here with a 502 and logs a core fault. It checks the plan as JSON, as
//! main receives it; the browser's executor mirrors it, with the same
//! vectors.

use fc_json::JsValue;

use crate::bzz::{FORWARDED_REQUEST_HEADERS, SWARM_HEADERS, has_encoded_separator, is_reference};
use crate::ipfs::{GatewayForm, REDIRECT_HEADERS, STRIPPED_REQUEST_HEADERS, gateway_form};
use crate::plan::{
    BODY_IDLE_MS, BZZ_HEADERS_MS, BZZ_RETRY_DELAYS_MS, BZZ_RETRY_STATUSES, Backend, Ipfs,
    NATIVE_QUEUE_MS, ResponseOp, Scheme, content_trust,
};
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
    /// that backend isn't up.
    #[error("node")]
    Node,
    /// The target leaves the node's namespace, isn't normalized, or (Ant)
    /// carries an encoded separator.
    #[error("path")]
    Path,
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
        "redirect" => redirect(body, request, scheme),
        "error" => error(body),
        _ => Err(Refusal::Shape),
    }
}

/// An object with exactly these keys.
fn exact<'v>(value: &'v JsValue, keys: &[&str]) -> Result<&'v [(String, JsValue)], Refusal> {
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
    check_headers(&headers, scheme)?;
    check_retry(retry, backend)?;
    check_timers(timers, backend)?;
    check_response(response, backend)?;
    check_trust(trust, backend)
}

/// The target: normalized, in the request's namespace, with a reference.
fn check_path(path: &str, scheme: Scheme) -> Result<(), Refusal> {
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

/// A value `Headers` would hold: Latin-1, no NUL, CR or LF, and no HTTP
/// whitespace at either end.
fn is_header_value(value: &str) -> bool {
    value
        .chars()
        .all(|c| u32::from(c) <= 0xff && !matches!(c, '\0' | '\r' | '\n'))
        && !value.starts_with([' ', '\t'])
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
    let mut seen = Vec::new();
    for item in response {
        let op = item
            .as_str()
            .and_then(ResponseOp::from_name)
            .ok_or(Refusal::Response)?;
        if !allowed_ops(backend).contains(&op) || seen.contains(&op) {
            return Err(Refusal::Response);
        }
        seen.push(op);
    }
    Ok(())
}

fn check_trust(trust: &JsValue, backend: Backend) -> Result<(), Refusal> {
    let name_ok = matches!(trust.get("name"), Some(JsValue::Null | JsValue::String(_)));
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

/// One of today's statuses, the same code, and a bounded message.
fn error(body: &JsValue) -> Result<(), Refusal> {
    exact(body, &["status", "code", "message"])?;
    let status = body.get("status");
    let status_ok = matches!(status, Some(JsValue::Number(n)) if ERROR_STATUSES.iter().any(|&s| f64::from(s) == *n));
    let code_ok = body.get("code") == status;
    let message_ok = body
        .get("message")
        .and_then(JsValue::as_str)
        .is_some_and(|message| js::utf16_len(message) <= MAX_MESSAGE_UNITS);
    if status_ok && code_ok && message_ok {
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
}
