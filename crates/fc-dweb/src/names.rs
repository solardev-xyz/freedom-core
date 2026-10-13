//! Name hosts: which hosts the handlers resolve, which resolver they ask,
//! how a published base path joins the request path, and how a resolution
//! result maps to a status (`bzz-protocol.js`, `ipfs-protocol.js`,
//! `content-name-resolver.js`, `shared/origin-utils.js`).

use fc_json::JsValue;

use crate::js::is_js_whitespace;

/// `isEnsHost`: `.eth`, `.box`, `.wei` or `.gwei`, case-insensitively.
pub fn is_ens_host(host: &str) -> bool {
    let lower = host.to_lowercase();
    [".eth", ".box", ".wei", ".gwei"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

/// `isTezosDomainHost`: `.tez`, with no empty label.
pub fn is_tezos_domain_host(host: &str) -> bool {
    let lower = host.to_lowercase();
    lower.ends_with(".tez") && lower.split('.').all(|label| !label.is_empty())
}

/// `isDwebNameHost`.
pub fn is_dweb_name_host(host: &str) -> bool {
    is_ens_host(host) || is_tezos_domain_host(host)
}

/// `isPotentialEnsName`: dotted, no empty label, and nothing a name can't
/// hold (whitespace, `/:@?#%\`, controls).
pub fn is_potential_ens_name(value: &str) -> bool {
    value.contains('.')
        && !value
            .chars()
            .any(|c| is_js_whitespace(c) || "/:@?#%\\".contains(c))
        && !value
            .chars()
            .any(|c| u32::from(c) < 32 || u32::from(c) == 127)
        && value.split('.').all(|label| !label.is_empty())
}

/// `hasEmptyLabel`.
pub(crate) fn has_empty_label(host: &str) -> bool {
    host.split('.').any(str::is_empty)
}

/// `nameSystemLabelForHost`.
pub fn name_system_label_for_host(host: &str) -> &'static str {
    let lower = host.to_lowercase();
    if lower.ends_with(".tez") {
        "Tezos Domains"
    } else if lower.ends_with(".wei") {
        "WNS"
    } else if lower.ends_with(".gwei") {
        "GNS"
    } else {
        "ENS"
    }
}

/// `nameSystemLabelForResult`: the result's `system`, else the host's.
fn name_system_label_for_result(result: &JsValue, host: &str) -> &'static str {
    match result.get("system").and_then(JsValue::as_str) {
        Some("tezos") => "Tezos Domains",
        Some("wns") => "WNS",
        Some("gns") => "GNS",
        _ => name_system_label_for_host(host),
    }
}

/// Which resolver `resolveContentName` asks for a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolver {
    /// `resolveEnsContent`: ENS, and WNS and GNS through it.
    Ens,
    /// `resolveTezosDomain`.
    Tezos,
}

impl Resolver {
    pub fn for_name(name: &str) -> Self {
        if is_tezos_domain_host(name) {
            Self::Tezos
        } else {
            Self::Ens
        }
    }
}

/// `joinPublishedPath(basePath, requestPath)`; `None` stands for any falsy
/// base path.
pub fn join_published_path(base_path: Option<&str>, request_path: &str) -> String {
    let base = match base_path {
        Some(base) if !base.is_empty() && base != "/" => base.strip_suffix('/').unwrap_or(base),
        _ => "",
    };
    let requested = if request_path.is_empty() {
        "/"
    } else {
        request_path
    };
    let rooted = |path: &str| {
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        }
    };
    if base.is_empty() {
        rooted(requested)
    } else if requested == "/" {
        format!("{base}/")
    } else {
        format!("{base}{}", rooted(requested))
    }
}

/// What the resolver did with the name.
#[derive(Debug, Clone, Copy)]
pub enum Resolved<'a> {
    /// It threw, with this message.
    Threw(&'a str),
    /// It returned this value, as JavaScript sees it.
    Returned(&'a JsValue),
}

/// Where the reference throws while mapping a result, so no response is
/// made: a property it reads as a string isn't one (`basePath.replace`),
/// or can't become one (`String(value)` of an object with its own
/// `toString`). The naming code never returns such a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the reference throws on this result's `{0}`")]
pub struct Unplannable(pub &'static str);

/// A name's result, mapped: the content reference and published path to
/// fetch, or the status and message to answer with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mapped {
    /// `/<namespace>/<decoded><joined path><search>`, before normalization.
    Target(String),
    Failure(u16, String),
}

/// `String(value)` in a template literal.
fn template(value: Option<&JsValue>, field: &'static str) -> Result<String, Unplannable> {
    match value {
        None => Ok("undefined".to_owned()),
        Some(value) => value.js_string().map_err(|_| Unplannable(field)),
    }
}

/// `a || b || 'unknown'` over result fields, as a string.
fn first_truthy(result: &JsValue, fields: &[&'static str]) -> Result<String, Unplannable> {
    for &field in fields {
        if let Some(value) = result.get(field).filter(|v| v.truthy()) {
            return template(Some(value), field);
        }
    }
    Ok("unknown".to_owned())
}

/// `resolveEnsToGatewayUrl`'s mapping, for `namespace` (`bzz`, `ipfs` or
/// `ipns`). `host` is the URL's hostname; `pathname` and `search` the
/// request's.
pub(crate) fn map_resolution(
    namespace: &str,
    host: &str,
    pathname: &str,
    search: &str,
    resolved: Resolved<'_>,
) -> Result<Mapped, Unplannable> {
    let fallback = name_system_label_for_host(host);
    let result = match resolved {
        Resolved::Threw(message) => {
            return Ok(Mapped::Failure(
                502,
                format!("{fallback} resolver error: {message}"),
            ));
        }
        Resolved::Returned(result) if !result.truthy() => {
            return Ok(Mapped::Failure(
                502,
                format!("{fallback} resolver returned no result for {host}"),
            ));
        }
        Resolved::Returned(result) => result,
    };
    let label = name_system_label_for_result(result, host);
    Ok(match result.get("type").and_then(JsValue::as_str) {
        Some("ok") => {
            if result.get("protocol").and_then(JsValue::as_str) != Some(namespace) {
                let protocol = template(result.get("protocol"), "protocol")?;
                let expected = if namespace == "bzz" {
                    "Swarm".to_owned()
                } else {
                    namespace.to_uppercase()
                };
                Mapped::Failure(
                    404,
                    format!("{label} name {host} resolves to {protocol}, not {expected}"),
                )
            } else {
                let decoded = template(result.get("decoded"), "decoded")?;
                let base_path = match result.get("basePath") {
                    Some(value) if value.truthy() => {
                        Some(value.as_str().ok_or(Unplannable("basePath"))?)
                    }
                    _ => None,
                };
                let joined = join_published_path(base_path, pathname);
                Mapped::Target(format!("/{namespace}/{decoded}{joined}{search}"))
            }
        }
        Some("not_found") => {
            let reason = first_truthy(result, &["reason"])?;
            Mapped::Failure(
                404,
                format!("{label} name {host} has no contenthash ({reason})"),
            )
        }
        Some("unsupported") => Mapped::Failure(
            415,
            format!("{label} name {host} contenthash format unsupported"),
        ),
        Some("conflict") => Mapped::Failure(502, format!("{label} providers disagree on {host}")),
        _ => {
            let detail = first_truthy(result, &["error", "reason"])?;
            Mapped::Failure(
                502,
                format!("{label} resolution failed for {host}: {detail}"),
            )
        }
    })
}

/// The name's trust level, when the result carries one as a string.
pub(crate) fn trust_level(resolved: Resolved<'_>) -> Option<String> {
    match resolved {
        Resolved::Returned(result) => result
            .get("trust")
            .and_then(|trust| trust.get("level"))
            .and_then(JsValue::as_str)
            .map(str::to_owned),
        Resolved::Threw(_) => None,
    }
}
