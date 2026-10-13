//! The request failed after the dial: what the page gets, by node.

use crate::plan::{Backend, ErrorPlan, Ipfs};

/// An error the transport threw, as the handlers read it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Thrown<'a> {
    /// `error.name`.
    pub name: &'a str,
    pub message: &'a str,
    /// `error.code`.
    pub code: Option<&'a str>,
    /// `error.cause.code`.
    pub cause_code: Option<&'a str>,
}

/// The error plan for a thrown fetch, after any retries.
///
/// - Ant: 503 when `cause.code || code` is a refused, reset or unknown
///   host, else 502.
/// - The native IPFS node: 502 with the error's message.
/// - The external gateway: an abort with its message, else a fixed 502.
pub fn after_dial(backend: Backend, thrown: &Thrown<'_>) -> ErrorPlan {
    let message = if thrown.message.is_empty() {
        "freedom-ipfs native gateway error"
    } else {
        thrown.message
    };
    match backend {
        Backend::Ant(_) => {
            let code = thrown
                .cause_code
                .filter(|c| !c.is_empty())
                .or(thrown.code.filter(|c| !c.is_empty()))
                .unwrap_or("");
            if matches!(code, "ECONNREFUSED" | "ECONNRESET" | "ENOTFOUND") {
                ErrorPlan::new(503, "bee gateway unreachable")
            } else {
                ErrorPlan::new(502, "bee gateway error")
            }
        }
        Backend::Ipfs(Ipfs::Gateway) if thrown.name != "AbortError" => {
            ErrorPlan::new(502, "external IPFS gateway request failed")
        }
        Backend::Ipfs(_) => ErrorPlan::new(502, message),
    }
}

/// The external gateway's text when it isn't running. A `{ ipfs:
/// "absent" }` plan carries the native node's text, which today's
/// external mode doesn't use.
pub const GATEWAY_NOT_RUNNING: &str = "external IPFS gateway is not running";
