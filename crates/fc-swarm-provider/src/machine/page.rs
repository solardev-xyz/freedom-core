//! A page's errors, `{ code, message, data? }`, in today's shapes
//! (swarm-provider-ipc.js's `ERRORS`, `invalidParams`, `notAuthorized`).

use fc_json::JsString;

use crate::errors::{INTERNAL_ERROR, INVALID_PARAMS, NODE_UNAVAILABLE, PageError};
use crate::value::Value;

/// `ERRORS.UNAUTHORIZED`'s code.
pub const UNAUTHORIZED: i32 = 4100;
/// `ERRORS.UNSUPPORTED_METHOD`'s code.
pub const UNSUPPORTED_METHOD: i32 = 4200;

/// A page's error.
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    pub code: i32,
    pub message: JsString,
    pub data: Option<Value>,
}

impl Failure {
    /// `{ code, message }`.
    pub fn bare(code: i32, message: impl Into<JsString>) -> Failure {
        Failure {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// `invalidParams(message, reason)`: -32602 with `data: { reason }`.
    pub fn invalid_params(message: impl Into<JsString>, reason: &str) -> Failure {
        Failure::invalid_params_with(message, reason, Vec::new())
    }

    /// `invalidParams(message, reason, extra)`: `data: { reason, ...extra }`.
    pub fn invalid_params_with(
        message: impl Into<JsString>,
        reason: &str,
        extra: Vec<(&str, Value)>,
    ) -> Failure {
        let mut data = vec![(JsString::from("reason"), Value::str(reason))];
        data.extend(extra.into_iter().map(|(k, v)| (JsString::from(k), v)));
        Failure {
            code: INVALID_PARAMS,
            message: message.into(),
            data: Some(Value::Object(data)),
        }
    }

    /// `notAuthorized(reason)`: 4100 with `data: { reason }`.
    pub fn not_authorized(reason: &str) -> Failure {
        Failure {
            code: UNAUTHORIZED,
            message: JsString::from("The origin is not authorized for this operation"),
            data: Some(Value::object([("reason", Value::str(reason))])),
        }
    }

    /// `notConnected()`.
    pub fn not_connected() -> Failure {
        Failure::not_authorized("not_connected")
    }

    /// A readiness check's `{ ok: false, reason }`: 4900 `Node not
    /// available: <reason>` with `data: { reason }`.
    pub fn node_unavailable(reason: &JsString) -> Failure {
        Failure {
            code: NODE_UNAVAILABLE,
            message: crate::js::concat(&[&JsString::from("Node not available: "), reason]),
            data: Some(Value::object([("reason", Value::String(reason.clone()))])),
        }
    }

    /// `{ ...ERRORS.INTERNAL_ERROR, message }`.
    pub fn internal(message: impl Into<JsString>) -> Failure {
        Failure::bare(INTERNAL_ERROR, message)
    }

    /// 4900 `busy` with `data: { reason: "busy" }`: the core's queue or
    /// memory, main's Swarm I/O pool (deviation `busy`).
    pub fn busy() -> Failure {
        Failure {
            code: NODE_UNAVAILABLE,
            message: JsString::from("busy"),
            data: Some(Value::object([("reason", Value::str("busy"))])),
        }
    }

    /// -32603 `Internal error`: a call main refused by its grammar, which
    /// only a core bug makes (design 0015, "The rules").
    pub fn internal_error() -> Failure {
        Failure::internal("Internal error")
    }
}

impl From<PageError> for Failure {
    fn from(err: PageError) -> Self {
        Failure {
            code: err.code,
            message: err.message,
            data: err
                .reason
                .map(|reason| Value::object([("reason", Value::str(reason))])),
        }
    }
}
