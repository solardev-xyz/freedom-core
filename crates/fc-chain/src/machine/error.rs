//! Errors as the router throws them, and the machine's own failures
//! (design 0005, Errors and text).
//!
//! A [`Thrown`] is today's error: its constructor, its message and its own
//! enumerable properties in order, which is what main rebuilds and what
//! dApps see. Its text comes either from a node's error the core parsed out
//! of an answer ([`Origin::Node`]) or from the core's own texts
//! ([`Origin::Core`]); verifiers and transports never supply text.

use std::rc::Rc;

use super::budget::Charge;
use super::config::number_text;
use crate::js::JsString;
use crate::pattern::{JsPattern, MatchText};
use crate::text::safe_error_message;

/// An own property's value: JSON text, or `undefined`. The text is
/// shared: a copy of an error costs no copy of its data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prop {
    Undefined,
    Json(Rc<str>),
}

impl Prop {
    pub(crate) fn of(text: Option<&str>) -> Self {
        text.map_or(Self::Undefined, |t| Self::Json(t.into()))
    }

    pub(crate) fn string(text: &str) -> Self {
        Self::Json(JsString::from(text).to_json().into())
    }

    /// The JSON text, `None` for `undefined`.
    pub fn json(&self) -> Option<&str> {
        match self {
            Self::Undefined => None,
            Self::Json(text) => Some(text),
        }
    }
}

/// The error's constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    Error,
    TypeError,
    SyntaxError,
    RangeError,
    /// `SourceUnavailableError`: the next source; never the last error.
    SourceUnavailable,
    /// `SourceDeadlineError`, a `SourceUnavailableError`.
    SourceDeadline,
    /// `TruncatedLogsError`: ends the request at once.
    TruncatedLogs,
}

impl ErrorClass {
    /// The constructor's name.
    pub fn constructor(self) -> &'static str {
        match self {
            Self::Error => "Error",
            Self::TypeError => "TypeError",
            Self::SyntaxError => "SyntaxError",
            Self::RangeError => "RangeError",
            Self::SourceUnavailable => "SourceUnavailableError",
            Self::SourceDeadline => "SourceDeadlineError",
            Self::TruncatedLogs => "TruncatedLogsError",
        }
    }

    /// `error.name`.
    pub fn name(self) -> &'static str {
        self.constructor()
    }

    pub(crate) fn from_name(name: &str) -> Self {
        match name {
            "TypeError" => Self::TypeError,
            "SyntaxError" => Self::SyntaxError,
            "RangeError" => Self::RangeError,
            _ => Self::Error,
        }
    }
}

/// Where an error's text came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A JSON-RPC error object the core parsed out of an answer.
    Node,
    /// The core's own texts.
    Core,
}

/// What a quorum round that failed leaves for Direct.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct QuorumMiss {
    /// `directUnansweredUrls`: the members that never answered.
    pub unanswered: Vec<String>,
    /// `directAttemptedUrls`: every member.
    pub attempted: Vec<String>,
    /// `directFallback`: the lowest-index member that answered.
    pub fallback: Option<Rc<Fallback>>,
}

/// A quorum member's answer Direct reuses without a new request.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Fallback {
    pub url: String,
    /// Its result's JSON text, `None` for `undefined`.
    pub result: Option<Rc<super::text::Retained>>,
    pub agreed: Vec<String>,
    pub dissented: Vec<String>,
    pub queried: Vec<String>,
    /// `{ k, m, achieved: false }`.
    pub k: usize,
    pub m: f64,
}

/// An error as the router throws it.
#[derive(Debug, Clone)]
pub struct Thrown {
    pub class: ErrorClass,
    /// Shared, like the properties: the router keeps an error in several
    /// places (the last error, the kept one, the failures), and a node's
    /// can be as large as its answer.
    pub message: Rc<JsString>,
    /// Own enumerable properties, in order.
    pub props: Vec<(&'static str, Prop)>,
    pub origin: Origin,
    /// A failed quorum's evidence for Direct; never in a reply.
    pub(crate) quorum: Option<Rc<QuorumMiss>>,
    /// Main classed a Colibri failure as a capacity limit: the one bit of
    /// the adapter's text the adaptive bypass needs; never in a reply.
    pub(crate) capacity: bool,
    /// A node error's charge against its request's budget, held while any
    /// copy of it lives (`memory-budgets`).
    pub(crate) charge: Option<Rc<Charge>>,
}

/// Errors compare by what a reply carries.
impl PartialEq for Thrown {
    fn eq(&self, other: &Self) -> bool {
        self.class == other.class
            && self.message == other.message
            && self.props == other.props
            && self.origin == other.origin
    }
}

static CAPACITY_TEXT: JsPattern = JsPattern::new(
    r"out of gas|execution (?:gas|resource) limit|exceeds? (?:the )?(?:gas|execution) limit",
    "i",
);

/// `failureKind(error)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureKind {
    Capacity,
    Timeout,
}

impl Thrown {
    fn core(class: ErrorClass, message: impl Into<JsString>) -> Self {
        Self {
            class,
            message: Rc::new(message.into()),
            props: Vec::new(),
            origin: Origin::Core,
            quorum: None,
            capacity: false,
            charge: None,
        }
    }

    /// A plain `Error` with the core's text.
    pub(crate) fn error(message: &str) -> Self {
        Self::core(ErrorClass::Error, message)
    }

    /// `new SourceUnavailableError(message, failureKind)`.
    pub(crate) fn unavailable_kind(message: impl Into<JsString>, kind: Option<&str>) -> Self {
        let mut error = Self::core(ErrorClass::SourceUnavailable, message);
        error.props = vec![
            ("name", Prop::string("SourceUnavailableError")),
            (
                "failureKind",
                kind.map_or(Prop::Json("null".into()), Prop::string),
            ),
        ];
        error
    }

    pub(crate) fn unavailable(message: impl Into<JsString>) -> Self {
        Self::unavailable_kind(message, None)
    }

    /// `new SourceDeadlineError(source, timeoutMs)`.
    pub(crate) fn source_deadline(source: &str, timeout: f64) -> Self {
        let message = format!(
            "{source} exceeded its {}ms interactive deadline",
            number_text(timeout)
        );
        let mut error = Self::unavailable_kind(message.as_str(), Some("timeout"));
        error.class = ErrorClass::SourceDeadline;
        error.props[0].1 = Prop::string("SourceDeadlineError");
        error
    }

    /// The router's own timeout of an exchange, or of a quorum's members
    /// cut at its deadline: `RPC query timeout after <n>ms`.
    pub(crate) fn rpc_timeout(timeout: f64) -> Self {
        let message = format!("RPC query timeout after {}ms", number_text(timeout));
        let mut error = Self::core(ErrorClass::Error, message.as_str());
        error.props = vec![("failureKind", Prop::string("timeout"))];
        error
    }

    /// A node's JSON-RPC error: `code` and `data` are always own
    /// properties, `undefined` when the node sent none.
    pub(crate) fn node(error: &crate::answer::NodeError<'_>) -> Self {
        Self {
            class: ErrorClass::Error,
            message: Rc::new(error.message.clone()),
            props: vec![
                ("code", Prop::of(error.code)),
                ("data", Prop::of(error.data)),
            ],
            origin: Origin::Node,
            quorum: None,
            capacity: false,
            charge: None,
        }
    }

    /// An error of another constructor with the core's text.
    pub(crate) fn of_class(class: ErrorClass, message: impl Into<JsString>) -> Self {
        Self::core(class, message)
    }

    /// Adds an own property.
    pub(crate) fn with(mut self, key: &'static str, value: Prop) -> Self {
        self.props.push((key, value));
        self
    }

    /// An own property's value.
    pub fn prop(&self, key: &str) -> Option<&Prop> {
        self.props.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// `error.code`'s JSON text.
    pub fn code(&self) -> Option<&str> {
        self.prop("code").and_then(Prop::json)
    }

    /// What its text holds, as the budget counts it.
    pub(crate) fn bytes(&self) -> usize {
        self.message.len().saturating_mul(2).saturating_add(
            self.props
                .iter()
                .map(|(_, v)| v.json().map_or(0, str::len))
                .sum(),
        )
    }

    /// `instanceof SourceUnavailableError`.
    pub(crate) fn is_unavailable(&self) -> bool {
        matches!(
            self.class,
            ErrorClass::SourceUnavailable | ErrorClass::SourceDeadline
        )
    }

    /// `err.code === 3`.
    pub(crate) fn is_revert(&self) -> bool {
        self.code() == Some("3")
    }

    /// `err.myotisRefusal`, truthy.
    pub(crate) fn is_myotis_refusal(&self) -> bool {
        self.prop("myotisRefusal")
            .and_then(Prop::json)
            .is_some_and(|v| v != "\"\"" && v != "null" && v != "false")
    }

    /// `safeErrorMessage(error)`.
    pub(crate) fn safe_message(&self) -> JsString {
        safe_error_message(self.class.name(), self.message.units())
    }

    /// `isCapacityFailure` and `failureKind`.
    pub(crate) fn failure_kind(&self) -> Option<FailureKind> {
        let kind = self.prop("failureKind").and_then(Prop::json);
        if self.capacity
            || kind == Some("\"capacity\"")
            || CAPACITY_TEXT.test(&MatchText::new(self.safe_message().units()))
        {
            return Some(FailureKind::Capacity);
        }
        (kind == Some("\"timeout\"")).then_some(FailureKind::Timeout)
    }

    /// `error.failureKind === 'timeout'`, the router's own timeouts.
    pub(crate) fn is_own_timeout(&self) -> bool {
        self.prop("failureKind").and_then(Prop::json) == Some("\"timeout\"")
    }
}

/// 0001's codes for what isn't today's error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Past the request's overall deadline (`overall-deadline`).
    Deadline,
    /// The caller's `cancel`.
    Cancelled,
    /// Over admission's limits, or the total memory budget (`admission`,
    /// `memory-budgets`).
    Busy,
    /// The request spent its memory budget (`memory-budgets`).
    Budget,
    /// The reply would be over the message cap.
    TooLarge,
    /// The chain's configuration changed; main sends reads and fee quotes
    /// again once (`config-change`).
    Reconfigured,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deadline => "deadline",
            Self::Cancelled => "cancelled",
            Self::Busy => "busy",
            Self::Budget => "budget",
            Self::TooLarge => "too_large",
            Self::Reconfigured => "reconfigured",
        }
    }
}

/// A request's failure.
#[derive(Debug, Clone, PartialEq)]
pub enum ChainError {
    /// 0001's `chain_error`: today's thrown error.
    Thrown(Thrown),
    Protocol(Protocol),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::safe_source;

    #[test]
    fn capacity_pattern() {
        assert!(CAPACITY_TEXT.compiles());
        assert!(safe_source(CAPACITY_TEXT.source));
        let error = Thrown::error("prover execution failed: Out of gas");
        assert_eq!(error.failure_kind(), Some(FailureKind::Capacity));
        assert_eq!(
            Thrown::error("execution gas limit reached").failure_kind(),
            Some(FailureKind::Capacity)
        );
        assert_eq!(
            Thrown::rpc_timeout(5000.0).failure_kind(),
            Some(FailureKind::Timeout)
        );
        assert_eq!(Thrown::unavailable("x").failure_kind(), None);
        let deadline = Thrown::source_deadline("Colibri", 2000.0);
        assert_eq!(
            deadline.message.to_string_lossy(),
            "Colibri exceeded its 2000ms interactive deadline"
        );
        assert!(deadline.is_unavailable());
        assert_eq!(deadline.failure_kind(), Some(FailureKind::Timeout));
    }
}
