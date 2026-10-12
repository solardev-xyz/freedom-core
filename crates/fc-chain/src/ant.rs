//! The Ant profile (design 0005, Logs): the bundled Ant node's log scans
//! through its chain bridge (`swarm/ant-chain-bridge.js`). The bridge's
//! router options become one named profile: the exclusions, Blockscout,
//! the widened quorum budget, and its two functions over errors as
//! received, before any reply is built:
//! - [`rank_log_scan_error`] (`rankLogScanError`): how useful a failure is
//!   to Ant, for the router's keep-the-most-useful-error rule;
//! - [`log_scan_range_cap`] (`logScanRangeCap`): the block span an
//!   endpoint's refusal says it serves.
//!
//! Every pattern is the bridge's own source, matched with JavaScript's
//! semantics ([`crate::pattern`]); the vectors pin the sources too.

use fc_json::index::{Index, Kind};

use crate::js::{is_safe_integer, string_to_number};
use crate::pattern::{JsPattern, MatchText, lowercase};

/// What the profile's callers exclude: only two independent providers that
/// agree answer a scan (the quorum, or Blockscout with one RPC endpoint).
pub const ANT_EXCLUDE_SOURCES: [&str; 3] = ["myotis", "colibri", "direct"];

/// The opt-in source the profile names.
pub const ANT_INCLUDE_SOURCES: [&str; 1] = ["blockscout"];

/// The quorum budget a scan gets: a full-history answer can take seconds.
pub const LOG_SCAN_QUORUM_TIMEOUT_MS: u64 = 30_000;

/// Ant's `is_range_limit_error` needles (Ant v0.5.64): its scan halves the
/// window only on an error whose lowercased message contains one.
pub const ANT_LOG_SCAN_SHRINK_NEEDLES: [&str; 12] = [
    "block range",
    "range",
    "more than",
    "exceed",
    "too large",
    "10000",
    "limit",
    "logs matched",
    "response size",
    "up to a",
    "query timeout",
    "too many results",
];

/// How useful a failure is to Ant (`ERROR_RANK`); a later failure replaces
/// the kept one only when it ranks higher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorRank {
    /// Depends on the endpoint; Ant can't act on it.
    Endpoint = 0,
    /// A reply Ant may act on, though it may also be a throttle.
    Hint = 1,
    /// A timeout: Ant shrinks its window, but another endpoint may answer.
    Timeout = 2,
    /// Depends on the request itself (a range limit): it ends the request.
    Request = 3,
}

/// An error as the router received it, before any reply is built.
#[derive(Debug, Clone, Copy)]
pub struct ReceivedError<'a> {
    /// The constructor's name: `Error`, `AbortError`, `TypeError`, ...
    pub name: &'a str,
    /// The message, as UTF-16 code units.
    pub message: &'a [u16],
    /// `error.code`'s JSON text; `None` when the error has none.
    pub code: Option<&'a str>,
    /// `error.failureKind === 'timeout'`: the router's own timeouts.
    pub timeout: bool,
}

impl ReceivedError<'_> {
    /// `Number.isSafeInteger(error.code)`.
    fn has_integer_code(&self) -> bool {
        self.code
            .and_then(|code| Index::new(code).ok())
            .is_some_and(|index| {
                let code = index.root();
                code.kind() == Kind::Number && is_safe_integer(code.number())
            })
    }
}

static TIMEOUT_TEXT: JsPattern = JsPattern::new(r"time(?:d)?[\s-]?out", "i");

/// Wordings that name the query's block range.
static RANGE_SIZE_TEXT: JsPattern = JsPattern::new(
    r"(?:max(?:imum)?|allowed|permitted) (?:block )?range|exceeds? (?:the )?(?:block )?range|(?:block )?range (?:is |of )?(?:too\b|larger|greater|wider|bigger|longer|more than|limit|exceed|limited|capped|size|span)|(?:limited to|up to) (?:an? )?[\w,.]+ (?:blocks? )?range",
    "i",
);

/// Wordings that name the result's size.
static REQUEST_LIMIT_TEXT: JsPattern = JsPattern::new(
    r"too many (?:results|logs|blocks)|response size|logs? matched|(?:returned )?more than [\d,]+ (?:results|logs|blocks)|(?:max(?:imum)?|too many) (?:number of )?(?:results|logs|blocks)|result(?:s| set)? (?:size |limit|too large|exceed)",
    "i",
);

/// Throttles: they describe the endpoint, not the query.
static ENDPOINT_LIMIT_TEXT: JsPattern = JsPattern::new(
    r"\brate\b|rate[\s-]?limit|too many requests|\b429\b|quota|credits?\b|daily request|capacity|requests? (?:per|limit)|throttl",
    "i",
);

/// An endpoint behind the chain head.
static ENDPOINT_STATE_TEXT: JsPattern = JsPattern::new(
    r"beyond (?:the )?(?:current |latest )?(?:executed )?(?:head|latest|chain)|(?:still |is )syncing|not (?:yet )?synced|head block|latest executed block",
    "i",
);

/// A block-range cap named in the message: the number, and `k` for
/// thousands.
static BLOCK_RANGE_CAP_TEXT: [JsPattern; 4] = [
    JsPattern::new(r"maximum of ([\d,]+)(k?) blocks?\b", "i"),
    JsPattern::new(
        r"max(?:imum)? (?:allowed )?block range(?: is)?:? ?([\d,]+)(k?)\b",
        "i",
    ),
    JsPattern::new(
        r"(?:up to|limited to) an? ([\d,]+)(k?)[ -]?(?:blocks? )?range",
        "i",
    ),
    JsPattern::new(
        r"ranges? (?:over|above|greater than|larger than|wider than) ([\d,]+)(k?) blocks?\b",
        "i",
    ),
];

/// Wordings about the answer's size rather than the block range.
static RESULT_SIZE_TEXT: JsPattern = JsPattern::new(r"\bresults?\b|\blogs?\b|response size", "i");

/// `antShrinksLogScanOn(message)`: whether Ant halves its window on it.
pub fn ant_shrinks_log_scan_on(message: &[u16]) -> bool {
    let lower = lowercase(message);
    ANT_LOG_SCAN_SHRINK_NEEDLES
        .iter()
        .any(|needle| lower.contains(needle))
}

/// `rankLogScanError(error)`:
/// - **Timeout:** the router's own timeouts, an `AbortError`, or a message
///   naming a timeout;
/// - **Endpoint:** no integer code, a throttle or a lagging endpoint, or a
///   message none of Ant's needles is in;
/// - **Request:** a coded reply naming the query's range or result size;
/// - **Hint:** any other coded reply Ant would shrink on.
pub fn rank_log_scan_error(error: &ReceivedError<'_>) -> ErrorRank {
    let text = MatchText::new(error.message);
    if error.timeout || error.name == "AbortError" || TIMEOUT_TEXT.test(&text) {
        return ErrorRank::Timeout;
    }
    if endpoint_dependent(error, &text) || !ant_shrinks_log_scan_on(error.message) {
        return ErrorRank::Endpoint;
    }
    if RANGE_SIZE_TEXT.test(&text) || REQUEST_LIMIT_TEXT.test(&text) {
        ErrorRank::Request
    } else {
        ErrorRank::Hint
    }
}

fn endpoint_dependent(error: &ReceivedError<'_>, text: &MatchText) -> bool {
    !error.has_integer_code() || ENDPOINT_LIMIT_TEXT.test(text) || ENDPOINT_STATE_TEXT.test(text)
}

/// `logScanRangeCap(error, span)`: the widest span the refusing endpoint
/// serves, from its refusal of a query over `span` blocks:
/// - the cap its message names (`10,000`, `2K`), when a positive safe
///   integer;
/// - otherwise `span - 1` for a request-ranked refusal that names no result
///   or response size, when `span` is a safe integer above 1;
/// - `None` for anything else: throttles, lagging endpoints, timeouts,
///   uncoded failures and result-count caps.
pub fn log_scan_range_cap(error: &ReceivedError<'_>, span: Option<u64>) -> Option<u64> {
    let text = MatchText::new(error.message);
    if endpoint_dependent(error, &text) {
        return None;
    }
    for pattern in &BLOCK_RANGE_CAP_TEXT {
        let Some(groups) = pattern.exec(&text) else {
            continue;
        };
        let digits: String = groups
            .first()
            .copied()
            .flatten()
            .unwrap_or_default()
            .chars()
            .filter(|c| *c != ',')
            .collect();
        let thousands = groups
            .get(1)
            .copied()
            .flatten()
            .is_some_and(|k| !k.is_empty());
        let cap = string_to_number(&digits) * if thousands { 1000.0 } else { 1.0 };
        return (is_safe_integer(cap) && cap > 0.0).then_some(cap as u64);
    }
    let span = span.filter(|&span| span > 1 && is_safe_integer(span as f64))?;
    (rank_log_scan_error(error) == ErrorRank::Request && !RESULT_SIZE_TEXT.test(&text))
        .then(|| span - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::safe_source;

    fn all_patterns() -> Vec<(&'static str, &'static JsPattern)> {
        let mut patterns = vec![
            ("TIMEOUT_TEXT", &TIMEOUT_TEXT),
            ("RANGE_SIZE_TEXT", &RANGE_SIZE_TEXT),
            ("REQUEST_LIMIT_TEXT", &REQUEST_LIMIT_TEXT),
            ("ENDPOINT_LIMIT_TEXT", &ENDPOINT_LIMIT_TEXT),
            ("ENDPOINT_STATE_TEXT", &ENDPOINT_STATE_TEXT),
            ("RESULT_SIZE_TEXT", &RESULT_SIZE_TEXT),
        ];
        for pattern in &BLOCK_RANGE_CAP_TEXT {
            patterns.push(("BLOCK_RANGE_CAP_TEXT", pattern));
        }
        patterns
    }

    #[test]
    fn patterns_compile_and_are_safe() {
        for (name, pattern) in all_patterns() {
            assert!(pattern.compiles(), "{name}");
            assert!(safe_source(pattern.source), "{name}");
        }
    }

    /// The sources and flags are the bridge's, as the vectors record them.
    #[test]
    fn patterns_are_the_references() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/chain.json");
        let vectors: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let recorded = &vectors["ant_profile"]["patterns"];
        let mut caps = 0;
        for (name, pattern) in all_patterns() {
            let entry = match &recorded[name] {
                serde_json::Value::Array(list) => {
                    caps += 1;
                    list[caps - 1].clone()
                }
                entry => entry.clone(),
            };
            assert_eq!(entry["source"], pattern.source, "{name}");
            assert_eq!(entry["flags"], pattern.flags, "{name}");
        }
        assert_eq!(
            caps,
            recorded["BLOCK_RANGE_CAP_TEXT"].as_array().unwrap().len()
        );
        assert_eq!(recorded.as_object().unwrap().len(), 7);
    }

    #[test]
    fn ranks() {
        let units = |s: &str| s.encode_utf16().collect::<Vec<_>>();
        let message = units("query exceeds max block range 50000");
        let error = ReceivedError {
            name: "Error",
            message: &message,
            code: Some("-32005"),
            timeout: false,
        };
        assert_eq!(rank_log_scan_error(&error), ErrorRank::Request);
        assert_eq!(log_scan_range_cap(&error, Some(60_000)), Some(50_000));
        let uncoded = ReceivedError {
            code: None,
            ..error
        };
        assert_eq!(rank_log_scan_error(&uncoded), ErrorRank::Endpoint);
        let message = units("block range is too wide");
        let wide = ReceivedError {
            message: &message,
            ..error
        };
        assert_eq!(log_scan_range_cap(&wide, Some(50_000)), Some(49_999));
        assert_eq!(log_scan_range_cap(&wide, Some(1 << 53)), None);
        assert!(ErrorRank::Request > ErrorRank::Timeout);
    }
}
