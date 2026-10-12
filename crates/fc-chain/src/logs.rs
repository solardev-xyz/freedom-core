//! `eth_getLogs` helpers and constants shared by the router's log
//! mechanisms (design 0005, Logs): the span a filter covers, and the range
//! refusal a range-capped scan gets when no quorum can serve its span.

use fc_json::index::{Index, Kind, Value};

use crate::js::{Element, element};

/// How long a learned range cap holds.
pub const LOG_RANGE_CAP_TTL_MS: u64 = 30 * 60_000;

/// How long a scan leaves out an endpoint that failed for its own reasons,
/// and how long a span its upstream timed out on bounds it.
pub const LOG_SCAN_COOLDOWN_MS: u64 = 30_000;

/// Quorum rounds per range-capped scan.
pub const LOG_SCAN_QUORUM_ROUNDS: u32 = 2;

/// The truncation check's tail: an answer whose logs all fall in this many
/// newest blocks of the range is suspect.
pub const LOG_TRUNCATION_TAIL_BLOCKS: u64 = 1000;

/// The narrowest range the truncation check looks at.
pub const LOG_TRUNCATION_MIN_SPAN: u64 = 2 * LOG_TRUNCATION_TAIL_BLOCKS;

/// The code of a range refusal ([`log_range_refusal_text`]).
pub const LOG_RANGE_REFUSAL_CODE: i64 = -32005;

const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// `blockNumberOf`: a `0x` hex string (any case, `0X` too) whose value is a
/// safe integer.
pub(crate) fn block_number_of(units: impl IntoIterator<Item = u16>) -> Option<u64> {
    let units: Vec<u16> = units.into_iter().collect();
    let digits = match units.as_slice() {
        [0x30, 0x78 | 0x58, digits @ ..] if !digits.is_empty() => digits,
        _ => return None,
    };
    let mut value: u64 = 0;
    for &unit in digits {
        let digit = char::from_u32(u32::from(unit))?.to_digit(16)?;
        value = value.checked_mul(16)?.checked_add(u64::from(digit))?;
        if value > MAX_SAFE_INTEGER {
            // Every further digit keeps it unsafe; the rest must still be
            // hex for the text to be one.
            return None;
        }
    }
    Some(value)
}

/// A string value's block number ([`block_number_of`]).
pub(crate) fn block_number_value(value: Option<Value<'_, '_>>) -> Option<u64> {
    value
        .filter(|value| value.kind() == Kind::String)
        .and_then(|value| block_number_of(value.units()))
}

/// `logQuerySpan`: the blocks an `eth_getLogs` filter covers, both ends
/// included, when `params[0]` has numeric `fromBlock` and `toBlock` (`to >=
/// from`). `None` for a tag, a missing end or another method: such a query
/// is never filtered or learned from.
pub fn log_query_span(method: &str, params: &str) -> Option<u64> {
    if method != "eth_getLogs" {
        return None;
    }
    let index = Index::new(params).ok()?;
    let Some(Element::Value(filter)) = element(index.root(), 0) else {
        return None;
    };
    let from = block_number_value(filter.get("fromBlock"))?;
    let to = block_number_value(filter.get("toBlock"))?;
    (to >= from).then(|| to - from + 1)
}

/// The range refusal's message, code [`LOG_RANGE_REFUSAL_CODE`]: the widest
/// span a quorum can still serve.
pub fn log_range_refusal_text(span: u64) -> String {
    format!("query exceeds max block range {span}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans() {
        let span = |params: &str| log_query_span("eth_getLogs", params);
        assert_eq!(span(r#"[{"fromBlock":"0x1","toBlock":"0X0a"}]"#), Some(10));
        assert_eq!(span(r#"[{"fromBlock":"0x2","toBlock":"0x1"}]"#), None);
        assert_eq!(span(r#"[{"fromBlock":"0x1","toBlock":"latest"}]"#), None);
        assert_eq!(
            span(r#"[{"fromBlock":"0x0","toBlock":"0x1fffffffffffff"}]"#),
            Some(1 << 53)
        );
        assert_eq!(
            span(r#"[{"fromBlock":"0x0","toBlock":"0x20000000000000"}]"#),
            None
        );
        assert_eq!(
            span(r#"{"0":{"fromBlock":"0x1","toBlock":"0x1"}}"#),
            Some(1)
        );
        assert_eq!(span("null"), None);
        assert_eq!(
            log_query_span("eth_call", r#"[{"fromBlock":"0x1","toBlock":"0x1"}]"#),
            None
        );
        assert_eq!(
            block_number_of("0x0000000000000000000001".encode_utf16()),
            Some(1)
        );
        assert_eq!(block_number_of("0x".encode_utf16()), None);
        assert_eq!(
            log_range_refusal_text(49_999),
            "query exceeds max block range 49999"
        );
    }
}
