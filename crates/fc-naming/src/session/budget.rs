//! Deviation `memory-budgets` (design 0004, Bounds: Memory): what each
//! session and all of them together may hold.
//!
//! A session is charged, until it ends, for its name, its requests, its
//! answers, its aliasing decodes' output and its replies. Everything a
//! session retains derives from those, and a decode that can't alias never
//! outgrows its input, so the charge bounds what it holds without tracking
//! each value. Replies stay counted in the total after their session ends,
//! until the driver has written them.

use std::collections::{BTreeMap, BTreeSet};

use super::bounds::Bounds;

/// What a JSON body can come to hold once parsed, per byte, when its shape
/// is unknown. The parser shrinks each container and string to its length
/// as it closes, so a value holds its 32-byte slot and its own allocation
/// (at least 32 bytes as allocated): at worst a nested array, 2 bytes of
/// input a level, holds 24 bytes a byte. A test measures the shapes
/// against it. Answers are charged by [`parsed_bound`] instead, which
/// counts their values.
pub(crate) const PARSED_FACTOR: usize = 32;

/// What one JSON value or key can hold once parsed, besides its string
/// bytes: an object member's slot (a key and a value, 56 bytes, the
/// largest slot) and its own allocation (at least 32 bytes as allocated).
pub(crate) const VALUE_BYTES: usize = 88;

/// What a string's lone surrogates can hold besides its text, per escaped
/// surrogate (`\uD800` to `\uDFFF`) in the input. A string keeps them in a
/// boxed list (32 bytes as allocated) of 8-byte entries that grows by
/// doubling from 4 (48 bytes as allocated), so `k` of them in one string
/// hold at most max(80, 48 + 16k) bytes: 80 each at most.
pub(crate) const SURROGATE_BYTES: usize = 80;

/// What a JSON text can come to hold once parsed: its string bytes (at
/// most its length), [`VALUE_BYTES`] for each value and key, counted by a
/// pass that allocates nothing (#73), and [`SURROGATE_BYTES`] for each
/// escaped surrogate. A text that isn't JSON is parsed only up to its
/// error, at most a value per two bytes. A block of 1,000 transaction
/// hashes (about 69 KB) is so bounded at about 160 KB; with its body, the
/// answer is charged about 230 KB, where the flat factor charged 2.2 MB.
pub(crate) fn parsed_bound(text: &str) -> usize {
    let values = crate::jsjson::index::Index::values_in(text).unwrap_or(text.len().div_ceil(2));
    text.len()
        .saturating_add(values.saturating_mul(VALUE_BYTES))
        .saturating_add(surrogate_escapes(text).saturating_mul(SURROGATE_BYTES))
}

/// The escaped surrogates in a JSON text, each a lone one at worst. An
/// escaped backslash before `ud800` counts too, which only overcounts.
fn surrogate_escapes(text: &str) -> usize {
    text.as_bytes()
        .windows(4)
        .filter(|w| {
            w[0] == b'\\'
                && w[1] == b'u'
                && matches!(w[2], b'd' | b'D')
                && matches!(w[3], b'8' | b'9' | b'a'..=b'f' | b'A'..=b'F')
        })
        .count()
}

/// The copies a session keeps of its name and key (its in-flight key, its
/// subject, the cache key, each attempt's captures), per byte.
pub(crate) const INPUT_COPIES: usize = 8;

#[derive(Debug, Default)]
pub(crate) struct Budget {
    used: BTreeMap<u64, usize>,
    total: usize,
    over: BTreeSet<u64>,
    /// Set when a charge crosses the total; new sessions are busy until
    /// the total falls under `resume_bytes`.
    saturated: bool,
    /// Replies made and not yet taken by the driver.
    output: usize,
    /// Replies the driver has taken and not yet written (its backlog).
    backlog: usize,
}

impl Budget {
    /// Charges `bytes` to `session`. False, and the session is over, when
    /// its own bound or the total's is crossed.
    pub(crate) fn charge(&mut self, session: u64, bytes: usize, bounds: &Bounds) -> bool {
        let used = self.used.entry(session).or_default();
        *used = used.saturating_add(bytes);
        let own = *used > bounds.session_bytes;
        self.total = self.total.saturating_add(bytes);
        let all = self.held() > bounds.total_bytes;
        self.saturated |= all;
        if own || all {
            self.over.insert(session);
        }
        !(own || all)
    }

    /// Whether a new session charged `bytes` could start: within its own
    /// bound and the total's, and the total not saturated.
    pub(crate) fn admits(&mut self, bytes: usize, bounds: &Bounds) -> bool {
        bytes <= bounds.session_bytes
            && self.held().saturating_add(bytes) <= bounds.total_bytes
            && !self.saturated(bounds)
    }

    /// Takes back `bytes` charged to `session`, for what it no longer holds.
    pub(crate) fn uncharge(&mut self, session: u64, bytes: usize) {
        if let Some(used) = self.used.get_mut(&session) {
            let freed = bytes.min(*used);
            *used -= freed;
            self.total = self.total.saturating_sub(freed);
        }
    }

    pub(crate) fn over(&self, session: u64) -> bool {
        self.over.contains(&session)
    }

    /// A session has ended: what it held is free.
    pub(crate) fn release(&mut self, session: u64) {
        if let Some(used) = self.used.remove(&session) {
            self.total = self.total.saturating_sub(used);
        }
        self.over.remove(&session);
    }

    /// Whether a new session is refused.
    pub(crate) fn saturated(&mut self, bounds: &Bounds) -> bool {
        if self.saturated && self.held() < bounds.resume_bytes {
            self.saturated = false;
        }
        self.saturated
    }

    pub(crate) fn total(&self) -> usize {
        self.total
    }

    /// Everything the total counts: the sessions' charges, and the replies
    /// that have left them until they are written. A finished session's
    /// replies so stay counted, and a session finishing after it can't
    /// reuse their room (`memory-budgets`).
    pub(crate) fn held(&self) -> usize {
        self.total
            .saturating_add(self.output)
            .saturating_add(self.backlog)
    }

    /// A reply has been made.
    pub(crate) fn add_output(&mut self, bytes: usize) {
        self.output = self.output.saturating_add(bytes);
    }

    /// The driver has taken the replies made: its backlog counts them now.
    pub(crate) fn take_output(&mut self) {
        self.output = 0;
    }

    /// The driver's replies not yet written.
    pub(crate) fn set_backlog(&mut self, bytes: usize) {
        self.backlog = bytes;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds() -> Bounds {
        Bounds {
            session_bytes: 100,
            total_bytes: 150,
            resume_bytes: 120,
            ..Bounds::default()
        }
    }

    #[test]
    fn a_parsed_value_fits_its_factor() {
        assert_eq!(std::mem::size_of::<crate::jsjson::JsValue>(), 32);
        let nested = |depth: usize| format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let many = |item: &str, n: usize| format!("[{}]", vec![item; n].join(","));
        let shapes = [
            // Review round 2's shape: singleton chains in an ignored field.
            format!(r#"{{"code":[],"extra":{}}}"#, many(&nested(100), 150)),
            nested(500),
            many("[]", 5_000),
            many("{}", 5_000),
            many("0", 5_000),
            many(r#""""#, 5_000),
            many(r#""a""#, 5_000),
            many("[0]", 5_000),
            many(r#"{"":0}"#, 5_000),
            many(r#"{"":[]}"#, 5_000),
            many(r#"{"a":"b"}"#, 5_000),
            format!("{}0{}", r#"{"":"#.repeat(500), "}".repeat(500)),
            format!(r#""{}""#, "x".repeat(10_000)),
            format!(r#""{}""#, "é".repeat(5_000)),
        ];
        for text in &shapes {
            let value = crate::jsjson::parse(text).unwrap();
            // Its own slot, wherever it is kept.
            let holds = value.held() + 32;
            assert!(
                holds <= PARSED_FACTOR * text.len(),
                "{} bytes hold {holds}: {}",
                text.len(),
                text.chars().take(40).collect::<String>()
            );
        }
    }

    /// What a parsed answer holds stays within the bound its values give,
    /// for every shape, and a typical answer's bound is far below the flat
    /// factor's.
    #[test]
    fn a_parsed_value_fits_its_bound() {
        let nested = |depth: usize| format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let many = |item: &str, n: usize| format!("[{}]", vec![item; n].join(","));
        let hashes = many(&format!(r#""0x{}""#, "ab".repeat(32)), 1_000);
        let shapes = [
            format!(r#"{{"code":[],"extra":{}}}"#, many(&nested(100), 150)),
            nested(500),
            many("[]", 5_000),
            many("{}", 5_000),
            many("0", 5_000),
            many(r#""""#, 5_000),
            many(r#""a""#, 5_000),
            many("[0]", 5_000),
            many(r#"{"":0}"#, 5_000),
            many(r#"{"":[]}"#, 5_000),
            many(r#"{"a":"b"}"#, 5_000),
            format!("{}0{}", r#"{"":"#.repeat(500), "}".repeat(500)),
            format!(r#""{}""#, "x".repeat(10_000)),
            format!(r#""{}""#, "é".repeat(5_000)),
            // Lone surrogates, which a string keeps in a list of its own
            // (#95): one string of them, a string each, keys too, and
            // escaped pairs, which are no lone ones.
            format!(r#""{}""#, r"\ud800".repeat(5_000)),
            format!(r#""{}""#, r"a\uDFFF".repeat(3_000)),
            many(r#""\ud800""#, 5_000),
            many(r#"{"\udc00":"\udbff"}"#, 5_000),
            many(r#""\ud83d\ude00""#, 5_000),
            format!(
                r#"{{"jsonrpc":"2.0","id":1,"result":{{"hash":"0x","transactions":{hashes}}}}}"#
            ),
        ];
        for text in &shapes {
            let value = crate::jsjson::parse(text).unwrap();
            let holds = value.held() + 32;
            assert!(
                holds <= parsed_bound(text),
                "{} bytes hold {holds}, bound {}: {}",
                text.len(),
                parsed_bound(text),
                text.chars().take(40).collect::<String>()
            );
        }
        let block = &shapes[shapes.len() - 1];
        assert!(
            parsed_bound(block) < 3 * block.len(),
            "{}",
            parsed_bound(block)
        );
        // Not JSON: at most a value per two bytes of what was parsed.
        assert_eq!(parsed_bound("[[[[x"), 5 + 3 * VALUE_BYTES);
        // Each escaped surrogate is a lone one at worst, in either case.
        assert_eq!(
            parsed_bound(r#"["\ud800","\uDC00x"]"#),
            20 + 3 * VALUE_BYTES + 2 * SURROGATE_BYTES
        );
        // A value or a key each, as the counting pass and the harness count.
        assert_eq!(
            crate::jsjson::index::Index::values_in(r#"{"a":[1,"x"],"b":{}}"#),
            Ok(7)
        );
    }

    #[test]
    fn replies_count_in_the_total_until_written() {
        let mut budget = Budget::default();
        budget.add_output(100);
        // A session can't use the room a finished session's replies hold.
        assert!(!budget.admits(60, &bounds()));
        assert!(budget.admits(50, &bounds()));
        assert!(!budget.charge(1, 51, &bounds()));
        budget.release(1);
        // Taken by the driver, they are its backlog until written.
        budget.take_output();
        budget.set_backlog(150);
        assert!(!budget.admits(1, &bounds()));
        assert!(!budget.charge(2, 1, &bounds()));
        assert!(budget.saturated(&bounds()));
        budget.release(2);
        // Written, the room is back.
        budget.set_backlog(10);
        assert!(!budget.saturated(&bounds()));
        assert!(budget.admits(100, &bounds()));
    }

    #[test]
    fn a_session_crosses_its_own_bound() {
        let mut budget = Budget::default();
        assert!(budget.charge(1, 100, &bounds()));
        assert!(!budget.over(1));
        assert!(!budget.charge(1, 1, &bounds()));
        assert!(budget.over(1));
        assert!(!budget.saturated(&bounds()));
        budget.release(1);
        assert!(!budget.over(1));
        assert_eq!(budget.total(), 0);
    }

    #[test]
    fn crossing_the_total_fails_the_charger_and_refuses_new_sessions_until_it_drops() {
        let mut budget = Budget::default();
        assert!(budget.charge(1, 80, &bounds()));
        assert!(!budget.charge(2, 80, &bounds()));
        assert!(budget.over(2) && !budget.over(1));
        assert!(budget.saturated(&bounds()));
        budget.release(2);
        // 80 is under 120: new sessions are admitted again.
        assert!(!budget.saturated(&bounds()));
        // Saturation holds until the total is under the resume mark.
        assert!(!budget.charge(3, 75, &bounds()));
        budget.release(3);
        assert!(budget.charge(4, 45, &bounds()));
        assert_eq!(budget.total(), 125);
        assert!(budget.saturated(&bounds()));
        budget.release(4);
        assert!(!budget.saturated(&bounds()));
    }
}
