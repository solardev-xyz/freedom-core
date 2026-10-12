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

/// What a JSON body can come to hold once parsed, per byte. The parser
/// shrinks each container and string to its length as it closes, so a
/// value holds its 32-byte slot and its own allocation (at least 32 bytes
/// as allocated): at worst a nested array, 2 bytes of input a level, holds
/// 24 bytes a byte. A test measures the shapes against it.
pub(crate) const PARSED_FACTOR: usize = 32;

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
