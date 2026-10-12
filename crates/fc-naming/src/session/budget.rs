//! Deviation `memory-budgets` (design 0004, Bounds: Memory): what each
//! session and all of them together may hold.
//!
//! A session is charged, until it ends, for its requests, its answers, its
//! aliasing decodes' output and its replies. Everything a session retains
//! derives from those, and a decode that can't alias never outgrows its
//! input, so the charge bounds what it holds without tracking each value.

use std::collections::{BTreeMap, BTreeSet};

use super::bounds::Bounds;

#[derive(Debug, Default)]
pub(crate) struct Budget {
    used: BTreeMap<u64, usize>,
    total: usize,
    over: BTreeSet<u64>,
    /// Set when a charge crosses the total; new sessions are busy until
    /// the total falls under `resume_bytes`.
    saturated: bool,
}

impl Budget {
    /// Charges `bytes` to `session`. False, and the session is over, when
    /// its own bound or the total's is crossed.
    pub(crate) fn charge(&mut self, session: u64, bytes: usize, bounds: &Bounds) -> bool {
        let used = self.used.entry(session).or_default();
        *used = used.saturating_add(bytes);
        let own = *used > bounds.session_bytes;
        self.total = self.total.saturating_add(bytes);
        let all = self.total > bounds.total_bytes;
        self.saturated |= all;
        if own || all {
            self.over.insert(session);
        }
        !(own || all)
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
        if self.saturated && self.total < bounds.resume_bytes {
            self.saturated = false;
        }
        self.saturated
    }

    pub(crate) fn total(&self) -> usize {
        self.total
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
