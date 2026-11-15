//! `eip1193.request`'s deadline class (design 0012, "Deadlines"; APR-5b,
//! *inferred* in part).
//!
//! - **No overall deadline while one of its own `approval.request`s is
//!   open:** a prompt has none (0011), so its clock stops while main shows
//!   one.
//! - **Outside them,** a request has a session's 120 s in all
//!   ([`OVERALL_MS`]), the bound main's hang watchdog counts (0001: the
//!   deadline plus 15 s, skipped while main answers one of its prompts).
//! - **Each I/O step keeps its own deadline** (a chain read's, design
//!   0005), within what is left of those 120 s.
//!
//! Times are the caller's monotonic milliseconds.

/// What a request has in all outside its prompts: a session's 120 s.
pub const OVERALL_MS: u64 = 120_000;

/// One request's time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// What was left when its clock last started or stopped.
    left: u64,
    /// When its clock last started; `None` while a prompt is open.
    running_since: Option<u64>,
    /// Its prompts open now.
    prompts: u32,
}

impl Budget {
    /// A request that arrived at `now`.
    pub fn new(now: u64) -> Budget {
        Budget {
            left: OVERALL_MS,
            running_since: Some(now),
            prompts: 0,
        }
    }

    /// What is left at `now`.
    pub fn left(&self, now: u64) -> u64 {
        match self.running_since {
            Some(since) => self.left.saturating_sub(now.saturating_sub(since)),
            None => self.left,
        }
    }

    /// A step's deadline from `now`: its own (`own_ms`), within what is
    /// left.
    pub fn step(&self, now: u64, own_ms: u64) -> u64 {
        own_ms.min(self.left(now))
    }

    /// One of its `approval.request`s opened at `now`: the clock stops.
    pub fn prompt_opened(&mut self, now: u64) {
        self.left = self.left(now);
        self.running_since = None;
        self.prompts = self.prompts.saturating_add(1);
    }

    /// One of them was answered at `now`: with none left open, the clock
    /// runs again.
    pub fn prompt_closed(&mut self, now: u64) {
        self.prompts = self.prompts.saturating_sub(1);
        if self.prompts == 0 && self.running_since.is_none() {
            self.running_since = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_keep_their_own_deadline_within_what_is_left() {
        let budget = Budget::new(1_000);
        assert_eq!(budget.step(1_000, 120_000), 120_000);
        assert_eq!(budget.step(1_000, 5_000), 5_000);
        assert_eq!(budget.step(101_000, 120_000), 20_000);
        assert_eq!(budget.step(121_000, 120_000), 0);
        assert_eq!(budget.step(500_000, 120_000), 0);
    }

    #[test]
    fn no_overall_deadline_while_a_prompt_is_open() {
        let mut budget = Budget::new(0);
        budget.prompt_opened(30_000);
        budget.prompt_opened(40_000);
        // An hour at the prompts costs nothing.
        assert_eq!(budget.left(3_600_000), 90_000);
        budget.prompt_closed(3_600_000);
        assert_eq!(budget.left(3_700_000), 90_000, "one is still open");
        budget.prompt_closed(3_700_000);
        assert_eq!(budget.left(3_710_000), 80_000);
        assert_eq!(budget.step(3_710_000, 120_000), 80_000);
        // A close with none open changes nothing.
        budget.prompt_closed(3_710_000);
        assert_eq!(budget.left(3_720_000), 70_000);
    }
}
