//! Unlock throttling (K-4): one counter shared by every password check
//! (unlock, verify, change_password, delete, both exports).
//!
//! - The first [`FREE_FAILURES`] failures cost nothing.
//! - After that, an attempt must wait `2^(n - FREE_FAILURES)` seconds since
//!   the last failure, capped at [`MAX_DELAY_MS`], where `n` counts failures.
//! - A success resets the counter.
//! - An attempt is reserved before its KDF starts and counts as a failure
//!   until settled, so concurrent guesses can't all pass the check at once.
//!
//! Time is a caller-supplied monotonic millisecond counter.

/// Failures allowed before any delay.
pub const FREE_FAILURES: u32 = 5;
/// The longest delay between attempts: 5 minutes.
pub const MAX_DELAY_MS: u64 = 5 * 60 * 1000;

/// The throttle state.
#[derive(Debug, Default, Clone)]
pub struct Throttle {
    failures: u32,
    last_failure_ms: u64,
    in_flight: u32,
}

/// A reserved attempt. Settle it with [`Throttle::settle`]; dropping it
/// without settling leaves it counted as in flight.
#[derive(Debug)]
#[must_use = "settle the attempt with Throttle::settle"]
pub struct Attempt(());

/// The caller must wait before trying again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Throttled {
    pub retry_after_ms: u64,
}

/// How a reserved attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The password was correct.
    Success,
    /// The password was wrong.
    Failure,
    /// The attempt never checked a password (cancelled before its KDF ran).
    NotTried,
}

impl Throttle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserves an attempt, or says how long to wait.
    pub fn reserve(&mut self, now_ms: u64) -> Result<Attempt, Throttled> {
        let pending = self.failures.saturating_add(self.in_flight);
        if pending >= FREE_FAILURES {
            if self.in_flight > 0 {
                // One attempt at a time once delays apply.
                return Err(Throttled {
                    retry_after_ms: delay_ms(pending.saturating_add(1)),
                });
            }
            let ready_at = self.last_failure_ms.saturating_add(delay_ms(self.failures));
            if now_ms < ready_at {
                return Err(Throttled {
                    retry_after_ms: ready_at - now_ms,
                });
            }
        }
        self.in_flight += 1;
        Ok(Attempt(()))
    }

    /// Settles a reserved attempt.
    pub fn settle(&mut self, attempt: Attempt, outcome: Outcome, now_ms: u64) {
        let Attempt(()) = attempt;
        self.in_flight = self.in_flight.saturating_sub(1);
        match outcome {
            Outcome::Success => self.failures = 0,
            Outcome::Failure => {
                self.failures = self.failures.saturating_add(1);
                self.last_failure_ms = now_ms;
            }
            Outcome::NotTried => {}
        }
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }
}

/// The wait after `failures` failures.
fn delay_ms(failures: u32) -> u64 {
    if failures < FREE_FAILURES {
        return 0;
    }
    let exponent = failures - FREE_FAILURES;
    if exponent >= 20 {
        return MAX_DELAY_MS;
    }
    (1000u64 << exponent).min(MAX_DELAY_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fail(throttle: &mut Throttle, now: u64) {
        let attempt = throttle.reserve(now).unwrap();
        throttle.settle(attempt, Outcome::Failure, now);
    }

    #[test]
    fn five_free_failures_then_exponential_delay() {
        let mut t = Throttle::new();
        for i in 0..5 {
            fail(&mut t, i);
        }
        // 5 failures: wait 1 s after the last one (at t=4).
        assert_eq!(
            t.reserve(4).unwrap_err(),
            Throttled {
                retry_after_ms: 1000
            }
        );
        assert_eq!(
            t.reserve(1003).unwrap_err(),
            Throttled { retry_after_ms: 1 }
        );
        fail(&mut t, 1004);
        // 6 failures: 2 s.
        assert_eq!(
            t.reserve(1004).unwrap_err(),
            Throttled {
                retry_after_ms: 2000
            }
        );
        fail(&mut t, 3004);
        assert_eq!(
            t.reserve(3004).unwrap_err(),
            Throttled {
                retry_after_ms: 4000
            }
        );
    }

    #[test]
    fn delay_caps_at_five_minutes() {
        assert_eq!(delay_ms(4), 0);
        assert_eq!(delay_ms(5), 1000);
        assert_eq!(delay_ms(13), 256_000);
        assert_eq!(delay_ms(14), MAX_DELAY_MS);
        assert_eq!(delay_ms(u32::MAX), MAX_DELAY_MS);
    }

    #[test]
    fn success_resets() {
        let mut t = Throttle::new();
        for i in 0..7 {
            let attempt = t.reserve(i * 100_000).unwrap();
            t.settle(attempt, Outcome::Failure, i * 100_000);
        }
        let attempt = t.reserve(10_000_000).unwrap();
        t.settle(attempt, Outcome::Success, 10_000_000);
        assert_eq!(t.failures(), 0);
        assert!(t.reserve(10_000_000).is_ok());
    }

    #[test]
    fn concurrent_guesses_cannot_all_pass() {
        let mut t = Throttle::new();
        for i in 0..4 {
            fail(&mut t, i);
        }
        // One free slot left: the first concurrent attempt gets it, the
        // second must wait even though neither has finished.
        let first = t.reserve(10).unwrap();
        assert!(t.reserve(10).is_err());
        t.settle(first, Outcome::NotTried, 10);
        assert!(t.reserve(10).is_ok());
    }
}
