//! Unlock throttling (K-4): one counter shared by every password check
//! (unlock, verify, change_password, delete, both exports).
//!
//! - The first [`FREE_FAILURES`] failures cost nothing.
//! - After that, an attempt must wait `2^(n - FREE_FAILURES)` seconds since
//!   the last failure, capped at [`MAX_DELAY_MS`], where `n` counts failures.
//! - A success resets the counter.
//! - An attempt is reserved before its KDF starts and counts as a failure
//!   until settled, so concurrent guesses can't all pass the check at once.
//! - A reservation that is never settled (its owner dropped it, crashed, or
//!   lost track of it) expires after [`RESERVATION_TTL_MS`] and is counted as
//!   a failure. That fails safe and keeps the throttle usable.
//!
//! Time is a caller-supplied monotonic millisecond counter. A timestamp
//! older than one already seen is treated as the newest seen.

/// Failures allowed before any delay.
pub const FREE_FAILURES: u32 = 5;
/// The longest delay between attempts: 5 minutes.
pub const MAX_DELAY_MS: u64 = 5 * 60 * 1000;
/// How long a reservation may stay unsettled: far longer than any KDF
/// (900k PBKDF2 rounds take about a second).
pub const RESERVATION_TTL_MS: u64 = 2 * 60 * 1000;

/// The throttle state.
#[derive(Debug, Default, Clone)]
pub struct Throttle {
    failures: u32,
    last_failure_ms: u64,
    /// The latest time seen, so time never runs backwards here.
    now_ms: u64,
    next_id: u64,
    /// Reservations in flight: (id, reserved at). At most FREE_FAILURES.
    in_flight: Vec<(u64, u64)>,
}

/// A reserved attempt. Settle it with [`Throttle::settle`]; if it's dropped
/// instead, it expires after [`RESERVATION_TTL_MS`] as a failure.
#[derive(Debug)]
#[must_use = "settle the attempt with Throttle::settle"]
pub struct Attempt {
    id: u64,
}

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
    /// The password was wrong, or the KDF ran and its result was discarded
    /// (cancelled or revoked after it started).
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
        let now_ms = self.observe(now_ms);
        self.expire(now_ms);
        let in_flight = u32::try_from(self.in_flight.len()).unwrap_or(u32::MAX);
        let pending = self.failures.saturating_add(in_flight);
        if pending >= FREE_FAILURES {
            if let Some(oldest) = self.in_flight.iter().map(|(_, at)| *at).min() {
                // One attempt at a time once delays apply; the slot frees when
                // the attempt settles, or when it expires at the latest.
                let expires = oldest.saturating_add(RESERVATION_TTL_MS);
                return Err(Throttled {
                    retry_after_ms: delay_ms(pending).min(expires.saturating_sub(now_ms)).max(1),
                });
            }
            let ready_at = self.last_failure_ms.saturating_add(delay_ms(self.failures));
            if now_ms < ready_at {
                return Err(Throttled {
                    retry_after_ms: ready_at - now_ms,
                });
            }
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.in_flight.push((id, now_ms));
        Ok(Attempt { id })
    }

    /// Settles a reserved attempt. Settling an attempt that already expired
    /// (and was counted as a failure) only applies a success's reset.
    pub fn settle(&mut self, attempt: Attempt, outcome: Outcome, now_ms: u64) {
        let now_ms = self.observe(now_ms);
        let position = self.in_flight.iter().position(|(id, _)| *id == attempt.id);
        if let Some(position) = position {
            self.in_flight.swap_remove(position);
        }
        match outcome {
            Outcome::Success => self.failures = 0,
            Outcome::Failure if position.is_some() => self.fail(now_ms),
            Outcome::Failure | Outcome::NotTried => {}
        }
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    fn observe(&mut self, now_ms: u64) -> u64 {
        self.now_ms = self.now_ms.max(now_ms);
        self.now_ms
    }

    fn fail(&mut self, now_ms: u64) {
        self.failures = self.failures.saturating_add(1);
        self.last_failure_ms = self.last_failure_ms.max(now_ms);
    }

    /// Counts reservations older than the TTL as failures.
    fn expire(&mut self, now_ms: u64) {
        let before = self.in_flight.len();
        self.in_flight
            .retain(|(_, at)| now_ms.saturating_sub(*at) < RESERVATION_TTL_MS);
        for _ in self.in_flight.len()..before {
            self.fail(now_ms);
        }
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
            fail(&mut t, i * 100_000);
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
        let first = t.reserve(10).unwrap();
        assert!(t.reserve(10).is_err());
        t.settle(first, Outcome::NotTried, 10);
        assert!(t.reserve(10).is_ok());
    }

    #[test]
    fn a_dropped_attempt_expires_as_a_failure() {
        // PR #6 review, M2: a dropped reservation must not jam the throttle.
        let mut t = Throttle::new();
        drop(t.reserve(0).unwrap());
        for i in 1..5 {
            fail(&mut t, i);
        }
        assert!(t.reserve(10).is_err(), "the dropped attempt still counts");
        let later = RESERVATION_TTL_MS + 10;
        // Expired: counted as the fifth failure, so a 1 s delay applies from
        // the expiry, and then attempts work again.
        assert!(t.reserve(later).is_err());
        assert_eq!(t.failures(), 5);
        assert!(t.reserve(later + 1000).is_ok());
    }

    #[test]
    fn settling_an_expired_attempt_does_not_double_count() {
        let mut t = Throttle::new();
        let attempt = t.reserve(0).unwrap();
        let _ = t.reserve(RESERVATION_TTL_MS);
        assert_eq!(t.failures(), 1);
        t.settle(attempt, Outcome::Failure, RESERVATION_TTL_MS);
        assert_eq!(t.failures(), 1);
    }

    #[test]
    fn time_never_runs_backwards() {
        // PR #6 review, m2: an older completion time must not move the
        // deadline back.
        let mut t = Throttle::new();
        let attempts: Vec<_> = (0..5).map(|_| t.reserve(100_000).unwrap()).collect();
        for (i, attempt) in attempts.into_iter().enumerate() {
            let at = if i == 4 { 0 } else { 100_000 };
            t.settle(attempt, Outcome::Failure, at);
        }
        assert_eq!(
            t.reserve(1000).unwrap_err(),
            Throttled {
                retry_after_ms: 1000
            }
        );
    }
}
