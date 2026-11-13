//! R-6's rate limit on what a standing rule answers without a prompt
//! (design 0012, "The rules"; the reference's
//! `radicle/auto-write-limiter.js`), and Q9's rate, which reuses it as it is
//! ("Limits on 'Always allow' (Q9)").
//!
//! Per key: a burst of [`RateLimits::burst`], refilled continuously at one per
//! [`RateLimits::refill_ms`], and at most [`RateLimits::daily_max`] in any
//! [`RateLimits::day_ms`]: a use counted at `t` stops counting at exactly
//! `t + day_ms`. On the vault's clock, which the caller passes as `now_ms`.
//! In memory: a restart starts every bucket full and empty, and
//! [`RateLimiter::forget`] (a disconnect, a revoked grant) drops a key's.
//!
//! Over the limit, the request is asked, not refused, and a request the user
//! approves at its prompt isn't counted: the caller counts only what a rule
//! answers ([`RateLimiter::admit`]).
//!
//! **Q9's buckets** are one per key and request class
//! ([`RequestClass`]): a site's signatures and its transactions apart, and
//! all its transaction rules sharing one.
//!
//! The refill is counted in doubles, as the reference counts it: the same
//! operations in the same order (`min(BURST, tokens + max(0, elapsed) /
//! REFILL_MS)`, then `tokens - 1` for a use), so that the core rounds where
//! the reference rounds and is never more permissive. Exact credit would
//! not be: two partial refills of 19,185 and 1,887 ms then one of 8,928 ms
//! add up to 30,000 ms, but their doubles to 0.9999999999999999 of a token,
//! and the reference refuses.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

/// The limiter's constants (the reference's `LIMITS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    pub burst: u64,
    pub refill_ms: u64,
    pub daily_max: usize,
    pub day_ms: u64,
}

/// R-6's: a burst of 5, one more per 30 s, at most 50 in any 24 hours.
pub const LIMITS: RateLimits = RateLimits {
    burst: 5,
    refill_ms: 30_000,
    daily_max: 50,
    day_ms: 24 * 60 * 60 * 1000,
};

/// Q9's two buckets for a site's dApp rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestClass {
    /// `personal_sign` and `eth_signTypedData_v4` under the signing rule.
    Signature,
    /// `eth_sendTransaction` under any of the site's transaction rules.
    Transaction,
}

#[derive(Debug, Clone)]
struct Bucket {
    /// Tokens, as the reference's double.
    tokens: f64,
    /// When `tokens` was last brought up to date.
    at: u64,
    /// When each use in the last `day_ms` was counted, oldest first.
    recent: VecDeque<u64>,
}

/// A limiter over keys of type `K`: a site's key for R-6, a site's key and
/// its [`RequestClass`] for Q9.
#[derive(Debug, Clone)]
pub struct RateLimiter<K> {
    limits: RateLimits,
    buckets: HashMap<K, Bucket>,
}

impl<K: Eq + Hash + Clone> Default for RateLimiter<K> {
    fn default() -> Self {
        RateLimiter::new(LIMITS)
    }
}

impl<K: Eq + Hash + Clone> RateLimiter<K> {
    pub fn new(limits: RateLimits) -> Self {
        RateLimiter {
            limits,
            buckets: HashMap::new(),
        }
    }

    /// The key's bucket brought up to `now_ms`, as the reference's
    /// `stateFor` does: refilled by the time since its last use (none if
    /// the clock ran back, and its time moves back with it), and its uses
    /// older than a day dropped.
    fn current(&self, key: &K, now_ms: u64) -> Bucket {
        // The vault's clock and the limits stay below 2^53, where the
        // reference's numbers hold them exactly: these conversions are
        // exact, and so is the elapsed time, as JS's `time - state.at`.
        let burst = self.limits.burst as f64;
        let mut bucket = self.buckets.get(key).cloned().unwrap_or(Bucket {
            tokens: burst,
            at: now_ms,
            recent: VecDeque::new(),
        });
        let elapsed = now_ms.saturating_sub(bucket.at) as f64;
        bucket.tokens = burst.min(bucket.tokens + elapsed / self.limits.refill_ms as f64);
        bucket.at = now_ms;
        while bucket.recent.front().is_some_and(|first| {
            now_ms
                .checked_sub(*first)
                .is_some_and(|age| age >= self.limits.day_ms)
        }) {
            bucket.recent.pop_front();
        }
        bucket
    }

    fn allows(&self, bucket: &Bucket) -> bool {
        bucket.tokens >= 1.0 && bucket.recent.len() < self.limits.daily_max
    }

    /// Counts one use for `key` if the limit allows it (the reference's
    /// `admit`): whether the rule may answer without a prompt.
    pub fn admit(&mut self, key: &K, now_ms: u64) -> bool {
        let mut bucket = self.current(key, now_ms);
        let allowed = self.allows(&bucket);
        if allowed {
            bucket.tokens -= 1.0;
            bucket.recent.push_back(now_ms);
        }
        self.buckets.insert(key.clone(), bucket);
        allowed
    }

    /// Whether [`RateLimiter::admit`] would allow a use now, without
    /// counting one: advice, for the choice between a prompt and none
    /// (`approval.check`).
    pub fn would_admit(&self, key: &K, now_ms: u64) -> bool {
        self.allows(&self.current(key, now_ms))
    }

    /// Forgets the key's bucket (a disconnect, a revoked grant): whether it
    /// had one.
    pub fn forget(&mut self, key: &K) -> bool {
        self.buckets.remove(key).is_some()
    }

    /// Forgets every bucket `drop` names, as a revoked site's buckets of
    /// both classes.
    pub fn forget_where(&mut self, mut drop: impl FnMut(&K) -> bool) {
        self.buckets.retain(|key, _| !drop(key));
    }

    /// Forgets every bucket (the reference's `reset`).
    pub fn reset(&mut self) {
        self.buckets.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 5_000_000;

    #[test]
    fn q9_buckets_keep_signatures_and_transactions_apart() {
        let mut limiter: RateLimiter<(String, RequestClass)> = RateLimiter::default();
        let site = |class| ("https://app.example".to_owned(), class);
        for _ in 0..5 {
            assert!(limiter.admit(&site(RequestClass::Transaction), T0));
        }
        assert!(!limiter.admit(&site(RequestClass::Transaction), T0));
        assert!(limiter.would_admit(&site(RequestClass::Signature), T0));
        assert!(limiter.admit(&site(RequestClass::Signature), T0));
        // A revoked grant forgets both.
        limiter.forget_where(|(key, _)| key == "https://app.example");
        assert!(limiter.would_admit(&site(RequestClass::Transaction), T0));
    }

    #[test]
    fn refills_round_as_the_references_doubles() {
        // 19,185 + 1,887 + 8,928 ms is 30 s, but the doubles add up to
        // 0.9999999999999999 of a token: refused, as the reference refuses.
        let mut limiter: RateLimiter<&str> = RateLimiter::default();
        for _ in 0..5 {
            assert!(limiter.admit(&"a", T0));
        }
        assert!(!limiter.admit(&"a", T0 + 19_185));
        assert!(!limiter.admit(&"a", T0 + 21_072));
        assert!(!limiter.would_admit(&"a", T0 + 30_000));
        assert!(!limiter.admit(&"a", T0 + 30_000));
        assert!(limiter.admit(&"a", T0 + 30_001));
    }

    #[test]
    fn advice_counts_nothing() {
        let mut limiter: RateLimiter<&str> = RateLimiter::default();
        for _ in 0..10 {
            assert!(limiter.would_admit(&"a", T0));
        }
        for _ in 0..5 {
            assert!(limiter.admit(&"a", T0));
        }
        assert!(!limiter.would_admit(&"a", T0));
        assert!(limiter.would_admit(&"a", T0 + 30_000));
        assert!(!limiter.would_admit(&"a", T0 + 29_999));
    }
}
