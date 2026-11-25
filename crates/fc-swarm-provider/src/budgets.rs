//! The permission-free read budgets (`READ_BUDGETS`, swarm-provider-ipc.js):
//! per key, a window of 60 s with 600 requests and 5 MiB for a connected
//! site, 120 requests and 512 KiB otherwise. The swarm thread holds one
//! [`ReadBudgets`] for every request; the clock comes in as a parameter.
//!
//! - **`consume`** (`consumePermissionFreeReadBudget`) adds first and checks
//!   after, so what it adds stays charged when it refuses.
//! - **`reserve`** (`reservePermissionFreeReadBytes`) checks and adds in one
//!   step, or adds nothing.
//! - **The window** is the key's bucket while `now - startedAt` is under
//!   60 s, else a fresh one from `now`. Which budget applies is read at
//!   each call from the site's grant, as the reference reads it.
//!
//! A bucket whose window has passed is the same as none, so buckets past
//! their window are dropped once there are many: the map stays bounded by
//! the keys read from within one window.

use std::collections::BTreeMap;

use fc_json::JsString;

use crate::machine::Failure;
use crate::value::Value;

/// A read budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub window_ms: u64,
    pub max_requests: u64,
    pub max_bytes: u64,
}

/// `READ_BUDGETS.connected`.
pub const CONNECTED: Budget = Budget {
    window_ms: 60_000,
    max_requests: 600,
    max_bytes: 5 * 1024 * 1024,
};

/// `READ_BUDGETS.anonymous`.
pub const ANONYMOUS: Budget = Budget {
    window_ms: 60_000,
    max_requests: 120,
    max_bytes: 512 * 1024,
};

/// `getReadBudget(origin)`: the connected budget for a site with the
/// connection grant.
pub fn budget(connected: bool) -> &'static Budget {
    if connected { &CONNECTED } else { &ANONYMOUS }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bucket {
    started_at: u64,
    requests: u64,
    bytes: u64,
}

/// How many buckets the map holds before it drops those past their window.
const PRUNE_AT: usize = 1024;

/// Every key's bucket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadBudgets {
    buckets: BTreeMap<JsString, Bucket>,
}

impl ReadBudgets {
    pub fn new() -> Self {
        Self::default()
    }

    /// The key's bucket for this window, as the reference finds it: the
    /// one it has while `now - startedAt < windowMs`, else a fresh one. A
    /// clock set back keeps the bucket, as a negative difference does.
    fn current(&self, origin: &JsString, budget: &Budget, now: u64) -> Bucket {
        match self.buckets.get(origin) {
            Some(bucket) if now.saturating_sub(bucket.started_at) < budget.window_ms => *bucket,
            _ => Bucket {
                started_at: now,
                requests: 0,
                bytes: 0,
            },
        }
    }

    fn store(&mut self, origin: &JsString, bucket: Bucket, budget: &Budget, now: u64) {
        if self.buckets.len() >= PRUNE_AT && !self.buckets.contains_key(origin) {
            self.buckets
                .retain(|_, b| now.saturating_sub(b.started_at) < budget.window_ms);
        }
        self.buckets.insert(origin.clone(), bucket);
    }

    /// `consumePermissionFreeReadBudget(origin, { requests, bytes })`.
    pub fn consume(
        &mut self,
        origin: &JsString,
        connected: bool,
        now: u64,
        requests: u64,
        bytes: u64,
    ) -> Result<(), Failure> {
        let budget = budget(connected);
        let mut bucket = self.current(origin, budget, now);
        bucket.requests = bucket.requests.saturating_add(requests);
        bucket.bytes = bucket.bytes.saturating_add(bytes);
        self.store(origin, bucket, budget, now);
        if bucket.requests > budget.max_requests || bucket.bytes > budget.max_bytes {
            return Err(exceeded(budget));
        }
        Ok(())
    }

    /// `reservePermissionFreeReadBytes(origin, bytes)`.
    pub fn reserve(
        &mut self,
        origin: &JsString,
        connected: bool,
        now: u64,
        bytes: u64,
    ) -> Result<(), Failure> {
        let budget = budget(connected);
        let mut bucket = self.current(origin, budget, now);
        if bucket.bytes.saturating_add(bytes) > budget.max_bytes {
            return Err(exceeded(budget));
        }
        bucket.bytes += bytes;
        self.store(origin, bucket, budget, now);
        Ok(())
    }

    /// What is left of the key's bytes in this window. (It doesn't bound
    /// what a latest feed entry holds: the window can roll during the
    /// read.)
    pub fn room(&self, origin: &JsString, connected: bool, now: u64) -> u64 {
        let budget = budget(connected);
        budget
            .max_bytes
            .saturating_sub(self.current(origin, budget, now).bytes)
    }
}

/// `readBudgetExceeded(budget)`: -32602 `rate_limited` with the budget.
pub fn exceeded(budget: &Budget) -> Failure {
    Failure::invalid_params_with(
        "Permission-free read budget exceeded",
        "rate_limited",
        vec![
            ("windowMs", Value::int(budget.window_ms)),
            ("maxRequests", Value::int(budget.max_requests)),
            ("maxBytes", Value::int(budget.max_bytes)),
        ],
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn consume_charges_even_when_it_refuses() {
        let mut b = ReadBudgets::new();
        let key = JsString::from("https://a.example");
        for _ in 0..120 {
            b.consume(&key, false, 1000, 1, 0).unwrap();
        }
        assert!(b.consume(&key, false, 1000, 1, 0).is_err());
        // The refused request counted.
        assert_eq!(b.buckets[&key].requests, 121);
        // The window passes.
        assert!(b.consume(&key, false, 61_000, 1, 0).is_ok());
    }

    #[test]
    fn reserve_is_all_or_nothing() {
        let mut b = ReadBudgets::new();
        let key = JsString::from("k");
        b.reserve(&key, false, 0, 500_000).unwrap();
        assert!(b.reserve(&key, false, 0, 30_000).is_err());
        assert_eq!(b.room(&key, false, 0), 524_288 - 500_000);
        assert_eq!(b.room(&key, true, 0), 5 * 1024 * 1024 - 500_000);
    }

    #[test]
    fn a_clock_set_back_keeps_the_window() {
        let mut b = ReadBudgets::new();
        let key = JsString::from("k");
        b.consume(&key, false, 100_000, 0, 10).unwrap();
        b.consume(&key, false, 50_000, 0, 10).unwrap();
        assert_eq!(b.buckets[&key].bytes, 20);
    }
}
