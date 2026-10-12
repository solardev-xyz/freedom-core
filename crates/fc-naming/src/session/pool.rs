//! The quorum's provider pool: a shuffled order and per-endpoint quarantine
//! (`getShuffledPublicProviders`, `isQuarantined`, `markProviderFailure`,
//! `markProviderSuccess`).

use std::collections::HashMap;

use super::exec::Ms;
use super::random::{Random, index_below};

/// An opaque endpoint reference (design 0004, Configuration).
pub type Endpoint = String;

const QUARANTINE_BASE_MS: Ms = 60_000;
const QUARANTINE_MAX_MS: Ms = 600_000;

#[derive(Debug, Clone, Copy)]
struct Entry {
    failures: u32,
    until: Ms,
}

#[derive(Debug, Default)]
pub struct Pool {
    /// The shuffled order and the list it was shuffled from.
    shuffled: Option<(Vec<Endpoint>, Vec<Endpoint>)>,
    quarantine: HashMap<Endpoint, Entry>,
}

impl Pool {
    /// The shuffled order, recomputed only when `effective` changes.
    pub fn shuffled(&mut self, effective: &[Endpoint], random: &mut dyn Random) -> Vec<Endpoint> {
        if let Some((source, order)) = &self.shuffled
            && source.as_slice() == effective
        {
            return order.clone();
        }
        let mut order = effective.to_vec();
        // Fisher–Yates from the last index down, as `shuffleInPlace`.
        for i in (1..order.len()).rev() {
            let j = index_below(random, i + 1);
            order.swap(i, j);
        }
        self.shuffled = Some((effective.to_vec(), order.clone()));
        order
    }

    /// Whether `endpoint` sits in quarantine. An expired entry is deleted,
    /// so its failure count starts again.
    pub fn is_quarantined(&mut self, endpoint: &str, now: Ms) -> bool {
        match self.quarantine.get(endpoint) {
            None => false,
            Some(entry) if now >= entry.until => {
                self.quarantine.remove(endpoint);
                false
            }
            Some(_) => true,
        }
    }

    pub fn mark_failure(&mut self, endpoint: &str, now: Ms) {
        let entry = self.quarantine.entry(endpoint.to_owned()).or_insert(Entry {
            failures: 0,
            until: 0,
        });
        entry.failures = entry.failures.saturating_add(1);
        let doubling = 1u64.checked_shl(entry.failures - 1).unwrap_or(u64::MAX);
        let cooldown = QUARANTINE_BASE_MS
            .saturating_mul(doubling)
            .min(QUARANTINE_MAX_MS);
        entry.until = now.saturating_add(cooldown);
    }

    pub fn mark_success(&mut self, endpoint: &str) {
        self.quarantine.remove(endpoint);
    }

    /// Drops a retired endpoint's state (deviation `endpoint-retention`).
    pub fn forget(&mut self, endpoint: &str) {
        self.quarantine.remove(endpoint);
    }

    /// The shuffled order without quarantined endpoints
    /// (`getAvailableProviders`).
    pub fn available(
        &mut self,
        effective: &[Endpoint],
        random: &mut dyn Random,
        now: Ms,
    ) -> Vec<Endpoint> {
        let order = self.shuffled(effective, random);
        order
            .into_iter()
            .filter(|e| !self.is_quarantined(e, now))
            .collect()
    }

    /// Today's `invalidateProviderPool`, without the anchor (which the
    /// machine owns).
    pub fn reset(&mut self) {
        self.shuffled = None;
        self.quarantine.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::random::Mulberry32;

    fn endpoints(names: &[&str]) -> Vec<Endpoint> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn the_shuffle_is_the_references_for_its_seed() {
        // `quorum-agree`: seed 7 over a..d probes c, b, d, a.
        let mut random = Mulberry32::new(7);
        let mut pool = Pool::default();
        let effective = endpoints(&["a", "b", "c", "d"]);
        assert_eq!(
            pool.shuffled(&effective, &mut random),
            endpoints(&["c", "b", "d", "a"])
        );
        // Unchanged list: no new draw, same order.
        assert_eq!(
            pool.shuffled(&effective, &mut random),
            endpoints(&["c", "b", "d", "a"])
        );
    }

    #[test]
    fn quarantine_doubles_only_while_an_entry_lasts() {
        let mut pool = Pool::default();
        pool.mark_failure("b", 20);
        assert!(pool.is_quarantined("b", 60_019));
        pool.mark_failure("b", 30_000);
        // Overlapping: 120 s from the second failure.
        assert!(pool.is_quarantined("b", 149_999));
        assert!(!pool.is_quarantined("b", 150_000));
        // Expired and deleted: the next failure is 60 s again.
        pool.mark_failure("b", 150_000);
        assert!(!pool.is_quarantined("b", 210_000));
        pool.mark_failure("b", 0);
        pool.mark_success("b");
        assert!(!pool.is_quarantined("b", 1));
    }

    #[test]
    fn cooldowns_cap_at_ten_minutes() {
        let mut pool = Pool::default();
        for _ in 0..40 {
            pool.mark_failure("b", 0);
        }
        assert!(pool.is_quarantined("b", 599_999));
        assert!(!pool.is_quarantined("b", 600_000));
    }
}
