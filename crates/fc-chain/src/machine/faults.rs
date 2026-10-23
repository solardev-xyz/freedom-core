//! Colibri's verifier-fault backoff (design 0005, Colibri: verifier
//! faults; freedom-browser main's `colibriFaults`, #752): per chain and
//! method, whoever asked. Two faults within 60 s keep Colibri out of that
//! method on that chain for the next cooldown; an answer deletes the
//! record.

use super::io::Ms;

/// `COLIBRI_FAULT_WINDOW_MS`.
const WINDOW_MS: Ms = 60_000;
/// `COLIBRI_FAULT_THRESHOLD`.
const THRESHOLD: usize = 2;
/// `COLIBRI_FAULT_COOLDOWNS_MS`: the last repeats.
const COOLDOWNS_MS: [Ms; 3] = [60_000, 5 * 60_000, 15 * 60_000];

/// One chain and method's record: `{ faults, strikes, coolUntil }`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FaultRecord {
    /// The faults' times within the window, oldest first.
    pub faults: Vec<Ms>,
    /// Cooldowns started since the record was made.
    pub strikes: u32,
    /// The current cooldown's end; 0 when none has started.
    pub cool_until: Ms,
}

/// A cooldown that has just started, for the log: the chain, the method
/// and its length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackedOff {
    pub chain_id: u64,
    pub method: String,
    pub cooldown_ms: Ms,
}

/// The records, in insertion order (a `Map`, as main's), at most `limit`
/// of them (deviation `memory-budgets`: the reference's is unbounded).
#[derive(Debug, Default)]
pub(crate) struct ColibriFaults {
    records: Vec<(String, FaultRecord)>,
}

/// The record's key, as main's `colibriFaultKey`: `"<chain> <method>"`.
fn key(chain_id: u64, method: &str) -> String {
    format!("{chain_id} {method}")
}

impl ColibriFaults {
    fn find(&self, key: &str) -> Option<usize> {
        self.records.iter().position(|(k, _)| k == key)
    }

    /// `colibriBackedOff`: a cooldown runs until the clock reaches its end.
    pub(crate) fn backed_off(&self, chain_id: u64, method: &str, now: Ms) -> bool {
        self.find(&key(chain_id, method))
            .is_some_and(|at| self.records[at].1.cool_until > now)
    }

    /// `noteColibriAnswer`: the record goes, strikes and all, a cooldown's
    /// included.
    pub(crate) fn answer(&mut self, chain_id: u64, method: &str) {
        if let Some(at) = self.find(&key(chain_id, method)) {
            self.records.remove(at);
        }
    }

    /// `noteColibriFault`. A fault during a cooldown adds nothing. Outside
    /// one, the times a window old or older go and this one is added; at
    /// the threshold a cooldown starts, the next of the steps, and the
    /// times clear. The cooldown started, if one did.
    pub(crate) fn fault(
        &mut self,
        chain_id: u64,
        method: &str,
        now: Ms,
        limit: usize,
    ) -> Option<BackedOff> {
        let key = key(chain_id, method);
        let at = match self.find(&key) {
            Some(at) => at,
            None => {
                if limit == 0 {
                    return None;
                }
                if self.records.len() >= limit {
                    self.records.remove(0);
                }
                self.records.push((key, FaultRecord::default()));
                self.records.len() - 1
            }
        };
        let record = &mut self.records[at].1;
        if record.cool_until > now {
            return None;
        }
        record
            .faults
            .retain(|&fault| now.saturating_sub(fault) < WINDOW_MS);
        record.faults.push(now);
        if record.faults.len() < THRESHOLD {
            return None;
        }
        let step = usize::try_from(record.strikes).unwrap_or(usize::MAX);
        let cooldown_ms = COOLDOWNS_MS[step.min(COOLDOWNS_MS.len() - 1)];
        record.strikes = record.strikes.saturating_add(1);
        record.faults.clear();
        record.cool_until = now.saturating_add(cooldown_ms);
        Some(BackedOff {
            chain_id,
            method: method.to_owned(),
            cooldown_ms,
        })
    }

    /// The records, as the replay compares them.
    pub(crate) fn table(&self) -> Vec<(String, FaultRecord)> {
        self.records.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CALL: &str = "eth_call";

    #[test]
    fn two_faults_within_the_window_start_each_cooldown_in_turn() {
        let mut faults = ColibriFaults::default();
        assert_eq!(faults.fault(1, CALL, 0, 8), None);
        let started = faults.fault(1, CALL, 59_999, 8).unwrap();
        assert_eq!(started.cooldown_ms, 60_000);
        assert!(faults.backed_off(1, CALL, 119_998));
        assert!(!faults.backed_off(1, CALL, 119_999));
        // Other methods and chains are their own.
        assert!(!faults.backed_off(1, "eth_getBalance", 60_000));
        assert!(!faults.backed_off(100, CALL, 60_000));
        let mut at = 119_999;
        for cooldown in [300_000, 900_000, 900_000] {
            assert_eq!(faults.fault(1, CALL, at, 8), None);
            assert_eq!(faults.fault(1, CALL, at, 8).unwrap().cooldown_ms, cooldown);
            at += cooldown;
        }
        assert_eq!(faults.table()[0].1.strikes, 4);
    }

    #[test]
    fn faults_a_window_apart_never_meet() {
        let mut faults = ColibriFaults::default();
        assert_eq!(faults.fault(1, CALL, 0, 8), None);
        assert_eq!(faults.fault(1, CALL, 60_000, 8), None);
        assert_eq!(faults.table()[0].1.faults, [60_000]);
    }

    #[test]
    fn a_fault_during_a_cooldown_adds_nothing_and_an_answer_ends_it() {
        let mut faults = ColibriFaults::default();
        faults.fault(1, CALL, 0, 8);
        faults.fault(1, CALL, 10, 8);
        assert_eq!(faults.fault(1, CALL, 20, 8), None);
        assert_eq!(
            faults.table(),
            [(
                "1 eth_call".to_owned(),
                FaultRecord {
                    faults: vec![],
                    strikes: 1,
                    cool_until: 60_010
                }
            )]
        );
        faults.answer(1, CALL);
        assert!(!faults.backed_off(1, CALL, 30));
        assert!(faults.table().is_empty());
    }

    #[test]
    fn the_oldest_record_goes_past_the_limit() {
        let mut faults = ColibriFaults::default();
        for chain in 1..=3 {
            faults.fault(chain, CALL, 0, 2);
        }
        let keys: Vec<String> = faults.table().into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, ["2 eth_call", "3 eth_call"]);
        assert_eq!(faults.fault(4, CALL, 0, 0), None);
        assert_eq!(faults.table().len(), 2);
    }
}
