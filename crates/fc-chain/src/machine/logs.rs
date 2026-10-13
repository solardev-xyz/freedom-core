//! What the router learns from log scans (design 0005, Logs), and the error
//! keeper a ranked caller's request uses.
//!
//! - **Range learning** (`logRangeState`): per endpoint, a block-range cap
//!   it refused, a span its upstream timed out on, and a cooldown after a
//!   failure of its own.
//! - **Blockscout's cooldowns**: the log index per chain, and a pair
//!   endpoint that answered with a malformed entry.
//! - **The error keeper** (`createErrorKeeper`): a ranked request keeps its
//!   most useful failure.

use std::collections::VecDeque;

use super::error::{FailureKind, Thrown};
use super::io::Ms;
use crate::ant::{ErrorRank, ReceivedError, log_scan_range_cap, rank_log_scan_error};
use crate::logs::{LOG_RANGE_CAP_TTL_MS, LOG_SCAN_COOLDOWN_MS};

/// How a ranked caller rates a failure (`rankError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ranker {
    /// Every failure ends the request (a test-only ranker of the replay).
    Request,
    /// The Ant profile's `rankLogScanError`.
    Ant,
}

/// How a ranked caller reads a range cap from a refusal (`rangeCapOf`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapReader {
    /// The Ant profile's `logScanRangeCap`.
    Ant,
}

/// An error as the Ant profile's functions read it.
fn received(error: &Thrown) -> (Vec<u16>, &'static str, bool) {
    (
        error.message.units().to_vec(),
        error.class.name(),
        error.is_own_timeout(),
    )
}

impl Ranker {
    /// `Number(rankError(error))`.
    pub(crate) fn rank(self, error: &Thrown) -> f64 {
        match self {
            Self::Request => 3.0,
            Self::Ant => {
                let (message, name, timeout) = received(error);
                let rank = rank_log_scan_error(&ReceivedError {
                    name,
                    message: &message,
                    code: error.code(),
                    timeout,
                });
                f64::from(rank as u8)
            }
        }
    }
}

impl CapReader {
    /// `capOf(error, span)`.
    pub(crate) fn cap(self, error: &Thrown, span: u64) -> Option<u64> {
        match self {
            Self::Ant => {
                let (message, name, timeout) = received(error);
                log_scan_range_cap(
                    &ReceivedError {
                        name,
                        message: &message,
                        code: error.code(),
                        timeout,
                    },
                    Some(span),
                )
            }
        }
    }
}

const ENDPOINT: f64 = ErrorRank::Endpoint as u8 as f64;
const TIMEOUT: f64 = ErrorRank::Timeout as u8 as f64;
const REQUEST: f64 = ErrorRank::Request as u8 as f64;

/// `createErrorKeeper(rankError)`.
#[derive(Debug, Clone)]
pub(crate) struct Keeper {
    ranker: Option<Ranker>,
    kept: Option<Thrown>,
    rank: f64,
}

impl Keeper {
    pub(crate) fn new(ranker: Option<Ranker>) -> Self {
        Self {
            ranker,
            kept: None,
            rank: -1.0,
        }
    }

    /// Keeps `error` when it ranks higher than the kept one, or when both
    /// are timeouts (the later one ended the request).
    pub(crate) fn note(&mut self, error: &Thrown) {
        let Some(ranker) = self.ranker else { return };
        let mut rank = ranker.rank(error);
        if !rank.is_finite() {
            rank = ENDPOINT;
        }
        if rank > self.rank || (rank == self.rank && rank == TIMEOUT) {
            self.kept = Some(error.clone());
            self.rank = rank;
        }
    }

    /// A request-ranked failure ends the request.
    pub(crate) fn is_final(&self) -> bool {
        self.rank >= REQUEST
    }

    /// Only a failure the caller can act on replaces the router's report.
    pub(crate) fn error(&self) -> Option<&Thrown> {
        if self.rank > ENDPOINT {
            self.kept.as_ref()
        } else {
            None
        }
    }
}

/// A range-capped log scan's options (`logRange`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LogRange {
    pub span: u64,
    pub cap: CapReader,
    pub ranker: Option<Ranker>,
    /// False for the truncation check's own query: it learns nothing.
    pub learn: bool,
}

/// One endpoint's learned range state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RangeEntry {
    /// The smallest span it refused as a range limit.
    pub refused_from: Option<u64>,
    pub cap_until: Ms,
    /// The smallest span its upstream timed out on.
    pub slow_from: Option<u64>,
    pub slow_until: Ms,
    /// Left out of scans until then.
    pub cool_until: Ms,
}

/// The router's log tables, in insertion order (JavaScript `Map`s).
#[derive(Debug, Default)]
pub(crate) struct LogState {
    pub range: Vec<(String, RangeEntry)>,
    /// `logIndexCoolUntil`: per chain.
    pub index_cool_until: Vec<(u64, Ms)>,
    /// `logIndexPairCoolUntil`: per `${chain}|${url}`.
    pub pair_cool_until: Vec<(String, Ms)>,
    /// Endpoints no longer configured whose state is kept, oldest first
    /// (deviation `state-retention`).
    pub retired: VecDeque<String>,
}

/// `logRangeKey`.
pub(crate) fn range_key(chain_id: u64, url: &str) -> String {
    format!("{chain_id} {url}")
}

impl LogState {
    fn entry(&self, key: &str) -> Option<&RangeEntry> {
        self.range.iter().find(|(k, _)| k == key).map(|(_, e)| e)
    }

    /// `servableLogSpan`: 0 while cooling down, infinite while no cap is
    /// known.
    pub(crate) fn servable(&self, chain_id: u64, url: &str, now: Ms) -> f64 {
        let Some(entry) = self.entry(&range_key(chain_id, url)) else {
            return f64::INFINITY;
        };
        if entry.cool_until > now {
            return 0.0;
        }
        let mut span = f64::INFINITY;
        if let Some(refused) = entry.refused_from
            && entry.cap_until > now
        {
            span = refused as f64 - 1.0;
        }
        if let Some(slow) = entry.slow_from
            && entry.slow_until > now
        {
            span = span.min(slow as f64 - 1.0);
        }
        span
    }

    /// `quorumLogSpan`: the widest span `m` endpoints can serve together.
    pub(crate) fn quorum_span(&self, chain_id: u64, urls: &[String], m: f64, now: Ms) -> f64 {
        let mut spans: Vec<f64> = urls
            .iter()
            .map(|url| self.servable(chain_id, url, now))
            .collect();
        spans.sort_by(|a, b| b.total_cmp(a));
        #[allow(clippy::cast_precision_loss)]
        let enough = spans.len() as f64 >= m;
        if !enough {
            return 0.0;
        }
        // `spans[m - 1]`: a fractional m reads nothing.
        if m.fract() != 0.0 {
            return f64::NAN;
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        spans.get((m - 1.0) as usize).copied().unwrap_or(f64::NAN)
    }

    /// `noteLogRangeAnswer`: an answer ends a cooldown, and an answer at
    /// or above a cap clears it.
    pub(crate) fn note_answer(&mut self, chain_id: u64, url: &str, span: u64) {
        let key = range_key(chain_id, url);
        let Some(at) = self.range.iter().position(|(k, _)| *k == key) else {
            return;
        };
        let entry = &mut self.range[at].1;
        entry.cool_until = 0;
        if entry.refused_from.is_some_and(|refused| span >= refused) {
            entry.refused_from = None;
        }
        if entry.slow_from.is_some_and(|slow| span >= slow) {
            entry.slow_from = None;
        }
        if entry.refused_from.is_none() && entry.slow_from.is_none() {
            self.range.remove(at);
        }
    }

    /// `noteLogRangeFailure`.
    pub(crate) fn note_failure(
        &mut self,
        chain_id: u64,
        url: &str,
        span: u64,
        error: &Thrown,
        range: &LogRange,
        now: Ms,
    ) {
        if !range.learn {
            return;
        }
        let key = range_key(chain_id, url);
        let mut entry = self.entry(&key).copied().unwrap_or_default();
        let cap = range.cap.cap(error, span).filter(|cap| *cap > 0);
        let rank = range.ranker.map_or(f64::NAN, |ranker| ranker.rank(error));
        let client_timeout = error.failure_kind() == Some(FailureKind::Timeout);
        if let Some(cap) = cap {
            entry.refused_from = Some(match entry.refused_from {
                Some(refused) if entry.cap_until > now => refused.min(cap + 1),
                _ => cap + 1,
            });
            entry.cap_until = now + LOG_RANGE_CAP_TTL_MS;
        } else if !client_timeout && rank == TIMEOUT {
            entry.slow_from = Some(match entry.slow_from {
                Some(slow) if entry.slow_until > now => slow.min(span),
                _ => span,
            });
            entry.slow_until = now + LOG_SCAN_COOLDOWN_MS;
        } else if client_timeout || rank <= ENDPOINT || rank.is_nan() {
            entry.cool_until = now + LOG_SCAN_COOLDOWN_MS;
        } else {
            return;
        }
        match self.range.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = entry,
            None => self.range.push((key, entry)),
        }
    }

    /// Deviation `state-retention`: endpoints that left every chain's
    /// configuration join the retired list, re-added ones leave it, and
    /// past `bound` the oldest lose their state.
    pub(crate) fn retire(&mut self, old: &[(u64, String)], new: &[(u64, String)], bound: usize) {
        let tag = |(chain, url): &(u64, String)| format!("{chain} {url}");
        let current: Vec<String> = new.iter().map(tag).collect();
        for endpoint in old.iter().map(tag) {
            if !current.contains(&endpoint) && !self.retired.contains(&endpoint) {
                self.retired.push_back(endpoint);
            }
        }
        self.retired.retain(|endpoint| !current.contains(endpoint));
        while self.retired.len() > bound {
            let Some(dropped) = self.retired.pop_front() else {
                break;
            };
            let pair = dropped.replacen(' ', "|", 1);
            self.range.retain(|(k, _)| *k != dropped);
            self.pair_cool_until.retain(|(k, _)| *k != pair);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::error::Prop;

    fn node(code: i64, message: &str) -> Thrown {
        Thrown::error(message).with("code", Prop::Json(code.to_string()))
    }

    #[test]
    fn caps_slow_spans_and_cooldowns() {
        let mut state = LogState::default();
        let range = LogRange {
            span: 100_000,
            cap: CapReader::Ant,
            ranker: Some(Ranker::Ant),
            learn: true,
        };
        let cap = node(-32005, "query exceeds max block range 50000");
        state.note_failure(100, "a", 100_000, &cap, &range, 0);
        assert_eq!(state.servable(100, "a", 1), 50_000.0);
        // The cap lasts 30 minutes.
        assert_eq!(
            state.servable(100, "a", LOG_RANGE_CAP_TTL_MS),
            f64::INFINITY
        );
        state.note_failure(100, "b", 100_000, &Thrown::rpc_timeout(5000.0), &range, 0);
        assert_eq!(state.servable(100, "b", 29_999), 0.0);
        assert_eq!(state.servable(100, "b", 30_000), f64::INFINITY);
        let slow = node(-32000, "query timeout exceeded");
        state.note_failure(100, "c", 4000, &slow, &range, 0);
        assert_eq!(state.servable(100, "c", 0), 3999.0);
        state.note_answer(100, "c", 4000);
        assert_eq!(state.servable(100, "c", 0), f64::INFINITY);
        assert_eq!(
            state.quorum_span(100, &["a".into(), "b".into(), "c".into()], 2.0, 1),
            50_000.0
        );
        // The truncation check's own query learns nothing.
        let quiet = LogRange {
            learn: false,
            ..range
        };
        state.note_failure(100, "d", 100_000, &cap, &quiet, 0);
        assert_eq!(state.servable(100, "d", 1), f64::INFINITY);
    }

    #[test]
    fn retired_state_is_bounded() {
        let mut state = LogState::default();
        let range = LogRange {
            span: 10,
            cap: CapReader::Ant,
            ranker: Some(Ranker::Ant),
            learn: true,
        };
        for url in ["a", "b", "c"] {
            state.note_failure(1, url, 10, &Thrown::rpc_timeout(1.0), &range, 0);
            state.pair_cool_until.push((format!("1|{url}"), 5));
        }
        let all: Vec<(u64, String)> = ["a", "b", "c"]
            .iter()
            .map(|u| (1, (*u).to_owned()))
            .collect();
        state.retire(&all, &all[2..], 1);
        // a and b retired; with room for one, a's state goes.
        assert_eq!(state.retired, ["1 b"]);
        assert!(state.range.iter().all(|(k, _)| k != "1 a"));
        assert!(state.pair_cool_until.iter().all(|(k, _)| k != "1|a"));
        assert!(state.pair_cool_until.iter().any(|(k, _)| k == "1|b"));
        // Re-added, b is no longer retired and keeps its state.
        state.retire(&all[2..], &all[1..], 1);
        assert!(state.retired.is_empty());
        assert_eq!(state.servable(1, "b", 0), 0.0);
    }

    #[test]
    fn keeper_keeps_the_most_useful() {
        let mut keeper = Keeper::new(Some(Ranker::Ant));
        keeper.note(&node(-32601, "the method eth_getLogs does not exist"));
        assert!(keeper.error().is_none());
        keeper.note(&Thrown::rpc_timeout(5000.0));
        assert!(keeper.error().is_some() && !keeper.is_final());
        keeper.note(&node(-32005, "query exceeds max block range 50000"));
        assert!(keeper.is_final());
        keeper.note(&Thrown::rpc_timeout(5000.0));
        assert_eq!(keeper.error().and_then(Thrown::code), Some("-32005"));
        let mut none = Keeper::new(None);
        none.note(&node(-32005, "query exceeds max block range 50000"));
        assert!(none.error().is_none() && !none.is_final());
    }
}
