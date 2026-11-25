//! The next index of a feed write (feed-service.js's `resolveNextIndex` and
//! `probeFeedHead`), for `updateFeed`, `writeFeedEntry` and `swarm.feed`'s
//! update, which the Feeds piece brings; and a feed's latest index
//! (`readFeedState`), for `swarm.feed`'s read ([`NextIndex::head`]).
//!
//! - **The lookup** is `feed_head`: `GET /feeds/<o>/<t>` with
//!   `swarm-only-root-chunk: true`, whose headers alone the core reads,
//!   where the reference downloads the latest payload whole to learn its
//!   index (deviation `index-probe`). The headers are read as bee-js reads
//!   them (`readFeedUpdateHeaders`): both are required, each an 8-byte
//!   `FeedIndex`, and the next index is `swarm-feed-index-next`'s.
//! - **A 404 or a 500** (`isNotFoundError`) falls back to the head probe
//!   over the update chunks themselves: index 0, then 1, 2, 4, … to 2^40
//!   while each exists, then the halving between the last found and the
//!   first missing, at most 81 reads. Only a 404 says a chunk is missing;
//!   any other error answer ends the lookup with its text. No feed has 0:
//!   the next index is the head + 1, or 0.
//! - **A read** (`readFeedState`) takes the same lookup and probe, but only
//!   a 404 falls back to the probe (a 500 is the lookup's error, as
//!   `readFeedState` throws it), and its answer is the latest index itself:
//!   the lookup's `swarm-feed-index` (both headers read as bee-js reads
//!   them), or the probe's head, or none ([`Next::Head`]).
//!
//! It is a sub-machine: each step gives the next node call, or the index,
//! or why there is none; the method machine that runs it makes the calls.

use fc_json::JsString;
use fc_swarm::verify::feed_update_address;

use crate::chunks::bytes_from_hex;
use crate::errors::Site;
use crate::machine::{Failed, NodeCall, Reply};

/// `MAX_PROBED_FEED_INDEX`: the highest index the head probe looks for.
pub const MAX_PROBED_INDEX: u64 = 1 << 40;
/// The head probe's longest run: index 0, 41 growing reads to 2^40, and 39
/// halving ones (SWM-1's vectors measure it).
pub const MAX_PROBE_READS: u32 = 81;

/// The lookup's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextIndex {
    owner: [u8; 20],
    topic: [u8; 32],
    state: State,
    reads: u32,
    /// `readFeedState`'s lookup: the latest index, not the next.
    head: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Lookup,
    /// Index 0 asked.
    Zero,
    /// `hi` asked; `lo` exists.
    Grow {
        lo: u64,
        hi: u64,
    },
    /// `mid` asked, between `lo` (exists) and `hi` (missing).
    Bisect {
        lo: u64,
        hi: u64,
        mid: u64,
    },
    Ended,
}

/// What the lookup does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// Make this call, and hand its answer back.
    Call(NodeCall),
    /// The index to write at.
    Index(u64),
    /// A read's answer ([`NextIndex::head`]): the feed's latest index, or
    /// `None` when no update was found.
    Head(Option<u64>),
    /// The lookup failed with a header's text, as the reference throws it.
    Error(JsString),
    /// The lookup failed with a node's error answer (the lookup's, or a
    /// probe's), bee-js's `BeeResponseError`, whose status its callers read.
    Node(crate::errors::NodeError),
    /// The call failed before any reply.
    Failed(Failed),
}

impl NextIndex {
    /// Starts the lookup: its first call, `feed_head`.
    pub fn start(owner: [u8; 20], topic: [u8; 32]) -> (NextIndex, NodeCall) {
        (
            NextIndex {
                owner,
                topic,
                state: State::Lookup,
                reads: 0,
                head: false,
            },
            NodeCall::feed_head(&owner, &topic),
        )
    }

    /// Starts `readFeedState`'s lookup of the feed's latest index: its
    /// first call, `feed_head`.
    pub fn head(owner: [u8; 20], topic: [u8; 32]) -> (NextIndex, NodeCall) {
        let (next, call) = NextIndex::start(owner, topic);
        (NextIndex { head: true, ..next }, call)
    }

    /// The probe's end: the latest index found (`None`: index 0 is
    /// missing), as the write's next index or the read's head.
    fn found(&mut self, latest: Option<u64>) -> Next {
        self.end(if self.head {
            Next::Head(latest)
        } else {
            Next::Index(latest.map_or(0, |latest| latest + 1))
        })
    }

    /// The probe reads made so far.
    pub fn reads(&self) -> u32 {
        self.reads
    }

    fn probe(&mut self, index: u64, state: State) -> Next {
        self.reads += 1;
        self.state = state;
        Next::Call(
            NodeCall::chunk(&feed_update_address(&self.owner, &self.topic, index))
                .with_feed(self.owner, index),
        )
    }

    fn end(&mut self, next: Next) -> Next {
        self.state = State::Ended;
        next
    }

    /// The call failed before any reply.
    pub fn failed(&mut self, failed: Failed) -> Next {
        self.end(Next::Failed(failed))
    }

    /// The current call's reply.
    pub fn reply(&mut self, reply: &Reply) -> Next {
        match self.state {
            State::Lookup => self.lookup(reply),
            State::Zero | State::Grow { .. } | State::Bisect { .. } => match exists(reply) {
                Ok(found) => self.step(found),
                Err(ended) => self.end(ended.into()),
            },
            State::Ended => Next::Error(JsString::from("Internal error")),
        }
    }

    fn lookup(&mut self, reply: &Reply) -> Next {
        if !reply.ok() {
            // `isNotFoundError` for a write; `readFeedState` probes after a
            // 404 alone.
            let probes = |err: &crate::errors::NodeError| {
                if self.head {
                    err.name == crate::errors::NodeErrorName::BeeResponseError
                        && err.status == Some(404)
                } else {
                    err.is_not_found()
                }
            };
            return match reply.error(Site::BeeJs) {
                Err(failed) => self.end(Next::Failed(failed)),
                Ok(err) if probes(&err) => self.probe(0, State::Zero),
                Ok(err) => self.end(Next::Node(err)),
            };
        }
        let text = |name: &str| {
            reply
                .header(name)
                .map(|v| v.text())
                .filter(|t| !t.is_empty())
        };
        let Some(index) = text("swarm-feed-index") else {
            return self.end(Next::Error(JsString::from(
                "Response did not contain expected swarm-feed-index!",
            )));
        };
        let Some(next) = text("swarm-feed-index-next") else {
            return self.end(Next::Error(JsString::from(
                "Response did not contain expected swarm-feed-index-next!",
            )));
        };
        let index = match bytes_from_hex::<8>(&index) {
            Ok(bytes) => u64::from_be_bytes(bytes),
            Err(message) => return self.end(Next::Error(JsString::from(message))),
        };
        match bytes_from_hex::<8>(&next) {
            // A read's answer is `feedIndexToNumber(latest.feedIndex)`,
            // which its caller takes as a double.
            Ok(_) if self.head => self.end(Next::Head(Some(index))),
            // `feedIndexToNumber`: a double, which a write takes back as
            // `BigInt(index)`.
            Ok(bytes) => self.end(Next::Index(round_trip(u64::from_be_bytes(bytes)))),
            Err(message) => self.end(Next::Error(JsString::from(message))),
        }
    }

    fn step(&mut self, found: bool) -> Next {
        match (self.state, found) {
            (State::Zero, false) => self.found(None),
            (State::Zero, true) => self.probe(1, State::Grow { lo: 0, hi: 1 }),
            (State::Grow { hi, .. }, true) => {
                let lo = hi;
                let hi = hi * 2;
                if hi > MAX_PROBED_INDEX {
                    return self.end(Next::Error(JsString::from(
                        "Feed head probe exceeded the maximum feed index",
                    )));
                }
                self.probe(hi, State::Grow { lo, hi })
            }
            (State::Grow { lo, hi }, false) => self.bisect(lo, hi),
            (State::Bisect { mid, hi, .. }, true) => self.bisect(mid, hi),
            (State::Bisect { lo, mid, .. }, false) => self.bisect(lo, mid),
            _ => self.end(Next::Error(JsString::from("Internal error"))),
        }
    }

    fn bisect(&mut self, lo: u64, hi: u64) -> Next {
        if hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            return self.probe(mid, State::Bisect { lo, hi, mid });
        }
        self.found(Some(lo))
    }
}

/// `feedUpdateChunkExists`: a 2xx says the update exists, a 404 that it
/// doesn't; any other answer is the node's error, which ends the lookup.
fn exists(reply: &Reply) -> Result<bool, Ended> {
    if reply.ok() {
        return Ok(true);
    }
    match reply.error(Site::BeeJs) {
        Err(failed) => Err(Ended::Failed(failed)),
        Ok(_) if reply.status == 404 => Ok(false),
        Ok(err) => Err(Ended::Node(err)),
    }
}

/// Why a probe read ends the lookup.
enum Ended {
    Node(crate::errors::NodeError),
    Failed(Failed),
}

impl From<Ended> for Next {
    fn from(ended: Ended) -> Self {
        match ended {
            Ended::Node(err) => Next::Node(err),
            Ended::Failed(failed) => Next::Failed(failed),
        }
    }
}

/// `BigInt(Number(n))` for an index: `n` rounded to a double, taken back
/// modulo 2^64 as `FeedIndex.fromBigInt` takes it.
pub fn round_trip(n: u64) -> u64 {
    #[expect(
        clippy::cast_precision_loss,
        reason = "Number(n), as the reference reads the index"
    )]
    wrapping_index(n as f64)
}

/// `FeedIndex.fromBigInt(BigInt(x))` for a non-negative integer double `x`:
/// its value modulo 2^64 (`setBigUint64` keeps the low 64 bits).
pub fn wrapping_index(x: f64) -> u64 {
    const TWO_64: f64 = 18_446_744_073_709_551_616.0;
    if x < TWO_64 {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a non-negative integer below 2^64"
        )]
        return x as u64;
    }
    let bits = x.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i64 - 1075;
    let mantissa = (bits & ((1 << 52) - 1)) | (1 << 52);
    if exponent >= 64 {
        0
    } else {
        // At least 2^64, so the exponent is at least 12.
        ((u128::from(mantissa) << exponent) & u128::from(u64::MAX)) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes_wrap_as_setbiguint64() {
        assert_eq!(wrapping_index(0.0), 0);
        assert_eq!(wrapping_index(-0.0), 0);
        assert_eq!(wrapping_index(18_446_744_073_709_551_616.0), 0);
        assert_eq!(wrapping_index(18_446_744_073_709_555_712.0), 4096);
        assert_eq!(wrapping_index(1e300), 0);
        assert_eq!(round_trip(9_007_199_254_740_993), 9_007_199_254_740_992);
    }
}
