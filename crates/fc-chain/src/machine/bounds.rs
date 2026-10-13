//! The machine's bounds (design 0005, Bounds). Each sits above every valid
//! case; what happens when one is reached is the deviation the design lists
//! for it.

use super::io::Ms;

/// The machine's bounds. `Default` is design 0005's values; tests lower one
/// so that its boundary fits a small vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// Running chain requests (`admission`).
    pub running: usize,
    /// Requests waiting for a running slot (`admission`).
    pub waiting: usize,
    /// A request's overall deadline, unless the caller's is lower
    /// (`overall-deadline`).
    pub deadline_ms: Ms,
    /// How long before its deadline a broadcast stops its attempts, so it
    /// can reconcile (design 0005, Deadlines).
    pub reconcile_ms: Ms,
    /// One answer (`response-caps`): 18 MiB, an `html()` document at its
    /// 8 MiB limit with room for envelopes.
    pub answer_bytes: usize,
    /// One message, serialized: a reply over it fails with `too_large`.
    pub message_bytes: usize,
    /// What one request may hold (`memory-budgets`).
    pub request_bytes: usize,
    /// What all requests may hold, unwritten replies included.
    pub total_bytes: usize,
    /// Quorum members (`quorum-clamps`).
    pub quorum_k: usize,
    /// The quorum's timeout (`quorum-clamps`).
    pub quorum_timeout_ms: Ms,
    /// Endpoints per chain (`quorum-clamps`).
    pub endpoints: usize,
    /// Adaptive routes kept; past it the oldest is evicted.
    pub adaptive_routes: usize,
    /// Retired endpoints whose log-range state is kept (`state-retention`).
    pub retired_endpoints: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            running: 64,
            waiting: 256,
            deadline_ms: 120_000,
            reconcile_ms: 10_000,
            answer_bytes: 18 * 1024 * 1024,
            message_bytes: 32 * 1024 * 1024,
            request_bytes: 96 * 1024 * 1024,
            total_bytes: 256 * 1024 * 1024,
            quorum_k: 9,
            quorum_timeout_ms: 60_000,
            endpoints: 64,
            adaptive_routes: 1024,
            retired_endpoints: 64,
        }
    }
}
