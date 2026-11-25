//! `window.swarm`'s backend in the core (design 0015): the logic crate the
//! swarm thread's method machines will live in, sans-I/O. This first part
//! (SWM-3, part 1) starts with the reader under every typed reader of a
//! node's JSON reply ([`json`]): it reads a reply once and keeps nothing,
//! with the design's nesting bound.
//!
//! The reference is freedom-browser's `src/main/swarm/` at the swarm
//! reference commit over bee-js 13.2.0 and core-sdk 0.2.2;
//! `vectors/swarm.json` is the contract (AGENTS rule 5). The crate does no
//! I/O: replies come in as bytes.

#[allow(dead_code)] // its users arrive with batch choice and node errors
mod js;
pub mod json;

/// Why a node's reply isn't read (design 0015, "JSON replies").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplyError {
    /// Past its form's cap, its element cap, or with a refusal whose text
    /// would pass the cap: the call fails `too_large` (deviation
    /// `reply-bounds`).
    #[error("the node's reply is past its cap")]
    TooLarge,
    /// Nested past [`json::MAX_NESTING`]: the call fails `error`.
    #[error("the node's reply nests too deep")]
    TooDeep,
    /// Not JSON, as `JSON.parse` would throw.
    #[error("the node's reply is not JSON (byte {0})")]
    Syntax(usize),
}

impl From<json::ReadError> for ReplyError {
    fn from(err: json::ReadError) -> Self {
        match err {
            json::ReadError::Syntax(at) => Self::Syntax(at),
            json::ReadError::TooDeep => Self::TooDeep,
        }
    }
}
