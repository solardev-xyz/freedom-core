//! `window.swarm`'s backend in the core (design 0015): the logic crate the
//! swarm thread's method machines will live in, sans-I/O. This first part
//! (SWM-3, part 1) holds:
//!
//! - **Batch choice** ([`stamps`]): the node's `/stamps` reply through its
//!   typed reader, bee-js 13.2.0's `stamp.getAll` over it (zod's schema and
//!   `mapPostageBatch`'s arithmetic, IEEE doubles included),
//!   swarm-service.js's classification of a raw batch, and
//!   `selectBestBatch`, with one `/stamps` read (deviation
//!   `stamps-one-read`).
//! - **The readers** ([`json`], [`zod`]): a pull reader that reads a reply
//!   once and keeps nothing, which every typed reader is built on, with the
//!   design's nesting bound; and zod's refusals as the page reads them.
//!
//! The reference is freedom-browser's `src/main/swarm/` at the swarm
//! reference commit over bee-js 13.2.0 and core-sdk 0.2.2;
//! `vectors/swarm.json` is the contract (AGENTS rule 5). The crate does no
//! I/O: replies come in as bytes.

#[allow(dead_code)] // the error texts' helpers arrive with node errors
mod js;
pub mod json;
pub mod stamps;
pub mod zod;

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
