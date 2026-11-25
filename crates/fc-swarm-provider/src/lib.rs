//! `window.swarm`'s backend in the core (design 0015): the logic crate the
//! swarm thread's method machines live in, sans-I/O. The first part
//! (SWM-3, part 1) holds:
//!
//! - **Batch choice** ([`stamps`]): the node's `/stamps` reply through its
//!   typed reader, bee-js 13.2.0's `stamp.getAll` over it (zod's schema and
//!   `mapPostageBatch`'s arithmetic, IEEE doubles included),
//!   swarm-service.js's classification of a raw batch, and
//!   `selectBestBatch`, with one `/stamps` read (deviation
//!   `stamps-one-read`).
//! - **Node errors** ([`errors`]): each call site's error for a node's
//!   error answer (class, message, body, `isChunkNotFoundError`), from at
//!   most 8 KiB of its body (deviation `error-body-bound`); and the
//!   provider's mappings, `nodeWriteError`, `mapChunkReadError` and
//!   `isBatchNotYetKnownError`.
//! - **The readers** ([`json`], [`zod`]): a pull reader that reads a reply
//!   once and keeps nothing, which every typed reader is built on, with the
//!   design's nesting bound; and zod's refusals as the page reads them.
//!
//! The second part (SWM-3, part 2) adds:
//!
//! - **The stores** ([`stores`]): `swarm-feeds.json`,
//!   `swarm-manifest-grants.json` and `publish-history.sqlite` as codecs and
//!   rules: each parses the text or rows it is handed, applies an
//!   operation as the reference module does, and answers the exact text or
//!   the statements to write (deviations `index-allocation`,
//!   `history-bound`, `store-writes`).
//!
//! The third part (SWM-3, part 3a) adds the method machines:
//!
//! - **The framework** ([`machine`]): one [`machine::Request`] per
//!   `swarm.request`, which asks for what it needs (a readiness answer, a
//!   node call with its charge, hashing, and for the pieces to come a
//!   part, a signature, a store write, a GSOC search) and is handed the
//!   answers; the world it reads between them (the clock, the grants, the
//!   feed store, the read budgets); a page's errors; the typed params
//!   ([`value`]).
//! - **Access and Reads** ([`methods`]): `requestAccess`,
//!   `getCapabilities`, `listFeeds`, `readChunk`,
//!   `readSingleOwnerChunk`, `readData` through 0009's verified walk
//!   (deviation `read-data-verified`), and `readFeedEntry` with #1057's
//!   metered reads; the read budgets ([`budgets`]); chunks as bee-js reads
//!   them ([`chunks`]); and the feed index lookup the feed writes will use
//!   ([`methods::feed_index`], deviation `index-probe`).
//!
//! The reference is freedom-browser's `src/main/swarm/` at the swarm
//! reference commit over bee-js 13.2.0 and core-sdk 0.2.2;
//! `vectors/swarm.json` is the contract (AGENTS rule 5). The crate does no
//! I/O: replies come in as bytes.

pub mod budgets;
pub mod chunks;
pub mod errors;
mod js;
pub mod json;
pub mod machine;
pub mod methods;
pub mod stamps;
pub mod stores;
pub mod value;
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
