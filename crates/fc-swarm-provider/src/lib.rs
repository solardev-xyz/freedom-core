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
//!   `history-bound`, `history-blobs`, `store-shapes`, `store-refusal`,
//!   `own-keys`, `legacy-dates`, `store-writes`).
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
//! The fourth part (SWM-3, part 3b) adds the Publish group:
//!
//! - **Uploads** ([`methods::publish`]): `publishData`, `publishFiles` and
//!   `publishChunk` along design 0015's path: the publish readiness, the
//!   history row and its bound (deviation `history-bound`), one `/stamps`
//!   read and the batch, the effect's guard, the upload (one file inline
//!   or streamed from its part, page-upload.js's tar, a chunk), the node's
//!   answer as the reference reads it, the chunk's reference checked
//!   (deviation `reference-check`), the tag's owner and the row's update.
//! - **`getUploadStatus`** ([`methods::upload_status`]): the tag's owner,
//!   and `normalizeTag`'s object through a typed reader ([`replies`]).
//! - **The framework's upload asks** ([`machine`]): a streaming upload's
//!   turn, a history insert answered with its rowid, `swarm.body` out of
//!   the core with credit on a part only for what went out, and the row's
//!   update when a request ends without its machine.
//!
//! The third part's last piece (SWM-3, part 3c) adds the feed and SOC
//! writes, with SW-1 in the core:
//!
//! - **`createFeed`, `updateFeed`, `writeFeedEntry`** ([`methods::create_feed`],
//!   [`methods::feed_write`]): the topic, the index and the identifier the
//!   core computes; the key the site's own store names; the index lookup
//!   (deviation `index-probe`) and an explicit index's check; one write to
//!   a topic at a time; a feed entry over one chunk streamed to `/bytes`,
//!   its root computed as it goes and checked against the node's
//!   (deviations `feed-wrap-root`, `reference-check`); entries of at most
//!   10 MiB (deviation `feed-entry-bound`).
//! - **`writeSingleOwnerChunk`** ([`methods::soc_write`]): SW-1's check in
//!   today's place, its re-check in the step that hands the signature to
//!   the vault, and the signature asked under SW-1's hold.
//! - **`getSigningIdentity`** ([`methods::signing`]).
//! - **SW-1's keeper** ([`machine::keeper`]): every feed-store change, the
//!   listed ones deferred while a hold stands, each kept only once written
//!   (deviation `store-refusal`); allocation past every stored index
//!   (deviation `index-allocation`).
//! - **The framework's write asks** ([`machine`]): the vault's owner of a
//!   key, a signature with its kind, the topic's turn, and a feed-store
//!   change.
//!
//! The part's last piece (SWM-3, part 3d) adds Messaging and the mining
//! lane:
//!
//! - **`getMessagingIdentity`, `sendPss`, `sendGsoc`, `subscribe`**
//!   ([`methods::messaging`]): the node's compressed PSS key through bee-js's
//!   `/addresses` schema; a PSS message under `selectMessageBatch`'s batch
//!   (a full mutable batch allowed) to the page's compressed recipient; a
//!   GSOC message signed with the signer mined from its topic; and a
//!   subscription, after question 4's subscribe check (deviation
//!   `subscribe-proxy`), which main opens inside the request (design
//!   0015's D16): the core asks main to open it once its guard passes,
//!   asks the live facts again once it is open, and answers the page `{
//!   subscriptionId, kind, key }` with main's id, or has main close it and
//!   answers `NO_ADDRESS` if the name or the document moved. A request
//!   that ends while main opens or holds its subscription closes it, and a
//!   close is answered within its bound or the connection ends.
//! - **The mining lane** ([`mining`]): its cache, the new-topic budget,
//!   joins, fair turns, the queue's bounds (deviation `busy`), batches of
//!   256 candidates, the job's 15 s and the stuck-batch watchdog, sans-I/O
//!   for the swarm thread to drive.
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
pub mod mining;
pub mod replies;
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
