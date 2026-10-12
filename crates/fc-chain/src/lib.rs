//! Chain data for Freedom (design 0005): the codecs of freedom-browser's
//! chain-data router, with its behavior byte for byte. `vectors/chain.json`,
//! produced by the pinned JS, is the contract.
//!
//! - `normalizeParams` for call objects: [`normalize_params`].
//! - An RPC answer as `requestRpcUrl` reads it: [`decode_answer`].
//! - Agreement between answers, as SHA-256 of `stableValue`:
//!   [`stable_digest`].
//! - `feeQuote`: [`fee_quote`].
//! - `safeErrorMessage` and the aggregate failure texts:
//!   [`safe_error_message`], [`request_failure_text`].
//! - Myotis reads: the gates, the payload classification and the trust
//!   block: [`myotis_operation`], [`myotis_answer`], [`myotis_trust`].
//! - The Ant profile's error ranking and range caps:
//!   [`rank_log_scan_error`], [`log_scan_range_cap`], with
//!   [`log_query_span`] and the range refusal ([`log_range_refusal_text`]).
//! - A broadcast's hash: [`transaction_hash`].
//!
//! Deviations, each pinned by vectors: `json-depth` (nesting deeper than
//! 512 levels is refused), `json-parse-text` (a fixed text for a body that
//! isn't JSON), `bigint-width` (decimal input, gas prices and Myotis
//! numbers wider than 4096 bits are refused).
//!
//! The crate does no I/O.

mod answer;
mod ant;
mod bigint;
mod fee;
mod js;
mod logs;
mod myotis;
mod normalize;
mod pattern;
mod stable;
mod text;
mod txhash;

pub use answer::{
    Answer, AnswerError, JSON_DEPTH_FAILURE, JSON_PARSE_FAILURE, NodeError, Outcome, decode_answer,
};
pub use ant::{
    ANT_EXCLUDE_SOURCES, ANT_INCLUDE_SOURCES, ANT_LOG_SCAN_SHRINK_NEEDLES, ErrorRank,
    LOG_SCAN_QUORUM_TIMEOUT_MS, ReceivedError, ant_shrinks_log_scan_on, log_scan_range_cap,
    rank_log_scan_error,
};
pub use bigint::MAX_DECIMAL_BITS;
pub use fee::{FeeQuote, fee_quote};
pub use js::{JsError, JsString, is_js_whitespace};
pub use logs::{
    LOG_RANGE_CAP_TTL_MS, LOG_RANGE_REFUSAL_CODE, LOG_SCAN_COOLDOWN_MS, LOG_SCAN_QUORUM_ROUNDS,
    LOG_TRUNCATION_MIN_SPAN, LOG_TRUNCATION_TAIL_BLOCKS, log_query_span, log_range_refusal_text,
};
pub use myotis::{
    MAX_MYOTIS_REFUSAL_MESSAGE, MYOTIS_BLOB_FIELDS, MYOTIS_NOT_READY, MYOTIS_PROOF, MyotisFailure,
    MyotisOperation, MyotisRefusal, MyotisVerdict, myotis_answer, myotis_operation, myotis_trust,
    myotis_trust_block,
};
pub use normalize::{Normalized, normalize_params};
pub use stable::{StableDigest, stable_digest, stable_value, value_digest};
pub use text::{
    SourceFailure, broadcast_failure_text, fee_quote_failure_text, request_failure_text,
    safe_error_message,
};
pub use txhash::{NotHex, TxHash, transaction_hash};
