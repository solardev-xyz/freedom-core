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
//! - A broadcast's hash: [`transaction_hash`].
//!
//! Deviations, each pinned by vectors: `json-depth` (nesting deeper than
//! 512 levels is refused), `json-parse-text` (a fixed text for a body that
//! isn't JSON), `bigint-width` (decimal input, gas prices and Myotis
//! numbers wider than 4096 bits are refused).
//!
//! The crate does no I/O.

mod answer;
mod bigint;
mod fee;
mod js;
mod myotis;
mod normalize;
mod pattern;
mod stable;
mod text;
mod txhash;

pub use answer::{
    Answer, AnswerError, JSON_DEPTH_FAILURE, JSON_PARSE_FAILURE, NodeError, Outcome, decode_answer,
};
pub use bigint::MAX_DECIMAL_BITS;
pub use fee::{FeeQuote, fee_quote};
pub use js::{JsError, JsString, is_js_whitespace};
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
