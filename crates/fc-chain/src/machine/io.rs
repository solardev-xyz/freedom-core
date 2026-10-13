//! What the machine asks main for, and main's replies (design 0005, Requests
//! the core makes, Verified operations).

use crate::myotis::MyotisOperation;

pub use fc_naming::session::exec::Ms;

/// An opaque endpoint reference (design 0004, Configuration): main maps it
/// to a URL. The core is never given one.
pub type Endpoint = String;

/// A `shell.*` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `shell.rpc` with `policy: "plain"`: one JSON-RPC exchange, no 429
    /// back-off and no repeated attempts.
    Rpc {
        endpoint: Endpoint,
        /// `JSON.stringify({ jsonrpc: '2.0', id, method, params })`, with
        /// `id` a per-request counter (deviation `rpc-id`).
        body: String,
        /// The answer cap the core accepts (deviation `response-caps`).
        max_bytes: usize,
        /// When main gives up on the exchange; the core's own timer for it
        /// ends at the same time.
        deadline_ms: Ms,
    },
    /// `shell.verified`: a whole verifier operation through today's
    /// adapter.
    Verified(VerifiedOp),
    /// `shell.blockscout`: one page of Blockscout's log index, through
    /// `blockscout-logs.js`'s redirect and address policy.
    Blockscout {
        endpoint: Endpoint,
        /// The page's path and query.
        query: String,
        max_bytes: usize,
        deadline_ms: Ms,
    },
}

/// A verifier operation (design 0005, Verified operations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedOp {
    /// A Myotis read; main samples the optimistic head before and after.
    MyotisRead {
        chain_id: u64,
        operation: MyotisOperation,
    },
    /// `sendRawTransaction`.
    MyotisBroadcast { chain_id: u64, raw: String },
    /// `requestViaColibri(chain, method, params, { deadlineMs })`.
    Colibri {
        chain_id: u64,
        method: String,
        /// The request's normalized params, as JSON.
        params: String,
        deadline_ms: Ms,
    },
}

/// A transport failure: no text, no URL (design 0004, Transport errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Main's own deadline for the exchange.
    Timeout,
    /// DNS, connect, TLS or a reset: what undici reports as `fetch failed`.
    Network,
    /// The URL or a redirect hop failed main's policy.
    Refused,
    /// The answer exceeded `max_bytes`.
    TooLarge,
    /// Main's chain I/O pool is full (design 0005, Main's pool).
    Busy,
}

/// The closed set of failure classes of a Myotis operation (design 0005,
/// Myotis read outcomes). They carry no text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MyotisClass {
    NotRunning,
    NotReady,
    StateChanged,
    QueueFull,
    QueueDeadline,
    CallerDeadline,
    TooLarge,
    Busy,
    /// Any other throw.
    Error,
}

/// A Myotis operation's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MyotisReply {
    /// A read's payload (the adapter's JSON, snake_case keys) and the
    /// optimistic block number before and after it, as JSON (`None` when
    /// the status had none).
    Read {
        payload: String,
        block_before: Option<String>,
        block_after: Option<String>,
    },
    /// A broadcast's transaction hash, as the client returned it (JSON).
    Sent {
        hash: String,
    },
    /// The client judged the transaction unpayable or its nonce used, and
    /// sent nothing (its reason).
    Rejected {
        reason: String,
    },
    /// Dispatched, then a deadline, an exit or a stop; or an answer
    /// without a hash.
    Uncertain,
    /// Queued and expired, or the client wasn't running.
    NotSent,
    Failure(MyotisClass),
}

/// A Colibri failure's class. `Capacity` is the one bit of the adapter's
/// text the adaptive bypass needs: main sets it where the router's
/// `isCapacityFailure` matches the error (see the design-versus-vector
/// notes in the replay test).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColibriClass {
    Capacity,
    TooLarge,
    Busy,
    Error,
}

/// A Colibri operation's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColibriReply {
    /// The verified result, as JSON.
    Result(String),
    /// A revert the prover verified: code 3 and its hex data.
    Revert {
        data: String,
    },
    Failure(ColibriClass),
}

/// Main's terminal reply to a `shell.*` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The exchange's HTTP answer.
    Rpc {
        status: u16,
        body: Vec<u8>,
    },
    /// A Blockscout page's last hop.
    Blockscout {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// Main performed nothing: a stale generation, a cancel before the
    /// exchange started, or an endpoint refused before connecting. No byte
    /// of the request left main.
    NotSent,
    Failed(Transport),
    Myotis(MyotisReply),
    Colibri(ColibriReply),
}

impl Answer {
    /// The bytes it holds, as the budget counts them.
    pub fn bytes(&self) -> usize {
        match self {
            Self::Rpc { body, .. } => body.len(),
            Self::Blockscout { headers, body, .. } => headers
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
                .saturating_add(body.len()),
            Self::NotSent | Self::Failed(_) => 0,
            Self::Myotis(reply) => match reply {
                MyotisReply::Read {
                    payload,
                    block_before,
                    block_after,
                } => {
                    payload.len()
                        + block_before.as_ref().map_or(0, String::len)
                        + block_after.as_ref().map_or(0, String::len)
                }
                MyotisReply::Sent { hash } => hash.len(),
                MyotisReply::Rejected { reason } => reason.len(),
                _ => 0,
            },
            Self::Colibri(reply) => match reply {
                ColibriReply::Result(text) | ColibriReply::Revert { data: text } => text.len(),
                ColibriReply::Failure(_) => 0,
            },
        }
    }
}

/// An answer as the machine's futures receive it: with its charge against
/// the request's budget, released when the answer is.
#[derive(Debug)]
pub struct Delivered {
    pub answer: Answer,
    pub(crate) charge: super::budget::Charge,
}

/// The JSON-RPC body of one exchange.
pub(crate) fn rpc_body(id: u64, method: &str, params: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":{},"params":{params}}}"#,
        crate::js::JsString::from(method).to_json()
    )
}
