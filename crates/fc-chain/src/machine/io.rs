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

/// Which of the Myotis adapter's definite refusals a broadcast's
/// `rejected` is (design 0005, The rest): a closed set, each with the
/// code and `myotisRefusal` marker the adapter throws it with. Neither
/// sent anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MyotisRejection {
    /// The client judged the transaction unpayable or its nonce used, on
    /// verified state (ABI 36): geth's `-32000`, `rejected`.
    Rejected,
    /// Bytes that are no transaction Myotis relays (ABI 44): the
    /// permanent `-32602`, `invalid-params`.
    InvalidParams,
}

impl MyotisRejection {
    /// The error's `code`.
    pub fn code(self) -> i32 {
        match self {
            Self::Rejected => -32000,
            Self::InvalidParams => -32602,
        }
    }

    /// The error's `myotisRefusal`.
    pub fn marker(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::InvalidParams => "invalid-params",
        }
    }
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
    /// One of the adapter's definite refusals, which sent nothing: its
    /// reason, and which refusal it was.
    Rejected {
        reason: String,
        kind: MyotisRejection,
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

/// A Colibri operation's outcome (design 0005, Verified operations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColibriReply {
    /// The verified result, as JSON.
    Result(String),
    /// A verified result of `undefined`, which JSON can't carry: the read's
    /// result is `undefined`, as today.
    Undefined,
    /// A revert the prover verified: code 3 and its hex data. `capacity`
    /// when the adapter's error is also a capacity failure: the read
    /// rejects with the revert, and the app's Colibri route is blocked as
    /// for any capacity failure. `fault` as for a failure.
    Revert {
        data: String,
        capacity: bool,
        fault: bool,
    },
    /// Any other failure, by class. `fault` when main marked it a verifier
    /// fault (main's `isColibriFault`), which counts toward the backoff of
    /// its chain and method (design 0005, Colibri).
    Failure { class: ColibriClass, fault: bool },
}

/// What a terminal reply means for a Colibri operation's fault record
/// (design 0005, Colibri: verifier faults): an answer deletes it, a fault
/// counts, anything else leaves it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Verdict {
    #[default]
    Neither,
    Answer,
    Fault,
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
    /// The bytes it holds, as the budget counts them: each buffer's
    /// capacity.
    pub fn bytes(&self) -> usize {
        match self {
            Self::Rpc { body, .. } => body.capacity(),
            // The vector's places too, which it keeps whoever fills them.
            Self::Blockscout { headers, body, .. } => headers
                .iter()
                .map(|(k, v)| k.capacity() + v.capacity())
                .sum::<usize>()
                .saturating_add(
                    headers
                        .capacity()
                        .saturating_mul(std::mem::size_of::<(String, String)>()),
                )
                .saturating_add(body.capacity()),
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
                MyotisReply::Rejected { reason, .. } => reason.len(),
                _ => 0,
            },
            Self::Colibri(reply) => match reply {
                ColibriReply::Result(text) | ColibriReply::Revert { data: text, .. } => {
                    text.capacity()
                }
                ColibriReply::Undefined | ColibriReply::Failure { .. } => 0,
            },
        }
    }

    /// What it means for a Colibri operation's fault record: a result
    /// (`undefined` included) is an answer; a revert or a failure main
    /// marked `fault` is a fault. `too_large` is neither: main couldn't
    /// send the result, and can't have it told from an oversized revert.
    pub fn verdict(&self) -> Verdict {
        match self {
            Self::Colibri(ColibriReply::Result(_) | ColibriReply::Undefined) => Verdict::Answer,
            Self::Colibri(
                ColibriReply::Revert { fault: true, .. }
                | ColibriReply::Failure { fault: true, .. },
            ) => Verdict::Fault,
            _ => Verdict::Neither,
        }
    }
}

/// An answer as the machine's futures receive it: with its charge against
/// the request's budget, released when the answer is.
#[derive(Debug)]
pub struct Delivered {
    pub answer: Answer,
    pub(crate) charge: super::budget::Charge,
    /// Main's terminal reply arrived, but its payload was over its
    /// request's budget: it completes the operation (freeing a verifier's
    /// slot) and is dropped.
    pub(crate) discarded: bool,
    /// What it means for a Colibri operation's fault record, kept when the
    /// payload is dropped: a reply counts when it arrives, read or not.
    pub(crate) verdict: Verdict,
}

impl Request {
    /// The bytes it holds, as the budget counts them.
    pub(crate) fn bytes(&self) -> usize {
        match self {
            Self::Rpc { endpoint, body, .. } => endpoint.capacity() + body.capacity(),
            Self::Blockscout {
                endpoint, query, ..
            } => endpoint.capacity() + query.capacity(),
            Self::Verified(VerifiedOp::MyotisRead { operation, .. }) => match operation {
                MyotisOperation::Account { address } | MyotisOperation::Code { address } => {
                    address.as_ref().map_or(0, String::capacity)
                }
                MyotisOperation::Storage { address, slot } => {
                    address.as_ref().map_or(0, String::capacity)
                        + slot.as_ref().map_or(0, String::capacity)
                }
                MyotisOperation::CallTx { tx } | MyotisOperation::EstimateTx { tx } => {
                    tx.capacity()
                }
                MyotisOperation::Fee => 0,
            },
            Self::Verified(VerifiedOp::MyotisBroadcast { raw, .. }) => raw.capacity(),
            Self::Verified(VerifiedOp::Colibri { method, params, .. }) => {
                method.capacity() + params.capacity()
            }
        }
    }

    /// Whether it sends a transaction: a broadcast's attempt, Direct's
    /// `eth_sendRawTransaction` or Myotis's `broadcast`. None starts at or
    /// after its broadcast's attempt cutoff (design 0005, Deadlines); a
    /// reconciliation read may, until the broadcast's deadline. Reads never
    /// send `eth_sendRawTransaction` ([`crate::is_read_method`]).
    pub fn sends_transaction(&self) -> bool {
        match self {
            Self::Rpc { body, .. } => rpc_method_is(body, "eth_sendRawTransaction"),
            Self::Verified(VerifiedOp::MyotisBroadcast { .. }) => true,
            Self::Verified(VerifiedOp::MyotisRead { .. } | VerifiedOp::Colibri { .. })
            | Self::Blockscout { .. } => false,
        }
    }
}

/// Whether `body`, as [`rpc_body`] makes it, calls `method`: a name of the
/// core's own, which needs no escaping.
fn rpc_method_is(body: &str, method: &str) -> bool {
    let Some(rest) = body.strip_prefix(r#"{"jsonrpc":"2.0","id":"#) else {
        return false;
    };
    let rest = rest.trim_start_matches(|c: char| c.is_ascii_digit());
    rest.strip_prefix(r#","method":""#)
        .and_then(|rest| rest.strip_prefix(method))
        .is_some_and(|rest| rest.starts_with(r#"","params":"#))
}

/// The length of [`rpc_body`]'s text, known before it is made.
pub(crate) fn rpc_body_len(id: u64, method: &str, params: &str) -> usize {
    r#"{"jsonrpc":"2.0","id":,"method":,"params":}"#.len()
        + id.to_string().len()
        + crate::js::JsString::from(method).to_json().len()
        + params.len()
}

/// The JSON-RPC body of one exchange, in a buffer of exactly its length.
pub(crate) fn rpc_body(id: u64, method: &str, params: &str) -> String {
    let mut body = String::with_capacity(rpc_body_len(id, method, params));
    body.push_str(r#"{"jsonrpc":"2.0","id":"#);
    body.push_str(&id.to_string());
    body.push_str(r#","method":"#);
    body.push_str(&crate::js::JsString::from(method).to_json());
    body.push_str(r#","params":"#);
    body.push_str(params);
    body.push('}');
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_broadcasts_attempts_send_a_transaction() {
        let rpc = |method: &str, params: &str| Request::Rpc {
            endpoint: "e1".into(),
            body: rpc_body(12, method, params),
            max_bytes: 1,
            deadline_ms: 5000,
        };
        assert!(rpc("eth_sendRawTransaction", r#"["0x01"]"#).sends_transaction());
        // Reconciliation, and a method that only starts the same.
        assert!(!rpc("eth_getTransactionByHash", r#"["0x01"]"#).sends_transaction());
        assert!(!rpc("eth_sendRawTransactionX", "[]").sends_transaction());
        assert!(!rpc("eth_send", "[]").sends_transaction());
        assert!(
            Request::Verified(VerifiedOp::MyotisBroadcast {
                chain_id: 1,
                raw: "0x01".into(),
            })
            .sends_transaction()
        );
        assert!(
            !Request::Verified(VerifiedOp::MyotisRead {
                chain_id: 1,
                operation: MyotisOperation::Fee,
            })
            .sends_transaction()
        );
    }

    #[test]
    fn a_pages_answer_counts_its_headers_places() {
        let mut headers = Vec::with_capacity(8);
        headers.push(("retry-after".to_owned(), "3".to_owned()));
        let answer = Answer::Blockscout {
            status: 429,
            headers,
            body: Vec::new(),
        };
        let strings = "retry-after".len() + "3".len();
        assert!(answer.bytes() >= strings + 8 * std::mem::size_of::<(String, String)>());
    }

    #[test]
    fn a_body_is_made_in_a_buffer_of_its_length() {
        let body = rpc_body(12, "eth_call", r#"[{"to":"0x1"},"latest"]"#);
        assert_eq!(
            body,
            r#"{"jsonrpc":"2.0","id":12,"method":"eth_call","params":[{"to":"0x1"},"latest"]}"#
        );
        assert_eq!(
            body.capacity(),
            rpc_body_len(12, "eth_call", r#"[{"to":"0x1"},"latest"]"#)
        );
        assert_eq!(body.len(), body.capacity());
    }
}
