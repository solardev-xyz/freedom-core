//! A broadcast (design 0005, Broadcast): today's order and re-sending, with
//! each attempt classed and the outcome taken from all of them (deviation
//! `broadcast-outcome`).
//!
//! - **Attempts** keep the reference's order: Myotis, then Direct's
//!   endpoints one at a time, re-sending the same bytes after any error.
//!   A refusal after an attempt that may have been sent stops the loop, as
//!   Myotis's final verdicts do; it can't erase that attempt.
//! - **Classes:** accepted (the transaction's own hash), refused (an exact
//!   refusal predicate, or Myotis's `rejected`), not sent (main proves it
//!   sent nothing), ambiguous (everything else, an outstanding attempt
//!   included).
//! - **Outcome:** `sent` when an attempt was accepted, `rejected` when none
//!   was accepted or ambiguous and one was refused, `not_sent` when none
//!   may have been sent, `uncertain` otherwise. Before reporting
//!   `uncertain`, the core asks once whether the network knows the hash.

use std::cell::RefCell;
use std::rc::Rc;

use fc_json::index::{Index, Kind};
use fc_naming::session::exec::{Either, race};

use super::config::ms;
use super::ctx::{Release, Req, reply, started};
use super::error::{ErrorClass, Prop, Thrown};
use super::exchange::{answer_error, node_error, transport_error};
use super::io::{Answer, Delivered, Ms, MyotisClass, MyotisReply, Request, VerifiedOp, rpc_body};
use super::read::{MYOTIS_FAILED, ReadOptions, myotis_adapter_error, read};
use crate::answer::{Outcome as AnswerOutcome, decode_answer};
use crate::broadcast::{AttemptClass, broadcast_refusal};
use crate::js::JsString;
use crate::myotis::MYOTIS_NOT_READY;
use crate::text::broadcast_failure_text;
use crate::txhash::{TxHash, transaction_hash};

/// A broadcast's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastOutcome {
    Sent,
    Uncertain,
    Rejected,
    NotSent,
}

impl BroadcastOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Uncertain => "uncertain",
            Self::Rejected => "rejected",
            Self::NotSent => "not_sent",
        }
    }
}

/// One attempt's class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Accepted,
    Refused,
    NotSent,
    Ambiguous,
}

/// What a broadcast has done so far, shared with the machine so that a
/// cancel, a configuration change or a budget can end it through the
/// outcome table.
#[derive(Debug, Default)]
pub(crate) struct SendState {
    pub hash: Option<TxHash>,
    pub attempts: Vec<(&'static str, Class)>,
    /// The attempt in flight, possibly sent from when its request was made.
    pub outstanding: Option<&'static str>,
    pub last_refusal: Option<Thrown>,
    /// Today's last error that wasn't a source being unavailable.
    pub last_rpc_error: Option<Thrown>,
    /// Today's per-broadcaster failures.
    pub failures: Vec<(&'static str, Thrown)>,
}

impl SendState {
    /// The outcome table (design 0005, Outcome), an outstanding attempt
    /// counted as ambiguous.
    pub(crate) fn outcome(&self) -> BroadcastOutcome {
        let classes = self
            .attempts
            .iter()
            .map(|(_, class)| *class)
            .chain(self.outstanding.map(|_| Class::Ambiguous));
        let (mut accepted, mut ambiguous, mut refused) = (false, false, false);
        for class in classes {
            match class {
                Class::Accepted => accepted = true,
                Class::Ambiguous => ambiguous = true,
                Class::Refused => refused = true,
                Class::NotSent => {}
            }
        }
        if accepted {
            BroadcastOutcome::Sent
        } else if ambiguous {
            BroadcastOutcome::Uncertain
        } else if refused {
            BroadcastOutcome::Rejected
        } else {
            BroadcastOutcome::NotSent
        }
    }

    /// The broadcaster of the last attempt that may have been sent.
    pub(crate) fn source(&self) -> &'static str {
        self.outstanding
            .or_else(|| {
                self.attempts
                    .iter()
                    .rev()
                    .find(|(_, class)| *class != Class::NotSent)
                    .map(|(source, _)| *source)
            })
            .unwrap_or("direct")
    }

    /// Whether an attempt so far may have been sent.
    fn possibly_sent(&self) -> bool {
        self.attempts
            .iter()
            .any(|(_, class)| *class == Class::Ambiguous)
    }

    fn record(&mut self, source: &'static str, class: Class) {
        self.outstanding = None;
        self.attempts.push((source, class));
    }

    /// Today's error when every broadcaster failed.
    pub(crate) fn todays_error(&self) -> Thrown {
        if let Some(error) = &self.last_rpc_error {
            return error.clone();
        }
        let parts: Vec<(&str, &[u16])> = self
            .failures
            .iter()
            .map(|(source, error)| (*source, error.message.units()))
            .collect();
        Thrown::of_class(ErrorClass::Error, broadcast_failure_text(&parts))
    }
}

/// How a broadcast ended.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Ended {
    /// `sent` or `uncertain`: `{ hash, source, outcome }`.
    Reported {
        hash: Option<String>,
        source: &'static str,
        outcome: BroadcastOutcome,
    },
    /// `rejected` (the last refusal) or `not_sent` (today's error).
    Failed {
        error: Thrown,
        outcome: BroadcastOutcome,
    },
}

/// What the outcome table gives when a broadcast ends from outside (a
/// cancel, the deadline, a configuration change, a budget): `None` for
/// `not_sent` with no error of today's, so the caller reports its own code.
pub(crate) fn ended_from(state: &SendState) -> Option<Ended> {
    let outcome = state.outcome();
    match outcome {
        BroadcastOutcome::Sent | BroadcastOutcome::Uncertain => Some(Ended::Reported {
            hash: state.hash.map(|h| h.to_hex()),
            source: state.source(),
            outcome,
        }),
        BroadcastOutcome::Rejected => Some(Ended::Failed {
            error: state
                .last_refusal
                .clone()
                .unwrap_or_else(|| state.todays_error()),
            outcome,
        }),
        BroadcastOutcome::NotSent => None,
    }
}

/// `broadcastRawTransaction(chainId, raw)` with the design's outcomes.
/// `stop_at` is when attempts stop (10 s before the deadline), `deadline_at`
/// when reconciliation must be done.
pub(crate) async fn broadcast(
    req: &Req,
    raw: &str,
    state: &RefCell<SendState>,
    stop_at: Ms,
    deadline_at: Ms,
) -> Ended {
    state.borrow_mut().hash = transaction_hash(raw).ok();
    let room = stop_at.saturating_sub(req.now());
    let timer = started(req.ctx.rt.sleep(room));
    let attempts = attempts(req, raw, state);
    let sent = match race(attempts, timer).await {
        Either::Left(sent) => sent,
        // Out of time: the attempt in flight is dropped, and counts as
        // ambiguous.
        Either::Right(()) => None,
    };
    if let Some(source) = sent {
        return Ended::Reported {
            hash: state.borrow().hash.map(|h| h.to_hex()),
            source,
            outcome: BroadcastOutcome::Sent,
        };
    }
    let outcome = state.borrow().outcome();
    match outcome {
        BroadcastOutcome::Uncertain => {
            let hash = state.borrow().hash;
            let room = deadline_at.saturating_sub(req.now());
            let timer = started(req.ctx.rt.sleep(room));
            let found = match hash {
                Some(hash) => matches!(race(reconcile(req, hash), timer).await, Either::Left(true)),
                None => false,
            };
            let state = state.borrow();
            if found {
                Ended::Reported {
                    hash: state.hash.map(|h| h.to_hex()),
                    source: "reconcile",
                    outcome: BroadcastOutcome::Sent,
                }
            } else {
                Ended::Reported {
                    hash: state.hash.map(|h| h.to_hex()),
                    source: state.source(),
                    outcome,
                }
            }
        }
        BroadcastOutcome::Rejected => {
            let state = state.borrow();
            Ended::Failed {
                error: state
                    .last_refusal
                    .clone()
                    .unwrap_or_else(|| state.todays_error()),
                outcome,
            }
        }
        BroadcastOutcome::NotSent | BroadcastOutcome::Sent => Ended::Failed {
            error: state.borrow().todays_error(),
            outcome: BroadcastOutcome::NotSent,
        },
    }
}

/// The attempt loop: the source that accepted, or `None`.
async fn attempts(req: &Req, raw: &str, state: &RefCell<SendState>) -> Option<&'static str> {
    let chain = Rc::clone(&req.chain);
    for &source in &chain.broadcast_order {
        let stop = match source {
            "myotis" => myotis(req, raw, state).await,
            "direct" => direct(req, raw, state).await,
            _ => {
                let error =
                    Thrown::unavailable(format!("{source} cannot broadcast transactions").as_str());
                state.borrow_mut().failures.push((source, error));
                Step::Next
            }
        };
        match stop {
            Step::Accepted => return Some(source),
            Step::Stop => return None,
            Step::Next => {}
        }
    }
    None
}

enum Step {
    Accepted,
    Stop,
    Next,
}

/// Records a failure as today's loop does.
fn fail(state: &RefCell<SendState>, source: &'static str, error: Thrown) {
    let mut state = state.borrow_mut();
    if !error.is_unavailable() {
        state.last_rpc_error = Some(error.clone());
    }
    state.failures.push((source, error));
}

/// Myotis's `sendRawTransaction`: `rejected` and `uncertain` end the loop,
/// `not_sent` falls to the next broadcaster.
async fn myotis(req: &Req, raw: &str, state: &RefCell<SendState>) -> Step {
    let chain_id = req.chain.chain_id;
    if !req.ctx.ready(chain_id) {
        fail(state, "myotis", Thrown::unavailable(MYOTIS_NOT_READY));
        return Step::Next;
    }
    state.borrow_mut().outstanding = Some("myotis");
    let cell = req.ctx.hold(
        Request::Verified(VerifiedOp::MyotisBroadcast {
            chain_id,
            raw: raw.to_owned(),
        }),
        Release::Nothing,
    );
    let Delivered { answer, .. } = reply(&cell).await;
    let hash = state.borrow().hash;
    match answer {
        Answer::Myotis(MyotisReply::Sent { hash: sent }) => {
            if hash.is_some() && TxHash::from_json(&sent) == hash {
                state.borrow_mut().record("myotis", Class::Accepted);
                Step::Accepted
            } else {
                // Today a success with another hash ends the loop.
                state.borrow_mut().record("myotis", Class::Ambiguous);
                Step::Stop
            }
        }
        Answer::Myotis(MyotisReply::Rejected { reason }) => {
            let error = Thrown::error(&reason)
                .with("code", Prop::Json("-32000".into()))
                .with("myotisRefusal", Prop::string("rejected"));
            let mut state = state.borrow_mut();
            state.record("myotis", Class::Refused);
            state.last_refusal = Some(error);
            Step::Stop
        }
        Answer::Myotis(MyotisReply::Uncertain) => {
            state.borrow_mut().record("myotis", Class::Ambiguous);
            Step::Stop
        }
        Answer::Myotis(MyotisReply::NotSent) | Answer::NotSent => {
            state.borrow_mut().record("myotis", Class::NotSent);
            fail(state, "myotis", Thrown::error(MYOTIS_FAILED));
            Step::Next
        }
        Answer::Myotis(MyotisReply::Failure(class)) => {
            // Never dispatched: the client wasn't running or ready, or the
            // read queue refused it. Anything else may have been.
            let not_sent = matches!(
                class,
                MyotisClass::NotRunning
                    | MyotisClass::NotReady
                    | MyotisClass::QueueFull
                    | MyotisClass::QueueDeadline
            );
            let class_of = if not_sent {
                Class::NotSent
            } else {
                Class::Ambiguous
            };
            state.borrow_mut().record("myotis", class_of);
            fail(state, "myotis", myotis_adapter_error(req, class));
            Step::Next
        }
        _ => {
            state.borrow_mut().record("myotis", Class::Ambiguous);
            fail(state, "myotis", Thrown::error(MYOTIS_FAILED));
            Step::Next
        }
    }
}

/// Direct: every endpoint in turn, the same bytes, until one accepts.
async fn direct(req: &Req, raw: &str, state: &RefCell<SendState>) -> Step {
    let urls = req.chain.urls();
    if urls.is_empty() {
        fail(
            state,
            "direct",
            Thrown::unavailable("No RPC endpoint configured"),
        );
        return Step::Next;
    }
    let timeout = req.chain.timeout;
    let params = format!("[{}]", JsString::from(raw).to_json());
    let mut last: Option<Thrown> = None;
    let mut stopped = false;
    for url in &urls {
        let earlier_ambiguous = state.borrow().possibly_sent();
        state.borrow_mut().outstanding = Some("direct");
        let timer = started(req.ctx.rt.sleep(ms(timeout)));
        let io = req.ctx.rt.request(Request::Rpc {
            endpoint: url.clone(),
            body: rpc_body(req.next_rpc_id(), "eth_sendRawTransaction", &params),
            max_bytes: req.ctx.bounds.answer_bytes,
            deadline_ms: ms(timeout),
        });
        let (class, error) = match race(io, timer).await {
            Either::Left(Delivered { answer, .. }) => attempt(req, state, answer, timeout),
            Either::Right(()) => (Class::Ambiguous, Some(Thrown::rpc_timeout(timeout))),
        };
        state.borrow_mut().record("direct", class);
        match (class, error) {
            (Class::Accepted, _) => return Step::Accepted,
            // Today any success ends the loop; another hash is ambiguous.
            (Class::Ambiguous, None) => return Step::Stop,
            (Class::Refused, Some(error)) => {
                state.borrow_mut().last_refusal = Some(error.clone());
                last = Some(error);
                if earlier_ambiguous {
                    stopped = true;
                    break;
                }
            }
            (_, error) => last = error.or(last),
        }
    }
    if let Some(error) = last {
        fail(state, "direct", error);
    }
    if stopped { Step::Stop } else { Step::Next }
}

/// One Direct attempt's class, and today's error for it.
fn attempt(
    req: &Req,
    state: &RefCell<SendState>,
    answer: Answer,
    timeout: f64,
) -> (Class, Option<Thrown>) {
    match answer {
        Answer::Rpc { status, body } => {
            let decoded = decode_answer(status, body);
            let hash = state.borrow().hash;
            let class = match hash {
                Some(hash) => crate::broadcast::classify_broadcast_answer(&hash, &decoded),
                None => match &decoded {
                    Ok(answer) => match answer.outcome() {
                        AnswerOutcome::NodeError(error) => {
                            broadcast_refusal(error.code, error.message.units())
                                .map_or(AttemptClass::Ambiguous, AttemptClass::Refused)
                        }
                        AnswerOutcome::Result(_) => AttemptClass::Ambiguous,
                    },
                    Err(_) => AttemptClass::Ambiguous,
                },
            };
            let error = match &decoded {
                Ok(answer) => match answer.outcome() {
                    AnswerOutcome::NodeError(error) => Some(node_error(req, &error)),
                    AnswerOutcome::Result(_) => None,
                },
                Err(error) => Some(answer_error(error.clone())),
            };
            let class = match class {
                AttemptClass::Accepted => Class::Accepted,
                AttemptClass::Refused(_) => Class::Refused,
                AttemptClass::Ambiguous => Class::Ambiguous,
            };
            (class, error)
        }
        Answer::NotSent => (
            Class::NotSent,
            Some(Thrown::error(super::exchange::NOT_SENT)),
        ),
        Answer::Failed(transport) => (Class::Ambiguous, Some(transport_error(transport, timeout))),
        _ => (
            Class::Ambiguous,
            Some(Thrown::error(super::exchange::NOT_SENT)),
        ),
    }
}

/// Reconciliation: `eth_getTransactionByHash` as a non-interactive read
/// through the read order. A result whose `hash` is the transaction's
/// makes the outcome `sent`; anything else leaves it.
async fn reconcile(req: &Req, hash: TxHash) -> bool {
    let params = format!("[\"{}\"]", hash.to_hex());
    let Ok(answer) = Box::pin(read(
        req,
        "eth_getTransactionByHash",
        &params,
        &ReadOptions::default(),
    ))
    .await
    else {
        return false;
    };
    let Some(text) = answer.result else {
        return false;
    };
    let Ok(index) = Index::new(text.json()) else {
        return false;
    };
    let root = index.root();
    if root.kind() != Kind::Object {
        return false;
    }
    root.get("hash")
        .is_some_and(|found| TxHash::from_json(found.raw()) == Some(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(attempts: &[Class], outstanding: bool) -> SendState {
        SendState {
            attempts: attempts.iter().map(|c| ("direct", *c)).collect(),
            outstanding: outstanding.then_some("direct"),
            ..SendState::default()
        }
    }

    #[test]
    fn the_outcome_table() {
        use BroadcastOutcome as O;
        use Class as C;
        assert_eq!(with(&[], false).outcome(), O::NotSent);
        assert_eq!(with(&[C::NotSent, C::NotSent], false).outcome(), O::NotSent);
        assert_eq!(
            with(&[C::Refused, C::NotSent], false).outcome(),
            O::Rejected
        );
        // A refusal can't erase an ambiguous attempt, in either order.
        assert_eq!(
            with(&[C::Ambiguous, C::Refused], false).outcome(),
            O::Uncertain
        );
        assert_eq!(
            with(&[C::Refused, C::Ambiguous], false).outcome(),
            O::Uncertain
        );
        assert_eq!(with(&[C::Refused, C::Accepted], false).outcome(), O::Sent);
        // An outstanding attempt is possibly sent.
        assert_eq!(with(&[], true).outcome(), O::Uncertain);
        assert_eq!(with(&[C::Refused], true).outcome(), O::Uncertain);
    }
}
