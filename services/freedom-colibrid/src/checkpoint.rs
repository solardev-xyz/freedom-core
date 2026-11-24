//! `colibri.checkpoint` (design 0014, "Methods main calls"): the one-shot
//! process's check, as `checkpoint-verifier-worker.js` makes it today.
//! 1. The proof: a `checkpoint_proof` fetch, which main makes itself from
//!    the prover (4 MiB at most); the service asks for it and takes
//!    nothing else from it.
//! 2. Decoded (`c4_decode_proof`, which checks the bytes first).
//! 3. Verified as `eth_getBlockByNumber ["latest",false]` on the memory
//!    store, at main's freshness bound. Its `checkpointz` fetches main
//!    answers from its quorum.
//!
//! The reply is `{ decoded, result }`, both as the C core wrote them, or
//! `{ status: "error", stage, error }`, `stage` being where it failed
//! (`decode` or `verify`), so main keeps its own classes. No proof at all
//! counts as one that doesn't decode.
//!
//! As for a request, every call into the C core has its own marker (the
//! decoding, the verifier's creation and freshness bound, each step, each
//! answer and the free), and a cancel is checked after each. The verifier
//! is freed before the reply, or kept until exit if its free can't be
//! marked. Then the process ends.

use std::rc::Rc;
use std::time::{Duration, Instant};

use colibri_stateless::{Step, Verifier};
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::Exit;
use serde::Deserialize;
use serde_json::json;
use serde_json::value::RawValue;

use crate::request::{
    Env, FetchBudget, Fetched, PendingStatus, RawRequest, Reply, Stop, SuccessStatus, TaskState,
    VERIFY_FLAGS, all_unless_cancelled, cancelled, cut_error, fetch, send_reply,
};

/// The proof: the fetch contract's `checkpoint_proof`, 4 MiB at most.
const MAX_PROOF: u64 = 4 << 20;
/// Any other body a check fetches: 64 KiB.
const MAX_OTHER: u64 = 64 << 10;
/// What the verifier is asked, as the worker asks it.
const METHOD: &str = "eth_getBlockByNumber";
const ARGS: &str = r#"["latest",false]"#;
/// The decoder's refusal, as the WASM binding throws it.
const UNKNOWN_PROOF: &str = "Unknown proof format";

/// `colibri.checkpoint`'s params.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    pub min_latest_block_ts: u64,
    pub deadline_ms: u64,
}

impl Params {
    /// The check's deadline, if the clock can hold it.
    pub fn deadline(&self) -> Option<Instant> {
        Instant::now().checked_add(Duration::from_millis(self.deadline_ms))
    }
}

/// `{status:"error",stage,error}`, the error cut as a request's is
/// (64 Ki UTF-16 units).
fn failed(stage: &str, error: &str) -> Reply {
    Reply::Raw(json!({ "status": "error", "stage": stage, "error": cut_error(error) }).to_string())
}

/// Past the checkpoint process's resident memory: the check fails (it
/// doesn't recycle).
const OVER_RESIDENT: &str = "resident memory past the checkpoint process's budget";

/// Runs check `id` to its reply, then ends the process.
pub async fn run(env: Rc<Env>, id: u64, params: Params, state: Rc<TaskState>) {
    let reply = check(&env, id, &params, &state).await;
    send_reply(&env, id, reply);
    env.shared.request_done();
    // One check per process (0014, "Spawn"): the reply flushes, then the
    // process exits 0.
    env.conn.fail(Exit::Ok);
}

/// Ends the check with `reply`: the verifier freed behind its marker first.
/// A cancel seen meanwhile wins.
async fn end(env: &Env, id: u64, state: &TaskState, verifier: Verifier, reply: Reply) -> Reply {
    if let Err(stop) = env.free_all(id, state, vec![verifier]).await {
        return stop.reply();
    }
    if state.cancelled.get() {
        cancelled(state)
    } else {
        reply
    }
}

/// Stops a check whose marker wasn't written: the verifier is kept until
/// exit, never freed unmarked.
fn stop(env: &Env, verifier: Verifier, stop: Stop) -> Reply {
    env.bury([verifier]);
    stop.reply()
}

#[allow(clippy::too_many_lines)]
async fn check(env: &Rc<Env>, id: u64, p: &Params, state: &Rc<TaskState>) -> Reply {
    if state.cancelled.get() {
        return cancelled(state);
    }
    let Some(deadline) = p.deadline() else {
        return Reply::Error(ErrorBody::new(
            ErrorCode::InvalidArgument,
            "deadline_ms is past what the clock holds",
        ));
    };
    // The check's fetches, the proof's included, share one budget (0014,
    // Budgets: 1,024 per request in all).
    let mut budget = FetchBudget::default();
    let proof_request = RawRequest::own("checkpoint_proof", "post", "ssz");
    let over = !budget.take();
    let proof_fetch: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = Fetched> + '_>>> =
        vec![Box::pin(fetch(
            env,
            id,
            &proof_request,
            0,
            0,
            0,
            deadline,
            over,
            MAX_PROOF,
        ))];
    // A cancel ends the wait, and drops the ask with main.
    let Some(mut proof) = all_unless_cancelled(proof_fetch, state).await else {
        return cancelled(state);
    };
    let proof = match proof.pop() {
        Some(Ok((bytes, _, _hold))) => bytes,
        Some(Err(text)) => return failed("decode", &text),
        None => return failed("decode", "no proof"),
    };
    if state.cancelled.get() {
        return cancelled(state);
    }
    let decoded = match env
        .call(id, state, "decode", || {
            colibri_stateless::decode_proof(&proof)
        })
        .await
    {
        Ok(decoded) => decoded,
        Err(stop) => return stop.reply(),
    };
    env.shared.step_done();
    if state.cancelled.get() {
        return cancelled(state);
    }
    if env.shared.over_resident() {
        return failed("decode", OVER_RESIDENT);
    }
    let Some(decoded) = decoded else {
        return failed("decode", UNKNOWN_PROOF);
    };
    if RawValue::from_string(decoded.clone()).is_err() {
        return failed("decode", "the decoded proof isn't JSON");
    }
    let chain = env.shared.chain_id;
    let created = match env
        .call(id, state, "create", || {
            crate::testhooks::in_create();
            Verifier::new(&proof, METHOD, ARGS, chain, None, VERIFY_FLAGS)
        })
        .await
    {
        Ok(created) => created,
        Err(stop) => return stop.reply(),
    };
    // A cancel queued during the creation wins over its outcome.
    let mut verifier = match created {
        Ok(verifier) if state.cancelled.get() => {
            return end(env, id, state, verifier, cancelled(state)).await;
        }
        Ok(verifier) => verifier,
        Err(_) if state.cancelled.get() => return cancelled(state),
        Err(e) => return failed("verify", &e.to_string()),
    };
    let min = p.min_latest_block_ts;
    if let Err(e) = env
        .call(id, state, "freshness", || {
            verifier.set_min_latest_block_ts(min)
        })
        .await
    {
        return stop(env, verifier, e);
    }
    if state.cancelled.get() {
        return end(env, id, state, verifier, cancelled(state)).await;
    }
    loop {
        let outcome = match env
            .call(id, state, "execute", || {
                crate::testhooks::in_step();
                verifier.execute_with_status()
            })
            .await
        {
            Ok(outcome) => outcome,
            Err(e) => return stop(env, verifier, e),
        };
        env.shared.step_done();
        let (step, status) = match outcome {
            Ok(step) => step,
            Err(e) => {
                let reply = failed("verify", &e.to_string());
                return end(env, id, state, verifier, reply).await;
            }
        };
        if state.cancelled.get() {
            drop(step);
            return end(env, id, state, verifier, cancelled(state)).await;
        }
        if env.shared.over_resident() {
            drop(step);
            let reply = failed("verify", OVER_RESIDENT);
            return end(env, id, state, verifier, reply).await;
        }
        let requests = match step {
            Step::Success { .. } => {
                let result = match serde_json::from_str::<SuccessStatus<'_>>(&status) {
                    Ok(SuccessStatus {
                        result: Some(result),
                    }) => result.get().to_owned(),
                    _ => "null".to_owned(),
                };
                let reply = Reply::Raw(format!(r#"{{"decoded":{decoded},"result":{result}}}"#));
                return end(env, id, state, verifier, reply).await;
            }
            Step::Revert { data } => {
                let reply = failed("verify", &format!("execution reverted: {data}"));
                return end(env, id, state, verifier, reply).await;
            }
            Step::Error { message } => {
                let reply = failed("verify", &message);
                return end(env, id, state, verifier, reply).await;
            }
            Step::Pending { requests } => requests,
        };
        let raw = match serde_json::from_str::<PendingStatus<'_>>(&status) {
            Ok(raw) if raw.requests.len() == requests.len() => raw.requests,
            _ => {
                drop(requests);
                let reply = failed("verify", "the C core's pending requests don't parse");
                return end(env, id, state, verifier, reply).await;
            }
        };
        let mut fetches: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = Fetched> + '_>>> =
            Vec::new();
        for (request, fields) in requests.iter().zip(&raw) {
            let over = !budget.take();
            fetches.push(Box::pin(fetch(
                env,
                id,
                fields,
                u64::from(request.delay),
                u64::from(request.ttl),
                request.exclude_mask,
                deadline,
                over,
                MAX_OTHER,
            )));
        }
        let Some(answers) = all_unless_cancelled(fetches, state).await else {
            drop(requests);
            return end(env, id, state, verifier, cancelled(state)).await;
        };
        // Each answer is a call of its own; the bodies are the C core's
        // once given (it copies them).
        let mut pairs = requests.into_iter().zip(answers);
        let mut stopped = None;
        for (request, answer) in pairs.by_ref() {
            let given = match answer {
                Ok((body, node, hold)) => {
                    let given = env
                        .call(id, state, "answer", move || {
                            crate::testhooks::in_answer();
                            request.set_response(&body, node);
                        })
                        .await;
                    drop(hold);
                    given
                }
                Err(text) => {
                    env.call(id, state, "answer", move || {
                        crate::testhooks::in_answer();
                        request.set_error(&text, 0);
                    })
                    .await
                }
            };
            if let Err(e) = given {
                stopped = Some(Some(e));
                break;
            }
            if state.cancelled.get() {
                stopped = Some(None);
                break;
            }
        }
        drop(pairs);
        match stopped {
            Some(Some(e)) => return stop(env, verifier, e),
            Some(None) => return end(env, id, state, verifier, cancelled(state)).await,
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error_of(reply: Reply) -> String {
        let Reply::Raw(text) = reply else {
            panic!("not a raw reply");
        };
        let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        value["error"].as_str().unwrap_or_default().to_owned()
    }

    #[test]
    fn a_failures_error_is_cut_as_a_requests_is() {
        // 64 Ki UTF-16 units: a BMP character is one, an astral one two,
        // and none is split.
        let cut = error_of(failed("decode", &"é".repeat(65_536 + 5)));
        assert_eq!(cut.encode_utf16().count(), 65_536);
        let cut = error_of(failed("verify", &format!("a{}", "😀".repeat(32_768))));
        assert_eq!(cut.encode_utf16().count(), 65_535);
        assert!(cut.ends_with('😀'));
        assert_eq!(error_of(failed("verify", "short")), "short");
    }
}
