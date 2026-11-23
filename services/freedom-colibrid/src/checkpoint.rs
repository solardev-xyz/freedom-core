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
//! counts as one that doesn't decode. Every call into the C core is behind
//! the step marker, and the context is freed before the reply. Then the
//! process ends.

use std::rc::Rc;
use std::time::{Duration, Instant};

use colibri_stateless::{Step, Verifier};
use fc_service::Exit;
use serde::Deserialize;
use serde_json::json;
use serde_json::value::RawValue;

use crate::request::{
    Env, Fetched, Marked, PendingStatus, RawRequest, Reply, SuccessStatus, TaskState, VERIFY_FLAGS,
    all_unless_cancelled, busy, cancelled, fetch, send_reply,
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

fn failed(stage: &str, error: &str) -> Reply {
    Reply::Raw(json!({ "status": "error", "stage": stage, "error": error }).to_string())
}

/// Runs check `id` to its reply, then ends the process.
pub async fn run(env: Rc<Env>, id: u64, params: Params, state: Rc<TaskState>) {
    let reply = check(&env, id, &params, &state).await;
    send_reply(&env, id, reply);
    env.shared.request_done();
    // One check per process (0014, "Spawn"): the reply flushes, then the
    // process exits 0.
    env.conn.fail(Exit::Ok);
}

async fn check(env: &Rc<Env>, id: u64, p: &Params, state: &Rc<TaskState>) -> Reply {
    let deadline = Instant::now() + Duration::from_millis(p.deadline_ms);
    let proof_request = RawRequest::own("checkpoint_proof", "post", "ssz");
    let proof = match fetch(env, id, &proof_request, 0, 0, 0, deadline, false, MAX_PROOF).await {
        Ok((bytes, _, _hold)) => bytes,
        Err(text) => return failed("decode", &text),
    };
    if state.cancelled.get() {
        return cancelled(state);
    }
    // Decoded, behind a marker.
    match env.mark(id, state) {
        Marked::Go => {}
        Marked::Busy => return busy(),
        Marked::Gone => return Reply::None,
    }
    let decoded = colibri_stateless::decode_proof(&proof);
    env.stepped(id);
    env.shared.step_done();
    let Some(decoded) = decoded else {
        return failed("decode", UNKNOWN_PROOF);
    };
    if RawValue::from_string(decoded.clone()).is_err() {
        return failed("decode", "the decoded proof isn't JSON");
    }
    // Verified, each step behind a marker.
    match env.mark(id, state) {
        Marked::Go => {}
        Marked::Busy => return busy(),
        Marked::Gone => return Reply::None,
    }
    let mut verifier = match Verifier::new(
        &proof,
        METHOD,
        ARGS,
        env.shared.chain_id,
        None,
        VERIFY_FLAGS,
    ) {
        Ok(verifier) => verifier,
        Err(e) => {
            env.stepped(id);
            return failed("verify", &e.to_string());
        }
    };
    verifier.set_min_latest_block_ts(p.min_latest_block_ts);
    loop {
        let outcome = verifier.execute_with_status();
        env.shared.step_done();
        let (step, status) = match outcome {
            Ok(step) => step,
            Err(e) => {
                let text = e.to_string();
                drop(verifier);
                env.stepped(id);
                return failed("verify", &text);
            }
        };
        if env.shared.over_resident() {
            drop(step);
            drop(verifier);
            env.stepped(id);
            return failed(
                "verify",
                "resident memory past the checkpoint process's budget",
            );
        }
        match step {
            Step::Success { .. } => {
                let result = match serde_json::from_str::<SuccessStatus<'_>>(&status) {
                    Ok(SuccessStatus {
                        result: Some(result),
                    }) => result.get().to_owned(),
                    _ => "null".to_owned(),
                };
                drop(verifier);
                env.stepped(id);
                return Reply::Raw(format!(r#"{{"decoded":{decoded},"result":{result}}}"#));
            }
            Step::Revert { data } => {
                drop(verifier);
                env.stepped(id);
                return failed("verify", &format!("execution reverted: {data}"));
            }
            Step::Error { message } => {
                drop(verifier);
                env.stepped(id);
                return failed("verify", &message);
            }
            Step::Pending { requests } => {
                env.stepped(id);
                let raw = match serde_json::from_str::<PendingStatus<'_>>(&status) {
                    Ok(raw) if raw.requests.len() == requests.len() => raw.requests,
                    _ => {
                        drop(requests);
                        env.free(id, state, vec![verifier]);
                        return failed("verify", "the C core's pending requests don't parse");
                    }
                };
                let mut fetches: Vec<
                    std::pin::Pin<Box<dyn std::future::Future<Output = Fetched> + '_>>,
                > = Vec::new();
                for (request, fields) in requests.iter().zip(&raw) {
                    fetches.push(Box::pin(fetch(
                        env,
                        id,
                        fields,
                        u64::from(request.delay),
                        u64::from(request.ttl),
                        request.exclude_mask,
                        deadline,
                        false,
                        MAX_OTHER,
                    )));
                }
                let Some(answers) = all_unless_cancelled(fetches, state).await else {
                    drop(requests);
                    env.free(id, state, vec![verifier]);
                    return cancelled(state);
                };
                match env.mark(id, state) {
                    Marked::Go => {}
                    Marked::Busy => {
                        drop(requests);
                        env.bury(vec![verifier]);
                        return busy();
                    }
                    Marked::Gone => {
                        drop(requests);
                        env.bury(vec![verifier]);
                        return Reply::None;
                    }
                }
                let mut holds = Vec::new();
                for (request, answer) in requests.into_iter().zip(answers) {
                    match answer {
                        Ok((body, node, hold)) => {
                            request.set_response(&body, node);
                            holds.push(hold);
                        }
                        Err(text) => request.set_error(&text, 0),
                    }
                }
                drop(holds);
            }
        }
    }
}
