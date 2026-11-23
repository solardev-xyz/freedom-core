//! One `colibri.request` (design 0014, "Methods main calls"), as a task on
//! the verifier thread. It runs the JavaScript client's `rpc()` loop with
//! the flags `colibri-worker.js` pins:
//! 1. the served list and block forms ([`crate::served`]), before any
//!    context;
//! 2. a context (`c4_create_rpc_ctx`, remote prover mode, verified-only,
//!    ZK per client) and the request's freshness bound;
//! 3. steps, each behind the step marker ([`Env::mark`]). A pending step's
//!    data requests go to main as `shell.colibri_fetch`, and their answers
//!    are given to the C core before the next step;
//! 4. on an error naming a ZK sync proof with ZK on, the client's ZK is off
//!    from then on (F-4, `index.js:261`) and the request runs again on a
//!    new context; the old one is freed after it, as the client's `finally`
//!    frees it;
//! 5. #1080's rule for a failed remote proof ([A failed remote
//!    proof](../../docs/design/0014-colibri-verifier.md)).
//!
//! Every call into the C core for the request (create, step, answers,
//! free) is made behind a marker, and the context is freed before the
//! reply, since a marker after the reply would name no open request.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use colibri_stateless::{MethodType, ProverMode, RpcCtx, Step};
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::Exit;
use fc_service::conn::{
    AskError, AskFailed, BodyError, Connection, EventError, Hold, Reserved, WrittenError,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::value::RawValue;

use crate::exec::{Timers, sleep};
use crate::served;
use crate::shared::Shared;

/// The ZK proof flag (`prover_flags`, `1 << 7`), as the client sets it.
const ZK_FLAG: u32 = 1 << 7;
/// The verify flags `colibri-worker.js` pins: verified-only.
pub const VERIFY_FLAGS: u32 = 2;
/// How long a marker may take to be written (0014, "The step marker").
const MARKER_WAIT: Duration = Duration::from_secs(1);
/// What the client's ZK fallback looks for in an error (`index.js:261`).
const ZK_SYNC_PROOF: &str = "zk sync proof";
/// #1080's prefix, byte for byte.
const NO_LOCAL_PROVING: &str = "remote proof failed (no local proving)";
/// The longest error text a reply carries, in UTF-16 units: a bound on the
/// reply only. Main cuts the completed message to 2,000 units.
const MAX_ERROR_UNITS: usize = 64 * 1024;

/// Fetches open at once, in the process (0014, Budgets).
pub const MAX_FETCHES_OPEN: u64 = 64;
/// Fetches one request makes in all.
const MAX_FETCHES_PER_REQUEST: u32 = 1024;
/// The largest body a fetch may bring: the fetch contract's largest
/// variant (main holds each variant to its own).
pub const MAX_BODY: u64 = 16 << 20;

/// The text the C core gets for a fetch the service refuses.
const FETCH_BUSY: &str = "Colibri fetch busy";
/// For a body that breaks its head's length.
const BODY_MISMATCH: &str = "Colibri body length mismatch";

/// `colibri.request`'s params.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Main's id for one client (a chain, a prover and its ZK setting).
    pub client: String,
    pub zk: bool,
    pub method: String,
    /// The caller's JSON text.
    pub params: String,
    pub min_latest_block_ts: u64,
    pub deadline_ms: u64,
    /// The instant the C core's clock reads, in milliseconds, for a replay
    /// (tests only: the `testhooks` feature).
    #[cfg(feature = "testhooks")]
    #[serde(default)]
    pub test_clock_ms: Option<u64>,
}

/// A task's flags, which the verifier thread sets.
#[derive(Default)]
pub struct TaskState {
    /// Main cancelled the request.
    pub cancelled: Cell<bool>,
    /// The request's commit point is claimed: main's cancel now reaches the
    /// service with nothing queued, and the service owes the reply.
    committed: Cell<bool>,
}

/// What the request's tasks share on the verifier thread.
pub struct Env {
    pub conn: Connection,
    pub shared: Arc<Shared>,
    pub timers: Rc<Timers>,
    /// The clients whose ZK is off (F-4), by main's id.
    pub zk_off: RefCell<HashMap<String, bool>>,
    /// Contexts whose free couldn't be marked: freed at exit (0014: "its
    /// context is freed later, under its own marker, or at exit").
    pub graveyard: RefCell<Vec<RpcCtx>>,
    /// Fetches open, process-wide.
    pub fetches: Cell<u64>,
}

/// Whether a marker was written.
enum Marked {
    /// Written: the C core may be entered.
    Go,
    /// Not written: the request ends with `busy`.
    Busy,
    /// The request is answered or cancelled already, or the connection is
    /// ending: nothing more for it.
    Gone,
}

/// How a request ends.
enum Reply {
    /// A reply's JSON text.
    Raw(String),
    /// A refusal.
    Error(ErrorBody),
    /// Nothing to send.
    None,
}

impl Env {
    /// The marker before a call into the C core for request `id`.
    fn mark(&self, id: u64, state: &TaskState) -> Marked {
        if !state.committed.get() {
            if !self.conn.commit(id) {
                return Marked::Gone;
            }
            state.committed.set(true);
        }
        match self
            .conn
            .event_written("colibri.step", &json!({ "request": id }), MARKER_WAIT)
        {
            Ok(()) => Marked::Go,
            // Never reached main: nothing to clear.
            Err(WrittenError::Withdrawn | WrittenError::Full | WrittenError::Encode) => {
                Marked::Busy
            }
            // May still reach main whole: cleared, so main never sees the
            // step left open.
            Err(WrittenError::Unfinished) => {
                self.stepped(id);
                Marked::Busy
            }
            Err(WrittenError::Closed) => Marked::Gone,
        }
    }

    /// The clearing event after a call: queued before any frame the step
    /// caused. If it can't be queued the process ends (0014: a full queue
    /// fails with 70; a closed connection is ending anyway).
    fn stepped(&self, id: u64) {
        match self
            .conn
            .event_for(id, "colibri.stepped", &json!({ "request": id }))
        {
            Ok(()) | Err(EventError::Closed) => {}
            Err(EventError::Full | EventError::Encode | EventError::Answered) => {
                self.conn.fail(Exit::Internal)
            }
        }
    }

    /// Frees `contexts` behind a marker, or leaves them for exit.
    fn free(&self, id: u64, state: &TaskState, contexts: Vec<RpcCtx>) {
        if contexts.is_empty() {
            return;
        }
        match self.mark(id, state) {
            Marked::Go => {
                drop(contexts);
                self.stepped(id);
            }
            Marked::Busy | Marked::Gone => self.graveyard.borrow_mut().extend(contexts),
        }
    }
}

/// Runs request `id` to its reply.
pub async fn run(env: Rc<Env>, id: u64, params: Params, state: Rc<TaskState>) {
    let reply = serve(&env, id, &params, &state).await;
    let sent = match reply {
        Reply::Raw(text) => match RawValue::from_string(text) {
            Ok(raw) => env.conn.reply(id, &raw),
            Err(_) => env.conn.reply_error(
                id,
                &ErrorBody::new(ErrorCode::Internal, "the reply isn't JSON"),
            ),
        },
        Reply::Error(error) => env.conn.reply_error(id, &error),
        Reply::None => Ok(()),
    };
    if let Err(fc_protocol::stream::SendError::TooLarge) = sent {
        let _ = env.conn.reply_error(
            id,
            &ErrorBody::new(ErrorCode::TooLarge, "the reply is over the message cap"),
        );
    }
    if env.shared.request_done() {
        // Recycled: the open requests are answered (0014, Crashes, overruns
        // and restarts). Exit 0, no fault.
        env.conn.fail(Exit::Ok);
    }
}

fn busy() -> Reply {
    Reply::Error(ErrorBody::new(
        ErrorCode::Busy,
        "the step marker wasn't written",
    ))
}

fn cancelled(state: &TaskState) -> Reply {
    // Before the commit point main queued `cancelled` itself.
    if state.committed.get() {
        Reply::Error(ErrorBody::new(ErrorCode::Cancelled, "cancelled"))
    } else {
        Reply::None
    }
}

/// `{"status":"error","error":<text>}`, the text cut at
/// [`MAX_ERROR_UNITS`].
fn error_reply(text: &str) -> Reply {
    let mut units = 0;
    let mut end = text.len();
    for (at, c) in text.char_indices() {
        units += c.len_utf16();
        if units > MAX_ERROR_UNITS {
            end = at;
            break;
        }
    }
    Reply::Raw(json!({ "status": "error", "error": &text[..end] }).to_string())
}

/// The params the client hands the C core: `request()`'s
/// `Array.isArray(params) ? params : (params ? [params] : [])`, then
/// `rpc()`'s `JSON.stringify` (`cjs/index.js`). So `null` params, which
/// `eth_getBlockByNumber` is served with, reach the C core as `[]`. Params
/// that don't parse go as sent, and the C core answers them.
fn client_params(params: &str) -> String {
    let Ok(value) = fc_json::parse(params) else {
        return params.to_owned();
    };
    if value.as_array().is_some() {
        value.stringify()
    } else if value.truthy() {
        format!("[{}]", value.stringify())
    } else {
        "[]".to_owned()
    }
}

async fn serve(env: &Rc<Env>, id: u64, p: &Params, state: &Rc<TaskState>) -> Reply {
    if let Err(served::Refusal(text)) = served::check(&p.method, &p.params) {
        return Reply::Raw(format!(r#"{{"status":"error","error":{text}}}"#));
    }
    let params = client_params(&p.params);
    let chain = env.shared.chain_id;
    let proofable = matches!(
        colibri_stateless::get_method_support(chain, &p.method, Some(&params), VERIFY_FLAGS),
        Ok(MethodType::Proofable)
    );
    let deadline = Instant::now() + Duration::from_millis(p.deadline_ms);
    let mut done = Vec::new();
    let mut zk = p.zk && !env.zk_off.borrow().get(&p.client).copied().unwrap_or(false);
    loop {
        match attempt(
            env, id, p, &params, state, zk, proofable, deadline, &mut done,
        )
        .await
        {
            Attempt::Done(reply) => return reply,
            Attempt::WithoutZk(ctx) => {
                env.zk_off.borrow_mut().insert(p.client.clone(), true);
                zk = false;
                done.push(ctx);
            }
        }
    }
}

enum Attempt {
    Done(Reply),
    /// The context ended in a ZK sync proof's error: run again without ZK,
    /// and free this one after.
    WithoutZk(RpcCtx),
}

/// The raw fields of a pending step's requests, from the C core's status
/// text: the payload goes to main as the C core wrote it.
#[derive(Deserialize)]
struct PendingStatus<'a> {
    #[serde(borrow)]
    requests: Vec<RawRequest<'a>>,
}

#[derive(Deserialize)]
struct RawRequest<'a> {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    url: String,
    #[serde(borrow, default)]
    payload: Option<&'a RawValue>,
    #[serde(default)]
    encoding: String,
}

/// A success's result, as the C core wrote it.
#[derive(Deserialize)]
struct SuccessStatus<'a> {
    #[serde(borrow, default)]
    result: Option<&'a RawValue>,
}

/// One answer for the C core: the body and its node, or the error text.
type Fetched = Result<(Vec<u8>, u16, Option<Hold>), String>;

#[allow(clippy::too_many_arguments)]
async fn attempt(
    env: &Rc<Env>,
    id: u64,
    p: &Params,
    params: &str,
    state: &Rc<TaskState>,
    zk: bool,
    proofable: bool,
    deadline: Instant,
    done: &mut Vec<RpcCtx>,
) -> Attempt {
    // This context first, then those a ZK fallback left: the client's
    // `finally` frees the inner call's context before its caller's.
    let free_all = |ctx: RpcCtx, done: &mut Vec<RpcCtx>| {
        drop(ctx);
        while let Some(older) = done.pop() {
            drop(older);
        }
    };
    match env.mark(id, state) {
        Marked::Go => {}
        Marked::Busy => return Attempt::Done(busy()),
        Marked::Gone => return Attempt::Done(Reply::None),
    }
    #[cfg(feature = "testhooks")]
    if let Some(ms) = p.test_clock_ms {
        colibri_stateless::set_fixed_time(Some(ms / 1000));
    }
    let prover_flags = if zk { ZK_FLAG } else { 0 };
    let mut ctx = match RpcCtx::new(
        &p.method,
        params,
        env.shared.chain_id,
        prover_flags,
        VERIFY_FLAGS,
        ProverMode::Remote,
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            drop(std::mem::take(done));
            env.stepped(id);
            return Attempt::Done(error_reply(&e.to_string()));
        }
    };
    ctx.set_min_latest_block_ts(p.min_latest_block_ts);
    let mut first = true;
    let mut fetched_so_far: u32 = 0;
    loop {
        // Behind a marker taken before the loop or at the end of the last
        // round.
        let outcome = ctx.execute_with_status();
        env.shared.step_done();
        let (step, status) = match outcome {
            Ok(step) => step,
            Err(e) => {
                let text = e.to_string();
                free_all(ctx, done);
                env.stepped(id);
                return Attempt::Done(error_reply(&text));
            }
        };
        match step {
            Step::Success { .. } => {
                let reply = match serde_json::from_str::<SuccessStatus<'_>>(&status) {
                    Ok(SuccessStatus {
                        result: Some(result),
                    }) => format!(r#"{{"status":"success","result":{}}}"#, result.get()),
                    _ => r#"{"status":"success"}"#.to_owned(),
                };
                free_all(ctx, done);
                env.stepped(id);
                return Attempt::Done(Reply::Raw(reply));
            }
            Step::Revert { data } => {
                let reply = json!({ "status": "revert", "data": data }).to_string();
                free_all(ctx, done);
                env.stepped(id);
                return Attempt::Done(Reply::Raw(reply));
            }
            Step::Error { message } => {
                if zk && message.contains(ZK_SYNC_PROOF) {
                    env.stepped(id);
                    return Attempt::WithoutZk(ctx);
                }
                free_all(ctx, done);
                env.stepped(id);
                return Attempt::Done(error_reply(&message));
            }
            Step::Pending { requests } => {
                env.stepped(id);
                let raw = match serde_json::from_str::<PendingStatus<'_>>(&status) {
                    Ok(raw) if raw.requests.len() == requests.len() => raw.requests,
                    _ => {
                        drop(requests);
                        env.free(id, state, vec![ctx]);
                        env.free(id, state, std::mem::take(done));
                        return Attempt::Done(error_reply(
                            "the C core's pending requests don't parse",
                        ));
                    }
                };
                // #1080: the first step of a proofable context, asking for
                // exactly one prover fetch, the remote proof.
                let remote_proof = first && proofable && raw.len() == 1 && raw[0].kind == "prover";
                first = false;
                if state.cancelled.get() {
                    drop(requests);
                    env.free(id, state, vec![ctx]);
                    env.free(id, state, std::mem::take(done));
                    return Attempt::Done(cancelled(state));
                }
                let mut fetches: Vec<Pin<Box<dyn Future<Output = Fetched> + '_>>> = Vec::new();
                for (request, fields) in requests.iter().zip(&raw) {
                    fetched_so_far = fetched_so_far.saturating_add(1);
                    let over = fetched_so_far > MAX_FETCHES_PER_REQUEST;
                    fetches.push(Box::pin(fetch(
                        env,
                        id,
                        fields,
                        u64::from(request.delay),
                        u64::from(request.ttl),
                        request.exclude_mask,
                        deadline,
                        over,
                    )));
                }
                let answers = match all_unless_cancelled(fetches, state).await {
                    Some(answers) => answers,
                    None => {
                        drop(requests);
                        env.free(id, state, vec![ctx]);
                        env.free(id, state, std::mem::take(done));
                        return Attempt::Done(cancelled(state));
                    }
                };
                match env.mark(id, state) {
                    Marked::Go => {}
                    Marked::Busy => {
                        drop(requests);
                        env.graveyard.borrow_mut().push(ctx);
                        env.graveyard.borrow_mut().append(done);
                        return Attempt::Done(busy());
                    }
                    Marked::Gone => {
                        drop(requests);
                        env.graveyard.borrow_mut().push(ctx);
                        env.graveyard.borrow_mut().append(done);
                        return Attempt::Done(Reply::None);
                    }
                }
                if remote_proof && let Some(Err(text)) = answers.first() {
                    // The remote proof failed: the C core gets the text,
                    // and the step where 3.0.3 would prove locally never
                    // runs. The client's ZK fallback still reads the
                    // error: a prover with no ZK sync proof yet says so in
                    // its text.
                    let error = format!("{NO_LOCAL_PROVING}: {text}");
                    let text = text.clone();
                    for request in requests {
                        request.set_error(&text, 0);
                    }
                    if zk && error.contains(ZK_SYNC_PROOF) {
                        env.stepped(id);
                        return Attempt::WithoutZk(ctx);
                    }
                    free_all(ctx, done);
                    env.stepped(id);
                    return Attempt::Done(error_reply(&error));
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
                // The bodies are the C core's now (it copies them).
                drop(holds);
            }
        }
    }
}

/// Waits for every fetch, or for the request's cancel: `None` then, and the
/// fetches still open are dropped, which cancels them with main.
async fn all_unless_cancelled<'a, T>(
    mut futures: Vec<Pin<Box<dyn Future<Output = T> + 'a>>>,
    state: &TaskState,
) -> Option<Vec<T>> {
    let mut results: Vec<Option<T>> = futures.iter().map(|_| None).collect();
    std::future::poll_fn(move |cx| {
        if state.cancelled.get() {
            return Poll::Ready(None);
        }
        let mut pending = false;
        for (future, result) in futures.iter_mut().zip(results.iter_mut()) {
            if result.is_none() {
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => *result = Some(value),
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(Some(results.iter_mut().filter_map(Option::take).collect()))
        }
    })
    .await
}

/// `shell.colibri_fetch`'s params (0014, "Requests the service makes"):
/// the payload as the C core wrote it.
#[derive(Serialize)]
struct FetchParams<'a> {
    /// Main's open `colibri.request` the fetch is for.
    request: u64,
    #[serde(rename = "type")]
    kind: &'a str,
    method: &'a str,
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<&'a RawValue>,
    accept: &'a str,
    exclude_mask: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_age: Option<u64>,
}

/// Main's head for a fetch: the body's node and exact length.
#[derive(Deserialize)]
struct Head {
    #[serde(default)]
    node: u16,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct HeadBytes {
    bytes: u64,
}

/// A fetch in the process-wide count of open fetches.
struct OpenFetch<'a>(&'a Cell<u64>);

impl<'a> OpenFetch<'a> {
    fn new(count: &'a Cell<u64>) -> OpenFetch<'a> {
        count.set(count.get() + 1);
        OpenFetch(count)
    }
}

impl Drop for OpenFetch<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}

/// Gives a body's reservation back to the bodies budget.
struct Release {
    budget: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Release {
    fn drop(&mut self) {
        self.budget.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Reserves exactly `bytes` of `budget`, within `limit`.
fn reserve(budget: &Arc<AtomicU64>, limit: u64, bytes: u64) -> Option<Hold> {
    let mut held = budget.load(Ordering::Acquire);
    loop {
        let next = held.checked_add(bytes).filter(|next| *next <= limit)?;
        match budget.compare_exchange_weak(held, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                return Some(Hold::new(Release {
                    budget: Arc::clone(budget),
                    bytes,
                }));
            }
            Err(now) => held = now,
        }
    }
}

/// One data request to main, `shell.colibri_fetch`, and its body.
#[allow(clippy::too_many_arguments)]
async fn fetch(
    env: &Rc<Env>,
    id: u64,
    fields: &RawRequest<'_>,
    delay_ms: u64,
    ttl: u64,
    exclude_mask: u32,
    deadline: Instant,
    over: bool,
) -> Fetched {
    if delay_ms > 0 {
        sleep(
            Rc::clone(&env.timers),
            Instant::now() + Duration::from_millis(delay_ms),
        )
        .await;
    }
    if over || env.fetches.get() >= MAX_FETCHES_OPEN {
        return Err(FETCH_BUSY.to_owned());
    }
    let params = FetchParams {
        request: id,
        kind: &fields.kind,
        method: &fields.method,
        path: &fields.url,
        payload: fields.payload,
        accept: &fields.encoding,
        exclude_mask,
        max_age: (ttl > 0).then_some(ttl),
    };
    let budget = Arc::clone(&env.shared.bodies);
    let limit = env.shared.bodies_limit;
    let asked = env.conn.ask_reserving(
        "shell.colibri_fetch",
        &params,
        Some(deadline),
        move |head: &RawValue| {
            let refused = || ErrorBody::new(ErrorCode::Busy, FETCH_BUSY);
            let bytes = serde_json::from_str::<HeadBytes>(head.get())
                .map_err(|_| ErrorBody::new(ErrorCode::InvalidArgument, "a head without bytes"))?
                .bytes;
            if bytes > MAX_BODY {
                return Err(refused());
            }
            let hold = reserve(&budget, limit, bytes).ok_or_else(refused)?;
            Ok(Reserved { len: bytes, hold })
        },
    );
    let asked = match asked {
        Ok(asked) => asked,
        Err(AskError::Full) => return Err(FETCH_BUSY.to_owned()),
        Err(AskError::Closed) => return Err("Colibri service closing".to_owned()),
        Err(AskError::OneWay | AskError::Encode) => {
            return Err("Colibri fetch couldn't be sent".to_owned());
        }
    };
    // Counted until the fetch ends, its body read, or until it is dropped
    // with its request.
    let _open = OpenFetch::new(&env.fetches);
    let answer = match asked.await {
        Ok(answer) => answer,
        Err(AskFailed::Error(error)) => return Err(error.message),
        Err(AskFailed::Refused(_)) => return Err(FETCH_BUSY.to_owned()),
        Err(AskFailed::Deadline) => return Err("Colibri fetch deadline passed".to_owned()),
        Err(AskFailed::Closed) => return Err("Colibri service closing".to_owned()),
    };
    let head: Head = serde_json::from_str(answer.result.get())
        .map_err(|_| "Colibri fetch head doesn't parse".to_owned())?;
    if let Some(error) = head.error {
        return Err(error);
    }
    let Some(mut body) = answer.body else {
        return Err("Colibri fetch has no body".to_owned());
    };
    let mut bytes = Vec::new();
    loop {
        match body.chunk().await {
            Ok(Some(chunk)) => bytes.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(BodyError::Mismatch { .. }) => return Err(BODY_MISMATCH.to_owned()),
            Err(BodyError::Aborted(_)) => return Err("Colibri fetch body aborted".to_owned()),
            Err(BodyError::Closed) => return Err("Colibri service closing".to_owned()),
        }
    }
    Ok((bytes, head.node, answer.hold))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_as_the_client_sends_them() {
        assert_eq!(
            client_params(r#"["0xabc", "latest"]"#),
            r#"["0xabc","latest"]"#
        );
        for falsy in ["null", "false", "0", r#""""#] {
            assert_eq!(client_params(falsy), "[]", "{falsy}");
        }
        assert_eq!(client_params(r#""0x1""#), r#"["0x1"]"#);
        assert_eq!(client_params(r#"{"b":1,"a":2}"#), r#"[{"b":1,"a":2}]"#);
        assert_eq!(client_params("not json"), "not json");
    }

    #[test]
    fn error_text_is_cut_at_its_bound() {
        let Reply::Raw(text) = error_reply(&"é".repeat(MAX_ERROR_UNITS + 5)) else {
            panic!("not raw");
        };
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            value["error"].as_str().unwrap().encode_utf16().count(),
            MAX_ERROR_UNITS
        );
        // An astral character counts two units and is never split.
        let Reply::Raw(text) = error_reply(&"😀".repeat(MAX_ERROR_UNITS)) else {
            panic!("not raw");
        };
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            value["error"].as_str().unwrap().encode_utf16().count(),
            MAX_ERROR_UNITS
        );
    }

    #[test]
    fn an_open_fetch_is_counted_until_dropped() {
        let count = Cell::new(0);
        let a = OpenFetch::new(&count);
        let b = OpenFetch::new(&count);
        assert_eq!(count.get(), 2);
        drop(a);
        drop(b);
        assert_eq!(count.get(), 0);
    }

    #[test]
    fn bodies_are_reserved_exactly() {
        let budget = Arc::new(AtomicU64::new(0));
        let a = reserve(&budget, 10, 6).unwrap();
        assert!(reserve(&budget, 10, 5).is_none());
        let b = reserve(&budget, 10, 4).unwrap();
        assert_eq!(budget.load(Ordering::Acquire), 10);
        drop(a);
        assert_eq!(budget.load(Ordering::Acquire), 4);
        drop(b);
        assert_eq!(budget.load(Ordering::Acquire), 0);
    }
}
