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

use crate::exec::{Timers, sleep, yield_now};
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
    pub graveyard: RefCell<Vec<Box<dyn std::any::Any>>>,
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
pub(crate) enum Reply {
    /// A reply's JSON text.
    Raw(String),
    /// A refusal.
    Error(ErrorBody),
    /// Nothing to send.
    None,
}

/// Why a request stops before its reply: its marker wasn't written
/// (`busy`), or the request is answered or gone, or the connection is
/// ending.
pub(crate) enum Stop {
    Busy,
    Gone,
}

impl Stop {
    pub(crate) fn reply(self) -> Reply {
        match self {
            Stop::Busy => busy(),
            Stop::Gone => Reply::None,
        }
    }
}

impl Env {
    /// The marker before call `what` into the C core for request `id`.
    /// With the `testhooks` feature it names the call, so a test can tell
    /// which one a death was in; the design's marker carries the request
    /// alone.
    fn mark(&self, id: u64, state: &TaskState, what: &'static str) -> Marked {
        if !state.committed.get() {
            if !self.conn.commit(id) {
                return Marked::Gone;
            }
            state.committed.set(true);
        }
        #[cfg(feature = "testhooks")]
        let marker = json!({ "request": id, "call": what });
        #[cfg(not(feature = "testhooks"))]
        let marker = {
            let _ = what;
            json!({ "request": id })
        };
        match self
            .conn
            .event_written("colibri.step", &marker, MARKER_WAIT)
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

    /// The clearing event after a call: queued as it returns, before any
    /// frame it caused. If it can't be queued the process ends (0014: a
    /// full queue fails with 70; a closed connection is ending anyway).
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

    /// One call into the C core for request `id` (0014, "The step marker"):
    /// its own marker, written within its second, then the call, then its
    /// clearing event as it returns, then a yield, so a cancel queued
    /// meanwhile is seen before anything else is done for the request. No
    /// marker, no call: `f` is then dropped uncalled.
    pub(crate) async fn call<T>(
        &self,
        id: u64,
        state: &TaskState,
        what: &'static str,
        f: impl FnOnce() -> T,
    ) -> Result<T, Stop> {
        match self.mark(id, state, what) {
            Marked::Go => {}
            Marked::Busy => return Err(Stop::Busy),
            Marked::Gone => return Err(Stop::Gone),
        }
        debug_assert_eq!(
            std::thread::current().name(),
            Some("verifier"),
            "a call into the C core off the verifier thread"
        );
        self.shared.call_done();
        let value = f();
        self.stepped(id);
        yield_now().await;
        Ok(value)
    }

    /// Frees `contexts` in order, each behind its own marker; from the
    /// first whose marker isn't written, they are kept until exit, and the
    /// request ends as that marker says.
    pub(crate) async fn free_all<T: 'static>(
        &self,
        id: u64,
        state: &TaskState,
        contexts: Vec<T>,
    ) -> Result<(), Stop> {
        let mut contexts = contexts.into_iter();
        while let Some(ctx) = contexts.next() {
            let stop = match self.mark(id, state, "free") {
                Marked::Go => {
                    debug_assert_eq!(std::thread::current().name(), Some("verifier"));
                    self.shared.call_done();
                    drop(ctx);
                    self.stepped(id);
                    yield_now().await;
                    continue;
                }
                Marked::Busy => Stop::Busy,
                Marked::Gone => Stop::Gone,
            };
            self.bury(std::iter::once(ctx).chain(contexts));
            return Err(stop);
        }
        Ok(())
    }

    /// Keeps `contexts` until exit (0014: "its context is freed later,
    /// under its own marker, or at exit").
    pub(crate) fn bury<T: 'static>(&self, contexts: impl IntoIterator<Item = T>) {
        let mut graveyard = self.graveyard.borrow_mut();
        for context in contexts {
            graveyard.push(Box::new(context));
        }
    }

    /// Ends a request with `reply`: `ctx` freed, then the contexts a ZK
    /// fallback left (the inner call's context before its caller's, as the
    /// client's `finally` frees them). A cancel seen meanwhile wins.
    async fn end(
        &self,
        id: u64,
        state: &TaskState,
        ctx: Option<RpcCtx>,
        done: &mut Vec<RpcCtx>,
        reply: Reply,
    ) -> Reply {
        let mut all: Vec<RpcCtx> = ctx.into_iter().collect();
        all.extend(done.drain(..).rev());
        // A free that couldn't be marked ends the request with `busy`: no
        // marker, no call (0014).
        if let Err(stop) = self.free_all(id, state, all).await {
            return stop.reply();
        }
        if state.cancelled.get() {
            cancelled(state)
        } else {
            reply
        }
    }

    /// Stops a request whose marker wasn't written: `ctx` and the older
    /// contexts are kept until exit, never freed unmarked.
    fn stop(&self, ctx: Option<RpcCtx>, done: &mut Vec<RpcCtx>, stop: Stop) -> Reply {
        self.bury(ctx);
        self.bury(done.drain(..));
        stop.reply()
    }
}

/// Runs request `id` to its reply.
pub async fn run(env: Rc<Env>, id: u64, params: Params, state: Rc<TaskState>) {
    let reply = serve(&env, id, &params, &state).await;
    send_reply(&env, id, reply);
    if env.shared.request_done() {
        // Recycled: the open requests are answered (0014, Crashes, overruns
        // and restarts). Exit 0, no fault.
        env.conn.fail(Exit::Ok);
    }
}

/// Sends request `id`'s reply.
pub(crate) fn send_reply(env: &Env, id: u64, reply: Reply) {
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
}

pub(crate) fn busy() -> Reply {
    Reply::Error(ErrorBody::new(
        ErrorCode::Busy,
        "the step marker wasn't written",
    ))
}

pub(crate) fn cancelled(state: &TaskState) -> Reply {
    // Before the commit point main queued `cancelled` itself.
    if state.committed.get() {
        Reply::Error(ErrorBody::new(ErrorCode::Cancelled, "cancelled"))
    } else {
        Reply::None
    }
}

/// `{"status":"error","error":<text>}`, the text cut at
/// [`MAX_ERROR_UNITS`].
pub(crate) fn error_reply(text: &str) -> Reply {
    Reply::Raw(json!({ "status": "error", "error": cut_error(text) }).to_string())
}

/// `text`'s first [`MAX_ERROR_UNITS`] UTF-16 units, never splitting a
/// character: an error a reply carries (0014, Budgets).
pub(crate) fn cut_error(text: &str) -> &str {
    let mut units = 0;
    for (at, c) in text.char_indices() {
        units += c.len_utf16();
        if units > MAX_ERROR_UNITS {
            return &text[..at];
        }
    }
    text
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

/// The fetches one request may make in all, across a ZK fallback's two
/// contexts (0014, Budgets: 1,024 per request).
#[derive(Debug)]
pub(crate) struct FetchBudget {
    taken: u32,
    limit: u32,
}

impl Default for FetchBudget {
    /// 1,024 fetches, or the test hook's bound.
    fn default() -> FetchBudget {
        FetchBudget {
            taken: 0,
            limit: crate::testhooks::fetch_budget().unwrap_or(MAX_FETCHES_PER_REQUEST),
        }
    }
}

impl FetchBudget {
    /// Takes one fetch: false past the bound.
    pub(crate) fn take(&mut self) -> bool {
        self.taken = self.taken.saturating_add(1);
        self.taken <= self.limit
    }
}

impl Params {
    /// The request's deadline, if the clock can hold it.
    pub fn deadline(&self) -> Option<Instant> {
        Instant::now().checked_add(Duration::from_millis(self.deadline_ms))
    }
}

async fn serve(env: &Rc<Env>, id: u64, p: &Params, state: &Rc<TaskState>) -> Reply {
    // A cancel that came with the request.
    if state.cancelled.get() {
        return cancelled(state);
    }
    if let Err(served::Refusal(text)) = served::check(&p.method, &p.params) {
        return Reply::Raw(format!(r#"{{"status":"error","error":{text}}}"#));
    }
    let params = client_params(&p.params);
    let Some(deadline) = p.deadline() else {
        return Reply::Error(ErrorBody::new(
            ErrorCode::InvalidArgument,
            "deadline_ms is past what the clock holds",
        ));
    };
    let chain = env.shared.chain_id;
    let support = match env
        .call(id, state, "classify", || {
            crate::testhooks::in_classify();
            colibri_stateless::get_method_support(chain, &p.method, Some(&params), VERIFY_FLAGS)
        })
        .await
    {
        Ok(support) => support,
        Err(stop) => return stop.reply(),
    };
    if state.cancelled.get() {
        return cancelled(state);
    }
    let proofable = matches!(support, Ok(MethodType::Proofable));
    let mut budget = FetchBudget::default();
    let mut done = Vec::new();
    let mut zk = p.zk && !env.zk_off.borrow().get(&p.client).copied().unwrap_or(false);
    loop {
        let attempt = Attempt {
            env,
            id,
            p,
            params: &params,
            state,
            zk,
            proofable,
            deadline,
        };
        match attempt.run(&mut budget, &mut done).await {
            Outcome::Done(reply) => return reply,
            Outcome::WithoutZk(ctx) => {
                env.zk_off.borrow_mut().insert(p.client.clone(), true);
                zk = false;
                done.push(ctx);
            }
        }
    }
}

/// How one context's run ends.
enum Outcome {
    Done(Reply),
    /// It ended in a ZK sync proof's error: run again without ZK, and free
    /// this one after.
    WithoutZk(RpcCtx),
}

/// One context's run within a request.
struct Attempt<'a> {
    env: &'a Rc<Env>,
    id: u64,
    p: &'a Params,
    params: &'a str,
    state: &'a Rc<TaskState>,
    zk: bool,
    proofable: bool,
    deadline: Instant,
}

/// The raw fields of a pending step's requests, from the C core's status
/// text: the payload goes to main as the C core wrote it.
#[derive(Deserialize)]
pub(crate) struct PendingStatus<'a> {
    #[serde(borrow)]
    pub(crate) requests: Vec<RawRequest<'a>>,
}

#[derive(Deserialize)]
pub(crate) struct RawRequest<'a> {
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

impl RawRequest<'static> {
    /// A fetch the service makes itself, not the C core.
    pub(crate) fn own(kind: &str, method: &str, encoding: &str) -> RawRequest<'static> {
        RawRequest {
            kind: kind.to_owned(),
            method: method.to_owned(),
            url: String::new(),
            payload: None,
            encoding: encoding.to_owned(),
        }
    }
}

/// A success's result, as the C core wrote it: absent, or its JSON text,
/// `null` included (the client's caller gets `null` then, not `undefined`).
#[derive(Deserialize)]
pub(crate) struct SuccessStatus<'a> {
    #[serde(borrow, default, deserialize_with = "present")]
    pub(crate) result: Option<&'a RawValue>,
}

/// A field that is there, `null` or not: serde reads a `null` `Option` as
/// absent.
fn present<'de, D>(deserializer: D) -> Result<Option<&'de RawValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <&RawValue>::deserialize(deserializer).map(Some)
}

/// One answer for the C core: the body and its node, or the error text.
pub(crate) type Fetched = Result<(Vec<u8>, u16, Option<Hold>), String>;

impl Attempt<'_> {
    #[allow(clippy::too_many_lines)]
    async fn run(&self, budget: &mut FetchBudget, done: &mut Vec<RpcCtx>) -> Outcome {
        let (env, id, state) = (self.env, self.id, &**self.state);
        let prover_flags = if self.zk { ZK_FLAG } else { 0 };
        #[cfg(feature = "testhooks")]
        if let Some(ms) = self.p.test_clock_ms {
            if let Err(stop) = env
                .call(id, state, "clock", || {
                    colibri_stateless::set_fixed_time(Some(ms / 1000));
                })
                .await
            {
                return Outcome::Done(env.stop(None, done, stop));
            }
            if state.cancelled.get() {
                return Outcome::Done(env.end(id, state, None, done, cancelled(state)).await);
            }
        }
        let created = env
            .call(id, state, "create", || {
                crate::testhooks::in_create();
                RpcCtx::new(
                    &self.p.method,
                    self.params,
                    env.shared.chain_id,
                    prover_flags,
                    VERIFY_FLAGS,
                    ProverMode::Remote,
                )
            })
            .await;
        let created = match created {
            Ok(created) => created,
            Err(stop) => return Outcome::Done(env.stop(None, done, stop)),
        };
        let mut ctx = match created {
            Ok(ctx) => ctx,
            Err(e) => {
                let reply = error_reply(&e.to_string());
                return Outcome::Done(env.end(id, state, None, done, reply).await);
            }
        };
        if state.cancelled.get() {
            return Outcome::Done(env.end(id, state, Some(ctx), done, cancelled(state)).await);
        }
        let min = self.p.min_latest_block_ts;
        if let Err(stop) = env
            .call(id, state, "freshness", || ctx.set_min_latest_block_ts(min))
            .await
        {
            return Outcome::Done(env.stop(Some(ctx), done, stop));
        }
        if state.cancelled.get() {
            return Outcome::Done(env.end(id, state, Some(ctx), done, cancelled(state)).await);
        }
        let mut first = true;
        loop {
            let outcome = env
                .call(id, state, "execute", || {
                    crate::testhooks::in_step();
                    ctx.execute_with_status()
                })
                .await;
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(stop) => return Outcome::Done(env.stop(Some(ctx), done, stop)),
            };
            env.shared.step_done();
            let (step, status) = match outcome {
                Ok(step) => step,
                Err(e) => {
                    let reply = error_reply(&e.to_string());
                    return Outcome::Done(env.end(id, state, Some(ctx), done, reply).await);
                }
            };
            if state.cancelled.get() {
                drop(step);
                return Outcome::Done(env.end(id, state, Some(ctx), done, cancelled(state)).await);
            }
            let requests = match step {
                Step::Success { .. } => {
                    let reply = match serde_json::from_str::<SuccessStatus<'_>>(&status) {
                        Ok(SuccessStatus {
                            result: Some(result),
                        }) => format!(r#"{{"status":"success","result":{}}}"#, result.get()),
                        _ => r#"{"status":"success"}"#.to_owned(),
                    };
                    let reply = Reply::Raw(reply);
                    return Outcome::Done(env.end(id, state, Some(ctx), done, reply).await);
                }
                Step::Revert { data } => {
                    let reply = Reply::Raw(json!({ "status": "revert", "data": data }).to_string());
                    return Outcome::Done(env.end(id, state, Some(ctx), done, reply).await);
                }
                Step::Error { message } => {
                    if self.zk && message.contains(ZK_SYNC_PROOF) {
                        return Outcome::WithoutZk(ctx);
                    }
                    let reply = error_reply(&message);
                    return Outcome::Done(env.end(id, state, Some(ctx), done, reply).await);
                }
                Step::Pending { requests } => requests,
            };
            let raw = match serde_json::from_str::<PendingStatus<'_>>(&status) {
                Ok(raw) if raw.requests.len() == requests.len() => raw.requests,
                _ => {
                    drop(requests);
                    let reply = error_reply("the C core's pending requests don't parse");
                    return Outcome::Done(env.end(id, state, Some(ctx), done, reply).await);
                }
            };
            // #1080: the first step of a proofable context, asking for
            // exactly one prover fetch, the remote proof.
            let remote_proof = first && self.proofable && raw.len() == 1 && raw[0].kind == "prover";
            first = false;
            let mut fetches: Vec<Pin<Box<dyn Future<Output = Fetched> + '_>>> = Vec::new();
            for (request, fields) in requests.iter().zip(&raw) {
                let over = !budget.take();
                fetches.push(Box::pin(fetch(
                    env,
                    id,
                    fields,
                    u64::from(request.delay),
                    u64::from(request.ttl),
                    request.exclude_mask,
                    self.deadline,
                    over,
                    MAX_BODY,
                )));
            }
            let Some(answers) = all_unless_cancelled(fetches, state).await else {
                drop(requests);
                return Outcome::Done(env.end(id, state, Some(ctx), done, cancelled(state)).await);
            };
            if remote_proof && let Some(Err(text)) = answers.first() {
                // The remote proof failed: the C core gets the text, and the
                // step where 3.0.3 would prove locally never runs. The
                // client's ZK fallback still reads the error: a prover with
                // no ZK sync proof yet says so in its text.
                let error = format!("{NO_LOCAL_PROVING}: {text}");
                let text = text.clone();
                if let Some(request) = requests.into_iter().next()
                    && let Err(stop) = env
                        .call(id, state, "answer", move || {
                            crate::testhooks::in_answer();
                            request.set_error(&text, 0)
                        })
                        .await
                {
                    return Outcome::Done(env.stop(Some(ctx), done, stop));
                }
                if state.cancelled.get() {
                    return Outcome::Done(
                        env.end(id, state, Some(ctx), done, cancelled(state)).await,
                    );
                }
                if self.zk && error.contains(ZK_SYNC_PROOF) {
                    return Outcome::WithoutZk(ctx);
                }
                let reply = error_reply(&error);
                return Outcome::Done(env.end(id, state, Some(ctx), done, reply).await);
            }
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
                                request.set_response(&body, node)
                            })
                            .await;
                        drop(hold);
                        given
                    }
                    Err(text) => {
                        env.call(id, state, "answer", move || {
                            crate::testhooks::in_answer();
                            request.set_error(&text, 0)
                        })
                        .await
                    }
                };
                if let Err(stop) = given {
                    stopped = Some(Some(stop));
                    break;
                }
                if state.cancelled.get() {
                    stopped = Some(None);
                    break;
                }
            }
            drop(pairs);
            match stopped {
                Some(Some(stop)) => return Outcome::Done(env.stop(Some(ctx), done, stop)),
                Some(None) => {
                    return Outcome::Done(
                        env.end(id, state, Some(ctx), done, cancelled(state)).await,
                    );
                }
                None => {}
            }
        }
    }
}

/// Waits for every fetch, or for the request's cancel: `None` then, and the
/// fetches still open are dropped, which cancels them with main.
pub(crate) async fn all_unless_cancelled<'a, T>(
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
pub(crate) async fn fetch(
    env: &Rc<Env>,
    id: u64,
    fields: &RawRequest<'_>,
    delay_ms: u64,
    ttl: u64,
    exclude_mask: u32,
    deadline: Instant,
    over: bool,
    max_body: u64,
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
            if bytes > max_body {
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
    fn a_null_result_is_kept_and_an_absent_one_is_absent() {
        let null: SuccessStatus<'_> =
            serde_json::from_str(r#"{"status":"success","result":null}"#).unwrap();
        assert_eq!(null.result.map(RawValue::get), Some("null"));
        let value: SuccessStatus<'_> =
            serde_json::from_str(r#"{"status":"success","result":{"a":1}}"#).unwrap();
        assert_eq!(value.result.map(RawValue::get), Some(r#"{"a":1}"#));
        let absent: SuccessStatus<'_> = serde_json::from_str(r#"{"status":"success"}"#).unwrap();
        assert!(absent.result.is_none());
    }

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
    fn one_request_makes_1024_fetches_in_all() {
        // One budget per request, which its ZK fallback's second context
        // shares (`serve` holds it).
        let mut budget = FetchBudget::default();
        for _ in 0..MAX_FETCHES_PER_REQUEST {
            assert!(budget.take());
        }
        assert!(!budget.take(), "the 1,025th fetch");
        assert!(!budget.take());
    }

    #[test]
    fn fetch_params_carry_the_c_cores_fields() {
        let payload: Box<RawValue> =
            serde_json::from_str(r#"{"method": "eth_getProof","params":[1]}"#).unwrap();
        let params = FetchParams {
            request: 7,
            kind: "beacon_api",
            method: "get",
            path: "eth/v1/x",
            payload: Some(&payload),
            accept: "ssz",
            exclude_mask: 5,
            max_age: Some(6),
        };
        assert_eq!(
            serde_json::to_string(&params).unwrap(),
            r#"{"request":7,"type":"beacon_api","method":"get","path":"eth/v1/x","payload":{"method": "eth_getProof","params":[1]},"accept":"ssz","exclude_mask":5,"max_age":6}"#
        );
        let none = FetchParams {
            payload: None,
            max_age: None,
            exclude_mask: 0,
            ..params
        };
        assert_eq!(
            serde_json::to_string(&none).unwrap(),
            r#"{"request":7,"type":"beacon_api","method":"get","path":"eth/v1/x","accept":"ssz","exclude_mask":0}"#
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
