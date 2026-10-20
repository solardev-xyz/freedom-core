//! `ipfs.request` (design 0007, "Methods", "Cancel, deadlines and
//! admission", "Errors" and "Panics").
//!
//! - **Parsing, as the add-on does.** The params are checked
//!   ([`params::request`]), then upstream's native-request parser builds the
//!   gateway request from the method, path and headers, with the request ID
//!   set to the envelope ID and the top-level path to `path`, as main sets
//!   them today. What it refuses is `invalid_argument`.
//! - **Admission, at once, on the reader thread:** a request naming an
//!   instance that isn't live (retired, unknown, starting or stopping) gets
//!   `stopped`; with 512 requests admitted in the process, `busy`. A
//!   request is admitted from here until its work has ended **and** nothing
//!   of it is held on the wire any more (its reply, or its stream's
//!   terminal, written and flushed): heads, open streams and work still
//!   ending after a cancel all count, and so does a refusal of a spawn an
//!   instance fenced. Its record ([`Slot`]) is an owned guard, dropped only
//!   then.
//! - **The work** runs on its instance's runtime, in the instance's task
//!   set, under its own token, a child of the instance's root, and marked
//!   as request work for the panic hook ([`TaskKind::REQUEST`]): the
//!   gateway's response, its head (`status`, `headers`, `body`), then its
//!   body under main's credit through fc-service's stream state machine,
//!   which the writer owns ([`serve`]). `body` is false for `HEAD`, 204, 205
//!   and 304, and any bytes the gateway produces then are dropped.
//! - **A watcher per request,** on the process runtime, holds the record
//!   and awaits the work's join handle ([`watch`]):
//!   - **the deadline:** `headers_ms` runs from admission. If no head is
//!     queued by then, the reply is `deadline` and the work's token is
//!     cancelled. The work checks it too, as it queues its head
//!     ([`Connection::head_by`]): a head produced after it is never sent,
//!     whichever runtime runs first, and a head queued in time stands
//!     however late the watcher runs. After the head there is no deadline
//!     here.
//!   - **a cancel** (main's) reaches the work through its token
//!     ([`Requests::cancel`]); the connection has queued `cancelled`.
//!   - **work that ended without its outcome** (its token cancelled by its
//!     instance's teardown, or its runtime gone) is settled `stopped`,
//!     unless something settled it already.
//!   - **a panic** in the work is caught here, at its join handle, after
//!     the hook's fixed line. The instance is fenced first, then the
//!     request settled `internal` as the writer decides it (an error before
//!     its head is written, the head dropped if queued, an abort if its
//!     stream is open, nothing if settled already), then the instance torn
//!     down, and `ipfs.instance_retired { reason: "panic" }` sent once
//!     quiescence is proven ([`Instances::fence_after_panic`]).
//! - **A teardown** settles its instance's requests `stopped` before it
//!   cancels them ([`Requests::stop_instance`]): an error for those whose
//!   head isn't written, an abort for open streams.
//! - **Locks:** the request table's lock is taken before the instance
//!   table's, never the other way round, and neither is held across a call
//!   into freedom-ipfs (0007: so an upstream panic can't poison one). A
//!   request is recorded, with its token, before its work is spawned: a
//!   teardown or a cancel handled from then on finds it, and an instance
//!   fenced in between refuses the spawn (`stopped`) or cancels the work.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Poll;
use std::time::Duration;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::stream::{Abort, AbortCode, SendError};
use fc_service::conn::{Connection, Headed, SendBytes};
use fc_service::panic::{Labeled, TaskKind};
use freedom_ipfs_gateway::{
    CancellationToken, GatewayCore, GatewayCoreRequest, MemoryBudget, MemoryWait, NativeRequest,
    parse_native_request, with_memory_wait,
};
use futures_core::Stream;
use serde_json::json;
use serde_json::value::RawValue;
use tokio::runtime::Handle;
use tokio::task::{JoinError, JoinHandle};
use tokio::time::Instant;

use crate::instances::Instances;
use crate::params;
use crate::stats::GatewayCounters;
use crate::testhooks::{self, Phase, RequestHooks};

/// The most requests admitted at once in the process (0007, "Admission").
pub const MAX_ADMITTED: usize = 512;

/// A request's watcher: the service's own work, so a panic in it exits 70.
const WATCHER: TaskKind = TaskKind::named("request-watch");

/// The process's requests.
pub struct Requests {
    /// The process runtime: the watchers.
    runtime: Handle,
    /// The process's memory budget: what a pending head reserves.
    budget: MemoryBudget,
    table: Mutex<HashMap<u64, Entry>>,
}

/// An admitted request.
struct Entry {
    /// The instance it runs on.
    instance: String,
    /// Its work's token.
    token: CancellationToken,
    /// Its instance's counters.
    counters: Arc<GatewayCounters>,
    /// Main has cancelled it.
    cancelled: bool,
}

impl Requests {
    pub fn new(runtime: Handle, budget: MemoryBudget) -> Arc<Requests> {
        Arc::new(Requests {
            runtime,
            budget,
            table: Mutex::new(HashMap::new()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Entry>> {
        self.table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The requests admitted now.
    pub fn admitted(&self) -> usize {
        self.lock().len()
    }

    /// `ipfs.request`, on the reader thread: refused, or admitted with its
    /// work spawned on its instance, at once.
    pub fn request(
        self: &Arc<Self>,
        instances: &Arc<Instances>,
        conn: &Connection,
        id: u64,
        params: Option<&RawValue>,
    ) {
        let wire = match params::request(params) {
            Ok(wire) => wire,
            Err(message) => return refuse(conn, id, ErrorCode::InvalidArgument, message),
        };
        // Upstream's parser, given what the add-on gives it: the request ID
        // is the envelope ID, the top-level path the request's path.
        let parsed = match parse_native_request(NativeRequest {
            method: Some(wire.method),
            path: wire.path.clone(),
            headers: Some(wire.headers),
            request_id: Some(id),
            parent_request_id: None,
            top_level_path: Some(wire.path),
        }) {
            Ok(parsed) => parsed,
            // Its error can quote the input: a fixed message instead.
            Err(_) => {
                return refuse(
                    conn,
                    id,
                    ErrorCode::InvalidArgument,
                    "the request can't be parsed: an unsupported method, path or header",
                );
            }
        };
        let deadline = Instant::now() + wire.headers_ms;
        let head_only = parsed.method_label == "HEAD";
        let mut table = self.lock();
        if table.len() >= MAX_ADMITTED {
            drop(table);
            return refuse(
                conn,
                id,
                ErrorCode::Busy,
                "the service holds 512 requests already",
            );
        }
        // Its instance, live, and its token: recorded before the work is
        // spawned, so a teardown or a cancel handled from here on finds it.
        let Some((context, core, counters)) = instances.with_live(&wire.instance, |running| {
            (
                running.instance.context().clone(),
                running.core.clone(),
                running.counters.clone(),
            )
        }) else {
            drop(table);
            return refuse(conn, id, ErrorCode::Stopped, NOT_LIVE);
        };
        let token = context.request_token();
        record(
            &mut table,
            id,
            Entry {
                instance: wire.instance.clone(),
                token: token.clone(),
                counters: counters.clone(),
                cancelled: false,
            },
        );
        drop(table);
        let slot = Slot {
            requests: self.clone(),
            id,
            counters: counters.clone(),
        };
        // Outside the service's locks, as every call into freedom-ipfs is.
        // An instance fenced since has refused it: `stopped`. One fenced
        // after cancels it, and its watcher settles it.
        let work = Labeled::new(
            TaskKind::REQUEST,
            serve(
                Work {
                    conn: conn.clone(),
                    id,
                    core,
                    head_only,
                    deadline,
                    budget: self.budget.clone(),
                    counters: counters.clone(),
                },
                parsed.request,
            ),
        );
        let Ok(join) = context.spawn_request(token.clone(), work) else {
            // Admitted until its refusal is written, as any request is.
            refuse(conn, id, ErrorCode::Stopped, NOT_LIVE);
            let conn = conn.clone();
            drop(self.runtime.spawn(Labeled::new(WATCHER, async move {
                conn.settled(id).await;
                drop(slot);
            })));
            return;
        };
        drop(self.runtime.spawn(Labeled::new(
            WATCHER,
            watch(Watched {
                slot,
                instances: instances.clone(),
                conn: conn.clone(),
                instance: wire.instance,
                token,
                join,
                deadline,
                counters,
            }),
        )));
    }

    /// Main cancelled request `id`: its `cancelled` reply or abort is
    /// queued; its work ends at its next await.
    pub fn cancel(&self, id: u64) {
        if let Some(entry) = self.lock().get_mut(&id) {
            entry.token.cancel();
            if !entry.cancelled {
                entry.cancelled = true;
                entry.counters.cancelled();
            }
        }
    }

    /// A teardown's step 3 for the requests on `instance` (0007, "The
    /// teardown"): each is settled `stopped` (an error if its head isn't
    /// written, an abort if its stream is open) and its work cancelled.
    pub fn stop_instance(&self, conn: &Connection, instance: &str) {
        let tokens: Vec<(u64, CancellationToken)> = self
            .lock()
            .iter()
            .filter(|(_, entry)| entry.instance == instance)
            .map(|(id, entry)| (*id, entry.token.clone()))
            .collect();
        for (id, token) in tokens {
            let _ = conn.settle(id, &stopped(), &Abort::new(AbortCode::Stopped, STOPPED));
            token.cancel();
        }
    }
}

/// Records request `id`'s admission, and counts it started under the
/// table's lock, as its end is counted ([`Slot`]): an instance's active
/// requests are always its entries here.
fn record(table: &mut HashMap<u64, Entry>, id: u64, entry: Entry) {
    entry.counters.started();
    table.insert(id, entry);
}

/// A request's admission: released when dropped, by its watcher once the
/// work has ended and the request is settled on the wire, or on unwind.
struct Slot {
    requests: Arc<Requests>,
    id: u64,
    counters: Arc<GatewayCounters>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut table = self.requests.lock();
        table.remove(&self.id);
        // Under the table's lock, as its start was counted.
        self.counters.freed();
        drop(table);
        #[cfg(test)]
        tests::after_free(&self.requests);
    }
}

/// What a request's watcher holds.
struct Watched {
    slot: Slot,
    instances: Arc<Instances>,
    conn: Connection,
    instance: String,
    token: CancellationToken,
    join: JoinHandle<Option<Outcome>>,
    deadline: Instant,
    counters: Arc<GatewayCounters>,
}

/// Watches a request's work to its end (see the module's documentation),
/// then keeps its admission until nothing of it is held on the wire.
async fn watch(watched: Watched) {
    let Watched {
        slot,
        instances,
        conn,
        instance,
        token,
        join,
        deadline,
        counters,
    } = watched;
    let id = slot.id;
    let ended = until_deadline(join, deadline, || {
        // Only before the head: once one is queued, the reply is taken.
        if conn.reply_error(id, &late()).is_ok() {
            token.cancel();
            counters.failed("deadline", LATE);
        }
    })
    .await;
    match ended {
        // Its work settled it.
        Ok(Some(Outcome::Completed)) => counters.completed(),
        Ok(Some(Outcome::Failed(code, message))) => counters.failed(code, message),
        Ok(Some(Outcome::Settled)) => {}
        Err(error) if error.is_panic() => {
            counters.failed("internal", PANICKED);
            // 1. The fence, before anything is queued or awaited.
            let retiring = instances.fence_after_panic(&instance);
            // 2. The request's terminal, queued, not awaited.
            let _ = conn.settle(
                id,
                &ErrorBody::new(ErrorCode::Internal, PANICKED),
                &Abort::new(AbortCode::Internal, PANICKED),
            );
            // 3 and 4. The rest of the teardown, then the event.
            if let Some(retiring) = retiring {
                instances.retire(&conn, retiring);
            }
        }
        // Cancelled (main's cancel and the deadline have settled it), or
        // its runtime dropped it: owed `stopped`, if nothing settled it.
        Ok(None) | Err(_) => {
            let _ = conn.settle(id, &stopped(), &Abort::new(AbortCode::Stopped, STOPPED));
        }
    }
    conn.settled(id).await;
    drop(slot);
}

/// Awaits `join`, calling `on_deadline` once if `deadline` passes first.
async fn until_deadline<T>(
    mut join: JoinHandle<T>,
    deadline: Instant,
    on_deadline: impl FnOnce(),
) -> Result<T, JoinError> {
    let mut sleep = Box::pin(tokio::time::sleep_until(deadline));
    let mut on_deadline = Some(on_deadline);
    std::future::poll_fn(move |cx| {
        if let Poll::Ready(ended) = Pin::new(&mut join).poll(cx) {
            return Poll::Ready(ended);
        }
        if on_deadline.is_some()
            && sleep.as_mut().poll(cx).is_ready()
            && let Some(expired) = on_deadline.take()
        {
            expired();
        }
        Poll::Pending
    })
    .await
}

/// How a request's work ended, for its instance's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Its body's `end` queued, or its head without a body.
    Completed,
    /// With an error the work gave it: its code and fixed message.
    Failed(&'static str, &'static str),
    /// Settled by someone else (a cancel, the deadline, a teardown), or the
    /// connection closing.
    Settled,
}

/// What a request's work needs besides the request.
struct Work {
    conn: Connection,
    id: u64,
    core: GatewayCore,
    head_only: bool,
    /// `headers_ms`'s end.
    deadline: Instant,
    budget: MemoryBudget,
    counters: Arc<GatewayCounters>,
}

/// How long before the head's deadline a wait for memory gives up, so the
/// work's `busy` usually beats the watcher's `deadline`: 50 ms, or half of
/// a shorter `headers_ms`. A scheduling allowance, not the arbiter: the
/// refusal is queued against the deadline itself ([`busy`]).
const MEMORY_MARGIN: Duration = Duration::from_millis(50);
/// How long a stream's next fetch waits for memory (0007, "Budgets").
pub const STREAM_MEMORY_WAIT: Duration = Duration::from_secs(10);
/// Upstream's header naming an error response's cause.
const ERROR_CODE_HEADER: &str = "x-freedom-ipfs-error-code";
/// What a body's error says when a fetch couldn't reserve memory: upstream
/// gives the body no typed error, only its text.
const MEMORY_REFUSED: &str = "memory budget";
const BUSY: &str = "the memory budget is exhausted";

/// The work of a request: the gateway's response, its head, then its body
/// under credit. Every way out leaves the request settled, or settled
/// already by someone else (a cancel, the deadline, a teardown), or the
/// connection closing.
///
/// **Memory** (0007, "When admitted work can't reserve"): before the head,
/// the gateway's fetches wait for memory until a moment before
/// `headers_ms` ends ([`MEMORY_MARGIN`]), and what the head will hold
/// ([`fc_service::conn::head_len`]) is reserved within the same time, held
/// until the writer has written it. A refusal is `busy` if that is queued
/// before `headers_ms` ends, and `deadline` otherwise, as a head would be.
/// (If upstream moves on to another source after a refusal, its answer can
/// come after `headers_ms`: the reply is then `deadline` too.) After the
/// head, each next read of the body waits for its fetches' memory up to
/// 10 s, then the stream aborts `busy`.
async fn serve(work: Work, request: GatewayCoreRequest) -> Outcome {
    let Work {
        conn,
        id,
        core,
        head_only,
        deadline,
        budget,
        counters,
    } = work;
    let hooks = RequestHooks::of(&request);
    hooks.at(Phase::Request).await;
    let memory_deadline = memory_deadline(deadline);
    let response = with_memory_wait(MemoryWait::until(memory_deadline), core.handle(request)).await;
    let status = response.status().as_u16();
    let cause = response
        .headers()
        .get(ERROR_CODE_HEADER)
        .and_then(|value| value.to_str().ok());
    if status == 503 && cause == Some("memory_budget") {
        // The gateway's fetches couldn't reserve in time: `busy`, not the
        // gateway's 503 head.
        return busy(&conn, id, deadline);
    }
    if status == 503 && cause == Some("gateway_busy") {
        counters.gateway_busy();
    }
    // Main's rule today: no body for HEAD, 204, 205 and 304.
    let body = !head_only && !matches!(status, 204 | 205 | 304);
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    let head = json!({ "status": status, "headers": headers, "body": body });
    // What the pending head holds, reserved before it is encoded, and held
    // until the writer has written it (0007, "Pending replies").
    let size = match fc_service::conn::head_len(id, &head) {
        Ok(size) => size,
        Err(_) => return too_large(&conn, id, deadline),
    };
    let Ok(charge) = budget.reserve_until(size, memory_deadline).await else {
        return busy(&conn, id, deadline);
    };
    // Queued only before the deadline, checked as it is queued: however
    // late this work runs, and however late its watcher, a head after
    // `headers_ms` is never sent, and one queued in time stands.
    match conn.head_by(
        id,
        &head,
        body,
        deadline.into_std(),
        &late(),
        Some(Box::new(charge)),
    ) {
        Ok(Headed::Queued) => {}
        // `deadline` is its reply: the work ends here.
        Ok(Headed::Late) => return Outcome::Failed("deadline", LATE),
        Err(SendError::TooLarge) => return too_large(&conn, id, deadline),
        // Settled already (a cancel, the deadline), or closing.
        Err(_) => return Outcome::Settled,
    }
    if !body {
        return Outcome::Completed;
    }
    hooks.at(Phase::Body).await;
    let stream_wait = testhooks::stream_memory_wait(STREAM_MEMORY_WAIT);
    let mut data = response.into_body().into_data_stream();
    loop {
        let next = with_memory_wait(
            MemoryWait::until(Instant::now() + stream_wait),
            std::future::poll_fn(|cx| Pin::new(&mut data).poll_next(cx)),
        )
        .await;
        match next {
            None => break,
            Some(Ok(bytes)) if bytes.is_empty() => {}
            Some(Ok(bytes)) => {
                let send = Counted {
                    send: conn.send(id, &bytes),
                    counted: 0,
                    counters: &counters,
                };
                if send.await.is_err() {
                    // Aborted (a cancel, a teardown), or closing.
                    return Outcome::Settled;
                }
            }
            Some(Err(error)) => {
                let (code, abort, message) = if error.to_string().contains(MEMORY_REFUSED) {
                    ("busy", AbortCode::Busy, BUSY)
                } else {
                    (
                        "body_stream_error",
                        AbortCode::BodyStreamError,
                        "the response's body failed",
                    )
                };
                return match conn.abort(id, &Abort::new(abort, message)) {
                    Ok(()) => Outcome::Failed(code, message),
                    Err(_) => Outcome::Settled,
                };
            }
        }
    }
    match conn.finish(id) {
        Ok(()) => Outcome::Completed,
        Err(_) => Outcome::Settled,
    }
}

/// A send that counts its bytes in `bytes_read` as they are queued: so
/// what it queued is counted whether it then completes, fails, or is
/// dropped with its work (a cancel).
struct Counted<'a> {
    send: SendBytes<'a>,
    counted: usize,
    counters: &'a GatewayCounters,
}

impl Future for Counted<'_> {
    type Output = Result<(), SendError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.send).poll(cx);
        let sent = this.send.sent();
        this.counters.read(sent.saturating_sub(this.counted));
        this.counted = sent;
        polled
    }
}

/// When a request's waits for memory give up: [`MEMORY_MARGIN`] before its
/// head's deadline, or half way to a nearer one.
fn memory_deadline(deadline: Instant) -> Instant {
    let left = deadline.saturating_duration_since(Instant::now());
    deadline - MEMORY_MARGIN.min(left / 2)
}

/// Answers `busy` before the head, its memory not had in time, if that is
/// queued before `deadline`: as for a head, `deadline` from then on.
fn busy(conn: &Connection, id: u64, deadline: Instant) -> Outcome {
    let busy = ErrorBody::new(ErrorCode::Busy, BUSY);
    match conn.reply_error_by(id, &busy, deadline.into_std(), &late()) {
        Ok(Headed::Queued) => Outcome::Failed("busy", BUSY),
        Ok(Headed::Late) => Outcome::Failed("deadline", LATE),
        Err(_) => Outcome::Settled,
    }
}

/// Answers a head that can't be one frame, if that is queued before
/// `deadline`: as for a head, `deadline` from then on.
fn too_large(conn: &Connection, id: u64, deadline: Instant) -> Outcome {
    let message = "the response's head is too large";
    let internal = ErrorBody::new(ErrorCode::Internal, message);
    match conn.reply_error_by(id, &internal, deadline.into_std(), &late()) {
        Ok(Headed::Queued) => Outcome::Failed("internal", message),
        Ok(Headed::Late) => Outcome::Failed("deadline", LATE),
        Err(_) => Outcome::Settled,
    }
}

const STOPPED: &str = "the instance was stopped";
const PANICKED: &str = "the request's work panicked";

const LATE: &str = "no head within headers_ms";

/// The reply to a request with no head within `headers_ms`.
fn late() -> ErrorBody {
    ErrorBody::new(ErrorCode::Deadline, LATE)
}
const NOT_LIVE: &str = "the instance is retired, unknown or stopping";

fn stopped() -> ErrorBody {
    ErrorBody::new(ErrorCode::Stopped, STOPPED)
}

fn refuse(conn: &Connection, id: u64, code: ErrorCode, message: &str) {
    let _ = conn.reply_error(id, &ErrorBody::new(code, message));
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::mpsc;

    use super::*;

    type Hook = Box<dyn FnOnce() + Send>;

    /// Runs once, on the thread dropping a slot of the `Requests` it names,
    /// after the slot's admission has ended.
    static AFTER_FREE: Mutex<Option<(usize, Hook)>> = Mutex::new(None);

    pub(super) fn after_free(requests: &Arc<Requests>) {
        let mut hook = AFTER_FREE.lock().unwrap_or_else(|p| p.into_inner());
        if hook
            .as_ref()
            .is_some_and(|(of, _)| *of == Arc::as_ptr(requests) as usize)
            && let Some((_, hook)) = hook.take()
        {
            hook();
        }
    }

    fn entry(counters: &Arc<GatewayCounters>) -> Entry {
        Entry {
            instance: "e-1".into(),
            token: CancellationToken::new(),
            counters: counters.clone(),
            cancelled: false,
        }
    }

    /// Review of #141: a request admitted in the place of one whose slot
    /// is being dropped never counts as one more active than admitted.
    #[test]
    fn max_active_follows_admission_when_a_slot_is_reused() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .unwrap();
        let requests = Requests::new(runtime.handle().clone(), MemoryBudget::new(1));
        let counters = Arc::new(GatewayCounters::default());
        for id in 1..=MAX_ADMITTED as u64 {
            record(&mut requests.lock(), id, entry(&counters));
        }
        // Request 1's slot is dropped, and held just after its end is
        // counted: request 513 takes its place then.
        let (freed, seen) = mpsc::channel();
        let (resume, held) = mpsc::channel::<()>();
        *AFTER_FREE.lock().unwrap() = Some((
            Arc::as_ptr(&requests) as usize,
            Box::new(move || {
                freed.send(()).unwrap();
                held.recv().unwrap();
            }),
        ));
        let slot = Slot {
            requests: requests.clone(),
            id: 1,
            counters: counters.clone(),
        };
        let dropping = std::thread::spawn(move || drop(slot));
        seen.recv_timeout(Duration::from_secs(10)).unwrap();
        record(&mut requests.lock(), 513, entry(&counters));
        resume.send(()).unwrap();
        dropping.join().unwrap();
        let gateway = counters.snapshot();
        assert_eq!(requests.admitted(), MAX_ADMITTED);
        assert_eq!(gateway["active_native_handles"], MAX_ADMITTED);
        assert_eq!(gateway["max_active_handles"], MAX_ADMITTED, "{gateway}");
        requests.lock().clear();
        runtime.shutdown_background();
    }
}
