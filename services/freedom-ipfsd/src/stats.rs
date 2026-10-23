//! `ipfs.stats` (design 0007, "Stats"): what `getNativeDiagnostics()`
//! shows today, under today's field names, for one instance.
//!
//! - **`gateway`:** the service counts these itself, per instance
//!   ([`GatewayCounters`]):
//!   - `active_native_handles`: its requests admitted and not yet freed;
//!   - `total_started`: admitted; `total_completed`: whose work reached its
//!     end (the body's `end` queued, or a head without a body);
//!     `total_failed`: ended by an error the service gave them (`deadline`,
//!     `busy`, `internal`, a body's `body_stream_error` or `busy` abort);
//!     `total_cancelled`: cancelled by main; `total_freed`: whose
//!     admission ended;
//!   - `total_gateway_busy_responses`: heads of upstream's 503
//!     `gateway_busy`; `bytes_read`: body bytes queued for main;
//!     `max_active_handles`;
//!   - `last_native_error_code` and `last_native_error_message`: the last
//!     failure's code and its fixed message, or a `gateway_busy` head's.
//!
//!   The event-queue fields went with the queue (deviation `stats-fields`).
//! - **`progress`:** in the persistent process, the instance's recorder's
//!   snapshot, cut to fit the reply's frame ([`crate::progress`]); `null`
//!   in the ephemeral process, which records none.
//! - **`store`:** `block_count` and `total_bytes`.
//! - **`budget`:** each budget's use and limit: the memory budget, the
//!   retrieval admission's four limits, the request admission, the writer's
//!   data queue, and the instance's background queue.
//!
//! The store's figures are SQLite queries, which can wait behind a
//! statement in progress, so they run as a blocking control job ([`Stats`]):
//! - **its deadline,** 5 s, runs from when the reader handles the request.
//!   The job's reply is queued only before it ([`Connection::reply_by`]),
//!   and a watcher answers `deadline` once it has passed, however late
//!   either runs.
//! - **at most [`MAX_STATS_JOBS`] stats calls** are outstanding in the
//!   process, each counted from its admission until its reply has been
//!   written (its reply holds its place, as a charge), or until its job's
//!   closure is dropped without a reply (aborted unrun, fenced, or answered
//!   `deadline`): never just because its job ended or its request was
//!   answered. Past them, `busy`.
//! - **a cancel, or the deadline,** fences the job, which then runs no SQL,
//!   and aborts it if it hasn't started. A job that starts past its
//!   deadline runs no SQL either, whether or not the watcher has run.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::stream::{SendError, WRITER_DATA_CAP};
use fc_service::conn::{Charge, Connection};
use fc_service::panic::{Labeled, TaskKind, with_kind};
use serde_json::value::RawValue;
use serde_json::{Value, json};
use tokio::runtime::Handle;
use tokio::task::AbortHandle;

use crate::budget::Budgets;
use crate::instances::Instances;
use crate::network::NetworkPolicy;
use crate::requests::{MAX_ADMITTED, Requests};
use crate::{params, progress, testhooks};

/// `ipfs.stats`'s deadline (0007, "Methods").
pub const STATS_DEADLINE: Duration = Duration::from_secs(5);
/// The most stats calls outstanding at once in the process, each from its
/// admission until its reply is written (0007, "Stats"): main asks every
/// 5 s and gives up at 20 s, so it has at most 4 asked.
pub const MAX_STATS_JOBS: usize = 4;

/// The stats' control job: the service's own work, so a panic exits 70.
const CONTROL: TaskKind = TaskKind::named("control");

/// An instance's gateway counters, today's `getNativeDiagnostics()`.
#[derive(Debug, Default)]
pub struct GatewayCounters {
    started: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    cancelled: AtomicU64,
    freed: AtomicU64,
    gateway_busy: AtomicU64,
    bytes_read: AtomicU64,
    max_active: AtomicU64,
    last_error: Mutex<Option<(&'static str, &'static str)>>,
}

impl GatewayCounters {
    /// A request admitted.
    pub fn started(&self) {
        let started = self.started.fetch_add(1, Ordering::Relaxed) + 1;
        let active = started.saturating_sub(self.freed.load(Ordering::Relaxed));
        self.max_active.fetch_max(active, Ordering::Relaxed);
    }

    /// Its work reached its end.
    pub fn completed(&self) {
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    /// It ended with an error the service gave it: a fixed code and
    /// message.
    pub fn failed(&self, code: &'static str, message: &'static str) {
        self.failed.fetch_add(1, Ordering::Relaxed);
        self.last_error(code, message);
    }

    /// Main cancelled it.
    pub fn cancelled(&self) {
        self.cancelled.fetch_add(1, Ordering::Relaxed);
    }

    /// Its admission ended.
    pub fn freed(&self) {
        self.freed.fetch_add(1, Ordering::Relaxed);
    }

    /// Its head was upstream's 503 `gateway_busy`.
    pub fn gateway_busy(&self) {
        self.gateway_busy.fetch_add(1, Ordering::Relaxed);
        self.last_error("gateway_busy", "gateway busy");
    }

    /// `bytes` of its body queued for main.
    pub fn read(&self, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
    }

    fn last_error(&self, code: &'static str, message: &'static str) {
        *self
            .last_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((code, message));
    }

    /// Today's `gateway` object.
    pub fn snapshot(&self) -> Value {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let started = load(&self.started);
        let freed = load(&self.freed);
        let last = *self
            .last_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        json!({
            "active_native_handles": started.saturating_sub(freed),
            "total_started": started,
            "total_completed": load(&self.completed),
            "total_failed": load(&self.failed),
            "total_cancelled": load(&self.cancelled),
            "total_freed": freed,
            "total_gateway_busy_responses": load(&self.gateway_busy),
            "bytes_read": load(&self.bytes_read),
            "max_active_handles": load(&self.max_active),
            "last_native_error_code": last.map(|(code, _)| code),
            "last_native_error_message": last.map(|(_, message)| message),
        })
    }
}

/// The process's stats jobs: their bound, and how to fence and abort each.
pub struct Stats {
    /// The process runtime: the jobs, on its blocking pool, and their
    /// watchers.
    runtime: Handle,
    budgets: Arc<Budgets>,
    /// [`STATS_DEADLINE`], but in tests.
    deadline: Duration,
    /// The process records progress: the persistent one.
    progress: bool,
    /// The jobs outstanding, by request ID: each is removed when its
    /// closure is dropped.
    jobs: Mutex<HashMap<u64, Job>>,
    /// Jobs that started, and those of them that went past their fence
    /// to the store.
    started: AtomicU64,
    ran: AtomicU64,
    /// Jobs that queued their reply and returned.
    #[cfg(test)]
    replied: AtomicU64,
    /// Runs in the next job, once started, before its fence is checked.
    #[cfg(test)]
    before_fence: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

/// An outstanding stats job.
#[derive(Clone)]
struct Job {
    /// Set by a cancel or the deadline: the job runs no SQL.
    fence: Arc<AtomicBool>,
    /// Aborts it, if it hasn't started.
    abort: Option<AbortHandle>,
}

/// A stats call's place in the bound, from its admission: freed once its
/// reply has been written and flushed (the reply holds it, as a charge), or
/// when its job's closure is dropped without one: aborted before it ran,
/// fenced, or answered `deadline`.
struct JobSlot {
    stats: Arc<Stats>,
    id: u64,
}

impl Drop for JobSlot {
    fn drop(&mut self) {
        self.stats.lock().remove(&self.id);
    }
}

impl Stats {
    pub fn new(
        runtime: Handle,
        budgets: Arc<Budgets>,
        deadline: Duration,
        progress: bool,
    ) -> Arc<Stats> {
        Arc::new(Stats {
            runtime,
            budgets,
            deadline,
            progress,
            jobs: Mutex::new(HashMap::new()),
            started: AtomicU64::new(0),
            ran: AtomicU64::new(0),
            #[cfg(test)]
            replied: AtomicU64::new(0),
            #[cfg(test)]
            before_fence: Mutex::new(None),
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Job>> {
        self.jobs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The jobs outstanding now.
    #[cfg(test)]
    pub fn outstanding(&self) -> usize {
        self.lock().len()
    }

    /// Runs `hook` in the next job, once started, before its fence.
    #[cfg(test)]
    pub fn before_fence(&self, hook: Box<dyn FnOnce() + Send>) {
        *self.before_fence.lock().unwrap_or_else(|p| p.into_inner()) = Some(hook);
    }

    /// The jobs that have queued their reply and returned.
    #[cfg(test)]
    pub fn replied(&self) -> u64 {
        self.replied.load(Ordering::SeqCst)
    }

    /// The jobs that have started, and those that ran their SQL.
    #[cfg(test)]
    pub fn ran(&self) -> (u64, u64) {
        (
            self.started.load(Ordering::SeqCst),
            self.ran.load(Ordering::SeqCst),
        )
    }

    /// Main cancelled request `id`: if it is a stats job, it is fenced and,
    /// if it hasn't started, aborted. Outside the jobs' lock: an aborted
    /// job's closure, dropped, takes it to free its place.
    pub fn cancel(&self, id: u64) {
        let job = self.lock().get(&id).cloned();
        if let Some(job) = job {
            job.fence.store(true, Ordering::SeqCst);
            if let Some(abort) = &job.abort {
                abort.abort();
            }
        }
    }

    /// `ipfs.stats`, on the reader thread: `stopped` for an instance that
    /// isn't live, `busy` with [`MAX_STATS_JOBS`] outstanding; otherwise
    /// answered from a control job by its deadline.
    pub fn stats(
        self: &Arc<Self>,
        instances: &Arc<Instances>,
        requests: &Arc<Requests>,
        conn: &Connection,
        id: u64,
        params: Option<&RawValue>,
    ) {
        // From when the request is handled, however late anything after
        // runs.
        let deadline = Instant::now() + self.deadline;
        let instance_id = match params::stop(params) {
            Ok(instance_id) => instance_id,
            Err(message) => {
                let _ = conn.reply_error(id, &ErrorBody::new(ErrorCode::InvalidArgument, message));
                return;
            }
        };
        let Some((store, counters, background, recorder, policy)) =
            instances.with_live(&instance_id, |running| {
                (
                    running.instance.node().store().clone(),
                    running.counters.clone(),
                    running.instance.node().background_queue().clone(),
                    running.instance.progress().clone(),
                    running.policy,
                )
            })
        else {
            let _ = conn.reply_error(
                id,
                &ErrorBody::new(
                    ErrorCode::Stopped,
                    "the instance is retired, unknown or stopping",
                ),
            );
            return;
        };
        let fence = Arc::new(AtomicBool::new(false));
        {
            let mut jobs = self.lock();
            if jobs.len() >= MAX_STATS_JOBS {
                drop(jobs);
                let _ = conn.reply_error(
                    id,
                    &ErrorBody::new(ErrorCode::Busy, "4 stats calls are outstanding already"),
                );
                return;
            }
            jobs.insert(
                id,
                Job {
                    fence: fence.clone(),
                    abort: None,
                },
            );
        }
        let slot = JobSlot {
            stats: self.clone(),
            id,
        };
        let gateway = counters.snapshot();
        let budget = self.budget(requests, conn, &background);
        // A `direct` instance's address table reads the process's NAT64
        // discovery; a `socks5` one learns nothing.
        let network = match policy {
            NetworkPolicy::Direct => json!({ "mode": "direct", "nat64": instances.nat64() }),
            NetworkPolicy::Socks5 { .. } => json!({ "mode": "socks5", "nat64": null }),
        };
        let (reply, timer) = (conn.clone(), conn.clone());
        let stats = self.clone();
        let job = self.runtime.spawn_blocking(move || {
            // The call's place in the bound (`slot`) goes with the closure,
            // unless its reply takes it.
            stats.started.fetch_add(1, Ordering::SeqCst);
            #[cfg(test)]
            {
                let hook = stats
                    .before_fence
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take();
                if let Some(hook) = hook {
                    hook();
                }
            }
            if fence.load(Ordering::SeqCst) {
                return;
            }
            // Past its deadline, however late the watcher runs: no SQL, and
            // `deadline`, through the same check as a reply.
            if Instant::now() >= deadline {
                let _ = reply.reply_error_by(id, &late(), deadline, &late(), None);
                return;
            }
            stats.ran.fetch_add(1, Ordering::SeqCst);
            with_kind(CONTROL, || {
                let store = match (store.block_count(), store.total_bytes()) {
                    (Ok(block_count), Ok(total_bytes)) => {
                        json!({ "block_count": block_count, "total_bytes": total_bytes })
                    }
                    _ => Value::Null,
                };
                // Here, not on the reader thread: a snapshot copies what
                // the recorder holds.
                let progress = if stats.progress {
                    serde_json::to_value(recorder.snapshot()).unwrap_or(Value::Null)
                } else {
                    Value::Null
                };
                let mut result = json!({ "gateway": gateway, "progress": progress,
                    "store": store, "budget": budget, "network": network });
                if let Some(counts) = testhooks::progress_counts(&recorder) {
                    result["test_progress"] = counts;
                }
                let result = progress::fit(id, result);
                // Fitted, it is within a frame; were it not, it would still
                // be answered.
                // The reply holds the call's place until it is written: the
                // bound counts replies waiting for the writer too.
                let charge: Charge = Box::new(slot);
                if let Err(SendError::TooLarge) =
                    reply.reply_by(id, &result, deadline, &late(), Some(charge))
                {
                    let too_large = ErrorBody::new(ErrorCode::Internal, "the stats are too large");
                    let _ = reply.reply_error_by(id, &too_large, deadline, &late(), None);
                }
                #[cfg(test)]
                stats.replied.fetch_add(1, Ordering::SeqCst);
            });
        });
        // Its abort, recorded before anything can stop it: a cancel is
        // handled on this thread, after this returns.
        if let Some(entry) = self.lock().get_mut(&id) {
            entry.abort = Some(job.abort_handle());
        }
        let expires = tokio::time::Instant::from_std(deadline);
        let stats = self.clone();
        drop(self.runtime.spawn(Labeled::new(CONTROL, async move {
            if tokio::time::timeout_at(expires, job).await.is_err() {
                // Past its deadline: fenced, aborted if it hasn't started,
                // and `deadline`, unless it was answered in time.
                stats.cancel(id);
                let _ = timer.reply_error(id, &late());
            }
        })));
    }

    /// Each budget's use and limit.
    fn budget(
        &self,
        requests: &Requests,
        conn: &Connection,
        background: &freedom_ipfs_gateway::BackgroundQueue,
    ) -> Value {
        let memory = &self.budgets.memory;
        let limits = &self.budgets.limits;
        let sizes = limits.sizes();
        json!({
            "memory": { "used": memory.used(), "limit": memory.limit() },
            "requests": { "admitted": requests.admitted(), "limit": MAX_ADMITTED },
            "writer": { "queued": conn.stats().held_bytes, "limit": WRITER_DATA_CAP },
            "block_fetches": {
                "in_flight": limits.block_fetches_in_flight(), "limit": sizes.block_fetches },
            "http_provider_requests": {
                "in_flight": limits.http_provider_requests_in_flight(),
                "limit": sizes.http_provider_requests },
            "bitswap_connections": {
                "in_use": limits.bitswap_connections(),
                "waiting": limits.bitswap_connections_waiting(),
                "denied": limits.bitswap_connections_denied(),
                "limit": sizes.bitswap_connections },
            "dht_queries": {
                "in_flight": limits.dht_queries_in_flight(), "limit": sizes.dht_queries },
            "background": {
                "outstanding": background.outstanding(),
                "dropped": background.dropped(),
                "limit": background.capacity() },
        })
    }
}

/// The reply past the deadline.
fn late() -> ErrorBody {
    ErrorBody::new(ErrorCode::Deadline, "no stats within 5 s")
}
