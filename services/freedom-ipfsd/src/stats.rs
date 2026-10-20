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
//! - **`progress`:** `null` until upstream's progress recorder leaves the
//!   FFI crate (upstream item 4; deviation `stats-progress`).
//! - **`store`:** `block_count` and `total_bytes`.
//! - **`budget`:** each budget's use and limit: the memory budget, the
//!   retrieval admission's four limits, the request admission, the writer's
//!   data queue, and the instance's background queue.
//!
//! The store's figures are SQLite queries, which can wait behind a
//! statement in progress, so they run as a control job, and the reply is
//! `deadline` past 5 s.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::stream::WRITER_DATA_CAP;
use fc_service::conn::Connection;
use fc_service::panic::{Labeled, TaskKind, with_kind};
use serde_json::value::RawValue;
use serde_json::{Value, json};
use tokio::runtime::Handle;

use crate::budget::Budgets;
use crate::instances::Instances;
use crate::params;
use crate::requests::{MAX_ADMITTED, Requests};

/// `ipfs.stats`'s deadline (0007, "Methods").
pub const STATS_DEADLINE: Duration = Duration::from_secs(5);

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

/// `ipfs.stats`, on the reader thread: `stopped` for an instance that isn't
/// live; otherwise answered from a control job, within 5 s.
pub fn stats(
    instances: &Arc<Instances>,
    requests: &Arc<Requests>,
    budgets: &Arc<Budgets>,
    runtime: &Handle,
    conn: &Connection,
    id: u64,
    params: Option<&RawValue>,
) {
    let instance_id = match params::stop(params) {
        Ok(instance_id) => instance_id,
        Err(message) => {
            let _ = conn.reply_error(id, &ErrorBody::new(ErrorCode::InvalidArgument, message));
            return;
        }
    };
    let Some((store, counters, background)) = instances.with_live(&instance_id, |running| {
        (
            running.instance.node().store().clone(),
            running.counters.clone(),
            running.instance.node().background_queue().clone(),
        )
    }) else {
        let _ = conn.reply_error(
            id,
            &ErrorBody::new(
                ErrorCode::Stopped,
                "the instance is retired, unknown or stopping",
            ),
        );
        return;
    };
    let gateway = counters.snapshot();
    let memory = &budgets.memory;
    let limits = &budgets.limits;
    let sizes = limits.sizes();
    let budget = json!({
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
    });
    let (reply, timer) = (conn.clone(), conn.clone());
    let figures = runtime.spawn_blocking(move || {
        with_kind(CONTROL, || {
            let store = match (store.block_count(), store.total_bytes()) {
                (Ok(block_count), Ok(total_bytes)) => {
                    json!({ "block_count": block_count, "total_bytes": total_bytes })
                }
                _ => Value::Null,
            };
            let _ = reply.reply(
                id,
                &json!({ "gateway": gateway, "progress": Value::Null, "store": store,
                    "budget": budget }),
            );
        });
    });
    drop(runtime.spawn(Labeled::new(CONTROL, async move {
        if tokio::time::timeout(STATS_DEADLINE, figures).await.is_err() {
            // Unanswered past its deadline: `deadline`, if the job hasn't
            // replied by now.
            let _ = timer.reply_error(
                id,
                &ErrorBody::new(ErrorCode::Deadline, "the stats took longer than 5 s"),
            );
        }
    })));
}
