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
//!   terminal, written): heads, open streams and work still ending after a
//!   cancel all count. Its record ([`Slot`]) is an owned guard, dropped
//!   only then.
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
//!     cancelled. After the head there is no deadline here.
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

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::stream::{Abort, AbortCode, SendError};
use fc_service::conn::Connection;
use fc_service::panic::{Labeled, TaskKind};
use freedom_ipfs_gateway::{
    CancellationToken, GatewayCore, GatewayCoreRequest, NativeRequest, parse_native_request,
};
use futures_core::Stream;
use serde_json::json;
use serde_json::value::RawValue;
use tokio::runtime::Handle;
use tokio::task::{JoinError, JoinHandle};
use tokio::time::Instant;

use crate::instances::Instances;
use crate::params;
use crate::testhooks::{Phase, RequestHooks};

/// The most requests admitted at once in the process (0007, "Admission").
pub const MAX_ADMITTED: usize = 512;

/// A request's watcher: the service's own work, so a panic in it exits 70.
const WATCHER: TaskKind = TaskKind::named("request-watch");

/// The process's requests.
pub struct Requests {
    /// The process runtime: the watchers.
    runtime: Handle,
    table: Mutex<HashMap<u64, Entry>>,
}

/// An admitted request.
struct Entry {
    /// The instance it runs on.
    instance: String,
    /// Its work's token.
    token: CancellationToken,
}

impl Requests {
    pub fn new(runtime: Handle) -> Arc<Requests> {
        Arc::new(Requests {
            runtime,
            table: Mutex::new(HashMap::new()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Entry>> {
        self.table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
        let Some((context, core)) = instances.with_live(&wire.instance, |instance, core| {
            (instance.context().clone(), core.clone())
        }) else {
            drop(table);
            return refuse(conn, id, ErrorCode::Stopped, NOT_LIVE);
        };
        let token = context.request_token();
        table.insert(
            id,
            Entry {
                instance: wire.instance.clone(),
                token: token.clone(),
            },
        );
        drop(table);
        let slot = Slot {
            requests: self.clone(),
            id,
        };
        // Outside the service's locks, as every call into freedom-ipfs is.
        // An instance fenced since has refused it: `stopped`. One fenced
        // after cancels it, and its watcher settles it.
        let work = Labeled::new(
            TaskKind::REQUEST,
            serve(conn.clone(), id, core, parsed.request, head_only),
        );
        let Ok(join) = context.spawn_request(token.clone(), work) else {
            drop(slot);
            return refuse(conn, id, ErrorCode::Stopped, NOT_LIVE);
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
            }),
        )));
    }

    /// Main cancelled request `id`: its `cancelled` reply or abort is
    /// queued; its work ends at its next await.
    pub fn cancel(&self, id: u64) {
        if let Some(entry) = self.lock().get(&id) {
            entry.token.cancel();
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

/// A request's admission: released when dropped, by its watcher once the
/// work has ended and the request is settled on the wire, or on unwind.
struct Slot {
    requests: Arc<Requests>,
    id: u64,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.requests.lock().remove(&self.id);
    }
}

/// What a request's watcher holds.
struct Watched {
    slot: Slot,
    instances: Arc<Instances>,
    conn: Connection,
    instance: String,
    token: CancellationToken,
    join: JoinHandle<Option<()>>,
    deadline: Instant,
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
    } = watched;
    let id = slot.id;
    let ended = until_deadline(join, deadline, || {
        // Only before the head: once one is queued, the reply is taken.
        if conn
            .reply_error(
                id,
                &ErrorBody::new(ErrorCode::Deadline, "no head within headers_ms"),
            )
            .is_ok()
        {
            token.cancel();
        }
    })
    .await;
    match ended {
        // Its work settled it.
        Ok(Some(())) => {}
        Err(error) if error.is_panic() => {
            // 1. The fence, before anything is queued or awaited.
            let retiring = instances.fence_after_panic(&instance);
            // 2. The request's terminal, queued, not awaited.
            let _ = conn.settle(
                id,
                &ErrorBody::new(ErrorCode::Internal, "the request's work panicked"),
                &Abort::new(AbortCode::Internal, "the request's work panicked"),
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

/// The work of request `id`: the gateway's response, its head, then its
/// body under credit. Every way out leaves the request settled, or settled
/// already by someone else (a cancel, the deadline, a teardown), or the
/// connection closing.
async fn serve(
    conn: Connection,
    id: u64,
    core: GatewayCore,
    request: GatewayCoreRequest,
    head_only: bool,
) {
    let hooks = RequestHooks::of(&request);
    hooks.at(Phase::Request).await;
    let response = core.handle(request).await;
    let status = response.status().as_u16();
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
    match conn.head(id, &head, body) {
        Ok(()) => {}
        Err(SendError::TooLarge) => {
            let _ = conn.reply_error(
                id,
                &ErrorBody::new(ErrorCode::Internal, "the response's head is too large"),
            );
            return;
        }
        // Settled already (a cancel, the deadline), or closing.
        Err(_) => return,
    }
    if !body {
        return;
    }
    hooks.at(Phase::Body).await;
    let mut data = response.into_body().into_data_stream();
    while let Some(chunk) = std::future::poll_fn(|cx| Pin::new(&mut data).poll_next(cx)).await {
        match chunk {
            Ok(bytes) if bytes.is_empty() => {}
            Ok(bytes) => {
                if conn.send(id, &bytes).await.is_err() {
                    // Aborted (a cancel, a teardown), or closing.
                    return;
                }
            }
            Err(_) => {
                let _ = conn.abort(
                    id,
                    &Abort::new(AbortCode::BodyStreamError, "the response's body failed"),
                );
                return;
            }
        }
    }
    let _ = conn.finish(id);
}

const STOPPED: &str = "the instance was stopped";
const NOT_LIVE: &str = "the instance is retired, unknown or stopping";

fn stopped() -> ErrorBody {
    ErrorBody::new(ErrorCode::Stopped, STOPPED)
}

fn refuse(conn: &Connection, id: u64, code: ErrorCode, message: &str) {
    let _ = conn.reply_error(id, &ErrorBody::new(code, message));
}
