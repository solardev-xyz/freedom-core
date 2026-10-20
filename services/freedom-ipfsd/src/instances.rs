//! Instances, their IDs and their teardown (design 0007, "Instances and
//! their teardown" and "Instance IDs").
//!
//! - **IDs are never reused.** An `ipfs.start` that is admitted takes its
//!   ID for the life of the process: running, stopping, failed or stopped.
//!   A start naming a taken ID is `invalid_argument`. A refused start
//!   (`invalid_argument`, `busy`) takes nothing.
//! - **Admission is decided at once,** on the reader thread: the ID, the
//!   store's kind, and the room. The persistent process holds one disk
//!   instance at a time, the ephemeral process up to 8 memory instances. An
//!   instance that is stopping still holds its room (`busy`) until its
//!   teardown is proven.
//! - **The build** (opening the store, wiring the node, starting its
//!   runtime) runs as a control job on the process runtime's blocking pool,
//!   under `ipfs.start`'s 10 s deadline. A start that is fenced while it
//!   builds (a stop, main's cancel, the deadline, the end of the
//!   connection) has its instance torn down as soon as it exists. The 5 s
//!   bound runs from that first fence, through the build and the teardown:
//!   a build that outlasts it ends the process (70), as a teardown would.
//! - **The start's success** (`{ instance }`) is queued as a head without a
//!   body: the same response on the wire, but cancellable until written. A
//!   cancel that beats the writer gets `cancelled`, and the instance goes.
//! - **The teardown,** for `ipfs.stop`, a cancelled start and the end of the
//!   connection alike:
//!   1. **Fence:** the ID is retired at once, on the reader thread: a later
//!      `ipfs.stop` for it gets `stopped`. The 5 s watchdog is armed at the
//!      same moment.
//!   2. **Revoke:** the network capability comes with the network policy
//!      (upstream item 3, implementation step 8). Nothing to revoke yet.
//!   3. **Cancel:** the instance's requests are settled `stopped` (an error
//!      for those whose head isn't written, an abort for open streams;
//!      [`Requests::stop_instance`]), then [`Instance::begin_shutdown`]
//!      cancels the root token, and so every task.
//!   4. **Quiescence:** the teardown's own thread drains the task set and
//!      blocking regions, drops and joins the instance's runtime, then
//!      closes the store. Only `reached` proves it.
//!   5. **Acknowledge:** then the watchdog is disarmed, the room and the ID's
//!      record released, and `ipfs.stop` answered `{ instance }`.
//!
//!   If quiescence isn't proven, nothing is released: the connection fails
//!   with 70, and the armed watchdog ends the process within the 5 s
//!   whatever else happens (`teardown_unproven`). Once the connection has
//!   ended, its exit watchdog is that bound.
//! - **After a request panic** (0007, "Panics"), the request's watcher
//!   fences the instance first ([`Instances::fence_after_panic`]: retired,
//!   and its 5 s bound armed), queues the request's `internal`, then runs
//!   the rest of the teardown ([`Instances::retire`]), and once quiescence
//!   is proven sends `ipfs.instance_retired { instance, reason: "panic" }`.
//!   An instance already stopping is left to that teardown.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::Exit;
use fc_service::conn::Connection;
use fc_service::log;
use fc_service::panic::{Labeled, TaskKind, with_kind};
use fc_service::watchdog::Watchdog;
use freedom_ipfs_gateway::{
    GatewayConfig, GatewayCore, Instance, InstanceConfig, OnlineNode, Quiescence,
};
use freedom_ipfs_store::{SqliteBlockStore, StoreError};
use serde_json::json;
use serde_json::value::RawValue;
use tokio::runtime::Handle;

use crate::network::NetworkPolicy;
use crate::params::{self, Start, Store};
use crate::requests::Requests;
use crate::testhooks;

/// The teardown's bound (0007): past it, `teardown_unproven` and exit 70.
pub const TEARDOWN_BOUND: Duration = Duration::from_secs(5);
/// How long a teardown lets the instance's tasks and blocking regions end
/// by themselves before dropping its runtime drops them. The runtime's join
/// and the store's close (at most 2 s) fit in what is left of the bound.
const DRAIN: Duration = Duration::from_secs(1);
/// `ipfs.start`'s deadline (0007, "Methods").
pub const START_DEADLINE: Duration = Duration::from_secs(10);
/// How long a store whose instance didn't come up gets to close.
const STORE_CLOSE: Duration = Duration::from_secs(2);
/// The ephemeral process's most instances (0007, "Private windows").
pub const MAX_EPHEMERAL: usize = 8;
/// The most instance IDs one process records. Each private partition and
/// each restart of the persistent instance takes one, so only a fault in
/// main reaches it; past it, starts are `busy`.
pub const MAX_IDS: usize = 1 << 16;
/// The persistent store's file in the data directory: the add-on's, so the
/// cache carries over (0007, "Inside the process").
pub const STORE_FILE: &str = "freedom-ipfs.sqlite3";
/// The watchdog's reason, a fixed name.
const UNPROVEN: &str = "teardown_unproven";

/// The service's own control work: a panic in it exits 70 (0007, "Panics").
const CONTROL: TaskKind = TaskKind::named("control");

/// Which process this is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// The profile's process, with its store's path under the gate.
    Persistent { store: PathBuf },
    /// The private windows' process.
    Ephemeral,
}

impl Kind {
    /// The name `ipfs.hello` reports.
    pub fn name(&self) -> &'static str {
        match self {
            Kind::Persistent { .. } => "persistent",
            Kind::Ephemeral => "ephemeral",
        }
    }

    /// An instance's runtime (0007, "Inside the process"): the persistent
    /// instance gets the core count of workers, at most 8, and a blocking
    /// cap of 512; each ephemeral one 2 workers and 64.
    fn runtime(&self, seq: u64) -> InstanceConfig {
        // At most 15 bytes, which is all the OS shows: `seq` is at most
        // MAX_IDS.
        let thread_name = format!("ipfs-inst-{seq}");
        match self {
            Kind::Persistent { .. } => InstanceConfig {
                thread_name,
                worker_threads: std::thread::available_parallelism().map_or(1, |n| n.get().min(8)),
                max_blocking_threads: 512,
            },
            Kind::Ephemeral => InstanceConfig {
                thread_name,
                worker_threads: 2,
                max_blocking_threads: 64,
            },
        }
    }
}

/// The process's instances.
pub struct Instances {
    kind: Kind,
    /// The process runtime: control jobs and their timers.
    runtime: Handle,
    /// The process's requests: a teardown settles its instance's.
    requests: Arc<Requests>,
    table: Mutex<Table>,
    /// An instance left the table, or a teardown failed.
    changed: Condvar,
}

#[derive(Default)]
struct Table {
    /// Instances starting, running or stopping, by ID.
    active: HashMap<String, Slot>,
    /// IDs whose instance has ended, or never came up.
    retired: HashSet<String>,
    /// Instances admitted so far: names their runtimes' threads.
    admitted: u64,
    /// The connection has ended: nothing new is admitted.
    ended: bool,
    /// A teardown couldn't prove quiescence: the process exits 70.
    unproven: bool,
}

struct Slot {
    /// The `ipfs.start` request that admitted it.
    start: u64,
    state: State,
}

enum State {
    /// Being built by its start's job.
    Starting {
        /// Retired before its start answered, and why.
        fenced: Option<Fence>,
        /// The 5 s bound, armed at the first fence and carried through the
        /// build and the teardown, never restarted. None before a fence,
        /// and for a fence by the end of the connection, whose exit
        /// watchdog is the bound ([`arm`]).
        bound: Option<Watchdog>,
        /// `ipfs.stop` requests to answer once its teardown is proven.
        stops: Vec<u64>,
    },
    Live(Box<Running>),
    /// Retired: its teardown runs.
    Stopping {
        stops: Vec<u64>,
    },
}

/// A live instance, and the one gateway its requests share: the gateway's
/// header permits and queue are the instance's (0007: today's 8 permits and
/// 15 s queue).
struct Running {
    instance: Instance,
    core: GatewayCore,
}

/// An instance fenced after a request panic, to tear down
/// ([`Instances::retire`]).
pub struct Retiring {
    instance_id: String,
    instance: Instance,
    watchdog: Option<Watchdog>,
}

/// Why a starting instance was retired before its start answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fence {
    /// Main cancelled the `ipfs.start`: the connection answered `cancelled`.
    Cancelled,
    /// The start's deadline passed: it was answered `deadline`.
    Deadline,
    /// `ipfs.stop`, or the end of the connection: the start is answered
    /// `stopped` once its build ends.
    Stopped,
}

impl Slot {
    /// Whether it counts as the persistent process's one instance: running,
    /// or starting and not yet fenced.
    fn is_up(&self) -> bool {
        matches!(
            self.state,
            State::Live(_) | State::Starting { fenced: None, .. }
        )
    }

    /// Retires a live instance: it becomes `Stopping`, to answer `stops`
    /// once its teardown is proven. Returns the instance to tear down.
    fn retire(&mut self, stops: Vec<u64>) -> Option<Instance> {
        if !matches!(self.state, State::Live(_)) {
            return None;
        }
        match std::mem::replace(&mut self.state, State::Stopping { stops }) {
            // The shared gateway goes with the fence; requests still
            // running hold their own clones until they end.
            State::Live(running) => Some(running.instance),
            _ => None,
        }
    }
}

impl Instances {
    pub fn new(kind: Kind, runtime: Handle, requests: Arc<Requests>) -> Arc<Instances> {
        Arc::new(Instances {
            kind,
            runtime,
            requests,
            table: Mutex::new(Table::default()),
            changed: Condvar::new(),
        })
    }

    pub fn kind(&self) -> &Kind {
        &self.kind
    }

    /// Whether `instance_id` is live: built, with its start answered.
    #[cfg(test)]
    pub fn is_live(&self, instance_id: &str) -> bool {
        matches!(
            self.lock().active.get(instance_id),
            Some(Slot {
                state: State::Live(_),
                ..
            })
        )
    }

    fn lock(&self) -> MutexGuard<'_, Table> {
        self.table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Runs `f` with instance `instance_id` and its gateway, if the instance
    /// is live: built, its start answered, not retired. A request's work is
    /// spawned here, under the table's lock, so a fence handled after it
    /// finds the request.
    pub fn with_live<R>(
        &self,
        instance_id: &str,
        f: impl FnOnce(&Instance, &GatewayCore) -> R,
    ) -> Option<R> {
        match self.lock().active.get(instance_id) {
            Some(Slot {
                state: State::Live(running),
                ..
            }) => Some(f(&running.instance, &running.core)),
            _ => None,
        }
    }

    /// `ipfs.start`, on the reader thread: admitted or refused at once; the
    /// build runs as a control job.
    pub fn start(self: &Arc<Self>, conn: &Connection, id: u64, params: Option<&RawValue>) {
        let start = match params::start(params) {
            Ok(start) => start,
            Err(message) => return refuse(conn, id, ErrorCode::InvalidArgument, message),
        };
        let seq = {
            let mut table = self.lock();
            if let Err((code, message)) = self.admit(&table, &start) {
                drop(table);
                return refuse(conn, id, code, message);
            }
            table.admitted += 1;
            table.active.insert(
                start.instance.clone(),
                Slot {
                    start: id,
                    state: State::Starting {
                        fenced: None,
                        bound: None,
                        stops: Vec::new(),
                    },
                },
            );
            table.admitted
        };
        log::info(
            "instance starting",
            json!({ "instance": start.instance, "kind": self.kind.name() }),
        );
        let deadline = testhooks::start_deadline(START_DEADLINE);
        let (instances, timer_conn, instance) =
            (self.clone(), conn.clone(), start.instance.clone());
        drop(self.runtime.spawn(Labeled::new(CONTROL, async move {
            tokio::time::sleep(deadline).await;
            instances.start_expired(&timer_conn, id, &instance);
        })));
        let (instances, conn) = (self.clone(), conn.clone());
        drop(self.runtime.spawn_blocking(move || {
            with_kind(CONTROL, || instances.build(&conn, id, start, seq));
        }));
    }

    fn admit(&self, table: &Table, start: &Start) -> Result<(), (ErrorCode, &'static str)> {
        if table.ended {
            return Err((ErrorCode::Stopped, "the service is ending"));
        }
        if table.active.contains_key(&start.instance) || table.retired.contains(&start.instance) {
            return Err((ErrorCode::InvalidArgument, "instance IDs are never reused"));
        }
        match (&self.kind, start.store) {
            (Kind::Persistent { .. }, Store::Memory { .. }) => {
                return Err((
                    ErrorCode::InvalidArgument,
                    "the persistent process takes a disk store only",
                ));
            }
            (Kind::Ephemeral, Store::Disk { .. }) => {
                return Err((
                    ErrorCode::InvalidArgument,
                    "the ephemeral process takes memory stores only",
                ));
            }
            _ => {}
        }
        if table.active.len() + table.retired.len() >= MAX_IDS {
            return Err((
                ErrorCode::Busy,
                "this process has used too many instance IDs",
            ));
        }
        match self.kind {
            Kind::Persistent { .. } if table.active.values().any(Slot::is_up) => Err((
                ErrorCode::InvalidArgument,
                "the persistent process holds one instance at a time",
            )),
            Kind::Persistent { .. } if !table.active.is_empty() => {
                Err((ErrorCode::Busy, "the previous instance is still stopping"))
            }
            Kind::Ephemeral if table.active.len() >= MAX_EPHEMERAL => Err((
                ErrorCode::Busy,
                "the ephemeral process holds 8 instances, running or stopping",
            )),
            _ => Ok(()),
        }
    }

    /// The start's job: builds the instance, then makes it live, or tears it
    /// down if it was fenced meanwhile.
    fn build(&self, conn: &Connection, id: u64, start: Start, seq: u64) {
        testhooks::start_delay();
        testhooks::panic_at("start");
        let built = self.open(&start, seq);
        let instance_id = start.instance;
        let mut table = self.lock();
        let (fenced, bound, stops) = match table.active.get_mut(&instance_id) {
            Some(Slot {
                state:
                    State::Starting {
                        fenced,
                        bound,
                        stops,
                    },
                ..
            }) => (*fenced, bound.take(), std::mem::take(stops)),
            // Only this job leaves `Starting`.
            _ => return,
        };
        let instance = match built {
            Err(error) => {
                // Nothing was built: nothing to tear down. The replies are
                // queued with the room released, under the lock, and before
                // `end` is woken: the connection still takes them.
                log::warn(
                    "instance failed to start",
                    json!({ "instance": instance_id, "code": error.code }),
                );
                table.active.remove(&instance_id);
                table.retired.insert(instance_id.clone());
                match fenced {
                    None => {
                        let _ = conn.reply_error(id, &error);
                    }
                    Some(Fence::Stopped) => {
                        let _ = conn.reply_error(id, &stopped());
                    }
                    Some(Fence::Cancelled | Fence::Deadline) => {}
                }
                for stop in stops {
                    let _ = conn.reply(stop, &json!({ "instance": instance_id }));
                }
                drop(table);
                self.changed.notify_all();
                // The fence's bound, once the cleanup is done.
                if let Some(bound) = bound {
                    bound.disarm();
                }
                return;
            }
            Ok(built) => built,
        };
        let (instance, core) = instance;
        let Some(slot) = table.active.get_mut(&instance_id) else {
            return;
        };
        if fenced.is_none() {
            log::info("instance started", json!({ "instance": instance_id }));
            slot.state = State::Live(Box::new(Running { instance, core }));
            // Queued under the lock: a stop or a cancel handled after this
            // finds a live instance whose start is answered. A head without
            // a body, not a reply: a cancel that arrives before the writer
            // takes it still drops it, answers `cancelled`, and reaches
            // `cancel` below, which retires the instance.
            let _ = conn.head(id, &json!({ "instance": instance_id }), false);
            return;
        }
        slot.state = State::Stopping { stops };
        drop(table);
        if fenced == Some(Fence::Stopped) {
            let _ = conn.reply_error(id, &stopped());
        }
        // Fenced while it built: the bound armed at the fence goes on.
        log::info("instance stopping", json!({ "instance": instance_id }));
        self.tear_down(conn, &instance_id, instance, bound);
    }

    /// Opens the store and builds the instance on a runtime of its own, and
    /// the one gateway its requests share.
    fn open(&self, start: &Start, seq: u64) -> Result<(Instance, GatewayCore), ErrorBody> {
        let store = match (&self.kind, start.store) {
            (Kind::Persistent { store }, Store::Disk { max_bytes }) => {
                SqliteBlockStore::open(store, max_bytes)
            }
            (_, Store::Memory { max_bytes }) => SqliteBlockStore::in_memory(max_bytes),
            // Refused at admission.
            (Kind::Ephemeral, Store::Disk { .. }) => {
                return Err(ErrorBody::new(
                    ErrorCode::Internal,
                    "no disk store in the ephemeral process",
                ));
            }
        };
        let store = store.map_err(|error| {
            log::error(
                "the store won't open",
                json!({ "instance": start.instance, "error": store_error_kind(&error) }),
            );
            ErrorBody::new(ErrorCode::Storage, "the store won't open")
                .with_data(json!({ "kind": "store_open" }))
        })?;
        // Today's transports: the only policy until step 8 (`network.rs`).
        match start.network {
            NetworkPolicy::Direct => {}
        }
        let built = OnlineNode::builder(store.clone())
            .routing_mode(start.routing.mode)
            .delegated_routers(start.routing.delegated_routers.iter().cloned())
            .dht_query_timeout(start.routing.dht_query_timeout)
            .dht_max_providers(start.routing.dht_max_providers)
            .gateway_config(
                GatewayConfig::new(start.gateway.max_concurrent_requests)
                    .with_request_queue_timeout(start.gateway.request_queue_timeout),
            )
            .build_instance(self.kind.runtime(seq));
        match built {
            Ok(instance) => {
                testhooks::hold_teardown(&instance);
                let core = instance.gateway_core();
                Ok((instance, core))
            }
            Err(_) => {
                let _ = store.close(STORE_CLOSE);
                log::error(
                    "an instance's runtime didn't start",
                    json!({ "instance": start.instance }),
                );
                Err(ErrorBody::new(
                    ErrorCode::Internal,
                    "the instance's runtime didn't start",
                ))
            }
        }
    }

    /// The start's deadline passed: a start still building is fenced and
    /// answered `deadline`; its instance goes once built, within the bound.
    fn start_expired(&self, conn: &Connection, id: u64, instance_id: &str) {
        let mut table = self.lock();
        let ended = table.ended;
        if let Some(Slot {
            start,
            state: State::Starting { fenced, bound, .. },
        }) = table.active.get_mut(instance_id)
            && *start == id
            && fenced.is_none()
        {
            *fenced = Some(Fence::Deadline);
            *bound = arm(ended);
            let _ = conn.reply_error(
                id,
                &ErrorBody::new(ErrorCode::Deadline, "the instance didn't start in time"),
            );
        }
    }

    /// `ipfs.stop`, on the reader thread: the fence at once, then the
    /// teardown as a control job. Answered `{ instance }` once quiescence is
    /// proven, or `stopped` for an ID that is retired, unknown or stopping.
    pub fn stop(self: &Arc<Self>, conn: &Connection, id: u64, params: Option<&RawValue>) {
        let instance_id = match params::stop(params) {
            Ok(instance_id) => instance_id,
            Err(message) => return refuse(conn, id, ErrorCode::InvalidArgument, message),
        };
        let mut table = self.lock();
        let Some(slot) = table.active.get_mut(&instance_id) else {
            drop(table);
            return refuse(
                conn,
                id,
                ErrorCode::Stopped,
                "the instance is retired or unknown",
            );
        };
        match &mut slot.state {
            State::Starting {
                fenced: fenced @ None,
                bound,
                stops,
            } => {
                // Answered once its build ends and its teardown is proven,
                // within the bound armed now, at the fence.
                *fenced = Some(Fence::Stopped);
                *bound = arm(false);
                stops.push(id);
            }
            State::Live(_) => {
                let instance = slot.retire(vec![id]);
                drop(table);
                if let Some(instance) = instance {
                    self.spawn_tear_down(conn, instance_id, instance);
                }
            }
            State::Starting { .. } | State::Stopping { .. } => {
                drop(table);
                refuse(conn, id, ErrorCode::Stopped, "the instance is stopping");
            }
        }
    }

    /// Main cancelled request `id` before its reply was written. For an
    /// `ipfs.start`, main has its `cancelled`: the instance goes, built or
    /// not, within the bound armed at the fence. A stop's teardown goes on.
    pub fn cancel(self: &Arc<Self>, conn: &Connection, id: u64) {
        let mut table = self.lock();
        let Some((instance_id, slot)) = table.active.iter_mut().find(|(_, slot)| slot.start == id)
        else {
            return;
        };
        match &mut slot.state {
            State::Starting { fenced, bound, .. } => {
                if fenced.is_none() {
                    *fenced = Some(Fence::Cancelled);
                    *bound = arm(false);
                }
            }
            State::Live(_) => {
                // Its `{ instance }` head was queued but not written: the
                // connection dropped it for `cancelled`.
                let instance_id = instance_id.clone();
                let instance = slot.retire(Vec::new());
                drop(table);
                if let Some(instance) = instance {
                    self.spawn_tear_down(conn, instance_id, instance);
                }
            }
            State::Stopping { .. } => {}
        }
    }

    /// A teardown's 5 s bound: `teardown_unproven` and exit 70 unless
    /// disarmed in time. Once the connection has ended, its exit watchdog
    /// is that bound: armed before `Service::end`, it exits 70 with
    /// `teardown_unproven` 5 s later while the teardown hasn't returned. A
    /// second watchdog would fire with it, and two exits racing can cut
    /// each other's report.
    fn bound(&self) -> Option<Watchdog> {
        arm(self.lock().ended)
    }

    /// Steps 3 to 5 of a retired instance's teardown, as a control job; the
    /// bound is armed now, at the fence.
    fn spawn_tear_down(
        self: &Arc<Self>,
        conn: &Connection,
        instance_id: String,
        instance: Instance,
    ) {
        let watchdog = self.bound();
        log::info("instance stopping", json!({ "instance": instance_id }));
        let (instances, conn) = (self.clone(), conn.clone());
        drop(self.runtime.spawn_blocking(move || {
            with_kind(CONTROL, || {
                instances.tear_down(&conn, &instance_id, instance, watchdog);
            });
        }));
    }

    /// Cancels the instance (its requests settled `stopped` first) and
    /// waits for its teardown's proof.
    fn tear_down(
        &self,
        conn: &Connection,
        instance_id: &str,
        instance: Instance,
        watchdog: Option<Watchdog>,
    ) -> bool {
        self.requests.stop_instance(conn, instance_id);
        let quiescence = instance.begin_shutdown(DRAIN).wait();
        self.finish(conn, instance_id, quiescence, watchdog)
    }

    /// A request on `instance_id` panicked: steps 1 and 2 of its teardown,
    /// at once (0007, "Panics"). The ID is retired, so later requests and
    /// stops get `stopped`, and the 5 s bound is armed. Returns the instance
    /// to tear down once the request's terminal is queued; `None` if it
    /// isn't live (already stopping: that teardown goes on).
    pub fn fence_after_panic(&self, instance_id: &str) -> Option<Retiring> {
        let mut table = self.lock();
        let ended = table.ended;
        let instance = table.active.get_mut(instance_id)?.retire(Vec::new())?;
        drop(table);
        log::warn(
            "a request panicked: its instance is retired",
            json!({ "instance": instance_id }),
        );
        Some(Retiring {
            instance_id: instance_id.to_owned(),
            instance,
            watchdog: arm(ended),
        })
    }

    /// The rest of a panicked instance's teardown, from step 3, as a control
    /// job; then, once quiescence is proven, `ipfs.instance_retired`.
    pub fn retire(self: &Arc<Self>, conn: &Connection, retiring: Retiring) {
        let Retiring {
            instance_id,
            instance,
            watchdog,
        } = retiring;
        log::info("instance stopping", json!({ "instance": instance_id }));
        let (instances, conn) = (self.clone(), conn.clone());
        drop(self.runtime.spawn_blocking(move || {
            with_kind(CONTROL, || {
                if instances.tear_down(&conn, &instance_id, instance, watchdog) {
                    let _ = conn.event(
                        "ipfs.instance_retired",
                        &json!({ "instance": instance_id, "reason": "panic" }),
                    );
                }
            });
        }));
    }

    /// Acknowledges a teardown once quiescence is proven: the watchdog is
    /// disarmed, the room released, the ID recorded as retired, and the
    /// stops answered, in that order. Unproven, nothing is released.
    /// Returns whether quiescence was proven.
    fn finish(
        &self,
        conn: &Connection,
        instance_id: &str,
        quiescence: Quiescence,
        watchdog: Option<Watchdog>,
    ) -> bool {
        if !quiescence.reached {
            // The watchdog stays armed: it ends the process within its
            // bound whatever the connection's end does.
            log::error(
                "an instance's teardown is unproven",
                json!({
                    "instance": instance_id,
                    "joined": quiescence.joined,
                    "store_closed": quiescence.store_closed,
                }),
            );
            // The result first: `end` returns once it sees `unproven`.
            conn.fail(Exit::Internal);
            self.lock().unproven = true;
            self.changed.notify_all();
            return false;
        }
        if let Some(watchdog) = watchdog {
            watchdog.disarm();
        }
        log::info(
            "instance stopped",
            json!({ "instance": instance_id, "tasks_dropped": quiescence.tasks_dropped }),
        );
        let mut table = self.lock();
        let stops = match table.active.remove(instance_id) {
            Some(Slot {
                state: State::Stopping { stops },
                ..
            }) => stops,
            _ => Vec::new(),
        };
        table.retired.insert(instance_id.to_owned());
        // Under the lock with the release: a start main sends once it has
        // a reply finds the room free. And before `end` is woken: the
        // connection still takes them.
        for stop in stops {
            let _ = conn.reply(stop, &json!({ "instance": instance_id }));
        }
        drop(table);
        self.changed.notify_all();
        true
    }

    /// The connection ended (`Service::end`): every instance is torn down,
    /// in parallel, under the connection's exit watchdog ([`Self::bound`]).
    /// Returns once every instance has ended, starts still building and
    /// stops in flight included, or one teardown couldn't be proven.
    pub fn end(self: &Arc<Self>, conn: &Connection) {
        let live: Vec<(String, Instance)> = {
            let mut table = self.lock();
            table.ended = true;
            let mut live = Vec::new();
            for (instance_id, slot) in table.active.iter_mut() {
                if let State::Starting { fenced, .. } = &mut slot.state {
                    // Its job tears it down once built. A start fenced
                    // earlier keeps its bound; one fenced now is bounded by
                    // the connection's exit watchdog.
                    fenced.get_or_insert(Fence::Stopped);
                } else if let Some(instance) = slot.retire(Vec::new()) {
                    live.push((instance_id.clone(), instance));
                }
            }
            live
        };
        let begun: Vec<_> = live
            .into_iter()
            .map(|(instance_id, instance)| {
                log::info("instance stopping", json!({ "instance": instance_id }));
                self.requests.stop_instance(conn, &instance_id);
                (instance_id, instance.begin_shutdown(DRAIN))
            })
            .collect();
        for (instance_id, teardown) in begun {
            self.finish(conn, &instance_id, teardown.wait(), None);
        }
        let mut table = self.lock();
        while !table.active.is_empty() && !table.unproven {
            table = self
                .changed
                .wait(table)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

/// A teardown's bound (see [`Instances::bound`]), from a caller that holds
/// the table and knows whether the connection has ended.
fn arm(ended: bool) -> Option<Watchdog> {
    (!ended).then(|| Watchdog::arm(UNPROVEN, TEARDOWN_BOUND, Exit::Internal))
}

fn refuse(conn: &Connection, id: u64, code: ErrorCode, message: &str) {
    let _ = conn.reply_error(id, &ErrorBody::new(code, message));
}

fn stopped() -> ErrorBody {
    ErrorBody::new(ErrorCode::Stopped, "the instance was stopped")
}

/// A fixed name for a store error: its text can carry a path.
fn store_error_kind(error: &StoreError) -> &'static str {
    match error {
        StoreError::Sqlite(_) => "sqlite",
        StoreError::Core(_) => "core",
        StoreError::Json(_) => "json",
        StoreError::PageCap { .. } => "page_cap",
    }
}
