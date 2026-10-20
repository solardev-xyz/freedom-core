//! `freedom-cored serve`: the event loop (design 0001, "Process model").
//!
//! One thread owns all state and handles every message in order. Reading
//! stdin, writing stdout, logging and watching the parent happen on their own
//! threads behind bounded queues, so neither a slow peer nor a slow job can
//! keep the loop from handling EOF, shutdown or lock. KDF work will run on
//! worker threads and report back here.
//!
//! **Backpressure** (design 0001, Transport and framing). The loop's
//! replies and events go to the writer within its allowance
//! ([`transport::MAX_QUEUED_REPLIES`] frames). Past it they wait here, in
//! order ([`Outbox`]), and the loop takes no new request until they have
//! gone:
//!
//! - **Requests wait** in order, each with its reader credit, so once the
//!   credits are spent the reader stops reading stdin. Main's writes back
//!   up, not the core's memory.
//! - **The loop never blocks on the writer, nor polls it.** Freed room
//!   wakes it ([`Event::Room`]). Meanwhile it runs its timers and handles
//!   its worker's results, lifecycle events, and whatever else main sends:
//!   responses (for naming and chain), cancels and events.
//! - **The auto-lock fires on time,** whatever the room: it wipes the
//!   secrets and revokes admitted work at once. Only its event and the
//!   revoked requests' replies wait, and they carry no secret.
//! - **Requests that waited go one per turn of the loop** once there is
//!   room, each as if it had just been read: after the timers, so an
//!   auto-lock that comes due while they drain locks before the next one,
//!   and before a `vault.touch` could postpone it; and with whatever main
//!   sends meanwhile handled between them. The loop doesn't wait while one
//!   can go.
//! - **Control requests don't wait:**
//!   - **`core.shutdown`** among the waiting requests is handled at once.
//!     The requests before it are dropped: none of them ran, and main is
//!     closing the core.
//!   - **A `vault.lock`** locks at once and keeps its place, where it is
//!     handled again and acknowledged. Until then, whatever the requests
//!     before it admit is revoked at once, so nothing main sent before a
//!     lock outlives it.
//!   - **A `cancel`** reaches queued and running work at once, or waits
//!     behind its request if that request waits too.
//! - **What waits is bounded** by the work admitted before the wait: for
//!   each vault request (one running, 32 queued), its reply and at most one
//!   event. Lock events don't pile up: after a lock nothing can unlock
//!   until requests are taken again.
//! - **A stall ends the core:** once frames have waited [`STALL`] with the
//!   writer writing nothing, main has stopped reading, and the core exits.

use std::collections::VecDeque;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError, Sender, TryRecvError};
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::frame::{Frame, KIND_JSON};
use fc_protocol::message::{self, CallerKind, Context, Message, MessageError};
use fc_protocol::methods::{self, Admission};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use crate::exit::Exit;
use crate::requests::{self, Owner, Requests};
use crate::transport::{self, Allowance, Credits, Link, Pending};
use crate::vault::{FileSnapshot, Finished, NodeRecovery, Out, Vault};
use crate::worker::Worker;
use crate::{chain, gate, hardening, log, naming};
#[cfg(debug_assertions)]
use crate::{testhooks, testmethods};

/// How long the writer may take to flush on exit.
const EXIT_DRAIN: Duration = Duration::from_secs(2);
/// How long exiting waits for a vault job past its commit point to finish
/// and reply: inside main's 3 s shutdown grace, so the core exits on its
/// own (#127). A commit is a rename or unlink plus a directory flush, or a
/// node write's few fsyncs; the next start's recovery covers anything
/// slower, as it would a kill.
const COMMIT_DRAIN: Duration = Duration::from_secs(2);
/// How long the loop's frames may wait with the writer writing nothing
/// before the core decides main has stopped reading, and exits (design
/// 0001, Transport and framing):
/// - **Far above a healthy main's pauses:** a GC pause or a busy main
///   thread lasts milliseconds to seconds. Waiting costs nothing meanwhile:
///   no buffer grows, and the auto-lock still fires.
/// - **Between main's hang watchdogs** (deadline + 15 s): it is the longest
///   deadline the core gives a request (the KDF methods'), whose reply main
///   waits 45 s for. The core never gives up sooner than main does on a
///   short request (20 s), and a main that can no longer run its timers
///   keeps it waiting no longer than main would wait for a KDF reply.
const STALL: Duration = Duration::from_secs(30);

pub struct Options {
    pub data_dir: PathBuf,
    pub lock_dir: PathBuf,
    pub parent_pid: Option<u32>,
    pub hello_timeout: Duration,
    /// When the process started: the hello deadline counts from here, not
    /// from after the gate is taken.
    pub started: Instant,
}

/// What the loop reacts to.
pub enum Event {
    /// A frame, and its place in the reader's credits.
    Frame(Frame, transport::Credit),
    /// A fragmented response, reassembled (design 0005, Frames), and the
    /// credit whose drop returns main's bulk credit.
    Response {
        id: u64,
        payload: Zeroizing<Vec<u8>>,
        credit: transport::Credit,
    },
    Eof {
        at_boundary: bool,
        /// A fragmented response was in reassembly; it is discarded.
        in_response: bool,
    },
    /// A framing error, as a fixed category (never input text).
    ProtocolError(&'static str),
    WriterFailed,
    ThreadDied(&'static str),
    ParentGone,
    /// The startup read of the vault file finished.
    Snapshot(FileSnapshot, NodeRecovery),
    /// A vault worker job finished.
    JobDone(u64, Finished),
    /// The writer has room again in the loop's share: the frames waiting
    /// here can go, then the requests that waited for them.
    Room,
}

/// The methods `core.hello`'s capabilities name: every method this build
/// implements but the `chain.*` methods (design 0006's `chain.html`
/// included), which design 0005 doesn't add to them (it adds features
/// only). Every method, these and the chain methods, is a row of
/// fc-protocol's method table, which says who may call it (#101); a test
/// keeps the two in step. Only the table's names, and in debug builds the
/// test methods', are ever logged; anything else is logged as `<unknown>`.
const CAPABILITIES: &[&str] = &[
    "core.hello",
    "core.shutdown",
    "vault.status",
    "vault.lock",
    "vault.touch",
    "vault.unlock",
    "vault.verify_password",
    "vault.change_password",
    "vault.delete",
    "vault.export_mnemonic",
    "vault.export_private_key",
    "vault.create",
    "vault.import",
    "vault.reconcile",
    "nodes.write_identity",
    "nodes.op_status",
    "keys.generate_mnemonic",
    "keys.validate_mnemonic",
    "keys.addresses",
    "keys.radicle_did",
    "compat.private_key",
    "compat.bee_wallet_key",
    "compat.publisher_key",
    "sign.transaction",
    "sign.message",
    "sign.typed_data",
    "swarm.sign_soc",
    "typed_data.hash",
    "naming.configure",
    "naming.availability",
    "naming.resolve_content",
    "naming.resolve_address",
    "naming.resolve_reverse",
    "naming.resolve_tezos",
    "naming.invalidate_content",
    "naming.invalidate_tezos",
    "dweb.open",
];

/// The features in `core.hello`'s capabilities, after the methods (design
/// 0005):
/// - `fragments`: fragmented responses with bulk credit (Frames). The core
///   always offers them; it sends them only to a main whose hello offered
///   `frames: ["fragment"]`.
/// - `myotis_refusal_codes`: the core reads a Myotis broadcast's `{
///   rejected: { reason, code: -32602 } }` (The rest). Main sends that form
///   only to a core that offers it.
const FEATURES: &[&str] = &["fragments", "myotis_refusal_codes"];

pub fn run(options: &Options) -> Exit {
    hardening::harden();
    if !hardening::request_parent_death_signal(options.parent_pid) {
        log::error("parent is already gone", serde_json::json!({}));
        return Exit::Ok;
    }
    let gate = match gate::acquire(&options.data_dir, &options.lock_dir) {
        Ok(gate) => {
            log::info(
                "gate taken",
                serde_json::json!({ "lock": gate.lock_path.display().to_string() }),
            );
            gate
        }
        Err(e) => {
            log::error(
                "cannot take the gate",
                serde_json::json!({ "error": e.to_string() }),
            );
            return Exit::from(&e);
        }
    };

    let (events_tx, events) = mpsc::channel();
    let credits = Arc::new(Credits::default());
    let link = Link::new();
    // The core's requests to main still waiting for their answers: the
    // reader's set, and the gate naming and chain send them through.
    let pending = Arc::new(Pending::default());
    let requests = Requests::new(requests::MAX_OUTSTANDING, Arc::clone(&pending));
    let writer = match transport::spawn_writer(events_tx.clone(), Arc::clone(&link)) {
        Ok(writer) => writer,
        Err(_) => return Exit::Internal,
    };
    // The loop's own share of the writer: room freed after a refusal wakes
    // the loop to send what waits.
    let allowance = Allowance::new(transport::MAX_QUEUED_REPLIES, usize::MAX);
    let room = events_tx.clone();
    allowance.on_room(move || {
        let _ = room.send(Event::Room);
    });
    let Ok(worker) = Worker::spawn(events_tx.clone()) else {
        return Exit::Internal;
    };
    // Naming runs on its own thread and writes its own frames (design 0004,
    // Admission: vault control traffic never waits on naming work).
    let Ok(naming) = naming::spawn(
        writer.queue.clone(),
        events_tx.clone(),
        Arc::clone(&requests),
    ) else {
        return Exit::Internal;
    };
    // Chain data runs on its own thread too (design 0005), and fragments
    // its large replies for a main that offered fragments.
    let Ok(chain) = chain::spawn(
        writer.queue.clone(),
        events_tx.clone(),
        Arc::clone(&link),
        Arc::clone(&requests),
    ) else {
        return Exit::Internal;
    };
    #[cfg(debug_assertions)]
    let test = if testhooks::test_methods() {
        match testmethods::spawn(writer.queue.clone(), Arc::clone(&link), events_tx.clone()) {
            Ok(test) => Some(test),
            Err(_) => return Exit::Internal,
        }
    } else {
        None
    };
    // The status snapshot is read once, on its own thread: the gate makes
    // this process the only writer, so it never needs re-reading, and slow
    // storage can't hold up the loop (deadline, EOF, parent exit). core.hello
    // is answered once the snapshot is ready.
    if transport::spawn_reader(
        events_tx.clone(),
        Arc::clone(&credits),
        Arc::clone(&link),
        pending,
    )
    .is_err()
        || !spawn_snapshot(gate.identity_dir.clone(), events_tx.clone())
        || !spawn_parent_watch(options.parent_pid, events_tx)
    {
        log::error("cannot start a thread", serde_json::json!({}));
        return Exit::Internal;
    }

    let mut core = Core {
        snapshot_ready: false,
        node_recovery: None,
        pending_hello: None,
        outbox: Outbox::new(
            writer.queue,
            allowance,
            Arc::clone(&link),
            crate::testhooks::stall(STALL),
        ),
        parked: VecDeque::new(),
        locks_ahead: 0,
        link: Arc::clone(&link),
        credit: None,
        hello_done: false,
        last_request_id: 0,
        vault: Vault::new(
            gate.identity_dir.clone(),
            fc_vault::state::DEFAULT_AUTO_LOCK_MS,
        ),
        worker,
        requests,
        naming,
        chain,
        #[cfg(debug_assertions)]
        test,
    };
    let hello_deadline = options.started + options.hello_timeout;
    let exit = loop {
        if !core.hello_done && Instant::now() >= hello_deadline {
            log::error("no core.hello within the deadline", serde_json::json!({}));
            break Exit::Protocol;
        }
        let timeout = if core.hello_done {
            // The vault's timers, and the stall bound while frames wait.
            [core.vault.next_wakeup(), core.outbox.deadline()]
                .into_iter()
                .flatten()
                .min()
                .map_or(Duration::from_secs(3600), |at| {
                    at.saturating_duration_since(Instant::now())
                })
        } else {
            hello_deadline.saturating_duration_since(Instant::now())
        };
        // While a request that waited can go, the loop doesn't wait: it
        // takes an event if one is there, then that request (`resume`).
        let received = if core.resumable() {
            events.try_recv().map_err(|e| match e {
                TryRecvError::Empty => RecvTimeoutError::Timeout,
                TryRecvError::Disconnected => RecvTimeoutError::Disconnected,
            })
        } else {
            events.recv_timeout(timeout)
        };
        // Whatever arrived, first apply what is due (auto-lock, deadlines):
        // a busy queue must not postpone either, nor a writer without room.
        if core.hello_done {
            let outs = core.vault.tick();
            if let Flow::Exit(exit) = core.dispatch(outs) {
                break exit;
            }
        }
        match received {
            Ok(Event::Frame(frame, credit)) => {
                if let Flow::Exit(exit) = core.arrived(frame, credit) {
                    break exit;
                }
            }
            Ok(Event::Response {
                id,
                payload,
                credit,
            }) => {
                // As a frame's: forwarded with the message, or dropped once
                // it is handled, which returns main's bulk credit.
                core.credit = Some(credit);
                let flow = core.handle_fragmented(id, payload);
                core.credit = None;
                if let Flow::Exit(exit) = flow {
                    break exit;
                }
            }
            Ok(Event::Eof {
                at_boundary,
                in_response,
            }) => {
                if in_response {
                    log::warn(
                        "stdin closed in the middle of a fragmented response",
                        serde_json::json!({}),
                    );
                } else if !at_boundary {
                    log::warn(
                        "stdin closed in the middle of a frame",
                        serde_json::json!({}),
                    );
                }
                break Exit::Ok;
            }
            Ok(Event::ProtocolError(category)) => {
                log::error(
                    "protocol error",
                    serde_json::json!({ "category": category }),
                );
                break Exit::Protocol;
            }
            Ok(Event::WriterFailed) => {
                log::error("stdout closed", serde_json::json!({}));
                break Exit::Protocol;
            }
            Ok(Event::ThreadDied(name)) => {
                log::error("a thread died", serde_json::json!({ "thread": name }));
                break Exit::Internal;
            }
            Ok(Event::ParentGone) => {
                log::info("parent exited", serde_json::json!({}));
                break Exit::Ok;
            }
            Ok(Event::Snapshot(snapshot, recovery)) => {
                core.vault.set_snapshot(snapshot);
                core.node_recovery = recovery;
                core.snapshot_ready = true;
                if let Some(id) = core.pending_hello.take()
                    && let Flow::Exit(exit) = core.hello_reply(id)
                {
                    break exit;
                }
            }
            Ok(Event::JobDone(job, output)) => {
                let outs = core.vault.job_done(job, output);
                if let Flow::Exit(exit) = core.dispatch(outs) {
                    break exit;
                }
            }
            Ok(Event::Room) => {
                if let Flow::Exit(exit) = core.outbox.pump(Instant::now()) {
                    break exit;
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break Exit::Ok,
        }
        // Then the next request that waited, if the loop's frames have room;
        // and a writer that has written nothing for the stall bound means
        // main has stopped reading.
        if let Flow::Exit(exit) = core.resume() {
            break exit;
        }
        if let Flow::Exit(exit) = core.outbox.check(Instant::now()) {
            break exit;
        }
    };
    // No more requests to main, whatever ended the loop.
    core.requests.close();
    // Wipe the vault and revoke pre-commit work. Work past its commit point
    // finishes and replies before exit (bounded). Then let the writer flush
    // what's queued, but never wait on a peer that stopped reading: exiting
    // releases the gate. Requests still waiting their turn are dropped with
    // the loop: none of them ran.
    let outs = core.vault.shutdown();
    let _ = core.dispatch(outs);
    let draining = Instant::now();
    let until = draining + COMMIT_DRAIN;
    while core.vault.committing() {
        let Some(left) = until.checked_duration_since(Instant::now()) else {
            break;
        };
        match events.recv_timeout(left) {
            Ok(Event::JobDone(job, finished)) => {
                let outs = core.vault.job_done(job, finished);
                let _ = core.dispatch(outs);
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    // However the wait ended: past the drain, or the wait itself timing out.
    if core.vault.committing() {
        log::error(
            "a committed vault job did not finish before exit",
            serde_json::json!({ "waited_ms": draining.elapsed().as_millis() }),
        );
    }
    // What waits for room goes past the allowance: the drain below bounds it
    // by time instead.
    core.outbox.drain();
    // The writer ends once the producers' queues close; the transport's own
    // frames (main's credit) stop here.
    link.detach();
    drop(core);
    let _ = writer.done.recv_timeout(EXIT_DRAIN);
    drop(gate);
    exit
}

/// Reads the status snapshot on its own thread. False if the thread can't be
/// created. If the read never finishes, the hello deadline ends the process.
fn spawn_snapshot(identity_dir: PathBuf, events: Sender<Event>) -> bool {
    std::thread::Builder::new()
        .name("snapshot".into())
        .spawn(move || {
            crate::testhooks::snapshot_delay();
            let (snapshot, recovery) = crate::vault::startup_snapshot(&identity_dir);
            let _ = events.send(Event::Snapshot(snapshot, recovery));
        })
        .is_ok()
}

/// Starts the parent watcher. False if the thread can't be created.
fn spawn_parent_watch(parent_pid: Option<u32>, events: Sender<Event>) -> bool {
    if parent_pid.is_none() {
        return true;
    }
    std::thread::Builder::new()
        .name("parent".into())
        .spawn(move || {
            while hardening::parent_alive(parent_pid) {
                std::thread::sleep(Duration::from_secs(2));
            }
            let _ = events.send(Event::ParentGone);
        })
        .is_ok()
}

enum Flow {
    Continue,
    Exit(Exit),
}

struct Core {
    /// Whether the startup snapshot has arrived.
    snapshot_ready: bool,
    /// Startup's node identity recovery outcome, for core.hello.
    node_recovery: NodeRecovery,
    /// A valid core.hello received before the snapshot was ready.
    pending_hello: Option<u64>,
    /// The loop's share of the writer, and its frames waiting past it.
    outbox: Outbox,
    /// Requests from main waiting, in order, for the loop's frames to go.
    parked: VecDeque<Parked>,
    /// The `vault.lock`s among them, applied already and still to come.
    locks_ahead: usize,
    /// Bulk credit: main's hello says whether it takes fragments.
    link: Arc<Link>,
    /// The credit of the frame being handled.
    credit: Option<transport::Credit>,
    hello_done: bool,
    last_request_id: u64,
    vault: Vault,
    worker: Worker,
    /// The core's requests to main: where main's responses go back to.
    requests: Arc<Requests>,
    naming: naming::Handle,
    chain: chain::Handle,
    /// The `test.*` methods' thread, when the test hooks enable it (debug
    /// builds only).
    #[cfg(debug_assertions)]
    test: Option<testmethods::Handle>,
}

#[derive(Deserialize)]
struct HelloParams {
    protocol: u32,
    #[allow(dead_code)]
    shell_version: String,
    auto_lock_ms: u64,
    /// The frame kinds main takes beyond whole messages: `"fragment"` for
    /// fragmented responses with bulk credit (design 0005, Frames). Other
    /// names are ignored.
    #[serde(default)]
    frames: Vec<String>,
    /// Where main keeps each node's identity (`data_dir` for Bee, `home` for
    /// Radicle), as absolute paths: their files, which JS wrote under the
    /// umask, are tightened to 0600 (design 0001, "Writes and durability";
    /// #85). Optional.
    #[serde(default)]
    node_roots: Option<NodeRoots>,
}

#[derive(Deserialize)]
struct NodeRoots {
    #[serde(default)]
    bee: Option<String>,
    #[serde(default)]
    radicle: Option<String>,
}

impl NodeRoots {
    /// The roots given, as absolute, normalized paths. Others are logged
    /// and skipped: tightening is hardening, not worth failing a handshake.
    fn valid(self) -> Vec<(&'static str, PathBuf)> {
        [("bee", self.bee), ("radicle", self.radicle)]
            .into_iter()
            .filter_map(|(node, root)| {
                let root = PathBuf::from(root?);
                if crate::journal::normalized_absolute(&root) {
                    Some((node, root))
                } else {
                    log::warn(
                        "ignoring a node root that isn't an absolute path",
                        serde_json::json!({ "node": node }),
                    );
                    None
                }
            })
            .collect()
    }
}

/// Tightens existing node identity files on their own thread, so slow
/// storage can't hold up the handshake or the loop. Main starts nodes only
/// after the handshake, and a node reading its files meanwhile is
/// unaffected by a mode change.
fn spawn_adoption(roots: Vec<(&'static str, PathBuf)>) {
    if roots.is_empty() {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("adopt".into())
        .spawn(move || {
            for (node, root) in roots {
                let changed = crate::nodes::tighten_existing(node, &root);
                if changed > 0 {
                    log::info(
                        "tightened node identity files to 0600",
                        serde_json::json!({ "node": node, "count": changed }),
                    );
                }
            }
        });
    if spawned.is_err() {
        log::warn(
            "cannot start the thread that tightens node identity files",
            serde_json::json!({}),
        );
    }
}

#[derive(Serialize)]
struct HelloResult<'a> {
    protocol: u32,
    core_version: &'static str,
    /// The methods, then the transport features.
    capabilities: Vec<&'static str>,
    /// A node identity write that startup recovery couldn't finish
    /// (`pending_recovery`) or found broken (`corrupt`); `null` otherwise.
    /// Main keeps that node stopped.
    node_recovery: &'a NodeRecovery,
}

/// Where `text`, borrowed from `payload`, lies in it.
fn span(payload: &[u8], text: &RawValue) -> Range<usize> {
    let start = (text.get().as_ptr() as usize).wrapping_sub(payload.as_ptr() as usize);
    start..start.saturating_add(text.get().len())
}

/// A method name that is safe to log: known names only.
fn loggable(method: &str) -> &'static str {
    if let Some(row) = methods::method(method) {
        return row.name;
    }
    #[cfg(debug_assertions)]
    if let Some(name) = testmethods::METHODS.iter().find(|m| **m == method) {
        return name;
    }
    "<unknown>"
}

/// Whether `caller` may call `method` (#101): fc-protocol's method table,
/// checked once for every request before anything is dispatched, and in
/// debug builds the test methods, when their hook enables them. `Err` is
/// the refusal: a method the table doesn't list is unknown; one it lists,
/// but not for this caller, is forbidden.
fn admitted(method: &str, caller: CallerKind, test_methods: bool) -> Result<(), ErrorBody> {
    match methods::admit(method, caller) {
        Admission::Allowed(_) => Ok(()),
        Admission::Forbidden => Err(ErrorBody::new(
            ErrorCode::Forbidden,
            "not callable by this caller",
        )),
        Admission::Unknown => {
            #[cfg(debug_assertions)]
            if test_methods && testmethods::handles(method) && caller != CallerKind::Page {
                return Ok(());
            }
            let _ = test_methods;
            Err(ErrorBody::new(ErrorCode::UnknownMethod, "Unknown method"))
        }
    }
}

/// A fixed category for a malformed message; the parser's own text can quote
/// input and is never logged.
fn message_category(error: &MessageError) -> &'static str {
    match error {
        MessageError::Malformed(_) => "malformed",
        MessageError::UnknownType(_) => "unknown_type",
        MessageError::Missing(field) => field,
        MessageError::BadId(_) => "bad_id",
        MessageError::ResultAndError => "result_and_error",
    }
}

/// A message from main that waits, with its reader credit, for the loop's
/// frames to go.
struct Parked {
    frame: Frame,
    credit: transport::Credit,
    /// Its request ID; `None` for a cancel waiting behind its request.
    request: Option<u64>,
    /// A `vault.lock` the loop has applied already; its turn acknowledges
    /// it.
    lock: bool,
}

/// What a message that arrives while requests wait asks of the loop before
/// its turn.
enum Ahead {
    /// `core.shutdown`: handled at once.
    Shutdown,
    /// `vault.lock`: locks at once, and waits for its turn.
    Lock(u64),
    /// Any other request: waits for its turn.
    Request(u64),
    /// A cancel: reaches admitted work at once, unless its request waits.
    Cancel(u64),
    /// Anything else is handled at once, as it adds nothing to the loop's
    /// frames: responses go to naming and chain, events are ignored, and a
    /// malformed message ends the connection.
    Other,
}

impl Ahead {
    fn of(frame: &Frame) -> Self {
        if frame.kind != KIND_JSON {
            return Ahead::Other;
        }
        match Message::decode(&frame.payload) {
            // Refused in its turn: web content can't lock or shut down.
            // Refused in its turn: a caller the method table doesn't allow
            // for it (web content, or the browser UI for `core.shutdown`)
            // can't shut down or lock ahead of the requests that wait.
            Ok(Message::Request {
                id,
                method,
                context,
                ..
            }) if !matches!(
                methods::admit(&method, context.caller),
                Admission::Allowed(_)
            ) =>
            {
                Ahead::Request(id)
            }
            Ok(Message::Request { id, method, .. }) => match &*method {
                "core.shutdown" => Ahead::Shutdown,
                "vault.lock" => Ahead::Lock(id),
                _ => Ahead::Request(id),
            },
            Ok(Message::Cancel { id }) => Ahead::Cancel(id),
            _ => Ahead::Other,
        }
    }
}

impl Core {
    /// A frame from main. While requests wait (the loop's frames have no
    /// room in the writer), requests wait too, in order, and keep their
    /// credits: once those are spent, the reader stops reading stdin.
    /// Control traffic doesn't wait ([`Ahead`]).
    fn arrived(&mut self, frame: Frame, credit: transport::Credit) -> Flow {
        if self.waiting() {
            match Ahead::of(&frame) {
                // What waits before it never ran, and main is closing the
                // core: dropped.
                Ahead::Shutdown => {
                    self.parked.clear();
                    self.locks_ahead = 0;
                }
                // Locks now, as the auto-lock would: the secrets go and
                // admitted work is revoked. Its acknowledgement waits for its
                // turn, and until then holds the lock (`resume`).
                Ahead::Lock(id) => {
                    self.park(frame, credit, Some(id), true);
                    let outs = self.vault.lock();
                    return self.dispatch(outs);
                }
                Ahead::Request(id) => {
                    self.park(frame, credit, Some(id), false);
                    return Flow::Continue;
                }
                // Its request hasn't been handled yet: it follows it.
                Ahead::Cancel(id) if self.parked.iter().any(|p| p.request == Some(id)) => {
                    self.park(frame, credit, None, false);
                    return Flow::Continue;
                }
                Ahead::Cancel(_) | Ahead::Other => {}
            }
        }
        self.handle(frame, credit)
    }

    /// Whether requests wait: the loop's frames wait for room, or requests
    /// taken meanwhile still wait for their turn.
    fn waiting(&self) -> bool {
        self.outbox.is_waiting() || !self.parked.is_empty()
    }

    fn park(&mut self, frame: Frame, credit: transport::Credit, request: Option<u64>, lock: bool) {
        if lock {
            self.locks_ahead += 1;
        }
        self.parked.push_back(Parked {
            frame,
            credit,
            request,
            lock,
        });
    }

    /// Whether a request that waited can go: the loop's frames have room.
    fn resumable(&self) -> bool {
        !self.parked.is_empty() && !self.outbox.is_waiting()
    }

    /// Handles the next request that waited, if it can go: one per turn of
    /// the loop, as if it had just been read, so whatever main sends
    /// meanwhile (a cancel, a shutdown) and the loop's timers come between
    /// them.
    fn resume(&mut self) -> Flow {
        if !self.resumable() {
            return Flow::Continue;
        }
        // What is due first, right before the request: an auto-lock that
        // came due while the backlog drained locks before it, and before a
        // `vault.touch` could postpone it.
        let outs = self.vault.tick();
        if let Flow::Exit(exit) = self.dispatch(outs) {
            return Flow::Exit(exit);
        }
        if self.outbox.is_waiting() {
            return Flow::Continue;
        }
        let Some(parked) = self.parked.pop_front() else {
            return Flow::Continue;
        };
        if parked.lock {
            self.locks_ahead = self.locks_ahead.saturating_sub(1);
        }
        if let Flow::Exit(exit) = self.handle(parked.frame, parked.credit) {
            return Flow::Exit(exit);
        }
        // A lock still to come holds meanwhile: what this request admitted
        // is revoked, as that lock's turn would have done.
        if self.locks_ahead > 0 {
            let outs = self.vault.lock();
            return self.dispatch(outs);
        }
        Flow::Continue
    }

    /// Handles a frame. A message forwarded to another thread takes its
    /// credit along; otherwise the credit goes once the frame is handled.
    fn handle(&mut self, frame: Frame, credit: transport::Credit) -> Flow {
        self.credit = Some(credit);
        let flow = self.handle_frame(frame);
        self.credit = None;
        flow
    }

    fn handle_frame(&mut self, frame: Frame) -> Flow {
        if frame.kind != KIND_JSON {
            log::error(
                "protocol error",
                serde_json::json!({ "category": "frame_kind" }),
            );
            return Flow::Exit(Exit::Protocol);
        }
        let message = match Message::decode(&frame.payload) {
            Ok(message) => message,
            Err(e) => {
                log::error(
                    "protocol error",
                    serde_json::json!({ "category": message_category(&e) }),
                );
                return Flow::Exit(Exit::Protocol);
            }
        };
        match message {
            Message::Request {
                id,
                method,
                params,
                context,
            } => {
                if !self.hello_done && method != "core.hello" {
                    log::error(
                        "protocol error",
                        serde_json::json!({ "category": "not_hello_first" }),
                    );
                    return Flow::Exit(Exit::Protocol);
                }
                // IDs come from main's counter: strictly increasing, never
                // reused.
                if id <= self.last_request_id {
                    log::error(
                        "protocol error",
                        serde_json::json!({ "category": "reused_id", "id": id }),
                    );
                    return Flow::Exit(Exit::Protocol);
                }
                self.last_request_id = id;
                self.handle_request(id, &method, params.map(|p| p.get()), &context)
            }
            _ if !self.hello_done => {
                log::error(
                    "protocol error",
                    serde_json::json!({ "category": "not_hello_first" }),
                );
                Flow::Exit(Exit::Protocol)
            }
            // A cancel names a vault request, a naming one or a chain one;
            // each ignores IDs it doesn't hold.
            Message::Cancel { id } => {
                if !self.chain.send(chain::In::Cancel { id }, None)
                    || !self
                        .naming
                        .send(naming::In::Cancel { id }, self.credit.take())
                {
                    return Flow::Exit(Exit::Internal);
                }
                let outs = self.vault.cancel(id);
                self.dispatch(outs)
            }
            Message::Response { id, outcome } => {
                let outcome = match outcome {
                    Ok(result) => Ok(span(&frame.payload, result)),
                    Err(error) => Err(span(&frame.payload, error.raw())),
                };
                self.response(id, outcome, frame.payload)
            }
            Message::Event { .. } => {
                log::warn("ignoring an event from main", serde_json::json!({}));
                Flow::Continue
            }
        }
    }

    /// A fragmented response, reassembled: it must be the response its begin
    /// named.
    fn handle_fragmented(&mut self, id: u64, payload: Zeroizing<Vec<u8>>) -> Flow {
        let category = match Message::decode(&payload) {
            Ok(Message::Response {
                id: answered,
                outcome,
            }) if answered == id && self.hello_done => {
                let outcome = match outcome {
                    Ok(result) => Ok(span(&payload, result)),
                    Err(error) => Err(span(&payload, error.raw())),
                };
                return self.response(id, outcome, payload);
            }
            Ok(_) if !self.hello_done => "not_hello_first",
            Ok(_) => "fragmented_not_its_response",
            Err(e) => message_category(&e),
        };
        log::error(
            "protocol error",
            serde_json::json!({ "category": category }),
        );
        Flow::Exit(Exit::Protocol)
    }

    /// Main's response to one of the core's requests (`shell.*`), routed
    /// to the thread that made it: the span of its `result` or its `error`
    /// in `message`, the response as it was read. One that answers no
    /// request is unsolicited, a protocol error (0001).
    fn response(
        &mut self,
        id: u64,
        outcome: Result<Range<usize>, Range<usize>>,
        message: Zeroizing<Vec<u8>>,
    ) -> Flow {
        let Some(owner) = self.requests.answered(id) else {
            log::error(
                "protocol error",
                serde_json::json!({ "category": "unsolicited_response" }),
            );
            return Flow::Exit(Exit::Protocol);
        };
        let sent = match (owner, outcome) {
            // Naming copies its result out of the message, and reads its
            // error whole.
            (Owner::Naming, outcome) => {
                let span = match &outcome {
                    Ok(span) | Err(span) => span.clone(),
                };
                let Some(text) = message
                    .get(span)
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                else {
                    return Flow::Exit(Exit::Internal);
                };
                let outcome = match outcome {
                    Ok(_) => match RawValue::from_string(text.to_owned()) {
                        Ok(result) => Ok(result),
                        Err(_) => return Flow::Exit(Exit::Internal),
                    },
                    Err(_) => {
                        let error = serde_json::from_str::<&RawValue>(text)
                            .map_err(|e| MessageError::Malformed(e.to_string()))
                            .and_then(ErrorBody::from_raw);
                        match error {
                            Ok(error) => Err(error),
                            Err(e) => {
                                log::error(
                                    "protocol error",
                                    serde_json::json!({ "category": message_category(&e) }),
                                );
                                return Flow::Exit(Exit::Protocol);
                            }
                        }
                    }
                };
                self.naming
                    .send(naming::In::Response { id, outcome }, self.credit.take())
            }
            // The chain thread takes the message itself, uncopied, and
            // charges it to the request that asked before reading any of it,
            // its result or its error (57-M4; round 2).
            (Owner::Chain, Ok(result)) => self.chain.send(
                chain::In::Response {
                    id,
                    reply: chain::Shell::Result { message, result },
                },
                self.credit.take(),
            ),
            (Owner::Chain, Err(error)) => self.chain.send(
                chain::In::Response {
                    id,
                    reply: chain::Shell::Failed { message, error },
                },
                self.credit.take(),
            ),
        };
        if sent {
            Flow::Continue
        } else {
            Flow::Exit(Exit::Internal)
        }
    }

    fn handle_request(
        &mut self,
        id: u64,
        method: &str,
        params: Option<&str>,
        context: &Context,
    ) -> Flow {
        let started = Instant::now();
        #[cfg(debug_assertions)]
        let test_methods = self.test.is_some();
        #[cfg(not(debug_assertions))]
        let test_methods = false;
        if let Err(refusal) = admitted(method, context.caller, test_methods) {
            return self.error(id, refusal);
        }
        let flow = match method {
            "core.hello" => self.hello(id, params),
            "core.shutdown" => {
                // No request to main goes after the acknowledgement.
                self.requests.close();
                match self.result(id, &serde_json::json!({})) {
                    Flow::Continue => Flow::Exit(Exit::Ok),
                    exit => exit,
                }
            }
            method if Vault::handles(method) => {
                let outs = self.vault.request(id, method, params);
                self.dispatch(outs)
            }
            method if naming::handles(method) => {
                let params = match params.map(|p| RawValue::from_string(p.to_owned())) {
                    Some(Ok(params)) => Some(params),
                    Some(Err(_)) => return Flow::Exit(Exit::Internal),
                    None => None,
                };
                if self.naming.send(
                    naming::In::Request {
                        id,
                        method: loggable(method),
                        params,
                    },
                    self.credit.take(),
                ) {
                    Flow::Continue
                } else {
                    Flow::Exit(Exit::Internal)
                }
            }
            method if chain::handles(method) => {
                let params = match params.map(|p| RawValue::from_string(p.to_owned())) {
                    Some(Ok(params)) => Some(params),
                    Some(Err(_)) => return Flow::Exit(Exit::Internal),
                    None => None,
                };
                if self.chain.send(
                    chain::In::Request {
                        id,
                        method: loggable(method),
                        params,
                    },
                    self.credit.take(),
                ) {
                    Flow::Continue
                } else {
                    Flow::Exit(Exit::Internal)
                }
            }
            #[cfg(debug_assertions)]
            method if testmethods::handles(method) && self.test.is_some() => {
                let params = match params.map(|p| RawValue::from_string(p.to_owned())) {
                    Some(Ok(params)) => Some(params),
                    Some(Err(_)) => return Flow::Exit(Exit::Internal),
                    None => None,
                };
                let sent = self.test.as_ref().is_some_and(|test| {
                    test.send(testmethods::In::Request { id, params }, self.credit.take())
                });
                if sent {
                    Flow::Continue
                } else {
                    Flow::Exit(Exit::Internal)
                }
            }
            _ => self.error(
                id,
                ErrorBody::new(ErrorCode::UnknownMethod, "Unknown method"),
            ),
        };
        log::info(
            "request",
            serde_json::json!({ "id": id, "method": loggable(method), "ms": started.elapsed().as_millis() as u64 }),
        );
        flow
    }

    fn hello(&mut self, id: u64, params: Option<&str>) -> Flow {
        let params: Option<HelloParams> = params.and_then(|p| serde_json::from_str(p).ok());
        let Some(params) = params else {
            let _ = self.error(
                id,
                ErrorBody::new(ErrorCode::InvalidArgument, "Invalid core.hello parameters"),
            );
            return Flow::Exit(Exit::Protocol);
        };
        if params.protocol != fc_protocol::PROTOCOL_VERSION {
            let _ = self.error(
                id,
                ErrorBody::new(ErrorCode::ProtocolMismatch, "Protocol mismatch")
                    .with_data(serde_json::json!({ "core": fc_protocol::PROTOCOL_VERSION })),
            );
            return Flow::Exit(Exit::Protocol);
        }
        if self.hello_done || self.pending_hello.is_some() {
            return self.error(
                id,
                ErrorBody::new(ErrorCode::InvalidArgument, "core.hello was already sent"),
            );
        }
        self.vault.set_auto_lock_ms(params.auto_lock_ms);
        spawn_adoption(params.node_roots.map(NodeRoots::valid).unwrap_or_default());
        // Granted with the handshake: main holds the core's credit from now
        // on, and the core main's if main takes fragments.
        if params.frames.iter().any(|kind| kind == "fragment") {
            self.link.offer();
        }
        if !self.snapshot_ready {
            self.pending_hello = Some(id);
            return Flow::Continue;
        }
        self.hello_reply(id)
    }

    fn hello_reply(&mut self, id: u64) -> Flow {
        self.hello_done = true;
        let mut payload = Zeroizing::new(Vec::with_capacity(1024));
        let written = message::write_result(
            &mut *payload,
            id,
            &HelloResult {
                protocol: fc_protocol::PROTOCOL_VERSION,
                core_version: env!("CARGO_PKG_VERSION"),
                capabilities: CAPABILITIES.iter().chain(FEATURES).copied().collect(),
                node_recovery: &self.node_recovery,
            },
        );
        match written {
            Ok(()) => self.send(&payload),
            Err(_) => Flow::Exit(Exit::Internal),
        }
    }

    /// Sends the vault's payloads and submits its jobs.
    fn dispatch(&mut self, outs: Vec<Out>) -> Flow {
        for out in outs {
            let flow = match out {
                Out::Send(payload) => self.send(&payload),
                Out::Job(id, job) => {
                    if self.worker.submit(id, job) {
                        Flow::Continue
                    } else {
                        Flow::Exit(Exit::Internal)
                    }
                }
            };
            if let Flow::Exit(exit) = flow {
                return Flow::Exit(exit);
            }
        }
        Flow::Continue
    }

    fn result<R: Serialize>(&mut self, id: u64, result: &R) -> Flow {
        let mut payload = Zeroizing::new(Vec::with_capacity(256));
        match message::write_result(&mut *payload, id, result) {
            Ok(()) => self.send(&payload),
            Err(_) => Flow::Exit(Exit::Internal),
        }
    }

    fn error(&mut self, id: u64, error: ErrorBody) -> Flow {
        let mut payload = Zeroizing::new(Vec::with_capacity(256));
        match message::write_error(&mut *payload, id, &error) {
            Ok(()) => self.send(&payload),
            Err(_) => Flow::Exit(Exit::Internal),
        }
    }

    /// Queues a reply or an event: one frame, as every vault reply fits
    /// one. Past the loop's allowance it waits in the outbox, and requests
    /// wait with it.
    fn send(&mut self, payload: &[u8]) -> Flow {
        let Some(frame) = transport::frame(payload) else {
            return Flow::Exit(Exit::Internal);
        };
        self.outbox.send(frame, Instant::now())
    }
}

/// The loop's share of the writer (0001's reserved capacity, which naming
/// and chain traffic can't take), and its frames waiting past it, in the
/// order they were made. It never blocks, and never buffers past the work
/// the loop has taken (see the module documentation).
struct Outbox {
    out: Sender<transport::Out>,
    allowance: Arc<Allowance>,
    link: Arc<Link>,
    waiting: VecDeque<Zeroizing<Vec<u8>>>,
    /// Since when frames have waited.
    since: Option<Instant>,
    /// [`STALL`], or a test's.
    stall: Duration,
}

impl Outbox {
    fn new(
        out: Sender<transport::Out>,
        allowance: Arc<Allowance>,
        link: Arc<Link>,
        stall: Duration,
    ) -> Self {
        Outbox {
            out,
            allowance,
            link,
            waiting: VecDeque::new(),
            since: None,
            stall,
        }
    }

    /// Queues `frame` behind the frames that wait, and hands the writer
    /// what fits.
    fn send(&mut self, frame: Zeroizing<Vec<u8>>, now: Instant) -> Flow {
        self.waiting.push_back(frame);
        self.pump(now)
    }

    /// Hands waiting frames to the writer, in order, while the allowance
    /// has room. A refusal arms the allowance's wake-up ([`Event::Room`]).
    fn pump(&mut self, now: Instant) -> Flow {
        while let Some(frame) = self.waiting.front() {
            let Some(hold) = self.allowance.take(frame.len()) else {
                break;
            };
            let Some(frame) = self.waiting.pop_front() else {
                break;
            };
            if self
                .out
                .send(transport::Out::Frame { frame, hold })
                .is_err()
            {
                return Flow::Exit(Exit::Protocol);
            }
        }
        if self.waiting.is_empty() {
            self.since = None;
        } else if self.since.is_none() {
            self.since = Some(now);
        }
        Flow::Continue
    }

    /// Whether frames wait for room.
    fn is_waiting(&self) -> bool {
        !self.waiting.is_empty()
    }

    /// While frames wait, since when the writer has written nothing: since
    /// they started waiting, or since its last write if later.
    fn still(&self) -> Option<Instant> {
        let since = self.since?;
        Some(self.link.last_write().map_or(since, |at| at.max(since)))
    }

    /// When the stall bound passes unless the writer moves: the loop wakes
    /// then to look.
    fn deadline(&self) -> Option<Instant> {
        self.still()?.checked_add(self.stall)
    }

    /// Ends the core once frames have waited for the stall bound with the
    /// writer writing nothing: main has stopped reading.
    fn check(&self, now: Instant) -> Flow {
        let Some(still) = self.still() else {
            return Flow::Continue;
        };
        let waited = now.saturating_duration_since(still);
        if waited < self.stall {
            return Flow::Continue;
        }
        log::error(
            "main is not reading replies",
            serde_json::json!({ "ms": u64::try_from(waited.as_millis()).unwrap_or(u64::MAX) }),
        );
        Flow::Exit(Exit::Protocol)
    }

    /// Hands every waiting frame to the writer, past the allowance: on
    /// exit, where the writer's drain is bounded by time instead.
    fn drain(&mut self) {
        for frame in self.waiting.drain(..) {
            let hold = self.allowance.force(frame.len());
            let _ = self.out.send(transport::Out::Frame { frame, hold });
        }
        self.since = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::mpsc::Receiver;

    /// An outbox with room for `frames` frames in the writer, the writer's
    /// end of its queue, the link whose count the writer moves, and how
    /// often freed room woke the loop.
    fn outbox(
        frames: usize,
    ) -> (
        Outbox,
        Receiver<transport::Out>,
        Arc<Link>,
        Arc<Mutex<usize>>,
    ) {
        let (out, queue) = mpsc::channel();
        let allowance = Allowance::new(frames, usize::MAX);
        let woken = Arc::new(Mutex::new(0));
        let count = Arc::clone(&woken);
        allowance.on_room(move || *count.lock().unwrap() += 1);
        let link = Link::new();
        let outbox = Outbox::new(out, allowance, Arc::clone(&link), STALL);
        (outbox, queue, link, woken)
    }

    fn reply(id: u64) -> Zeroizing<Vec<u8>> {
        let json = format!(r#"{{"type":"response","id":{id},"result":{{}}}}"#);
        transport::frame(json.as_bytes()).unwrap()
    }

    /// The writer writes the next frame queued `at` then, which frees its
    /// place: the ID of the response it was.
    fn write_one(queue: &Receiver<transport::Out>, link: &Link, at: Instant) -> u64 {
        let Ok(transport::Out::Frame { frame, hold }) = queue.try_recv() else {
            panic!("nothing for the writer");
        };
        link.wrote(at);
        drop(hold);
        let message: serde_json::Value = serde_json::from_slice(&frame[5..]).unwrap();
        message["id"].as_u64().unwrap()
    }

    #[test]
    fn frames_past_the_allowance_wait_in_order_and_go_as_room_frees() {
        let (mut outbox, queue, link, woken) = outbox(2);
        let now = Instant::now();
        for id in 1..=5 {
            assert!(matches!(outbox.send(reply(id), now), Flow::Continue));
        }
        // Two went to the writer; three wait here.
        assert_eq!(outbox.waiting.len(), 3);
        // Each frame written wakes the loop, which sends the next, in order.
        let mut written = Vec::new();
        while outbox.is_waiting() || written.len() < 5 {
            written.push(write_one(&queue, &link, now));
            assert!(matches!(outbox.pump(now), Flow::Continue));
        }
        assert_eq!(written, [1, 2, 3, 4, 5]);
        assert_eq!(*woken.lock().unwrap(), 3);
        // Nothing waits: no stall clock runs, however long.
        assert_eq!(outbox.deadline(), None);
        assert!(matches!(outbox.check(now + 10 * STALL), Flow::Continue));
    }

    #[test]
    fn a_stall_exits_only_after_the_bound_without_writer_progress() {
        // The clock is injected: the bound passes without a 30 s wait.
        let (mut outbox, queue, link, _) = outbox(1);
        let start = Instant::now();
        for id in 1..=3 {
            assert!(matches!(outbox.send(reply(id), start), Flow::Continue));
        }
        assert_eq!(outbox.deadline(), Some(start + STALL));
        let short = STALL - Duration::from_millis(1);
        assert!(matches!(outbox.check(start + short), Flow::Continue));
        // Main reads one of the loop's frames 20 s in: room wakes the loop,
        // the next frame goes, and the bound counts from that write.
        let read = start + Duration::from_secs(20);
        assert_eq!(write_one(&queue, &link, read), 1);
        assert!(matches!(outbox.pump(read), Flow::Continue));
        assert!(outbox.is_waiting());
        assert_eq!(outbox.deadline(), Some(read + STALL));
        // Then it reads only other producers' frames (naming's, chain's),
        // which wake nothing here: the writer still moved, and the bound
        // counts from there too.
        let other = read + Duration::from_secs(25);
        link.wrote(other);
        assert_eq!(outbox.deadline(), Some(other + STALL));
        assert!(matches!(outbox.check(other + short), Flow::Continue));
        // Then nothing for the whole bound: main has stopped reading, and
        // the core exits 76.
        let Flow::Exit(exit) = outbox.check(other + STALL) else {
            panic!("no exit once the bound passed");
        };
        assert_eq!(exit, Exit::Protocol);
        assert_eq!(exit.code(), 76);
    }

    #[test]
    fn exiting_hands_the_writer_what_waits() {
        let (mut outbox, queue, _link, _) = outbox(1);
        let now = Instant::now();
        for id in 1..=3 {
            assert!(matches!(outbox.send(reply(id), now), Flow::Continue));
        }
        outbox.drain();
        assert!(!outbox.is_waiting());
        assert_eq!(outbox.deadline(), None);
        let ids: Vec<u64> = std::iter::from_fn(|| match queue.try_recv() {
            Ok(transport::Out::Frame { frame, .. }) => {
                let message: serde_json::Value = serde_json::from_slice(&frame[5..]).unwrap();
                message["id"].as_u64()
            }
            _ => None,
        })
        .collect();
        assert_eq!(ids, [1, 2, 3]);
    }

    /// #101: every method served is a row of fc-protocol's method table,
    /// and every row is served: the capabilities, then the chain methods.
    #[test]
    fn every_method_has_a_row_and_every_row_a_handler() {
        let rows: Vec<&str> = methods::METHODS.iter().map(|m| m.name).collect();
        let served: Vec<&str> = CAPABILITIES.iter().chain(chain::METHODS).copied().collect();
        assert_eq!(rows, served);
        for name in rows {
            assert!(
                matches!(name, "core.hello" | "core.shutdown")
                    || Vault::handles(name)
                    || naming::handles(name)
                    || chain::handles(name),
                "{name}"
            );
            assert_eq!(loggable(name), name);
        }
        assert_eq!(loggable("compat.root_key"), "<unknown>");
    }

    #[test]
    fn only_requests_wait_and_shutdown_and_lock_are_seen_ahead() {
        let ahead = |message: serde_json::Value| {
            Ahead::of(&Frame {
                kind: KIND_JSON,
                payload: Zeroizing::new(message.to_string().into_bytes()),
            })
        };
        let request = |id: u64, method: &str, caller: &str| {
            serde_json::json!({
                "type": "request", "id": id, "method": method, "context": { "caller": caller },
            })
        };
        assert!(matches!(
            ahead(request(7, "core.shutdown", "shell")),
            Ahead::Shutdown
        ));
        // #101: main's own; from the browser UI it waits, to be refused.
        assert!(matches!(
            ahead(request(7, "core.shutdown", "chrome")),
            Ahead::Request(7)
        ));
        assert!(matches!(
            ahead(request(7, "vault.lock", "chrome")),
            Ahead::Lock(7)
        ));
        assert!(matches!(
            ahead(request(7, "vault.status", "chrome")),
            Ahead::Request(7)
        ));
        // Web content can't lock or shut down: refused in its turn.
        let page = serde_json::json!({
            "type": "request", "id": 8, "method": "vault.lock",
            "context": { "caller": "page", "page": {
                "origin": "https://a.example", "top_origin": "https://a.example",
                "frame": 1, "navigation": 1,
            } },
        });
        assert!(matches!(ahead(page), Ahead::Request(8)));
        assert!(matches!(
            ahead(serde_json::json!({ "type": "cancel", "id": 9 })),
            Ahead::Cancel(9)
        ));
        // Handled at once: a response, an event, a malformed message.
        assert!(matches!(
            ahead(serde_json::json!({ "type": "response", "id": 9, "result": {} })),
            Ahead::Other
        ));
        assert!(matches!(
            ahead(serde_json::json!({ "type": "event", "event": "x" })),
            Ahead::Other
        ));
        assert!(matches!(ahead(serde_json::json!([1])), Ahead::Other));
    }
}
