//! `freedom-cored serve`: the event loop (design 0001, "Process model").
//!
//! One thread owns all state and handles every message in order. Reading
//! stdin, writing stdout, logging and watching the parent happen on their own
//! threads behind bounded queues, so neither a slow peer nor a slow job can
//! keep the loop from handling EOF, shutdown or lock. KDF work will run on
//! worker threads and report back here.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::frame::{Frame, KIND_JSON};
use fc_protocol::message::{self, CallerKind, Context, Message, MessageError};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use crate::exit::Exit;
use crate::transport::{self, Credits, Link, Pending};
use crate::vault::{FileSnapshot, Finished, NodeRecovery, Out, Vault};
use crate::worker::Worker;
use crate::{gate, hardening, log, naming, testhooks, testmethods};

/// How long the writer may take to flush on exit.
const EXIT_DRAIN: Duration = Duration::from_secs(2);
/// How long exiting waits for a vault job past its commit point to finish
/// and reply. A commit is a rename or unlink plus a directory flush; main's
/// hang watchdog and reconciliation cover anything slower.
const COMMIT_DRAIN: Duration = Duration::from_secs(5);

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
}

/// The methods this build implements, in `core.hello`'s capabilities. Only
/// these names and the test methods' are ever logged; anything else is
/// logged as `<unknown>`.
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
];

/// The transport features in `core.hello`'s capabilities, after the
/// methods: `fragments`, fragmented responses with bulk credit (design
/// 0005, Frames). The core always offers them; it sends them only to a main
/// whose hello offered `frames: ["fragment"]`.
const FEATURES: &[&str] = &["fragments"];

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
    // The core's requests to main still waiting for their answers.
    let pending = Arc::new(Pending::default());
    let writer = match transport::spawn_writer(events_tx.clone(), Arc::clone(&link)) {
        Ok(writer) => writer,
        Err(_) => return Exit::Internal,
    };
    let Ok(worker) = Worker::spawn(events_tx.clone()) else {
        return Exit::Internal;
    };
    // Naming runs on its own thread and writes its own frames (design 0004,
    // Admission: vault control traffic never waits on naming work).
    let Ok(naming) = naming::spawn(
        writer.queue.clone(),
        events_tx.clone(),
        Arc::clone(&pending),
    ) else {
        return Exit::Internal;
    };
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
        out: writer.queue,
        allowance: transport::Allowance::new(transport::MAX_QUEUED_REPLIES, usize::MAX),
        link: Arc::clone(&link),
        credit: None,
        hello_done: false,
        last_request_id: 0,
        vault: Vault::new(
            gate.identity_dir.clone(),
            fc_vault::state::DEFAULT_AUTO_LOCK_MS,
        ),
        worker,
        naming,
        test,
    };
    let hello_deadline = options.started + options.hello_timeout;
    let exit = loop {
        if !core.hello_done && Instant::now() >= hello_deadline {
            log::error("no core.hello within the deadline", serde_json::json!({}));
            break Exit::Protocol;
        }
        let timeout = if core.hello_done {
            core.vault
                .next_wakeup()
                .map_or(Duration::from_secs(3600), |at| {
                    at.saturating_duration_since(Instant::now())
                })
        } else {
            hello_deadline.saturating_duration_since(Instant::now())
        };
        let received = events.recv_timeout(timeout);
        // Whatever arrived, first apply what is due (auto-lock, deadlines):
        // a busy queue must not postpone either.
        if core.hello_done {
            let outs = core.vault.tick();
            if let Flow::Exit(exit) = core.dispatch(outs) {
                break exit;
            }
        }
        match received {
            Ok(Event::Frame(frame, credit)) => {
                // A message forwarded to the naming thread takes the credit
                // along; otherwise it goes once the frame is handled.
                core.credit = Some(credit);
                let flow = core.handle_frame(&frame);
                drop(frame);
                core.credit = None;
                if let Flow::Exit(exit) = flow {
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
                let flow = core.handle_fragmented(id, &payload);
                drop(payload);
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
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break Exit::Ok,
        }
    };
    // Naming starts no more I/O, whatever ended the loop.
    core.naming.close();
    // Wipe the vault and revoke pre-commit work. Work past its commit point
    // finishes and replies before exit (bounded). Then let the writer flush
    // what's queued, but never wait on a peer that stopped reading: exiting
    // releases the gate.
    let outs = core.vault.shutdown();
    let _ = core.dispatch(outs);
    let until = Instant::now() + COMMIT_DRAIN;
    while core.vault.committing() {
        let Some(left) = until.checked_duration_since(Instant::now()) else {
            log::error(
                "a committed vault job did not finish before exit",
                serde_json::json!({}),
            );
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
    out: mpsc::Sender<transport::Out>,
    /// The loop's own share of the writer: 0001's reserved capacity, which
    /// naming traffic can't take.
    allowance: Arc<transport::Allowance>,
    /// Bulk credit: main's hello says whether it takes fragments.
    link: Arc<Link>,
    /// The credit of the frame being handled.
    credit: Option<transport::Credit>,
    hello_done: bool,
    last_request_id: u64,
    vault: Vault,
    worker: Worker,
    naming: naming::Handle,
    /// The `test.*` methods' thread, when the test hooks enable it.
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

/// A method name that is safe to log: known names only.
fn loggable(method: &str) -> &'static str {
    CAPABILITIES
        .iter()
        .chain(testmethods::METHODS)
        .copied()
        .find(|m| *m == method)
        .unwrap_or("<unknown>")
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

impl Core {
    fn handle_frame(&mut self, frame: &Frame) -> Flow {
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
            // A cancel names a vault request or a naming one; each side
            // ignores IDs it doesn't hold.
            Message::Cancel { id } => {
                if !self
                    .naming
                    .send(naming::In::Cancel { id }, self.credit.take())
                {
                    return Flow::Exit(Exit::Internal);
                }
                let outs = self.vault.cancel(id);
                self.dispatch(outs)
            }
            Message::Response { id, outcome } => self.response(id, outcome),
            Message::Event { .. } => {
                log::warn("ignoring an event from main", serde_json::json!({}));
                Flow::Continue
            }
        }
    }

    /// A fragmented response, reassembled: it must be the response its begin
    /// named.
    fn handle_fragmented(&mut self, id: u64, payload: &[u8]) -> Flow {
        let category = match Message::decode(payload) {
            Ok(Message::Response {
                id: answered,
                outcome,
            }) if answered == id && self.hello_done => return self.response(id, outcome),
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

    /// Main's response to one of the core's requests. Only the naming
    /// thread sends requests (`shell.*`): it checks that a response answers
    /// one of them.
    fn response(&mut self, id: u64, outcome: Result<&RawValue, ErrorBody>) -> Flow {
        let outcome = match outcome {
            Ok(result) => match RawValue::from_string(result.get().to_owned()) {
                Ok(result) => Ok(result),
                Err(_) => return Flow::Exit(Exit::Internal),
            },
            Err(error) => Err(error),
        };
        if self
            .naming
            .send(naming::In::Response { id, outcome }, self.credit.take())
        {
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
        if context.caller == CallerKind::Page {
            return self.error(
                id,
                ErrorBody::new(ErrorCode::Forbidden, "not callable from web content"),
            );
        }
        let flow = match method {
            "core.hello" => self.hello(id, params),
            "core.shutdown" => {
                // No naming request goes after the acknowledgement.
                self.naming.close();
                match self.result(id, &serde_json::json!({})) {
                    Flow::Continue => Flow::Exit(Exit::Ok),
                    exit => exit,
                }
            }
            method if Vault::handles(method) => {
                let outs = self.vault.request(id, method, params, context.caller);
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
        self.result(
            id,
            &HelloResult {
                protocol: fc_protocol::PROTOCOL_VERSION,
                core_version: env!("CARGO_PKG_VERSION"),
                capabilities: CAPABILITIES.iter().chain(FEATURES).copied().collect(),
                node_recovery: &self.node_recovery,
            },
        )
    }

    /// Sends the vault's payloads and submits its jobs.
    fn dispatch(&self, outs: Vec<Out>) -> Flow {
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

    fn result<R: Serialize>(&self, id: u64, result: &R) -> Flow {
        let mut payload = Zeroizing::new(Vec::with_capacity(256));
        match message::write_result(&mut *payload, id, result) {
            Ok(()) => self.send(&payload),
            Err(_) => Flow::Exit(Exit::Internal),
        }
    }

    fn error(&self, id: u64, error: ErrorBody) -> Flow {
        let mut payload = Zeroizing::new(Vec::with_capacity(256));
        match message::write_error(&mut *payload, id, &error) {
            Ok(()) => self.send(&payload),
            Err(_) => Flow::Exit(Exit::Internal),
        }
    }

    /// Queues a reply: one frame, as every vault reply fits one. A full
    /// allowance means main stopped reading stdout: exit rather than buffer
    /// without limit.
    fn send(&self, payload: &[u8]) -> Flow {
        let Some(frame) = transport::frame(payload) else {
            return Flow::Exit(Exit::Internal);
        };
        let Some(hold) = self.allowance.take(frame.len()) else {
            log::error("main is not reading replies", serde_json::json!({}));
            return Flow::Exit(Exit::Protocol);
        };
        match self.out.send(transport::Out::Frame { frame, hold }) {
            Ok(()) => Flow::Continue,
            Err(_) => Flow::Exit(Exit::Protocol),
        }
    }
}
