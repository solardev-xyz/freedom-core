//! `freedom-cored serve`: the event loop (design 0001, "Process model").
//!
//! One thread owns all state and handles every message in order. Reading
//! stdin, writing stdout, logging and watching the parent happen on their own
//! threads behind bounded queues, so neither a slow peer nor a slow job can
//! keep the loop from handling EOF, shutdown or lock. KDF work will run on
//! worker threads and report back here.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError, Sender, TrySendError};
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::frame::{Frame, KIND_JSON};
use fc_protocol::message::{self, CallerKind, Context, Message, MessageError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::exit::Exit;
use crate::transport::{self, Credits};
use crate::{gate, hardening, log};

/// The vault file inside the identity directory.
pub const VAULT_FILE: &str = "identity-vault.json";
/// The largest vault file `vault.status` reads. Real vaults are about 1 KB.
const MAX_VAULT_BYTES: u64 = 1 << 20;
/// How long the writer may take to flush on exit.
const EXIT_DRAIN: Duration = Duration::from_secs(2);

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
    Frame(Frame),
    Eof {
        at_boundary: bool,
    },
    /// A framing error, as a fixed category (never input text).
    ProtocolError(&'static str),
    WriterFailed,
    ThreadDied(&'static str),
    ParentGone,
}

/// The methods this build implements, in `core.hello`'s capabilities. Only
/// these names are ever logged; anything else is logged as `<unknown>`.
const CAPABILITIES: &[&str] = &["core.hello", "core.shutdown", "vault.status"];

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
    let writer = match transport::spawn_writer(events_tx.clone()) {
        Ok(writer) => writer,
        Err(_) => return Exit::Internal,
    };
    if transport::spawn_reader(events_tx.clone(), Arc::clone(&credits)).is_err()
        || !spawn_parent_watch(options.parent_pid, events_tx)
    {
        log::error("cannot start a thread", serde_json::json!({}));
        return Exit::Internal;
    }

    // The status snapshot is taken here, before serving: the gate makes this
    // process the only writer, so it never needs re-reading on the loop
    // (where slow storage would delay shutdown and EOF).
    let snapshot = vault_status(&gate.identity_dir);
    let mut core = Core {
        snapshot,
        out: writer.queue,
        hello_done: false,
        last_request_id: 0,
    };
    let hello_deadline = options.started + options.hello_timeout;
    let exit = loop {
        if !core.hello_done && Instant::now() >= hello_deadline {
            log::error("no core.hello within the deadline", serde_json::json!({}));
            break Exit::Protocol;
        }
        let timeout = if core.hello_done {
            Duration::from_secs(3600)
        } else {
            hello_deadline.saturating_duration_since(Instant::now())
        };
        match events.recv_timeout(timeout) {
            Ok(Event::Frame(frame)) => {
                let flow = core.handle_frame(&frame);
                drop(frame);
                credits.release();
                if let Flow::Exit(exit) = flow {
                    break exit;
                }
            }
            Ok(Event::Eof { at_boundary }) => {
                if !at_boundary {
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
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break Exit::Ok,
        }
    };
    // Let the writer flush what's queued (e.g. the shutdown reply), but never
    // wait on a peer that stopped reading: exiting releases the gate.
    drop(core);
    let _ = writer.done.recv_timeout(EXIT_DRAIN);
    drop(gate);
    exit
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
    snapshot: Result<StatusResult, &'static str>,
    out: mpsc::SyncSender<Zeroizing<Vec<u8>>>,
    hello_done: bool,
    last_request_id: u64,
}

#[derive(Deserialize)]
struct HelloParams {
    protocol: u32,
    #[allow(dead_code)]
    shell_version: String,
    #[allow(dead_code)]
    auto_lock_ms: u64,
}

#[derive(Serialize)]
struct HelloResult {
    protocol: u32,
    core_version: &'static str,
    capabilities: &'static [&'static str],
}

#[derive(Serialize)]
struct StatusResult {
    exists: bool,
    unlocked: bool,
    epoch: Option<u64>,
    fingerprint: Option<String>,
}

/// A method name that is safe to log: known names only.
fn loggable(method: &str) -> &'static str {
    CAPABILITIES
        .iter()
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
            // Nothing long-running exists yet, so there is nothing to cancel.
            Message::Cancel { .. } => Flow::Continue,
            // The core sends no requests yet, so any response is unsolicited.
            Message::Response { id, .. } => {
                log::error(
                    "protocol error",
                    serde_json::json!({ "category": "unsolicited_response", "id": id }),
                );
                Flow::Exit(Exit::Protocol)
            }
            Message::Event { .. } => {
                log::warn("ignoring an event from main", serde_json::json!({}));
                Flow::Continue
            }
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
            "core.shutdown" => match self.result(id, &serde_json::json!({})) {
                Flow::Continue => Flow::Exit(Exit::Ok),
                exit => exit,
            },
            "vault.status" => match &self.snapshot {
                Ok(status) => self.result(id, status),
                Err(kind) => self.error(
                    id,
                    ErrorBody::new(ErrorCode::Storage, "Storage error")
                        .with_data(serde_json::json!({ "kind": kind })),
                ),
            },
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
        if self.hello_done {
            return self.error(
                id,
                ErrorBody::new(ErrorCode::InvalidArgument, "core.hello was already sent"),
            );
        }
        self.hello_done = true;
        self.result(
            id,
            &HelloResult {
                protocol: fc_protocol::PROTOCOL_VERSION,
                core_version: env!("CARGO_PKG_VERSION"),
                capabilities: CAPABILITIES,
            },
        )
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

    /// Queues a reply. A full queue means main stopped reading stdout: exit
    /// rather than buffer without limit.
    fn send(&self, payload: &[u8]) -> Flow {
        let Some(frame) = transport::frame(payload) else {
            return Flow::Exit(Exit::Internal);
        };
        match self.out.try_send(frame) {
            Ok(()) => Flow::Continue,
            Err(TrySendError::Full(_)) => {
                log::error("main is not reading replies", serde_json::json!({}));
                Flow::Exit(Exit::Protocol)
            }
            Err(TrySendError::Disconnected(_)) => Flow::Exit(Exit::Protocol),
        }
    }
}

/// The `vault.status` snapshot, read once at startup (the skeleton has no
/// vault writes yet): whether the vault file exists and its SHA-256, which
/// quick unlock binds to. Only a regular file of bounded size is read, so a
/// FIFO or a huge file is refused. Reading never writes.
fn vault_status(data_dir: &Path) -> Result<StatusResult, &'static str> {
    let path = data_dir.join(VAULT_FILE);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(StatusResult {
                exists: false,
                unlocked: false,
                epoch: None,
                fingerprint: None,
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Err("permission"),
        Err(_) => return Err("other"),
    };
    if !metadata.is_file() {
        return Err("not_regular");
    }
    if metadata.len() > MAX_VAULT_BYTES {
        return Err("too_large");
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Err("permission"),
        Err(_) => return Err("other"),
    };
    let mut fingerprint = String::with_capacity(64);
    for byte in Sha256::digest(&bytes) {
        fingerprint.push_str(&format!("{byte:02x}"));
    }
    Ok(StatusResult {
        exists: true,
        unlocked: false,
        epoch: None,
        fingerprint: Some(fingerprint),
    })
}
