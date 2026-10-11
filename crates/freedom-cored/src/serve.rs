//! `freedom-cored serve`: the event loop (design 0001, "Process model").
//!
//! One thread owns all state and handles every message in order. Reading
//! stdin, writing stdout and watching the parent happen on their own threads,
//! so a slow job can never delay a lock or shutdown. KDF work will run on
//! worker threads and report back here.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::frame::{Frame, KIND_JSON};
use fc_protocol::message::{self, CallerKind, Context, Message};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::exit::Exit;
use crate::{gate, hardening, log, transport};

/// The vault file inside the identity directory.
pub const VAULT_FILE: &str = "identity-vault.json";

pub struct Options {
    pub data_dir: PathBuf,
    pub lock_dir: PathBuf,
    pub parent_pid: Option<u32>,
    pub hello_timeout: Duration,
}

/// What the loop reacts to.
pub enum Event {
    Frame(Frame),
    Eof { at_boundary: bool },
    ProtocolError(String),
    ParentGone,
}

pub fn run(options: &Options) -> Exit {
    hardening::harden();
    if !hardening::request_parent_death_signal(options.parent_pid) {
        log::error("parent is already gone", serde_json::json!({}));
        return Exit::Ok;
    }
    let _gate = match gate::acquire(&options.data_dir, &options.lock_dir) {
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
    let (frames_tx, frames) = mpsc::channel();
    let (Ok(_reader), Ok(writer)) = (
        transport::spawn_reader(events_tx.clone()),
        transport::spawn_writer(frames),
    ) else {
        return Exit::Internal;
    };
    spawn_parent_watch(options.parent_pid, events_tx);

    let mut core = Core {
        data_dir: options.data_dir.clone(),
        out: frames_tx,
        hello_done: false,
    };
    let hello_deadline = Instant::now() + options.hello_timeout;
    let exit = loop {
        let timeout = if core.hello_done {
            Duration::from_secs(3600)
        } else {
            hello_deadline.saturating_duration_since(Instant::now())
        };
        match events.recv_timeout(timeout) {
            Ok(Event::Frame(frame)) => match core.handle_frame(&frame) {
                Flow::Continue => {}
                Flow::Exit(exit) => break exit,
            },
            Ok(Event::Eof { at_boundary }) => {
                if !at_boundary {
                    log::warn(
                        "stdin closed in the middle of a frame",
                        serde_json::json!({}),
                    );
                }
                break Exit::Ok;
            }
            Ok(Event::ProtocolError(error)) => {
                log::error("protocol error", serde_json::json!({ "error": error }));
                break Exit::Protocol;
            }
            Ok(Event::ParentGone) => {
                log::info("parent exited", serde_json::json!({}));
                break Exit::Ok;
            }
            Err(RecvTimeoutError::Timeout) if !core.hello_done => {
                log::error("no core.hello within the deadline", serde_json::json!({}));
                break Exit::Protocol;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break Exit::Ok,
        }
    };
    // Let the writer flush what's queued (e.g. the shutdown reply).
    drop(core);
    let _ = writer.join();
    exit
}

fn spawn_parent_watch(parent_pid: Option<u32>, events: Sender<Event>) {
    if parent_pid.is_none() {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("parent".into())
        .spawn(move || {
            while hardening::parent_alive(parent_pid) {
                std::thread::sleep(Duration::from_secs(2));
            }
            let _ = events.send(Event::ParentGone);
        });
}

enum Flow {
    Continue,
    Exit(Exit),
}

struct Core {
    data_dir: PathBuf,
    out: Sender<Zeroizing<Vec<u8>>>,
    hello_done: bool,
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

/// The methods this build implements, in `core.hello`'s capabilities.
const CAPABILITIES: &[&str] = &["core.hello", "core.shutdown", "vault.status"];

impl Core {
    fn handle_frame(&mut self, frame: &Frame) -> Flow {
        if frame.kind != KIND_JSON {
            log::error(
                "unexpected frame kind",
                serde_json::json!({ "kind": frame.kind }),
            );
            return Flow::Exit(Exit::Protocol);
        }
        let message = match Message::decode(&frame.payload) {
            Ok(message) => message,
            Err(e) => {
                log::error(
                    "protocol error",
                    serde_json::json!({ "error": e.to_string() }),
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
                        "first message was not core.hello",
                        serde_json::json!({ "method": method }),
                    );
                    return Flow::Exit(Exit::Protocol);
                }
                self.handle_request(id, method, params.map(|p| p.get()), &context)
            }
            // Nothing long-running exists yet, so there is nothing to cancel.
            Message::Cancel { .. } => Flow::Continue,
            // The core sends no requests yet, so any response is unsolicited.
            Message::Response { id, .. } => {
                log::error("unsolicited response", serde_json::json!({ "id": id }));
                Flow::Exit(Exit::Protocol)
            }
            Message::Event { event, .. } => {
                log::warn(
                    "ignoring event from main",
                    serde_json::json!({ "event": event }),
                );
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
            self.error(
                id,
                ErrorBody::new(ErrorCode::Forbidden, "not callable from web content"),
            );
            return Flow::Continue;
        }
        let flow = match method {
            "core.hello" => self.hello(id, params),
            "core.shutdown" => {
                self.result(id, &serde_json::json!({}));
                Flow::Exit(Exit::Ok)
            }
            "vault.status" => {
                let status = vault_status(&self.data_dir);
                match status {
                    Ok(status) => self.result(id, &status),
                    Err(e) => self.error(
                        id,
                        ErrorBody::new(ErrorCode::Storage, "Storage error")
                            .with_data(serde_json::json!({ "kind": e })),
                    ),
                }
                Flow::Continue
            }
            _ => {
                self.error(
                    id,
                    ErrorBody::new(ErrorCode::UnknownMethod, "Unknown method"),
                );
                Flow::Continue
            }
        };
        log::info(
            "request",
            serde_json::json!({ "id": id, "method": method, "ms": started.elapsed().as_millis() as u64 }),
        );
        flow
    }

    fn hello(&mut self, id: u64, params: Option<&str>) -> Flow {
        let params: Option<HelloParams> = params.and_then(|p| serde_json::from_str(p).ok());
        let Some(params) = params else {
            self.error(
                id,
                ErrorBody::new(ErrorCode::InvalidArgument, "Invalid core.hello parameters"),
            );
            return Flow::Exit(Exit::Protocol);
        };
        if params.protocol != fc_protocol::PROTOCOL_VERSION {
            self.error(
                id,
                ErrorBody::new(ErrorCode::ProtocolMismatch, "Protocol mismatch")
                    .with_data(serde_json::json!({ "core": fc_protocol::PROTOCOL_VERSION })),
            );
            return Flow::Exit(Exit::Protocol);
        }
        if self.hello_done {
            self.error(
                id,
                ErrorBody::new(ErrorCode::InvalidArgument, "core.hello was already sent"),
            );
            return Flow::Continue;
        }
        self.hello_done = true;
        self.result(
            id,
            &HelloResult {
                protocol: fc_protocol::PROTOCOL_VERSION,
                core_version: env!("CARGO_PKG_VERSION"),
                capabilities: CAPABILITIES,
            },
        );
        Flow::Continue
    }

    fn result<R: Serialize>(&self, id: u64, result: &R) {
        let mut payload = Zeroizing::new(Vec::with_capacity(256));
        if message::write_result(&mut *payload, id, result).is_ok() {
            self.send(&payload);
        }
    }

    fn error(&self, id: u64, error: ErrorBody) {
        let mut payload = Zeroizing::new(Vec::with_capacity(256));
        if message::write_error(&mut *payload, id, &error).is_ok() {
            self.send(&payload);
        }
    }

    fn send(&self, payload: &[u8]) {
        if let Some(frame) = transport::frame(payload) {
            let _ = self.out.send(frame);
        }
    }
}

/// `vault.status` without the lock state (the skeleton has no vault yet):
/// whether the vault file exists and its SHA-256, which quick unlock binds
/// to. Reading never writes.
fn vault_status(data_dir: &Path) -> Result<StatusResult, &'static str> {
    match std::fs::read(data_dir.join(VAULT_FILE)) {
        Ok(bytes) => {
            let digest = Sha256::digest(&bytes);
            let mut fingerprint = String::with_capacity(64);
            for byte in digest {
                fingerprint.push_str(&format!("{byte:02x}"));
            }
            Ok(StatusResult {
                exists: true,
                unlocked: false,
                epoch: None,
                fingerprint: Some(fingerprint),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StatusResult {
            exists: false,
            unlocked: false,
            epoch: None,
            fingerprint: None,
        }),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err("permission"),
        Err(_) => Err("other"),
    }
}
