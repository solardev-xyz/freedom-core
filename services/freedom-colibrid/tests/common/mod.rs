//! A scripted main for `freedom-colibrid`: the binary spawned on pipes,
//! frames decoded on a reader thread, and main's frames written by hand
//! (0001's framing: a 4-byte big-endian length that counts the kind byte,
//! the kind, the payload).

#![allow(dead_code)]
// Test support: a failed setup or a broken frame ends the test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fc_protocol::frame::{KIND_ABORT, KIND_DATA, KIND_END, KIND_JSON, KIND_STREAM_CREDIT};
use fc_protocol::stream::{StreamFrame, WINDOW};
use serde_json::{Value, json};

pub const BIN: &str = env!("CARGO_BIN_EXE_freedom-colibrid");

/// The largest data frame main sends.
const DATA_FRAME: usize = 64 << 10;

/// A frame from the service.
#[derive(Debug)]
pub enum Frame {
    /// A JSON message, parsed and as written.
    Json(Value, String),
    Data {
        id: u64,
        len: usize,
    },
    End {
        id: u64,
    },
    Abort {
        id: u64,
    },
    Credit {
        id: u64,
        bytes: u32,
    },
}

/// One body main is sending, held to the service's credit.
struct Outgoing {
    id: u64,
    bytes: Vec<u8>,
    sent: usize,
    credit: usize,
    /// Send this many bytes in all, then end (a body shorter or longer
    /// than its head).
    send: usize,
}

pub struct Colibrid {
    child: Child,
    stdin: Option<ChildStdin>,
    frames: Receiver<Frame>,
    stderr: Arc<Mutex<String>>,
    next_id: u64,
    outgoing: Vec<Outgoing>,
}

/// Temporary directories, removed when dropped.
pub struct Dirs {
    pub root: PathBuf,
}

impl Dirs {
    pub fn new(name: &str) -> Dirs {
        let root = std::env::temp_dir().join(format!(
            "colibrid-test-{}-{name}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("data")).unwrap();
        std::fs::create_dir_all(root.join("lock")).unwrap();
        Dirs { root }
    }

    pub fn data(&self) -> PathBuf {
        self.root.join("data")
    }

    pub fn lock(&self) -> PathBuf {
        self.root.join("lock")
    }
}

impl Drop for Dirs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Colibrid {
    /// `serve` for `chain`, persistent on `dirs` or private without.
    pub fn serve(chain: u64, dirs: Option<&Dirs>) -> Colibrid {
        Colibrid::serve_with(chain, dirs, &[])
    }

    /// [`Colibrid::serve`] with test hooks set in its environment.
    pub fn serve_with(chain: u64, dirs: Option<&Dirs>, env: &[(&str, &str)]) -> Colibrid {
        let mut command = Command::new(BIN);
        command.args(["serve", "--chain", &chain.to_string()]);
        command.envs(env.iter().copied());
        if let Some(dirs) = dirs {
            command.arg("--data-dir").arg(dirs.data());
            command.arg("--lock-dir").arg(dirs.lock());
        }
        Colibrid::spawn(command)
    }

    /// The one-shot checkpoint process for `chain`.
    pub fn checkpoint(chain: u64) -> Colibrid {
        let mut command = Command::new(BIN);
        command.args(["checkpoint", "--chain", &chain.to_string()]);
        Colibrid::spawn(command)
    }

    pub fn spawn(mut command: Command) -> Colibrid {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr_pipe = child.stderr.take().unwrap();
        let (tx, frames) = mpsc::channel();
        std::thread::spawn(move || {
            let mut header = [0u8; 4];
            while stdout.read_exact(&mut header).is_ok() {
                let len = u32::from_be_bytes(header) as usize;
                let mut frame = vec![0u8; len];
                if stdout.read_exact(&mut frame).is_err() || frame.is_empty() {
                    break;
                }
                let (kind, payload) = (frame[0], &frame[1..]);
                let decoded = if kind == KIND_JSON {
                    Frame::Json(
                        serde_json::from_slice(payload).unwrap(),
                        String::from_utf8(payload.to_vec()).unwrap(),
                    )
                } else {
                    match StreamFrame::decode(kind, payload).unwrap() {
                        StreamFrame::Data { id, bytes } => Frame::Data {
                            id,
                            len: bytes.len(),
                        },
                        StreamFrame::End { id } => Frame::End { id },
                        StreamFrame::Abort { id, .. } => Frame::Abort { id },
                        StreamFrame::Credit { id, bytes } => Frame::Credit { id, bytes },
                    }
                };
                if tx.send(decoded).is_err() {
                    break;
                }
            }
        });
        let stderr = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&stderr);
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr_pipe.read_to_string(&mut text);
            sink.lock().unwrap().push_str(&text);
        });
        let stdin = child.stdin.take();
        Colibrid {
            child,
            stdin,
            frames,
            stderr,
            next_id: 1,
            outgoing: Vec::new(),
        }
    }

    pub fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    fn write_frame(&mut self, kind: u8, payload: &[u8]) {
        let mut out = Vec::with_capacity(payload.len() + 5);
        out.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
        out.push(kind);
        out.extend_from_slice(payload);
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = stdin.write_all(&out);
            let _ = stdin.flush();
        }
    }

    pub fn send(&mut self, value: &Value) {
        self.write_frame(KIND_JSON, value.to_string().as_bytes());
    }

    /// Sends request `method` and returns its id.
    pub fn request(&mut self, method: &str, params: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "type": "request", "id": id, "method": method, "params": params }));
        id
    }

    pub fn cancel(&mut self, id: u64) {
        self.send(&json!({ "type": "cancel", "id": id }));
    }

    pub fn respond(&mut self, id: u64, result: Value) {
        self.send(&json!({ "type": "response", "id": id, "result": result }));
    }

    pub fn respond_error(&mut self, id: u64, code: &str, message: &str) {
        self.send(
            &json!({ "type": "response", "id": id, "error": { "code": code, "message": message } }),
        );
    }

    /// Answers fetch `id` with `body` from node `node`: the head, then the
    /// body as the service's credit allows ([`Colibrid::pump`]). `send`
    /// bytes in all (a body that breaks its head when it differs).
    pub fn answer_body(&mut self, id: u64, node: u16, body: Vec<u8>, send: usize) {
        self.respond(
            id,
            json!({ "node": node, "bytes": body.len(), "body": true }),
        );
        let mut bytes = body;
        bytes.resize(send.max(bytes.len()), 0x5a);
        self.outgoing.push(Outgoing {
            id,
            bytes,
            sent: 0,
            credit: WINDOW,
            send,
        });
        self.pump();
    }

    /// Sends what the credit allows of the bodies in flight, and ends each
    /// once it is all sent.
    pub fn pump(&mut self) {
        let mut frames: Vec<(u8, Vec<u8>)> = Vec::new();
        self.outgoing.retain_mut(|out| {
            while out.sent < out.send && out.credit > 0 {
                let len = (out.send - out.sent).min(out.credit).min(DATA_FRAME);
                let mut payload = Vec::new();
                StreamFrame::Data {
                    id: out.id,
                    bytes: &out.bytes[out.sent..out.sent + len],
                }
                .encode(&mut payload)
                .unwrap();
                frames.push((KIND_DATA, payload));
                out.sent += len;
                out.credit -= len;
            }
            if out.sent >= out.send {
                let mut payload = Vec::new();
                StreamFrame::End { id: out.id }
                    .encode(&mut payload)
                    .unwrap();
                frames.push((KIND_END, payload));
                false
            } else {
                true
            }
        });
        for (_, encoded) in frames {
            // `encode` wrote the whole frame, header included.
            if let Some(stdin) = self.stdin.as_mut() {
                let _ = stdin.write_all(&encoded);
                let _ = stdin.flush();
            }
        }
    }

    /// The next frame, within `wait`. Credit for a body in flight is
    /// applied and the body pumped before the frame is returned.
    pub fn recv(&mut self, wait: Duration) -> Option<Frame> {
        match self.frames.recv_timeout(wait) {
            Ok(frame) => {
                if let Frame::Credit { id, bytes } = frame {
                    for out in &mut self.outgoing {
                        if out.id == id {
                            out.credit += bytes as usize;
                        }
                    }
                    self.pump();
                }
                Some(frame)
            }
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => None,
        }
    }

    /// The handshake.
    pub fn hello(&mut self) -> Value {
        let id = self.request(
            "colibri.hello",
            json!({ "protocol": 1, "shell_version": "test", "frames": ["stream"] }),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Some(Frame::Json(message, _)) = self.recv(Duration::from_secs(30))
                && message["type"] == "response"
                && message["id"] == id
            {
                return message["result"].clone();
            }
        }
        panic!("no hello reply; stderr: {}", self.stderr());
    }

    /// `colibri.shutdown` (no reply), then the exit code.
    pub fn shutdown(&mut self) -> Option<i32> {
        self.request("colibri.shutdown", json!({}));
        self.exit_code(Duration::from_secs(20))
    }

    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// The exit code, within `wait`; `None` if the process is still
    /// running, or died of a signal.
    pub fn exit_code(&mut self, wait: Duration) -> Option<i32> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code();
            }
            if Instant::now() >= deadline {
                return None;
            }
            // Keep reading, so the service's writer never stalls.
            let _ = self.recv(Duration::from_millis(20));
        }
    }

    /// Whether the process has ended, by exit or signal.
    pub fn exited(&mut self) -> bool {
        self.child.try_wait().unwrap().is_some()
    }
}

impl Drop for Colibrid {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The repository's root.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Whether `KIND_ABORT` and `KIND_STREAM_CREDIT` are the kinds the decoder
/// maps (a compile-time use, so a renamed constant fails here).
pub const _KINDS: [u8; 2] = [KIND_ABORT, KIND_STREAM_CREDIT];
