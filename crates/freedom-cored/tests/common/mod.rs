//! Shared test harness: the real binary over its pipes, with timeouts on
//! every read and a kill-and-reap guard.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

pub const BIN: &str = env!("CARGO_BIN_EXE_freedom-cored");
/// A hang guard, never a timing assertion: no test waits on it to prove
/// silence, and a test whose timing matters asserts it itself (as
/// `auto_lock_fires` does). A generous guard only slows a failing test.
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// stdout, read on a thread: either frames (serve) or lines (hold-lock,
/// recover).
pub enum Output {
    /// A whole message (kind 0x01).
    Frame(Value),
    /// The parts of a fragmented response and bulk credit (design 0005,
    /// Frames).
    Wire(Wire),
    Line(String),
    /// The reader stopped on a frame it couldn't parse.
    Malformed(String),
}

/// One frame as main reads it.
#[derive(Clone, PartialEq)]
pub enum Wire {
    /// A whole message.
    Message(Value),
    /// `0x12`: a fragmented response begins.
    Begin { id: u64, bytes: usize },
    /// `0x10`.
    Fragment(Vec<u8>),
    /// `0x11`.
    Last(Vec<u8>),
    /// `0x13`: the core returned main's bulk credit.
    Credit,
}

/// Fragments show their size only: a megabyte doesn't belong in a panic.
impl std::fmt::Debug for Wire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Wire::Message(value) => write!(f, "Message({value})"),
            Wire::Begin { id, bytes } => write!(f, "Begin {{ id: {id}, bytes: {bytes} }}"),
            Wire::Fragment(bytes) => write!(f, "Fragment({} bytes)", bytes.len()),
            Wire::Last(bytes) => write!(f, "Last({} bytes)", bytes.len()),
            Wire::Credit => f.write_str("Credit"),
        }
    }
}

pub const KIND_FRAGMENT: u8 = 0x10;
pub const KIND_LAST: u8 = 0x11;
pub const KIND_BEGIN: u8 = 0x12;
pub const KIND_CREDIT: u8 = 0x13;

pub struct Core {
    pub child: Child,
    stdin: Option<ChildStdin>,
    output: Receiver<Output>,
    stderr: Option<std::thread::JoinHandle<String>>,
    /// Events seen while waiting for responses.
    pub events: Vec<Value>,
    /// While set, stdout isn't read: the pipe fills, as when main stalls.
    paused: Arc<(Mutex<bool>, Condvar)>,
    /// Set: pause right after the next begin frame.
    pause_on_begin: Arc<AtomicBool>,
}

impl Drop for Core {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn spawn(command: &str, data: &Path, locks: &Path, extra: &[&str]) -> Core {
    spawn_env(command, data, locks, extra, &[])
}

pub fn spawn_env(
    command: &str,
    data: &Path,
    locks: &Path,
    extra: &[&str],
    env: &[(&str, &str)],
) -> Core {
    let mut child = Command::new(BIN)
        .envs(env.iter().copied())
        .arg(command)
        .arg("--data-dir")
        .arg(data)
        .arg("--lock-dir")
        .arg(locks)
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let (tx, output) = mpsc::channel();
    let lines = command != "serve";
    let paused = Arc::new((Mutex::new(false), Condvar::new()));
    let gate = Arc::clone(&paused);
    let pause_on_begin = Arc::new(AtomicBool::new(false));
    let on_begin = Arc::clone(&pause_on_begin);
    std::thread::spawn(move || {
        if lines {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if tx.send(Output::Line(line)).is_err() {
                    return;
                }
            }
            return;
        }
        loop {
            {
                let (lock, resumed) = &*gate;
                let mut paused = lock.lock().unwrap();
                while *paused {
                    paused = resumed.wait(paused).unwrap();
                }
            }
            let mut header = [0u8; 5];
            if stdout.read_exact(&mut header).is_err() {
                return;
            }
            let Some(len) = (u32::from_be_bytes([header[0], header[1], header[2], header[3]])
                as usize)
                .checked_sub(1)
            else {
                let _ = tx.send(Output::Malformed(format!("frame header {header:?}")));
                return;
            };
            let mut payload = vec![0u8; len];
            if stdout.read_exact(&mut payload).is_err() {
                return;
            }
            let output = match header[4] {
                1 => match serde_json::from_slice(&payload) {
                    Ok(value) => Output::Frame(value),
                    Err(err) => {
                        Output::Malformed(format!("{err}: {}", String::from_utf8_lossy(&payload)))
                    }
                },
                KIND_BEGIN => match serde_json::from_slice::<Value>(&payload) {
                    Ok(begin) if begin["id"].is_u64() && begin["bytes"].is_u64() => {
                        Output::Wire(Wire::Begin {
                            id: begin["id"].as_u64().unwrap(),
                            bytes: begin["bytes"].as_u64().unwrap() as usize,
                        })
                    }
                    _ => Output::Malformed(format!("begin {}", String::from_utf8_lossy(&payload))),
                },
                KIND_FRAGMENT => Output::Wire(Wire::Fragment(payload)),
                KIND_LAST => Output::Wire(Wire::Last(payload)),
                KIND_CREDIT if payload.is_empty() => Output::Wire(Wire::Credit),
                kind => Output::Malformed(format!("frame kind {kind:#04x}")),
            };
            // Paused before the test sees the begin, so a resume that
            // follows it can't come first.
            if matches!(output, Output::Wire(Wire::Begin { .. }))
                && on_begin.swap(false, Ordering::SeqCst)
            {
                *gate.0.lock().unwrap() = true;
            }
            if tx.send(output).is_err() {
                return;
            }
        }
    });
    let stderr = std::thread::spawn(move || {
        let mut all = String::new();
        let _ = stderr.read_to_string(&mut all);
        all
    });
    Core {
        child,
        stdin,
        output,
        stderr: Some(stderr),
        events: Vec::new(),
        paused,
        pause_on_begin,
    }
}

pub fn frame(message: &Value) -> Vec<u8> {
    let payload = serde_json::to_vec(message).unwrap();
    let mut frame = u32::try_from(payload.len() + 1)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    frame.push(1);
    frame.extend_from_slice(&payload);
    frame
}

/// A frame of any kind.
pub fn raw_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = u32::try_from(payload.len() + 1)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    frame.push(kind);
    frame.extend_from_slice(payload);
    frame
}

/// A fragmented response: its begin, then `pieces` fragments of about equal
/// size, the last of kind 0x11.
pub fn fragmented(message: &Value, pieces: usize) -> Vec<Vec<u8>> {
    let payload = serde_json::to_vec(message).unwrap();
    let id = message["id"].as_u64().unwrap();
    let begin = json!({ "id": id, "bytes": payload.len() }).to_string();
    let mut frames = vec![raw_frame(KIND_BEGIN, begin.as_bytes())];
    let size = payload.len().div_ceil(pieces);
    let chunks: Vec<&[u8]> = payload.chunks(size).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let kind = if i + 1 == chunks.len() {
            KIND_LAST
        } else {
            KIND_FRAGMENT
        };
        frames.push(raw_frame(kind, chunk));
    }
    frames
}

pub fn request(id: u64, method: &str, params: Value) -> Value {
    json!({ "type": "request", "id": id, "method": method, "params": params, "context": { "caller": "chrome" } })
}

/// A request from main itself (caller `shell`), e.g. compat.*.
pub fn shell_request(id: u64, method: &str, params: Value) -> Value {
    json!({ "type": "request", "id": id, "method": method, "params": params, "context": { "caller": "shell" } })
}

impl Core {
    /// Stops reading stdout after the frame being read, until
    /// [`Core::resume_reading`].
    pub fn pause_reading(&self) {
        *self.paused.0.lock().unwrap() = true;
    }

    pub fn resume_reading(&self) {
        *self.paused.0.lock().unwrap() = false;
        self.paused.1.notify_all();
    }

    /// Resumes reading stdout after `delay`, from a thread: the test can
    /// meanwhile block writing a burst the core takes in only as main reads.
    pub fn resume_reading_after(&self, delay: Duration) -> std::thread::JoinHandle<()> {
        let paused = Arc::clone(&self.paused);
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            *paused.0.lock().unwrap() = false;
            paused.1.notify_all();
        })
    }

    /// Writes `bytes` to stdin from a thread: for a burst the core may never
    /// take in whole. The thread ends once the write is done or fails (the
    /// core exited), and hands stdin back still open, so EOF comes only
    /// when the test drops it.
    pub fn send_in_background(&mut self, bytes: Vec<u8>) -> std::thread::JoinHandle<ChildStdin> {
        let mut stdin = self.stdin.take().unwrap();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
            stdin
        })
    }

    /// Writes `frames` to stdin from a thread, one at a time, counting them
    /// as they go in ([`Feed`]).
    pub fn feed(&mut self, frames: Vec<Vec<u8>>) -> Feed {
        let mut stdin = self.stdin.take().unwrap();
        let written = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&written);
        let thread = std::thread::spawn(move || {
            for frame in frames {
                if stdin.write_all(&frame).is_err() {
                    break;
                }
                count.fetch_add(1, Ordering::SeqCst);
            }
            stdin
        });
        Feed { thread, written }
    }

    /// Takes stdin back from a feed once it has written everything.
    pub fn fed(&mut self, feed: Feed) {
        self.stdin = Some(feed.thread.join().unwrap());
    }

    /// The core's resident memory now (`VmRSS`) and at its peak (`VmHWM`),
    /// in KiB.
    #[cfg(target_os = "linux")]
    pub fn memory_kib(&self) -> (u64, u64) {
        let status = std::fs::read_to_string(format!("/proc/{}/status", self.child.id())).unwrap();
        let field = |name: &str| -> u64 {
            let line = status.lines().find(|l| l.starts_with(name)).unwrap();
            line[name.len()..]
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .unwrap()
        };
        (field("VmRSS:"), field("VmHWM:"))
    }

    /// Stops reading stdout right after the next begin frame, until
    /// [`Core::resume_reading`]: the core then stalls in that response.
    pub fn pause_after_begin(&self) {
        self.pause_on_begin.store(true, Ordering::SeqCst);
    }

    /// Returns the core's bulk credit (`0x13`).
    pub fn send_credit(&mut self) {
        self.send_raw(&raw_frame(KIND_CREDIT, b""));
    }

    /// The next frame, whatever its kind.
    pub fn recv_wire(&mut self) -> Wire {
        match self.output.recv_timeout(READ_TIMEOUT) {
            Ok(Output::Frame(value)) => Wire::Message(value),
            Ok(Output::Wire(wire)) => wire,
            Ok(Output::Line(line)) => panic!("expected a frame, got line {line:?}"),
            Ok(Output::Malformed(what)) => panic!("malformed frame: {what}"),
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("no frame within {READ_TIMEOUT:?}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => self.closed("a frame"),
        }
    }

    /// The next frame, if one comes within `within`.
    pub fn recv_wire_within(&mut self, within: Duration) -> Option<Wire> {
        match self.output.recv_timeout(within) {
            Ok(Output::Frame(value)) => Some(Wire::Message(value)),
            Ok(Output::Wire(wire)) => Some(wire),
            Ok(Output::Line(line)) => panic!("expected a frame, got line {line:?}"),
            Ok(Output::Malformed(what)) => panic!("malformed frame: {what}"),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => self.closed("a frame"),
        }
    }

    pub fn send(&mut self, message: &Value) {
        self.send_raw(&frame(message));
    }

    pub fn send_raw(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(bytes).unwrap();
        stdin.flush().unwrap();
    }

    pub fn recv(&mut self) -> Value {
        match self.output.recv_timeout(READ_TIMEOUT) {
            Ok(Output::Frame(value)) => value,
            Ok(Output::Wire(wire)) => panic!("expected a whole message, got {wire:?}"),
            Ok(Output::Line(line)) => panic!("expected a frame, got line {line:?}"),
            Ok(Output::Malformed(what)) => panic!("malformed frame: {what}"),
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("no reply within {READ_TIMEOUT:?}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => self.closed("a reply"),
        }
    }

    /// stdout ended while a test waited on it: say how the core ended, which
    /// a timeout would hide.
    fn closed(&mut self, waiting_for: &str) -> ! {
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => break None,
            }
        };
        let stderr = match (status, self.stderr.take()) {
            (Some(_), Some(handle)) => handle.join().unwrap_or_default(),
            _ => String::from("(core still running: stderr not collected)"),
        };
        panic!(
            "stdout closed while waiting for {waiting_for}; core status {status:?}; stderr:\n{stderr}"
        )
    }

    /// Every whole message left, until the core closes stdout; a bulk
    /// credit returned meanwhile is passed over.
    pub fn rest(&mut self) -> Vec<Value> {
        let mut frames = Vec::new();
        loop {
            match self.output.recv_timeout(READ_TIMEOUT) {
                Ok(Output::Frame(value)) => frames.push(value),
                Ok(Output::Wire(Wire::Credit)) => {}
                Ok(Output::Wire(wire)) => panic!("expected a whole message, got {wire:?}"),
                Ok(Output::Line(line)) => panic!("expected a frame, got line {line:?}"),
                Ok(Output::Malformed(what)) => panic!("malformed frame: {what}"),
                Err(mpsc::RecvTimeoutError::Disconnected) => return frames,
                Err(mpsc::RecvTimeoutError::Timeout) => panic!("stdout still open"),
            }
        }
    }

    pub fn line(&mut self) -> String {
        match self.output.recv_timeout(READ_TIMEOUT) {
            Ok(Output::Line(line)) => line,
            Ok(Output::Frame(_) | Output::Wire(_)) => panic!("expected a line"),
            Ok(Output::Malformed(what)) => panic!("malformed frame: {what}"),
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("no line within {READ_TIMEOUT:?}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => self.closed("a line"),
        }
    }

    pub fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(&request(id, method, params));
        self.response(id)
    }

    /// Calls with caller `shell` (main-internal methods such as compat.*).
    pub fn call_shell(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(&shell_request(id, method, params));
        self.response(id)
    }

    /// Reads until the response to `id`, setting events aside.
    pub fn response(&mut self, id: u64) -> Value {
        loop {
            let message = self.recv();
            if message["type"] == "event" {
                self.events.push(message);
                continue;
            }
            assert_eq!(message["type"], "response");
            assert_eq!(message["id"], id);
            return message;
        }
    }

    /// Reads until the response to `id`, setting events aside and skipping
    /// other responses.
    pub fn until_response(&mut self, id: u64) -> Value {
        loop {
            let message = self.recv();
            if message["type"] == "event" {
                self.events.push(message);
            } else if message["id"] == id {
                return message;
            }
        }
    }

    /// The process's user + system CPU time, in clock ticks.
    #[cfg(target_os = "linux")]
    pub fn cpu_ticks(&self) -> u64 {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.child.id())).unwrap();
        // Fields after the command name (which is in parentheses).
        let rest = &stat[stat.rfind(')').unwrap() + 2..];
        let fields: Vec<&str> = rest.split(' ').collect();
        fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
    }

    /// The events set aside so far.
    pub fn events(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.events)
    }

    /// Waits for the next event (already seen ones first).
    pub fn event(&mut self) -> Value {
        if !self.events.is_empty() {
            return self.events.remove(0);
        }
        let message = self.recv();
        assert_eq!(message["type"], "event", "{message}");
        message
    }

    pub fn hello(&mut self) -> Value {
        self.hello_with(900_000)
    }

    /// The handshake, offering fragments (design 0005, Frames).
    pub fn hello_fragments(&mut self) -> Value {
        self.call(
            1,
            "core.hello",
            json!({ "protocol": 1, "shell_version": "test", "auto_lock_ms": 900_000, "frames": ["fragment"] }),
        )
    }

    pub fn hello_with(&mut self, auto_lock_ms: u64) -> Value {
        self.call(
            1,
            "core.hello",
            json!({ "protocol": 1, "shell_version": "test", "auto_lock_ms": auto_lock_ms }),
        )
    }

    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    pub fn exit_code(&mut self, within: Duration) -> i32 {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code().unwrap_or(-1);
            }
            assert!(
                Instant::now() < deadline,
                "core did not exit within {within:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Everything the core wrote to stderr; call after it exited.
    pub fn stderr(&mut self) -> String {
        self.stderr.take().unwrap().join().unwrap()
    }
}

/// Frames going into stdin from a thread ([`Core::feed`]).
pub struct Feed {
    thread: std::thread::JoinHandle<ChildStdin>,
    written: Arc<AtomicUsize>,
}

impl Feed {
    /// Waits until no frame has gone in for `quiet`, and returns how many
    /// did. Frames larger than the pipe go in only as the core reads them,
    /// and it reads only as it handles what it holds: feeding stalls once
    /// the core stops taking frames, not while it is merely slow.
    pub fn wait_stalled(&self, quiet: Duration) -> usize {
        let deadline = Instant::now() + READ_TIMEOUT;
        let mut seen = self.written.load(Ordering::SeqCst);
        let mut since = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(20));
            let written = self.written.load(Ordering::SeqCst);
            assert!(!self.thread.is_finished(), "the core took every frame");
            if written != seen {
                seen = written;
                since = Instant::now();
            } else if since.elapsed() >= quiet {
                return written;
            }
            assert!(Instant::now() < deadline, "the core kept taking frames");
        }
    }
}

/// Requests too large for any pipe: `vault.status` padded to 64 KiB.
pub fn padded(ids: std::ops::Range<u64>) -> Vec<Vec<u8>> {
    let pad = "x".repeat(64 * 1024);
    ids.map(|id| frame(&request(id, "vault.status", json!({ "pad": pad }))))
        .collect()
}

pub fn dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("identity");
    let locks = root.path().join("locks");
    (root, data, locks)
}

/// The answer body naming's `quorum-agree` replay scenario recorded for
/// each JSON-RPC method.
pub fn naming_recorded() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/naming-replay.json"
    ))
    .unwrap();
    let vectors: Value = serde_json::from_str(&text).unwrap();
    let scenario = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "quorum-agree")
        .unwrap();
    let mut answers = BTreeMap::new();
    for exchange in scenario["io"].as_array().unwrap() {
        if let (Some(method), Some(body)) = (
            exchange["method"].as_str(),
            exchange["answer"]["body"].as_str(),
        ) {
            answers
                .entry(method.to_owned())
                .or_insert_with(|| body.to_owned());
        }
    }
    answers
}

/// A naming configuration: four RPC endpoints, a quorum of three.
pub fn naming_snapshot() -> Value {
    json!({
        "reset": "none",
        "rpc": [{ "endpoint": "e1" }, { "endpoint": "e2" }, { "endpoint": "e3" }, { "endpoint": "e4" }],
        "direct": null,
        "prover": null,
        "policy": { "order": ["quorum"], "prefer_verified": false },
        "quorum": { "k": 3, "m": 2, "timeout_ms": 5000, "anchor": "latest", "anchor_ttl_ms": 30000 },
        "myotis_enabled": false,
        "tezos": ["t1", "t2", "t3"],
    })
}
