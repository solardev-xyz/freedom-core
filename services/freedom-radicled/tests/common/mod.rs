//! The real binary over its pipes, as main speaks to it, after
//! freedom-ipfsd's harness. Every read has a timeout and every child is
//! killed and reaped on drop, so a regression fails a test instead of
//! hanging the suite.
//!
//! Each process gets the environment main gives it (0008, "Spawn and
//! lock"): cleared, with `HOME` at a directory of its own (and, on Windows,
//! `SystemRoot`, which the OS's own libraries need).
//!
//! **One spawn at a time** ([`spawning`]): on macOS std makes a child's
//! pipes with `pipe()` and only then marks them close-on-exec, so a child
//! spawned from another test's thread in between inherits them, and holding
//! the write end of another child's stdin keeps that child from seeing EOF
//! (issue #171; freedom-ipfsd's harness has the details).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{Value, json};

pub mod fixture;
pub mod hermetic;
pub mod js;

pub const BIN: &str = env!("CARGO_BIN_EXE_freedom-radicled");
/// A hang guard, never a timing assertion.
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a process gets to exit when it should.
pub const EXIT_TIMEOUT: Duration = Duration::from_secs(15);

/// Held across every spawn of this test process (see the module's doc).
static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The spawn lock: hold it across `Command::spawn` (never across a wait).
pub fn spawning() -> std::sync::MutexGuard<'static, ()> {
    SPAWN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A Radicle home, a lock directory and the service's own `HOME`, removed
/// on drop.
pub struct Dirs {
    _root: tempfile::TempDir,
    pub home: PathBuf,
    pub locks: PathBuf,
    pub own_home: PathBuf,
}

impl Dirs {
    pub fn new() -> Dirs {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("R").join("1");
        let locks = root.path().join("locks");
        let own_home = root.path().join("radicled-home");
        std::fs::create_dir_all(&own_home).unwrap();
        Dirs {
            _root: root,
            home,
            locks,
            own_home,
        }
    }

    /// A test hook's value, `<mode>:<path>`, that holds work until the
    /// test releases it (src/testhooks.rs), and the file that does: `name`,
    /// in the service's own `HOME`, which its confinement grants.
    pub fn held(&self, mode: &str, name: &str) -> (String, PathBuf) {
        let release = self.own_home.join(name);
        (format!("{mode}:{}", release.display()), release)
    }
}

/// The environment main gives the service, plus `extra`.
pub fn environment(command: &mut Command, dirs: &Dirs, extra: &[(&str, &str)]) {
    command.env_clear().env("HOME", &dirs.own_home);
    if cfg!(windows) {
        for name in ["SystemRoot", "SYSTEMROOT"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
    }
    command.envs(extra.iter().copied());
}

/// A `serve` process: frames on stdout.
pub struct Radicled {
    pub child: Child,
    stdin: Option<ChildStdin>,
    frames: Receiver<Value>,
    /// Messages read while waiting for another.
    pending: VecDeque<Value>,
    stderr: Option<std::thread::JoinHandle<String>>,
    /// stderr so far, as its reader has it.
    log: std::sync::Arc<std::sync::Mutex<String>>,
    /// Each stream's data so far, in order: its frames come as messages
    /// with their lengths alone ([`stream_frame`]).
    bodies: Bodies,
    next_id: u64,
    /// While set, stdout isn't read: the service's writer fills the pipe,
    /// then waits, as when main doesn't read ([`Radicled::pause`]).
    paused: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

type Bodies = std::sync::Arc<std::sync::Mutex<HashMap<u64, Vec<u8>>>>;

impl Drop for Radicled {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Radicled {
    /// `serve` for `dirs`, `direct`, with `extra` in its environment.
    pub fn serve(dirs: &Dirs, extra: &[(&str, &str)]) -> Radicled {
        Radicled::serve_on(dirs, "direct", extra)
    }

    /// `serve` for `dirs` under `network` (`--network`).
    pub fn serve_on(dirs: &Dirs, network: &str, extra: &[(&str, &str)]) -> Radicled {
        let mut command = Command::new(BIN);
        command
            .arg("serve")
            .arg("--home")
            .arg(&dirs.home)
            .arg("--lock-dir")
            .arg(&dirs.locks)
            .args(["--network", network]);
        environment(&mut command, dirs, extra);
        Radicled::spawn(command)
    }

    /// `import` for `dirs`, reading `source`, with `protected` as main's
    /// protected roots, and `extra` in its environment (design 0010, D5).
    pub fn import(
        dirs: &Dirs,
        source: &std::path::Path,
        protected: &[&std::path::Path],
        extra: &[(&str, &str)],
    ) -> Radicled {
        let mut command = Command::new(BIN);
        command
            .arg("import")
            .arg("--home")
            .arg(&dirs.home)
            .arg("--lock-dir")
            .arg(&dirs.locks)
            .arg("--source")
            .arg(source);
        for root in protected {
            command.arg("--protected").arg(root);
        }
        environment(&mut command, dirs, extra);
        Radicled::spawn(command)
    }

    pub fn spawn(mut command: Command) -> Radicled {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = {
            let _spawning = spawning();
            command.spawn().unwrap()
        };
        let stdin = child.stdin.take();
        let mut stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, frames) = mpsc::channel();
        let bodies: Bodies = Default::default();
        let data = bodies.clone();
        let paused = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pausing = paused.clone();
        std::thread::spawn(move || {
            loop {
                while pausing.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                let mut header = [0u8; 5];
                if stdout.read_exact(&mut header).is_err() {
                    return;
                }
                let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
                let mut payload = vec![0u8; (len as usize).saturating_sub(1)];
                if stdout.read_exact(&mut payload).is_err() {
                    return;
                }
                let message = match header[4] {
                    1 => {
                        let mut message: Value = serde_json::from_slice(&payload).unwrap_or_else(
                            |_| json!({ "malformed": String::from_utf8_lossy(&payload) }),
                        );
                        // An event as written: its envelope's exact bytes.
                        if message["type"] == "event" {
                            message["wire"] = String::from_utf8_lossy(&payload).into();
                        }
                        message
                    }
                    2..=4 => stream_frame(header[4], &payload, &data),
                    kind => json!({ "frame_kind": kind }),
                };
                if tx.send(message).is_err() {
                    return;
                }
            }
        });
        let log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let stderr = {
            let log = log.clone();
            std::thread::spawn(move || {
                let mut lines = BufReader::new(stderr);
                let mut line = Vec::new();
                while let Ok(1..) = lines.read_until(b'\n', &mut line) {
                    let text = String::from_utf8_lossy(&line);
                    log.lock().unwrap().push_str(&text);
                    line.clear();
                }
                log.lock().unwrap().clone()
            })
        };
        Radicled {
            child,
            stdin,
            frames,
            pending: VecDeque::new(),
            stderr: Some(stderr),
            log,
            bodies,
            next_id: 1,
            paused,
        }
    }

    /// Stops reading stdout after the frame being read: what the service
    /// writes next waits in the pipe, then in the service, as when main
    /// doesn't read.
    pub fn pause(&self) {
        self.paused.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Reads stdout again.
    pub fn resume(&self) {
        self.paused
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Request `id`'s `rad.progress` events, in the order they came, up to
    /// its reply, which it returns last; other messages wait.
    pub fn progress(&mut self, id: u64) -> (Vec<Value>, Value) {
        let ours = |m: &Value| m["event"] == "rad.progress" && m["data"]["id"] == id;
        let mut events = Vec::new();
        let mut kept = VecDeque::new();
        let mut reply = None;
        for message in std::mem::take(&mut self.pending) {
            if reply.is_none() && ours(&message) {
                events.push(message);
            } else if reply.is_none() && message["id"] == id {
                reply = Some(message);
            } else {
                kept.push_back(message);
            }
        }
        self.pending = kept;
        while reply.is_none() {
            let message = match self.frames.recv_timeout(READ_TIMEOUT) {
                Ok(message) => message,
                Err(e) => panic!("no reply to {id} from freedom-radicled: {e}"),
            };
            if ours(&message) {
                events.push(message);
            } else if message["id"] == id {
                reply = Some(message);
            } else {
                self.pending.push_back(message);
            }
        }
        (events, reply.unwrap())
    }

    /// Whether any `rad.progress` of request `id` has come since its reply,
    /// or comes within `within`.
    pub fn progress_after(&mut self, id: u64, within: Duration) -> bool {
        let ours = |m: &Value| m["event"] == "rad.progress" && m["data"]["id"] == id;
        let deadline = Instant::now() + within;
        loop {
            if self.pending.iter().any(ours) {
                return true;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            match self.frames.recv_timeout(left) {
                Ok(message) => self.pending.push_back(message),
                Err(_) => return false,
            }
        }
    }

    pub fn send(&mut self, message: &Value) {
        let mut frame = Vec::new();
        fc_protocol::frame::encode_json(message.to_string().as_bytes(), &mut frame).unwrap();
        let stdin = self.stdin.as_mut().expect("stdin is closed");
        stdin.write_all(&frame).unwrap();
        stdin.flush().unwrap();
    }

    /// Sends a request with the next ID, and returns the ID.
    pub fn request(&mut self, method: &str, params: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "type": "request", "id": id, "method": method, "params": params }));
        id
    }

    /// The reply to request `id`; other messages wait.
    pub fn reply(&mut self, id: u64) -> Value {
        if let Some(at) = self.pending.iter().position(|m| m["id"] == id) {
            return self.pending.remove(at).unwrap();
        }
        loop {
            let message = match self.frames.recv_timeout(READ_TIMEOUT) {
                Ok(message) => message,
                Err(e) => panic!("no reply to {id} from freedom-radicled: {e}"),
            };
            if message["id"] == id {
                return message;
            }
            self.pending.push_back(message);
        }
    }

    /// The replies to `ids`, by their IDs, in the order they arrived. They,
    /// and other messages, stay for [`Radicled::reply`].
    pub fn arrivals(&mut self, ids: &[u64]) -> Vec<u64> {
        let wanted = |message: &Value| message["id"].as_u64().filter(|id| ids.contains(id));
        let mut seen: Vec<u64> = Vec::new();
        for id in self.pending.iter().filter_map(wanted) {
            if !seen.contains(&id) {
                seen.push(id);
            }
        }
        while seen.len() < ids.len() {
            let message = match self.frames.recv_timeout(READ_TIMEOUT) {
                Ok(message) => message,
                Err(e) => panic!("no replies to {ids:?} from freedom-radicled: {e}"),
            };
            if let Some(id) = wanted(&message)
                && !seen.contains(&id)
            {
                seen.push(id);
            }
            self.pending.push_back(message);
        }
        seen
    }

    /// Main's cancel of request `id`.
    pub fn cancel(&mut self, id: u64) {
        self.send(&json!({ "type": "cancel", "id": id }));
    }

    /// Returns `bytes` of stream `id`'s window.
    pub fn credit(&mut self, id: u64, bytes: u32) {
        let frame = fc_protocol::stream::credit_frame(id, bytes).unwrap();
        let stdin = self.stdin.as_mut().expect("stdin is closed");
        stdin.write_all(&frame).unwrap();
        stdin.flush().unwrap();
    }

    /// The next frame of stream `id`; other messages wait.
    pub fn stream(&mut self, id: u64) -> Value {
        if let Some(at) = self.pending.iter().position(|m| m["stream_id"] == id) {
            return self.pending.remove(at).unwrap();
        }
        loop {
            let message = match self.frames.recv_timeout(READ_TIMEOUT) {
                Ok(message) => message,
                Err(e) => panic!("no frame of stream {id} from freedom-radicled: {e}"),
            };
            if message["stream_id"] == id {
                return message;
            }
            self.pending.push_back(message);
        }
    }

    /// Whether a frame of stream `id`, or a reply to `id`, arrives within
    /// `within`. Either stays for [`Radicled::reply`] or
    /// [`Radicled::stream`].
    pub fn any_within(&mut self, id: u64, within: Duration) -> bool {
        let ours = |m: &Value| m["stream_id"] == id || m["id"] == id;
        if self.pending.iter().any(ours) {
            return true;
        }
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.frames.recv_timeout(left) {
                Ok(message) => {
                    let found = ours(&message);
                    self.pending.push_back(message);
                    if found {
                        return true;
                    }
                }
                Err(_) => return false,
            }
        }
    }

    /// Stream `id`'s body to its terminal frame, returning each data
    /// frame's bytes as credit as main's consumer does: its bytes, and the
    /// terminal frame.
    pub fn body(&mut self, id: u64) -> (Vec<u8>, Value) {
        loop {
            let frame = self.stream(id);
            match frame["stream"].as_str() {
                Some("data") => {
                    let len = frame["len"].as_u64().unwrap();
                    self.credit(id, u32::try_from(len).unwrap());
                }
                _ => {
                    let bytes = self.bodies.lock().unwrap().remove(&id).unwrap_or_default();
                    return (bytes, frame);
                }
            }
        }
    }

    /// The data of stream `id` received so far, taken.
    pub fn taken(&mut self, id: u64) -> Vec<u8> {
        self.bodies.lock().unwrap().remove(&id).unwrap_or_default()
    }

    /// Reads stream `id`'s data frames, without credit, until `bytes` of it
    /// have come: a window's worth, say.
    pub fn uncredited(&mut self, id: u64, bytes: u64) {
        let mut came = 0;
        while came < bytes {
            let frame = self.stream(id);
            assert_eq!(frame["stream"], "data", "{frame}");
            came += frame["len"].as_u64().unwrap();
        }
        assert_eq!(came, bytes);
    }

    /// `rad.read { op, args }`: its body, if its head came, after checking
    /// the head and that the stream ended; or its error reply.
    pub fn read(&mut self, op: &str, args: Value) -> Result<Vec<u8>, Value> {
        let id = self.request("rad.read", json!({ "op": op, "args": args }));
        self.read_reply(id)
    }

    /// [`Radicled::read`]'s answer for request `id`.
    pub fn read_reply(&mut self, id: u64) -> Result<Vec<u8>, Value> {
        let head = self.reply(id);
        if head.get("error").is_some() {
            return Err(head);
        }
        assert_eq!(head["result"]["content_type"], "application/json", "{head}");
        let (bytes, end) = self.body(id);
        assert_eq!(end["stream"], "end", "{end}");
        assert_eq!(
            head["result"]["bytes"].as_u64(),
            Some(bytes.len() as u64),
            "{head}"
        );
        Ok(bytes)
    }

    /// Sends a request and returns its reply.
    pub fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.request(method, params);
        self.reply(id)
    }

    /// The handshake.
    pub fn hello(&mut self) -> Value {
        let reply = self.call(
            "rad.hello",
            json!({ "protocol": 1, "shell_version": "test", "frames": ["stream"] }),
        );
        assert!(reply["result"].is_object(), "{reply}");
        reply
    }

    pub fn close_stdin(&mut self) {
        self.stdin.take();
    }

    /// The start, as main runs it, as `SEED`'s identity: `rad.hello`,
    /// `rad.identity` with the key sealed, `rad.reconcile`, then `rad.start`,
    /// whose reply it returns.
    pub fn start(&mut self) -> Value {
        let hello = self.hello();
        let identity = self.call("rad.identity", sealed_to(&hello, &SEED));
        assert!(identity["result"].is_object(), "{identity}");
        let reconciled = self.call("rad.reconcile", json!({}));
        assert!(reconciled["result"].is_object(), "{reconciled}");
        self.call("rad.start", json!({ "alias": "started" }))
    }

    /// The import process's steps before `rad.import_repo`, as `SEED`'s
    /// identity: `rad.hello`, `rad.identity` with the key sealed, then
    /// `rad.reconcile`, whose reply it returns with `rad.hello`'s.
    pub fn reconciled(&mut self) -> (Value, Value) {
        let hello = self.hello();
        let identity = self.call("rad.identity", sealed_to(&hello, &SEED));
        assert!(identity["result"].is_object(), "{identity}");
        let reconciled = self.call("rad.reconcile", json!({}));
        assert!(reconciled["result"].is_object(), "{reconciled}");
        (hello, reconciled)
    }

    /// `rad.shutdown`, as main sends it; the process then exits.
    pub fn shutdown(&mut self) {
        self.request("rad.shutdown", json!({}));
    }

    /// The exit code, once it exits within `timeout`; `None` past it, or
    /// for an exit by signal.
    pub fn exit_code(&mut self, timeout: Duration) -> Option<i32> {
        wait(&mut self.child, timeout)
    }

    /// stderr, once the process has exited.
    pub fn stderr(&mut self) -> String {
        self.stderr.take().unwrap().join().unwrap()
    }

    /// Waits up to `within` for a stderr line containing `needle`, while
    /// the process runs.
    pub fn logs(&self, needle: &str, within: Duration) -> bool {
        self.logs_times(needle, 1, within)
    }

    /// Waits up to `within` for `times` stderr lines containing `needle`,
    /// while the process runs.
    pub fn logs_times(&self, needle: &str, times: usize, within: Duration) -> bool {
        let until = Instant::now() + within;
        while self.log.lock().unwrap().matches(needle).count() < times {
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        true
    }
}

/// A `hold-lock` process: lines on stdout.
pub struct HoldLock {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
}

impl Drop for HoldLock {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl HoldLock {
    pub fn spawn(dirs: &Dirs) -> HoldLock {
        let mut command = Command::new(BIN);
        command
            .arg("hold-lock")
            .arg("--home")
            .arg(&dirs.home)
            .arg("--lock-dir")
            .arg(&dirs.locks);
        environment(&mut command, dirs, &[]);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = {
            let _spawning = spawning();
            command.spawn().unwrap()
        };
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        HoldLock {
            child,
            stdin,
            lines,
        }
    }

    pub fn line(&self) -> String {
        self.lines.recv_timeout(READ_TIMEOUT).unwrap()
    }

    pub fn release(&mut self) {
        self.stdin.take();
    }

    pub fn exit_code(&mut self, timeout: Duration) -> Option<i32> {
        wait(&mut self.child, timeout)
    }
}

/// A stream frame as a message: `{ stream, stream_id, … }`, a data frame's
/// length (its bytes go to `bodies`), and an abort's code and message.
fn stream_frame(kind: u8, payload: &[u8], bodies: &Bodies) -> Value {
    use fc_protocol::stream::StreamFrame;
    match StreamFrame::decode(kind, payload) {
        Ok(StreamFrame::Data { id, bytes }) => {
            bodies
                .lock()
                .unwrap()
                .entry(id)
                .or_default()
                .extend_from_slice(bytes);
            json!({ "stream": "data", "stream_id": id, "len": bytes.len() })
        }
        Ok(StreamFrame::End { id }) => json!({ "stream": "end", "stream_id": id }),
        Ok(StreamFrame::Abort { id, abort }) => json!({ "stream": "abort", "stream_id": id,
            "code": abort.code.as_str(), "message": abort.message }),
        Ok(other) => json!({ "unexpected_frame": format!("{other:?}") }),
        Err(e) => json!({ "unexpected_kind": kind, "error": e.category() }),
    }
}

fn wait(child: &mut Child, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code();
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Writes `home`'s `config.json` for a node that reaches no one by itself:
/// the test network, no preferred seeds (one would bring the shipped seed
/// book after it), a static peer set and no `connect` peers. `node`'s
/// members add to its node configuration, or replace these.
pub fn configure(home: &std::path::Path, node: Value) {
    std::fs::create_dir_all(home).unwrap();
    let mut fields = json!({ "alias": "quiet", "network": "test", "peers": { "type": "static" } });
    for (key, value) in node.as_object().unwrap() {
        fields[key] = value.clone();
    }
    std::fs::write(
        home.join("config.json"),
        json!({ "preferredSeeds": [], "node": fields }).to_string(),
    )
    .unwrap();
}

/// RFC 8032's first Ed25519 test key, and the node ID of its public key.
pub const SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
pub const NID: &str = "z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";

pub struct OsRng;

impl rand_core::TryRng for OsRng {
    type Error = getrandom::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst)
    }
}

impl rand_core::TryCryptoRng for OsRng {}

/// What the core's `nodes.seal_radicle_key` returns for `key`, sealed to
/// the recipient `rad.hello` named.
pub fn sealed_to(hello: &Value, key: &[u8; 32]) -> Value {
    let recipient: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(hello["result"]["recipient"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sealed = fc_seal::seal(&recipient, key, &mut OsRng).unwrap();
    json!({ "sealed": {
        "enc": base64::engine::general_purpose::STANDARD.encode(sealed.enc),
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(sealed.ciphertext),
    } })
}
