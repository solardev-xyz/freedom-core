//! The real binary over its pipes, as main speaks to it. Every read has a
//! timeout and every child is killed and reaped on drop, so a regression
//! fails a test instead of hanging the suite.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

pub const BIN: &str = env!("CARGO_BIN_EXE_freedom-ipfsd");
/// A hang guard, never a timing assertion.
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a process gets to exit when it should.
pub const EXIT_TIMEOUT: Duration = Duration::from_secs(15);

/// A data directory and a lock directory, removed on drop.
pub struct Dirs {
    _root: tempfile::TempDir,
    pub data: PathBuf,
    pub locks: PathBuf,
}

impl Dirs {
    pub fn new() -> Dirs {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("ipfs-data").join("freedom-ipfs");
        let locks = root.path().join("locks");
        Dirs {
            _root: root,
            data,
            locks,
        }
    }
}

/// A `serve` process: frames on stdout.
pub struct Ipfsd {
    pub child: Child,
    stdin: Option<ChildStdin>,
    frames: Receiver<Value>,
    /// Messages read while waiting for another.
    pending: VecDeque<Value>,
    stderr: Option<std::thread::JoinHandle<String>>,
    next_id: u64,
    /// Whether stdout's reader is paused: main not reading.
    paused: Arc<(Mutex<bool>, Condvar)>,
}

impl Drop for Ipfsd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.resume_reading();
    }
}

impl Ipfsd {
    /// Main stops reading stdout: once the pipe's buffer is full, the
    /// service's writer blocks inside the frame it is writing.
    pub fn pause_reading(&self) {
        *self.paused.0.lock().unwrap() = true;
    }

    pub fn resume_reading(&self) {
        *self.paused.0.lock().unwrap() = false;
        self.paused.1.notify_all();
    }
}

impl Ipfsd {
    /// The persistent process for `dirs`.
    pub fn persistent(dirs: &Dirs, env: &[(&str, &str)]) -> Ipfsd {
        let mut command = Command::new(BIN);
        command
            .arg("serve")
            .arg("--data-dir")
            .arg(&dirs.data)
            .arg("--lock-dir")
            .arg(&dirs.locks);
        Ipfsd::spawn(command, env)
    }

    /// The ephemeral process.
    pub fn ephemeral(env: &[(&str, &str)]) -> Ipfsd {
        let mut command = Command::new(BIN);
        command.args(["serve", "--ephemeral"]);
        Ipfsd::spawn(command, env)
    }

    /// Any command whose stdout carries frames.
    pub fn spawn(mut command: Command, env: &[(&str, &str)]) -> Ipfsd {
        let mut child = command
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let (tx, frames) = mpsc::channel();
        let paused = Arc::new((Mutex::new(false), Condvar::new()));
        let reading = paused.clone();
        std::thread::spawn(move || {
            loop {
                {
                    let mut paused = reading.0.lock().unwrap();
                    while *paused {
                        paused = reading.1.wait(paused).unwrap();
                    }
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
                let message = if header[4] == 1 {
                    serde_json::from_slice(&payload).unwrap_or_else(
                        |_| json!({ "malformed": String::from_utf8_lossy(&payload) }),
                    )
                } else {
                    stream_frame(header[4], &payload)
                };
                if tx.send(message).is_err() {
                    return;
                }
            }
        });
        let stderr = std::thread::spawn(move || {
            let mut all = String::new();
            let _ = stderr.read_to_string(&mut all);
            all
        });
        Ipfsd {
            child,
            stdin,
            frames,
            pending: VecDeque::new(),
            stderr: Some(stderr),
            next_id: 1,
            paused,
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

    /// The next stream frame of stream `id`; other messages wait for
    /// [`Ipfsd::recv`].
    pub fn stream(&mut self, id: u64) -> Value {
        if let Some(at) = self.pending.iter().position(|m| m["stream_id"] == id) {
            return self.pending.remove(at).unwrap();
        }
        loop {
            let message = match self.frames.recv_timeout(READ_TIMEOUT) {
                Ok(message) => message,
                Err(e) => panic!("no frame of stream {id} from freedom-ipfsd: {e}"),
            };
            if message["stream_id"] == id {
                return message;
            }
            self.pending.push_back(message);
        }
    }

    /// Whether a frame of stream `id` arrives within `within`.
    pub fn stream_frame_within(&mut self, id: u64, within: Duration) -> bool {
        if self.pending.iter().any(|m| m["stream_id"] == id) {
            return true;
        }
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.frames.recv_timeout(left) {
                Ok(message) => {
                    let ours = message["stream_id"] == id;
                    self.pending.push_back(message);
                    if ours {
                        return true;
                    }
                }
                Err(_) => return false,
            }
        }
    }

    /// Stream `id`'s body to its terminal, returning each byte read as
    /// credit as main's consumer would: the bytes, and the terminal frame.
    pub fn body(&mut self, id: u64) -> (Vec<u8>, Value) {
        let mut bytes = Vec::new();
        loop {
            let frame = self.stream(id);
            match frame["stream"].as_str() {
                Some("data") => {
                    let chunk = unhex(frame["hex"].as_str().unwrap());
                    self.credit(id, u32::try_from(chunk.len()).unwrap());
                    bytes.extend_from_slice(&chunk);
                }
                _ => return (bytes, frame),
            }
        }
    }

    /// The next event named `name`; other messages wait for
    /// [`Ipfsd::recv`].
    pub fn event(&mut self, name: &str) -> Value {
        if let Some(at) = self.pending.iter().position(|m| m["event"] == name) {
            return self.pending.remove(at).unwrap();
        }
        loop {
            let message = match self.frames.recv_timeout(READ_TIMEOUT) {
                Ok(message) => message,
                Err(e) => panic!("no {name} from freedom-ipfsd: {e}"),
            };
            if message["event"] == name {
                return message;
            }
            self.pending.push_back(message);
        }
    }

    /// The next message, in the order the service wrote them.
    pub fn recv(&mut self) -> Value {
        if let Some(message) = self.pending.pop_front() {
            return message;
        }
        match self.frames.recv_timeout(READ_TIMEOUT) {
            Ok(message) => message,
            Err(e) => panic!("no message from freedom-ipfsd: {e}"),
        }
    }

    /// The reply to request `id`; other messages wait for [`Ipfsd::recv`].
    pub fn reply(&mut self, id: u64) -> Value {
        if let Some(at) = self.pending.iter().position(|m| m["id"] == id) {
            return self.pending.remove(at).unwrap();
        }
        loop {
            let message = match self.frames.recv_timeout(READ_TIMEOUT) {
                Ok(message) => message,
                Err(e) => panic!("no reply to {id} from freedom-ipfsd: {e}"),
            };
            if message["id"] == id {
                return message;
            }
            self.pending.push_back(message);
        }
    }

    /// Sends a request and returns its reply.
    pub fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.request(method, params);
        self.reply(id)
    }

    /// The handshake, with ID 1 unless requests went first.
    pub fn hello(&mut self) -> Value {
        let reply = self.call(
            "ipfs.hello",
            json!({ "protocol": 1, "shell_version": "test", "frames": ["stream"] }),
        );
        assert!(reply["result"].is_object(), "{reply}");
        reply
    }

    pub fn start(&mut self, params: Value) -> Value {
        self.call("ipfs.start", params)
    }

    pub fn stop(&mut self, instance: &str) -> Value {
        self.call("ipfs.stop", json!({ "instance": instance }))
    }

    /// `ipfs.shutdown`: no reply, the process exits.
    pub fn shutdown(&mut self) {
        self.request("ipfs.shutdown", json!({}));
    }

    pub fn close_stdin(&mut self) {
        self.stdin.take();
    }

    /// Whether stdout closes within `timeout` with no message left: every
    /// process holding it has exited.
    pub fn stdout_closes_within(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.frames.recv_timeout(left) {
                Ok(message) => self.pending.push_back(message),
                Err(RecvTimeoutError::Disconnected) => return true,
                Err(RecvTimeoutError::Timeout) => return false,
            }
        }
    }

    /// Messages written but not yet taken, once stdout has closed.
    pub fn leftover(&mut self) -> Vec<Value> {
        while let Ok(message) = self.frames.try_recv() {
            self.pending.push_back(message);
        }
        self.pending.drain(..).collect()
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

    /// Threads of this process named `name`.
    #[cfg(target_os = "linux")]
    pub fn threads(&self, name: &str) -> usize {
        let tasks = format!("/proc/{}/task", self.child.id());
        std::fs::read_dir(tasks)
            .unwrap()
            .filter_map(|task| std::fs::read_to_string(task.ok()?.path().join("comm")).ok())
            .filter(|comm| comm.trim_end() == name)
            .count()
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
        let mut child = Command::new(BIN)
            .arg("hold-lock")
            .arg("--data-dir")
            .arg(&dirs.data)
            .arg("--lock-dir")
            .arg(&dirs.locks)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
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

/// `ipfs.start`'s params for a disk instance: today's values (0007,
/// "Methods"), except that routing is offline, so nothing touches the
/// network.
pub fn disk(instance: &str) -> Value {
    start_params(instance, json!({ "kind": "disk", "max_bytes": 268435456 }))
}

/// As [`disk`], for a private instance's memory store.
pub fn memory(instance: &str) -> Value {
    start_params(instance, json!({ "kind": "memory", "max_bytes": 33554432 }))
}

pub fn start_params(instance: &str, store: Value) -> Value {
    json!({
        "instance": instance,
        "store": store,
        "routing": { "mode": "offline",
            "delegated_routers": ["https://delegated-ipfs.dev/routing/v1", "https://cid.contact/routing/v1"],
            "doh_endpoint": "https://cloudflare-dns.com/dns-query",
            "dht_query_timeout_s": 3, "dht_max_providers": 32 },
        "gateway": { "max_concurrent_requests": 8, "request_queue_timeout_ms": 15000 },
        "network": { "mode": "direct" }
    })
}

/// A stream frame as a message: `{ stream, stream_id, … }`, with a data
/// frame's bytes in hex and an abort's code and message.
fn stream_frame(kind: u8, payload: &[u8]) -> Value {
    use fc_protocol::stream::StreamFrame;
    match StreamFrame::decode(kind, payload) {
        Ok(StreamFrame::Data { id, bytes }) => {
            json!({ "stream": "data", "stream_id": id, "hex": hex(bytes) })
        }
        Ok(StreamFrame::End { id }) => json!({ "stream": "end", "stream_id": id }),
        Ok(StreamFrame::Abort { id, abort }) => json!({ "stream": "abort", "stream_id": id,
            "code": abort.code.as_str(), "message": abort.message }),
        Ok(other) => json!({ "unexpected_frame": format!("{other:?}") }),
        Err(e) => json!({ "unexpected_kind": kind, "error": e.category() }),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// Puts `blocks` (raw blocks) into the persistent store of `dirs`, before
/// the service opens it, and returns their CIDs.
pub fn seed(dirs: &Dirs, blocks: &[Vec<u8>]) -> Vec<String> {
    std::fs::create_dir_all(&dirs.data).unwrap();
    let store =
        freedom_ipfs_store::SqliteBlockStore::open(dirs.data.join("freedom-ipfs.sqlite3"), 1 << 30)
            .unwrap();
    let cids = blocks
        .iter()
        .map(|data| {
            let cid = freedom_ipfs_core::cid_from_data(freedom_ipfs_core::CODEC_RAW, data);
            store.put_block(&cid, data).unwrap();
            cid.to_string()
        })
        .collect();
    assert!(store.close(Duration::from_secs(2)));
    cids
}

/// An HTTP provider on loopback whose fetches never end: it accepts, and
/// never says a word.
pub struct Server {
    pub port: u16,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
}

impl Server {
    pub fn start() -> Server {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = accepted.clone();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                held.push(stream);
            }
        });
        Server { port, accepted }
    }

    /// The connections it accepted.
    pub fn accepted(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Records `provider` as the HTTP provider of `cids` in the persistent store
/// of `dirs`, before the service opens it: an offline instance asks it for
/// them.
pub fn seed_provider(dirs: &Dirs, cids: &[String], provider: &Server) {
    std::fs::create_dir_all(&dirs.data).unwrap();
    let store =
        freedom_ipfs_store::SqliteBlockStore::open(dirs.data.join("freedom-ipfs.sqlite3"), 1 << 30)
            .unwrap();
    let record = freedom_ipfs_store::CachedProviderRecord {
        id: None,
        addrs: vec![format!("/ip4/127.0.0.1/tcp/{}/http", provider.port)],
    };
    for cid in cids {
        let cid = cid.parse().unwrap();
        store
            .put_provider_records(
                &cid,
                std::slice::from_ref(&record),
                Duration::from_secs(3600),
            )
            .unwrap();
    }
    assert!(store.close(Duration::from_secs(2)));
}

/// A protobuf varint.
fn varint(mut n: u64, out: &mut Vec<u8>) {
    while n >= 0x80 {
        out.push((n as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

fn field(tag: u8, bytes: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

/// A dag-pb node: `links` (name, CID bytes, size), then UnixFS `data`.
fn pb_node(links: &[(&str, Vec<u8>, u64)], data: &[u8]) -> Vec<u8> {
    let mut node = Vec::new();
    for (name, cid, size) in links {
        let mut link = Vec::new();
        field(0x0a, cid, &mut link);
        field(0x12, name.as_bytes(), &mut link);
        link.push(0x18);
        varint(*size, &mut link);
        field(0x12, &link, &mut node);
    }
    field(0x0a, data, &mut node);
    node
}

/// A UnixFS file of `leaves` (CID bytes, size), in order.
pub fn pb_file(leaves: &[(Vec<u8>, u64)]) -> Vec<u8> {
    let mut data = vec![0x08, 2];
    data.push(0x18);
    varint(leaves.iter().map(|(_, size)| size).sum(), &mut data);
    for (_, size) in leaves {
        data.push(0x20);
        varint(*size, &mut data);
    }
    let links: Vec<(&str, Vec<u8>, u64)> = leaves
        .iter()
        .map(|(cid, size)| ("", cid.clone(), *size))
        .collect();
    pb_node(&links, &data)
}

/// A UnixFS directory of `entries` (name, CID bytes, size).
pub fn pb_directory(entries: &[(&str, Vec<u8>, u64)]) -> Vec<u8> {
    pb_node(entries, &[0x08, 1])
}

/// Puts `blocks` (codec, bytes) into the persistent store of `dirs`, before
/// the service opens it, and returns their CIDs as bytes and as text.
pub fn seed_blocks(dirs: &Dirs, blocks: &[(u64, Vec<u8>)]) -> Vec<(Vec<u8>, String)> {
    std::fs::create_dir_all(&dirs.data).unwrap();
    let store =
        freedom_ipfs_store::SqliteBlockStore::open(dirs.data.join("freedom-ipfs.sqlite3"), 1 << 30)
            .unwrap();
    let cids = blocks
        .iter()
        .map(|(codec, data)| {
            let cid = freedom_ipfs_core::cid_from_data(*codec, data);
            store.put_block(&cid, data).unwrap();
            (cid.to_bytes(), cid.to_string())
        })
        .collect();
    assert!(store.close(Duration::from_secs(2)));
    cids
}

/// `ipfs.request`'s params for a `GET` of `path` on `instance`.
pub fn get(instance: &str, path: &str) -> Value {
    json!({ "instance": instance, "method": "GET", "path": path, "headers": [],
        "headers_ms": 30000 })
}

/// A command run to its end with no stdin, and its exit code.
pub fn status<S: AsRef<OsStr>>(args: &[S]) -> Option<i32> {
    Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .code()
}
