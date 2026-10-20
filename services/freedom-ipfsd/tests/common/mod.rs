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
}

impl Drop for Ipfsd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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
        std::thread::spawn(move || {
            loop {
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
                    json!({ "unexpected_kind": header[4] })
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
            "dht_query_timeout_s": 3, "dht_max_providers": 32 },
        "gateway": { "max_concurrent_requests": 8, "request_queue_timeout_ms": 15000 },
        "network": { "mode": "direct" }
    })
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
