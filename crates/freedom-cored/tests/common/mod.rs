//! Shared test harness: the real binary over its pipes, with timeouts on
//! every read and a kill-and-reap guard.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

pub const BIN: &str = env!("CARGO_BIN_EXE_freedom-cored");
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// stdout, read on a thread: either frames (serve) or lines (hold-lock,
/// recover).
pub enum Output {
    Frame(Value),
    Line(String),
}

pub struct Core {
    pub child: Child,
    stdin: Option<ChildStdin>,
    output: Receiver<Output>,
    stderr: Option<std::thread::JoinHandle<String>>,
    /// Events seen while waiting for responses.
    pub events: Vec<Value>,
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
            let mut header = [0u8; 5];
            if stdout.read_exact(&mut header).is_err() {
                return;
            }
            let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize - 1;
            let mut payload = vec![0u8; len];
            if stdout.read_exact(&mut payload).is_err() {
                return;
            }
            if tx
                .send(Output::Frame(serde_json::from_slice(&payload).unwrap()))
                .is_err()
            {
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

pub fn request(id: u64, method: &str, params: Value) -> Value {
    json!({ "type": "request", "id": id, "method": method, "params": params, "context": { "caller": "chrome" } })
}

impl Core {
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
            Ok(Output::Line(line)) => panic!("expected a frame, got line {line:?}"),
            Err(_) => panic!("no reply within {READ_TIMEOUT:?}"),
        }
    }

    pub fn line(&mut self) -> String {
        match self.output.recv_timeout(READ_TIMEOUT) {
            Ok(Output::Line(line)) => line,
            Ok(Output::Frame(_)) => panic!("expected a line"),
            Err(_) => panic!("no line within {READ_TIMEOUT:?}"),
        }
    }

    pub fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(&request(id, method, params));
        self.response(id)
    }

    /// Calls with caller `shell` (main-internal methods such as compat.*).
    pub fn call_shell(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(&json!({ "type": "request", "id": id, "method": method, "params": params, "context": { "caller": "shell" } }));
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

pub fn dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("identity");
    let locks = root.path().join("locks");
    (root, data, locks)
}
