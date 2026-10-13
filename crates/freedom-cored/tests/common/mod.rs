//! Shared test harness: the real binary over its pipes, with timeouts on
//! every read and a kill-and-reap guard.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
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
    Frame(Value),
    Line(String),
    /// The reader stopped on a frame it couldn't parse.
    Malformed(String),
}

pub struct Core {
    pub child: Child,
    stdin: Option<ChildStdin>,
    output: Receiver<Output>,
    stderr: Option<std::thread::JoinHandle<String>>,
    /// Events seen while waiting for responses.
    pub events: Vec<Value>,
    /// While set, stdout isn't read: the pipe fills, as when main stalls.
    paused: Arc<(Mutex<bool>, Condvar)>,
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
            let output = match serde_json::from_slice(&payload) {
                Ok(value) => Output::Frame(value),
                Err(err) => {
                    Output::Malformed(format!("{err}: {}", String::from_utf8_lossy(&payload)))
                }
            };
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

    /// Every frame left, until the core closes stdout.
    pub fn rest(&mut self) -> Vec<Value> {
        let mut frames = Vec::new();
        loop {
            match self.output.recv_timeout(READ_TIMEOUT) {
                Ok(Output::Frame(value)) => frames.push(value),
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
            Ok(Output::Frame(_)) => panic!("expected a line"),
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
