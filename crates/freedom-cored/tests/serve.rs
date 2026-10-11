//! Integration tests: the real binary, spoken to over its pipes. Every read
//! has a timeout and every child is killed and reaped on drop, so a
//! regression fails a test instead of hanging the suite.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_freedom-cored");
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// stdout, read on a thread: either frames (serve) or lines (hold-lock,
/// recover).
enum Output {
    Frame(Value),
    Line(String),
}

struct Core {
    child: Child,
    stdin: Option<ChildStdin>,
    output: Receiver<Output>,
    stderr: Option<std::thread::JoinHandle<String>>,
}

impl Drop for Core {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn(command: &str, data: &Path, locks: &Path, extra: &[&str]) -> Core {
    let mut child = Command::new(BIN)
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
    }
}

fn frame(message: &Value) -> Vec<u8> {
    let payload = serde_json::to_vec(message).unwrap();
    let mut frame = u32::try_from(payload.len() + 1)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    frame.push(1);
    frame.extend_from_slice(&payload);
    frame
}

fn request(id: u64, method: &str, params: Value) -> Value {
    json!({ "type": "request", "id": id, "method": method, "params": params, "context": { "caller": "chrome" } })
}

impl Core {
    fn send(&mut self, message: &Value) {
        self.send_raw(&frame(message));
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(bytes).unwrap();
        stdin.flush().unwrap();
    }

    fn recv(&mut self) -> Value {
        match self.output.recv_timeout(READ_TIMEOUT) {
            Ok(Output::Frame(value)) => value,
            Ok(Output::Line(line)) => panic!("expected a frame, got line {line:?}"),
            Err(_) => panic!("no reply within {READ_TIMEOUT:?}"),
        }
    }

    fn line(&mut self) -> String {
        match self.output.recv_timeout(READ_TIMEOUT) {
            Ok(Output::Line(line)) => line,
            Ok(Output::Frame(_)) => panic!("expected a line"),
            Err(_) => panic!("no line within {READ_TIMEOUT:?}"),
        }
    }

    fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(&request(id, method, params));
        let response = self.recv();
        assert_eq!(response["type"], "response");
        assert_eq!(response["id"], id);
        response
    }

    fn hello(&mut self) -> Value {
        self.call(
            1,
            "core.hello",
            json!({ "protocol": 1, "shell_version": "test", "auto_lock_ms": 900000 }),
        )
    }

    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    fn exit_code(&mut self, within: Duration) -> i32 {
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
    fn stderr(&mut self) -> String {
        self.stderr.take().unwrap().join().unwrap()
    }
}

fn dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("identity");
    let locks = root.path().join("locks");
    (root, data, locks)
}

#[test]
fn hello_status_shutdown() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    let hello = core.hello();
    assert_eq!(hello["result"]["protocol"], 1);
    assert!(
        hello["result"]["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("vault.status"))
    );

    let status = core.call(2, "vault.status", json!({}));
    assert_eq!(
        status["result"],
        json!({ "exists": false, "unlocked": false, "epoch": null, "fingerprint": null })
    );

    let vault = br#"{"version": 1}"#;
    std::fs::write(data.join("identity-vault.json"), vault).unwrap();
    let status = core.call(3, "vault.status", json!({}));
    assert_eq!(status["result"]["exists"], true);
    let expected: String = Sha256::digest(vault)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(status["result"]["fingerprint"], expected);
    // Reading never rewrites the vault (quick unlock binds to its bytes).
    assert_eq!(
        std::fs::read(data.join("identity-vault.json")).unwrap(),
        vault
    );

    assert_eq!(
        core.call(4, "core.shutdown", json!({}))["result"],
        json!({})
    );
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

#[test]
fn errors_are_typed() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    assert_eq!(
        core.call(2, "vault.nope", json!({}))["error"]["code"],
        "unknown_method"
    );
    core.send(&json!({ "type": "request", "id": 3, "method": "vault.status", "params": {},
        "context": { "caller": "page", "page": { "origin": "https://a", "top_origin": "https://a", "frame": 1, "navigation": 1 } } }));
    assert_eq!(core.recv()["error"]["code"], "forbidden");
    let again = core.call(
        4,
        "core.hello",
        json!({ "protocol": 1, "shell_version": "t", "auto_lock_ms": 0 }),
    );
    assert_eq!(again["error"]["code"], "invalid_argument");
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

#[test]
fn status_refuses_non_regular_vault_files_without_blocking() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    std::fs::create_dir_all(data.join("identity-vault.json")).unwrap();
    let status = core.call(2, "vault.status", json!({}));
    assert_eq!(status["error"]["code"], "storage");
    assert_eq!(status["error"]["data"]["kind"], "not_regular");
    // The loop is still responsive.
    assert_eq!(
        core.call(3, "core.shutdown", json!({}))["result"],
        json!({})
    );
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

#[cfg(unix)]
#[test]
fn a_fifo_vault_does_not_stall_the_loop() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let status = Command::new("mkfifo")
        .arg(data.join("identity-vault.json"))
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        core.call(2, "vault.status", json!({}))["error"]["data"]["kind"],
        "not_regular"
    );
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

#[test]
fn handshake_rules() {
    // The first message must be a core.hello request.
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.send(&request(1, "vault.status", json!({})));
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);

    // Not even a cancel or event first.
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.send(&json!({ "type": "cancel", "id": 1 }));
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);

    // A protocol mismatch is answered, then the core exits.
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    let reply = core.call(
        1,
        "core.hello",
        json!({ "protocol": 2, "shell_version": "t", "auto_lock_ms": 0 }),
    );
    assert_eq!(reply["error"]["code"], "protocol_mismatch");
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);

    // No hello within the deadline.
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &["--hello-timeout-ms", "300"]);
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);
}

#[test]
fn request_ids_must_increase() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    core.call(5, "vault.status", json!({}));
    core.send(&request(5, "vault.status", json!({})));
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);
}

#[test]
fn malformed_input_closes_the_connection_without_logging_it() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    core.send_raw(&[0, 0, 0, 1, 0x07]);
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);

    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    core.send(&json!({ "type": "response", "id": 9, "result": {} }));
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);

    // A value in a malformed envelope must never reach the log.
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    core.send(
        &json!({ "type": "request", "id": "SECRET_SENTINEL_PASSWORD", "method": "vault.status",
        "context": { "caller": "chrome" } }),
    );
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);
    let stderr = core.stderr();
    assert!(!stderr.contains("SECRET_SENTINEL"), "{stderr}");
    assert!(stderr.contains("protocol error"));
}

#[test]
fn a_burst_beyond_the_decoder_budget_is_fully_served() {
    // 200 requests in one write: more than the decoder holds at once, so the
    // reader must keep feeding it after popping (backpressure, no drops).
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let burst: Vec<u8> = (2..202u64)
        .flat_map(|id| frame(&request(id, "vault.status", json!({}))))
        .collect();
    core.send_raw(&burst);
    for id in 2..202u64 {
        let reply = core.recv();
        assert_eq!(reply["id"], id);
        assert_eq!(reply["result"]["exists"], false);
    }
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

#[test]
fn a_peer_that_stops_reading_makes_the_core_exit() {
    // Replies pile up past the pipe and the bounded queue: the core exits
    // instead of buffering without limit, and releases its gate.
    let (_root, data, locks) = dirs();
    let mut core = Command::new(BIN)
        .args(["serve", "--data-dir"])
        .arg(&data)
        .arg("--lock-dir")
        .arg(&locks)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = core.stdin.take().unwrap();
    let hello = frame(&request(
        1,
        "core.hello",
        json!({ "protocol": 1, "shell_version": "t", "auto_lock_ms": 0 }),
    ));
    let burst: Vec<u8> = hello
        .into_iter()
        .chain((2..5002u64).flat_map(|id| frame(&request(id, "vault.status", json!({})))))
        .collect();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&burst);
        stdin
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let code = loop {
        if let Some(status) = core.try_wait().unwrap() {
            break status.code();
        }
        assert!(Instant::now() < deadline, "core kept buffering");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(code, Some(76));
    drop(writer);
    let mut next = spawn("serve", &data, &locks, &[]);
    assert_eq!(next.hello()["result"]["protocol"], 1);
}

#[test]
fn eof_exits_cleanly() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

#[test]
fn one_core_per_identity_dir() {
    let (_root, data, locks) = dirs();
    let mut first = spawn("serve", &data, &locks, &[]);
    first.hello();
    let mut second = spawn("serve", &data, &locks, &[]);
    assert_eq!(second.exit_code(Duration::from_secs(10)), 75);

    #[cfg(unix)]
    {
        // A symlink alias of the same directory shares the gate.
        let alias = data.parent().unwrap().join("alias");
        std::os::unix::fs::symlink(&data, &alias).unwrap();
        let mut third = spawn("serve", &alias, &locks, &[]);
        assert_eq!(third.exit_code(Duration::from_secs(10)), 75);
    }

    first.close_stdin();
    assert_eq!(first.exit_code(Duration::from_secs(5)), 0);
    let mut fourth = spawn("serve", &data, &locks, &[]);
    assert_eq!(fourth.hello()["result"]["protocol"], 1);
}

#[cfg(unix)]
#[test]
fn the_core_keeps_using_the_directory_it_locked() {
    // Retargeting a symlink after startup must not move the core to another
    // directory whose gate it doesn't hold.
    let (root, a, locks) = dirs();
    let b = root.path().join("b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(b.join("identity-vault.json"), b"B").unwrap();
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&a, &alias).unwrap();
    let mut core = spawn("serve", &alias, &locks, &[]);
    core.hello();
    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&b, &alias).unwrap();
    assert_eq!(
        core.call(2, "vault.status", json!({}))["result"]["exists"],
        false,
        "still reads A"
    );
}

#[test]
fn the_lock_dir_must_be_outside_the_identity_dir() {
    let (_root, data, _locks) = dirs();
    let mut inside = spawn("serve", &data, &data.join("locks"), &[]);
    assert_eq!(inside.exit_code(Duration::from_secs(10)), 74);
    let mut same = spawn("hold-lock", &data, &data, &[]);
    assert_eq!(same.exit_code(Duration::from_secs(10)), 74);
}

#[test]
fn hold_lock_survives_deleting_the_identity_dir() {
    let (_root, data, locks) = dirs();
    let mut holder = spawn("hold-lock", &data, &locks, &[]);
    assert_eq!(holder.line(), "locked");

    // Delete and recreate the identity directory while the gate is held, as
    // a profile reset does. A core still can't start: the gate lives outside.
    std::fs::remove_dir_all(&data).unwrap();
    std::fs::create_dir_all(&data).unwrap();
    let mut blocked = spawn("serve", &data, &locks, &[]);
    assert_eq!(blocked.exit_code(Duration::from_secs(10)), 75);

    holder.close_stdin();
    assert_eq!(holder.exit_code(Duration::from_secs(5)), 0);
    let mut core = spawn("serve", &data, &locks, &[]);
    assert_eq!(core.hello()["result"]["protocol"], 1);
}

#[test]
fn recover_takes_the_gate() {
    let (_root, data, locks) = dirs();
    let mut recover = spawn("recover", &data, &locks, &[]);
    assert_eq!(recover.line(), "recovered");
    assert_eq!(recover.exit_code(Duration::from_secs(5)), 0);
}

#[cfg(unix)]
#[test]
fn exits_when_the_parent_is_not_main() {
    // PID 1 is never the test's child's parent.
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &["--parent-pid", "1"]);
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

#[test]
fn usage_errors() {
    let status = Command::new(BIN)
        .arg("serve")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(64));
    let status = Command::new(BIN)
        .args(["frobnicate", "--data-dir", "/tmp", "--lock-dir", "/tmp"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(64));
}
