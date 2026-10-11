//! Integration tests: the real binary, spoken to over its pipes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_freedom-cored");

struct Core {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
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
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take();
    let stdout = child.stdout.take().unwrap();
    Core {
        child,
        stdin,
        stdout,
    }
}

impl Core {
    fn send(&mut self, message: &Value) {
        let payload = serde_json::to_vec(message).unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&u32::try_from(payload.len() + 1).unwrap().to_be_bytes());
        frame.push(1);
        frame.extend_from_slice(&payload);
        self.stdin.as_mut().unwrap().write_all(&frame).unwrap();
        self.stdin.as_mut().unwrap().flush().unwrap();
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        self.stdin.as_mut().unwrap().write_all(bytes).unwrap();
        self.stdin.as_mut().unwrap().flush().unwrap();
    }

    fn recv(&mut self) -> Value {
        let mut header = [0u8; 5];
        self.stdout.read_exact(&mut header).unwrap();
        assert_eq!(header[4], 1, "JSON frame");
        let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize - 1;
        let mut payload = vec![0u8; len];
        self.stdout.read_exact(&mut payload).unwrap();
        serde_json::from_slice(&payload).unwrap()
    }

    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(&json!({ "type": "request", "id": id, "method": method, "params": params, "context": { "caller": "chrome" } }));
        let response = self.recv();
        assert_eq!(response["type"], "response");
        assert_eq!(response["id"], id);
        response
    }

    fn hello(&mut self) -> Value {
        self.request(
            1,
            "core.hello",
            json!({ "protocol": 1, "shell_version": "test", "auto_lock_ms": 900000 }),
        )
    }

    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    fn exit_code(mut self, within: Duration) -> i32 {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code().unwrap_or(-1);
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("core did not exit within {within:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn dirs() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
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

    let status = core.request(2, "vault.status", json!({}));
    assert_eq!(
        status["result"],
        json!({ "exists": false, "unlocked": false, "epoch": null, "fingerprint": null })
    );

    let vault = br#"{"version": 1}"#;
    std::fs::write(data.join("identity-vault.json"), vault).unwrap();
    let status = core.request(3, "vault.status", json!({}));
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

    let shutdown = core.request(4, "core.shutdown", json!({}));
    assert_eq!(shutdown["result"], json!({}));
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

#[test]
fn errors_are_typed() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let unknown = core.request(2, "vault.nope", json!({}));
    assert_eq!(unknown["error"]["code"], "unknown_method");
    core.send(&json!({ "type": "request", "id": 3, "method": "vault.status", "params": {},
        "context": { "caller": "page", "page": { "origin": "https://a", "top_origin": "https://a", "frame": 1, "navigation": 1 } } }));
    let forbidden = core.recv();
    assert_eq!(forbidden["error"]["code"], "forbidden");
    let again = core.hello();
    assert_eq!(again["error"]["code"], "invalid_argument");
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

#[test]
fn handshake_rules() {
    // The first message must be core.hello.
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.send(&json!({ "type": "request", "id": 1, "method": "vault.status", "params": {}, "context": { "caller": "chrome" } }));
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);

    // A protocol mismatch is answered, then the core exits.
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    let reply = core.request(
        1,
        "core.hello",
        json!({ "protocol": 2, "shell_version": "t", "auto_lock_ms": 0 }),
    );
    assert_eq!(reply["error"]["code"], "protocol_mismatch");
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);

    // No hello within the deadline.
    let (_root, data, locks) = dirs();
    let core = spawn("serve", &data, &locks, &["--hello-timeout-ms", "300"]);
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);
}

#[test]
fn malformed_input_closes_the_connection() {
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
}

#[test]
fn a_burst_beyond_the_decoder_budget_is_fully_served() {
    // 200 requests in one write: more than the decoder holds at once, so the
    // reader must keep feeding it after popping (backpressure, no drops).
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let mut burst = Vec::new();
    for id in 2..202u64 {
        let payload = serde_json::to_vec(
            &json!({ "type": "request", "id": id, "method": "vault.status",
            "params": {}, "context": { "caller": "chrome" } }),
        )
        .unwrap();
        burst.extend_from_slice(&u32::try_from(payload.len() + 1).unwrap().to_be_bytes());
        burst.push(1);
        burst.extend_from_slice(&payload);
    }
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
    let second = spawn("serve", &data, &locks, &[]);
    assert_eq!(second.exit_code(Duration::from_secs(10)), 75);

    // A symlink alias of the same directory shares the gate.
    #[cfg(unix)]
    {
        let alias = data.parent().unwrap().join("alias");
        std::os::unix::fs::symlink(&data, &alias).unwrap();
        let third = spawn("serve", &alias, &locks, &[]);
        assert_eq!(third.exit_code(Duration::from_secs(10)), 75);
    }

    first.close_stdin();
    assert_eq!(first.exit_code(Duration::from_secs(5)), 0);
    let mut fourth = spawn("serve", &data, &locks, &[]);
    assert_eq!(fourth.hello()["result"]["protocol"], 1);
}

#[test]
fn hold_lock_survives_deleting_the_identity_dir() {
    let (_root, data, locks) = dirs();
    let mut holder = spawn("hold-lock", &data, &locks, &[]);
    let mut line = String::new();
    BufReader::new(&mut holder.stdout)
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "locked\n");

    // Delete and recreate the identity directory while the gate is held, as
    // a profile reset does. A core still can't start: the gate lives outside.
    std::fs::remove_dir_all(&data).unwrap();
    std::fs::create_dir_all(&data).unwrap();
    let blocked = spawn("serve", &data, &locks, &[]);
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
    let mut line = String::new();
    BufReader::new(&mut recover.stdout)
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "recovered\n");
    assert_eq!(recover.exit_code(Duration::from_secs(5)), 0);
}

#[cfg(unix)]
#[test]
fn exits_when_the_parent_is_not_main() {
    // PID 1 is never the test's child's parent.
    let (_root, data, locks) = dirs();
    let core = spawn("serve", &data, &locks, &["--parent-pid", "1"]);
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
        .arg("frobnicate")
        .arg("--data-dir")
        .arg("/tmp")
        .arg("--lock-dir")
        .arg("/tmp")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(64));
}
