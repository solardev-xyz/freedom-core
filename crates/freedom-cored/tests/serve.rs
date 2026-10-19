//! Integration tests: the real binary, spoken to over its pipes. Every read
//! has a timeout and every child is killed and reaped on drop, so a
//! regression fails a test instead of hanging the suite.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::*;
use serde_json::json;
use sha2::{Digest, Sha256};

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
    assert_eq!(
        core.call(3, "core.shutdown", json!({}))["result"],
        json!({})
    );
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);

    // An existing vault: its fingerprint, and the bytes stay untouched.
    let vault = br#"{"version": 1}"#;
    std::fs::write(data.join("identity-vault.json"), vault).unwrap();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let status = core.call(2, "vault.status", json!({}));
    assert_eq!(status["result"]["exists"], true);
    let expected: String = Sha256::digest(vault)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(status["result"]["fingerprint"], expected);
    assert_eq!(
        std::fs::read(data.join("identity-vault.json")).unwrap(),
        vault
    );
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
    std::fs::create_dir_all(data.join("identity-vault.json")).unwrap();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
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
fn a_fifo_vault_does_not_stall_the_core() {
    // Status is a startup snapshot: a FIFO in place of the vault is refused
    // at startup without blocking, and the loop stays responsive.
    let (_root, data, locks) = dirs();
    std::fs::create_dir_all(&data).unwrap();
    let status = Command::new("mkfifo")
        .arg(data.join("identity-vault.json"))
        .status()
        .unwrap();
    assert!(status.success());
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
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
fn a_peer_that_stops_reading_gets_backpressure_then_an_exit() {
    // Replies pile up past the pipe and the loop's allowance: the core stops
    // taking requests, so its reader stops reading and main's writes back
    // up. Only once the writer has written nothing for the stall bound
    // (30 s, 3 s here) does it exit, and release its gate.
    let (_root, data, locks) = dirs();
    let mut core = spawn_env(
        "serve",
        &data,
        &locks,
        &[],
        &[("FREEDOM_CORED_TEST_STALL_MS", "3000")],
    );
    core.hello();
    core.pause_reading();
    let burst: Vec<u8> = (2..5002u64)
        .flat_map(|id| frame(&request(id, "vault.status", json!({}))))
        .collect();
    let started = Instant::now();
    let writer = core.send_in_background(burst);
    // Within the bound: alive, and not reading what main writes.
    std::thread::sleep(Duration::from_millis(1000));
    assert!(core.child.try_wait().unwrap().is_none(), "exited early");
    assert!(!writer.is_finished(), "the core kept reading");
    assert_eq!(core.exit_code(Duration::from_secs(20)), 76);
    assert!(started.elapsed() >= Duration::from_secs(3));
    assert!(core.stderr().contains("main is not reading replies"));
    drop(writer.join().unwrap());
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

/// #84: `flock` works on a read-only handle, so another local user who can
/// open the lock file can hold the gate and keep the core from starting.
/// The lock and identity directories are private (`0700`), the lock file
/// `0600`; what an earlier build or the umask left wider is tightened.
#[cfg(unix)]
#[test]
fn the_gate_is_private_to_the_user() {
    use std::os::unix::fs::PermissionsExt;
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
    let set = |path: &std::path::Path, mode: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    let lock_file = |locks: &std::path::Path| {
        let entries: Vec<_> = std::fs::read_dir(locks)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 1, "{entries:?}");
        entries[0].clone()
    };

    let (_root, data, locks) = dirs();
    let mut holder = spawn("hold-lock", &data, &locks, &[]);
    assert_eq!(holder.line(), "locked");
    assert_eq!(mode(&data), 0o700);
    assert_eq!(mode(&locks), 0o700);
    assert_eq!(mode(&lock_file(&locks)), 0o600);
    holder.close_stdin();
    assert_eq!(holder.exit_code(Duration::from_secs(5)), 0);

    // As an earlier build and the default umask left them.
    set(&data, 0o755);
    set(&locks, 0o755);
    set(&lock_file(&locks), 0o644);
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    assert_eq!(mode(&data), 0o700);
    assert_eq!(mode(&locks), 0o700);
    assert_eq!(mode(&lock_file(&locks)), 0o600);
}

/// A symlink in the lock file's place is never followed: the core refuses
/// to start (74), and the file it points to is untouched.
#[cfg(unix)]
#[test]
fn a_symlinked_lock_file_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let (root, data, locks) = dirs();
    let mut holder = spawn("hold-lock", &data, &locks, &[]);
    assert_eq!(holder.line(), "locked");
    holder.close_stdin();
    assert_eq!(holder.exit_code(Duration::from_secs(5)), 0);
    let lock = std::fs::read_dir(&locks)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::remove_file(&lock).unwrap();
    let elsewhere = root.path().join("elsewhere");
    std::fs::write(&elsewhere, b"").unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &lock).unwrap();
    let mut core = spawn("serve", &data, &locks, &[]);
    assert_eq!(core.exit_code(Duration::from_secs(10)), 74);
    assert_eq!(
        std::fs::metadata(&elsewhere).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

/// Someone else's lock directory is refused (74). Only root can make one,
/// so elsewhere this checks nothing.
#[cfg(unix)]
#[test]
fn a_lock_dir_of_another_user_is_refused() {
    if !running_as_root() {
        return;
    }
    let (_root, data, locks) = dirs();
    std::fs::create_dir_all(&locks).unwrap();
    // Some sandboxes map no UID 65534 (EINVAL): nothing to check there.
    if std::os::unix::fs::chown(&locks, Some(65534), None).is_err() {
        return;
    }
    let mut core = spawn("serve", &data, &locks, &[]);
    assert_eq!(core.exit_code(Duration::from_secs(10)), 74);
}

#[cfg(unix)]
fn running_as_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    // The test's own files are owned by whoever runs it.
    let probe = tempfile::tempdir().unwrap();
    std::fs::metadata(probe.path()).unwrap().uid() == 0
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

const SLOW_SNAPSHOT: (&str, &str) = ("FREEDOM_CORED_TEST_SNAPSHOT_DELAY_MS", "30000");

#[test]
fn slow_storage_at_startup_does_not_block_eof() {
    let (_root, data, locks) = dirs();
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("identity-vault.json"), b"{}").unwrap();
    let mut core = spawn_env("serve", &data, &locks, &[], &[SLOW_SNAPSHOT]);
    std::thread::sleep(Duration::from_millis(300));
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(3)), 0);
}

#[test]
fn slow_storage_at_startup_is_bounded_by_the_hello_deadline() {
    let (_root, data, locks) = dirs();
    let started = Instant::now();
    let mut core = spawn_env(
        "serve",
        &data,
        &locks,
        &["--hello-timeout-ms", "1000"],
        &[SLOW_SNAPSHOT],
    );
    core.send(&request(
        1,
        "core.hello",
        json!({ "protocol": 1, "shell_version": "test", "auto_lock_ms": 900000 }),
    ));
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[test]
fn hello_waits_for_the_snapshot() {
    let (_root, data, locks) = dirs();
    let mut core = spawn_env(
        "serve",
        &data,
        &locks,
        &[],
        &[("FREEDOM_CORED_TEST_SNAPSHOT_DELAY_MS", "500")],
    );
    let hello = core.hello();
    assert_eq!(hello["result"]["protocol"], 1);
    assert_eq!(
        core.call(2, "vault.status", json!({}))["result"]["exists"],
        false
    );
}
