//! The process through its pipes (design 0007, "Process model"): the
//! command line, the lifetime lock and `hold-lock`, the handshake,
//! `ipfs.shutdown`, stdin EOF, parent death and the panic hook.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;
#[cfg(feature = "testhooks")]
use std::time::Instant;

use common::*;
use serde_json::json;

#[test]
fn usage_errors_exit_64() {
    let cases: [&[&str]; 15] = [
        &[],
        &["serve"],
        &["serve", "--data-dir", "d"],
        &["serve", "--ephemeral", "--data-dir", "d", "--lock-dir", "l"],
        &["hold-lock", "--ephemeral"],
        &[
            "serve",
            "--ephemeral",
            "--network",
            "direct",
            "--parent-pid",
            "x",
        ],
        &["frobnicate", "--data-dir", "d", "--lock-dir", "l"],
        // `--network`: required, and each form it refuses (0007, "Spawn"):
        // a name, a zone, shorthand, IPv6 without brackets, port 0.
        &["serve", "--ephemeral"],
        &["serve", "--ephemeral", "--network", "socks5:localhost:9150"],
        &[
            "serve",
            "--ephemeral",
            "--network",
            "socks5:[fe80::1%eth0]:9150",
        ],
        &["serve", "--ephemeral", "--network", "socks5:127.1:9150"],
        &["serve", "--ephemeral", "--network", "socks5:::1:9150"],
        &["serve", "--ephemeral", "--network", "socks5:127.0.0.1:0"],
        &["serve", "--ephemeral", "--network", "tor"],
        &[
            "hold-lock",
            "--data-dir",
            "d",
            "--lock-dir",
            "l",
            "--network",
            "direct",
        ],
    ];
    for args in cases {
        assert_eq!(status(args), Some(64), "{args:?}");
    }
}

#[test]
fn the_gate_admits_one_owner() {
    let dirs = Dirs::new();
    let mut hold = HoldLock::spawn(&dirs);
    assert_eq!(hold.line(), "locked");
    // While hold-lock holds the gate, serve and another hold-lock give up
    // after 0001's 5 s of retries, with 75.
    let mut serve = Ipfsd::persistent(&dirs, &[]);
    let mut second = HoldLock::spawn(&dirs);
    assert_eq!(serve.exit_code(EXIT_TIMEOUT), Some(75));
    assert_eq!(second.exit_code(EXIT_TIMEOUT), Some(75));
    hold.release();
    assert_eq!(hold.exit_code(EXIT_TIMEOUT), Some(0));

    // Released: serve takes it, for its whole life.
    let mut serve = Ipfsd::persistent(&dirs, &[]);
    serve.hello();
    let lock_files: Vec<String> = std::fs::read_dir(&dirs.locks)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(lock_files.len(), 1, "{lock_files:?}");
    assert!(
        lock_files[0].starts_with("ipfs-") && lock_files[0].ends_with(".lock"),
        "{lock_files:?}"
    );
    let mut other = Ipfsd::persistent(&dirs, &[]);
    let mut hold = HoldLock::spawn(&dirs);
    assert_eq!(other.exit_code(EXIT_TIMEOUT), Some(75));
    assert_eq!(hold.exit_code(EXIT_TIMEOUT), Some(75));
    serve.shutdown();
    assert_eq!(serve.exit_code(EXIT_TIMEOUT), Some(0));

    // The ephemeral process takes no lock.
    let mut hold = HoldLock::spawn(&dirs);
    assert_eq!(hold.line(), "locked");
    let mut ephemeral = Ipfsd::ephemeral(&[]);
    ephemeral.hello();
    ephemeral.close_stdin();
    assert_eq!(ephemeral.exit_code(EXIT_TIMEOUT), Some(0));
    hold.release();
    assert_eq!(hold.exit_code(EXIT_TIMEOUT), Some(0));
}

#[test]
fn the_handshake() {
    let dirs = Dirs::new();
    let mut ipfsd = Ipfsd::persistent(&dirs, &[]);
    let hello = ipfsd.hello();
    let result = &hello["result"];
    assert_eq!(result["protocol"], 1);
    assert_eq!(result["service_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(result["freedom_ipfs"]["version"], "0.4.6");
    let commit = result["freedom_ipfs"]["git_commit"].as_str().unwrap();
    assert!(
        commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()),
        "{commit}"
    );
    assert_eq!(result["kind"], "persistent");
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));

    let mut ipfsd = Ipfsd::ephemeral(&[]);
    assert_eq!(ipfsd.hello()["result"]["kind"], "ephemeral");
    // A second hello is a protocol error.
    ipfsd.request(
        "ipfs.hello",
        json!({ "protocol": 1, "shell_version": "test", "frames": ["stream"] }),
    );
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(76));

    // Nothing before the handshake.
    let mut ipfsd = Ipfsd::ephemeral(&[]);
    ipfsd.request("ipfs.start", memory("e-1"));
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(76));

    // A mismatch is answered, then the process exits: a packaging bug.
    for params in [
        json!({ "protocol": 2, "shell_version": "test", "frames": ["stream"] }),
        json!({ "protocol": 1, "shell_version": "test", "frames": [] }),
    ] {
        let mut ipfsd = Ipfsd::ephemeral(&[]);
        let reply = ipfsd.call("ipfs.hello", params);
        assert_eq!(reply["error"]["code"], "protocol_mismatch", "{reply}");
        assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(76));
    }
}

#[test]
fn shutdown_tears_down_every_instance_then_exits_0() {
    let mut ipfsd = Ipfsd::ephemeral(&[]);
    ipfsd.hello();
    for instance in ["e-1", "e-2", "e-3"] {
        assert_eq!(
            ipfsd.start(memory(instance))["result"]["instance"],
            instance
        );
    }
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    // `ipfs.shutdown` has no reply: the process exits.
    assert!(ipfsd.stdout_closes_within(EXIT_TIMEOUT));
    assert_eq!(ipfsd.leftover(), Vec::<serde_json::Value>::new());
    let stderr = ipfsd.stderr();
    assert_eq!(
        stderr.matches("\"instance stopped\"").count(),
        3,
        "{stderr}"
    );
}

#[test]
fn stdin_eof_tears_down_and_exits_0() {
    let dirs = Dirs::new();
    let mut ipfsd = Ipfsd::persistent(&dirs, &[]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(disk("p-1"))["result"]["instance"], "p-1");
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    let stderr = ipfsd.stderr();
    assert!(stderr.contains("\"instance stopped\""), "{stderr}");
    // The service logs no path.
    let data = dirs.data.to_string_lossy();
    assert!(!stderr.contains(data.as_ref()), "{stderr}");
}

#[cfg(unix)]
#[test]
fn the_parent_s_death_ends_the_process() {
    // A shell stands in for main: it is freedom-ipfsd's parent, named by
    // `--parent-pid`, and hands it the test's pipes (its own stdin as the
    // background job's, which would otherwise be /dev/null).
    let mut command = std::process::Command::new("sh");
    command
        .arg("-c")
        .arg(
            r#"exec 3<&0; "$0" serve --ephemeral --network direct --parent-pid $$ <&3 3<&- & wait"#,
        )
        .arg(BIN);
    let mut ipfsd = Ipfsd::spawn(command, &[]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(memory("e-1"))["result"]["instance"], "e-1");
    // Main dies; stdin stays open, held by the test.
    ipfsd.child.kill().unwrap();
    ipfsd.child.wait().unwrap();
    // The service goes too (Linux: PR_SET_PDEATHSIG; elsewhere the 2 s
    // poll, then the teardown), so stdout closes.
    assert!(ipfsd.stdout_closes_within(Duration::from_secs(10)));
}

#[cfg(unix)]
#[test]
fn a_parent_already_gone_exits_at_once() {
    // PID 1 is never the test's child's parent.
    let mut command = std::process::Command::new(BIN);
    command.args([
        "serve",
        "--ephemeral",
        "--network",
        "direct",
        "--parent-pid",
        "1",
    ]);
    let mut ipfsd = Ipfsd::spawn(command, &[]);
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}

#[cfg(feature = "testhooks")]
#[test]
fn a_panic_in_the_service_s_own_work_exits_70_with_one_fixed_line() {
    let mut ipfsd = Ipfsd::ephemeral(&[("FREEDOM_IPFSD_TEST_PANIC", "start")]);
    ipfsd.hello();
    ipfsd.request("ipfs.start", memory("e-1"));
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(70));
    let stderr = ipfsd.stderr();
    assert!(stderr.contains("{\"panic\":\"control\"}\n"), "{stderr}");
    // Never the payload, its path, or Rust's default message.
    for leak in ["SECRET", "/home/user", "panicked at", "test panic"] {
        assert!(!stderr.contains(leak), "{leak}: {stderr}");
    }
}

#[cfg(feature = "testhooks")]
#[test]
fn shutdown_waits_for_quiescence() {
    let mut ipfsd = Ipfsd::ephemeral(&[("FREEDOM_IPFSD_TEST_HOLD_TEARDOWN_MS", "1500")]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(memory("e-1"))["result"]["instance"], "e-1");
    let sent = Instant::now();
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    // The exit waited for the instance's runtime to be joined.
    assert!(sent.elapsed() >= Duration::from_millis(1500));
}

#[cfg(feature = "testhooks")]
#[test]
fn eof_with_a_teardown_held_past_5_s_exits_70() {
    let mut ipfsd = Ipfsd::ephemeral(&[("FREEDOM_IPFSD_TEST_HOLD_TEARDOWN_MS", "8000")]);
    ipfsd.hello();
    assert_eq!(ipfsd.start(memory("e-1"))["result"]["instance"], "e-1");
    let closed = Instant::now();
    ipfsd.close_stdin();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(70));
    // Within the bound, never by the held job's end.
    let took = closed.elapsed();
    assert!(
        took >= Duration::from_secs(5) && took < Duration::from_secs(8),
        "{took:?}"
    );
    let stderr = ipfsd.stderr();
    assert!(stderr.contains("teardown_unproven"), "{stderr}");
    assert!(!stderr.contains("\"instance stopped\""), "{stderr}");
}
