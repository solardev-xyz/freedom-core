//! Confinement through the binary (design 0014, "Confinement"; COL-4):
//! once confined, the process can't open a socket or reach a file outside
//! its grant, from the main thread or the verifier thread, and a private or
//! checkpoint process is granted no file at all. Each is checked where
//! `hello` reports the property enforced (Linux with Landlock and seccomp,
//! macOS); elsewhere the report itself is checked.

// Test code: a failed setup ends the test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::process::Command;
use std::time::Duration;

use common::{BIN, Colibrid, Dirs};
use serde_json::{Value, json};

/// The probes' log lines: (message, thread) → whether the probe could.
fn probes(stderr: &str) -> Vec<(String, String, bool)> {
    stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|line| line["msg"].as_str().is_some_and(|m| m.starts_with("test ")))
        .map(|line| {
            (
                line["msg"].as_str().unwrap().to_owned(),
                line["thread"].as_str().unwrap().to_owned(),
                line["ok"].as_bool().unwrap(),
            )
        })
        .collect()
}

/// Spawns `args` with the probes set, runs one request so the verifier
/// thread starts, and returns `hello` and the probes.
fn probed(
    args: &[&str],
    canary: &std::path::Path,
    write: &std::path::Path,
) -> (Value, Vec<(String, String, bool)>) {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .env("FREEDOM_COLIBRID_TEST_CANARY", canary)
        .env("FREEDOM_COLIBRID_TEST_WRITE", write)
        .env("FREEDOM_COLIBRID_TEST_SOCKET", "1");
    let mut colibrid = Colibrid::spawn(command);
    let hello = colibrid.hello();
    colibrid.request("colibri.stats", json!({}));
    let _ = colibrid.recv(Duration::from_secs(10));
    colibrid.close_stdin();
    assert!(colibrid.exit_code(Duration::from_secs(20)).is_some());
    std::thread::sleep(Duration::from_millis(200));
    (hello, probes(&colibrid.stderr()))
}

fn check(hello: &Value, probes: &[(String, String, bool)], write_allowed: bool) {
    let confinement = &hello["confinement"];
    assert!(confinement.is_object(), "{hello}");
    for thread in ["main", "verifier"] {
        for probe in ["test canary", "test write", "test socket"] {
            let ok = probes
                .iter()
                .find(|(m, t, _)| m == probe && t == thread)
                .map(|(_, _, ok)| *ok)
                .unwrap_or_else(|| panic!("no {probe} from {thread}: {probes:?}"));
            let enforced = match probe {
                "test socket" => confinement["network"] == "enforced",
                _ => confinement["files"] == "enforced",
            };
            if enforced {
                let expected = probe == "test write" && write_allowed;
                assert_eq!(ok, expected, "{probe} from {thread}: {confinement}");
            }
        }
    }
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        assert_eq!(confinement["network"], "enforced", "{confinement}");
    }
    // Files are enforced on macOS, and on Linux wherever the kernel has
    // Landlock (the CI runners' have): then the file probes above ran.
    if files_enforceable() {
        assert_eq!(confinement["files"], "enforced", "{confinement}");
    }
}

/// Whether this host can enforce file confinement: macOS always, Linux with
/// Landlock among its security modules.
fn files_enforceable() -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    if cfg!(target_os = "linux") {
        return std::fs::read_to_string("/sys/kernel/security/lsm")
            .is_ok_and(|lsm| lsm.split(',').any(|m| m.trim() == "landlock"));
    }
    false
}

#[test]
fn a_persistent_process_reaches_its_directory_alone() {
    let dirs = Dirs::new("confined");
    let outside = Dirs::new("outside");
    let canary = outside.root.join("canary");
    std::fs::write(&canary, b"secret").unwrap();
    let (hello, probes) = probed(
        &[
            "serve",
            "--chain",
            "1",
            "--data-dir",
            dirs.data().to_str().unwrap(),
            "--lock-dir",
            dirs.lock().to_str().unwrap(),
        ],
        &canary,
        &outside.root.join("written"),
    );
    check(&hello, &probes, false);
    // Inside its grant it writes: the probe's file in the chain's
    // directory.
    let (hello, probes) = probed(
        &[
            "serve",
            "--chain",
            "1",
            "--data-dir",
            dirs.data().to_str().unwrap(),
            "--lock-dir",
            dirs.lock().to_str().unwrap(),
        ],
        &canary,
        &dirs.data().join("written"),
    );
    check(&hello, &probes, true);
}

#[test]
fn private_and_checkpoint_processes_are_granted_no_file() {
    let outside = Dirs::new("private");
    let canary = outside.root.join("canary");
    std::fs::write(&canary, b"secret").unwrap();
    for args in [
        &["serve", "--chain", "1"][..],
        &["checkpoint", "--chain", "1"],
    ] {
        let (hello, probes) = probed(args, &canary, &outside.data().join("written"));
        check(&hello, &probes, false);
    }
}
