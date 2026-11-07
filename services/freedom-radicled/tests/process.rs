//! The process through the real binary (design 0008, "Spawn and lock",
//! "Start, stop and reconciliation" and "Keys"): the gate and `hold-lock`,
//! the environment, the handshake, `rad.identity`, and the order the
//! process starts in.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};

#[test]
fn hello_names_this_starts_recipient_and_the_libradicle_it_links() {
    let dirs = Dirs::new();
    let mut a = Radicled::serve(&dirs, &[]);
    let hello = a.hello();
    let result = &hello["result"];
    assert_eq!(result["protocol"], 1);
    assert_eq!(result["service_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        result["libradicle"],
        json!({ "version": "0.8.0", "git_commit": "216ced6dddccd7cb1103b2cfda238936cd618897" })
    );
    let recipient = STANDARD
        .decode(result["recipient"].as_str().unwrap())
        .unwrap();
    assert_eq!(recipient.len(), 32);
    // The policy as passed, and what confinement it got (design 0010).
    assert_eq!(result["network"], json!({ "mode": "direct" }));
    let confinement = &result["confinement"];
    #[cfg(target_os = "linux")]
    if let Ok(abi) = fc_sys::linux::landlock_abi() {
        let abi = abi.min(9);
        // The ABI the kernel offers: no silent downgrade.
        assert_eq!(
            confinement["mechanism"],
            format!("landlock-{abi}+seccomp"),
            "{confinement}"
        );
        // `refer` needs ABI 2; below it files are unavailable.
        let files = if abi >= 2 { "enforced" } else { "unavailable" };
        assert_eq!(confinement["files"], files, "{confinement}");
        assert_eq!(confinement["exec"], "enforced", "{confinement}");
    }
    // Windows, step 1: the job and each mitigation, read back.
    if cfg!(windows) {
        assert_eq!(confinement["mechanism"], "job", "{confinement}");
        assert_eq!(confinement["exec"], "partial", "{confinement}");
        assert_eq!(confinement["files"], "unavailable", "{confinement}");
        assert_eq!(
            confinement["mitigations"],
            json!({ "dynamic_code": "set", "image_load": "set", "extension_points": "set" }),
            "{confinement}"
        );
    }
    assert!(confinement.is_object(), "{confinement}");
    a.close_stdin();
    assert_eq!(a.exit_code(EXIT_TIMEOUT), Some(0));
    // A new start, a new key.
    let mut b = Radicled::serve(&dirs, &[]);
    assert_ne!(
        b.hello()["result"]["recipient"],
        hello["result"]["recipient"]
    );
}

/// The sealed key, end to end: sealed to this start's recipient, opened
/// once, and the node's identity is the key's. Nothing is written under the
/// home's `keys/`, and no log line carries the key.
#[test]
fn a_sealed_key_gives_the_nodes_identity() {
    let dirs = Dirs::new();
    let mut radicled = Radicled::serve(&dirs, &[]);
    let hello = radicled.hello();
    let params = sealed_to(&hello, &SEED);
    let identity = radicled.call("rad.identity", params.clone());
    assert_eq!(
        identity["result"],
        json!({ "did": format!("did:key:{NID}"), "nid": NID, "ephemeral": false }),
        "{identity}"
    );
    // A second rad.identity: invalid_argument, and the process ends.
    let again = radicled.call("rad.identity", json!({ "ephemeral": true }));
    assert_eq!(again["error"]["code"], "invalid_argument", "{again}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    let seed_hex: String = SEED.iter().map(|b| format!("{b:02x}")).collect();
    for secret in [
        seed_hex.as_str(),
        params["sealed"]["ciphertext"].as_str().unwrap(),
        params["sealed"]["enc"].as_str().unwrap(),
    ] {
        assert!(!log.contains(secret), "the log carries {secret}");
    }
    assert!(!dirs.home.join("keys").exists());
}

#[test]
fn a_profile_without_a_vault_gets_a_throwaway_key_each_start() {
    let dirs = Dirs::new();
    let mut nids = Vec::new();
    for _ in 0..2 {
        let mut radicled = Radicled::serve(&dirs, &[]);
        radicled.hello();
        let identity = radicled.call("rad.identity", json!({ "ephemeral": true }));
        assert_eq!(identity["result"]["ephemeral"], true, "{identity}");
        nids.push(identity["result"]["nid"].as_str().unwrap().to_owned());
        radicled.close_stdin();
        assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    }
    assert_ne!(nids[0], nids[1]);
    assert!(!dirs.home.join("keys").exists());
}

/// Every failed start step answers, then the process ends: exit 0, since
/// main read the error.
#[test]
fn a_failed_identity_answers_then_the_process_ends() {
    // A ciphertext sealed to another start's key.
    let dirs = Dirs::new();
    let mut earlier = Radicled::serve(&dirs, &[]);
    let earlier_hello = earlier.hello();
    earlier.close_stdin();
    assert_eq!(earlier.exit_code(EXIT_TIMEOUT), Some(0));
    let mut radicled = Radicled::serve(&dirs, &[]);
    radicled.hello();
    let reply = radicled.call("rad.identity", sealed_to(&earlier_hello, &SEED));
    assert_eq!(reply["error"]["code"], "bad_sealed_key", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));

    // Neither form.
    let mut radicled = Radicled::serve(&dirs, &[]);
    radicled.hello();
    let reply = radicled.call("rad.identity", json!({ "ephemeral": false }));
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

/// A key file left by an earlier build refuses the start before anything
/// opens: main runs the switch, then starts again.
#[test]
fn a_key_file_refuses_the_start() {
    let dirs = Dirs::new();
    std::fs::create_dir_all(dirs.home.join("keys")).unwrap();
    std::fs::write(dirs.home.join("keys").join("radicle"), b"an old key file").unwrap();
    for params in [None, Some(json!({ "ephemeral": true }))] {
        let mut radicled = Radicled::serve(&dirs, &[]);
        let hello = radicled.hello();
        let params = params.unwrap_or_else(|| sealed_to(&hello, &SEED));
        let reply = radicled.call("rad.identity", params);
        assert_eq!(reply["error"]["code"], "key_file_present", "{reply}");
        assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    }
}

/// Before `rad.identity`, the steps that need the identity end the process;
/// `rad.stats` is answered (tests/stats.rs); every other method 0008 lists
/// is `stopped` (no node runs), and a method 0008 doesn't list is
/// `unknown_method`. `rad.start` itself is tests/start.rs's.
#[test]
fn methods_before_running() {
    let dirs = Dirs::new();
    let mut radicled = Radicled::serve(&dirs, &[]);
    radicled.hello();
    let reply = radicled.call("rad.stats", json!({}));
    assert_eq!(reply["result"]["node"], "waiting", "{reply}");
    for method in [
        "rad.read",
        "rad.blob",
        "rad.quarantine_list",
        "rad.remove_repo",
        "rad.connect_seeds",
        "rad.clone",
        "rad.unseed",
        "rad.write",
        "rad.import_repo",
    ] {
        let reply = radicled.call(method, json!({}));
        assert_eq!(reply["error"]["code"], "stopped", "{method}: {reply}");
    }
    let reply = radicled.call("rad.other", json!({}));
    assert_eq!(reply["error"]["code"], "unknown_method", "{reply}");
    let reply = radicled.call("rad.start", json!({ "alias": "x" }));
    assert_eq!(reply["error"]["code"], "no_identity", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));

    let mut radicled = Radicled::serve(&dirs, &[]);
    radicled.hello();
    let reply = radicled.call("rad.reconcile", json!({}));
    assert_eq!(reply["error"]["code"], "no_identity", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));

    // With the identity, the home reconciles, and the methods are still
    // `stopped`.
    let mut radicled = Radicled::serve(&dirs, &[]);
    radicled.hello();
    radicled.call("rad.identity", json!({ "ephemeral": true }));
    let reply = radicled.call("rad.reconcile", json!({}));
    assert_eq!(reply["result"]["was_dirty"], false, "{reply}");
    let reply = radicled.call("rad.read", json!({}));
    assert_eq!(reply["error"]["code"], "stopped", "{reply}");
}

/// No `rad.identity` within its deadline after `rad.hello`'s reply: the
/// process ends, as for a missed handshake (76). One that came in time
/// disarms it.
#[test]
fn rad_identity_has_a_deadline() {
    let dirs = Dirs::new();
    let short = [("FREEDOM_RADICLED_TEST_IDENTITY_DEADLINE_MS", "300")];
    let mut late = Radicled::serve(&dirs, &short);
    late.hello();
    assert_eq!(late.exit_code(EXIT_TIMEOUT), Some(76));
    assert!(late.stderr().contains("identity_deadline"));

    let mut in_time = Radicled::serve(&dirs, &short);
    in_time.hello();
    in_time.call("rad.identity", json!({ "ephemeral": true }));
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(
        in_time.exit_code(Duration::ZERO),
        None,
        "it outlived the deadline"
    );
    in_time.close_stdin();
    assert_eq!(in_time.exit_code(EXIT_TIMEOUT), Some(0));
}

/// The gate: `hold-lock` holds it, and while it does, `serve` and another
/// `hold-lock` give up after 0001's 5 s with 75. A running service holds it
/// too.
#[test]
fn the_gate_keeps_one_owner_per_home() {
    let dirs = Dirs::new();
    let mut hold = HoldLock::spawn(&dirs);
    assert_eq!(hold.line(), "locked");
    let mut serve = Radicled::serve(&dirs, &[]);
    let mut second = HoldLock::spawn(&dirs);
    assert_eq!(serve.exit_code(EXIT_TIMEOUT), Some(75));
    assert_eq!(second.exit_code(EXIT_TIMEOUT), Some(75));
    hold.release();
    assert_eq!(hold.exit_code(EXIT_TIMEOUT), Some(0));

    let mut serve = Radicled::serve(&dirs, &[]);
    serve.hello();
    let mut other = Radicled::serve(&dirs, &[]);
    let mut hold = HoldLock::spawn(&dirs);
    assert_eq!(other.exit_code(EXIT_TIMEOUT), Some(75));
    assert_eq!(hold.exit_code(EXIT_TIMEOUT), Some(75));
    serve.close_stdin();
    assert_eq!(serve.exit_code(EXIT_TIMEOUT), Some(0));
    // The lock file is keyed by the canonical home.
    let names: Vec<String> = std::fs::read_dir(&dirs.locks)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
    assert!(names[0].starts_with("radicle-") && names[0].ends_with(".lock"));
}

/// What heartwood, libgit2 or systemd would read refuses the start (64),
/// as does a missing `HOME`; nothing is opened, the gate included.
#[test]
fn an_environment_main_should_have_cleared_refuses_the_start() {
    let dirs = Dirs::new();
    for (name, value) in [
        ("RAD_SOCKET", "/tmp/x"),
        ("RAD_KEYGEN_SEED", "00"),
        ("GIT_COMMITTER_DATE", "1"),
        ("SSH_AUTH_SOCK", "/tmp/agent"),
        ("LISTEN_FDS", "1"),
        ("XDG_CONFIG_HOME", "/tmp"),
    ] {
        let mut radicled = Radicled::serve(&dirs, &[(name, value)]);
        assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(64), "{name}");
        assert!(
            !radicled.stderr().contains(value),
            "{name}'s value is logged"
        );
    }
    let mut command = std::process::Command::new(BIN);
    command
        .arg("serve")
        .arg("--home")
        .arg(&dirs.home)
        .arg("--lock-dir")
        .arg(&dirs.locks)
        .args(["--network", "direct"])
        .env_clear();
    let mut radicled = Radicled::spawn(command);
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(64));
    assert!(!dirs.locks.exists(), "the gate was touched");
}

/// The confinement point (design 0010's seam) is reached while the process
/// has one thread: after the gate, before logging's writer and the
/// connection's threads.
#[cfg(target_os = "linux")]
#[test]
fn the_confinement_point_is_single_threaded() {
    let dirs = Dirs::new();
    let mut radicled = Radicled::serve(&dirs, &[("FREEDOM_RADICLED_TEST_THREADS", "1")]);
    radicled.hello();
    radicled.close_stdin();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    let line = log
        .lines()
        .find(|line| line.contains("confinement point"))
        .unwrap_or_else(|| panic!("no confinement point in {log}"));
    let line: Value = serde_json::from_str(line).unwrap();
    assert_eq!(line["threads"], 1, "{line}");
    // stdio and the lock: nothing else crosses confinement.
    let descriptors = line["descriptors"].as_array().unwrap();
    assert!(
        descriptors.len() == 1 && descriptors[0].as_str().unwrap().ends_with(".lock"),
        "{line}"
    );
}

/// libgit2's object cache is off before anything reads (0008, "Pools and
/// budgets"; review of #277, round 2): a tree looked up twice in a
/// repository in memory is two objects, so nothing a walk loads outlives
/// it. The probe sees the cache on in a process that hasn't turned it off
/// (the unit test `reads::tests::the_probe_sees_the_object_cache`).
#[test]
fn libgit2s_object_cache_is_off() {
    let dirs = Dirs::new();
    let mut radicled = Radicled::serve(&dirs, &[("FREEDOM_RADICLED_TEST_OBJECT_CACHE", "1")]);
    radicled.hello();
    radicled.close_stdin();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    let line = log
        .lines()
        .find(|line| line.contains("libgit2's object cache"))
        .unwrap_or_else(|| panic!("no probe in {log}"));
    let line: Value = serde_json::from_str(line).unwrap();
    assert_eq!(line["on"], false, "{line}");
}

/// Under `socks5`, `rad.hello` reports the policy as passed.
#[test]
fn hello_reports_a_socks5_policy() {
    let dirs = Dirs::new();
    let mut radicled = Radicled::serve_on(&dirs, "socks5:[::1]:9150", &[]);
    let hello = radicled.hello();
    assert_eq!(
        hello["result"]["network"],
        json!({ "mode": "socks5", "ip": "::1", "port": 9150 })
    );
    radicled.close_stdin();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

#[test]
fn stdin_eof_ends_the_process() {
    let dirs = Dirs::new();
    let mut radicled = Radicled::serve(&dirs, &[]);
    radicled.close_stdin();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

#[test]
fn usage_errors_exit_64() {
    let dirs = Dirs::new();
    for args in [
        vec!["serve"],
        vec!["serve", "--home"],
        vec!["start"],
        vec!["serve", "--network", "direct"],
        // `--network`: required, and each form it refuses.
        vec!["serve", "--home", "h", "--lock-dir", "l"],
        vec![
            "serve",
            "--home",
            "h",
            "--lock-dir",
            "l",
            "--network",
            "socks5:localhost:9150",
        ],
        vec![
            "serve",
            "--home",
            "h",
            "--lock-dir",
            "l",
            "--network",
            "socks5:::1:9150",
        ],
        vec![
            "serve",
            "--home",
            "h",
            "--lock-dir",
            "l",
            "--network",
            "socks5:127.0.0.1:0",
        ],
    ] {
        let mut command = std::process::Command::new(BIN);
        command.args(&args);
        environment(&mut command, &dirs, &[]);
        let mut radicled = Radicled::spawn(command);
        assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(64), "{args:?}");
    }
}
