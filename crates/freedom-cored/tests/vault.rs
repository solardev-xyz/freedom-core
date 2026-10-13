//! The vault methods through the real binary: lifecycle, JS parity strings,
//! lock semantics, throttling, auto-lock, and opening vaults written by
//! freedom-browser's JS.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};
use sha2::Digest;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn b64(s: &str) -> String {
    STANDARD.encode(s)
}

fn decoded(value: &Value) -> String {
    String::from_utf8(STANDARD.decode(value.as_str().unwrap()).unwrap()).unwrap()
}

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

#[test]
fn create_lock_unlock_export_change_delete() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();

    // Create: the phrase for backup display, the addresses, and unlocked.
    let created = core.call(
        2,
        "vault.create",
        json!({ "password_b64": b64("testpass1"), "words": 24 }),
    );
    let phrase = decoded(&created["result"]["mnemonic_b64"]);
    assert_eq!(phrase.split(' ').count(), 24);
    let user_wallet = created["result"]["addresses"]["user_wallet"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(user_wallet.starts_with("0x"));
    assert_eq!(core.event()["event"], "vault.unlocked");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(data.join("identity-vault.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "written with 0600");
    }

    let status = core.call(3, "vault.status", json!({}));
    assert_eq!(status["result"]["exists"], true);
    assert_eq!(status["result"]["unlocked"], true);

    let addresses = core.call(
        4,
        "keys.addresses",
        json!({ "accounts": [0, 1], "publishers": [0] }),
    );
    assert_eq!(
        addresses["result"]["user_wallets"][0]["address"],
        user_wallet
    );
    assert!(
        addresses["result"]["radicle"]["did"]
            .as_str()
            .unwrap()
            .starts_with("did:key:z6Mk")
    );

    // Lock: event, and every key is out of reach.
    assert_eq!(core.call(5, "vault.lock", json!({}))["result"], json!({}));
    let locked = core.event();
    assert_eq!(locked["event"], "vault.locked");
    assert_eq!(locked["data"]["reason"], "manual");
    let refused = core.call(6, "keys.addresses", json!({}));
    assert_eq!(refused["error"]["code"], "vault_locked");
    assert_eq!(refused["error"]["message"], "Vault is locked");

    // Unlock: a wrong password, then the right one.
    let wrong = core.call(
        7,
        "vault.unlock",
        json!({ "password_b64": b64("nope-nope") }),
    );
    assert_eq!(wrong["error"]["code"], "incorrect_password");
    assert_eq!(wrong["error"]["message"], "Incorrect password");
    let unlocked = core.call(
        8,
        "vault.unlock",
        json!({ "password_b64": b64("testpass1") }),
    );
    assert_eq!(unlocked["result"]["addresses"]["user_wallet"], user_wallet);
    assert_eq!(core.event()["event"], "vault.unlocked");

    // Exports and compat.
    let exported = core.call(
        9,
        "vault.export_mnemonic",
        json!({ "password_b64": b64("testpass1") }),
    );
    assert_eq!(decoded(&exported["result"]["mnemonic_b64"]), phrase);
    let forbidden = core.call(10, "compat.private_key", json!({ "account": 0 }));
    assert_eq!(forbidden["error"]["code"], "forbidden");
    let key = core.call_shell(11, "compat.private_key", json!({ "account": 0 }));
    let hex = key["result"]["private_key_hex"].as_str().unwrap();
    assert_eq!(hex.len(), 66);
    assert!(hex.starts_with("0x") && hex[2..].bytes().all(|b| b"0123456789abcdef".contains(&b)));

    // Change password: the lock state is unchanged (stays unlocked).
    let changed = core.call(
        12,
        "vault.change_password",
        json!({ "password_b64": b64("testpass1"), "new_password_b64": b64("testpass2") }),
    );
    assert_eq!(changed["result"], json!({}));
    assert_eq!(
        core.call(13, "vault.status", json!({}))["result"]["unlocked"],
        true
    );
    assert_eq!(
        core.call(
            14,
            "vault.verify_password",
            json!({ "password_b64": b64("testpass1") })
        )["error"]["code"],
        "incorrect_password"
    );
    assert_eq!(
        core.call(
            15,
            "vault.verify_password",
            json!({ "password_b64": b64("testpass2") })
        )["result"],
        json!({})
    );

    // Delete: locked, file gone.
    assert_eq!(
        core.call(
            16,
            "vault.delete",
            json!({ "password_b64": b64("testpass2") })
        )["result"],
        json!({})
    );
    let deleted = core.event();
    assert_eq!(deleted["data"]["reason"], "delete");
    assert!(!data.join("identity-vault.json").exists());
    assert_eq!(
        core.call(
            17,
            "vault.unlock",
            json!({ "password_b64": b64("testpass2") })
        )["error"]["message"],
        "No vault found. Create one first."
    );
    assert_eq!(
        core.call(
            18,
            "vault.verify_password",
            json!({ "password_b64": b64("testpass2") })
        )["error"]["message"],
        "No vault found"
    );
}

#[test]
fn import_and_parity_errors() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();

    let invalid = core.call(
        2,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64("not a phrase") }),
    );
    assert_eq!(invalid["error"]["message"], "Invalid mnemonic");
    let weak = core.call(
        3,
        "vault.import",
        json!({ "password_b64": b64("short"), "mnemonic_b64": b64(ABANDON) }),
    );
    assert_eq!(weak["error"]["code"], "weak_password");
    assert_eq!(
        weak["error"]["message"],
        "Password must be at least 8 characters"
    );

    let imported = core.call(
        4,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON) }),
    );
    assert_eq!(
        imported["result"]["addresses"]["user_wallet"],
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    );

    let again = core.call(
        5,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON) }),
    );
    assert_eq!(
        again["error"]["message"],
        "Vault already exists. Set overwrite=true to replace."
    );
    let create = core.call(
        6,
        "vault.create",
        json!({ "password_b64": b64("testpass1"), "words": 12 }),
    );
    assert_eq!(
        create["error"]["message"],
        "Vault already exists. Use importVault to replace."
    );
    let overwrite = core.call(7, "vault.import",
        json!({ "password_b64": b64("testpass9"), "mnemonic_b64": b64(ABANDON), "overwrite": true }));
    assert!(overwrite["result"]["addresses"].is_object());

    let generated = core.call(8, "keys.generate_mnemonic", json!({ "words": 15 }));
    assert_eq!(
        decoded(&generated["result"]["mnemonic_b64"])
            .split(' ')
            .count(),
        15
    );
    assert_eq!(
        core.call(
            9,
            "keys.validate_mnemonic",
            json!({ "mnemonic_b64": b64(ABANDON) })
        )["result"]["valid"],
        true
    );
    assert_eq!(
        core.call(10, "keys.generate_mnemonic", json!({ "words": 13 }))["error"]["code"],
        "invalid_argument"
    );
    // The well-known key of that address, in ethers' format.
    const KEY: &str = "0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727";
    let compat = core.call_shell(11, "compat.private_key", json!({ "account": 0 }));
    assert_eq!(compat["result"]["private_key_hex"], KEY);
    let exported = core.call(
        12,
        "vault.export_private_key",
        json!({ "password_b64": b64("testpass9"), "account": 0 }),
    );
    assert_eq!(exported["result"]["private_key_hex"], KEY);
}

#[test]
fn opens_vaults_written_by_the_js() {
    let fixtures: Value = serde_json::from_str(
        &std::fs::read_to_string(vectors().join("fixtures/vaults.json")).unwrap(),
    )
    .unwrap();
    let fixture = &fixtures["fixtures"][0];
    let (_root, data, locks) = dirs();
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(
        data.join("identity-vault.json"),
        fixture["fileContents"].as_str().unwrap(),
    )
    .unwrap();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let password = fixture["password"].as_str().unwrap();
    let unlocked = core.call(2, "vault.unlock", json!({ "password_b64": b64(password) }));
    assert!(unlocked["result"]["addresses"].is_object(), "{unlocked}");
    let exported = core.call(
        3,
        "vault.export_mnemonic",
        json!({ "password_b64": b64(password) }),
    );
    assert_eq!(
        decoded(&exported["result"]["mnemonic_b64"]),
        fixture["mnemonic"].as_str().unwrap()
    );
    // Opening never rewrites the file.
    assert_eq!(
        std::fs::read_to_string(data.join("identity-vault.json")).unwrap(),
        fixture["fileContents"].as_str().unwrap()
    );
}

#[test]
fn a_lock_revokes_an_unlock_in_flight() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    core.call(
        2,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON) }),
    );
    core.call(3, "vault.lock", json!({}));
    // Both frames in one write: the lock is handled while the unlock derives.
    let burst = [
        frame(&request(
            4,
            "vault.unlock",
            json!({ "password_b64": b64("testpass1") }),
        )),
        frame(&request(5, "vault.lock", json!({}))),
    ]
    .concat();
    core.send_raw(&burst);
    // The lock answers the revoked unlock at once, then itself.
    let unlock = core.response(4);
    assert_eq!(unlock["error"]["code"], "vault_locked", "{unlock}");
    assert_eq!(core.response(5)["result"], json!({}));
    assert_eq!(
        core.call(6, "vault.status", json!({}))["result"]["unlocked"],
        false
    );
}

#[test]
fn wrong_passwords_are_throttled() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    core.call(
        2,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON) }),
    );
    for id in 3..8 {
        let wrong = core.call(
            id,
            "vault.unlock",
            json!({ "password_b64": b64("wrong-password") }),
        );
        assert_eq!(wrong["error"]["code"], "incorrect_password");
    }
    let throttled = core.call(
        8,
        "vault.verify_password",
        json!({ "password_b64": b64("testpass1") }),
    );
    assert_eq!(throttled["error"]["code"], "throttled", "{throttled}");
    assert!(
        throttled["error"]["data"]["retry_after_ms"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[test]
fn auto_lock_fires() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello_with(1_500);
    core.call(
        2,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON) }),
    );
    assert_eq!(core.event()["event"], "vault.unlocked");
    let unlocked = Instant::now();
    let locked = core.event();
    assert_eq!(locked["event"], "vault.locked");
    assert_eq!(locked["data"]["reason"], "auto");
    // Its own bound: the read guard is generous, and a late auto-lock leaves
    // secrets unlocked. 1.5 s configured, with room for a loaded runner.
    let after = unlocked.elapsed();
    assert!(
        after < Duration::from_millis(6_500),
        "auto-lock after {after:?}"
    );
    assert_eq!(
        core.call(3, "vault.status", json!({}))["result"]["unlocked"],
        false
    );
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

#[test]
fn two_queued_creates_never_overwrite() {
    // Both pass admission (no vault yet); the second must fail at run time
    // instead of replacing the vault whose phrase the first one returned.
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let create = |id| {
        frame(&request(
            id,
            "vault.create",
            json!({ "password_b64": b64("testpass1"), "words": 12 }),
        ))
    };
    core.send_raw(&[create(2), create(3)].concat());
    let first = core.response(2);
    let phrase = decoded(&first["result"]["mnemonic_b64"]);
    let second = core.response(3);
    assert_eq!(second["error"]["code"], "vault_exists", "{second}");
    assert_eq!(
        second["error"]["message"],
        "Vault already exists. Use importVault to replace."
    );
    let exported = core.call(
        4,
        "vault.export_mnemonic",
        json!({ "password_b64": b64("testpass1") }),
    );
    assert_eq!(decoded(&exported["result"]["mnemonic_b64"]), phrase);
    // The snapshot followed the write.
    let status = core.call(5, "vault.status", json!({}));
    assert_eq!(status["result"]["exists"], true);
    let bytes = std::fs::read(data.join("identity-vault.json")).unwrap();
    let expected: String = sha2::Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(status["result"]["fingerprint"], expected);
}

// ---- Review regressions (PR #9): commit gating, revocation, deadlines ----

const VAULT: &str = "identity-vault.json";
/// Every vault job stalls this long before doing anything (pre-commit).
const SLOW_JOBS: (&str, &str) = ("FREEDOM_CORED_TEST_JOB_DELAY_MS", "800");

/// A core with `env` hooks and the abandon...about wallet imported under
/// "testpass1" (unlocked). The next free request ID is 3.
fn imported(env: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf, Core) {
    let (root, data, locks) = dirs();
    let mut core = spawn_env("serve", &data, &locks, &[], env);
    core.hello();
    let imported = core.call(
        2,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON) }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    assert_eq!(core.event()["event"], "vault.unlocked");
    (root, data, core)
}

fn cancel(id: u64) -> Vec<u8> {
    frame(&json!({ "type": "cancel", "id": id }))
}

#[test]
fn cancel_stops_mutations_before_their_commit() {
    let mutations = [
        ("vault.delete", json!({ "password_b64": b64("testpass1") })),
        (
            "vault.change_password",
            json!({ "password_b64": b64("testpass1"), "new_password_b64": b64("testpass2") }),
        ),
        (
            "vault.import",
            json!({ "password_b64": b64("testpass9"), "mnemonic_b64": b64(ABANDON), "overwrite": true }),
        ),
    ];
    for (method, params) in mutations {
        let (_root, data, mut core) = imported(&[SLOW_JOBS]);
        let before = std::fs::read(data.join(VAULT)).unwrap();
        core.send_raw(&[frame(&request(3, method, params)), cancel(3)].concat());
        let reply = core.response(3);
        assert_eq!(reply["error"]["code"], "cancelled", "{method}: {reply}");
        // Queued behind the abandoned job: proves it finished without writing.
        let verify = core.call(
            4,
            "vault.verify_password",
            json!({ "password_b64": b64("testpass1") }),
        );
        assert_eq!(verify["result"], json!({}), "{method}: {verify}");
        assert_eq!(std::fs::read(data.join(VAULT)).unwrap(), before, "{method}");
    }

    // A cancelled create writes no vault.
    let (_root, data, locks) = dirs();
    let mut core = spawn_env("serve", &data, &locks, &[], &[SLOW_JOBS]);
    core.hello();
    let create = request(
        2,
        "vault.create",
        json!({ "password_b64": b64("testpass1"), "words": 12 }),
    );
    core.send_raw(&[frame(&create), cancel(2)].concat());
    assert_eq!(core.response(2)["error"]["code"], "cancelled");
    let verify = core.call(
        3,
        "vault.verify_password",
        json!({ "password_b64": b64("testpass1") }),
    );
    assert_eq!(verify["error"]["code"], "no_vault", "{verify}");
    assert!(!data.join(VAULT).exists());
}

#[test]
fn a_lock_revokes_all_pre_commit_work() {
    let (_root, data, mut core) = imported(&[SLOW_JOBS]);
    core.call(3, "vault.lock", json!({}));
    assert_eq!(core.event()["data"]["reason"], "manual");
    let before = std::fs::read(data.join(VAULT)).unwrap();
    // A slow verify runs; an unlock and an overwriting import wait behind it.
    let burst = [
        frame(&request(4, "vault.verify_password", json!({ "password_b64": b64("testpass1") }))),
        frame(&request(5, "vault.unlock", json!({ "password_b64": b64("testpass1") }))),
        frame(&request(
            6,
            "vault.import",
            json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON), "overwrite": true }),
        )),
        frame(&request(7, "vault.lock", json!({}))),
    ]
    .concat();
    core.send_raw(&burst);
    // Everything admitted before the lock is revoked, in admission order.
    for id in 4..7 {
        assert_eq!(core.response(id)["error"]["code"], "vault_locked", "{id}");
    }
    assert_eq!(core.response(7)["result"], json!({}));
    let status = core.call(8, "vault.status", json!({}));
    assert_eq!(status["result"]["unlocked"], false, "{status}");
    assert_eq!(std::fs::read(data.join(VAULT)).unwrap(), before);
}

#[test]
fn deadlines_answer_stalled_work_once_and_stop_its_commit() {
    let env = [
        ("FREEDOM_CORED_TEST_JOB_DELAY_MS", "1500"),
        ("FREEDOM_CORED_TEST_KDF_DEADLINE_MS", "400"),
    ];
    let (_root, data, locks) = dirs();
    let mut core = spawn_env("serve", &data, &locks, &[], &env);
    core.hello();
    let started = Instant::now();
    let burst = [
        frame(&request(
            2,
            "vault.create",
            json!({ "password_b64": b64("testpass1"), "words": 12 }),
        )),
        frame(&request(
            3,
            "vault.verify_password",
            json!({ "password_b64": b64("testpass1") }),
        )),
    ]
    .concat();
    core.send_raw(&burst);
    // Running and queued work both time out on the loop's own wakeup, long
    // before the stalled worker returns.
    assert_eq!(core.response(2)["error"]["code"], "deadline");
    assert_eq!(core.response(3)["error"]["code"], "deadline");
    assert!(
        started.elapsed() < Duration::from_millis(1200),
        "{:?}",
        started.elapsed()
    );
    // The loop stays live, and the stalled create never commits.
    assert_eq!(
        core.call(4, "vault.status", json!({}))["result"]["exists"],
        false
    );
    std::thread::sleep(Duration::from_millis(2500));
    assert!(!data.join(VAULT).exists());
    // No second reply for 2 or 3: the next response is this one.
    assert_eq!(
        core.call(5, "vault.status", json!({}))["result"]["exists"],
        false
    );
}

#[test]
fn auto_lock_is_not_postponed_by_a_busy_queue() {
    // 1,500 requests deriving 64 addresses each take far longer than the
    // 150 ms auto-lock, so the lock must land while the queue is busy, and
    // the secret lookup queued at the end must find the vault locked.
    let (_root, data, locks) = dirs();
    let mut core = spawn_env("serve", &data, &locks, &[], &[]);
    core.hello_with(150);
    core.call(
        2,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON) }),
    );
    let accounts: Vec<u32> = (0..64).collect();
    let mut burst = Vec::new();
    for id in 3..1503 {
        burst.extend(frame(&request(
            id,
            "keys.addresses",
            json!({ "accounts": accounts }),
        )));
    }
    burst.extend(frame(&shell_request(
        1503,
        "compat.private_key",
        json!({ "account": 0 }),
    )));
    core.send_raw(&burst);
    let compat = core.until_response(1503);
    assert_eq!(compat["error"]["code"], "vault_locked", "{compat}");
    let events = core.events();
    assert!(
        events.iter().any(|e| e["data"]["reason"] == "auto"),
        "{events:?}"
    );
}

#[test]
fn a_burst_survives_main_pausing_its_reads() {
    // The flake behind `auto_lock_is_not_postponed_by_a_busy_queue`: main
    // stopped reading during a burst (a GC pause, a busy main thread), the
    // replies filled the loop's allowance, and the core exited. Now the loop
    // stops taking requests, the reader stops reading, and everything is
    // answered, in order, once main reads again.
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    #[cfg(target_os = "linux")]
    let (resident, _) = core.memory_kib();
    // 64 KiB of padding the method ignores, in each of 1,500 requests: a
    // 96 MiB burst, far past the 16 MiB of frames the core may hold.
    let pad = "x".repeat(64 * 1024);
    let burst: Vec<u8> = (2..1502u64)
        .flat_map(|id| frame(&request(id, "vault.status", json!({ "pad": pad }))))
        .collect();
    core.pause_reading();
    let paused = Instant::now();
    let resume = core.resume_reading_after(Duration::from_secs(2));
    core.send_raw(&burst);
    // The core took the burst in only as main read its replies.
    assert!(
        paused.elapsed() >= Duration::from_millis(1900),
        "the core kept reading: {:?}",
        paused.elapsed()
    );
    for id in 2..1502u64 {
        let reply = core.recv();
        assert_eq!(reply["id"], id, "{reply}");
        assert_eq!(reply["result"]["exists"], false, "{reply}");
    }
    resume.join().unwrap();
    // What the core held at its peak is its bounds' (the frames read and the
    // replies queued), not the burst's.
    #[cfg(target_os = "linux")]
    {
        let (_, peak) = core.memory_kib();
        assert!(
            peak < resident + 40 * 1024,
            "peak {peak} KiB, from {resident} KiB"
        );
    }
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

/// `ids` requests deriving 8 addresses each. Their replies, about 900
/// bytes, fill any OS's stdout pipe and the loop's 256-frame allowance
/// within a few hundred, so 450 of them leave what follows within the
/// reader's 256 credits. Each is padded to 64 KiB, which the method
/// ignores, so the core reads them only as it handles them
/// (`Feed::wait_stalled`).
fn filling(ids: std::ops::Range<u64>) -> Vec<Vec<u8>> {
    let accounts: Vec<u32> = (0..8).collect();
    let pad = "x".repeat(64 * 1024);
    ids.map(|id| {
        frame(&request(
            id,
            "keys.addresses",
            json!({ "accounts": accounts, "pad": pad }),
        ))
    })
    .collect()
}

#[test]
fn auto_lock_fires_while_main_is_not_reading() {
    // An export starts, then replies fill the loop's allowance while main
    // reads nothing. The auto-lock lands on time all the same: it revokes
    // the export, whose job only finishes later, still before main reads
    // again. Had the lock waited for room, the export would have returned
    // the phrase.
    let (_root, data, locks) = dirs();
    let mut core = spawn_env(
        "serve",
        &data,
        &locks,
        &[],
        &[("FREEDOM_CORED_TEST_JOB_DELAY_MS", "4000")],
    );
    core.hello_with(2_000);
    core.call(
        2,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON) }),
    );
    assert_eq!(core.event()["event"], "vault.unlocked");
    core.pause_reading();
    let resume = core.resume_reading_after(Duration::from_secs(6));
    let mut burst = frame(&request(
        3,
        "vault.export_mnemonic",
        json!({ "password_b64": b64("testpass1") }),
    ));
    // Small, quick replies: they fill the pipe and the allowance within
    // milliseconds, long before the lock is due.
    for id in 4..1504u64 {
        burst.extend(frame(&request(id, "vault.status", json!({}))));
    }
    core.send_raw(&burst);
    let mut seen = Vec::new();
    while seen.last().is_none_or(|m: &Value| m["id"] != 1503) {
        seen.push(core.recv());
    }
    resume.join().unwrap();
    let export = seen.iter().find(|m| m["id"] == 3).unwrap();
    assert_eq!(export["error"]["code"], "vault_locked", "{export}");
    let events: Vec<&Value> = seen.iter().filter(|m| m["type"] == "event").collect();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["event"], "vault.locked");
    assert_eq!(events[0]["data"]["reason"], "auto");
    // The lock landed while requests waited: those answered before it saw
    // the vault unlocked, and those that waited, locked.
    let unlocked = |m: &Value| m["result"]["unlocked"].as_bool();
    let lock = seen.iter().position(|m| m["type"] == "event").unwrap();
    let (before, after) = seen.split_at(lock);
    assert!(before.iter().filter_map(unlocked).all(|u| u));
    let waited: Vec<bool> = after.iter().filter_map(unlocked).collect();
    assert!(!waited.is_empty() && waited.iter().all(|u| !u));
}

#[test]
fn shutdown_is_honored_while_main_is_not_reading() {
    // The shutdown waits behind requests main hasn't read replies for; the
    // core still finds it, and exits 0 without main reading anything more.
    let (root, data, mut core) = imported(&[]);
    core.pause_reading();
    let mut burst = filling(3..453).concat();
    burst.extend(frame(&request(453, "core.shutdown", json!({}))));
    // Stdin stays open: the exit is the shutdown's, not EOF's.
    let writer = core.send_in_background(burst);
    assert_eq!(core.exit_code(Duration::from_secs(10)), 0);
    drop(writer.join().unwrap());
    // The gate is free for the next core.
    let mut next = spawn("serve", &data, &root.path().join("locks"), &[]);
    assert_eq!(next.hello()["result"]["protocol"], 1);
}

#[test]
fn a_lock_is_honored_while_main_is_not_reading() {
    // A vault.lock behind requests that wait for main to read locks at once:
    // the requests sent before it find the vault locked when their turn
    // comes, and the lock is acknowledged in its own turn.
    let (_root, _data, mut core) = imported(&[]);
    core.pause_reading();
    let mut frames = filling(3..453);
    frames.push(frame(&request(453, "vault.lock", json!({}))));
    frames.extend(filling(454..464));
    // Past the reader's credits: feeding stalls once the core waits.
    frames.extend(padded(464..764));
    let feed = core.feed(frames);
    feed.wait_stalled(Duration::from_secs(1));
    core.resume_reading();
    core.fed(feed);
    let mut seen = Vec::new();
    while seen.last().is_none_or(|m: &Value| m["id"] != 763) {
        seen.push(core.recv());
    }
    let events: Vec<usize> = (0..seen.len())
        .filter(|&i| seen[i]["type"] == "event")
        .collect();
    assert_eq!(events.len(), 1);
    let event = events[0];
    assert_eq!(seen[event]["event"], "vault.locked");
    assert_eq!(seen[event]["data"]["reason"], "manual");
    let lock = seen.iter().position(|m| m["id"] == 453).unwrap();
    assert_eq!(seen[lock]["result"], json!({}));
    // Lookups sent before the lock were answered after it took effect.
    let first_locked = seen
        .iter()
        .position(|m| m["error"]["code"] == "vault_locked")
        .unwrap();
    assert!(seen[first_locked]["id"].as_u64().unwrap() < 453);
    assert!(event < first_locked && first_locked < lock);
    // Replies stay in request order, and none after the lock found keys.
    let ids: Vec<u64> = seen.iter().filter_map(|m| m["id"].as_u64()).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
    for reply in &seen[first_locked..] {
        if reply["id"] == 453 || reply["type"] == "event" {
            continue;
        }
        let locked =
            reply["error"]["code"] == "vault_locked" || reply["result"]["unlocked"] == false;
        assert!(locked, "{}", reply["id"]);
    }
}

#[test]
fn a_cancel_reaches_queued_work_while_main_is_not_reading() {
    // A verify runs and a second one is queued behind it. Replies then fill
    // the loop's allowance, and a cancel for the queued verify comes behind
    // requests that wait for main to read. It still reaches the verify at
    // once, which would otherwise run to its end while main reads nothing.
    let (_root, _data, mut core) = imported(&[("FREEDOM_CORED_TEST_JOB_DELAY_MS", "2000")]);
    core.pause_reading();
    let paused = Instant::now();
    let verify = |id| {
        frame(&request(
            id,
            "vault.verify_password",
            json!({ "password_b64": b64("testpass1") }),
        ))
    };
    let mut frames = vec![verify(3), verify(4)];
    frames.extend(filling(5..455));
    frames.push(cancel(4));
    frames.extend(padded(455..755));
    let feed = core.feed(frames);
    feed.wait_stalled(Duration::from_secs(1));
    // Long enough for both verifies to have run (2 s of delay each).
    std::thread::sleep(Duration::from_secs(7).saturating_sub(paused.elapsed()));
    core.resume_reading();
    core.fed(feed);
    let mut seen = Vec::new();
    while seen.len() < 752 {
        let message = core.recv();
        if message["type"] == "response" {
            seen.push(message);
        }
    }
    let reply = |id: u64| seen.iter().find(|m| m["id"] == id).unwrap();
    assert_eq!(reply(3)["result"], json!({}), "{}", reply(3));
    assert_eq!(reply(4)["error"]["code"], "cancelled", "{}", reply(4));
}

/// `keys.addresses` for accounts and publishers `0..n`, padded like
/// `filling`. With `n = 4` it is light: a few milliseconds, and a reply of
/// about 1 KB. With `n = 64`, the most, it is heavy: tens of milliseconds,
/// and about 10 KB.
fn addresses(id: u64, n: u32) -> Vec<u8> {
    let indices: Vec<u32> = (0..n).collect();
    frame(&request(
        id,
        "keys.addresses",
        json!({ "accounts": indices, "publishers": indices, "pad": "x".repeat(64 * 1024) }),
    ))
}

/// A backlog that drains slowly once main reads again, from ID `first`:
/// 330 light lookups, then 170 heavy ones. The light replies fill any OS's
/// stdout pipe and the loop's allowance within the first 321 frames, so
/// all the heavy lookups wait, and the frames right after them still fall
/// within the reader's credits. Every 25th of the first 250 frames is a
/// `vault.touch` instead, so the auto-lock counts from just before the
/// wait. Returns the frames and the heavy lookups' IDs.
fn slow_backlog(first: u64) -> (Vec<Vec<u8>>, std::ops::Range<u64>) {
    let pad = "x".repeat(64 * 1024);
    let mut frames = Vec::new();
    for id in first..first + 330 {
        frames.push(if (id - first).is_multiple_of(25) && id - first <= 250 {
            frame(&request(id, "vault.touch", json!({ "pad": pad })))
        } else {
            addresses(id, 4)
        });
    }
    let heavy = first + 330..first + 500;
    frames.extend(heavy.clone().map(|id| addresses(id, 64)));
    (frames, heavy)
}

/// Main stops reading while a slow backlog waits, then reads again before
/// the auto-lock is due, and the lock comes due while the backlog drains.
/// A key request at its end, after a `vault.touch` if `late_touch`, must
/// find the vault locked.
fn auto_lock_due_while_draining(late_touch: bool) {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello_with(4_000);
    core.call(
        2,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON) }),
    );
    assert_eq!(core.event()["event"], "vault.unlocked");
    core.pause_reading();
    let (mut frames, heavy) = slow_backlog(3);
    let pad = "x".repeat(64 * 1024);
    let touch = heavy.end;
    if late_touch {
        frames.push(frame(&request(touch, "vault.touch", json!({ "pad": pad }))));
    }
    let key = if late_touch { touch + 1 } else { touch };
    frames.push(frame(&shell_request(
        key,
        "compat.private_key",
        json!({ "account": 0, "pad": pad }),
    )));
    // Past the reader's credits: feeding stalls once the core waits.
    frames.extend(padded(key + 1..key + 101));
    let feed = core.feed(frames);
    feed.wait_stalled(Duration::from_secs(1));
    core.resume_reading();
    core.fed(feed);
    let mut seen = Vec::new();
    while seen.last().is_none_or(|m: &Value| m["id"] != key + 100) {
        seen.push(core.recv());
    }
    let at = |id: u64| seen.iter().position(|m| m["id"] == id).unwrap();
    // Main read again before the lock was due: heavy lookups that waited
    // still found keys.
    assert!(
        seen.iter()
            .any(|m| heavy.contains(&m["id"].as_u64().unwrap_or(0)) && m["result"].is_object()),
        "main read again only after the lock was due"
    );
    let events: Vec<usize> = (0..seen.len())
        .filter(|&i| seen[i]["type"] == "event")
        .collect();
    assert_eq!(
        events.len(),
        1,
        "{:?}",
        events.iter().map(|&i| &seen[i]).collect::<Vec<_>>()
    );
    let lock = events[0];
    assert_eq!(seen[lock]["event"], "vault.locked");
    assert_eq!(seen[lock]["data"]["reason"], "auto");
    // The lock landed before the requests that came after its deadline: the
    // touch didn't postpone it, and the key request found the vault locked.
    if late_touch {
        assert!(lock < at(touch));
    }
    assert!(lock < at(key));
    assert_eq!(
        seen[at(key)]["error"]["code"],
        "vault_locked",
        "{}",
        seen[at(key)]
    );
    assert!(
        seen.iter()
            .all(|m| m["result"]["private_key_hex"].is_null())
    );
    // Nothing after the lock found keys.
    for reply in &seen[lock + 1..] {
        if reply["id"] == touch && late_touch {
            continue;
        }
        let locked =
            reply["error"]["code"] == "vault_locked" || reply["result"]["unlocked"] == false;
        assert!(locked, "{}", reply["id"]);
    }
    let status = core.call(key + 101, "vault.status", json!({}));
    assert_eq!(status["result"]["unlocked"], false, "{status}");
}

#[test]
fn auto_lock_due_while_waiting_requests_drain_locks_before_the_next() {
    auto_lock_due_while_draining(false);
}

#[test]
fn a_late_touch_cannot_postpone_a_lock_due_while_requests_drain() {
    auto_lock_due_while_draining(true);
}

#[test]
fn a_draining_backlog_does_not_starve_a_shutdown() {
    // A shutdown that arrives while a slow backlog drains is handled within
    // a request or so: the core exits with much of the backlog unanswered,
    // rather than answering all of it first.
    let (_root, _data, mut core) = imported(&[]);
    core.pause_reading();
    let (mut frames, heavy) = slow_backlog(3);
    // Past the reader's credits: it reads the shutdown only as the backlog
    // drains.
    frames.extend(padded(heavy.end..heavy.end + 100));
    frames.push(frame(&request(heavy.end + 100, "core.shutdown", json!({}))));
    let feed = core.feed(frames);
    feed.wait_stalled(Duration::from_secs(1));
    core.resume_reading();
    core.fed(feed);
    let replies = core.rest();
    assert_eq!(core.exit_code(Duration::from_secs(10)), 0);
    let answered = replies
        .iter()
        .filter(|m| heavy.contains(&m["id"].as_u64().unwrap_or(0)))
        .count();
    // 170 heavy lookups; the shutdown came after the first 100 or so frames.
    assert!(answered <= 120, "{answered} of 170 heavy lookups answered");
}

#[test]
fn a_draining_backlog_does_not_starve_a_cancel() {
    // 32 verifies, half a second each: the last is still queued long after
    // the rest of this test. A cancel for it arrives while a slow backlog
    // drains, and is handled within a request or so: its reply comes before
    // most of the backlog's, not after all of it.
    let (_root, _data, mut core) = imported(&[("FREEDOM_CORED_TEST_JOB_DELAY_MS", "500")]);
    core.pause_reading();
    let mut frames: Vec<Vec<u8>> = (3..35)
        .map(|id| {
            frame(&request(
                id,
                "vault.verify_password",
                json!({ "password_b64": b64("testpass1") }),
            ))
        })
        .collect();
    let (backlog, heavy) = slow_backlog(35);
    frames.extend(backlog);
    frames.extend(padded(heavy.end..heavy.end + 100));
    frames.push(cancel(34));
    let feed = core.feed(frames);
    feed.wait_stalled(Duration::from_secs(1));
    core.resume_reading();
    core.fed(feed);
    let mut seen = Vec::new();
    while seen
        .last()
        .is_none_or(|m: &Value| m["id"] != heavy.end + 99)
    {
        let message = core.recv();
        if message["type"] == "response" {
            seen.push(message);
        }
    }
    let cancelled = seen
        .iter()
        .position(|m| m["id"] == 34)
        .expect("no reply to the cancelled verify before the backlog's end");
    assert_eq!(
        seen[cancelled]["error"]["code"], "cancelled",
        "{}",
        seen[cancelled]
    );
    let heavy_after = seen[cancelled..]
        .iter()
        .filter(|m| heavy.contains(&m["id"].as_u64().unwrap_or(0)))
        .count();
    assert!(
        heavy_after >= 50,
        "only {heavy_after} heavy replies after the cancel's"
    );
}

#[test]
fn malformed_public_keys_never_crash_the_core() {
    let (_root, _data, mut core) = imported(&[]);
    for id in 3..6 {
        let wrong = core.call(
            id,
            "vault.verify_password",
            json!({ "password_b64": b64("wrong-password") }),
        );
        assert_eq!(wrong["error"]["code"], "incorrect_password");
    }
    // A 64-byte string with a multi-byte character at every position.
    let mut id = 6;
    for k in 0..=61 {
        let key = format!("{}€{}", "0".repeat(k), "0".repeat(61 - k));
        assert_eq!(key.len(), 64);
        let reply = core.call(id, "keys.radicle_did", json!({ "public_key": key }));
        assert_eq!(reply["error"]["code"], "invalid_argument", "{k}: {reply}");
        id += 1;
    }
    let did = core.call(
        id,
        "keys.radicle_did",
        json!({ "public_key": "0x".to_owned() + &"ab".repeat(32) }),
    );
    assert!(
        did["result"]["did"]
            .as_str()
            .unwrap()
            .starts_with("did:key:z6Mk")
    );
    // The process and its throttle counter survived: 3 + 2 failures, then
    // the next attempt is throttled.
    for next in [id + 1, id + 2] {
        let wrong = core.call(
            next,
            "vault.verify_password",
            json!({ "password_b64": b64("wrong-password") }),
        );
        assert_eq!(wrong["error"]["code"], "incorrect_password");
    }
    let throttled = core.call(
        id + 3,
        "vault.verify_password",
        json!({ "password_b64": b64("testpass1") }),
    );
    assert_eq!(throttled["error"]["code"], "throttled", "{throttled}");
}

#[test]
fn verify_and_exports_check_passwords_like_js() {
    // JS verifyPassword only decrypts: a version-2 envelope still verifies,
    // while unlock refuses it.
    let fixtures: Value = serde_json::from_str(
        &std::fs::read_to_string(vectors().join("fixtures/vaults.json")).unwrap(),
    )
    .unwrap();
    let fixture = &fixtures["fixtures"][0];
    let contents =
        fixture["fileContents"]
            .as_str()
            .unwrap()
            .replacen("\"version\": 1", "\"version\": 2", 1);
    let (_root, data, locks) = dirs();
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join(VAULT), contents).unwrap();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let password = b64(fixture["password"].as_str().unwrap());
    assert_eq!(
        core.call(
            2,
            "vault.verify_password",
            json!({ "password_b64": password })
        )["result"],
        json!({})
    );
    let unlock = core.call(3, "vault.unlock", json!({ "password_b64": password }));
    assert_eq!(unlock["error"]["code"], "unsupported_vault_version");
    assert_eq!(unlock["error"]["message"], "Unsupported vault version: 2");
    // Exports: password first, then the lock state.
    let export = core.call(
        4,
        "vault.export_mnemonic",
        json!({ "password_b64": password }),
    );
    assert_eq!(export["error"]["code"], "vault_locked", "{export}");
}

#[test]
fn wire_fields_follow_design_0001() {
    let (_root, _data, mut core) = imported(&[]);
    let addresses = core.call(
        3,
        "keys.addresses",
        json!({ "accounts": [0], "publishers": [0] }),
    );
    let result = &addresses["result"];
    let mut keys: Vec<&str> = result
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["bee_wallet", "publishers", "radicle", "user_wallets"]
    );
    let mut radicle: Vec<&str> = result["radicle"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    radicle.sort_unstable();
    assert_eq!(radicle, ["did", "node_id", "public_key"]);
    let public_key = result["radicle"]["public_key"].as_str().unwrap();
    let did = core.call(4, "keys.radicle_did", json!({ "public_key": public_key }));
    assert_eq!(did["result"]["did"], result["radicle"]["did"]);
    let status = core.call(5, "vault.status", json!({}));
    let mut fields: Vec<&str> = status["result"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(fields, ["epoch", "exists", "fingerprint", "unlocked"]);
    let changed = core.call(
        6,
        "vault.change_password",
        json!({ "password_b64": b64("testpass1"), "new_password_b64": b64("testpass2") }),
    );
    assert_eq!(changed["result"], json!({}));
    let key = core.call(
        7,
        "vault.export_private_key",
        json!({ "password_b64": b64("testpass2"), "account": 0 }),
    );
    let mut fields: Vec<&str> = key["result"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(fields, ["private_key_hex"]);
}

// ---- The commit point (PR #9 confirmation pass) ----

/// Each job stalls this long right after claiming its commit point, before
/// the rename or unlink.
const COMMIT_STALL: &str = "3000";

/// Hooks that stall the commit and mark the moment it's claimed.
fn commit_hooks(marker: &std::path::Path) -> Vec<(&'static str, String)> {
    vec![
        (
            "FREEDOM_CORED_TEST_COMMIT_DELAY_MS",
            COMMIT_STALL.to_owned(),
        ),
        (
            "FREEDOM_CORED_TEST_COMMIT_MARKER",
            marker.display().to_string(),
        ),
    ]
}

fn env_refs<'a>(env: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    env.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

/// Waits until the core has claimed a commit point (the marker exists).
fn wait_for_claim(marker: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !marker.exists() {
        assert!(
            Instant::now() < deadline,
            "the job never claimed its commit point"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn past_the_commit_point_the_reply_is_the_real_outcome() {
    // A cancel arriving after the claim doesn't apply: the delete happens
    // and replies success, exactly once.
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("claimed");
    let env = commit_hooks(&marker);
    let (_root, data, mut core) = imported(&env_refs(&env));
    // The import above claimed a commit too; wait for the delete's own claim.
    std::fs::remove_file(&marker).unwrap();
    let delete = request(
        3,
        "vault.delete",
        json!({ "password_b64": b64("testpass1") }),
    );
    core.send_raw(&frame(&delete));
    wait_for_claim(&marker);
    core.send_raw(&cancel(3));
    let reply = core.response(3);
    assert_eq!(reply["result"], json!({}), "{reply}");
    assert!(!data.join(VAULT).exists());
    // The snapshot follows the commit, and nothing else replies to 3.
    assert_eq!(
        core.call(4, "vault.status", json!({}))["result"]["exists"],
        false
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_committed_job_past_its_deadline_does_not_spin_the_loop() {
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("claimed");
    let mut env = commit_hooks(&marker);
    env[0].1 = "6000".into();
    env.push(("FREEDOM_CORED_TEST_KDF_DEADLINE_MS", "4000".into()));
    let (_root, data, locks) = dirs();
    let mut core = spawn_env("serve", &data, &locks, &[], &env_refs(&env));
    core.hello();
    let sent = Instant::now();
    let create = request(
        2,
        "vault.create",
        json!({ "password_b64": b64("testpass1"), "words": 12 }),
    );
    core.send_raw(&frame(&create));
    wait_for_claim(&marker);
    assert!(
        sent.elapsed() < Duration::from_millis(3800),
        "the KDF took too long for this test"
    );
    // Past the 4 s deadline, with the rename still stalled: measure CPU.
    std::thread::sleep(Duration::from_millis(4200).saturating_sub(sent.elapsed()));
    let before = core.cpu_ticks();
    std::thread::sleep(Duration::from_millis(500));
    let spent = core.cpu_ticks() - before;
    assert!(spent < 20, "the loop spun: {spent} ticks in 0.5 s");
    let reply = core.response(2);
    assert!(reply["result"]["mnemonic_b64"].is_string(), "{reply}");
}

#[test]
fn shutdown_waits_for_committed_work_and_sends_its_reply() {
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("claimed");
    let env = commit_hooks(&marker);
    let (_root, data, locks) = dirs();
    let mut core = spawn_env("serve", &data, &locks, &[], &env_refs(&env));
    core.hello();
    let create = request(
        2,
        "vault.create",
        json!({ "password_b64": b64("testpass1"), "words": 12 }),
    );
    core.send_raw(&frame(&create));
    wait_for_claim(&marker);
    core.send_raw(&frame(&request(3, "core.shutdown", json!({}))));
    // The shutdown is acknowledged, and the committed create still delivers
    // its phrase before the process exits.
    assert_eq!(core.response(3)["result"], json!({}));
    let reply = core.response(2);
    assert!(reply["result"]["mnemonic_b64"].is_string(), "{reply}");
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
    assert!(data.join(VAULT).exists());
}
