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

    // The backup export; no raw-key export exists any more (design 0002:
    // compat.* is gone), and signing happens in the core.
    let exported = core.call(
        9,
        "vault.export_mnemonic",
        json!({ "password_b64": b64("testpass1") }),
    );
    assert_eq!(decoded(&exported["result"]["mnemonic_b64"]), phrase);
    let gone = core.call_shell(10, "compat.private_key", json!({ "account": 0 }));
    assert_eq!(gone["error"]["code"], "unknown_method", "{gone}");
    let signed = core.call(
        11,
        "sign.message",
        json!({ "key": { "kind": "account", "index": 0 }, "message": "0x01" }),
    );
    let signature = signed["result"]["signature"].as_str().unwrap();
    assert_eq!(signature.len(), 132);

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

/// Phase 2 removed the raw-key exports (design 0002): signing happens in the
/// core. They are unknown to every caller, unlocked or not.
#[test]
fn compat_exports_are_gone() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    core.call(
        2,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON) }),
    );
    let mut id = 2;
    for method in [
        "compat.private_key",
        "compat.bee_wallet_key",
        "compat.publisher_key",
    ] {
        let params = json!({ "account": 0, "origin_index": 0 });
        id += 1;
        let shell = core.call_shell(id, method, params.clone());
        assert_eq!(
            shell["error"]["code"], "unknown_method",
            "{method}: {shell}"
        );
        id += 1;
        let chrome = core.call(id, method, params);
        assert_eq!(
            chrome["error"]["code"], "unknown_method",
            "{method}: {chrome}"
        );
    }
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
    let locked = core.event();
    assert_eq!(locked["event"], "vault.locked");
    assert_eq!(locked["data"]["reason"], "auto");
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
        "sign.message",
        json!({ "key": { "kind": "account", "index": 0 }, "message": "0x01" }),
    )));
    core.send_raw(&burst);
    let signed = core.until_response(1503);
    assert_eq!(signed["error"]["code"], "vault_locked", "{signed}");
    let events = core.events();
    assert!(
        events.iter().any(|e| e["data"]["reason"] == "auto"),
        "{events:?}"
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
