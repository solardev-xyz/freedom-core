//! The vault methods through the real binary: lifecycle, JS parity strings,
//! lock semantics, throttling, auto-lock, and opening vaults written by
//! freedom-browser's JS.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;
use std::time::Duration;

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
    assert_eq!(core.response(5)["result"], json!({}));
    let unlock = core.response(4);
    assert_eq!(unlock["error"]["code"], "vault_locked", "{unlock}");
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
