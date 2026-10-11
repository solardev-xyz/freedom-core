//! `vault.reconcile` through the real binary: each row of design 0001's
//! reconciliation table, committed and not committed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ABANDON_WALLET: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

fn b64(s: &str) -> String {
    STANDARD.encode(s)
}

/// The current fingerprint, from `vault.status`.
fn fingerprint(core: &mut Core, id: u64) -> Value {
    core.call(id, "vault.status", json!({}))["result"]["fingerprint"].clone()
}

fn reconcile(core: &mut Core, id: u64, params: Value) -> Value {
    core.call_shell(id, "vault.reconcile", params)["result"].clone()
}

#[test]
fn create() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let params = |install: bool| json!({ "op": "create", "fingerprint_before": null, "password_b64": b64("testpass1"), "install": install });
    // No vault yet: not committed.
    assert_eq!(
        reconcile(&mut core, 2, params(true))["status"],
        "not_committed"
    );

    let created = core.call(
        3,
        "vault.create",
        json!({ "password_b64": b64("testpass1"), "words": 12 }),
    );
    let phrase = created["result"]["mnemonic_b64"].clone();
    let wallet = created["result"]["addresses"]["user_wallet"].clone();
    assert_eq!(core.event()["event"], "vault.unlocked");
    core.call(4, "vault.lock", json!({}));
    assert_eq!(core.event()["event"], "vault.locked");

    // Committed, without install: the phrase and addresses, still locked.
    let found = reconcile(&mut core, 5, params(false));
    assert_eq!(found["status"], "committed");
    assert_eq!(found["mnemonic_b64"], phrase);
    assert_eq!(found["addresses"]["user_wallet"], wallet);
    assert_eq!(
        core.call(6, "vault.status", json!({}))["result"]["unlocked"],
        false
    );

    // With install: unlocked.
    let found = reconcile(&mut core, 7, params(true));
    assert_eq!(found["status"], "committed");
    assert_eq!(core.event()["event"], "vault.unlocked");
    assert_eq!(
        core.call(8, "vault.status", json!({}))["result"]["unlocked"],
        true
    );

    // A wrong password, or a vault that existed before: not committed.
    let wrong = json!({ "op": "create", "fingerprint_before": null, "password_b64": b64("nope-nope"), "install": false });
    assert_eq!(reconcile(&mut core, 9, wrong)["status"], "not_committed");
    let before = fingerprint(&mut core, 10);
    let existed = json!({ "op": "create", "fingerprint_before": before, "password_b64": b64("testpass1"), "install": false });
    assert_eq!(reconcile(&mut core, 11, existed)["status"], "not_committed");
}

#[test]
fn import() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    core.call(
        2,
        "vault.create",
        json!({ "password_b64": b64("testpass1"), "words": 12 }),
    );
    let old = fingerprint(&mut core, 3);
    core.call(
        4,
        "vault.import",
        json!({ "password_b64": b64("testpass2"), "mnemonic_b64": b64(ABANDON), "overwrite": true }),
    );
    let new = fingerprint(&mut core, 5);
    assert_ne!(old, new);

    let params = |before: &Value, password: &str, mnemonic: &str| json!({ "op": "import", "fingerprint_before": before, "password_b64": b64(password), "mnemonic_b64": b64(mnemonic), "install": false });
    let found = reconcile(&mut core, 6, params(&old, "testpass2", ABANDON));
    assert_eq!(found["status"], "committed");
    assert_eq!(found["addresses"]["user_wallet"], ABANDON_WALLET);
    assert!(
        found.get("mnemonic_b64").is_none(),
        "import returns no phrase"
    );
    // Unchanged fingerprint, wrong password, or another mnemonic: not committed.
    assert_eq!(
        reconcile(&mut core, 7, params(&new, "testpass2", ABANDON))["status"],
        "not_committed"
    );
    assert_eq!(
        reconcile(&mut core, 8, params(&old, "testpass1", ABANDON))["status"],
        "not_committed"
    );
    let other = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    assert_eq!(
        reconcile(&mut core, 9, params(&old, "testpass2", other))["status"],
        "not_committed"
    );
    // Import needs its mnemonic.
    let missing = core.call_shell(
        10,
        "vault.reconcile",
        json!({ "op": "import", "fingerprint_before": old, "password_b64": b64("testpass2") }),
    );
    assert_eq!(missing["error"]["code"], "invalid_argument");
}

#[test]
fn change_password_and_delete() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    core.call(
        2,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON) }),
    );
    let before = fingerprint(&mut core, 3);
    let change = |before: &Value, password: &str| json!({ "op": "change_password", "fingerprint_before": before, "password_b64": b64(password) });
    // Not changed yet.
    assert_eq!(
        reconcile(&mut core, 4, change(&before, "testpass2"))["status"],
        "not_committed"
    );
    core.call(
        5,
        "vault.change_password",
        json!({ "password_b64": b64("testpass1"), "new_password_b64": b64("testpass2") }),
    );
    let found = reconcile(&mut core, 6, change(&before, "testpass2"));
    assert_eq!(found, json!({ "status": "committed" }));
    // The old password doesn't open the changed vault.
    assert_eq!(
        reconcile(&mut core, 7, change(&before, "testpass1"))["status"],
        "not_committed"
    );

    let after = fingerprint(&mut core, 8);
    let delete = |before: &Value| json!({ "op": "delete", "fingerprint_before": before, "password_b64": b64("testpass2") });
    assert_eq!(
        reconcile(&mut core, 9, delete(&after))["status"],
        "not_committed"
    );
    core.call(
        10,
        "vault.delete",
        json!({ "password_b64": b64("testpass2") }),
    );
    assert_eq!(
        reconcile(&mut core, 11, delete(&after)),
        json!({ "status": "committed" })
    );
    // No vault before either: nothing was deleted.
    assert_eq!(
        reconcile(&mut core, 12, delete(&Value::Null))["status"],
        "not_committed"
    );
}

#[test]
fn main_internal_unthrottled_and_validated() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    core.call(
        2,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON) }),
    );
    let params =
        json!({ "op": "create", "fingerprint_before": null, "password_b64": b64("testpass1") });
    let forbidden = core.call(3, "vault.reconcile", params.clone());
    assert_eq!(forbidden["error"]["code"], "forbidden");

    // Five failures make unlock throttled; reconcile still answers.
    for id in 4..9 {
        let wrong = core.call(
            id,
            "vault.unlock",
            json!({ "password_b64": b64("wrong-password") }),
        );
        assert_eq!(wrong["error"]["code"], "incorrect_password");
    }
    assert_eq!(
        core.call(
            9,
            "vault.verify_password",
            json!({ "password_b64": b64("testpass1") })
        )["error"]["code"],
        "throttled"
    );
    // A vault exists that didn't "before" (null), and testpass1 opens it.
    assert_eq!(reconcile(&mut core, 10, params)["status"], "committed");

    // Fingerprints are 64 lowercase hex digits.
    for (id, bad) in [
        (11, "ABC".to_owned()),
        (12, "g".repeat(64)),
        (13, "A".repeat(64)),
    ] {
        let reply = core.call_shell(
            id,
            "vault.reconcile",
            json!({ "op": "delete", "fingerprint_before": bad, "password_b64": b64("x") }),
        );
        assert_eq!(reply["error"]["code"], "invalid_argument", "{bad}");
    }
    // Unknown pre-state is not "no vault before": the field is required,
    // and a password change needs a vault before it.
    for (id, params) in [
        (
            14,
            json!({ "op": "create", "password_b64": b64("testpass1") }),
        ),
        (
            15,
            json!({ "op": "delete", "password_b64": b64("testpass1") }),
        ),
        (
            16,
            json!({ "op": "change_password", "fingerprint_before": null, "password_b64": b64("testpass1") }),
        ),
    ] {
        let reply = core.call_shell(id, "vault.reconcile", params);
        assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
        assert!(reply.get("result").is_none());
    }
    assert_eq!(
        core.call(17, "vault.status", json!({}))["result"]["unlocked"],
        true
    );
    let unknown = core.call_shell(
        18,
        "vault.reconcile",
        json!({ "op": "rename", "fingerprint_before": null, "password_b64": b64("x") }),
    );
    assert_eq!(unknown["error"]["code"], "invalid_argument");
}
