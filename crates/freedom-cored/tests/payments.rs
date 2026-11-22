//! The payment history in the core (design 0013, "Payment history";
//! PRF-5g-2): `payments.*` through `serve`, as main reaches them.
//!
//! - **The handover:** until `core.hello` names `payments` in
//!   `store_moved`, every method answers `not_moved` and the database is
//!   never opened or created; once named, the hello echoes it, and the
//!   first request opens the database and runs the `x402-receipts.json`
//!   import.
//! - **The callers:** the chrome reads and clears; the writes and the
//!   repoll's read are main's; a page reaches none.
//!
//! The rows after each of the reference's operations, the import's file
//! steps and the failure paths are `payments::tests`; the database read by
//! the reference, and the reference's read by the core, are
//! `vectors/generator/interop.test.js`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use serde_json::{Value, json};

const METHODS: &[&str] = &[
    "payments.append",
    "payments.update",
    "payments.mark_confirmed",
    "payments.mark_failed",
    "payments.mark_dropped",
    "payments.set_dropped_seen",
    "payments.pending",
    "payments.get_recent",
    "payments.get_by_id",
    "payments.get_count",
    "payments.clear",
];

/// The chrome's: `payments:get-recent`, `:get-count`, `:get-by-id`,
/// `:clear` and `x402:get-receipts`.
const CHROME: &[&str] = &[
    "payments.get_recent",
    "payments.get_by_id",
    "payments.get_count",
    "payments.clear",
];

fn code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or("")
}

/// Request ids only grow within a session: the next one, from a counter.
fn call(core: &mut common::Core, caller: &str, method: &str, params: Value) -> Value {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(10);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    core.send(&json!({
        "type": "request", "id": id, "method": method, "params": params,
        "context": { "caller": caller },
    }));
    core.response(id)
}

/// Not named: `not_moved` for every method and caller allowed, nothing
/// created or imported, and no echo. Named: echoed once, and the first
/// request opens the database and imports the legacy file.
#[test]
fn the_handover() {
    let (_root, data, locks) = common::dirs();
    let mut core = common::spawn("serve", &data, &locks, &[]);
    let grant_root = core.grant_root.clone();
    std::fs::create_dir_all(&grant_root).unwrap();
    let legacy = r#"[{"id":"r1","settledAt":1699000000,"status":"settled","chainId":8453,"amount":"500","origin":"https://x.example","url":"https://x.example/a"}]"#;
    std::fs::write(grant_root.join("x402-receipts.json"), legacy).unwrap();
    core.store_moved = vec!["vault_meta"];
    let hello = core.hello();
    assert_eq!(
        hello["result"]["store_moved"],
        json!(["vault_meta"]),
        "{hello}"
    );
    for method in METHODS {
        for caller in ["chrome", "shell"] {
            let reply = call(&mut core, caller, method, json!({}));
            if caller == "chrome" && !CHROME.contains(method) {
                assert_eq!(code(&reply), "forbidden", "{method}: {reply}");
            } else {
                assert_eq!(code(&reply), "not_moved", "{method} {caller}: {reply}");
                assert_eq!(reply["error"]["data"]["store"], "payments");
            }
        }
    }
    assert!(!grant_root.join("payment-history.sqlite").exists());
    assert!(grant_root.join("x402-receipts.json").exists());
    drop(core);

    let mut core = common::spawn("serve", &data, &locks, &[]);
    core.store_moved = vec!["payments", "vault_meta", "payments"];
    let hello = core.hello();
    assert_eq!(
        hello["result"]["store_moved"],
        json!(["payments", "vault_meta"]),
        "{hello}"
    );
    // Named, but nothing opened before the first request.
    assert!(!grant_root.join("payment-history.sqlite").exists());
    let reply = call(&mut core, "chrome", "payments.get_recent", json!({}));
    let payments = reply["result"]["payments"].as_array().unwrap();
    assert_eq!(payments.len(), 1, "{reply}");
    assert_eq!(payments[0]["kind"], "x402");
    assert_eq!(payments[0]["metadata"]["legacyId"], "r1");
    assert!(grant_root.join("payment-history.sqlite").exists());
    assert!(!grant_root.join("x402-receipts.json").exists());
    assert!(grant_root.join("x402-receipts.json.migrated").exists());
}

fn receipt(id: &str) -> String {
    format!(
        r#"[{{"id":"{id}","settledAt":1699000000,"status":"settled","chainId":8453,"amount":"500","origin":"https://x.example","url":"https://x.example/a"}}]"#
    )
}

/// The handshake naming `payments`, with `user_data_dir`.
fn hello_with_user_data(
    core: &mut common::Core,
    grant_root: &std::path::Path,
    user_data: &std::path::Path,
) -> Value {
    let hello = core.call_shell(
        1,
        "core.hello",
        json!({
            "protocol": 2, "shell_version": "test", "auto_lock_ms": 900_000,
            "frames": ["stream"], "grant_root": grant_root,
            "user_data_dir": user_data, "store_moved": ["payments"],
        }),
    );
    assert_eq!(
        hello["result"]["store_moved"],
        json!(["payments"]),
        "{hello}"
    );
    hello
}

/// A moved profile's `serve`, as main spawns it (design 0017, C1): its
/// Freedom root, and the profile's root, whose receipts it hands over
/// before it confines itself (C5).
fn spawn_moved(
    data: &std::path::Path,
    locks: &std::path::Path,
    grant_root: &std::path::Path,
    user_data: &std::path::Path,
) -> common::Core {
    common::spawn(
        "serve",
        data,
        locks,
        &[
            "--grant-root",
            grant_root.to_str().unwrap(),
            "--user-data-dir",
            user_data.to_str().unwrap(),
        ],
    )
}

fn legacy_ids(core: &mut common::Core) -> Vec<String> {
    let reply = call(core, "chrome", "payments.get_recent", json!({}));
    reply["result"]["payments"]
        .as_array()
        .unwrap_or_else(|| panic!("{reply}"))
        .iter()
        .filter_map(|payment| payment["metadata"]["legacyId"].as_str())
        .map(str::to_owned)
        .collect()
}

/// A moved profile (design 0017, C5): `--user-data-dir` isn't its
/// `--grant-root`. The receipts at the profile's root are copied into the
/// Freedom root at the start, before `confine`, and imported from the copy,
/// which is renamed `.migrated` there; the original stays at the profile's
/// root until the next start, which drops it, importing nothing twice. The
/// database stays under `grant_root`.
#[test]
fn a_moved_profile_imports_its_receipts_from_a_copy() {
    let (_root, data, locks) = common::dirs();
    let user_data = common::default_grant_root(&data);
    let grant_root = user_data.join("freedom");
    std::fs::create_dir_all(&grant_root).unwrap();
    std::fs::write(user_data.join("x402-receipts.json"), receipt("profile")).unwrap();
    let mut core = spawn_moved(&data, &locks, &grant_root, &user_data);
    hello_with_user_data(&mut core, &grant_root, &user_data);
    assert_eq!(legacy_ids(&mut core), ["profile"]);
    assert!(grant_root.join("payment-history.sqlite").exists());
    assert!(!user_data.join("payment-history.sqlite").exists());
    assert_eq!(
        std::fs::read_to_string(user_data.join("x402-receipts.json")).unwrap(),
        receipt("profile")
    );
    assert!(!user_data.join("x402-receipts.json.migrated").exists());
    assert!(!grant_root.join("x402-receipts.json").exists());
    assert_eq!(
        std::fs::read_to_string(grant_root.join("x402-receipts.json.migrated")).unwrap(),
        receipt("profile")
    );
    drop(core);

    let mut core = spawn_moved(&data, &locks, &grant_root, &user_data);
    hello_with_user_data(&mut core, &grant_root, &user_data);
    assert_eq!(legacy_ids(&mut core), ["profile"]);
    assert!(!user_data.join("x402-receipts.json").exists());
    assert!(grant_root.join("x402-receipts.json.migrated").exists());
}

/// A file in the Freedom root that isn't the copy of the profile's root's
/// (design 0017, C5, a conflict): neither is imported or renamed, the
/// conflict is logged, and the payment history serves. The old layout,
/// `user_data_dir` naming `grant_root` itself, imports and renames at that
/// root, as before.
#[test]
fn a_conflicting_copy_skips_the_import() {
    let (_root, data, locks) = common::dirs();
    let user_data = common::default_grant_root(&data);
    let grant_root = user_data.join("freedom");
    std::fs::create_dir_all(&grant_root).unwrap();
    std::fs::write(user_data.join("x402-receipts.json"), receipt("profile")).unwrap();
    std::fs::write(grant_root.join("x402-receipts.json"), receipt("freedom")).unwrap();
    let mut core = spawn_moved(&data, &locks, &grant_root, &user_data);
    hello_with_user_data(&mut core, &grant_root, &user_data);
    assert_eq!(legacy_ids(&mut core), Vec::<String>::new());
    let appended = call(
        &mut core,
        "shell",
        "payments.append",
        json!({ "entry": { "kind": "x402", "chainId": 1, "amount": "1", "createdAt": 5 } }),
    );
    assert_eq!(appended["result"]["payment"]["id"], 1, "{appended}");
    for (dir, id) in [(&user_data, "profile"), (&grant_root, "freedom")] {
        assert_eq!(
            std::fs::read_to_string(dir.join("x402-receipts.json")).unwrap(),
            receipt(id)
        );
        assert!(!dir.join("x402-receipts.json.migrated").exists());
    }
    core.close_stdin();
    core.exit_code(std::time::Duration::from_secs(10));
    let log = core.stderr();
    assert!(
        log.contains("conflicts with the Freedom root's; legacy import skipped"),
        "{log}"
    );

    // The old layout: the Freedom root's file is the one imported.
    let mut core = spawn_moved(&data, &locks, &grant_root, &grant_root);
    hello_with_user_data(&mut core, &grant_root, &grant_root);
    assert_eq!(legacy_ids(&mut core), ["freedom"]);
    assert!(!grant_root.join("x402-receipts.json").exists());
    assert!(grant_root.join("x402-receipts.json.migrated").exists());
    assert_eq!(
        std::fs::read_to_string(user_data.join("x402-receipts.json")).unwrap(),
        receipt("profile")
    );
}

/// A `user_data_dir` that isn't an absolute path free of `..`, or isn't a
/// string, makes the hello malformed: `invalid_argument`, and the core
/// exits 76, whether or not `payments` is named.
#[test]
fn a_relative_user_data_dir_refuses_the_hello() {
    let (_root, data, locks) = common::dirs();
    let grant_root = data.parent().unwrap().join("userData");
    for (dir, stores) in [
        (json!("relative/userData"), json!(["payments"])),
        (json!("relative/userData"), json!([])),
        (
            json!(format!("{}/../userData", grant_root.display())),
            json!(["payments"]),
        ),
        (json!(""), json!([])),
        (json!(7), json!(["payments"])),
    ] {
        let mut core = common::spawn("serve", &data, &locks, &[]);
        let hello = core.call_shell(
            1,
            "core.hello",
            json!({
                "protocol": 2, "shell_version": "test", "auto_lock_ms": 900_000,
                "frames": ["stream"], "grant_root": grant_root,
                "user_data_dir": dir, "store_moved": stores,
            }),
        );
        assert_eq!(code(&hello), "invalid_argument", "{dir}: {hello}");
        assert_eq!(
            core.exit_code(std::time::Duration::from_secs(5)),
            76,
            "{dir}"
        );
    }
    assert!(!grant_root.join("payment-history.sqlite").exists());
}

/// Each method's callers: the chrome reads and clears, main writes, a page
/// reaches none; and the answers' shapes on the wire.
#[test]
fn callers_and_answers() {
    let (_root, data, locks) = common::dirs();
    let mut core = common::spawn("serve", &data, &locks, &[]);
    std::fs::create_dir_all(&core.grant_root).unwrap();
    core.store_moved = vec!["payments"];
    core.hello();
    for method in METHODS {
        let reply = call(&mut core, "page", method, json!({}));
        assert!(
            matches!(code(&reply), "forbidden" | "unknown_method"),
            "{method}: {reply}"
        );
        let reply = call(&mut core, "chrome", method, json!({}));
        if !CHROME.contains(method) {
            assert_eq!(code(&reply), "forbidden", "{method}: {reply}");
        }
    }
    let entry = json!({ "kind": "wallet-send", "chainId": 1, "amount": "7", "txHash": "0xab",
        "createdAt": 1_700_000_000_000_u64, "metadata": { "txNonce": 4 } });
    let reply = call(
        &mut core,
        "shell",
        "payments.append",
        json!({ "entry": entry }),
    );
    let payment = &reply["result"]["payment"];
    assert_eq!(payment["id"], 1, "{reply}");
    assert_eq!(payment["status"], "pending");
    assert_eq!(payment["chainId"], 1);
    // The repoll's rows as it reads them: snake_case, metadata as text.
    let reply = call(&mut core, "shell", "payments.pending", json!({}));
    let row = &reply["result"]["payments"][0];
    assert_eq!(row["tx_hash"], "0xab", "{reply}");
    assert_eq!(row["chain_id"], 1, "{reply}");
    assert_eq!(row["metadata"], r#"{"txNonce":4}"#, "{reply}");
    let reply = call(
        &mut core,
        "shell",
        "payments.set_dropped_seen",
        json!({ "id": 1, "seen_at": 5 }),
    );
    assert_eq!(reply["result"], json!({}), "{reply}");
    let reply = call(&mut core, "shell", "payments.pending", json!({}));
    assert_eq!(
        reply["result"]["payments"][0]["metadata"], r#"{"txNonce":4,"txDroppedSeenAt":5}"#,
        "{reply}"
    );
    let reply = call(
        &mut core,
        "shell",
        "payments.mark_dropped",
        json!({ "id": 1 }),
    );
    assert_eq!(reply["result"]["payment"]["status"], "dropped", "{reply}");
    let reply = call(
        &mut core,
        "shell",
        "payments.set_dropped_seen",
        json!({ "id": 1, "seen_at": null }),
    );
    assert_eq!(reply["result"], json!({}), "{reply}");
    let reply = call(
        &mut core,
        "shell",
        "payments.append",
        json!({ "entry": { "kind": "x402", "chainId": 1, "amount": "1.5" } }),
    );
    assert_eq!(code(&reply), "invalid_argument", "{reply}");
    assert_eq!(
        reply["error"]["message"],
        "payment-history: amount must be a digit string"
    );
    assert_eq!(reply["error"]["data"], json!({ "name": "Error" }));
    let reply = call(
        &mut core,
        "chrome",
        "payments.get_by_id",
        json!({ "id": 1 }),
    );
    assert_eq!(reply["result"]["payment"]["id"], 1, "{reply}");
    let reply = call(
        &mut core,
        "chrome",
        "payments.get_count",
        json!({ "filters": { "status": "dropped" } }),
    );
    assert_eq!(reply["result"], json!({ "count": 1 }), "{reply}");
    let reply = call(&mut core, "chrome", "payments.clear", json!({}));
    assert_eq!(reply["result"], json!({ "removed": 1 }), "{reply}");
    let reply = call(
        &mut core,
        "chrome",
        "payments.get_recent",
        json!({ "filters": { "limit": 5 } }),
    );
    assert_eq!(reply["result"], json!({ "payments": [] }), "{reply}");
}
