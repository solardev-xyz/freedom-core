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
    assert_eq!(hello["result"]["store_moved"], json!([]), "{hello}");
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
        json!(["payments"]),
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
    let reply = call(&mut core, "shell", "payments.pending", json!({}));
    assert_eq!(reply["result"]["payments"][0]["txHash"], "0xab", "{reply}");
    let reply = call(
        &mut core,
        "shell",
        "payments.set_dropped_seen",
        json!({ "id": 1, "seen_at": 5 }),
    );
    assert_eq!(
        reply["result"]["payment"]["metadata"]["txDroppedSeenAt"], 5,
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
    assert_eq!(reply["result"], json!({ "payment": null }), "{reply}");
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
