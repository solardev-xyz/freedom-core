//! The Phase 2 signing methods through the real binary (design 0002): every
//! vectors/signing.json case for the `abandon` keys, over the wire, plus key
//! kinds, locking and malformed input.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn signing_vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/signing.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn unlocked() -> (tempfile::TempDir, Core) {
    let (root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let imported = core.call(
        2,
        "vault.import",
        json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(ABANDON) }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    assert_eq!(core.event()["event"], "vault.unlocked");
    (root, core)
}

/// The vector keys of the `abandon-12` mnemonic: id → wire key reference.
fn abandon_keys(vectors: &Value) -> Vec<(String, Value)> {
    vectors["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|k| k["mnemonicId"] == "abandon-12")
        .map(|k| (k["id"].as_str().unwrap().to_owned(), k["key"].clone()))
        .collect()
}

fn must_fail(entry: &Value) -> bool {
    entry["result"]["status"] == "error" || entry.get("deviation").is_some()
}

#[test]
fn every_vector_case_over_the_wire() {
    let vectors = signing_vectors();
    let keys = abandon_keys(&vectors);
    let (_root, mut core) = unlocked();
    let mut id = 100;
    let mut checked = 0;
    for (section, method) in [
        ("transactions", "sign.transaction"),
        ("messages", "sign.message"),
        ("typedData", "sign.typed_data"),
        ("socs", "swarm.sign_soc"),
    ] {
        for case in vectors[section].as_array().unwrap() {
            let Some((_, key)) = keys.iter().find(|(k, _)| *k == case["keyId"]) else {
                continue;
            };
            let params = match section {
                "transactions" => json!({ "key": key, "tx": case["tx"] }),
                "messages" => json!({ "key": key, "message": case["message"] }),
                "typedData" => json!({ "key": key, "typed_data": case["typed_data"] }),
                _ => {
                    let mut params = json!({ "key": key, "identifier": case["identifier"], "payload": case["payload"] });
                    if let Some(span) = case.get("span") {
                        params["span"] = span.clone();
                    }
                    params
                }
            };
            id += 1;
            let reply = core.call(id, method, params);
            let label = case["id"].as_str().unwrap();
            checked += 1;
            if must_fail(case) {
                assert_eq!(
                    reply["error"]["code"], "invalid_argument",
                    "{label}: {reply}"
                );
                continue;
            }
            let (result, expected) = (&reply["result"], &case["result"]);
            match section {
                "transactions" => {
                    assert_eq!(result["raw"], expected["raw"], "{label}");
                    assert_eq!(result["hash"], expected["hash"], "{label}");
                }
                "messages" => assert_eq!(result["signature"], expected["signature"], "{label}"),
                "typedData" => {
                    assert_eq!(result["signature"], expected["signature"], "{label}");
                    id += 1;
                    let hash = core.call(
                        id,
                        "typed_data.hash",
                        json!({ "typed_data": case["typed_data"] }),
                    );
                    assert_eq!(hash["result"]["hash"], expected["hash"], "{label}");
                }
                _ => {
                    for (wire, vector) in [
                        ("signature", "signature"),
                        ("owner", "owner"),
                        ("chunk_address", "chunkAddress"),
                        ("soc_address", "socAddress"),
                        ("span", "span"),
                    ] {
                        assert_eq!(result[wire], expected[vector], "{label} {wire}");
                    }
                }
            }
        }
    }
    assert!(checked > 150, "only {checked} cases");
}

#[test]
fn bee_and_publisher_keys_sign_only_chunks() {
    let (_root, mut core) = unlocked();
    let tx = json!({ "type": 2, "chain_id": "1", "nonce": "0", "gas_limit": "21000", "to": null,
        "value": "0", "data": "0x", "max_fee_per_gas": "2", "max_priority_fee_per_gas": "1" });
    let typed = json!({ "domain": {}, "types": { "M": [] }, "message": {} });
    let mut id = 10;
    for key in [
        json!({ "kind": "bee_wallet" }),
        json!({ "kind": "publisher", "origin_index": 0 }),
    ] {
        for (method, params) in [
            ("sign.transaction", json!({ "key": key, "tx": tx })),
            ("sign.message", json!({ "key": key, "message": "0x01" })),
            (
                "sign.typed_data",
                json!({ "key": key, "typed_data": typed }),
            ),
        ] {
            id += 1;
            let reply = core.call(id, method, params);
            assert_eq!(
                reply["error"]["code"], "invalid_argument",
                "{method} {key}: {reply}"
            );
        }
        id += 1;
        let soc = core.call(id, "swarm.sign_soc", json!({ "key": key, "identifier": format!("0x{}", "00".repeat(32)), "payload": "0x01" }));
        assert!(soc["result"]["signature"].is_string(), "{soc}");
    }
}

#[test]
fn locked_vault_and_malformed_requests() {
    let (_root, mut core) = unlocked();
    assert!(core.call(3, "vault.lock", json!({}))["result"].is_object());
    let account = json!({ "kind": "account", "index": 0 });
    let reply = core.call(
        4,
        "sign.message",
        json!({ "key": account, "message": "0x01" }),
    );
    assert_eq!(reply["error"]["code"], "vault_locked", "{reply}");
    // The public hash works while locked.
    let typed = json!({ "domain": { "name": "x" }, "types": { "M": [{ "name": "v", "type": "uint8" }] }, "message": { "v": 1 } });
    let hash = core.call(5, "typed_data.hash", json!({ "typed_data": typed }));
    assert!(
        hash["result"]["hash"].as_str().unwrap().starts_with("0x"),
        "{hash}"
    );
    // Malformed requests fail before the lock is even considered.
    let mut id = 6;
    for (method, params) in [
        ("sign.message", json!({ "key": account, "message": "0xzz" })),
        (
            "sign.message",
            json!({ "key": account, "message": "0x01", "extra": 1 }),
        ),
        (
            "sign.message",
            json!({ "key": { "kind": "account", "index": 2147483648u64 }, "message": "0x01" }),
        ),
        (
            "sign.message",
            json!({ "key": { "kind": "root" }, "message": "0x01" }),
        ),
        (
            "sign.typed_data",
            json!({ "key": account, "typed_data": { "domain": {}, "types": {}, "message": {}, "primaryType": "M" } }),
        ),
        (
            "swarm.sign_soc",
            json!({ "key": account, "identifier": "0x01", "payload": "0x01" }),
        ),
        (
            "swarm.sign_soc",
            json!({ "key": account, "identifier": format!("0x{}", "00".repeat(32)), "payload": "0x" }),
        ),
        (
            "swarm.sign_soc",
            json!({ "key": account, "identifier": format!("0x{}", "00".repeat(32)), "payload": "0x01", "span": 1 }),
        ),
    ] {
        id += 1;
        let reply = core.call(id, method, params.clone());
        assert_eq!(
            reply["error"]["code"], "invalid_argument",
            "{method} {params}: {reply}"
        );
    }
}

/// A JSON number in the frame is read as `JSON.parse` reads it (#87):
/// main sends `JSON.stringify` output, but a caller passing a dApp's own
/// JSON text gets the integer ethers would sign, never an approximation.
#[test]
fn typed_data_numbers_are_read_as_json_parse_reads_them() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let mut hash = |id: u64, number: &str| {
        let text = format!(
            r#"{{"type":"request","id":{id},"method":"typed_data.hash","params":{{"typed_data":{{"domain":{{"name":"N"}},"types":{{"M":[{{"name":"v","type":"uint256"}}]}},"message":{{"v":{number}}}}}}},"context":{{"caller":"chrome"}}}}"#
        );
        core.send_raw(&raw_frame(1, text.as_bytes()));
        core.response(id)
    };
    let tie = hash(2, "4503599627370496.5");
    let even = hash(3, r#""4503599627370496""#);
    assert!(tie["result"]["hash"].is_string(), "{tie}");
    assert_eq!(tie["result"], even["result"]);
    // (2^53 - 1) + 0.5 is 2^53: no safe integer.
    let unsafe_tie = hash(4, "9007199254740991.5");
    assert_eq!(
        unsafe_tie["error"]["code"], "invalid_argument",
        "{unsafe_tie}"
    );
}
