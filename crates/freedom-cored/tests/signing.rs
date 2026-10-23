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
    let mut views = 0;
    let mut refused_account_socs = 0;
    let mut chunk_key_socs = 0;
    let mut binary_32 = 0;
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
                // The confirmed hash (#88): ethers' own where it hashed, so
                // a deviation is refused for its input, not for the hash.
                "typedData" => json!({
                    "key": key,
                    "typed_data": case["typed_data"],
                    "expected_hash": case["result"].get("hash").unwrap_or(&json!(ZERO_HASH)),
                }),
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
            // bee-js signs a chunk with an account key, and the vector
            // records that; the core refuses it (#89), and signs nothing.
            if section == "socs" && key["kind"] == "account" {
                assert_eq!(
                    reply["error"]["code"], "invalid_argument",
                    "{label}: {reply}"
                );
                assert!(reply.get("result").is_none(), "{label}: {reply}");
                refused_account_socs += 1;
                continue;
            }
            if must_fail(case) {
                assert_eq!(
                    reply["error"]["code"], "invalid_argument",
                    "{label}: {reply}"
                );
                if section == "typedData" {
                    // The public hash refuses it too: the input is refused,
                    // whatever hash was confirmed.
                    id += 1;
                    let hash = core.call(
                        id,
                        "typed_data.hash",
                        json!({ "typed_data": case["typed_data"] }),
                    );
                    assert_eq!(hash["error"]["code"], "invalid_argument", "{label}: {hash}");
                }
                continue;
            }
            let (result, expected) = (&reply["result"], &case["result"]);
            match section {
                "transactions" => {
                    assert_eq!(result["raw"], expected["raw"], "{label}");
                    assert_eq!(result["hash"], expected["hash"], "{label}");
                }
                "messages" => {
                    assert_eq!(result["signature"], expected["signature"], "{label}");
                    // A 32-byte message signs as before (#89): the warning
                    // is main's.
                    if label.starts_with("binary-32/") {
                        binary_32 += 1;
                    }
                }
                "typedData" => {
                    assert_eq!(result["signature"], expected["signature"], "{label}");
                    id += 1;
                    let hash = core.call(
                        id,
                        "typed_data.hash",
                        json!({ "typed_data": case["typed_data"] }),
                    );
                    assert_eq!(hash["result"]["hash"], expected["hash"], "{label}");
                    check_view(label, &result["view"], &expected["payload"]);
                    assert_eq!(hash["result"]["view"], result["view"], "{label}");
                    views += 1;
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
                    chunk_key_socs += 1;
                }
            }
        }
    }
    assert!(checked > 150, "only {checked} cases");
    assert!(views > 100, "only {views} views");
    // Two account keys of the abandon mnemonic, and the Bee wallet and one
    // publisher, over eight chunk cases each.
    assert_eq!(refused_account_socs, 16);
    assert_eq!(chunk_key_socs, 16);
    assert_eq!(binary_32, 2);
    // Typed data as JSON text, sent in the frame as written (#87): the core
    // reads each number as JSON.parse does, whatever its spelling.
    for case in vectors["typedDataText"].as_array().unwrap() {
        let Some((_, key)) = keys.iter().find(|(k, _)| *k == case["keyId"]) else {
            continue;
        };
        let label = case["id"].as_str().unwrap();
        let text = case["typed_data_json"].as_str().unwrap();
        let mut send = |method: &str, params: String| {
            id += 1;
            let frame = format!(
                r#"{{"type":"request","id":{id},"method":"{method}","params":{params},"context":{{"caller":"chrome"}}}}"#
            );
            core.send_raw(&raw_frame(1, frame.as_bytes()));
            core.response(id)
        };
        let confirmed = case["result"]
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or(ZERO_HASH);
        let signed = send(
            "sign.typed_data",
            format!(r#"{{"key":{key},"typed_data":{text},"expected_hash":"{confirmed}"}}"#),
        );
        let hashed = send("typed_data.hash", format!(r#"{{"typed_data":{text}}}"#));
        if case["result"]["status"] == "error" {
            for reply in [&signed, &hashed] {
                assert_eq!(
                    reply["error"]["code"], "invalid_argument",
                    "{label}: {reply}"
                );
            }
            continue;
        }
        assert_eq!(
            signed["result"]["signature"], case["result"]["signature"],
            "{label}: {signed}"
        );
        assert_eq!(
            hashed["result"]["hash"], case["result"]["hash"],
            "{label}: {hashed}"
        );
        check_view(label, &signed["result"]["view"], &case["result"]["payload"]);
        assert_eq!(
            hashed["result"]["view"], signed["result"]["view"],
            "{label}"
        );
    }
    // The reports (#88): primary_type and chain_id as given, compared and
    // reported, and nothing signed differently.
    let mut reported = 0;
    for case in vectors["typedDataReports"].as_array().unwrap() {
        let Some((_, key)) = keys.iter().find(|(k, _)| *k == case["keyId"]) else {
            continue;
        };
        let label = case["id"].as_str().unwrap();
        let mut params = json!({ "typed_data": case["typed_data"] });
        for parameter in ["primary_type", "chain_id"] {
            if let Some(value) = case.get(parameter) {
                params[parameter] = value.clone();
            }
        }
        id += 1;
        let hashed = core.call(id, "typed_data.hash", params.clone());
        params["key"] = key.clone();
        params["expected_hash"] = case["result"]["hash"].clone();
        id += 1;
        let signed = core.call(id, "sign.typed_data", params);
        assert_eq!(
            hashed["result"]["hash"], case["result"]["hash"],
            "{label}: {hashed}"
        );
        assert_eq!(
            signed["result"]["signature"], case["result"]["signature"],
            "{label}: {signed}"
        );
        check_view(label, &signed["result"]["view"], &case["result"]["payload"]);
        assert_eq!(
            hashed["result"]["view"], signed["result"]["view"],
            "{label}"
        );
        for report in ["named_type", "chain"] {
            assert_eq!(
                signed["result"]["view"][report], case["report"][report],
                "{label}: {report}"
            );
        }
        reported += 1;
    }
    assert!(reported >= 50, "only {reported} report cases");
}

/// No hash anyone confirmed.
const ZERO_HASH: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// The view is the reference's getPayload (#88), with primaryType as
/// primary_type, in its order: the request's types then EIP712Domain, the
/// domain's fields in canonical order, the message's in declaration order.
/// The reports follow.
fn check_view(label: &str, view: &Value, payload: &Value) {
    let expected = json!({
        "types": payload["types"],
        "domain": payload["domain"],
        "primary_type": payload["primaryType"],
        "message": payload["message"],
    });
    let view = view.as_object().unwrap();
    let shown: serde_json::Map<String, Value> = view
        .iter()
        .take(4)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    // Text, not values: the order of every object counts too.
    assert_eq!(
        serde_json::to_string(&shown).unwrap(),
        serde_json::to_string(&expected).unwrap(),
        "{label}"
    );
    assert_eq!(
        view.keys().skip(4).collect::<Vec<_>>(),
        ["ignored", "named_type", "chain"],
        "{label}"
    );
}

/// #88, test 2: `sign.typed_data` signs only the hash the user confirmed,
/// the one `typed_data.hash` returned. Any other, or none, is
/// `invalid_argument` with no signature, before any key: so still
/// `invalid_argument` with the vault locked.
#[test]
fn typed_data_signs_only_the_confirmed_hash() {
    let (_root, mut core) = unlocked();
    let account = json!({ "kind": "account", "index": 0 });
    let typed = json!({ "domain": { "name": "Ether Mail", "chainId": 1 },
        "types": { "Mail": [{ "name": "contents", "type": "string" }] },
        "message": { "contents": "Hello, Bob!" } });
    let other = json!({ "domain": { "name": "Ether Mail", "chainId": 1 },
        "types": { "Mail": [{ "name": "contents", "type": "string" }] },
        "message": { "contents": "Hello, Eve!" } });
    let hashed = core.call(3, "typed_data.hash", json!({ "typed_data": typed }));
    let hash = hashed["result"]["hash"].as_str().unwrap().to_owned();
    let other_hash =
        core.call(4, "typed_data.hash", json!({ "typed_data": other }))["result"]["hash"]
            .as_str()
            .unwrap()
            .to_owned();
    let mut flipped = hash.clone().into_bytes();
    let last = flipped.len() - 1;
    flipped[last] = if flipped[last] == b'0' { b'1' } else { b'0' };
    let flipped = String::from_utf8(flipped).unwrap();
    let sign = |core: &mut Core, id: u64, expected: Option<&str>| {
        let mut params = json!({ "key": account, "typed_data": typed });
        if let Some(expected) = expected {
            params["expected_hash"] = json!(expected);
        }
        core.call(id, "sign.typed_data", params)
    };
    let signed = sign(&mut core, 5, Some(&hash));
    assert!(signed["result"]["signature"].is_string(), "{signed}");
    assert_eq!(signed["result"]["view"], hashed["result"]["view"]);
    // Either case of hex, as everywhere.
    let upper = format!("0x{}", hash[2..].to_uppercase());
    let again = sign(&mut core, 6, Some(&upper));
    assert_eq!(again["result"], signed["result"], "{again}");
    let refusals = [
        Some(flipped.as_str()),
        Some(other_hash.as_str()),
        Some("0x01"),
        Some(""),
        None,
    ];
    let mut id = 10;
    for locked in [false, true] {
        if locked {
            id += 1;
            assert!(core.call(id, "vault.lock", json!({}))["result"].is_object());
            id += 1;
            let reply = sign(&mut core, id, Some(&hash));
            assert_eq!(reply["error"]["code"], "vault_locked", "{reply}");
        }
        for expected in refusals {
            id += 1;
            let reply = sign(&mut core, id, expected);
            assert_eq!(
                reply["error"]["code"], "invalid_argument",
                "locked {locked}, {expected:?}: {reply}"
            );
            assert!(reply.get("result").is_none(), "{reply}");
        }
    }
}

/// Typed data for the size bound: `count` zeros, each `"0"` in the view, and
/// a string of `len` bytes. 90,000 zeros grow by 180 KB in the view, so its
/// signing reply fills the frame while the request stays inside one.
fn sized(count: usize, len: usize) -> Value {
    json!({
        "domain": {},
        "types": { "M": [{ "name": "v", "type": "uint8[]" }, { "name": "s", "type": "string" }] },
        "message": { "v": vec![0; count], "s": "x".repeat(len) },
    })
}

/// #88, test 3 (deviation `view-size`): one bound for both methods, the
/// signing response at the largest ID. Refused requests are refused before
/// any key is derived: `invalid_argument` with the vault locked too.
/// Request IDs only increase, so the long ones come last.
#[test]
fn typed_data_too_large_to_show_is_refused_at_one_bound() {
    const MAX_ID: u64 = (1 << 53) - 1;
    const FRAME: usize = 1 << 20;
    let (_root, mut core) = unlocked();
    let account = json!({ "kind": "account", "index": 0 });
    // The signing response around its view, as the core writes it.
    let envelope = format!(
        r#"{{"type":"response","id":{MAX_ID},"result":{{"signature":"0x{}","view":}}}}"#,
        "00".repeat(65)
    )
    .len();
    let view_len = |reply: &Value| {
        serde_json::to_string(&reply["result"]["view"])
            .unwrap()
            .len()
    };
    let hash_of = |core: &mut Core, id: u64, data: &Value| {
        core.call(id, "typed_data.hash", json!({ "typed_data": data }))
    };
    // The hash ethers signs, computed outside the core: a refusal below is
    // for the size alone.
    let confirmed = |data: &Value| {
        json!(fc_evm::to_hex(
            &fc_evm::typed_data_hash(&data["domain"], &data["types"], &data["message"]).unwrap()
        ))
    };
    let sign_at = |core: &mut Core, id: u64, data: &Value| {
        core.call(
            id,
            "sign.typed_data",
            json!({ "key": account, "typed_data": data, "expected_hash": confirmed(data) }),
        )
    };
    let refused = |reply: &Value, what: &str| {
        assert_eq!(
            reply["error"]["code"], "invalid_argument",
            "{what}: {reply}"
        );
        assert!(reply.get("result").is_none(), "{what}");
    };
    let probe = hash_of(&mut core, 3, &sized(90_000, 0));
    // The longest view: the signing response at MAX_ID fills the frame.
    let exact = FRAME - envelope - view_len(&probe);
    let fits = sized(90_000, exact);
    let hashed = hash_of(&mut core, 4, &fits);
    assert_eq!(view_len(&hashed), FRAME - envelope);
    // Past the bound: one byte more; by the 71 bytes the hash reply is
    // shorter (its reply at MAX_ID would exactly fill the frame); and by
    // the 15 bytes a one-digit ID saves (its signing reply would fit at
    // ID 6).
    let over: Vec<Value> = [1, 71, 15].map(|more| sized(90_000, exact + more)).to_vec();
    refused(&hash_of(&mut core, 5, &over[2]), "15 more, hashed at 5");
    refused(&sign_at(&mut core, 6, &over[2]), "15 more, signed at 6");
    let mut id = 10;
    for locked in [false, true] {
        if locked {
            id += 1;
            assert!(core.call(id, "vault.lock", json!({}))["result"].is_object());
            assert_eq!(core.event()["event"], "vault.locked");
        }
        for (data, what) in over.iter().zip(["1 more", "71 more", "15 more"]) {
            id += 1;
            refused(&hash_of(&mut core, id, data), what);
            id += 1;
            refused(&sign_at(&mut core, id, data), what);
        }
    }
    id += 1;
    let reunlocked = core.call(
        id,
        "vault.unlock",
        json!({ "password_b64": STANDARD.encode("testpass1") }),
    );
    assert!(reunlocked["result"].is_object(), "{reunlocked}");
    assert_eq!(core.event()["event"], "vault.unlocked");
    // The fitting request signs at a short ID too.
    id += 1;
    let short = sign_at(&mut core, id, &fits);
    assert!(
        short["result"]["signature"].is_string(),
        "{}",
        short["error"]
    );

    // At long IDs: refused while locked and unlocked, and the fitting one
    // signed at the largest ID, filling the frame exactly.
    let mut long = MAX_ID - 8;
    assert!(core.call(long, "vault.lock", json!({}))["result"].is_object());
    assert_eq!(core.event()["event"], "vault.locked");
    for data in &over {
        long += 1;
        refused(&sign_at(&mut core, long, data), "locked, at a long ID");
    }
    long += 1;
    let reunlocked = core.call(
        long,
        "vault.unlock",
        json!({ "password_b64": STANDARD.encode("testpass1") }),
    );
    assert!(reunlocked["result"].is_object(), "{reunlocked}");
    assert_eq!(core.event()["event"], "vault.unlocked");
    for data in &over {
        long += 1;
        refused(&sign_at(&mut core, long, data), "at a long ID");
    }
    assert_eq!(long, MAX_ID - 1);
    let signed = sign_at(&mut core, MAX_ID, &fits);
    assert!(
        signed["result"]["signature"].is_string(),
        "{}",
        signed["error"]
    );
    assert_eq!(serde_json::to_vec(&signed).unwrap().len(), FRAME);
    assert_eq!(signed["result"]["view"], hashed["result"]["view"]);
    assert_eq!(signed["result"]["signature"], short["result"]["signature"]);
}

#[test]
fn bee_and_publisher_keys_sign_only_chunks() {
    let (_root, mut core) = unlocked();
    let tx = json!({ "type": 2, "chain_id": "1", "nonce": "0", "gas_limit": "21000", "to": null,
        "value": "0", "data": "0x", "max_fee_per_gas": "2", "max_priority_fee_per_gas": "1" });
    let typed = json!({ "domain": {}, "types": { "M": [] }, "message": {} });
    let typed_hash =
        core.call(9, "typed_data.hash", json!({ "typed_data": typed }))["result"]["hash"].clone();
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
                json!({ "key": key, "typed_data": typed, "expected_hash": typed_hash }),
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

/// #89: an account key never signs a chunk, at either end of the index
/// range and whether the vault is locked or not: the refusal comes before
/// any key is derived. The Bee wallet and publisher keys still sign.
#[test]
fn account_keys_never_sign_chunks() {
    let (_root, mut core) = unlocked();
    let identifier = format!("0x{}", "00".repeat(32));
    let mut id = 10;
    for locked in [false, true] {
        if locked {
            id += 1;
            assert!(core.call(id, "vault.lock", json!({}))["result"].is_object());
        }
        for index in [0u64, 2_147_483_647] {
            let key = json!({ "kind": "account", "index": index });
            for params in [
                json!({ "key": key, "identifier": identifier, "payload": "0x01" }),
                json!({ "key": key, "identifier": identifier, "payload": "0x01", "span": "0" }),
            ] {
                id += 1;
                let reply = core.call(id, "swarm.sign_soc", params);
                assert_eq!(
                    reply["error"]["code"], "invalid_argument",
                    "locked {locked}, index {index}: {reply}"
                );
                assert!(reply.get("result").is_none(), "{reply}");
            }
        }
        for key in [
            json!({ "kind": "bee_wallet" }),
            json!({ "kind": "publisher", "origin_index": 0 }),
            json!({ "kind": "publisher", "origin_index": 2_147_483_647u64 }),
        ] {
            id += 1;
            let reply = core.call(
                id,
                "swarm.sign_soc",
                json!({ "key": key, "identifier": identifier, "payload": "0x01" }),
            );
            if locked {
                assert_eq!(reply["error"]["code"], "vault_locked", "{key}: {reply}");
            } else {
                assert!(reply["result"]["signature"].is_string(), "{key}: {reply}");
            }
        }
    }
}

#[test]
fn locked_vault_and_malformed_requests() {
    let (_root, mut core) = unlocked();
    assert!(core.call(3, "vault.lock", json!({}))["result"].is_object());
    let account = json!({ "kind": "account", "index": 0 });
    // Chunks are signed by publisher and Bee wallet keys only (#89), so a
    // malformed chunk request names one, and fails for its malformation.
    let publisher = json!({ "kind": "publisher", "origin_index": 0 });
    let reply = core.call(
        4,
        "sign.message",
        json!({ "key": account, "message": "0x01" }),
    );
    assert_eq!(reply["error"]["code"], "vault_locked", "{reply}");
    let reply = core.call(
        5,
        "swarm.sign_soc",
        json!({ "key": publisher, "identifier": format!("0x{}", "00".repeat(32)), "payload": "0x01" }),
    );
    assert_eq!(reply["error"]["code"], "vault_locked", "{reply}");
    // The public hash works while locked.
    let typed = json!({ "domain": { "name": "x" }, "types": { "M": [{ "name": "v", "type": "uint8" }] }, "message": { "v": 1 } });
    let hash = core.call(6, "typed_data.hash", json!({ "typed_data": typed }));
    assert!(
        hash["result"]["hash"].as_str().unwrap().starts_with("0x"),
        "{hash}"
    );
    // Malformed requests fail before the lock is even considered.
    let mut id = 7;
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
            json!({ "key": account, "typed_data": { "domain": {}, "types": {}, "message": {}, "primaryType": "M" }, "expected_hash": ZERO_HASH }),
        ),
        (
            "swarm.sign_soc",
            json!({ "key": publisher, "identifier": "0x01", "payload": "0x01" }),
        ),
        (
            "swarm.sign_soc",
            json!({ "key": publisher, "identifier": format!("0x{}", "00".repeat(32)), "payload": "0x" }),
        ),
        (
            "swarm.sign_soc",
            json!({ "key": publisher, "identifier": format!("0x{}", "00".repeat(32)), "payload": "0x01", "span": 1 }),
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

/// #86: errors that quoted malformed input whole could outgrow one frame:
/// a `uint256` field of 300,000 combining marks became a 2.4 MB error reply,
/// and the core exited 70. `typed_data.hash` needs no unlock. Now every
/// quote is bounded, and the core answers and lives on.
#[test]
fn errors_quoting_malformed_input_stay_small() {
    let (root, data, locks) = dirs();
    let _root = root;
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let marks = "\u{300}".repeat(300_000);
    let quotes = "\"".repeat(400_000);
    let controls = "\u{1}".repeat(150_000);
    let typed = |value: &str| {
        json!({ "typed_data": {
            "domain": { "name": "x" },
            "types": { "M": [{ "name": "v", "type": "uint256" }] },
            "message": { "v": value },
        } })
    };
    let typed_type = |field_type: &str| {
        json!({ "typed_data": {
            "domain": { "name": "x" },
            "types": { "M": [{ "name": "v", "type": field_type }] },
            "message": { "v": 1 },
        } })
    };
    let account = json!({ "kind": "account", "index": 0 });
    let mut tx = json!({ "type": 2, "chain_id": "0x1", "nonce": "0x0", "gas_limit": "0x5208",
        "to": format!("0x{}", "11".repeat(20)), "value": "0x0", "data": "0x",
        "max_fee_per_gas": "0x1", "max_priority_fee_per_gas": "0x1" });
    tx[&controls] = json!(1);
    let mut unknown = json!({ "key": account, "message": "0x01" });
    unknown[&controls] = json!(1);
    let requests = [
        ("typed_data.hash", typed(&marks)),
        ("typed_data.hash", typed(&quotes)),
        ("typed_data.hash", typed_type(&marks)),
        (
            "typed_data.hash",
            typed_type(&format!("uint{}", "0".repeat(500_000))),
        ),
        (
            "typed_data.hash",
            json!({ "typed_data": {
                "domain": { &quotes: 1 },
                "types": { "M": [{ "name": "v", "type": "uint8" }] },
                "message": { "v": 1 },
            } }),
        ),
        ("sign.transaction", json!({ "key": account, "tx": tx })),
        ("sign.message", unknown),
    ];
    for (id, (method, params)) in (2..).zip(requests) {
        let reply = core.call(id, method, params);
        assert_eq!(reply["error"]["code"], "invalid_argument", "{method}");
        let message = reply["error"]["message"].as_str().unwrap();
        assert!(message.len() < 1024, "{method}: {} bytes", message.len());
    }
    // Still running, and still answering.
    let status = core.call(20, "vault.status", json!({}));
    assert_eq!(status["result"]["unlocked"], false, "{status}");
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
    // The same tie with a padded integer significand, which serde_json's
    // float_roundtrip reads as 2^52 + 1.
    let padded = hash(5, &format!("45035996273704965{}e-753", "0".repeat(752)));
    assert_eq!(padded["result"], even["result"], "{padded}");
    // Exponents past std's 0x10000, compensated by the decimal point's
    // position: exactly 1 both ways, and 2^53 + 1 (an unsafe 2^53).
    let one = hash(6, r#""1""#);
    let zeros = "0".repeat(655_359);
    let fraction = hash(7, &format!("0.{zeros}1e+655360"));
    assert_eq!(fraction["result"], one["result"], "{fraction}");
    let integer = hash(8, &format!("1{}e-1048000", "0".repeat(1_048_000)));
    assert_eq!(integer["result"], one["result"], "{integer}");
    let unsafe_one = hash(9, &format!("0.{zeros}9007199254740993e+655375"));
    assert_eq!(
        unsafe_one["error"]["code"], "invalid_argument",
        "{unsafe_one}"
    );
}
