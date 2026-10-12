//! Replays vectors/signing.json (transactions, messages, typed data), which
//! the pinned JS produced with ethers 6.17.0.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use fc_evm::{
    Transaction, keccak256, parse_bytes, sign_message, sign_typed_data, to_hex, typed_data_hash,
};
use fc_keys::{Mnemonic, Secp256k1Key, freedom};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Every key the vectors use, derived by fc-keys.
fn keys() -> BTreeMap<String, Secp256k1Key> {
    let mnemonics: BTreeMap<String, String> = load("keys.json")["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["id"].as_str().unwrap().to_owned(),
                v["mnemonic"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    load("signing.json")["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let seed = Mnemonic::parse(&mnemonics[entry["mnemonicId"].as_str().unwrap()])
                .unwrap()
                .to_seed();
            let key = &entry["key"];
            let derived = match key["kind"].as_str().unwrap() {
                "account" => {
                    freedom::derive_user_wallet(&seed, key["index"].as_u64().unwrap() as u32)
                }
                "bee_wallet" => freedom::derive_all(&seed).map(|all| all.bee_wallet),
                "publisher" => {
                    freedom::derive_publisher(&seed, key["origin_index"].as_u64().unwrap() as u32)
                }
                other => panic!("unknown key kind {other}"),
            }
            .unwrap();
            assert_eq!(
                derived.address().to_string(),
                entry["address"].as_str().unwrap()
            );
            (entry["id"].as_str().unwrap().to_owned(), derived)
        })
        .collect()
}

fn expects_error(entry: &Value) -> bool {
    entry["result"]["status"] == "error" || entry.get("deviation").is_some()
}

#[test]
fn transactions() {
    let keys = keys();
    let cases = load("signing.json")["transactions"]
        .as_array()
        .unwrap()
        .clone();
    assert!(cases.len() >= 30);
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        let key = keys[case["keyId"].as_str().unwrap()].signing_key();
        let signed = Transaction::from_json(&case["tx"]).and_then(|tx| tx.sign(key));
        if expects_error(case) {
            assert!(
                signed.is_err(),
                "{id}: ethers rejected it, the core signed it"
            );
            continue;
        }
        let signed = signed.unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(
            to_hex(&signed.raw),
            case["result"]["raw"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            to_hex(&signed.hash),
            case["result"]["hash"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(signed.hash, keccak256(&signed.raw));
    }
}

#[test]
fn messages() {
    let keys = keys();
    for case in load("signing.json")["messages"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let key = keys[case["keyId"].as_str().unwrap()].signing_key();
        let message = parse_bytes(case["message"].as_str().unwrap(), "message").unwrap();
        let signature = sign_message(key, &message).unwrap();
        assert_eq!(
            to_hex(&signature),
            case["result"]["signature"].as_str().unwrap(),
            "{id}"
        );
    }
}

#[test]
fn typed_data() {
    let keys = keys();
    let cases = load("signing.json")["typedData"]
        .as_array()
        .unwrap()
        .clone();
    let mut deviations = 0;
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        let key = keys[case["keyId"].as_str().unwrap()].signing_key();
        let data = &case["typed_data"];
        let (domain, types, message) = (&data["domain"], &data["types"], &data["message"]);
        let signed = sign_typed_data(key, domain, types, message);
        if expects_error(case) {
            if case.get("deviation").is_some() {
                // ethers signs these; the core must not (design 0002).
                assert_eq!(case["result"]["status"], "success", "{id}");
                deviations += 1;
            }
            assert!(
                signed.is_err(),
                "{id}: expected a rejection, the core signed it"
            );
            continue;
        }
        let signature = signed.unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(
            to_hex(&signature),
            case["result"]["signature"].as_str().unwrap(),
            "{id}"
        );
        let hash = typed_data_hash(domain, types, message).unwrap();
        assert_eq!(
            to_hex(&hash),
            case["result"]["hash"].as_str().unwrap(),
            "{id}"
        );
    }
    assert!(deviations >= 10, "the deviation cases went missing");
}
