//! Replays the SOC cases of vectors/signing.json (bee-js 13.1.0).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use fc_evm::{checksum_address, parse_bytes, to_hex};
use fc_keys::{Mnemonic, Secp256k1Key, freedom};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

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
            (entry["id"].as_str().unwrap().to_owned(), derived)
        })
        .collect()
}

/// Every case, whatever key signs it: the chunk format doesn't depend on
/// the signer. The core refuses account keys over the wire (design 0002,
/// #89), which is its key policy; this crate signs with any key.
#[test]
fn single_owner_chunks() {
    let keys = keys();
    let vectors = load("signing.json");
    let kinds: BTreeMap<&str, &str> = vectors["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            (
                k["id"].as_str().unwrap(),
                k["key"]["kind"].as_str().unwrap(),
            )
        })
        .collect();
    let cases = vectors["socs"].as_array().unwrap().clone();
    assert!(cases.len() >= 36);
    let mut replayed = BTreeMap::<&str, usize>::new();
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        *replayed
            .entry(kinds[case["keyId"].as_str().unwrap()])
            .or_default() += 1;
        let key = keys[case["keyId"].as_str().unwrap()].signing_key();
        let identifier: [u8; 32] = parse_bytes(case["identifier"].as_str().unwrap(), "id")
            .unwrap()
            .try_into()
            .unwrap();
        let payload = parse_bytes(case["payload"].as_str().unwrap(), "payload").unwrap();
        let span = case
            .get("span")
            .map(|s| s.as_str().unwrap().parse().unwrap());
        let signed = fc_swarm::sign_soc(key, &identifier, span, &payload).unwrap();
        let expected = &case["result"];
        assert_eq!(
            signed.span.to_string(),
            expected["span"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            to_hex(&signed.chunk_address),
            expected["chunkAddress"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            to_hex(&signed.signature),
            expected["signature"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            checksum_address(&signed.owner),
            expected["owner"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            to_hex(&signed.soc_address),
            expected["socAddress"].as_str().unwrap(),
            "{id}"
        );
    }
    for kind in ["account", "bee_wallet", "publisher"] {
        assert!(
            replayed.get(kind).is_some_and(|n| *n >= 8),
            "{kind}: {replayed:?}"
        );
    }
}
