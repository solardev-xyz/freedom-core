//! Replays vectors/signing.json's `transactionDecoding`: every input, as
//! the intent store checks it with ethers 6.17.0's `Transaction.from`, and
//! every accepted transaction's fields, digest, hash and signer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_evm::{DecodeError, SignedTx, decode_signed, parse_bytes, to_hex};
use serde_json::{Value, json};

fn cases() -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/signing.json");
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    vectors["transactionDecoding"].as_array().unwrap().clone()
}

/// The vectors' name for an answer.
fn verdict(result: &Result<SignedTx, DecodeError>) -> Value {
    match result {
        Ok(_) => json!({ "verdict": "accepted" }),
        Err(DecodeError::Undecodable) => json!({ "verdict": "undecodable" }),
        Err(DecodeError::Unsigned) => json!({ "verdict": "unsigned" }),
        Err(DecodeError::UnsupportedType(t)) => json!({ "verdict": "unsupported_type", "type": t }),
        Err(DecodeError::Unserializable) => json!({ "verdict": "unserializable" }),
        Err(DecodeError::NotCanonical) => json!({ "verdict": "not_canonical" }),
    }
}

/// The fields as the generator records ethers' (`fieldsOf`).
fn fields(tx: &SignedTx) -> Value {
    let decimal = |value: &fc_evm::U256| value.to_decimal();
    json!({
        "type": tx.tx_type(),
        "chain_id": decimal(tx.chain_id()),
        "nonce": tx.nonce(),
        "gas_limit": decimal(tx.gas_limit()),
        "to": tx.to().map(|to| to_hex(to)),
        "value": decimal(tx.value()),
        "data": to_hex(tx.data()),
        "gas_price": tx.gas_price().map(decimal),
        "max_fee_per_gas": tx.eip1559_fees().map(|(max, _)| decimal(max)),
        "max_priority_fee_per_gas": tx.eip1559_fees().map(|(_, priority)| decimal(priority)),
        "access_list": tx.access_list().map(|list| list
            .iter()
            .map(|entry| json!({
                "address": to_hex(&entry.address),
                "storage_keys": entry.storage_keys.iter().map(|key| to_hex(key)).collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>()),
        "v": tx.v().map(|v| v.to_decimal()),
        "y_parity": tx.y_parity(),
        "r": to_hex(tx.r()),
        "s": to_hex(tx.s()),
    })
}

#[test]
fn every_input_as_ethers_and_the_store_read_it() {
    let cases = cases();
    assert!(cases.len() >= 200, "{} cases", cases.len());
    let mut seen = std::collections::BTreeMap::new();
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        let raw = parse_bytes(case["raw"].as_str().unwrap(), "raw").unwrap();
        let result = decode_signed(&raw);
        let expected = &case["result"];
        // A deviation gives the core's answer beside ethers'.
        let want = match case.get("deviation") {
            Some(deviation) => {
                assert_eq!(deviation, "tx-other-types", "{id}");
                case["core"].clone()
            }
            None => {
                let mut want = json!({ "verdict": expected["verdict"] });
                if let Some(t) = expected.get("type") {
                    want["type"] = t.clone();
                }
                want
            }
        };
        assert_eq!(verdict(&result), want, "{id}");
        *seen
            .entry(expected["verdict"].as_str().unwrap().to_owned())
            .or_insert(0) += 1;
        let Ok(tx) = result else { continue };
        assert_eq!(fields(&tx), expected["tx"], "{id}");
        assert_eq!(to_hex(tx.digest()), expected["digest"], "{id}");
        assert_eq!(to_hex(tx.hash()), expected["hash"], "{id}");
        let signer = tx.signer().map(|address| to_hex(&address));
        assert_eq!(json!(signer), expected["signer"], "{id}");
    }
    // Every answer occurs, and a signer is missing for some accepted ones.
    for verdict in [
        "accepted",
        "undecodable",
        "unsigned",
        "unsupported_type",
        "unserializable",
        "not_canonical",
    ] {
        assert!(seen.contains_key(verdict), "no {verdict} case: {seen:?}");
    }
    assert!(
        cases
            .iter()
            .any(|case| case["result"]["signer"].is_null()
                && case["result"]["verdict"] == "accepted")
    );
}

/// A high `s` is accepted on a legacy transaction and keeps its signer,
/// as ethers' `getCanonical` makes it; on EIP-1559 it can't be serialized.
#[test]
fn high_s_follows_ethers() {
    let cases = cases();
    let find = |id: &str| {
        cases
            .iter()
            .find(|case| case["id"] == id)
            .unwrap_or_else(|| panic!("{id}"))
    };
    let base = &find("legacy-eip155")["result"]["signer"];
    for id in ["legacy-high-s", "pre155-high-s"] {
        let case = find(id);
        let tx =
            decode_signed(&parse_bytes(case["raw"].as_str().unwrap(), "raw").unwrap()).unwrap();
        assert_eq!(json!(tx.signer().map(|a| to_hex(&a))), *base, "{id}");
    }
    let case = find("eip1559-high-s");
    assert_eq!(
        decode_signed(&parse_bytes(case["raw"].as_str().unwrap(), "raw").unwrap()),
        Err(DecodeError::Unserializable)
    );
}
