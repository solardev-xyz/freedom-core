//! Replays vectors/signing.json (transactions, messages, typed data), which
//! the pinned JS produced with ethers 6.17.0.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use fc_evm::{
    Transaction, ViewRequest, keccak256, parse_bytes, parse_json, parse_unsigned, sign_message,
    sign_typed_data, to_hex, typed_data_hash, typed_data_view,
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

/// No bound on the view's length: the core sets one (#88), tested there.
const UNBOUNDED: usize = usize::MAX;

/// Checks the view of a case the core accepts (#88, test 1): it is the
/// reference's `getPayload`, with `primaryType` as `primary_type`; its own
/// types (less `EIP712Domain`), domain and message hash to the same digest;
/// the message's undeclared top-level keys are in `ignored`, sorted, and in
/// nothing else. Returns the view.
fn check_view(id: &str, data: &Value, request: &ViewRequest<'_>, expected: &Value) -> Value {
    let (domain, types, message) = (&data["domain"], &data["types"], &data["message"]);
    let hashed =
        typed_data_view(domain, types, message, request).unwrap_or_else(|e| panic!("{id}: {e}"));
    assert_eq!(
        to_hex(&hashed.hash),
        expected["hash"].as_str().unwrap(),
        "{id}"
    );
    assert_eq!(
        hashed.hash,
        typed_data_hash(domain, types, message).unwrap(),
        "{id}"
    );
    let view: Value = serde_json::from_str(&hashed.view).unwrap();
    let payload = &expected["payload"];
    for (ours, theirs) in [
        ("types", "types"),
        ("domain", "domain"),
        ("primary_type", "primaryType"),
        ("message", "message"),
    ] {
        assert_eq!(view[ours], payload[theirs], "{id}: {ours}");
    }
    let mut own_types = view["types"].as_object().unwrap().clone();
    assert!(own_types.remove("EIP712Domain").is_some(), "{id}");
    let rehashed =
        typed_data_hash(&view["domain"], &Value::Object(own_types), &view["message"]).unwrap();
    assert_eq!(
        rehashed, hashed.hash,
        "{id}: the view hashes to another digest"
    );
    let root = view["primary_type"].as_str().unwrap();
    let declared: Vec<&str> = view["types"][root]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field["name"].as_str().unwrap())
        .collect();
    let mut ignored: Vec<&str> = message
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .filter(|key| !declared.contains(key))
        .collect();
    ignored.sort_unstable();
    assert_eq!(view["ignored"], serde_json::json!(ignored), "{id}");
    // Exactly these, and in this order (freedom-cored's replay checks the
    // order of every nested object too).
    assert_eq!(view.as_object().unwrap().len(), 7, "{id}");
    assert!(hashed.view.starts_with(r#"{"types":{"#), "{id}");
    view
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
    let mut viewed = 0;
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
        let request = ViewRequest {
            primary_type: None,
            chain_id: None,
            max_len: UNBOUNDED,
        };
        let view = check_view(id, data, &request, &case["result"]);
        // Without parameters: never a match.
        assert_eq!(view["named_type"], "unknown", "{id}");
        let has_chain = domain.get("chainId").is_some_and(|c| !c.is_null());
        assert_eq!(
            view["chain"],
            if has_chain { "unknown" } else { "absent" },
            "{id}"
        );
        viewed += 1;
    }
    assert!(deviations >= 10, "the deviation cases went missing");
    assert!(viewed >= 150, "only {viewed} views");
    // Undeclared keys: top-level ones are listed as ignored, nested ones
    // are nowhere in the view.
    let nested = cases
        .iter()
        .find(|c| c["id"] == "mail-nested-extra-field-ignored/account-0")
        .unwrap();
    let data = &nested["typed_data"];
    let hashed = typed_data_view(
        &data["domain"],
        &data["types"],
        &data["message"],
        &ViewRequest {
            primary_type: None,
            chain_id: None,
            max_len: UNBOUNDED,
        },
    )
    .unwrap();
    let view: Value = serde_json::from_str(&hashed.view).unwrap();
    assert_eq!(view["ignored"], serde_json::json!(["alpha", "zeta"]));
    assert!(!hashed.view.contains("nested"), "{}", hashed.view);
    assert_eq!(
        view["message"]["from"],
        serde_json::json!({ "name": "Cow", "wallet": "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826" })
    );
}

/// The reports (#88, tests 4 and 5): `named_type` and `chain` for the
/// `primary_type` and `chain_id` given, as the design text expects them,
/// while the hash and signature are ethers', whatever they say.
#[test]
fn typed_data_reports() {
    let keys = keys();
    let cases = load("signing.json")["typedDataReports"]
        .as_array()
        .unwrap()
        .clone();
    let mut seen = std::collections::BTreeSet::new();
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        let key = keys[case["keyId"].as_str().unwrap()].signing_key();
        let data = &case["typed_data"];
        let signature = sign_typed_data(key, &data["domain"], &data["types"], &data["message"])
            .unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(
            to_hex(&signature),
            case["result"]["signature"].as_str().unwrap(),
            "{id}"
        );
        let request = ViewRequest {
            primary_type: case.get("primary_type"),
            chain_id: case
                .get("chain_id")
                .map(|c| parse_unsigned(c.as_str().unwrap()).unwrap()),
            max_len: UNBOUNDED,
        };
        let view = check_view(id, data, &request, &case["result"]);
        for report in ["named_type", "chain"] {
            assert_eq!(view[report], case["report"][report], "{id}: {report}");
            seen.insert((report, view[report].as_str().unwrap().to_owned()));
        }
    }
    // Every value of both reports is exercised.
    for (report, value) in [
        ("named_type", "match"),
        ("named_type", "mismatch"),
        ("named_type", "unknown"),
        ("chain", "match"),
        ("chain", "mismatch"),
        ("chain", "absent"),
        ("chain", "unknown"),
    ] {
        assert!(
            seen.contains(&(report, value.to_owned())),
            "{report} {value}"
        );
    }
}

/// Typed data given as JSON text (#87): `parse_json` reads every number as
/// JSON.parse does, so the core signs what ethers signs, padded ties and
/// halfway subnormals included.
#[test]
fn typed_data_text() {
    let keys = keys();
    let cases = load("signing.json")["typedDataText"]
        .as_array()
        .unwrap()
        .clone();
    let mut tested = 0;
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        let key = keys[case["keyId"].as_str().unwrap()].signing_key();
        let data = parse_json(case["typed_data_json"].as_str().unwrap()).unwrap();
        let (domain, types, message) = (&data["domain"], &data["types"], &data["message"]);
        let signed = sign_typed_data(key, domain, types, message);
        tested += 1;
        if expects_error(case) {
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
        let request = ViewRequest {
            primary_type: None,
            chain_id: None,
            max_len: UNBOUNDED,
        };
        check_view(id, &data, &request, &case["result"]);
    }
    assert!(tested >= 30, "the text cases went missing");
}
