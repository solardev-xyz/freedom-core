//! Checks the shape of vectors/eip1193.json, which the approvals
//! reference's page-ethereum.js, page-signing.js and page-sends.js produced
//! (design 0012, APR-5a). The dispatcher's replay comes with each APR-5
//! step; this holds the file to what those replays read.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::{Map, Value};

fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/eip1193.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

const REFERENCE: &str = "7f85551d82bddb1337df73b331785e969d62d1b9";
const STEPS: [&str; 5] = ["APR-5b", "APR-5c", "APR-5d", "APR-5e", "APR-5f"];
const EFFECTS: [&str; 22] = [
    "chain.request",
    "chain.fee_quote",
    "name.check",
    "prompt",
    "token.issue",
    "token.spend",
    "custody",
    "core.typed_data_view",
    "sign.message",
    "sign.typed_data",
    "fees.check",
    "fees.at_approval",
    "send.paused",
    "send.turn",
    "send.waiting",
    "send.sign",
    "send.broadcast",
    "grant.write",
    "chain.select",
    "agent.request",
    "event",
    "world",
];
const CHANGES: [&str; 6] = [
    "navigated",
    "grant-revoked",
    "signing-rule-off",
    "wallet-removed",
    "vault-unlocked",
    "custody-entered",
];

fn object<'a>(value: &'a Value, what: &str) -> &'a Map<String, Value> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("{what}: not an object"))
}

fn array<'a>(value: &'a Value, what: &str) -> &'a Vec<Value> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{what}: not an array"))
}

fn text<'a>(value: &'a Value, what: &str) -> &'a str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{what}: not a string"))
}

/// `{ result }` or `{ error: { code, message, data? } }`, and the error's code.
fn outcome(value: &Value, what: &str) -> Option<i64> {
    let fields = object(value, what);
    assert_eq!(fields.len(), 1, "{what}: {value}");
    if fields.contains_key("result") {
        return None;
    }
    let error = object(&fields["error"], what);
    assert!(
        error
            .keys()
            .all(|key| ["code", "message", "data"].contains(&key.as_str())),
        "{what}: {value}"
    );
    text(&error["message"], what);
    Some(
        error["code"]
            .as_i64()
            .unwrap_or_else(|| panic!("{what}: no code")),
    )
}

fn quantity(value: &Value, what: &str) -> u128 {
    let text = text(value, what);
    match text.strip_prefix("0x") {
        Some(hex) => u128::from_str_radix(hex, 16).unwrap(),
        None => text.parse().unwrap(),
    }
}

#[test]
fn meta_and_fixtures() {
    let vectors = load();
    let meta = object(&vectors["meta"], "meta");
    assert_eq!(meta["freedomBrowserCommit"], REFERENCE);
    assert_eq!(meta["packages"]["ethers"], "6.17.0");
    for key in ["scenario", "request", "effect"] {
        text(&vectors["format"][key], "format");
    }
    assert!(vectors["now"].as_u64().is_some());
    let wallets = array(&vectors["wallets"], "wallets");
    assert_eq!(
        wallets[0]["address"], "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        "the first test wallet of abandon … about"
    );
    for wallet in wallets {
        assert!(wallet["index"].as_u64().is_some());
        text(&wallet["address"], "wallet");
        text(&wallet["type"], "wallet");
    }
    for (id, network) in object(&vectors["networks"], "networks") {
        id.parse::<u64>().unwrap();
        text(&network["name"], "network");
    }
    assert!(!array(&vectors["available"], "available").is_empty());
}

#[test]
fn method_table() {
    let vectors = load();
    let mut dispatched = BTreeSet::new();
    for row in array(&vectors["methods"], "methods") {
        let method = text(&row["method"], "method");
        let class = text(&row["class"], method);
        assert!(
            ["permission-free", "name-revalidated", "refused"].contains(&class),
            "{method}: {class}"
        );
        assert!(row["timeoutMs"].as_u64().is_some(), "{method}");
        if row["dispatched"] == true {
            assert!(row["error"].is_null(), "{method}");
            dispatched.insert(method);
        } else {
            assert_eq!(class, "refused", "{method}");
            assert_eq!(outcome(&json_error(&row["error"]), method), Some(4200));
        }
    }
    // 0011's dispatcher: the reads (23 through the chain machine), the
    // connects, the signatures and the send.
    assert_eq!(dispatched.len(), 31);
    for method in [
        "eth_chainId",
        "net_version",
        "eth_accounts",
        "eth_call",
        "eth_requestAccounts",
        "wallet_switchEthereumChain",
        "personal_sign",
        "eth_signTypedData_v4",
        "eth_sendTransaction",
    ] {
        assert!(dispatched.contains(method), "{method}");
    }
}

fn json_error(error: &Value) -> Value {
    serde_json::json!({ "error": error })
}

#[test]
fn scenarios_have_the_replays_shape() {
    let vectors = load();
    let dispatched: BTreeSet<&str> = array(&vectors["methods"], "methods")
        .iter()
        .filter(|row| row["dispatched"] == true)
        .map(|row| text(&row["method"], "method"))
        .collect();
    let mut ids = BTreeSet::new();
    let mut steps = BTreeMap::new();
    let mut methods = BTreeSet::new();
    let mut codes = BTreeSet::new();
    for scenario in array(&vectors["scenarios"], "scenarios") {
        let id = text(&scenario["id"], "id");
        assert!(ids.insert(id), "{id}: twice");
        let from = text(&scenario["from"], id);
        assert!(
            from.starts_with("design 00")
                || from.starts_with("page-") && from.contains(".test.js:"),
            "{id}: {from}"
        );
        let step = text(&scenario["step"], id);
        assert!(STEPS.contains(&step), "{id}: {step}");
        *steps.entry(step).or_insert(0) += 1;
        let world = object(&scenario["world"], id);
        let documents = array(&world["documents"], id);
        assert!(!documents.is_empty(), "{id}");
        for document in documents {
            text(&document["id"], id);
            assert!(
                document["key"].is_string() || document["key"].is_null(),
                "{id}"
            );
            assert!(document["window"].as_u64().is_some(), "{id}");
        }
        for flag in ["enabled", "vault", "custody"] {
            assert!(world[flag].is_boolean(), "{id}: {flag}");
        }
        object(&world["windows"], id);
        let grants = object(&scenario["grants"], id);
        for side in ["before", "after"] {
            assert!(
                grants[side].is_object() || grants[side].is_null(),
                "{id}: {side}"
            );
        }
        let requests = array(&scenario["requests"], id);
        assert!(!requests.is_empty(), "{id}");
        for request in requests {
            let method = text(&request["method"], id);
            assert!(dispatched.contains(method), "{id}: {method}");
            methods.insert(method);
            let what = format!("{id} {method}");
            for effect in array(&request["effects"], &what).iter().chain(
                request
                    .get("after")
                    .map_or(&vec![], |after| array(after, &what)),
            ) {
                check_effect(effect, &what);
            }
            if let Some(code) = outcome(&request["result"], &what) {
                codes.insert(code);
            }
            if request["answer"] != serde_json::json!({ "gone": true }) {
                outcome(&request["answer"], &what);
            }
            if let Some(keyless) = request.get("keyless") {
                outcome(keyless, &what);
            }
        }
    }
    for step in STEPS {
        assert!(
            steps.get(step).copied().unwrap_or(0) >= 5,
            "{step}: {steps:?}"
        );
    }
    assert_eq!(methods, dispatched, "every dispatched method is replayed");
    // The EIP-1193 codes main returns today, and a read's own (a revert's 3).
    for code in [3, 4001, 4100, 4200, 4900, 4902, -32002, -32602, -32603] {
        assert!(codes.contains(&code), "{code}: {codes:?}");
    }
}

fn check_effect(effect: &Value, what: &str) {
    let fields = object(effect, what);
    let name = text(&fields["effect"], what);
    assert!(EFFECTS.contains(&name), "{what}: {name}");
    if name == "world" {
        let change = text(&fields["change"], what);
        let kind = change.split(':').next().unwrap_or_default();
        assert!(CHANGES.contains(&kind), "{what}: {change}");
        assert_eq!(fields.len(), 2, "{what}: {effect}");
        return;
    }
    object(&fields["args"], what);
    assert!(
        !(fields.contains_key("answer") && fields.contains_key("throws")),
        "{what}: {effect}"
    );
    if let Some(thrown) = fields.get("throws") {
        text(&thrown["message"], what);
    }
    let allowed = ["effect", "args", "answer", "throws", "refused"];
    assert!(
        fields.keys().all(|key| allowed.contains(&key.as_str())),
        "{what}: {effect}"
    );
    if name == "prompt" {
        text(&fields["args"]["kind"], what);
        object(&fields["args"]["view"], what);
        let decision = object(&fields["answer"], what);
        assert!(
            decision.contains_key("approve")
                || decision.contains_key("closed")
                || decision.contains_key("error"),
            "{what}: {effect}"
        );
    }
}

/// The prepared send (APR-5e): every transaction main signs for a page
/// carries the type's fee fields, the chain and the gas limit, never a
/// nonce, and its gas limit is the estimate read just before plus 20%.
#[test]
fn prepared_sends() {
    let vectors = load();
    let mut sends = 0;
    for scenario in array(&vectors["scenarios"], "scenarios") {
        for request in array(&scenario["requests"], "requests") {
            let effects = array(&request["effects"], "effects");
            let mut estimate = None;
            for effect in effects {
                if effect["effect"] == "chain.request"
                    && effect["args"]["method"] == "eth_estimateGas"
                {
                    estimate = effect["answer"]["result"]
                        .as_str()
                        .map(|hex| quantity(&Value::String(hex.to_owned()), "estimate"));
                }
                if effect["effect"] != "send.sign" {
                    continue;
                }
                sends += 1;
                let tx = object(&effect["args"]["tx"], "tx");
                let mut keys: Vec<&str> = tx.keys().map(String::as_str).collect();
                keys.sort_unstable();
                let legacy = ["chainId", "data", "gasLimit", "gasPrice", "to", "value"];
                let eip1559 = [
                    "chainId",
                    "data",
                    "gasLimit",
                    "maxFeePerGas",
                    "maxPriorityFeePerGas",
                    "to",
                    "value",
                ];
                assert!(keys == legacy || keys == eip1559, "{keys:?}");
                let gas = quantity(&tx["gasLimit"], "gasLimit");
                assert_eq!(Some(gas), estimate.map(|e| e * 120 / 100), "{tx:?}");
            }
        }
    }
    assert!(sends >= 10, "{sends}");
}
