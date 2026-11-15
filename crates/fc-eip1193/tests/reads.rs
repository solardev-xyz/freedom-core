//! Replays every `step: "APR-5b"` scenario of vectors/eip1193.json through
//! the dispatcher (design 0012, APR-5b): each request as main sends it, with
//! the scenario's world and dApp grant, each chain read checked against the
//! effect the reference made and answered with that effect's answer, and
//! the answer compared, byte for byte, with the reference's result.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_eip1193::{Failure, ReadOutcome, Request, Step, start};
use fc_json::{JsString, JsValue};
use serde_json::{Value, json};

fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/eip1193.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// `world` as main sends it with each request, from the file's fixtures
/// and the scenario's world: the requester is the first document.
fn world_of(file: &Value, scenario: &Value) -> Value {
    let world = &scenario["world"];
    let doc = &world["documents"][0];
    let window = doc["window"].to_string();
    let wallets = world.get("wallets").unwrap_or(&file["wallets"]);
    let available: Vec<&Value> = file["available"].as_array().unwrap().iter().collect();
    let mut networks = serde_json::Map::new();
    for (id, network) in file["networks"].as_object().unwrap() {
        let up = available
            .iter()
            .any(|a| a.as_u64().is_some_and(|a| a.to_string() == *id));
        networks.insert(
            id.clone(),
            json!({ "name": network["name"], "available": up }),
        );
    }
    json!({
        "enabled": world["enabled"],
        "chain": doc["chain"],
        "window_chain": world["windows"][&window],
        "wallets": wallets,
        "networks": networks,
    })
}

/// eip1193.request's params for one of the scenario's requests.
fn params_of(request: &Value, world: &Value) -> String {
    let mut params = serde_json::Map::new();
    params.insert("method".into(), request["method"].clone());
    if let Some(p) = request.get("params") {
        params.insert("params".into(), p.clone());
    }
    params.insert("world".into(), world.clone());
    Value::Object(params).to_string()
}

fn js(value: &Value) -> JsValue {
    fc_json::parse(&value.to_string()).unwrap()
}

#[test]
fn every_apr5b_scenario_replays() {
    let file = load();
    let (mut scenarios, mut requests, mut reads) = (0, 0, 0);
    for scenario in file["scenarios"].as_array().unwrap() {
        if scenario["step"] != "APR-5b" {
            continue;
        }
        scenarios += 1;
        let id = scenario["id"].as_str().unwrap();
        // Reads write nothing.
        assert_eq!(
            scenario["grants"]["before"], scenario["grants"]["after"],
            "{id}"
        );
        let grants = &scenario["grants"]["before"];
        let world = world_of(&file, scenario);
        let key = scenario["world"]["documents"][0]["key"].as_str();
        for (i, recorded) in scenario["requests"].as_array().unwrap().iter().enumerate() {
            requests += 1;
            let what = format!("{id} #{i} {}", recorded["method"]);
            let request = Request::parse(&params_of(recorded, &world)).unwrap();
            let mut asked = Vec::new();
            let step = start(&request, key, |key| {
                asked.push(key.to_owned());
                grants.get(key).map(js)
            });
            let effects = recorded["effects"].as_array().unwrap();
            let answer = match step {
                Step::Answer(answer) => {
                    assert!(effects.is_empty(), "{what}: {effects:?}");
                    answer
                }
                Step::Read(read) => {
                    reads += 1;
                    assert_eq!(effects.len(), 1, "{what}");
                    let effect = &effects[0];
                    assert_eq!(effect["effect"], "chain.request", "{what}");
                    let args = &effect["args"];
                    assert_eq!(read.chain_id, args["chainId"].as_u64().unwrap(), "{what}");
                    assert_eq!(read.method, args["method"], "{what}");
                    assert_eq!(read.params, args["params"].to_string(), "{what}");
                    assert_eq!(read.origin.as_deref(), args["origin"].as_str(), "{what}");
                    let result;
                    let (message, code, data);
                    let outcome = if let Some(answer) = effect.get("answer") {
                        result = answer.get("result").map(Value::to_string);
                        ReadOutcome::Result(result.as_deref())
                    } else {
                        let throws = &effect["throws"];
                        message = JsString::from(throws["message"].as_str().unwrap());
                        code = throws.get("code").map(Value::to_string);
                        data = throws.get("data").map(Value::to_string);
                        ReadOutcome::Failed(Failure {
                            code: code.as_deref(),
                            message: &message,
                            data: data.as_deref(),
                        })
                    };
                    read.answer(outcome)
                }
            };
            assert_eq!(answer.as_str(), recorded["result"].to_string(), "{what}");
            // What main delivers is the dispatcher's answer.
            assert_eq!(recorded["answer"], recorded["result"], "{what}");
            assert!(recorded.get("after").is_none(), "{what}");
            // The grant is read only by `eth_accounts`, for the key, and
            // only while the switch is on.
            let reads_grant = recorded["method"] == "eth_accounts"
                && key.is_some()
                && scenario["world"]["enabled"] == true;
            assert_eq!(
                asked,
                if reads_grant {
                    vec![key.unwrap().to_owned()]
                } else {
                    vec![]
                },
                "{what}"
            );
            // A name-revalidated read registers the keyless answer (APR-5f):
            // the one a document with no key gets.
            if let Some(keyless) = recorded.get("keyless") {
                let step = start(&request, None, |_| panic!("no key, no grant"));
                let Step::Answer(answer) = step else {
                    panic!("{what}")
                };
                assert_eq!(answer.as_str(), keyless.to_string(), "{what}");
            }
        }
    }
    assert_eq!((scenarios, requests, reads), (15, 50, 31));
}

/// The reference's three recorded quirks (design 0012, APR-5): the one a
/// read makes, a node's code 0 with an empty message, replays as recorded.
#[test]
fn a_falsy_code_and_an_empty_message_are_none() {
    let world = r#"{"enabled":true,"window_chain":1,"wallets":[],"networks":{"1":{"name":"Ethereum","available":true}}}"#;
    let request =
        Request::parse(&format!(r#"{{"method":"eth_gasPrice","world":{world}}}"#)).unwrap();
    let Step::Read(read) = start(&request, Some("https://app.example"), |_| None) else {
        panic!()
    };
    let empty = JsString::from("");
    let text = JsString::from("boom");
    for (code, message, data, answer) in [
        (
            Some("0"),
            &empty,
            None,
            r#"{"error":{"code":-32603,"message":"All chain sources failed for chain 1"}}"#,
        ),
        (
            Some("-0.0"),
            &text,
            None,
            r#"{"error":{"code":-32603,"message":"boom"}}"#,
        ),
        (
            Some("\"\""),
            &text,
            None,
            r#"{"error":{"code":-32603,"message":"boom"}}"#,
        ),
        (
            Some("null"),
            &text,
            None,
            r#"{"error":{"code":-32603,"message":"boom"}}"#,
        ),
        (
            Some("false"),
            &text,
            None,
            r#"{"error":{"code":-32603,"message":"boom"}}"#,
        ),
        (
            Some("\"E\""),
            &text,
            Some("null"),
            r#"{"error":{"code":"E","message":"boom","data":null}}"#,
        ),
        (
            None,
            &text,
            Some("{\"a\":1}"),
            r#"{"error":{"code":-32603,"message":"boom","data":{"a":1}}}"#,
        ),
    ] {
        let outcome = ReadOutcome::Failed(Failure {
            code,
            message,
            data,
        });
        assert_eq!(read.answer(outcome).as_str(), answer, "{code:?}");
    }
    // An undefined result is left out, as JSON.stringify leaves it out.
    assert_eq!(read.answer(ReadOutcome::Result(None)).as_str(), "{}");
}

/// A chain the registry doesn't list, and one whose name is empty, are
/// named by their number; a listed chain with a source keeps the error's
/// own text.
#[test]
fn the_chromes_text_for_a_chain_without_a_source() {
    let cases = [
        (
            r#"{"5":{"name":"","available":false}}"#,
            "Chain 5 requires an RPC provider. Please configure one in Settings.",
        ),
        (
            r#"{}"#,
            "Chain 5 requires an RPC provider. Please configure one in Settings.",
        ),
        (r#"{"5":{"name":"Five"}}"#, "boom"),
        (
            r#"{"5":{"name":"Five","available":false}}"#,
            "Five requires an RPC provider. Please configure one in Settings.",
        ),
        (
            r#"{"5":{"name":7,"available":false}}"#,
            "7 requires an RPC provider. Please configure one in Settings.",
        ),
        // A name that doesn't convert throws inside `readError`'s try: the
        // error keeps its own text.
        (r#"{"5":{"name":{"toString":1},"available":false}}"#, "boom"),
    ];
    for (networks, message) in cases {
        let world =
            format!(r#"{{"enabled":true,"window_chain":5,"wallets":[],"networks":{networks}}}"#);
        let request =
            Request::parse(&format!(r#"{{"method":"eth_call","world":{world}}}"#)).unwrap();
        let Step::Read(read) = start(&request, None, |_| None) else {
            panic!()
        };
        assert_eq!(read.origin, None);
        let text = JsString::from("boom");
        let failure = Failure {
            code: Some("-32000"),
            message: &text,
            data: None,
        };
        let expected = format!(r#"{{"error":{{"code":-32000,"message":"{message}"}}}}"#);
        assert_eq!(
            read.answer(ReadOutcome::Failed(failure)).as_str(),
            expected,
            "{networks}"
        );
    }
}

/// `eth_accounts` finds the grant's wallet by JS's `===`, and a method
/// main doesn't list, `eth_sign`, or one without its route yet, is
/// refused as main refuses it.
#[test]
fn accounts_and_refusals() {
    let ask = |method: &str, enabled: bool, wallets: &str, grant: Option<&str>| {
        let world = format!(r#"{{"enabled":{enabled},"wallets":{wallets},"networks":{{}}}}"#);
        let request =
            Request::parse(&format!(r#"{{"method":"{method}","world":{world}}}"#)).unwrap();
        match start(&request, Some("k"), |_| {
            grant.map(|g| fc_json::parse(g).unwrap())
        }) {
            Step::Answer(answer) => answer.into_string(),
            Step::Read(_) => panic!("{method}"),
        }
    };
    let wallets = r#"[null,{"index":"1","address":"0xs"},{"index":1,"address":"0xn"},{"index":2}]"#;
    assert_eq!(
        ask("eth_accounts", true, wallets, Some(r#"{"walletIndex":1}"#)),
        r#"{"result":["0xn"]}"#
    );
    assert_eq!(
        ask(
            "eth_accounts",
            true,
            wallets,
            Some(r#"{"walletIndex":"1"}"#)
        ),
        r#"{"result":["0xs"]}"#
    );
    assert_eq!(
        ask("eth_accounts", true, wallets, Some(r#"{"walletIndex":2}"#)),
        r#"{"result":[null]}"#
    );
    // An absent walletIndex finds the nullish candidate, which is no wallet.
    assert_eq!(
        ask("eth_accounts", true, wallets, Some("{}")),
        r#"{"result":[]}"#
    );
    assert_eq!(
        ask("eth_accounts", true, wallets, Some("0")),
        r#"{"result":[]}"#
    );
    assert_eq!(
        ask("eth_accounts", true, "{}", Some(r#"{"walletIndex":1}"#)),
        r#"{"result":[]}"#
    );
    for (method, answer) in [
        (
            "eth_foo",
            r#"{"error":{"code":4200,"message":"Method not supported"}}"#,
        ),
        (
            "eth_sign",
            r#"{"error":{"code":4200,"message":"eth_sign is deprecated for security reasons"}}"#,
        ),
        (
            "personal_sign",
            r#"{"error":{"code":4200,"message":"Method not supported"}}"#,
        ),
    ] {
        assert_eq!(ask(method, true, "[]", None), answer, "{method}");
    }
    // Main refuses those two before the switch; the rest answer 4900.
    assert!(ask("eth_foo", false, "[]", None).contains("4200"));
    assert!(ask("eth_sign", false, "[]", None).contains("4200"));
    assert!(ask("personal_sign", false, "[]", None).contains("4900"));
}

/// The method table is page-methods.js's Ethereum rows: every name, class
/// and refusal, and the dispatcher serves each row but the refused one.
#[test]
fn the_method_table_is_the_references() {
    let file = load();
    let rows = file["methods"].as_array().unwrap();
    assert_eq!(rows.len(), fc_eip1193::METHODS.len());
    for (row, ours) in rows.iter().zip(fc_eip1193::METHODS) {
        assert_eq!(row["method"], ours.name);
        let class = match ours.class {
            fc_eip1193::Class::PermissionFree => "permission-free",
            fc_eip1193::Class::NameRevalidated => "name-revalidated",
            fc_eip1193::Class::Refused => "refused",
        };
        assert_eq!(row["class"], class, "{}", ours.name);
        let refusal = ours
            .refusal
            .map(|(code, message)| json!({ "code": code, "message": message }));
        assert_eq!(
            row["error"],
            refusal.unwrap_or(Value::Null),
            "{}",
            ours.name
        );
        assert_eq!(row["dispatched"], ours.refusal.is_none(), "{}", ours.name);
    }
}
