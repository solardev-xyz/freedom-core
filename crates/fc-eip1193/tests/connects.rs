//! Replays the connect scenarios of `step: "APR-5c"` in vectors/eip1193.json
//! through the dispatcher (design 0012, APR-5c-1): each request as main
//! sends it, a connected key's recheck answered live, each prompt checked
//! against the effect the reference made (its kind and view, byte for
//! byte) and answered as main would answer the core's `approval.request`
//! from that effect's decision, with main's world as it stands then. Each
//! grant the core would write is the reference's `grant.write`, and each
//! answer is the reference's result, byte for byte. The agent's route
//! (`agent.request`) is main's and is skipped; it declined every one.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_eip1193::connect::Decided;
use fc_eip1193::{Connect, Crossed, Prompts, Request, Step, start};
use fc_json::JsValue;
use serde_json::{Value, json};

fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/eip1193.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// `world` as main sends it, from the file's fixtures and the scenario's
/// world (the requester first), with the active account.
fn world_of(file: &Value, scenario: &Value) -> Value {
    let world = &scenario["world"];
    let doc = &world["documents"][0];
    let available = file["available"].as_array().unwrap();
    let networks: serde_json::Map<String, Value> = file["networks"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(id, network)| {
            let up = available
                .iter()
                .any(|a| a.as_u64().is_some_and(|a| a.to_string() == *id));
            (
                id.clone(),
                json!({ "name": network["name"], "available": up }),
            )
        })
        .collect();
    json!({
        "enabled": world["enabled"],
        "chain": doc["chain"],
        "window_chain": world["windows"][&doc["window"].to_string()],
        "wallets": world.get("wallets").unwrap_or(&file["wallets"]),
        "networks": networks,
        "active": world["active"],
    })
}

/// Main's world after the changes a scenario makes while a prompt is open.
fn changed(mut world: Value, effects: &[Value]) -> Value {
    for effect in effects.iter().filter(|e| e["effect"] == "world") {
        if let Some(index) = effect["change"]
            .as_str()
            .unwrap()
            .strip_prefix("wallet-removed:")
        {
            let index: u64 = index.parse().unwrap();
            let wallets = world["wallets"].as_array_mut().unwrap();
            wallets.retain(|w| w["index"].as_u64() != Some(index));
        }
    }
    world
}

/// The approval.request answer main sends for a recorded decision.
fn answer_of(prompt: &str, handle: &str, decision: &Value, world: &Value) -> String {
    let answer = if decision.get("approve").is_some() {
        let mut answer = json!({
            "prompt": prompt, "handle": handle,
            "approve": decision["approve"], "choices": decision["choices"],
        });
        if decision["approve"] == true {
            answer["world"] = world.clone();
        }
        answer
    } else if let Some(reason) = decision.get("closed") {
        json!({ "prompt": prompt, "closed": reason })
    } else {
        assert_eq!(decision["error"]["code"], -32002, "{decision}");
        json!({ "prompt": prompt, "busy": true })
    };
    answer.to_string()
}

fn is_connect(scenario: &Value) -> bool {
    scenario["step"] == "APR-5c"
        && scenario["requests"].as_array().unwrap().iter().all(|r| {
            ["eth_requestAccounts", "eth_accounts"].contains(&r["method"].as_str().unwrap())
        })
}

#[test]
fn every_apr5c_connect_scenario_replays() {
    let file = load();
    let mut prompts = Prompts::new();
    let mut handles = 0u32;
    let mut handle = || {
        handles += 1;
        format!("{handles:064x}")
    };
    let (mut scenarios, mut requests, mut asked) = (0, 0, 0);
    for scenario in file["scenarios"].as_array().unwrap() {
        if !is_connect(scenario) {
            continue;
        }
        scenarios += 1;
        let id = scenario["id"].as_str().unwrap();
        let mut grants = scenario["grants"]["before"].clone();
        let world = world_of(&file, scenario);
        let key = scenario["world"]["documents"][0]["key"].as_str();
        for (i, recorded) in scenario["requests"].as_array().unwrap().iter().enumerate() {
            requests += 1;
            let what = format!("{id} #{i} {}", recorded["method"]);
            let mut params = json!({ "method": recorded["method"], "world": world });
            if let Some(p) = recorded.get("params") {
                params["params"] = p.clone();
            }
            let request = Request::parse(&params.to_string()).unwrap();
            let lookup = grants.clone();
            let step = start(&request, key, |key| {
                lookup
                    .get(key)
                    .map(|g| fc_json::parse(&g.to_string()).unwrap())
            });
            // The agent's route is main's.
            let effects: Vec<Value> = recorded["effects"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|e| {
                    if e["effect"] == "agent.request" {
                        assert_eq!(e["answer"], json!({ "handled": false }), "{what}");
                        false
                    } else {
                        true
                    }
                })
                .cloned()
                .collect();
            let writes: Vec<&Value> = effects
                .iter()
                .filter(|e| e["effect"] == "grant.write")
                .collect();
            let answer = match step {
                Step::Answer(answer) => {
                    assert!(effects.is_empty(), "{what}: {effects:?}");
                    answer
                }
                Step::Read(_) | Step::Switch(_) | Step::Sign(_) | Step::Send(_) => {
                    panic!("{what}: not a connect")
                }
                Step::Connect(Connect::Connected(connected)) => {
                    let rechecked = connected.answer(true);
                    assert!(rechecked.touch, "{what}");
                    assert_eq!(writes.len(), 1, "{what}");
                    assert_eq!(
                        writes[0]["args"],
                        json!({ "op": "updateLastUsed", "key": key }),
                        "{what}"
                    );
                    rechecked.answer
                }
                Step::Connect(Connect::Ask(ask)) => {
                    asked += 1;
                    let prompt = effects.iter().find(|e| e["effect"] == "prompt").unwrap();
                    assert_eq!(ask.kind(), prompt["args"]["kind"], "{what}");
                    assert_eq!(ask.view(), prompt["args"]["view"].to_string(), "{what}");
                    let then = changed(world.clone(), &effects);
                    // Picks the prompt refused while it stayed open: main's
                    // to refuse, and refused here too if relayed.
                    for pick in prompt["refused"].as_array().into_iter().flatten() {
                        let id = prompts.issue(rand_bytes(&mut handle)).unwrap();
                        let decision = json!({ "approve": true, "choices": pick });
                        let text = answer_of(&id.hex(), &handle(), &decision, &then);
                        let decision = prompts.accept(&id, &text).unwrap();
                        assert_eq!(ask.decide(decision), Err(Crossed), "{what}: {pick}");
                    }
                    let id = prompts.issue(rand_bytes(&mut handle)).unwrap();
                    let text = answer_of(&id.hex(), &handle(), &prompt["answer"], &then);
                    match ask.decide(prompts.accept(&id, &text).unwrap()).unwrap() {
                        Decided::Answer(answer) => {
                            assert!(writes.is_empty(), "{what}: no grant without a decision");
                            answer
                        }
                        Decided::Grant(grant) => {
                            assert_eq!(writes.len(), 1, "{what}");
                            let args = &writes[0]["args"];
                            assert_eq!(
                                args,
                                &json!({
                                    "op": "grantPermission", "key": key,
                                    "walletIndex": grant.account, "chainId": grant.chain_id,
                                }),
                                "{what}"
                            );
                            let written = writes[0].get("throws").is_none();
                            if written {
                                if grants.is_null() {
                                    grants = json!({});
                                }
                                grants[key.unwrap()] = json!({ "walletIndex": grant.account });
                            }
                            grant.answer(written)
                        }
                    }
                }
            };
            assert_eq!(answer.as_str(), recorded["result"].to_string(), "{what}");
        }
    }
    assert_eq!((scenarios, requests, asked), (13, 14, 11));
}

/// 16 bytes, distinct for each call.
fn rand_bytes(counter: &mut impl FnMut() -> String) -> [u8; 16] {
    let text = counter();
    let mut bytes = [0u8; 16];
    for (i, b) in text.bytes().rev().take(16).enumerate() {
        bytes[i] = b;
    }
    bytes
}

/// `eth_accounts` reads what a connect wrote; a keyless connect asks no one.
#[test]
fn a_keyless_document_gets_4100_before_any_prompt() {
    let request = Request::parse(
        r#"{"method":"eth_requestAccounts","world":{"enabled":true,"wallets":[{"index":0,"address":"0xa"}],"networks":{}}}"#,
    )
    .unwrap();
    let mut read = false;
    match start(&request, None, |_| {
        read = true;
        Some(JsValue::Null)
    }) {
        Step::Answer(answer) => assert_eq!(
            answer.as_str(),
            r#"{"error":{"code":4100,"message":"This page has no address to connect from yet"}}"#
        ),
        other => panic!("{other:?}"),
    }
    assert!(!read, "no grant read");
    // With the switch off, 4900 first.
    let off = Request::parse(
        r#"{"method":"eth_requestAccounts","world":{"enabled":false,"wallets":[],"networks":{}}}"#,
    )
    .unwrap();
    match start(&off, None, |_| None) {
        Step::Answer(answer) => assert!(answer.as_str().contains("4900")),
        other => panic!("{other:?}"),
    }
}
