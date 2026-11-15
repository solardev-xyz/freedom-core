//! Replays the chain-switch scenarios of `step: "APR-5c"` in
//! vectors/eip1193.json through the dispatcher (design 0012, APR-5c-2):
//! each request as main sends it, with main's world as the scenario's
//! earlier switches left it. A switch past its checks is rechecked live;
//! the grant's chain the core would write is the reference's `grant.write`
//! (made only when the key has a grant), the chain main is asked to select
//! is the reference's `chain.select`, and each answer is the reference's
//! result, byte for byte. The `chainChanged` events are main's to send.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_eip1193::{Request, Step, start};
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

/// A scenario that switches chains.
fn is_switch(scenario: &Value) -> bool {
    scenario["step"] == "APR-5c"
        && scenario["requests"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["method"] == "wallet_switchEthereumChain")
}

#[test]
fn every_apr5c_switch_scenario_replays() {
    let file = load();
    let (mut scenarios, mut requests, mut switched, mut written) = (0, 0, 0, 0);
    for scenario in file["scenarios"].as_array().unwrap() {
        if !is_switch(scenario) {
            continue;
        }
        scenarios += 1;
        let id = scenario["id"].as_str().unwrap();
        let mut grants = scenario["grants"]["before"].clone();
        let mut world = world_of(&file, scenario);
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
            let effects = recorded["effects"].as_array().unwrap();
            let of = |name: &str| -> Vec<&Value> {
                effects.iter().filter(|e| e["effect"] == name).collect()
            };
            let answer = match step {
                Step::Answer(answer) => {
                    assert!(effects.is_empty(), "{what}: {effects:?}");
                    answer
                }
                Step::Switch(switch) => {
                    switched += 1;
                    assert_eq!(switch.rechecked(true), None, "{what}");
                    let chain = switch.chain_id();
                    // The grant takes the chain only when the key has one.
                    let writes = of("grant.write");
                    let has_grant = key.is_some_and(|key| grants.get(key).is_some());
                    if has_grant {
                        written += 1;
                        assert_eq!(writes.len(), 1, "{what}");
                        assert_eq!(
                            writes[0]["args"],
                            json!({ "op": "updateLastUsed", "key": key, "chainId": chain }),
                            "{what}"
                        );
                        grants[key.unwrap()]["chainId"] = json!(chain);
                    } else {
                        assert!(writes.is_empty(), "{what}");
                    }
                    let selects = of("chain.select");
                    assert_eq!(selects.len(), 1, "{what}");
                    assert_eq!(selects[0]["args"]["chainId"], json!(chain), "{what}");
                    // Main's selection, read by the next request.
                    world["window_chain"] = json!(chain);
                    // Nothing else but main's events.
                    assert_eq!(
                        effects.len(),
                        writes.len() + 1 + of("event").len(),
                        "{what}"
                    );
                    switch.answer()
                }
                other => panic!("{what}: {other:?}"),
            };
            assert_eq!(answer.as_str(), recorded["result"].to_string(), "{what}");
        }
        assert_eq!(grants, scenario["grants"]["after"], "{id}");
    }
    assert_eq!((scenarios, requests, switched, written), (7, 17, 5, 3));
}

/// The rest of the step's scenarios are the connects (`tests/connects.rs`):
/// every APR-5c scenario is replayed by one or the other.
#[test]
fn every_apr5c_scenario_is_a_connect_or_a_switch() {
    let file = load();
    let step: Vec<&Value> = file["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["step"] == "APR-5c")
        .collect();
    let connects = step
        .iter()
        .filter(|s| {
            s["requests"].as_array().unwrap().iter().all(|r| {
                ["eth_requestAccounts", "eth_accounts"].contains(&r["method"].as_str().unwrap())
            })
        })
        .count();
    let switches = step.iter().filter(|s| is_switch(s)).count();
    assert_eq!((step.len(), connects, switches), (20, 13, 7));
}

/// A switch that doesn't hold, and the method main doesn't list.
#[test]
fn a_keyless_switch_and_wallet_add_ethereum_chain() {
    let parse = |method: &str, enabled: bool| {
        Request::parse(&format!(
            r#"{{"method":"{method}","params":[{{"chainId":"0x1"}}],"world":{{"enabled":{enabled},"wallets":[],"networks":{{"1":{{"name":"Ethereum","available":true}}}}}}}}"#
        ))
        .unwrap()
    };
    let answer = |request: &Request, key: Option<&str>| match start(request, key, |_| {
        panic!("no grant read")
    }) {
        Step::Answer(answer) => answer.into_string(),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        answer(&parse("wallet_switchEthereumChain", true), None),
        r#"{"error":{"code":4100,"message":"This page has no address to connect from yet"}}"#
    );
    assert!(answer(&parse("wallet_switchEthereumChain", false), Some("k")).contains("4900"));
    // Not in main's table (page-requests.test.js): no prompt, no switch.
    for (enabled, key) in [(true, Some("k")), (true, None), (false, Some("k"))] {
        assert_eq!(
            answer(&parse("wallet_addEthereumChain", enabled), key),
            r#"{"error":{"code":4200,"message":"Method not supported"}}"#
        );
    }
}
