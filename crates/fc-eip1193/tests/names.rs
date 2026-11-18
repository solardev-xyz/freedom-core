//! Replays the `step: "APR-5f"` scenarios of vectors/eip1193.json at the
//! logic level (design 0012, APR-5f): each document's name binding from
//! its key and transport key, each recorded `keyless` answer, the checks
//! the reference makes before it first reads the key's grant, and for
//! `eth_accounts` the answer and whether its last check follows, from
//! the scripted `name.check` answers. The daemon replay
//! (`freedom-cored/tests/eip1193_names.rs`) runs the whole flow, with the
//! core's own naming.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_eip1193::names::{self, Binding};
use fc_eip1193::{Request, Step, start};
use serde_json::{Value, json};

fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/eip1193.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// naming's result for a check the reference recorded: the IPNS key, or
/// other content.
fn content(serves: bool, key: &str) -> fc_json::JsValue {
    let (protocol, decoded) = if serves {
        ("ipns", key)
    } else {
        ("ipfs", "QmW81r84Aihiqqi2Jw6nM1LnpeMfRCenRxtjwHNkXVkZYa")
    };
    fc_json::parse(&json!({ "type": "ok", "protocol": protocol, "decoded": decoded }).to_string())
        .unwrap()
}

#[test]
fn every_apr5f_scenario_replays_at_the_logic_level() {
    let file = load();
    let (mut scenarios, mut requests, mut checks) = (0, 0, 0);
    for scenario in file["scenarios"].as_array().unwrap() {
        if scenario["step"] != "APR-5f" {
            continue;
        }
        scenarios += 1;
        let id = scenario["id"].as_str().unwrap();
        let doc = &scenario["world"]["documents"][0];
        let key = doc["key"].as_str().unwrap();
        let transport = doc["transportKey"].as_str().unwrap();
        let binding = Binding::of(key, Some(transport)).unwrap();
        assert_eq!(binding.name(), key, "{id}");
        assert!(binding.resolvable(), "{id}");
        let ipns_key = transport.strip_prefix("ipns://").unwrap();
        let mut ended = false;
        for (i, recorded) in scenario["requests"].as_array().unwrap().iter().enumerate() {
            requests += 1;
            let method = recorded["method"].as_str().unwrap();
            let what = format!("{id} #{i} {method}");
            if let Some(keyless) = recorded.get("keyless") {
                assert_eq!(
                    names::keyless(method).as_str(),
                    keyless.to_string(),
                    "{what}"
                );
            }
            // The checks, each judged as the core judges naming's answer;
            // main's own effects (the agent's route, custody) set aside.
            let effects: Vec<&Value> = recorded["effects"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|e| !["agent.request", "custody"].contains(&e["effect"].as_str().unwrap()))
                .collect();
            let verdicts: Vec<bool> = effects
                .iter()
                .filter(|e| e["effect"] == "name.check")
                .map(|e| binding.served_by(Some(&content(e["answer"] == true, ipns_key))))
                .collect();
            for (effect, verdict) in effects
                .iter()
                .filter(|e| e["effect"] == "name.check")
                .zip(&verdicts)
            {
                assert_eq!(effect["args"]["name"], key, "{what}");
                assert_eq!(effect["args"]["transportKey"], transport, "{what}");
                assert_eq!(json!(verdict), effect["answer"], "{what}");
            }
            checks += verdicts.len();
            let leading = effects
                .iter()
                .take_while(|e| e["effect"] == "name.check")
                .count();
            match names::checks_first(method) {
                // Each check before the grant is read, cut short by a name
                // that moved, or none once the binding has ended (the
                // recorded check then is the generator's stand-in's: the
                // reference resolves nothing for a document with no key).
                Some(first) if !ended => {
                    let moved = verdicts.iter().position(|v| !v);
                    let expected =
                        moved.map_or(usize::from(first), |at| (at + 1).min(usize::from(first)));
                    assert!(leading >= expected, "{what}: {leading} < {expected}");
                }
                Some(_) => {
                    assert_eq!(recorded["result"], json!({ "result": [] }), "{what}");
                }
                // A switch: its params' checks, then one name check.
                None if method == "wallet_switchEthereumChain" => {
                    assert_eq!(verdicts.len(), 1, "{what}");
                }
                // The send's route is APR-5e's: its checks wait for it.
                None if method == "eth_sendTransaction" => {}
                // A permission-free read: no check.
                None => assert!(verdicts.is_empty(), "{what}"),
            }
            if method == "eth_accounts" && !ended && verdicts[0] {
                let mut params = json!({ "method": method, "world": {
                    "enabled": true, "wallets": file["wallets"], "networks": {},
                } });
                params["params"] = json!([]);
                let request = Request::parse(&params.to_string()).unwrap();
                let grants = &scenario["grants"]["before"];
                let step = start(&request, Some(key), |key| {
                    grants
                        .get(key)
                        .map(|g| fc_json::parse(&g.to_string()).unwrap())
                });
                let Step::Answer(answer) = step else {
                    panic!("{what}");
                };
                // The account goes only after one more check that holds.
                assert!(names::reveals_account(&answer), "{what}");
                assert_eq!(verdicts.len(), 2, "{what}");
                let expected = if verdicts[1] {
                    answer.as_str().to_owned()
                } else {
                    names::keyless(method).as_str().to_owned()
                };
                assert_eq!(expected, recorded["result"].to_string(), "{what}");
            }
            if verdicts.iter().any(|v| !v) {
                ended = true;
            }
            // A name that moved answers as a keyless document's would.
            if !verdicts.iter().all(|v| *v) && recorded.get("keyless").is_some() {
                assert_eq!(recorded["result"], recorded["keyless"], "{what}");
            }
        }
    }
    assert_eq!((scenarios, requests, checks), (8, 10, 21));
}
