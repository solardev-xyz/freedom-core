//! Replays the `step: "APR-5f"` scenarios of vectors/eip1193.json at the
//! logic level (design 0012, APR-5f): each document's name binding from
//! its key and transport key, each recorded `keyless` answer, the checks
//! the reference makes before it first reads the key's grant, and for
//! `eth_accounts` the answer and whether its last check follows, from
//! the scripted `name.check` answers; for a send (APR-5f-2), its form
//! before any check, its checks before the grant is read and before the
//! quote, and its check after the approve and the check at it. The daemon replay
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
            // Once the binding has ended the reference resolves nothing
            // (`recheckName`: the document has no key), and nothing is
            // recorded: a name-revalidated method answers as a keyless
            // document's.
            if ended {
                assert!(verdicts.is_empty(), "{what}: a check after the end");
                if recorded.get("keyless").is_some() {
                    assert_eq!(
                        recorded["result"].to_string(),
                        names::keyless(method).as_str(),
                        "{what}"
                    );
                }
            }
            checks += verdicts.len();
            let leading = effects
                .iter()
                .take_while(|e| e["effect"] == "name.check")
                .count();
            match names::checks_first(method) {
                // Each check before the grant is read, cut short by a name
                // that moved; none once the binding has ended (above).
                Some(_) if ended => {}
                Some(first) => {
                    let moved = verdicts.iter().position(|v| !v);
                    let expected =
                        moved.map_or(usize::from(first), |at| (at + 1).min(usize::from(first)));
                    assert!(leading >= expected, "{what}: {leading} < {expected}");
                }
                // A switch: its params' checks, then one name check.
                None if method == "wallet_switchEthereumChain" => {
                    assert_eq!(verdicts.len(), 1, "{what}");
                }
                // A send (APR-5f-2): its form first, with nothing resolved;
                // then two checks before its grant is read, one more after
                // the rule's choice, before its quote; and after the approve
                // and the fee check at it, one before the grant is read again
                // and the token minted (main's turn, D12, between them in the
                // reference).
                None if method == "eth_sendTransaction" => {
                    let mut params = json!({ "method": method, "world": {
                        "enabled": true, "wallets": file["wallets"], "networks": {},
                        "chain": doc["chain"],
                        "window_chain": scenario["world"]["windows"][doc["window"].to_string()],
                    } });
                    params["params"] = recorded["params"].clone();
                    let request = Request::parse(&params.to_string()).unwrap();
                    let grants = &scenario["grants"]["before"];
                    let grant = |key: &str| {
                        grants
                            .get(key)
                            .map(|g| fc_json::parse(&g.to_string()).unwrap())
                    };
                    let Step::Send(send) = start(&request, Some(key), grant) else {
                        panic!("{what}");
                    };
                    assert!(send.form().is_ok(), "{what}");
                    let prepare = send.prepare(grant).unwrap();
                    let estimate = effects
                        .iter()
                        .find(|e| e["effect"] == "chain.request")
                        .unwrap();
                    let asked: Value = serde_json::from_str(&prepare.estimate_params()).unwrap();
                    assert_eq!(asked, estimate["args"]["params"], "{what}");
                    assert_eq!(
                        leading,
                        usize::from(names::SEND_FIRST) + 1,
                        "{what}: the checks before the quote"
                    );
                    assert_eq!(effects[leading]["effect"], "chain.request", "{what}");
                    let approval = effects
                        .iter()
                        .position(|e| e["effect"] == "fees.at_approval")
                        .unwrap();
                    let kinds: Vec<&str> = effects[approval + 1..]
                        .iter()
                        .map(|e| e["effect"].as_str().unwrap())
                        .collect();
                    assert_eq!(kinds, ["send.turn", "name.check"], "{what}");
                    assert_eq!(verdicts.len(), leading + 1, "{what}");
                }
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
    assert_eq!((scenarios, requests, checks), (8, 10, 20));
}
