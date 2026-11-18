//! Replays the vault-prompt scenarios of `step: "APR-5d"` in
//! vectors/eip1193.json through the dispatcher (design 0012, APR-5d-1):
//! each request as main sends it, `PageContext.agent` as the scenario's
//! custody, the core's typed-data view answered as the reference's
//! `core.typed_data_view` effect scripted it (its params checked against
//! the effect's), each prompt checked against the effect the reference made
//! (its kind and view, byte for byte) and answered as main would answer
//! the core's `approval.request` from that effect's decision, with the
//! grant file as main's world changes left it. What an approve signs is
//! the reference's token payload in the core's form, the typed data's
//! hash the bound one, and the answer is the reference's result, byte for
//! byte, from the recorded signature.
//!
//! Custody reads are main's (the agent's route) or `PageContext.agent`;
//! each was `false`. Every scripted typed-data view is checked against
//! fc-evm's own view of the same request: the hash, `named_type` and
//! `chain` are the same.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_eip1193::sign::{Decided, RuleNow, TypedView};
use fc_eip1193::{Prompts, Request, Step, start};
use serde_json::{Value, json};

/// The scenarios a vault prompt answers, or that end before one; the rest
/// (a rule answering, a device, "Always allow") replay through the daemon.
pub const VAULT_PROMPT: [&str; 14] = [
    "sign-message-approved",
    "sign-message-text",
    "sign-typed-approved",
    "sign-typed-object",
    "sign-typed-chain-mismatch",
    "sign-rejected",
    "sign-not-connected",
    "sign-keyless",
    "sign-unshowable",
    "sign-account-gone",
    "sign-safe-off-gnosis",
    "sign-busy",
    "sign-navigated",
    "sign-revoked-during-prompt",
];

fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/eip1193.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

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

/// The grant file after the changes a scenario makes while a prompt is
/// open.
fn changed(mut grants: Value, effects: &[Value], key: &str) -> Value {
    for effect in effects.iter().filter(|e| e["effect"] == "world") {
        if effect["change"] == "grant-revoked" {
            grants.as_object_mut().unwrap().remove(key);
        }
    }
    grants
}

/// The bytes `personal_sign` signs, as the core's `sign.message` takes
/// them: 0x hex in lowercase.
fn message_hex(message: &str) -> String {
    let bytes = match message.strip_prefix("0x") {
        Some(hex) => (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect(),
        None => message.as_bytes().to_vec(),
    };
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{hex}")
}

/// fc-evm's own view of a `typed_data.hash` request: the hash and the view.
fn fc_evm_view(params: &str) -> (String, Value) {
    let params = fc_evm::parse_json(params).unwrap();
    let typed = &params["typed_data"];
    let request = fc_evm::ViewRequest {
        primary_type: params.get("primary_type"),
        chain_id: params["chain_id"].as_str().and_then(fc_evm::parse_unsigned),
        max_len: 1 << 20,
    };
    let viewed = fc_evm::typed_data_view(
        &typed["domain"],
        &typed["types"],
        &typed["message"],
        &request,
    )
    .unwrap();
    (
        fc_evm::to_hex(&viewed.hash),
        serde_json::from_str(&viewed.view).unwrap(),
    )
}

#[test]
fn every_vault_prompt_scenario_replays() {
    let file = load();
    let mut prompts = Prompts::new();
    let mut handles = 0u8;
    let (mut scenarios, mut requests, mut asked, mut signed, mut viewed) = (0, 0, 0, 0, 0);
    for scenario in file["scenarios"].as_array().unwrap() {
        let id = scenario["id"].as_str().unwrap();
        if !VAULT_PROMPT.contains(&id) {
            continue;
        }
        assert_eq!(scenario["step"], "APR-5d", "{id}");
        scenarios += 1;
        let world = world_of(&file, scenario);
        let agent = scenario["world"]["custody"].as_bool();
        let key = scenario["world"]["documents"][0]["key"].as_str();
        let grants = scenario["grants"]["before"].clone();
        let lookup = |grants: &Value, key: &str| {
            grants
                .get(key)
                .map(|g| fc_json::parse(&g.to_string()).unwrap())
        };
        for (i, recorded) in scenario["requests"].as_array().unwrap().iter().enumerate() {
            requests += 1;
            let what = format!("{id} #{i} {}", recorded["method"]);
            let mut params = json!({ "method": recorded["method"], "world": world });
            if let Some(p) = recorded.get("params") {
                params["params"] = p.clone();
            }
            let request = Request::parse(&params.to_string()).unwrap();
            let effects: Vec<Value> = recorded["effects"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|e| {
                    if e["effect"] == "custody" {
                        assert_eq!(e["answer"], false, "{what}");
                        false
                    } else {
                        true
                    }
                })
                .cloned()
                .collect();
            let find = |name: &str| effects.iter().find(|e| e["effect"] == name);
            let answer = match start(&request, key, |key| lookup(&grants, key)) {
                Step::Answer(answer) => {
                    assert!(effects.is_empty(), "{what}: {effects:?}");
                    answer
                }
                Step::Sign(sign) => {
                    let view_effect = find("core.typed_data_view");
                    let mut asked_view = false;
                    let ask = sign.ask(
                        agent,
                        |key| lookup(&grants, key),
                        // No rule answers a vault-prompt scenario.
                        |_| RuleNow::NotCovered,
                        |params| {
                            asked_view = true;
                            let effect = view_effect.expect("a view the reference asked for");
                            let args = &effect["args"];
                            let sent: Value = serde_json::from_str(params).unwrap();
                            assert_eq!(
                                sent["typed_data"].to_string(),
                                args["typedData"].to_string(),
                                "{what}"
                            );
                            assert_eq!(
                                sent.get("primary_type"),
                                args["options"].get("primaryType")
                            );
                            assert_eq!(
                                sent["chain_id"],
                                json!(args["options"]["chainId"].to_string()),
                                "{what}"
                            );
                            let scripted = &effect["answer"];
                            // fc-evm's own view agrees where the vectors script it.
                            let (hash, own) = fc_evm_view(params);
                            assert_eq!(hash, scripted["hash"].as_str().unwrap(), "{what}");
                            for report in ["named_type", "chain"] {
                                assert_eq!(own[report], scripted["view"][report], "{what}");
                            }
                            viewed += 1;
                            Ok(TypedView {
                                hash: scripted["hash"].as_str().unwrap().to_owned(),
                                view: scripted["view"].to_string(),
                            })
                        },
                    );
                    assert_eq!(asked_view, view_effect.is_some(), "{what}");
                    match ask {
                        Err(answer) => {
                            assert!(find("prompt").is_none(), "{what}");
                            answer
                        }
                        Ok(ask) => {
                            asked += 1;
                            let prompt = find("prompt").unwrap();
                            assert_eq!(ask.kind(), prompt["args"]["kind"], "{what}");
                            assert_eq!(ask.view(), prompt["args"]["view"].to_string(), "{what}");
                            let prompt_id = prompts.issue([asked; 16]).unwrap();
                            handles += 1;
                            let handle = format!("{handles:064x}");
                            let text =
                                answer_of(&prompt_id.hex(), &handle, &prompt["answer"], &world);
                            let decision = prompts.accept(&prompt_id, &text).unwrap();
                            let now = changed(grants.clone(), &effects, key.unwrap());
                            match ask.decide(decision, |key| lookup(&now, key)).unwrap() {
                                Decided::Answer(answer) => {
                                    assert!(find("token.issue").is_none(), "{what}");
                                    answer
                                }
                                Decided::Sign(approved) => {
                                    signed += 1;
                                    assert_eq!(approved.handle(), Some(handle.as_str()));
                                    assert!(!approved.always_allow(), "{what}");
                                    let issue = &find("token.issue").unwrap()["args"];
                                    assert_eq!(approved.method().token_kind(), issue["kind"]);
                                    assert_eq!(json!(approved.account()), issue["account"]);
                                    let spend = &find("token.spend").unwrap()["args"];
                                    assert_eq!(
                                        spend["token"],
                                        find("token.issue").unwrap()["answer"]
                                    );
                                    assert_eq!(spend["payload"], issue["payload"]);
                                    let payload: Value =
                                        serde_json::from_str(approved.payload()).unwrap();
                                    match issue["payload"].as_str() {
                                        Some(message)
                                            if approved.method().core_method()
                                                == "sign.message" =>
                                        {
                                            assert_eq!(
                                                payload,
                                                json!({ "message": message_hex(message) })
                                            );
                                            assert_eq!(approved.expected_hash(), None);
                                        }
                                        _ => {
                                            assert_eq!(
                                                approved.expected_hash(),
                                                issue["bound"]["hash"].as_str()
                                            );
                                            assert_eq!(
                                                approved.expected_hash(),
                                                find("token.spend").unwrap()["answer"]["hash"]
                                                    .as_str()
                                            );
                                            // What the user was shown: the view's own params.
                                            assert_eq!(
                                                payload["typed_data"].to_string(),
                                                find("core.typed_data_view").unwrap()["args"]
                                                    ["typedData"]
                                                    .to_string()
                                            );
                                        }
                                    }
                                    let effect = effects
                                        .iter()
                                        .find(|e| {
                                            e["effect"] == "sign.message"
                                                || e["effect"] == "sign.typed_data"
                                        })
                                        .unwrap();
                                    assert_eq!(
                                        effect["effect"].as_str().unwrap().replace('_', "."),
                                        approved.method().core_method().replace('_', "."),
                                    );
                                    assert_eq!(
                                        json!(approved.account()),
                                        effect["args"]["account"]
                                    );
                                    approved.answer(Ok(effect["answer"].as_str().unwrap()))
                                }
                                Decided::Device(device) => panic!("{what}: {device:?}"),
                            }
                        }
                    }
                }
                other => panic!("{what}: {other:?}"),
            };
            assert_eq!(answer.as_str(), recorded["result"].to_string(), "{what}");
            // Nothing written: none of these ticks "Always allow".
            assert!(find("grant.write").is_none(), "{what}");
        }
    }
    assert_eq!(
        (scenarios, requests, asked, signed, viewed),
        (14, 18, 9, 4, 3)
    );
}

/// Each step-"APR-5d" scenario is replayed here, or by name in
/// freedom-cored's `tests/eip1193_sign.rs` (APR-5d-2: a rule answering,
/// "Always allow", a Ledger), which needs the core's own grant, rate and
/// vault.
#[test]
fn the_rest_are_apr5d2s() {
    let file = load();
    let rest: Vec<&str> = file["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["step"] == "APR-5d")
        .map(|s| s["id"].as_str().unwrap())
        .filter(|id| !VAULT_PROMPT.contains(id))
        .collect();
    assert_eq!(
        rest,
        [
            "sign-always-allow",
            "sign-always-allow-fails",
            "sign-ledger-approved",
            "sign-ledger-declined",
            "sign-rule-answers",
            "sign-rule-warned-prompts",
            "sign-rule-locked-vault",
            "sign-rule-unlock-cancelled",
            "sign-rule-off-during-unlock",
            "sign-rule-custody-during-unlock",
        ]
    );
}
