//! Replays every `step: "APR-5e"` send in vectors/eip1193.json through the
//! dispatcher (design 0012, APR-5e-1 the prompted vault sends, APR-5e-2 the
//! device sends and the sends a rule answers):
//! each request as main sends it, the estimate's params and chain checked
//! against the reference's `chain.request` effect and answered from it,
//! the fee quote answered from `chain.fee_quote`, the transaction the fee
//! check judges checked against `fees.check` and `fees.at_approval` and
//! their verdicts scripted from them, each prompt checked against the
//! effect the reference made (its kind and view, byte for byte) and
//! answered as main would answer the core's `approval.request` from that
//! effect's decision, with the grant file as main's world changes left it.
//!
//! What an approve mints is the reference's `token.issue` payload in the
//! core's form (`sign.transaction`'s, without the nonce), and "Always
//! allow" rides in it as the reference would write the rule. The core's
//! answer is `{ send }`, which carries that transaction and its token: what
//! the page gets after it (the hash, or the send's failure) is main's, from
//! `sign.transaction` and its broadcast, and `send.sign` must sign exactly
//! the transaction `{ send }` carries. Every other request's answer is the
//! reference's result, byte for byte.
//!
//! Custody reads are main's (the agent's route) or `PageContext.agent`;
//! each was `false`. `send.turn` (D12), `token.spend`, `send.sign`,
//! `send.broadcast` and the rule's `grant.write` are main's steps after
//! `{ send }`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fc_eip1193::send::{Decided, Judged, RuleNow, RuleRechecked, Ruled};
use fc_eip1193::{Prompts, Recheck, Request, Step, start};
use serde_json::{Value, json};

/// The 19 scenarios a vault prompt answers, or that end before one; the
/// device and rule sends are APR-5e-2's.
pub const PROMPTED: [&str; 19] = [
    "send-approved",
    "send-plain-transfer-legacy",
    "send-erc20-transfer",
    "send-effective-gas-price",
    "send-rejected",
    "send-refusals",
    "send-not-connected",
    "send-keyless",
    "send-page-fields-ignored",
    "send-estimate-fails-page-gas",
    "send-safe-off-gnosis",
    "send-account-gone",
    "send-always-allow",
    "send-fee-asked-again",
    "send-quote-failed",
    "send-failed",
    "send-busy",
    "send-navigated",
    "send-revoked-during-prompt",
];

/// APR-5e-2's: devices, and the sends a rule answers.
pub const APR5E2: [&str; 10] = [
    "send-ledger-declined",
    "send-phone-outcome-unknown",
    "send-rule-answers",
    "send-rule-not-for-more-value",
    "send-rule-turn-busy",
    "send-rule-payment-waiting",
    "send-rule-fee-needs-user",
    "send-rule-estimate-fails",
    "send-rule-locked-vault",
    "send-rule-custody-during-unlock",
];

fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/eip1193.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// `world` as main sends it, each network with its native symbol.
pub fn world_of(file: &Value, scenario: &Value) -> Value {
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
                json!({ "name": network["name"], "available": up, "symbol": network["nativeSymbol"] }),
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

/// The reference's transaction (`sendTxOf`'s, or a token payload's) in
/// `sign.transaction`'s form, without its nonce: what the core binds.
pub fn core_tx(tx: &Value) -> Value {
    let eip1559 = tx.get("maxFeePerGas").is_some();
    let mut core = json!({
        "type": if eip1559 { 2 } else { 0 },
        "chain_id": tx["chainId"].as_u64().unwrap().to_string(),
        "gas_limit": tx["gasLimit"],
        "to": tx["to"],
        "value": tx["value"],
        "data": tx["data"],
    });
    if eip1559 {
        core["max_fee_per_gas"] = tx["maxFeePerGas"].clone();
        core["max_priority_fee_per_gas"] = tx["maxPriorityFeePerGas"].clone();
    } else {
        core["gas_price"] = tx["gasPrice"].clone();
    }
    core
}

/// An effect's answer as the dispatcher gets it, or `None` for a throw.
fn answered(effect: &Value) -> Option<fc_json::JsValue> {
    effect
        .get("answer")
        .map(|answer| fc_json::parse(&answer.to_string()).unwrap())
}

#[test]
fn every_prompted_send_replays() {
    let file = load();
    let mut prompts = Prompts::new();
    let mut handles = 0u8;
    let (mut scenarios, mut requests, mut asked, mut prepared, mut quotes) = (0, 0, 0, 0, 0);
    for scenario in file["scenarios"].as_array().unwrap() {
        let id = scenario["id"].as_str().unwrap();
        if !PROMPTED.contains(&id) {
            continue;
        }
        assert_eq!(scenario["step"], "APR-5e", "{id}");
        scenarios += 1;
        let world = world_of(&file, scenario);
        let key = scenario["world"]["documents"][0]["key"].as_str();
        let mut grants = scenario["grants"]["before"].clone();
        let lookup = |grants: &Value, key: &str| {
            grants
                .get(key)
                .map(|g| fc_json::parse(&g.to_string()).unwrap())
        };
        for (i, recorded) in scenario["requests"].as_array().unwrap().iter().enumerate() {
            requests += 1;
            let what = format!("{id} #{i}");
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
                        // Main's world changing while a prompt is open is
                        // applied at that prompt's answer.
                        e["effect"] != "world"
                    }
                })
                .cloned()
                .collect();
            let at = std::cell::Cell::new(0);
            let next = |name: &str| {
                let effect = effects
                    .get(at.get())
                    .unwrap_or_else(|| panic!("{what}: no {name}"));
                assert_eq!(effect["effect"], name, "{what}: {effect}");
                at.set(at.get() + 1);
                effect.clone()
            };
            let send = match start(&request, key, |key| lookup(&grants, key)) {
                Step::Answer(answer) => {
                    assert_eq!(answer.as_str(), recorded["result"].to_string(), "{what}");
                    assert!(effects.is_empty(), "{what}");
                    continue;
                }
                Step::Send(send) => send,
                _ => panic!("{what}: not a send"),
            };
            let mut prepare = match send.prepare(|key| lookup(&grants, key)) {
                Err(answer) => {
                    assert_eq!(answer.as_str(), recorded["result"].to_string(), "{what}");
                    assert!(effects.is_empty(), "{what}");
                    continue;
                }
                Ok(prepare) => prepare,
            };
            // Quote, prompt, decide, judge: until the request is answered.
            let answer = 'run: loop {
                quotes += 1;
                let estimate = next("chain.request");
                assert_eq!(estimate["args"]["method"], "eth_estimateGas", "{what}");
                assert_eq!(estimate["args"]["chainId"], prepare.chain_id(), "{what}");
                assert!(estimate["args"].get("origin").is_none(), "{what}");
                assert_eq!(
                    prepare.estimate_params(),
                    estimate["args"]["params"].to_string(),
                    "{what}"
                );
                let fee = next("chain.fee_quote");
                assert_eq!(fee["args"]["chainId"], prepare.chain_id(), "{what}");
                let result =
                    answered(&estimate).map(|answer| answer.get("result").unwrap().clone());
                let quoted = prepare.quoted(result.as_ref(), answered(&fee).as_ref());
                let verdict = quoted.as_ref().map(|quoted| {
                    let check = next("fees.check");
                    assert_eq!(
                        quoted.tx(&prepare),
                        core_tx(&check["args"]["tx"]).to_string(),
                        "{what}"
                    );
                    check["answer"].to_string()
                });
                let mut ask = prepare.clone().ask(quoted, verdict.as_deref());
                loop {
                    let prompt = next("prompt");
                    asked += 1;
                    assert_eq!(ask.kind(), prompt["args"]["kind"], "{what}");
                    assert_eq!(ask.view(), prompt["args"]["view"].to_string(), "{what}");
                    handles += 1;
                    let issued = prompts.issue([handles; 16]).unwrap();
                    let handle = format!("{handles:064x}");
                    // Main's world as it answers: a revoke made meanwhile.
                    let all = recorded["effects"].as_array().unwrap();
                    for change in all.iter().filter(|e| e["effect"] == "world") {
                        if change["change"] == "grant-revoked" {
                            grants.as_object_mut().unwrap().remove(key.unwrap());
                        }
                    }
                    let text = answer_of(&issued.hex(), &handle, &prompt["answer"], &world);
                    let decision = prompts.accept(&issued, &text).unwrap();
                    let judge = match ask.decide(decision).unwrap() {
                        Decided::Answer(answer) => break 'run Some(answer),
                        Decided::Requote(again) => {
                            prepare = again;
                            continue 'run;
                        }
                        Decided::Judge(judge) => judge,
                        Decided::Safe(_) => panic!("{what}: a Safe's send"),
                    };
                    let at = next("fees.at_approval");
                    assert_eq!(judge.tx(), core_tx(&at["args"]["tx"]).to_string(), "{what}");
                    assert_eq!(
                        judge.acknowledged(),
                        at["args"]["acknowledged"] == true,
                        "{what}"
                    );
                    let again = at["answer"]["askAgain"] == true;
                    let approved = match judge
                        .judged(&at["answer"].to_string(), again, |key| lookup(&grants, key))
                    {
                        Judged::Answer(answer) => {
                            // Main's turn was taken before the reference's
                            // last check: main's step.
                            let turn = next("send.turn");
                            assert_eq!(turn["args"]["wait"], true, "{what}");
                            break 'run Some(answer);
                        }
                        Judged::Ask(again) => {
                            ask = *again;
                            continue;
                        }
                        Judged::Send(approved) => approved,
                        Judged::Device(_) => panic!("{what}: a device's send"),
                    };
                    prepared += 1;
                    next("send.turn");
                    let issue = next("token.issue");
                    assert_eq!(issue["args"]["kind"], "dapp-send", "{what}");
                    assert_eq!(issue["args"]["account"], approved.account(), "{what}");
                    let mut payload = issue["args"]["payload"].clone();
                    assert_eq!(payload["origin"].as_str(), key, "{what}");
                    payload.as_object_mut().unwrap().remove("origin");
                    assert_eq!(approved.tx(), core_tx(&payload).to_string(), "{what}");
                    assert_eq!(approved.handle(), handle, "{what}");
                    // "Always allow" ticked on a contract call rides in the
                    // token, and `sign.transaction` writes the rule as it
                    // signs (0012's `token-remember`): the reference wrote
                    // it once the payment was sent, so a send that failed
                    // after (`send-failed`) wrote none there.
                    let data = payload["data"].as_str().unwrap();
                    let rule =
                        prompt["answer"]["choices"]["alwaysAllow"] == true && data.len() >= 10;
                    assert_eq!(approved.remember(), rule, "{what}");
                    let wrote = recorded["effects"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|e| e["effect"] == "grant.write");
                    assert!(!wrote || rule, "{what}");
                    assert_eq!(
                        approved.payload(),
                        format!(r#"{{"tx":{},"remember":{rule}}}"#, approved.tx()),
                        "{what}"
                    );
                    // What main signs, the nonce added: the transaction
                    // `{ send }` carries.
                    next("token.spend");
                    let signed = next("send.sign");
                    assert_eq!(
                        approved.tx(),
                        core_tx(&signed["args"]["tx"]).to_string(),
                        "{what}"
                    );
                    assert_eq!(signed["args"]["context"]["kind"], "dapp-send", "{what}");
                    let token = "0123456789abcdef".repeat(4);
                    let answer = approved.answer(&token).unwrap();
                    let mut written = Vec::with_capacity(answer.len());
                    answer.write_into(&mut written);
                    assert_eq!(written.len(), answer.len(), "{what}");
                    let send: Value = serde_json::from_slice(&written).unwrap();
                    assert_eq!(
                        send,
                        json!({ "send": {
                            "kind": "dapp-send", "account": approved.account(),
                            "tx": serde_json::from_str::<Value>(approved.tx()).unwrap(),
                            "handle": handle, "token": token,
                        } }),
                        "{what}"
                    );
                    break 'run None;
                }
            };
            match answer {
                Some(answer) => {
                    assert_eq!(answer.as_str(), recorded["result"].to_string(), "{what}");
                    assert_eq!(at.get(), effects.len(), "{what}");
                }
                // The rest is main's: the broadcast and the rule.
                None => {
                    for effect in &effects[at.get()..] {
                        let name = effect["effect"].as_str().unwrap();
                        assert!(["send.broadcast", "grant.write"].contains(&name), "{what}");
                    }
                }
            }
        }
    }
    assert_eq!(
        (scenarios, requests, asked, prepared, quotes),
        (19, 27, 16, 8, 15)
    );
}

/// The two lists are every step-APR-5e scenario.
#[test]
fn every_step_apr5e_scenario_is_replayed() {
    let file = load();
    let ids: Vec<&str> = file["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["step"] == "APR-5e")
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), PROMPTED.len() + APR5E2.len());
    for id in ids {
        assert!(PROMPTED.contains(&id) ^ APR5E2.contains(&id), "{id}");
    }
}

/// An effect's outcome as the core's read gives it: the answer's `result`
/// (`nested`) or the answer, or the thrown message.
fn outcome(effect: &Value, nested: bool) -> Result<fc_json::JsValue, String> {
    match effect.get("answer") {
        Some(answer) => {
            let answer = if nested { &answer["result"] } else { answer };
            Ok(fc_json::parse(&answer.to_string()).unwrap())
        }
        None => Err(effect["throws"]["message"].as_str().unwrap().to_owned()),
    }
}

/// The 10 scenarios APR-5e-2 replays. A device's send is prepared and asked
/// as a vault account's (a phone's fee unchecked); its approve mints the
/// reference's `token.issue` payload and answers `{ device }`, and what the
/// device does with it (`token.spend`, `send.sign`) is main's. A rule's
/// send is chosen where the reference's rule matched (it read D12's pause,
/// which main sends as `world.paused`), asks the unlock while the vault is
/// locked, is quoted and judged by the scripted fee check, and is
/// rechecked: the recheck's custody is the reference's read just before
/// its signature. Main's turn (D12) comes after `{ send }` through the
/// core, so a turn the reference found busy, or a payment it found
/// waiting, is main's refusal after it. Custody reads before the choice
/// are `PageContext.agent`.
#[test]
fn every_device_and_rule_send_replays() {
    let file = load();
    let mut prompts = Prompts::new();
    let mut handles = 100u8;
    let (mut scenarios, mut asked, mut devices, mut ruled, mut by_main) = (0, 0, 0, 0, 0);
    let lookup = |grants: &Value, key: &str| {
        grants
            .get(key)
            .map(|g| fc_json::parse(&g.to_string()).unwrap())
    };
    for scenario in file["scenarios"].as_array().unwrap() {
        let id = scenario["id"].as_str().unwrap();
        if !APR5E2.contains(&id) {
            continue;
        }
        scenarios += 1;
        let recorded = &scenario["requests"][0];
        assert_eq!(scenario["requests"].as_array().unwrap().len(), 1, "{id}");
        let effects: Vec<Value> = recorded["effects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["effect"] != "world")
            .cloned()
            .collect();
        let at = std::cell::Cell::new(0);
        let next = |name: &str| {
            let effect = effects
                .get(at.get())
                .unwrap_or_else(|| panic!("{id}: no {name}"));
            assert_eq!(effect["effect"], name, "{id}: {effect}");
            at.set(at.get() + 1);
            effect.clone()
        };
        let peek = || {
            effects
                .get(at.get())
                .map(|e| e["effect"].as_str().unwrap().to_owned())
        };
        // `PageContext.agent`: main's agent route and the rule's choice.
        for _ in 0..2 {
            assert_eq!(next("custody")["answer"], false, "{id}");
        }
        let paused = effects.iter().find(|e| e["effect"] == "send.paused");
        let mut world = world_of(&file, scenario);
        world["paused"] = paused.map_or(json!(false), |e| e["answer"].clone());
        let key = scenario["world"]["documents"][0]["key"].as_str();
        let grants = scenario["grants"]["before"].clone();
        assert_eq!(grants, scenario["grants"]["after"], "{id}: nothing written");
        let mut params =
            json!({ "method": recorded["method"], "world": world, "params": recorded["params"] });
        params["params"] = recorded["params"].clone();
        let request = Request::parse(&params.to_string()).unwrap();
        let Step::Send(send) = start(&request, key, |key| lookup(&grants, key)) else {
            panic!("{id}")
        };
        let prepare = send.prepare(|key| lookup(&grants, key)).unwrap();
        let mut decide = |view: &str, kind: &str, choices: &str| {
            let prompt = next("prompt");
            asked += 1;
            assert_eq!(kind, prompt["args"]["kind"], "{id}");
            assert_eq!(view, prompt["args"]["view"].to_string(), "{id}");
            // A Ledger's and a phone's offer "Always allow" as a vault
            // account's: the token carries it to the device's receipt.
            if kind == "eth.send" {
                assert_eq!(
                    choices, r#"{"alwaysAllow":[false,true],"feeAcknowledged":[false,true]}"#,
                    "{id}"
                );
            }
            handles += 1;
            let issued = prompts.issue([handles; 16]).unwrap();
            let handle = format!("{handles:064x}");
            let text = answer_of(&issued.hex(), &handle, &prompt["answer"], &world);
            (prompts.accept(&issued, &text).unwrap(), handle, prompt)
        };
        // The core judges the rule with its own grant: scripted as the
        // reference's match, which read the pause.
        let query = prepare.rule_query(Some(false));
        let device = prompt_type(&effects);
        assert_eq!(query.is_some(), device == "mnemonic", "{id}");
        let answer = match prepare.clone().ruled().filter(|_| paused.is_some()) {
            Some(rule) => {
                ruled += 1;
                assert_eq!(next("send.paused")["answer"], false, "{id}");
                if scenario["world"]["vault"] == false {
                    let (decision, _, _) = decide(&rule.unlock_view(), rule.unlock_kind(), "{}");
                    assert_eq!(rule.unlock_choices(), "{}");
                    assert_eq!(rule.unlocked(decision).unwrap(), None, "{id}");
                }
                let estimate = next("chain.request");
                assert_eq!(
                    rule.prepare().estimate_params(),
                    estimate["args"]["params"].to_string(),
                    "{id}"
                );
                let fee = next("chain.fee_quote");
                let (estimate, fee) = (outcome(&estimate, true), outcome(&fee, false));
                let quoted = rule.prepare().quote(read(&estimate), read(&fee));
                let judged = rule.judged(quoted, |tx| {
                    let check = next("fees.check");
                    assert_eq!(tx, core_tx(&check["args"]["tx"]).to_string(), "{id}");
                    check["answer"].to_string()
                });
                match judged {
                    Ruled::Answer(answer) => answer.as_str().to_owned(),
                    Ruled::Ask(ask) => {
                        let (decision, _, _) = decide(ask.view(), ask.kind(), ask.choices());
                        let Decided::Answer(answer) = ask.decide(decision).unwrap() else {
                            panic!("{id}")
                        };
                        answer.as_str().to_owned()
                    }
                    Ruled::Recheck(rule) => {
                        let tx = rule.tx().unwrap();
                        let verdict = effects
                            .iter()
                            .find(|e| e["effect"] == "fees.check")
                            .unwrap()["answer"]
                            .to_string();
                        // Main's turn, which the reference took before its
                        // last read of custody: main's, after `{ send }`.
                        let turn = next("send.turn");
                        assert_eq!(turn["args"]["wait"], false, "{id}");
                        let waiting = (turn.get("answer").is_some()).then(|| next("send.waiting"));
                        let refused = waiting.as_ref().is_none_or(|w| w["answer"] == true);
                        let agent = if refused {
                            false
                        } else {
                            next("custody")["answer"] == true
                        };
                        let rechecked = rule.rechecked(
                            &Recheck { live: true, agent },
                            RuleNow::Covered,
                            &verdict,
                        );
                        // Custody refuses it; otherwise the rule answers.
                        let answer = match rechecked {
                            RuleRechecked::Answer(answer) if agent => answer,
                            RuleRechecked::Send(answer) if !agent => answer,
                            other => panic!("{id}: {other:?}"),
                        };
                        if agent {
                            answer.as_str().to_owned()
                        } else {
                            let sent: Value = serde_json::from_str(answer.as_str()).unwrap();
                            assert_eq!(
                                sent,
                                json!({ "send": { "kind": "dapp-send", "account": 0,
                                    "tx": serde_json::from_str::<Value>(&tx).unwrap(), "standing": true } }),
                                "{id}"
                            );
                            by_main += 1;
                            if !refused {
                                let signed = next("send.sign");
                                assert_eq!(tx, core_tx(&signed["args"]["tx"]).to_string(), "{id}");
                                for name in ["custody", "send.broadcast", "grant.write"] {
                                    next(name);
                                }
                            }
                            // What the page gets is main's: the hash, or
                            // the pause's refusal in the site's turn.
                            recorded["result"].to_string()
                        }
                    }
                }
            }
            None => {
                let estimate = next("chain.request");
                let fee = next("chain.fee_quote");
                let (estimate, fee) = (outcome(&estimate, true), outcome(&fee, false));
                let quoted = prepare.quote(read(&estimate), read(&fee)).ok();
                let verdict = quoted
                    .as_ref()
                    .filter(|_| prepare.checks_fee())
                    .map(|quoted| {
                        let check = next("fees.check");
                        assert_eq!(
                            quoted.tx(&prepare),
                            core_tx(&check["args"]["tx"]).to_string(),
                            "{id}"
                        );
                        check["answer"].to_string()
                    });
                let ask = prepare.clone().ask(quoted, verdict.as_deref());
                let (decision, handle, prompt) = decide(ask.view(), ask.kind(), ask.choices());
                match ask.decide(decision).unwrap() {
                    Decided::Answer(answer) => answer.as_str().to_owned(),
                    Decided::Judge(judge) => {
                        let (verdict, again) = if judge.checks_fee() {
                            let at = next("fees.at_approval");
                            assert_eq!(judge.tx(), core_tx(&at["args"]["tx"]).to_string(), "{id}");
                            (at["answer"].to_string(), at["answer"]["askAgain"] == true)
                        } else {
                            (String::new(), false)
                        };
                        let Judged::Device(approved) =
                            judge.judged(&verdict, again, |key| lookup(&grants, key))
                        else {
                            panic!("{id}")
                        };
                        devices += 1;
                        next("send.turn");
                        let issue = next("token.issue");
                        let mut payload = issue["args"]["payload"].clone();
                        payload.as_object_mut().unwrap().remove("origin");
                        let remember = prompt["answer"]["choices"]["alwaysAllow"] == true;
                        assert_eq!(approved.token_kind(), issue["args"]["kind"], "{id}");
                        assert_eq!(approved.account(), issue["args"]["account"], "{id}");
                        assert_eq!(approved.handle(), handle, "{id}");
                        assert_eq!(approved.device().name(), device, "{id}");
                        assert_eq!(
                            approved.binds(),
                            json!({ "tx": core_tx(&payload), "remember": remember }).to_string(),
                            "{id}"
                        );
                        assert_eq!(
                            approved.payload(),
                            json!({ "tx": core_tx(&payload) }).to_string()
                        );
                        let token = "0123456789abcdef".repeat(4);
                        let answer = approved.answer(&token).unwrap();
                        let mut written = Vec::with_capacity(answer.len());
                        answer.write_into(&mut written);
                        let written: Value = serde_json::from_slice(&written).unwrap();
                        assert_eq!(
                            written,
                            json!({ "device": {
                            "type": device, "kind": "dapp-send", "account": approved.account(),
                            "payload": { "tx": core_tx(&payload) }, "handle": handle, "token": token,
                        } }),
                            "{id}"
                        );
                        // The device's send, and its failure, are main's.
                        next("token.spend");
                        let signed = next("send.sign");
                        assert_eq!(core_tx(&signed["args"]["tx"]), core_tx(&payload), "{id}");
                        by_main += 1;
                        recorded["result"].to_string()
                    }
                    other => panic!("{id}: {other:?}"),
                }
            }
        };
        assert_eq!(answer, recorded["result"].to_string(), "{id}");
        assert_eq!(peek(), None, "{id}: an effect not replayed");
    }
    assert_eq!(
        (scenarios, asked, devices, ruled, by_main),
        (10, 6, 2, 7, 6)
    );
}

/// The account type the scenario's prompt or grant names.
fn prompt_type(effects: &[Value]) -> String {
    effects
        .iter()
        .find(|e| e["effect"] == "send.sign")
        .and_then(|e| e["args"]["walletIndex"].as_u64())
        .map_or("mnemonic", |index| match index {
            1 => "ledger",
            2 => "remote",
            _ => "mnemonic",
        })
        .to_owned()
}

fn read(outcome: &Result<fc_json::JsValue, String>) -> Result<&fc_json::JsValue, &str> {
    outcome.as_ref().map_err(String::as_str)
}
