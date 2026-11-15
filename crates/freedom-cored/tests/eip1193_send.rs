//! `eth_sendTransaction` through the core (design 0012, APR-5e-1): the real
//! binary, with the test playing main and the chain's node. Every prompted
//! `step: "APR-5e"` scenario of vectors/eip1193.json replays: main's file
//! holds the scenario's dApp grant, each request goes under `page` with
//! main's wallet state, the core's own estimate is the reference's
//! `chain.request` (params and chain, byte for byte) answered from it, and
//! each prompt is the reference's (kind and view) answered from its
//! decision. Main then signs what `{ send }` carries with the nonce added.
//!
//! Adaptations, each checked: the node's quote is the core's own (16 gwei
//! and 2 gwei give the vectors' 30 gwei and 2 gwei; a legacy chain's 15.96
//! gwei gives 20), so a view's `fee.estimate` is the gas limit times the
//! core's effective price, and its `feeCheck` is the core's own verdict on
//! its own evidence, with the vectors' `maxCost` and `above`. What the page
//! gets after `{ send }` (the hash, or the send's failure) is main's.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{Core, dirs, spawn_env};
use serde_json::{Value, json};

const SITE: &str = "https://app.example";
const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NOW: u64 = 1_763_000_000_000;
const GWEI: u64 = 1_000_000_000;

#[path = "../../fc-eip1193/tests/sends.rs"]
#[allow(dead_code)]
mod logic;

fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/eip1193.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A core whose dApp store has moved, holding `grants`, its vault unlocked
/// with the test key, its wall clock at `NOW` and its approvals' clock read
/// from the returned file, with chains 1, 100 and 8453 read Direct from one
/// endpoint each.
fn core(grants: &Value) -> (tempfile::TempDir, Core, PathBuf) {
    let (root, data, locks) = dirs();
    let (wall, clock) = (root.path().join("wall"), root.path().join("approval"));
    std::fs::write(&wall, NOW.to_string()).unwrap();
    std::fs::write(&clock, "1000000").unwrap();
    let env = [
        ("FREEDOM_CORED_TEST_WALL_CLOCK", wall.to_str().unwrap()),
        ("FREEDOM_CORED_TEST_APPROVAL_CLOCK", clock.to_str().unwrap()),
    ];
    let mut core = spawn_env("serve", &data, &locks, &[], &env);
    std::fs::create_dir_all(&core.grant_root).unwrap();
    if !grants.is_null() {
        let text = serde_json::to_string_pretty(grants).unwrap();
        std::fs::write(core.grant_root.join("dapp-permissions.json"), text).unwrap();
    }
    core.grant_moved = vec!["dapp"];
    assert_eq!(core.hello_fragments()["result"]["protocol"], 2);
    let imported = core.call(
        2,
        "vault.import",
        json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(ABANDON) }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    let chain = |id: u64, rpc: &[&str]| {
        json!({
            "chain_id": id, "display_name": id.to_string(),
            "read_order": ["direct"], "broadcast_order": ["direct"],
            "quorum": { "k": 3, "m": 2, "timeout_ms": 5000 },
            "rpc": rpc.iter().map(|e| json!({ "endpoint": e, "user_configured": false })).collect::<Vec<_>>(),
            "prover": null, "myotis": false, "blockscout": null,
        })
    };
    let chains = [
        chain(1, &["e1"]),
        chain(100, &["e100"]),
        chain(8453, &["e8453"]),
    ];
    let reply = core.call(3, "chain.configure", json!({ "chains": chains }));
    assert!(reply["result"]["generations"].is_object(), "{reply}");
    (root, core, clock)
}

fn page(key: Option<&str>) -> Value {
    let origin = key.unwrap_or("");
    json!({ "caller": "page", "page": {
        "origin": origin, "top_origin": origin, "frame": 1, "navigation": 1, "agent": false,
    } })
}

fn request(core: &mut Core, id: u64, key: Option<&str>, body: &Value) {
    core.send(&json!({
        "type": "request", "id": id, "method": "eip1193.request",
        "params": body, "context": page(key),
    }));
}

/// How the test's node answers: the estimate as `estimate` scripts it (a
/// `chain.request` effect), the gas price, and the priority fee (none: a
/// legacy chain's node).
struct Node {
    estimate: Value,
    gas_price: u64,
    priority: Option<u64>,
    /// Methods seen, in order.
    seen: Vec<String>,
}

impl Node {
    fn new(estimate: Value) -> Node {
        Node {
            estimate,
            gas_price: 16 * GWEI,
            priority: Some(2 * GWEI),
            seen: Vec::new(),
        }
    }

    fn answer(&mut self, request: &Value) -> Value {
        let body: Value =
            serde_json::from_str(request["params"]["body"].as_str().unwrap()).unwrap();
        let method = body["method"].as_str().unwrap().to_owned();
        let outcome = match method.as_str() {
            "eth_estimateGas" => {
                // What the core asked its chain machine is the reference's
                // `chain.request` (fc-eip1193's replay checks it byte for
                // byte); the machine writes the value as a quantity, as for
                // main's `chain.request`.
                let mut asked = self.estimate["args"]["params"].clone();
                let value: u128 = asked[0]["value"].as_str().unwrap().parse().unwrap();
                asked[0]["value"] = json!(format!("{value:#x}"));
                assert_eq!(body["params"], asked);
                match self.estimate.get("answer") {
                    Some(answer) => json!({ "result": answer["result"] }),
                    None => json!({ "error": {
                        "code": self.estimate["throws"]["code"],
                        "message": self.estimate["throws"]["message"],
                    } }),
                }
            }
            "eth_gasPrice" if self.gas_price > 0 => {
                json!({ "result": format!("{:#x}", self.gas_price) })
            }
            "eth_maxPriorityFeePerGas" if self.priority.is_some() => {
                json!({ "result": format!("{:#x}", self.priority.unwrap()) })
            }
            _ => json!({ "error": { "code": -32601, "message": "the method does not exist" } }),
        };
        self.seen.push(method);
        let mut text = json!({ "jsonrpc": "2.0", "id": body["id"] });
        for (key, value) in outcome.as_object().unwrap() {
            text[key] = value.clone();
        }
        json!({ "result": { "status": 200, "body": STANDARD.encode(text.to_string()) } })
    }
}

/// What main sees next of request `id`: a prompt, or its response.
enum Next {
    Prompt(Value),
    Done(Value),
}

/// Plays main and the node until request `id`'s prompt or response.
fn next(core: &mut Core, id: u64, node: &mut Node) -> Next {
    loop {
        let message = core.recv();
        match (message["type"].as_str(), message["method"].as_str()) {
            (Some("event"), _) => {}
            (Some("request"), Some("shell.rpc")) => {
                let answer = node.answer(&message);
                respond(core, &message, answer);
            }
            (Some("request"), Some("approval.request")) => return Next::Prompt(message),
            (Some("response"), _) if message["id"] == id => return Next::Done(message),
            _ => panic!("unexpected {message}"),
        }
    }
}

fn respond(core: &mut Core, request: &Value, outcome: Value) {
    let mut message = json!({ "type": "response", "id": request["id"] });
    for (key, value) in outcome.as_object().unwrap() {
        message[key] = value.clone();
    }
    core.send(&message);
}

fn answer_of(prompt: &Value, handle: &str, decision: &Value, world: &Value) -> Value {
    if decision.get("approve").is_some() {
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
        json!({ "prompt": prompt, "busy": true })
    }
}

fn grant_file(core: &Core) -> Value {
    match std::fs::read_to_string(core.grant_root.join("dapp-permissions.json")) {
        Ok(text) => serde_json::from_str(&text).unwrap(),
        Err(_) => Value::Null,
    }
}

/// `sign.transaction` as main calls it on `{ send }`, under the request's
/// page: the transaction with `nonce`, edited by `edit` first.
fn sign(core: &mut Core, id: u64, send: &Value, edit: impl FnOnce(&mut Value)) -> Value {
    let mut tx = send["tx"].clone();
    tx["nonce"] = json!("7");
    edit(&mut tx);
    core.send(&json!({
        "type": "request", "id": id, "method": "sign.transaction",
        "params": {
            "key": { "kind": "account", "index": send["account"] }, "tx": tx,
            "authorization": { "token": send["token"], "kind": send["kind"], "handle": send["handle"] },
        },
        "context": page(Some(SITE)),
    }));
    core.until_response(id)
}

/// The view the core shows for a recorded one: its fee priced with the
/// core's own quote, and the core's own verdict where the reference's was
/// scripted, with the scripted `maxCost` and `above`.
fn adapted(recorded: &Value, shown: &Value) -> Value {
    let mut expected = recorded.clone();
    if let Some(fee) = expected["fee"].as_object_mut() {
        let gas: u128 = fee["gasLimit"].as_str().unwrap().parse().unwrap();
        let per_gas = if fee.contains_key("gasPrice") { 20 } else { 16 };
        fee["estimate"] = json!((gas * per_gas * u128::from(GWEI)).to_string());
    }
    if let Some(check) = recorded["feeCheck"].as_object() {
        let core = shown["feeCheck"].as_object().unwrap();
        assert_eq!(
            core.keys().collect::<Vec<_>>(),
            check.keys().collect::<Vec<_>>()
        );
        assert_eq!(core["maxCost"], check["maxCost"]);
        assert_eq!(core["above"], check["above"]);
        expected["feeCheck"] = shown["feeCheck"].clone();
    }
    expected
}

#[test]
fn every_prompted_send_replays_through_the_core() {
    let file = load();
    let (mut requests, mut prompts, mut sent) = (0, 0, 0);
    for scenario in file["scenarios"].as_array().unwrap() {
        let name = scenario["id"].as_str().unwrap();
        if !logic::PROMPTED.contains(&name) {
            continue;
        }
        let (_root, mut core, _clock) = core(&scenario["grants"]["before"]);
        let world = logic::world_of(&file, scenario);
        let key = scenario["world"]["documents"][0]["key"].as_str();
        for (i, recorded) in scenario["requests"].as_array().unwrap().iter().enumerate() {
            requests += 1;
            let what = format!("{name} #{i}");
            let id = 100 + i as u64 * 10;
            let effects = recorded["effects"].as_array().unwrap();
            let estimates: Vec<&Value> = effects
                .iter()
                .filter(|e| e["effect"] == "chain.request")
                .collect();
            let mut node = Node::new(estimates.first().map_or(Value::Null, |e| (*e).clone()));
            let quote = effects.iter().find(|e| e["effect"] == "chain.fee_quote");
            // A legacy node's 15.96 gwei: the core's headroom and least tip
            // make the vectors' 20 gwei.
            if quote.is_some_and(|q| q["answer"]["type"] == "legacy") {
                node.priority = None;
                node.gas_price = 15_960_000_000;
            }
            // A quote that failed: no gas price until the prompt.
            if quote.is_some_and(|q| q.get("throws").is_some()) {
                node.gas_price = 0;
            }
            let mut body = json!({ "method": recorded["method"], "world": world });
            if let Some(params) = recorded.get("params") {
                body["params"] = params.clone();
            }
            request(&mut core, id, key, &body);
            let mut shown = effects.iter().filter(|e| e["effect"] == "prompt");
            let mut asked_here = 0;
            let response = loop {
                match next(&mut core, id, &mut node) {
                    Next::Done(response) => break response,
                    Next::Prompt(asked) => {
                        prompts += 1;
                        asked_here += 1;
                        let prompt = shown.next().unwrap_or_else(|| panic!("{what}: no prompt"));
                        let params = &asked["params"];
                        assert_eq!(params["request"], id, "{what}");
                        assert_eq!(params["kind"], prompt["args"]["kind"], "{what}");
                        assert_eq!(
                            params["choices"],
                            json!({ "alwaysAllow": [false, true], "feeAcknowledged": [false, true] })
                        );
                        let expected = adapted(&prompt["args"]["view"], &params["view"]);
                        assert_eq!(params["view"].to_string(), expected.to_string(), "{what}");
                        if name == "send-fee-asked-again" && asked_here == 1 {
                            // Main's own fee reference, while the prompt is
                            // open, finds the fee newly above.
                            node.gas_price = 2 * GWEI;
                            node.priority = Some(GWEI);
                            core.send(&json!({
                                "type": "request", "id": id + 3, "method": "chain.fee_reference",
                                "params": { "chain_id": 1, "deadline_ms": 30_000 },
                                "context": { "caller": "chrome" },
                            }));
                            assert!(matches!(next(&mut core, id + 3, &mut node), Next::Done(_)));
                        }
                        for change in effects.iter().filter(|e| e["effect"] == "world") {
                            if change["change"] == "grant-revoked" {
                                let revoked = core.call_shell(
                                    id + 5,
                                    "approval.revoke",
                                    json!({ "store": "dapp", "key": SITE, "what": "grant" }),
                                );
                                assert!(revoked.get("result").is_some(), "{revoked}");
                            }
                        }
                        node.gas_price = if node.gas_price == 0 {
                            16 * GWEI
                        } else {
                            node.gas_price
                        };
                        if let Some(second) = estimates.get(1) {
                            node.estimate = (*second).clone();
                        }
                        let handle = format!("{:064x}", asked["id"].as_u64().unwrap());
                        let answer =
                            answer_of(&params["prompt"], &handle, &prompt["answer"], &world);
                        respond(&mut core, &asked, json!({ "result": answer }));
                    }
                }
            };
            assert!(shown.next().is_none(), "{what}: a prompt not asked");
            let result = &response["result"];
            let issued = effects.iter().find(|e| e["effect"] == "token.issue");
            match issued {
                None => assert_eq!(result.to_string(), recorded["result"].to_string(), "{what}"),
                Some(issued) => {
                    sent += 1;
                    let send = &result["send"];
                    let mut payload = issued["args"]["payload"].clone();
                    payload.as_object_mut().unwrap().remove("origin");
                    assert_eq!(send["tx"], logic::core_tx(&payload), "{what}");
                    assert_eq!(send["kind"], "dapp-send");
                    assert_eq!(send["account"], issued["args"]["account"]);
                    // Main signs it with the nonce added: the reference's
                    // `send.sign`; its broadcast is main's.
                    let signed = sign(&mut core, id + 9, send, |_| {});
                    assert!(signed["result"]["raw"].is_string(), "{what}: {signed}");
                }
            }
            // "Always allow" ticked on a contract call: Q9's limited rule,
            // as `sign.transaction` wrote it once it signed. It stands for
            // `send-failed` too, whose failure is main's after the
            // signature, where the reference wrote it only once the payment
            // was sent (0012's `token-remember`).
            let mut expected = scenario["grants"]["after"].clone();
            let ticked = effects
                .iter()
                .filter(|e| e["effect"] == "prompt")
                .last()
                .is_some_and(|p| p["answer"]["choices"]["alwaysAllow"] == true);
            if let (Some(_), true) = (
                issued,
                ticked && result["send"]["tx"]["data"].as_str().unwrap().len() >= 10,
            ) {
                let tx = &result["send"]["tx"];
                let rules = &mut expected[SITE]["autoApprove"];
                rules["transactions"] = json!([]);
                rules["limited"] = json!({ "signing": null, "transactions": [{
                    "to": tx["to"], "selector": tx["data"].as_str().unwrap()[..10],
                    "chainId": tx["chain_id"].as_str().unwrap().parse::<u64>().unwrap(),
                    "maxValue": tx["value"], "grantedAt": NOW,
                }] });
            }
            assert_eq!(grant_file(&core), expected, "{what}");
        }
    }
    assert_eq!((requests, prompts, sent), (27, 16, 8));
}
