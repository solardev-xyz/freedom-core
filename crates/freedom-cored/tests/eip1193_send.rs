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
    core_for(grants, 1, false)
}

/// [`core`], with chain 1 read from `endpoints` endpoints (two give fee
/// evidence that isn't one endpoint's word, which a rule needs) and the
/// vault locked if `locked`.
fn core_for(grants: &Value, endpoints: usize, locked: bool) -> (tempfile::TempDir, Core, PathBuf) {
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
        chain(1, &["e1", "e1b"][..endpoints]),
        chain(100, &["e100"]),
        chain(8453, &["e8453"]),
    ];
    let reply = core.call(3, "chain.configure", json!({ "chains": chains }));
    assert!(reply["result"]["generations"].is_object(), "{reply}");
    if locked {
        let reply = core.call_shell(4, "vault.lock", json!({}));
        assert!(reply["result"].is_object(), "{reply}");
    }
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

/// [`request`] with `PageContext.agent` as given: missing for `None`.
fn request_as(core: &mut Core, id: u64, agent: Option<bool>, body: &Value) {
    let mut context = page(Some(SITE));
    match agent {
        Some(agent) => context["page"]["agent"] = json!(agent),
        None => {
            context["page"].as_object_mut().unwrap().remove("agent");
        }
    }
    core.send(&json!({
        "type": "request", "id": id, "method": "eip1193.request",
        "params": body, "context": context,
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
                .rfind(|e| e["effect"] == "prompt")
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

fn connected() -> Value {
    json!({ SITE: {
        "origin": SITE, "connectedAt": NOW, "lastUsed": NOW, "walletIndex": 0, "chainId": 1,
        "autoApprove": { "signing": false, "transactions": [] },
    } })
}

fn world() -> Value {
    json!({
        "enabled": true, "chain": null, "window_chain": 1,
        "wallets": [{ "index": 0, "name": "Main Wallet", "address": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "type": "mnemonic" }],
        "networks": { "1": { "name": "Ethereum", "available": true, "symbol": "ETH" } },
    })
}

const TO: &str = "0xabababababababababababababababababababab";
const APPROVE_DATA: &str = "0x095ea7b3000000000000000000000000555555555555555555555555555555555555555500000000000000000000000000000000000000000000000000000000000003e8";

fn estimate() -> Value {
    json!({ "args": { "params": [{
        "from": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "to": TO, "value": "5", "data": APPROVE_DATA,
    }] }, "answer": { "result": "0xc350" } })
}

fn send_body() -> Value {
    json!({ "method": "eth_sendTransaction", "world": world(),
        "params": [{ "to": TO, "value": "0x5", "data": APPROVE_DATA }] })
}

/// A send asked and approved with `choices`: its prompt, and what main
/// gets after the answer (another prompt, or the response).
fn approve(core: &mut Core, id: u64, node: &mut Node, choices: Value) -> (Value, Next) {
    request(core, id, Some(SITE), &send_body());
    let Next::Prompt(asked) = next(core, id, node) else {
        panic!("no prompt")
    };
    let handle = format!("{:064x}", 1000 + asked["id"].as_u64().unwrap());
    let answer = json!({ "prompt": asked["params"]["prompt"], "handle": handle,
        "approve": true, "choices": choices, "world": world() });
    respond(core, &asked, json!({ "result": answer }));
    let after = next(core, id, node);
    (asked, after)
}

/// The row's test hook (design 0012, APR-5): main changes one field of
/// `{ send }` before `sign.transaction`, which refuses it with nothing
/// signed; with only the nonce added, it signs.
#[test]
fn each_prepared_field_changed_signs_nothing() {
    let (_root, mut core, _clock) = core(&connected());
    let mut node = Node::new(estimate());
    type Edit = Box<dyn Fn(&mut Value)>;
    let edits: Vec<(&str, Edit)> = vec![
        (
            "type",
            Box::new(|tx| {
                let fee = tx
                    .as_object_mut()
                    .unwrap()
                    .remove("max_fee_per_gas")
                    .unwrap();
                tx.as_object_mut()
                    .unwrap()
                    .remove("max_priority_fee_per_gas");
                tx["type"] = json!(0);
                tx["gas_price"] = fee;
            }),
        ),
        ("chain", Box::new(|tx| tx["chain_id"] = json!("100"))),
        (
            "to",
            Box::new(|tx| tx["to"] = json!("0x5555555555555555555555555555555555555555")),
        ),
        ("value", Box::new(|tx| tx["value"] = json!("6"))),
        ("data", Box::new(|tx| tx["data"] = json!("0x095ea7b4"))),
        ("gas limit", Box::new(|tx| tx["gas_limit"] = json!("60001"))),
        (
            "max fee",
            Box::new(|tx| tx["max_fee_per_gas"] = json!("30000000001")),
        ),
        (
            "priority fee",
            Box::new(|tx| tx["max_priority_fee_per_gas"] = json!("2000000001")),
        ),
    ];
    let mut id = 100;
    for (field, edit) in &edits {
        id += 10;
        let (_, after) = approve(&mut core, id, &mut node, json!({}));
        let Next::Done(response) = after else {
            panic!("{field}")
        };
        let send = &response["result"]["send"];
        assert_eq!(send["tx"]["gas_limit"], "60000", "the estimate plus 20%");
        assert_eq!(
            send["tx"]["max_fee_per_gas"], "30000000000",
            "the core's quote"
        );
        assert!(send["tx"].get("nonce").is_none());
        let refused = sign(&mut core, id + 1, send, |tx| edit(tx));
        assert_eq!(
            refused["error"]["code"], "not_authorized",
            "{field}: {refused}"
        );
        assert_eq!(refused["error"]["data"]["reason"], "mismatch", "{field}");
        // The token was burnt by its presentation: nothing signs with it.
        let again = sign(&mut core, id + 2, send, |_| {});
        assert!(again.get("error").is_some(), "{field}: {again}");
    }
    let (_, after) = approve(&mut core, id + 10, &mut node, json!({}));
    let Next::Done(response) = after else {
        panic!()
    };
    let signed = sign(&mut core, id + 11, &response["result"]["send"], |_| {});
    assert!(signed["result"]["raw"].is_string(), "{signed}");
}

/// A crossed answer (another prompt's id, a pick not offered, a choice
/// that isn't a boolean) fails the request with no token minted.
#[test]
fn a_crossed_answer_mints_nothing() {
    let (_root, mut core, _clock) = core(&connected());
    let mut node = Node::new(estimate());
    for (i, choices) in [
        json!({ "alwaysAllow": "yes" }),
        json!({ "other": true }),
        json!([]),
    ]
    .into_iter()
    .enumerate()
    {
        let id = 100 + i as u64 * 10;
        let (_, after) = approve(&mut core, id, &mut node, choices);
        let Next::Done(response) = after else {
            panic!()
        };
        assert_eq!(
            response["error"]["data"]["reason"], "mismatch",
            "{response}"
        );
    }
    request(&mut core, 200, Some(SITE), &send_body());
    let Next::Prompt(asked) = next(&mut core, 200, &mut node) else {
        panic!()
    };
    let answer = json!({ "prompt": "00".repeat(16), "handle": "11".repeat(32),
        "approve": true, "choices": {}, "world": world() });
    respond(&mut core, &asked, json!({ "result": answer }));
    let Next::Done(response) = next(&mut core, 200, &mut node) else {
        panic!()
    };
    assert_eq!(
        response["error"]["data"]["reason"], "mismatch",
        "{response}"
    );
    assert_eq!(grant_file(&core), connected());
}

/// APR-7: in Agent custody (`agent` true, or missing) a contract call's
/// prompt shows `alwaysAllow: false` and offers it unticked only, with
/// `feeAcknowledged` still offered; an approve that ticks it mints nothing
/// (`mismatch`), and one that doesn't gets a `{ send }` whose signature
/// writes no rule. With `agent: false` it is shown and offered, and a tick
/// rides in the token: the signature writes the site's rule.
#[test]
fn no_always_allow_in_custody() {
    let (_root, mut core, _clock) = core(&connected());
    let mut node = Node::new(estimate());
    let ask = |core: &mut Core, node: &mut Node, id: u64, agent: Option<bool>| {
        request_as(core, id, agent, &send_body());
        let Next::Prompt(asked) = next(core, id, node) else {
            panic!("{agent:?}: no prompt")
        };
        asked
    };
    let answer = |core: &mut Core, node: &mut Node, id: u64, asked: &Value, ticked: bool| {
        let handle = format!("{:064x}", 1000 + asked["id"].as_u64().unwrap());
        let answer = json!({ "prompt": asked["params"]["prompt"], "handle": handle,
            "approve": true, "choices": { "alwaysAllow": ticked }, "world": world() });
        respond(core, asked, json!({ "result": answer }));
        let Next::Done(response) = next(core, id, node) else {
            panic!("asked again")
        };
        response
    };
    let mut id = 100;
    for agent in [Some(true), None, Some(false)] {
        let offered = agent == Some(false);
        let asked = ask(&mut core, &mut node, id, agent);
        assert_eq!(asked["params"]["view"]["alwaysAllow"], offered, "{agent:?}");
        let picks = if offered {
            json!([false, true])
        } else {
            json!([false])
        };
        assert_eq!(
            asked["params"]["choices"],
            json!({ "alwaysAllow": picks, "feeAcknowledged": [false, true] }),
            "{agent:?}"
        );
        if !offered {
            let crossed = answer(&mut core, &mut node, id, &asked, true);
            assert_eq!(crossed["error"]["data"]["reason"], "mismatch", "{crossed}");
            id += 1;
            let asked = ask(&mut core, &mut node, id, agent);
            let response = answer(&mut core, &mut node, id, &asked, false);
            let signed = sign(&mut core, id + 1, &response["result"]["send"], |_| {});
            assert!(signed["result"]["raw"].is_string(), "{signed}");
            assert!(signed["result"].get("rule").is_none(), "{signed}");
            assert_eq!(grant_file(&core), connected(), "{agent:?}");
        } else {
            let response = answer(&mut core, &mut node, id, &asked, true);
            let signed = sign(&mut core, id + 1, &response["result"]["send"], |_| {});
            assert_eq!(
                signed["result"]["rule"],
                json!({ "added": true }),
                "{signed}"
            );
            assert_ne!(grant_file(&core), connected());
        }
        id += 10;
    }
}

/// Fee evidence older than 60 s on the approvals' clock is asked for again
/// at the approval, as the reference's `evidenceFor` asks: a fee now above
/// three times it is asked again, and confirmed, minted.
#[test]
fn stale_evidence_is_asked_for_again_at_approval() {
    let (_root, mut core, clock) = core(&connected());
    let mut node = Node::new(estimate());
    request(&mut core, 100, Some(SITE), &send_body());
    let Next::Prompt(asked) = next(&mut core, 100, &mut node) else {
        panic!()
    };
    // The core asked for its own evidence before the prompt: the verdict
    // compares the fee with its quote.
    let check = &asked["params"]["view"]["feeCheck"];
    assert_eq!(
        (check["comparable"].clone(), check["above"].clone()),
        (json!(true), json!(false))
    );
    assert_eq!(
        (check["basis"].clone(), check["ratio"].clone()),
        (json!("quote"), json!("1"))
    );
    std::fs::write(&clock, (1_000_000 + 60_001).to_string()).unwrap();
    node.gas_price = 2 * GWEI;
    node.priority = Some(GWEI);
    let seen = node.seen.len();
    let answer = json!({ "prompt": asked["params"]["prompt"], "handle": "22".repeat(32),
        "approve": true, "choices": {}, "world": world() });
    respond(&mut core, &asked, json!({ "result": answer }));
    let Next::Prompt(again) = next(&mut core, 100, &mut node) else {
        panic!("not asked again")
    };
    assert!(
        node.seen[seen..].iter().any(|m| m == "eth_gasPrice"),
        "new evidence"
    );
    let view = &again["params"]["view"];
    assert_eq!(
        (
            view["feeAskAgain"].clone(),
            view["feeCheck"]["askAgain"].clone()
        ),
        (json!(true), json!(true))
    );
    assert_eq!(view["feeCheck"]["ratio"], "10");
    let answer = json!({ "prompt": again["params"]["prompt"], "handle": "33".repeat(32),
        "approve": true, "choices": { "feeAcknowledged": true }, "world": world() });
    respond(&mut core, &again, json!({ "result": answer }));
    let Next::Done(response) = next(&mut core, 100, &mut node) else {
        panic!()
    };
    assert!(
        response["result"]["send"]["token"].is_string(),
        "{response}"
    );
}

/// The reference's transaction rules in Q9's form (`rule-legacy`): the
/// limited rule, granted at the vectors' `now`.
fn q9(mut grants: Value) -> Value {
    for entry in grants.as_object_mut().unwrap().values_mut() {
        let rules = &mut entry["autoApprove"];
        let mut limited = Vec::new();
        for rule in rules["transactions"].as_array().unwrap() {
            let mut rule = rule.clone();
            rule["grantedAt"] = json!(NOW);
            limited.push(rule);
        }
        if !limited.is_empty() {
            rules["transactions"] = json!([]);
            rules["limited"] = json!({ "signing": null, "transactions": limited });
        }
    }
    grants
}

/// `sign.transaction` under the site's rule, as main signs a rule's
/// `{ send }` in the site's turn with D12's `paused`.
fn sign_standing(core: &mut Core, id: u64, send: &Value, paused: bool) -> Value {
    let mut tx = send["tx"].clone();
    tx["nonce"] = json!("7");
    core.send(&json!({
        "type": "request", "id": id, "method": "sign.transaction",
        "params": {
            "key": { "kind": "account", "index": send["account"] }, "tx": tx,
            "authorization": { "standing": { "paused": paused } },
        },
        "context": page(Some(SITE)),
    }));
    core.until_response(id)
}

/// APR-5e-2's 10 scenarios through the binary. A device's send runs to
/// `{ device }`, whose token main spends on the device (a Ledger's
/// `approval.spend`, a phone's `phone.job`); what the device does next is
/// main's. A rule's send runs to `{ send }` under the rule, which main
/// signs under `{ standing }` in the site's turn: a turn the reference
/// found busy is main's refusal, and a payment waiting gives `paused`,
/// which the core refuses. The rule is the reference's in Q9's form, and
/// the fee evidence two endpoints' (one for `send-rule-fee-needs-user`,
/// whose verdict is one endpoint's word).
#[test]
fn every_device_and_rule_send_replays_through_the_core() {
    let file = load();
    let (mut prompts, mut devices, mut ruled) = (0, 0, 0);
    for scenario in file["scenarios"].as_array().unwrap() {
        let name = scenario["id"].as_str().unwrap();
        if !logic::APR5E2.contains(&name) {
            continue;
        }
        let endpoints = if name == "send-rule-fee-needs-user" {
            1
        } else {
            2
        };
        let locked = scenario["world"]["vault"] == false;
        let (_root, mut core, _clock) =
            core_for(&q9(scenario["grants"]["before"].clone()), endpoints, locked);
        let recorded = &scenario["requests"][0];
        let effects = recorded["effects"].as_array().unwrap();
        let custody: Vec<bool> = effects
            .iter()
            .filter(|e| e["effect"] == "custody")
            .map(|e| e["answer"] == true)
            .collect();
        let mut world = logic::world_of(&file, scenario);
        world["paused"] = json!(false);
        let estimate = effects
            .iter()
            .find(|e| e["effect"] == "chain.request")
            .unwrap();
        let mut node = Node::new(estimate.clone());
        let mut body = json!({ "method": recorded["method"], "world": world });
        body["params"] = recorded["params"].clone();
        let id = 100;
        request(&mut core, id, Some(SITE), &body);
        let mut shown = effects.iter().filter(|e| e["effect"] == "prompt");
        let response = loop {
            let message = core.recv();
            match (message["type"].as_str(), message["method"].as_str()) {
                (Some("event"), _) => {}
                (Some("request"), Some("shell.rpc")) => {
                    let answer = node.answer(&message);
                    respond(&mut core, &message, answer);
                }
                (Some("request"), Some("approval.recheck")) => {
                    // Main's read just before the effect: the reference's
                    // custody read after its turn.
                    let agent = custody.get(2).copied().unwrap_or(false);
                    respond(
                        &mut core,
                        &message,
                        json!({ "result": { "live": true, "agent": agent } }),
                    );
                }
                (Some("request"), Some("approval.request")) => {
                    prompts += 1;
                    let prompt = shown.next().unwrap_or_else(|| panic!("{name}: no prompt"));
                    let params = &message["params"];
                    assert_eq!(params["kind"], prompt["args"]["kind"], "{name}");
                    let expected = if params["kind"] == "eth.send" {
                        adapted(&prompt["args"]["view"], &params["view"])
                    } else {
                        // The unlock: main unlocks as the user approves.
                        let reply = core.call_shell(
                            id + 50,
                            "vault.unlock",
                            json!({ "password_b64": STANDARD.encode("testpass1") }),
                        );
                        assert!(reply["result"].is_object(), "{reply}");
                        prompt["args"]["view"].clone()
                    };
                    assert_eq!(params["view"].to_string(), expected.to_string(), "{name}");
                    let handle = format!("{:064x}", message["id"].as_u64().unwrap());
                    let answer = answer_of(&params["prompt"], &handle, &prompt["answer"], &world);
                    respond(&mut core, &message, json!({ "result": answer }));
                }
                (Some("response"), _) if message["id"] == id => break message,
                _ => panic!("{name}: unexpected {message}"),
            }
        };
        assert!(shown.next().is_none(), "{name}: a prompt not asked");
        let result = &response["result"];
        let issued = effects.iter().find(|e| e["effect"] == "token.issue");
        if let Some(issued) = issued {
            devices += 1;
            let device = &result["device"];
            let mut payload = issued["args"]["payload"].clone();
            payload.as_object_mut().unwrap().remove("origin");
            let tx = logic::core_tx(&payload);
            assert_eq!(device["kind"], "dapp-send", "{name}");
            assert_eq!(device["account"], issued["args"]["account"], "{name}");
            assert_eq!(device["payload"], json!({ "tx": tx }), "{name}");
            let account = device["account"].as_u64().unwrap();
            let auth = json!({ "token": device["token"], "kind": "dapp-send", "handle": device["handle"] });
            let spent = if device["type"] == "remote" {
                core.send(&json!({
                    "type": "request", "id": id + 170, "method": "phone.job",
                    "params": { "account": account, "address": scenario["world"].get("wallets")
                        .unwrap_or(&file["wallets"])[2]["address"], "method": "transaction",
                        "payload": device["payload"], "authorization": auth, "target": 9 },
                    "context": page(Some(SITE)),
                }));
                core.until_response(id + 170)
            } else {
                assert_eq!(device["type"], "ledger", "{name}");
                core.send(&json!({
                    "type": "request", "id": id + 170, "method": "approval.spend",
                    "params": { "token": device["token"], "kind": "dapp-send", "account": account,
                        "payload": device["payload"], "handle": device["handle"] },
                    "context": page(Some(SITE)),
                }));
                core.until_response(id + 170)
            };
            assert!(spent["result"].is_object(), "{name}: {spent}");
        } else if let Some(send) = result.get("send") {
            ruled += 1;
            assert_eq!(send["standing"], true, "{name}");
            let signed = effects.iter().find(|e| e["effect"] == "send.sign");
            match signed {
                Some(signed) => {
                    assert_eq!(send["tx"], logic::core_tx(&signed["args"]["tx"]), "{name}");
                    let reply = sign_standing(&mut core, id + 190, send, false);
                    assert!(reply["result"]["raw"].is_string(), "{name}: {reply}");
                }
                // Main's refusal in the site's turn; a payment waiting
                // gives `paused`, which the core refuses as well.
                None => {
                    let reply = sign_standing(&mut core, id + 190, send, true);
                    assert_eq!(
                        reply["error"]["data"]["reason"], "paused",
                        "{name}: {reply}"
                    );
                }
            }
        } else {
            assert_eq!(result.to_string(), recorded["result"].to_string(), "{name}");
        }
        assert_eq!(
            grant_file(&core),
            q9(scenario["grants"]["after"].clone()),
            "{name}"
        );
    }
    assert_eq!((prompts, devices, ruled), (6, 2, 4));
}

/// A site's limited rule for the test's `approve` call, up to `max` wei.
fn ruled_grants(max: &str) -> Value {
    let mut grants = connected();
    grants[SITE]["autoApprove"]["limited"] = json!({ "signing": null, "transactions": [{
        "to": TO, "selector": "0x095ea7b3", "chainId": 1, "maxValue": max, "grantedAt": NOW,
    }] });
    grants
}

/// Plays the node until request `id`'s recheck, its prompt or its
/// response.
fn until_main(core: &mut Core, id: u64, node: &mut Node) -> Value {
    loop {
        let message = core.recv();
        match (message["type"].as_str(), message["method"].as_str()) {
            (Some("event"), _) => {}
            (Some("request"), Some("shell.rpc")) => {
                let answer = node.answer(&message);
                respond(core, &message, answer);
            }
            (Some("request"), _) => return message,
            (Some("response"), _) if message["id"] == id => return message,
            _ => panic!("unexpected {message}"),
        }
    }
}

/// A rule's send (APR-5e-2) is rechecked just before its effect, in the
/// reference's order: custody, then the rule (gone once revoked), then the
/// document. Answered by the rule, it is `{ send }` under it: main signs it
/// under `{ standing }`, which binds what the rule covers and counts, so
/// after Q9's burst of five the next is asked, never refused.
#[test]
fn a_rule_send_is_rechecked_bound_and_counted() {
    let (_root, mut core, _clock) = core_for(&ruled_grants("5"), 2, false);
    let mut node = Node::new(estimate());
    let mut body = send_body();
    body["world"]["paused"] = json!(false);
    let mut ask = |core: &mut Core, id: u64, live: bool, agent: bool| {
        request(core, id, Some(SITE), &body);
        let recheck = until_main(core, id, &mut node);
        assert_eq!(recheck["method"], "approval.recheck", "{recheck}");
        respond(
            core,
            &recheck,
            json!({ "result": { "live": live, "agent": agent } }),
        );
        until_main(core, id, &mut node)
    };
    let custody = ask(&mut core, 100, true, true);
    assert_eq!(
        custody["result"]["error"]["data"]["reason"], "agent_custody",
        "{custody}"
    );
    let gone = ask(&mut core, 110, false, false);
    assert_eq!(gone["result"]["error"]["code"], 4100, "{gone}");
    let mut id = 120;
    for n in 0..5 {
        let send = ask(&mut core, id, true, false)["result"]["send"].clone();
        assert_eq!(send["standing"], true, "{send}");
        assert_eq!(send["tx"]["gas_limit"], "60000");
        if n == 0 {
            // What the rule doesn't cover signs nothing: another `to`, or
            // more value than the send it came from.
            for (field, value) in [
                ("to", json!("0x5555555555555555555555555555555555555555")),
                ("value", json!("6")),
            ] {
                let mut other = send.clone();
                other["tx"][field] = value;
                let refused = sign_standing(&mut core, id + 1, &other, false);
                assert_eq!(
                    refused["error"]["data"]["reason"], "no_rule",
                    "{field}: {refused}"
                );
                id += 1;
            }
        }
        let signed = sign_standing(&mut core, id + 5, &send, false);
        assert!(signed["result"]["raw"].is_string(), "{signed}");
        id += 10;
    }
    // Past the rate: no rule is chosen, the user is asked.
    request(&mut core, id, Some(SITE), &body);
    let asked = until_main(&mut core, id, &mut node);
    assert_eq!(asked["params"]["kind"], "eth.send", "{asked}");
    let answer = json!({ "prompt": asked["params"]["prompt"], "handle": "77".repeat(32),
        "approve": false, "choices": {} });
    respond(&mut core, &asked, json!({ "result": answer }));
    let rejected = until_main(&mut core, id, &mut node);
    assert_eq!(rejected["result"]["error"]["code"], 4001, "{rejected}");
}

/// The rule revoked between its choice and the recheck: refused, nothing
/// to sign. The vault locked: the unlock first, its refusals the user's.
#[test]
fn a_rule_send_gone_or_unlock_refused_signs_nothing() {
    let (_root, mut core, _clock) = core_for(&ruled_grants("5"), 2, true);
    let mut node = Node::new(estimate());
    let mut body = send_body();
    body["world"]["paused"] = json!(false);
    for (id, answer, code) in [
        (100, json!({ "approve": false, "choices": {} }), 4001),
        (110, json!({ "busy": true }), -32002),
        (120, json!({ "approve": true, "choices": { "x": true } }), 0),
    ] {
        request(&mut core, id, Some(SITE), &body);
        let unlock = until_main(&mut core, id, &mut node);
        assert_eq!(unlock["params"]["kind"], "vault.unlock", "{unlock}");
        assert_eq!(unlock["params"]["view"]["reason"], "send");
        let mut answer = answer;
        answer["prompt"] = unlock["params"]["prompt"].clone();
        if answer.get("approve").is_some() {
            answer["handle"] = json!(format!("{id:064x}"));
        }
        if answer["approve"] == true {
            answer["world"] = body["world"].clone();
        }
        respond(&mut core, &unlock, json!({ "result": answer }));
        let refused = until_main(&mut core, id, &mut node);
        match code {
            0 => assert_eq!(refused["error"]["data"]["reason"], "mismatch", "{refused}"),
            code => assert_eq!(refused["result"]["error"]["code"], code, "{refused}"),
        }
    }
    let reply = core.call_shell(
        125,
        "vault.unlock",
        json!({ "password_b64": STANDARD.encode("testpass1") }),
    );
    assert!(reply["result"].is_object(), "{reply}");
    request(&mut core, 130, Some(SITE), &body);
    let recheck = until_main(&mut core, 130, &mut node);
    assert_eq!(recheck["method"], "approval.recheck", "{recheck}");
    let revoked = core.call_shell(
        135,
        "approval.revoke",
        json!({ "store": "dapp", "key": SITE, "what": "grant" }),
    );
    assert!(revoked.get("result").is_some(), "{revoked}");
    respond(
        &mut core,
        &recheck,
        json!({ "result": { "live": true, "agent": false } }),
    );
    let gone = until_main(&mut core, 130, &mut node);
    assert_eq!(
        gone["result"]["error"]["message"],
        "Signing was not confirmed: this request is not covered by the site's auto-approve rules",
        "{gone}"
    );
}

/// Main's own `chain.fee_reference` for chain 1, the node answering at 2
/// gwei with a 1 gwei tip: a reference the core's quote (30 gwei) is far
/// above.
fn lower_the_reference(core: &mut Core, id: u64, node: &mut Node) {
    node.gas_price = 2 * GWEI;
    node.priority = Some(GWEI);
    core.send(&json!({
        "type": "request", "id": id, "method": "chain.fee_reference",
        "params": { "chain_id": 1, "deadline_ms": 30_000 },
        "context": { "caller": "chrome" },
    }));
    let reference = until_main(core, id, node);
    assert!(reference.get("error").is_none(), "{reference}");
}

/// Six rule sends chosen while the rule had room, each held at its
/// recheck. The first five answered and signed under `{ standing }` spend
/// Q9's burst, so at the sixth's recheck the rule is past its rate: the
/// user is asked with the sixth's own quote (*inferred*, as Q9 asks rather
/// than refuses), never `{ send }` under the rule nor its refusal.
/// Approved, the send is the user's: `{ send }` with its token.
#[test]
fn a_rule_past_its_rate_by_its_recheck_is_asked() {
    let (_root, mut core, _clock) = core_for(&ruled_grants("5"), 2, false);
    let mut node = Node::new(estimate());
    let mut body = send_body();
    body["world"]["paused"] = json!(false);
    let mut rechecks = Vec::new();
    for n in 0..6u64 {
        let id = 100 + 10 * n;
        request(&mut core, id, Some(SITE), &body);
        let recheck = until_main(&mut core, id, &mut node);
        assert_eq!(recheck["method"], "approval.recheck", "{n}: {recheck}");
        rechecks.push((id, recheck));
    }
    let live = json!({ "result": { "live": true, "agent": false } });
    let (sixth, last) = rechecks.pop().unwrap();
    // Main's request IDs only increase: the signatures come after all six.
    for (id, recheck) in &rechecks {
        respond(&mut core, recheck, live.clone());
        let send = until_main(&mut core, *id, &mut node)["result"]["send"].clone();
        assert_eq!(send["standing"], true, "{id}: {send}");
        let signed = sign_standing(&mut core, id + 100, &send, false);
        assert!(signed["result"]["raw"].is_string(), "{id}: {signed}");
    }
    respond(&mut core, &last, live);
    let asked = until_main(&mut core, sixth, &mut node);
    assert_eq!(asked["method"], "approval.request", "{asked}");
    assert_eq!(asked["params"]["kind"], "eth.send", "{asked}");
    assert_eq!(asked["params"]["request"], sixth, "{asked}");
    assert_eq!(
        asked["params"]["view"]["fee"]["gasLimit"], "60000",
        "{asked}"
    );
    assert_eq!(
        asked["params"]["view"]["feeCheck"]["above"], false,
        "{asked}"
    );
    let answer = json!({ "prompt": asked["params"]["prompt"], "handle": "66".repeat(32),
        "approve": true, "choices": {}, "world": body["world"] });
    respond(&mut core, &asked, json!({ "result": answer }));
    let done = until_main(&mut core, sixth, &mut node);
    let send = &done["result"]["send"];
    assert!(send["token"].is_string(), "{done}");
    assert!(send.get("standing").is_none(), "{done}");
    let signed = sign(&mut core, 300, send, |_| {});
    assert!(signed["result"]["raw"].is_string(), "{signed}");
}

/// A rule send the fee check let through at its quote, whose fee needs the
/// user by its recheck: main's own fee reference, lowered while the recheck
/// is open, finds the prepared fee newly above it, so the user is asked
/// with the check's verdict now (*inferred*, as for the rate), never
/// `{ send }` under the rule nor its refusal.
#[test]
fn a_rule_send_whose_fee_needs_the_user_by_its_recheck_is_asked() {
    let (_root, mut core, _clock) = core_for(&ruled_grants("5"), 2, false);
    let mut node = Node::new(estimate());
    let mut body = send_body();
    body["world"]["paused"] = json!(false);
    request(&mut core, 100, Some(SITE), &body);
    let recheck = until_main(&mut core, 100, &mut node);
    assert_eq!(recheck["method"], "approval.recheck", "{recheck}");
    lower_the_reference(&mut core, 103, &mut node);
    respond(
        &mut core,
        &recheck,
        json!({ "result": { "live": true, "agent": false } }),
    );
    let asked = until_main(&mut core, 100, &mut node);
    assert_eq!(asked["method"], "approval.request", "{asked}");
    assert_eq!(asked["params"]["kind"], "eth.send", "{asked}");
    let check = &asked["params"]["view"]["feeCheck"];
    assert_eq!(
        (check["above"].clone(), check["autoApprove"].clone()),
        (json!(true), json!(false)),
        "{asked}"
    );
    let answer = json!({ "prompt": asked["params"]["prompt"], "handle": "55".repeat(32),
        "approve": false, "choices": {} });
    respond(&mut core, &asked, json!({ "result": answer }));
    let rejected = until_main(&mut core, 100, &mut node);
    assert_eq!(rejected["result"]["error"]["code"], 4001, "{rejected}");
}

/// A Ledger's send with "Always allow" ticked answers `{ device }`, whose
/// `dapp-send` spent by main gives the device send's receipt. A Safe's is
/// asked with its executor paying, "Always allow" not pickable, and answers
/// `{ device }` with the site's `safe-send` for the Safe, its chain and the
/// SafeTx, which main spends into a Safe approval.
#[test]
fn a_device_send_answers_its_token() {
    const LEDGER: &str = "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0";
    const SAFE: &str = "0x4444444444444444444444444444444444444444";
    let mut grants = connected();
    grants[SITE]["walletIndex"] = json!(1);
    let (_root, mut core, _clock) = core_for(&grants, 2, false);
    let mut estimate = estimate();
    estimate["args"]["params"][0]["from"] = json!(LEDGER);
    let mut node = Node::new(estimate);
    let mut body = send_body();
    body["world"]["wallets"] = json!([
        { "index": 1, "name": "Ledger", "address": LEDGER, "type": "ledger" },
        { "index": 1000, "name": "Team Safe", "address": SAFE, "type": "safe" },
    ]);
    let approve = |core: &mut Core, node: &mut Node, id: u64, body: &Value, choices: Value| {
        request(core, id, Some(SITE), body);
        let asked = until_main(core, id, node);
        let answer = json!({ "prompt": asked["params"]["prompt"], "handle": format!("{id:064x}"),
            "approve": true, "choices": choices, "world": body["world"] });
        respond(core, &asked, json!({ "result": answer }));
        (asked, until_main(core, id, node))
    };
    let spend = |core: &mut Core, id: u64, device: &Value| {
        core.send(&json!({
            "type": "request", "id": id, "method": "approval.spend",
            "params": { "token": device["token"], "kind": device["kind"], "account": device["account"],
                "payload": device["payload"], "handle": device["handle"] },
            "context": page(Some(SITE)),
        }));
        core.until_response(id)
    };
    let (_, done) = approve(
        &mut core,
        &mut node,
        100,
        &body,
        json!({ "alwaysAllow": true }),
    );
    let device = &done["result"]["device"];
    assert_eq!(
        (device["type"].clone(), device["kind"].clone()),
        (json!("ledger"), json!("dapp-send"))
    );
    assert_eq!(device["payload"]["tx"]["gas_limit"], "60000", "{done}");
    let spent = spend(&mut core, 101, device);
    assert!(spent["result"]["receipt"].is_string(), "{spent}");
    // A Safe's, on Gnosis.
    let mut grants = connected();
    grants[SITE]["walletIndex"] = json!(1000);
    let (_root, mut core, _clock) = core_for(&grants, 2, false);
    body["world"]["window_chain"] = json!(100);
    let (asked, crossed) = approve(
        &mut core,
        &mut node,
        110,
        &body,
        json!({ "alwaysAllow": true }),
    );
    assert_eq!(
        asked["params"]["view"]["fee"],
        json!({ "paidBy": "executor" }),
        "{asked}"
    );
    assert_eq!(
        asked["params"]["choices"],
        json!({ "alwaysAllow": [false], "feeAcknowledged": [false, true] })
    );
    assert_eq!(crossed["error"]["data"]["reason"], "mismatch", "{crossed}");
    let (_, done) = approve(&mut core, &mut node, 120, &body, json!({}));
    let device = &done["result"]["device"];
    assert_eq!(device["kind"], "safe-send", "{done}");
    assert_eq!(
        device["payload"],
        json!({ "safe": SAFE, "chain_id": "100",
        "tx": { "to": TO, "value": "5", "data": APPROVE_DATA } })
    );
    let spent = spend(&mut core, 121, device);
    assert!(spent["result"].is_object(), "{spent}");
}

/// A phone picks and pays its own fee (design 0012, "Transaction
/// building"): its send is judged on no fee evidence, before its prompt or
/// at its approve. Main's own fee reference, lowered while the prompt is
/// open so that a vault's fee would be asked again, leaves the phone's
/// approve its `{ device }`, whose `dapp-send` main spends on `phone.job`.
#[test]
fn a_phone_send_is_never_fee_checked() {
    const PHONE: &str = "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A";
    let mut grants = connected();
    grants[SITE]["walletIndex"] = json!(2);
    let (_root, mut core, _clock) = core_for(&grants, 2, false);
    let mut estimate = estimate();
    estimate["args"]["params"][0]["from"] = json!(PHONE);
    let mut node = Node::new(estimate);
    let mut body = send_body();
    body["world"]["wallets"] =
        json!([{ "index": 2, "name": "Phone", "address": PHONE, "type": "remote" }]);
    request(&mut core, 100, Some(SITE), &body);
    let asked = until_main(&mut core, 100, &mut node);
    assert_eq!(asked["params"]["kind"], "eth.send", "{asked}");
    let view = &asked["params"]["view"];
    assert_eq!(
        (view["feeCheck"].clone(), view["feeAskAgain"].clone()),
        (Value::Null, json!(false)),
        "{asked}"
    );
    lower_the_reference(&mut core, 103, &mut node);
    let answer = json!({ "prompt": asked["params"]["prompt"], "handle": "44".repeat(32),
        "approve": true, "choices": {}, "world": body["world"] });
    respond(&mut core, &asked, json!({ "result": answer }));
    let done = until_main(&mut core, 100, &mut node);
    let device = &done["result"]["device"];
    assert_eq!(
        (device["type"].clone(), device["kind"].clone()),
        (json!("remote"), json!("dapp-send")),
        "{done}"
    );
    let tx = &device["payload"]["tx"];
    assert_eq!(
        (tx["gas_limit"].clone(), tx["max_fee_per_gas"].clone()),
        (json!("60000"), json!("30000000000")),
        "{done}"
    );
    core.send(&json!({
        "type": "request", "id": 110, "method": "phone.job",
        "params": { "account": device["account"], "address": PHONE, "method": "transaction",
            "payload": device["payload"],
            "authorization": { "token": device["token"], "kind": "dapp-send", "handle": device["handle"] },
            "target": 9 },
        "context": page(Some(SITE)),
    }));
    let spent = core.until_response(110);
    assert!(spent["result"].is_object(), "{spent}");
}
