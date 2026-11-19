//! Names over IPNS end to end (design 0012, APR-5f): the real binary, with
//! the test playing main. A document whose key is a DNS name served over
//! IPNS sends `PageContext.transport_key`, and the core resolves the name
//! itself, with its own naming, at each of the reference's checks of a
//! name-revalidated method. Here naming reads Direct from one endpoint,
//! and the test hook `FREEDOM_CORED_TEST_EIP1193_NAMES_UNCACHED` makes each
//! check a fresh lookup, so each check is one `eth_call` that main answers
//! as the test scripts it: the name serving the document's IPNS key, moved
//! to other content, or a node that fails.
//!
//! Every `step: "APR-5f"` scenario of vectors/eip1193.json replays, the
//! send's (APR-5f-2) with chain 1's node playing the core's own estimate and
//! quote. Then the guarantees: a name moved at each check point (before the
//! prompt, while it is open, between the approve and the effect, after the
//! signature) refuses with nothing written or signed, and a send's (a
//! vault's, a device's, a Safe's and a rule's) with nothing prepared or
//! minted; a binding ended by another request is read at main's recheck; a
//! name the core can't resolve fails closed; the binding ends for the
//! document, not for a new one; a page without a binding resolves nothing;
//! and a check has the request's deadline and cancel.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{Core, dirs, naming_recorded, spawn_env};
use serde_json::{Value, json};

const NAME: &str = "docs.example.org";
const IPNS_KEY: &str = "k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8";
/// `IPNS_KEY`'s contenthash: `ipns-ns`, then its CIDv1 (libp2p-key, an
/// inlined Ed25519 key), as ENS stores it.
const IPNS_CONTENTHASH: &str =
    "e5010172002408011220e4680b2f8c8d21090e6aa327f1bb342ab8e7d9238f1e35831a54d6a8f5c91124";
/// Another IPNS key's contenthash: the name moved to another key.
const OTHER_CONTENTHASH: &str =
    "e5010172002408011220000000000000000000000000000000000000000000000000000000000000beef";
const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NO_ADDRESS: &str =
    r#"{"error":{"code":4100,"message":"This page has no address to connect from yet"}}"#;
const ACCOUNT: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const GWEI: u64 = 1_000_000_000;

fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/eip1193.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn wall_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// What main's node answers for one name check.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Name {
    /// The name serves the document's IPNS key.
    Serves,
    /// The name moved: another IPNS key.
    Moved,
    /// The name moved: IPFS content (the recorded answer).
    MovedToIpfs,
    /// The node fails the call.
    Fails,
}

/// The `resolve` answer, ABI-encoded `(bytes, address)`, for `contenthash`.
fn resolve_body(contenthash: &str) -> String {
    let bytes = contenthash.len() / 2;
    let padded = bytes.div_ceil(32) * 32;
    let word = |n: usize| format!("{n:064x}");
    let inner = format!(
        "{}{}{contenthash}{}",
        word(32),
        word(bytes),
        "00".repeat(padded - bytes)
    );
    let result = format!(
        "0x{}{}{}{inner}",
        word(0x40),
        format_args!("{:0>64}", "2".repeat(40)),
        word(inner.len() / 2)
    );
    json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string()
}

/// main, played: naming's and the chain's `shell.rpc` answered as
/// scripted, the core's other requests and its answers handed to the test.
struct Main {
    core: Core,
    names: VecDeque<Name>,
    /// The name checks the core made.
    checks: usize,
    /// The node's answers for naming's anchor, from the naming replay.
    recorded: std::collections::BTreeMap<String, String>,
    events: Vec<Value>,
    /// Chain 1's node (APR-5f-2): the estimates the core asked for, the
    /// params each must have when scripted, and the gas price and tip it
    /// answers.
    estimates: usize,
    estimate_params: Option<Value>,
    gas_price: u64,
    priority: u64,
}

impl Main {
    /// A core whose dApp store has moved, holding `grants`, its vault
    /// imported from ABANDON and unlocked, naming read Direct from `n1`,
    /// Gnosis read Direct from `e100`, and chain 1 from `e1` and `e1b` (two
    /// endpoints, so that the fee evidence a rule needs isn't one's word).
    /// `env` adds to the name hook.
    fn new(grants: &Value, env: &[(&str, &str)]) -> (tempfile::TempDir, Main) {
        Main::with_timeout(grants, env, 5000)
    }

    /// As [`Main::new`], naming's calls timing out after `timeout_ms`.
    fn with_timeout(
        grants: &Value,
        env: &[(&str, &str)],
        timeout_ms: u64,
    ) -> (tempfile::TempDir, Main) {
        Main::build(grants, env, timeout_ms, true)
    }

    /// As [`Main::with_timeout`]; with `uncached` false, naming's cache
    /// stands, so concurrent checks of one name join one lookup.
    fn build(
        grants: &Value,
        env: &[(&str, &str)],
        timeout_ms: u64,
        uncached: bool,
    ) -> (tempfile::TempDir, Main) {
        let (root, data, locks) = dirs();
        let mut all = Vec::new();
        if uncached {
            all.push(("FREEDOM_CORED_TEST_EIP1193_NAMES_UNCACHED", "1"));
        }
        all.extend_from_slice(env);
        let mut core = spawn_env("serve", &data, &locks, &[], &all);
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
        assert_eq!(core.event()["event"], "vault.unlocked");
        let configured = core.call(
            3,
            "naming.configure",
            json!({
                "reset": "none",
                "rpc": [{ "endpoint": "n1" }],
                "direct": { "endpoint": "n1", "user_configured": true },
                "prover": null,
                "policy": { "order": ["direct"], "prefer_verified": false },
                "quorum": { "k": 3, "m": 2, "timeout_ms": timeout_ms, "anchor": "latest", "anchor_ttl_ms": 30000 },
                "myotis_enabled": false,
                "tezos": ["t1", "t2", "t3"],
            }),
        );
        assert!(configured["result"].is_object(), "{configured}");
        let chain = json!({
            "chain_id": 100, "display_name": "Gnosis",
            "read_order": ["direct"], "broadcast_order": ["direct"],
            "quorum": { "k": 3, "m": 2, "timeout_ms": 5000 },
            "rpc": [{ "endpoint": "e100", "user_configured": false }],
            "prover": null, "myotis": false, "blockscout": null,
        });
        let ethereum = json!({
            "chain_id": 1, "display_name": "Ethereum",
            "read_order": ["direct"], "broadcast_order": ["direct"],
            "quorum": { "k": 3, "m": 2, "timeout_ms": 5000 },
            "rpc": [{ "endpoint": "e1", "user_configured": false },
                { "endpoint": "e1b", "user_configured": false }],
            "prover": null, "myotis": false, "blockscout": null,
        });
        let reply = core.call(4, "chain.configure", json!({ "chains": [chain, ethereum] }));
        assert!(reply["result"]["generations"].is_object(), "{reply}");
        let main = Main {
            core,
            names: VecDeque::new(),
            checks: 0,
            recorded: naming_recorded(),
            events: Vec::new(),
            estimates: 0,
            estimate_params: None,
            gas_price: 16 * GWEI,
            priority: 2 * GWEI,
        };
        (root, main)
    }

    fn script(&mut self, names: &[Name]) {
        self.names.extend(names.iter().copied());
    }

    /// Chain 1's node, for a send's estimate and the core's fee quote and
    /// evidence (APR-5f-2): `0xc350` (50 000 gas, so a gas limit of 60 000),
    /// and a gas price and tip that the core's quote makes 30 gwei and 2
    /// gwei, as the vectors' quote has them.
    fn chain_node(&mut self, body: &Value) -> String {
        let result = match body["method"].as_str().unwrap() {
            "eth_estimateGas" => {
                self.estimates += 1;
                if let Some(expected) = &self.estimate_params {
                    assert_eq!(&body["params"], expected);
                }
                json!("0xc350")
            }
            "eth_gasPrice" => json!(format!("{:#x}", self.gas_price)),
            "eth_maxPriorityFeePerGas" => json!(format!("{:#x}", self.priority)),
            _ => {
                return json!({ "jsonrpc": "2.0", "id": 1,
                    "error": { "code": -32601, "message": "the method does not exist" } })
                .to_string();
            }
        };
        json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string()
    }

    /// main's answer to a `shell.rpc`: the node's `text`, under the
    /// request's own JSON-RPC id.
    fn node(&mut self, message: &Value, text: &str) {
        let body: Value =
            serde_json::from_str(message["params"]["body"].as_str().unwrap()).unwrap();
        let mut answer: Value = serde_json::from_str(text).unwrap();
        answer["id"] = body["id"].clone();
        self.core.send(&json!({
            "type": "response", "id": message["id"],
            "result": { "status": 200, "body": STANDARD.encode(answer.to_string()) },
        }));
    }

    /// Reads the core's messages up to the answer to a sentinel request
    /// `id` (a keyless document's `eth_chainId`), so that the events sent
    /// before it are kept.
    fn flush(&mut self, id: u64, world: &Value) {
        self.request(
            id,
            &json!({ "caller": "page", "page": {
            "origin": "", "top_origin": "", "frame": 9, "navigation": 9, "agent": false,
        } }),
            "eth_chainId",
            json!([]),
            world,
        );
        let _ = self.answer(id);
    }

    /// The next message for the test: one of the core's requests to main
    /// that isn't a `shell.*`, or a response. Naming's and the chain's
    /// requests are answered here, events kept.
    fn next(&mut self) -> Value {
        loop {
            let message = self.core.recv();
            match (message["type"].as_str(), message["method"].as_str()) {
                (Some("request"), Some("shell.rpc")) => {
                    let params = &message["params"];
                    let body: Value =
                        serde_json::from_str(params["body"].as_str().unwrap()).unwrap();
                    let method = body["method"].as_str().unwrap();
                    let text = match (params["endpoint"].as_str().unwrap(), method) {
                        ("e100", "eth_blockNumber") => {
                            json!({ "jsonrpc": "2.0", "id": 1, "result": "0x1406f40" }).to_string()
                        }
                        ("n1", "eth_call") => {
                            self.checks += 1;
                            let name = self
                                .names
                                .pop_front()
                                .unwrap_or_else(|| panic!("an unscripted name check: {message}"));
                            match name {
                                Name::Serves => resolve_body(IPNS_CONTENTHASH),
                                Name::Moved => resolve_body(OTHER_CONTENTHASH),
                                Name::MovedToIpfs => self.recorded["eth_call"].clone(),
                                Name::Fails => json!({ "jsonrpc": "2.0", "id": 1,
                                    "error": { "code": -32000, "message": "header not found" } })
                                .to_string(),
                            }
                        }
                        ("n1", method) => self.recorded[method].clone(),
                        ("e1" | "e1b", _) => self.chain_node(&body),
                        _ => panic!("unexpected {message}"),
                    };
                    self.node(&message, &text);
                }
                // Main prefetches an agreed answer on its own timer.
                (Some("request"), Some("shell.prefetch")) | (Some("cancel"), _) => {}
                (Some("event"), _) => self.events.push(message),
                _ => return message,
            }
        }
    }

    /// The next of the core's requests to main, which must be `method`.
    fn asked(&mut self, method: &str) -> Value {
        let message = self.next();
        assert_eq!(message["type"], "request", "{message}");
        assert_eq!(message["method"], method, "{message}");
        message
    }

    fn respond(&mut self, request: &Value, result: Value) {
        self.core
            .send(&json!({ "type": "response", "id": request["id"], "result": result }));
    }

    /// The next name check's `eth_call`, held: main doesn't answer it.
    fn held_call(&mut self) -> Value {
        loop {
            let message = self.core.recv();
            match (message["type"].as_str(), message["method"].as_str()) {
                (Some("request"), Some("shell.rpc")) => {
                    let body: Value =
                        serde_json::from_str(message["params"]["body"].as_str().unwrap()).unwrap();
                    let method = body["method"].as_str().unwrap().to_owned();
                    if method == "eth_call" {
                        self.checks += 1;
                        return message;
                    }
                    let text = match message["params"]["endpoint"].as_str().unwrap() {
                        "e1" | "e1b" => self.chain_node(&body),
                        _ => self.recorded[&method].clone(),
                    };
                    self.node(&message, &text);
                }
                (Some("request"), Some("shell.prefetch")) | (Some("cancel"), _) => {}
                (Some("event"), _) => self.events.push(message),
                _ => panic!("unexpected {message}"),
            }
        }
    }

    /// The page's answer to request `id`, as text.
    fn answer(&mut self, id: u64) -> String {
        let message = self.next();
        assert_eq!(message["type"], "response", "{message}");
        assert_eq!(message["id"], id, "{message}");
        message["result"].to_string()
    }

    fn request(&mut self, id: u64, context: &Value, method: &str, params: Value, world: &Value) {
        self.core.send(&json!({
            "type": "request", "id": id, "method": "eip1193.request",
            "params": { "method": method, "params": params, "world": world },
            "context": context,
        }));
    }

    fn file(&self) -> Value {
        std::fs::read_to_string(self.core.grant_root.join("dapp-permissions.json"))
            .map_or(Value::Null, |text| serde_json::from_str(&text).unwrap())
    }

    /// Every name check scripted was made.
    fn all_checked(&self, what: &str) {
        assert!(
            self.names.is_empty(),
            "{what}: unmade checks {:?}",
            self.names
        );
    }
}

/// A name-keyed document: `navigation` numbers it.
fn named(navigation: u64) -> Value {
    json!({ "caller": "page", "page": {
        "origin": NAME, "top_origin": NAME, "frame": 1, "navigation": navigation,
        "agent": false, "transport_key": format!("ipns://{IPNS_KEY}"),
    } })
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

fn scenario<'a>(file: &'a Value, id: &str) -> &'a Value {
    file["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == id)
        .unwrap()
}

/// The core's grant file, its times taken within `[from, to]` and set to
/// the vectors' `now`.
fn normalized(mut grants: Value, from: u64, to: u64, now: u64) -> Value {
    if let Some(entries) = grants.as_object_mut() {
        for entry in entries.values_mut() {
            for field in ["connectedAt", "lastUsed"] {
                let at = entry[field].as_u64().unwrap();
                if at != now {
                    assert!((from..=to).contains(&at), "{field} {at}");
                    entry[field] = json!(now);
                }
            }
        }
    }
    grants
}

/// main's answer to an `approval.request` from a recorded decision.
fn decision_for(asked: &Value, decision: &Value, handle: u64, world: &Value) -> Value {
    let prompt = &asked["params"]["prompt"];
    if decision["approve"] == true {
        json!({ "prompt": prompt, "handle": format!("{handle:064x}"), "approve": true,
            "choices": decision["choices"], "world": world })
    } else if let Some(reason) = decision.get("closed") {
        json!({ "prompt": prompt, "closed": reason })
    } else {
        json!({ "prompt": prompt, "handle": format!("{handle:064x}"), "approve": false, "choices": {} })
    }
}

/// A send's view as the core shows a recorded one (APR-5f-2, as
/// `eip1193_send.rs` adapts it): its fee estimate priced at the core's own
/// effective price (16 gwei from chain 1's node), and the fee check's
/// verdict the core's own on its own evidence, with the recorded keys,
/// `maxCost` and `above`.
fn adapted(recorded: &Value, shown: &Value) -> Value {
    let mut expected = recorded.clone();
    if let Some(fee) = expected["fee"].as_object_mut() {
        let gas: u128 = fee["gasLimit"].as_str().unwrap().parse().unwrap();
        fee["estimate"] = json!((gas * 16 * u128::from(GWEI)).to_string());
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
fn every_apr5f_scenario_replays_through_the_core() {
    let file = load();
    let now = file["now"].as_u64().unwrap();
    let (mut scenarios, mut requests, mut checks, mut prompts) = (0, 0, 0, 0);
    for scenario in file["scenarios"].as_array().unwrap() {
        if scenario["step"] != "APR-5f" {
            continue;
        }
        let id = scenario["id"].as_str().unwrap();
        scenarios += 1;
        let doc = &scenario["world"]["documents"][0];
        assert_eq!(doc["key"], NAME, "{id}");
        assert_eq!(doc["transportKey"], format!("ipns://{IPNS_KEY}"), "{id}");
        let from = wall_ms();
        let (_root, mut main) = Main::new(&scenario["grants"]["before"], &[]);
        let world = world_of(&file, scenario);
        let context = named(1);
        let mut ended = false;
        for (i, recorded) in scenario["requests"].as_array().unwrap().iter().enumerate() {
            requests += 1;
            let what = format!("{id} #{i} {}", recorded["method"]);
            let rid = 10 + i as u64;
            let effects = recorded["effects"].as_array().unwrap();
            // The checks in order, up to the prompt and after it. Once the
            // binding has ended, the reference resolves nothing more
            // (`recheckName`: the document has no key), and none is
            // recorded.
            let mut before = Vec::new();
            let mut after = Vec::new();
            let mut prompt = None;
            for effect in effects {
                match effect["effect"].as_str().unwrap() {
                    "name.check" => {
                        assert!(!ended, "{what}: a check recorded after the end");
                        let name = if effect["answer"] == true {
                            Name::Serves
                        } else {
                            ended = true;
                            Name::Moved
                        };
                        if prompt.is_none() {
                            before.push(name);
                        } else {
                            after.push(name);
                        }
                    }
                    "prompt" => prompt = Some(effect),
                    // A send's estimate (APR-5f-2): the core's own, on chain
                    // 1's node, its params the reference's (the value as a
                    // quantity, as the machine writes it).
                    "chain.request" if recorded["method"] == "eth_sendTransaction" => {
                        let mut params = effect["args"]["params"].clone();
                        let value: u128 = params[0]["value"].as_str().unwrap().parse().unwrap();
                        params[0]["value"] = json!(format!("{value:#x}"));
                        main.estimate_params = Some(params);
                    }
                    // Main's: the agent's route and custody, and a send's
                    // turn (D12). The core's own: a send's fee quote and its
                    // fee checks, before the prompt and at the approve.
                    "agent.request" | "custody" | "chain.request" | "grant.write"
                    | "chain.fee_quote" | "fees.check" | "fees.at_approval" | "send.turn" => {}
                    other => panic!("{what}: {other}"),
                }
            }
            checks += before.len() + after.len();
            main.script(&before);
            let params = recorded.get("params").cloned().unwrap_or(json!([]));
            main.request(
                rid,
                &context,
                recorded["method"].as_str().unwrap(),
                params,
                &world,
            );
            if let Some(prompt) = prompt {
                prompts += 1;
                let asked = main.asked("approval.request");
                main.all_checked(&what);
                assert_eq!(asked["params"]["kind"], prompt["args"]["kind"], "{what}");
                let view = &prompt["args"]["view"];
                let expected = if prompt["args"]["kind"] == "eth.send" {
                    assert_eq!(main.estimates, 1, "{what}");
                    adapted(view, &asked["params"]["view"])
                } else {
                    view.clone()
                };
                assert_eq!(
                    asked["params"]["view"].to_string(),
                    expected.to_string(),
                    "{what}"
                );
                main.script(&after);
                let answer = decision_for(&asked, &prompt["answer"], rid, &world);
                main.respond(&asked, answer);
            }
            assert_eq!(main.answer(rid), recorded["result"].to_string(), "{what}");
            main.all_checked(&what);
        }
        main.flush(99, &world);
        let granted = scenario["grants"]["after"] != scenario["grants"]["before"];
        let changed: Vec<&Value> = main
            .events
            .iter()
            .filter(|e| e["event"] == "approval.changed")
            .collect();
        assert_eq!(changed.len(), usize::from(granted), "{id}: {changed:?}");
        let to = wall_ms();
        assert_eq!(
            normalized(main.file(), from, to, now),
            scenario["grants"]["after"],
            "{id}"
        );
    }
    assert_eq!((scenarios, requests, checks, prompts), (8, 10, 20, 4));
}

/// The vectors' grants: the name's grant (account 0) and the IPNS key's
/// own (account 1), on Gnosis.
fn grants() -> Value {
    scenario(&load(), "name-accounts-honest")["grants"]["before"].clone()
}

fn plain_world() -> Value {
    let file = load();
    world_of(&file, scenario(&file, "name-accounts-honest"))
}

/// A connect with no grant: moved at each of its three checks (before and
/// after the agent's route, after the prompt): 4100, no grant written, no
/// event. Then the document's later requests answer as a keyless one's,
/// with nothing resolved.
#[test]
fn a_connect_moved_at_any_check_writes_nothing() {
    for moved_at in 0..3 {
        let what = format!("moved at check {moved_at}");
        let (_root, mut main) = Main::new(&Value::Null, &[]);
        let world = plain_world();
        let mut names = vec![Name::Serves; moved_at];
        names.push(Name::Moved);
        let (before, after) = names.split_at(names.len().min(2));
        main.script(before);
        main.request(10, &named(1), "eth_requestAccounts", json!([]), &world);
        if moved_at == 2 {
            let asked = main.asked("approval.request");
            main.script(after);
            let approve = json!({ "approve": true, "choices": { "walletIndex": 0 } });
            main.respond(&asked, decision_for(&asked, &approve, 1, &world));
        }
        assert_eq!(main.answer(10), NO_ADDRESS, "{what}");
        main.all_checked(&what);
        assert_eq!(main.file(), Value::Null, "{what}");
        // Ended for the document: no resolution, a keyless answer.
        main.request(11, &named(1), "eth_requestAccounts", json!([]), &world);
        assert_eq!(main.answer(11), NO_ADDRESS, "{what}");
        main.request(12, &named(1), "eth_accounts", json!([]), &world);
        assert_eq!(main.answer(12), r#"{"result":[]}"#, "{what}");
        assert!(main.events.is_empty(), "{what}: {:?}", main.events);
        assert_eq!(main.checks, moved_at + 1, "{what}");
    }
}

/// A connected key moved at its third check, its binding ended by another
/// request while main rechecks it, or its name moved while main rechecks
/// it, with no other request to see it (the core resolves the name again
/// after the recheck): 4100, its last use unmarked.
#[test]
fn a_connected_key_moved_marks_nothing() {
    let (_root, mut main) = Main::new(&grants(), &[]);
    let world = plain_world();
    let before = main.file();
    main.script(&[Name::Serves, Name::Serves, Name::Moved]);
    main.request(10, &named(1), "eth_requestAccounts", json!([]), &world);
    assert_eq!(main.answer(10), NO_ADDRESS);
    main.all_checked("third check");
    assert_eq!(main.file(), before);

    // Another document of the name: its connect waits on main's recheck
    // while its own eth_accounts finds the name moved.
    main.script(&[Name::Serves, Name::Serves, Name::Serves]);
    main.request(20, &named(2), "eth_requestAccounts", json!([]), &world);
    let recheck = main.asked("approval.recheck");
    main.script(&[Name::MovedToIpfs]);
    main.request(21, &named(2), "eth_accounts", json!([]), &world);
    assert_eq!(main.answer(21), r#"{"result":[]}"#);
    main.respond(&recheck, json!({ "live": true, "agent": false }));
    assert_eq!(main.answer(20), NO_ADDRESS);
    main.all_checked("recheck");
    assert_eq!(main.file(), before);
    let checks = main.checks;

    // Moved while main's recheck is held: the check after it refuses.
    main.script(&[Name::Serves, Name::Serves, Name::Serves]);
    main.request(30, &named(3), "eth_requestAccounts", json!([]), &world);
    let recheck = main.asked("approval.recheck");
    main.all_checked("before the recheck");
    main.script(&[Name::Moved]);
    main.respond(&recheck, json!({ "live": true, "agent": false }));
    assert_eq!(main.answer(30), NO_ADDRESS);
    main.all_checked("after the recheck");
    assert_eq!(main.checks, checks + 4);
    assert_eq!(main.file(), before);
    assert!(main.events.is_empty(), "{:?}", main.events);

    // A new document binds again: its connect marks the last use once the
    // name still serves the key after main's recheck, and main's last
    // recheck after that lookup finds the document live.
    main.script(&[Name::Serves, Name::Serves, Name::Serves]);
    main.request(40, &named(4), "eth_requestAccounts", json!([]), &world);
    let recheck = main.asked("approval.recheck");
    main.script(&[Name::Serves]);
    main.respond(&recheck, json!({ "live": true, "agent": false }));
    let last = main.asked("approval.recheck");
    main.respond(&last, json!({ "live": true, "agent": false }));
    assert_eq!(main.answer(40), format!(r#"{{"result":["{ACCOUNT}"]}}"#));
    main.all_checked("new document");
    assert_ne!(main.file()[NAME]["lastUsed"], before[NAME]["lastUsed"]);
}

/// A chain switch: moved, ended while main rechecks it, or moved while
/// main rechecks it (the core resolves the name again after the recheck):
/// 4100, the grant's chain unchanged, and main never asked to select the
/// chain. Honest at both checks, the chain is written and selected.
#[test]
fn a_switch_moved_changes_nothing() {
    let (_root, mut main) = Main::new(&grants(), &[]);
    let world = plain_world();
    let before = main.file();
    let to_mainnet = json!([{ "chainId": "0x1" }]);
    let mut world = world;
    world["networks"]["1"] = json!({ "name": "Ethereum", "available": true });
    main.script(&[Name::Moved]);
    main.request(
        10,
        &named(1),
        "wallet_switchEthereumChain",
        to_mainnet.clone(),
        &world,
    );
    assert_eq!(main.answer(10), NO_ADDRESS);

    main.script(&[Name::Serves]);
    main.request(
        20,
        &named(2),
        "wallet_switchEthereumChain",
        to_mainnet.clone(),
        &world,
    );
    let recheck = main.asked("approval.recheck");
    main.script(&[Name::Fails]);
    main.request(21, &named(2), "eth_accounts", json!([]), &world);
    assert_eq!(main.answer(21), r#"{"result":[]}"#);
    main.respond(&recheck, json!({ "live": true, "agent": false }));
    assert_eq!(main.answer(20), NO_ADDRESS);
    main.all_checked("switch");
    assert_eq!(main.file(), before);

    // Params that fail their checks answer before any resolution.
    main.request(
        30,
        &named(3),
        "wallet_switchEthereumChain",
        json!([{}]),
        &world,
    );
    assert!(main.answer(30).contains("-32602"));
    assert_eq!(main.checks, 3);

    // Moved while main's recheck is held: the check after it refuses, and
    // main is asked to select nothing (the page's answer comes next).
    main.script(&[Name::Serves]);
    main.request(
        40,
        &named(4),
        "wallet_switchEthereumChain",
        to_mainnet.clone(),
        &world,
    );
    let recheck = main.asked("approval.recheck");
    main.all_checked("before the recheck");
    main.script(&[Name::Moved]);
    main.respond(&recheck, json!({ "live": true, "agent": false }));
    assert_eq!(main.answer(40), NO_ADDRESS);
    main.all_checked("after the recheck");
    assert_eq!(main.checks, 5);
    assert_eq!(main.file(), before);

    // Honest at both: main's last recheck after the second lookup, then
    // the grant takes the chain and main selects it.
    main.script(&[Name::Serves]);
    main.request(
        50,
        &named(5),
        "wallet_switchEthereumChain",
        to_mainnet,
        &world,
    );
    let recheck = main.asked("approval.recheck");
    main.script(&[Name::Serves]);
    main.respond(&recheck, json!({ "live": true, "agent": false }));
    let last = main.asked("approval.recheck");
    main.respond(&last, json!({ "live": true, "agent": false }));
    let select = main.asked("eip1193.select_chain");
    assert_eq!(select["params"]["chain_id"], 1, "{select}");
    main.respond(&select, json!({}));
    assert_eq!(main.answer(50), r#"{"result":null}"#);
    main.all_checked("honest");
    assert_eq!(main.file()[NAME]["chainId"], 1);
}

/// `personal_sign`'s prompted path: moved at each of its five checks
/// (before and after the agent's route, after what is signed is prepared,
/// after the approve, after the signature): 4100, no signature returned,
/// and an "Always allow" never written.
#[test]
fn a_signature_moved_at_any_check_signs_nothing() {
    for moved_at in 0..5 {
        let what = format!("moved at check {moved_at}");
        let (_root, mut main) = Main::new(&grants(), &[]);
        let world = plain_world();
        let before = main.file();
        let mut names = vec![Name::Serves; moved_at];
        names.push(Name::Moved);
        let (first, after) = names.split_at(names.len().min(3));
        main.script(first);
        main.request(
            10,
            &named(1),
            "personal_sign",
            json!(["0x68656c6c6f"]),
            &world,
        );
        if moved_at >= 3 {
            let asked = main.asked("approval.request");
            main.script(after);
            let approve = json!({ "approve": true, "choices": { "alwaysAllow": true } });
            main.respond(&asked, decision_for(&asked, &approve, 1, &world));
        }
        assert_eq!(main.answer(10), NO_ADDRESS, "{what}");
        main.all_checked(&what);
        assert_eq!(main.file(), before, "{what}: no rule written");
        assert!(main.events.is_empty(), "{what}: {:?}", main.events);
    }
    // Honest at every check: signed, and the rule written.
    let (_root, mut main) = Main::new(&grants(), &[]);
    let world = plain_world();
    main.script(&[Name::Serves; 3]);
    main.request(
        10,
        &named(1),
        "personal_sign",
        json!(["0x68656c6c6f"]),
        &world,
    );
    let asked = main.asked("approval.request");
    main.script(&[Name::Serves; 2]);
    let approve = json!({ "approve": true, "choices": { "alwaysAllow": true } });
    main.respond(&asked, decision_for(&asked, &approve, 1, &world));
    let signed = main.answer(10);
    assert!(signed.starts_with(r#"{"result":"0x"#), "{signed}");
    main.all_checked("honest");
    assert!(main.file()[NAME]["autoApprove"]["limited"].is_object());
}

/// The site's rule for signatures, in Q9's form.
fn ruled() -> Value {
    let now = load()["now"].as_u64().unwrap();
    let mut ruled = grants();
    ruled[NAME]["autoApprove"]["limited"] =
        json!({ "signing": { "grantedAt": now }, "transactions": [] });
    ruled
}

/// A core holding [`ruled`], its wall clock held at the vectors' `now`.
fn ruled_core() -> (tempfile::TempDir, tempfile::TempDir, Main) {
    let now = load()["now"].as_u64().unwrap();
    let root = tempfile::tempdir().unwrap();
    let clock = root.path().join("wall");
    std::fs::write(&clock, now.to_string()).unwrap();
    let (core_root, main) = Main::new(
        &ruled(),
        &[("FREEDOM_CORED_TEST_WALL_CLOCK", clock.to_str().unwrap())],
    );
    (root, core_root, main)
}

/// A rule's `personal_sign` from document `navigation`, honest at its six
/// checks: whether the rule signed it (main's recheck, the name, main's
/// last recheck, then the signature) rather than asking the user (Q9's
/// rate spent: the core counts each signature it makes under the rule).
fn rule_signed(main: &mut Main, id: u64, navigation: u64, world: &Value) -> bool {
    main.script(&[Name::Serves; 4]);
    main.request(
        id,
        &named(navigation),
        "personal_sign",
        json!(["0x68656c6c6f"]),
        world,
    );
    let asked = main.next();
    if asked["method"] == "approval.request" {
        // Asked after three checks: the rule's fourth isn't made.
        assert_eq!(asked["params"]["kind"], "eth.sign", "{asked}");
        assert_eq!(main.names.len(), 1, "{asked}");
        main.names.clear();
        return false;
    }
    assert_eq!(asked["method"], "approval.recheck", "{asked}");
    main.all_checked("before the recheck");
    main.script(&[Name::Serves; 2]);
    main.respond(&asked, json!({ "live": true, "agent": false }));
    let last = main.asked("approval.recheck");
    assert_eq!(main.names.len(), 1, "{last}");
    main.respond(&last, json!({ "live": true, "agent": false }));
    let signed = main.answer(id);
    assert!(signed.starts_with(r#"{"result":"0x"#), "{signed}");
    main.all_checked("signed");
    true
}

/// A signature the site's rule answers: moved after the vault's unlock
/// is known (before main's recheck), while main's recheck is held (the
/// core resolves the name again after it), or after the signature: 4100,
/// no signature returned, the last use unmarked. Moved before the
/// signature, nothing is signed: Q9's rate still has its five, where a
/// signature made and dropped spends one.
#[test]
fn a_rule_signature_moved_signs_nothing() {
    for moved_at in [3, 4, 5] {
        let what = format!("moved at check {moved_at}");
        let (_root, _core_root, mut main) = ruled_core();
        let world = plain_world();
        let before = main.file();
        let mut names = vec![Name::Serves; moved_at];
        names.push(Name::Moved);
        let (first, after) = names.split_at(4);
        main.script(first);
        main.request(
            10,
            &named(1),
            "personal_sign",
            json!(["0x68656c6c6f"]),
            &world,
        );
        if moved_at >= 4 {
            let recheck = main.asked("approval.recheck");
            main.script(after);
            main.respond(&recheck, json!({ "live": true, "agent": false }));
        }
        if moved_at == 5 {
            let last = main.asked("approval.recheck");
            main.respond(&last, json!({ "live": true, "agent": false }));
        }
        assert_eq!(main.answer(10), NO_ADDRESS, "{what}");
        main.all_checked(&what);
        assert_eq!(main.file(), before, "{what}: no last use");
        // Q9's rate: five signatures under the rule, unless one was spent.
        let spent = usize::from(moved_at == 5);
        for n in 0..5 {
            let id = 20 + n;
            let signed = rule_signed(&mut main, id, 2 + n, &world);
            assert_eq!(signed, (n as usize) < 5 - spent, "{what}: #{n}");
        }
    }
}

/// A rule's signature with the vault locked: the name moved while main's
/// unlock prompt is open is caught by the check after the unlock, before
/// main is asked to recheck: 4100, nothing signed, the last use unmarked.
#[test]
fn a_rule_signature_moved_during_the_unlock_signs_nothing() {
    let (_root, _core_root, mut main) = ruled_core();
    let world = plain_world();
    let before = main.file();
    let locked = main.core.call_shell(5, "vault.lock", json!({}));
    assert!(locked["result"].is_object(), "{locked}");
    main.script(&[Name::Serves; 3]);
    main.request(
        10,
        &named(1),
        "personal_sign",
        json!(["0x68656c6c6f"]),
        &world,
    );
    let asked = main.asked("approval.request");
    assert_eq!(asked["params"]["kind"], "vault.unlock", "{asked}");
    main.all_checked("before the unlock");
    // main's request ids only increase.
    let unlocked = main.core.call_shell(
        11,
        "vault.unlock",
        json!({ "password_b64": STANDARD.encode("testpass1") }),
    );
    assert!(unlocked["result"].is_object(), "{unlocked}");
    main.script(&[Name::Moved]);
    let approve = json!({ "approve": true, "choices": {} });
    main.respond(&asked, decision_for(&asked, &approve, 1, &world));
    // The page's answer comes next: main is asked no recheck.
    assert_eq!(main.answer(10), NO_ADDRESS);
    main.all_checked("after the unlock");
    assert_eq!(main.file(), before, "no last use");
    for n in 0..5 {
        assert!(rule_signed(&mut main, 20 + n, 2 + n, &world), "#{n}");
    }
}

/// `agent_custody`'s refusal (`AGENT_CUSTODY` in the reference).
const AGENT_CUSTODY: &str = r#"{"error":{"code":4100,"message":"The origin is not authorized for this operation","data":{"reason":"agent_custody"}}}"#;
/// The rule no longer answering (`RULE_GONE` in the reference).
const RULE_GONE: &str = r#"{"error":{"code":-32603,"message":"Signing was not confirmed: this request is not covered by the site's auto-approve rules"}}"#;
/// Q9's limited rule answers for 30 days of the wall clock.
const RULE_DAYS_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// A rule's signature whose name lookup after main's recheck is held
/// (#401's round 2). While it is out, the tab goes into the agent's
/// custody, the document goes away, the rule expires, or (once the lookup
/// has answered, during main's last recheck) another request of the
/// document finds the name moved. The lookup answers that the name still
/// serves the key, and main's last recheck, which the core asks once the
/// lookup has answered, refuses it as the reference's reads after its
/// last `nameHolds` would: `agent_custody`, `4100`, the rule gone, `4100`.
/// Nothing is signed (Q9's rate keeps its five) and the last use isn't
/// marked.
#[test]
fn a_rule_signature_rechecked_after_its_lookup_signs_nothing() {
    for case in ["custody", "gone", "expired", "ended"] {
        let (clock_root, _core_root, mut main) = ruled_core();
        let clock = clock_root.path().join("wall");
        let now = load()["now"].as_u64().unwrap();
        let world = plain_world();
        let before = main.file();
        main.script(&[Name::Serves; 4]);
        main.request(
            10,
            &named(1),
            "personal_sign",
            json!(["0x68656c6c6f"]),
            &world,
        );
        let recheck = main.asked("approval.recheck");
        main.all_checked("before the recheck");
        main.respond(&recheck, json!({ "live": true, "agent": false }));
        let held = main.held_call();
        let mut answer = json!({ "live": true, "agent": false });
        let expected = match case {
            "custody" => {
                answer["agent"] = json!(true);
                AGENT_CUSTODY
            }
            "gone" => {
                answer["live"] = json!(false);
                NO_ADDRESS
            }
            "expired" => {
                std::fs::write(&clock, (now + RULE_DAYS_MS).to_string()).unwrap();
                RULE_GONE
            }
            _ => NO_ADDRESS,
        };
        main.node(&held, &resolve_body(IPNS_CONTENTHASH));
        let last = main.asked("approval.recheck");
        if case == "ended" {
            main.script(&[Name::Moved]);
            main.request(11, &named(1), "eth_accounts", json!([]), &world);
            assert_eq!(main.answer(11), r#"{"result":[]}"#);
        }
        main.respond(&last, answer);
        assert_eq!(main.answer(10), expected, "{case}");
        main.all_checked(case);
        assert_eq!(main.file(), before, "{case}: no last use");
        std::fs::write(&clock, now.to_string()).unwrap();
        for n in 0..5 {
            assert!(
                rule_signed(&mut main, 20 + n, 2 + n, &world),
                "{case}: #{n}"
            );
        }
    }
}

/// A connected key and a chain switch, past main's recheck and the name
/// lookup after it: the document gone by main's last recheck, or the
/// binding ended by another request while that recheck is out, refuses
/// (`4100`) with the last use unmarked, the grant's chain unchanged, and
/// main asked to select nothing.
#[test]
fn a_connected_key_or_switch_rechecked_after_its_lookup_changes_nothing() {
    let (_root, mut main) = Main::new(&grants(), &[]);
    let mut world = plain_world();
    world["networks"]["1"] = json!({ "name": "Ethereum", "available": true });
    let before = main.file();
    let mut navigation = 0;
    for (method, first) in [
        ("eth_requestAccounts", 3),
        ("wallet_switchEthereumChain", 1),
    ] {
        let params = if first == 1 {
            json!([{ "chainId": "0x1" }])
        } else {
            json!([])
        };
        for case in ["gone", "ended"] {
            let what = format!("{method} {case}");
            navigation += 1;
            let id = 10 * navigation;
            main.script(&vec![Name::Serves; first]);
            main.request(id, &named(navigation), method, params.clone(), &world);
            let recheck = main.asked("approval.recheck");
            main.all_checked(&what);
            main.script(&[Name::Serves]);
            main.respond(&recheck, json!({ "live": true, "agent": false }));
            let last = main.asked("approval.recheck");
            main.all_checked(&what);
            let live = case != "gone";
            if case == "ended" {
                main.script(&[Name::Moved]);
                main.request(
                    id + 1,
                    &named(navigation),
                    "eth_accounts",
                    json!([]),
                    &world,
                );
                assert_eq!(main.answer(id + 1), r#"{"result":[]}"#, "{what}");
            }
            main.respond(&last, json!({ "live": live, "agent": false }));
            // The page's answer comes next: main is asked to select nothing.
            assert_eq!(main.answer(id), NO_ADDRESS, "{what}");
            main.all_checked(&what);
            assert_eq!(main.file(), before, "{what}");
        }
    }
    main.flush(99, &world);
    assert!(main.events.is_empty(), "{:?}", main.events);
}

/// A name the core can't resolve fails closed, as `nameServesIpnsKey`'s
/// throw does, and ends the binding; so does a transport key that isn't
/// `ipns://<key>`, with nothing resolved.
#[test]
fn a_name_that_cannot_be_resolved_fails_closed() {
    let (_root, mut main) = Main::new(&grants(), &[]);
    let world = plain_world();
    main.script(&[Name::Fails]);
    main.request(10, &named(1), "eth_accounts", json!([]), &world);
    assert_eq!(main.answer(10), r#"{"result":[]}"#);
    main.request(11, &named(1), "eth_accounts", json!([]), &world);
    assert_eq!(main.answer(11), r#"{"result":[]}"#);
    assert_eq!(main.checks, 1);
    for (n, odd) in [
        "ipns://",
        "ipns://k51/x",
        "https://docs.example.org",
        "ipns://k5_1",
    ]
    .into_iter()
    .enumerate()
    {
        let id = 20 + n as u64;
        let mut context = named(2);
        context["page"]["transport_key"] = json!(odd);
        main.request(id, &context, "eth_requestAccounts", json!([]), &world);
        assert_eq!(main.answer(id), NO_ADDRESS, "{odd}");
    }
    assert_eq!(main.checks, 1);
    main.all_checked("odd");
}

/// A page without a binding resolves nothing: no transport key, or one
/// that is its key. Its permission-free reads never check the name.
#[test]
fn without_a_binding_nothing_is_resolved() {
    let (_root, mut main) = Main::new(&grants(), &[]);
    let world = plain_world();
    let ipns = format!("ipns://{IPNS_KEY}");
    let mut plain = named(1);
    plain["page"]
        .as_object_mut()
        .unwrap()
        .remove("transport_key");
    main.request(10, &plain, "eth_accounts", json!([]), &world);
    assert_eq!(main.answer(10), format!(r#"{{"result":["{ACCOUNT}"]}}"#));
    let own = json!({ "caller": "page", "page": {
        "origin": ipns, "top_origin": ipns, "frame": 1, "navigation": 2,
        "agent": false, "transport_key": ipns,
    } });
    main.request(11, &own, "eth_accounts", json!([]), &world);
    assert_eq!(
        main.answer(11),
        r#"{"result":["0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"]}"#
    );
    main.request(12, &named(3), "eth_chainId", json!([]), &world);
    assert_eq!(main.answer(12), r#"{"result":"0x64"}"#);
    main.request(13, &named(3), "eth_blockNumber", json!([]), &world);
    assert_eq!(main.answer(13), r#"{"result":"0x1406f40"}"#);
    // A send (APR-5f-2), to its prompt.
    main.request(
        14,
        &plain,
        "eth_sendTransaction",
        send_params(),
        &send_world(1),
    );
    let asked = main.asked("approval.request");
    assert_eq!(asked["params"]["kind"], "eth.send", "{asked}");
    assert_eq!(main.checks, 0);
}

/// A check has the request's clock: unanswered past it, the page hears the
/// deadline and the lookup is cancelled; a cancel ends one too. Neither
/// ends the binding.
#[test]
fn a_check_has_the_requests_deadline_and_cancel() {
    let (_root, mut main) = Main::with_timeout(
        &grants(),
        &[("FREEDOM_CORED_TEST_EIP1193_OVERALL_MS", "3000")],
        90_000,
    );
    let world = plain_world();
    main.request(10, &named(1), "eth_accounts", json!([]), &world);
    // The lookup reaches main, which holds it.
    let held = loop {
        let message = main.core.recv();
        assert_ne!(message["type"], "response", "{message}");
        if message["method"] == "shell.rpc" {
            let body: Value =
                serde_json::from_str(message["params"]["body"].as_str().unwrap()).unwrap();
            if body["method"] == "eth_call" {
                break message;
            }
            let method = body["method"].as_str().unwrap().to_owned();
            let text = main.recorded[&method].clone();
            main.node(&message, &text);
        }
    };
    let started = std::time::Instant::now();
    let reply = loop {
        let message = main.core.recv();
        match message["type"].as_str() {
            Some("cancel") => assert_eq!(message["id"], held["id"]),
            Some("response") => break message,
            _ => {}
        }
    };
    assert_eq!(reply["id"], 10);
    assert_eq!(
        reply["result"].to_string(),
        r#"{"error":{"code":-32603,"message":"The request's deadline passed"}}"#
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    main.node(&held, &resolve_body(OTHER_CONTENTHASH));
    // Not ended: the next request resolves, and the name serves.
    main.script(&[Name::Serves, Name::Serves]);
    main.request(11, &named(1), "eth_accounts", json!([]), &world);
    assert_eq!(main.answer(11), format!(r#"{{"result":["{ACCOUNT}"]}}"#));
    main.all_checked("after the deadline");
}

/// A device's signature (a Ledger) whose name moved after the approve:
/// 4100, and no `{ device }` token goes to main.
#[test]
fn a_device_signature_moved_after_the_approve_gets_no_token() {
    let mut ledger = grants();
    ledger[NAME]["walletIndex"] = json!(1);
    let (_root, mut main) = Main::new(&ledger, &[]);
    let world = plain_world();
    main.script(&[Name::Serves; 3]);
    main.request(
        10,
        &named(1),
        "personal_sign",
        json!(["0x68656c6c6f"]),
        &world,
    );
    let asked = main.asked("approval.request");
    assert_eq!(
        asked["params"]["choices"],
        json!({ "alwaysAllow": [false] })
    );
    main.script(&[Name::Moved]);
    let approve = json!({ "approve": true, "choices": { "alwaysAllow": false } });
    main.respond(&asked, decision_for(&asked, &approve, 1, &world));
    assert_eq!(main.answer(10), NO_ADDRESS);
    main.all_checked("device");
}

/// main's cancel of a page request whose name check is out: `cancelled`.
/// Naming keeps the lookup's session running (design 0004), and its
/// verdict, when it comes, decides nothing: the binding stands.
#[test]
fn a_cancel_ends_the_name_check() {
    let (_root, mut main) = Main::with_timeout(&grants(), &[], 90_000);
    let world = plain_world();
    main.request(10, &named(1), "eth_accounts", json!([]), &world);
    let held = main.held_call();
    main.core.send(&json!({ "type": "cancel", "id": 10 }));
    let reply = main.next();
    assert_eq!(reply["id"], 10, "{reply}");
    assert_eq!(reply["error"]["code"], "cancelled", "{reply}");
    main.node(&held, &resolve_body(OTHER_CONTENTHASH));
    main.script(&[Name::Serves, Name::Serves]);
    main.request(11, &named(1), "eth_accounts", json!([]), &world);
    assert_eq!(main.answer(11), format!(r#"{{"result":["{ACCOUNT}"]}}"#));
    main.all_checked("after the cancel");
}

/// Naming admits at most 64 callers to one name's lookup (design 0004,
/// Admission). A page request's cancel takes its check's caller out of
/// it: with 64 cancelled checks joined to one held lookup (naming's cache
/// standing, so they join), a 65th live check still joins and answers,
/// rather than failing busy and ending the binding.
#[test]
fn cancelled_checks_free_their_places_in_naming() {
    let (_root, mut main) = Main::build(&grants(), &[], 90_000, false);
    let world = plain_world();
    for n in 0..64 {
        main.request(100 + n, &named(1), "eth_accounts", json!([]), &world);
    }
    let held = main.held_call();
    for n in 0..64 {
        main.core.send(&json!({ "type": "cancel", "id": 100 + n }));
    }
    for n in 0..64 {
        let reply = main.next();
        assert_eq!(reply["id"], 100 + n, "{reply}");
        assert_eq!(reply["error"]["code"], "cancelled", "{reply}");
    }
    main.request(200, &named(1), "eth_accounts", json!([]), &world);
    // A keyless request's answer: the 65th check has gone to naming by
    // then, ahead of the held lookup's answer, and waits on it.
    let keyless = json!({ "caller": "page", "page": {
        "origin": "", "top_origin": "", "frame": 9, "navigation": 9, "agent": false,
    } });
    main.request(201, &keyless, "eth_chainId", json!([]), &world);
    let reply = main.next();
    assert_eq!(reply["id"], 201, "the 65th check answered first: {reply}");
    main.node(&held, &resolve_body(IPNS_CONTENTHASH));
    assert_eq!(main.answer(200), format!(r#"{{"result":["{ACCOUNT}"]}}"#));
    assert_eq!(main.checks, 1);
}

// Sends (APR-5f-2).

const TO: &str = "0xabababababababababababababababababababab";
const APPROVE_DATA: &str = "0x095ea7b3000000000000000000000000555555555555555555555555555555555555555500000000000000000000000000000000000000000000000000000000000003e8";

/// The name's grant for sends: account `index`, connected at the vectors'
/// `now`.
fn send_grants(index: u64) -> Value {
    let now = load()["now"].as_u64().unwrap();
    json!({ NAME: {
        "origin": NAME, "connectedAt": now, "lastUsed": now, "walletIndex": index, "chainId": 1,
        "autoApprove": { "signing": false, "transactions": [] },
    } })
}

/// main's world for a send on `chain`, D12's pause off.
fn send_world(chain: u64) -> Value {
    let mut world = plain_world();
    world["window_chain"] = json!(chain);
    world["paused"] = json!(false);
    world
}

/// An `approve` call to `TO`, with a value of 5.
fn send_params() -> Value {
    json!([{ "to": TO, "value": "0x5", "data": APPROVE_DATA }])
}

/// main approves send prompt `asked` of request `rid`, "Always allow"
/// unticked.
fn send_approve(main: &mut Main, asked: &Value, rid: u64, world: &Value) {
    let approve = json!({ "approve": true, "choices": {} });
    main.respond(asked, decision_for(asked, &approve, rid, world));
}

/// `sign.transaction` as main calls it on `send`, the page's `{ send }`,
/// with the nonce added, under document 1: the token's, or the rule's
/// `{ standing }`.
fn sign_send(main: &mut Main, id: u64, send: &Value) -> Value {
    let mut tx = send["tx"].clone();
    tx["nonce"] = json!("7");
    let authorization = if send["standing"] == true {
        json!({ "standing": { "paused": false } })
    } else {
        json!({ "token": send["token"], "kind": send["kind"], "handle": send["handle"] })
    };
    main.core.send(&json!({
        "type": "request", "id": id, "method": "sign.transaction",
        "params": { "key": { "kind": "account", "index": send["account"] }, "tx": tx,
            "authorization": authorization },
        "context": named(1),
    }));
    let response = main.next();
    assert_eq!(response["id"], id, "{response}");
    response
}

/// A vault account's send moved at each of its checks: before and after
/// the agent's route (before its grant is read), after the rule's choice
/// (before its quote), and after the approve and the fee check at it
/// (before the grant is read again and the token minted). Each answers
/// `4100`: nothing prepared before its quote's check (no estimate asked),
/// and no `{ send }`, so no token, after the approve; nothing written. The
/// document's later send answers `4100` with nothing resolved. A malformed
/// send is refused with nothing resolved, as the reference checks its form
/// first. Honest at every check, `{ send }`, which signs with the nonce
/// added.
#[test]
fn a_send_moved_at_any_check_prepares_and_mints_nothing() {
    let world = send_world(1);
    for moved_at in 0..4 {
        let what = format!("moved at check {moved_at}");
        let (_root, mut main) = Main::new(&send_grants(0), &[]);
        let before = main.file();
        let mut names = vec![Name::Serves; moved_at];
        names.push(Name::Moved);
        let (first, after) = names.split_at(names.len().min(3));
        main.script(first);
        main.request(10, &named(1), "eth_sendTransaction", send_params(), &world);
        if moved_at >= 3 {
            let asked = main.asked("approval.request");
            assert_eq!(asked["params"]["kind"], "eth.send", "{what}");
            main.script(after);
            send_approve(&mut main, &asked, 10, &world);
        }
        assert_eq!(main.answer(10), NO_ADDRESS, "{what}");
        main.all_checked(&what);
        assert_eq!(main.estimates, usize::from(moved_at >= 3), "{what}");
        main.request(11, &named(1), "eth_sendTransaction", send_params(), &world);
        assert_eq!(main.answer(11), NO_ADDRESS, "{what}");
        assert_eq!(main.checks, moved_at + 1, "{what}: resolved after the end");
        assert_eq!(main.estimates, usize::from(moved_at >= 3), "{what}");
        assert_eq!(main.file(), before, "{what}");
    }
    let (_root, mut main) = Main::new(&send_grants(0), &[]);
    let malformed = json!([{ "to": "0x12" }]);
    main.request(9, &named(1), "eth_sendTransaction", malformed, &world);
    assert_eq!(
        main.answer(9),
        r#"{"error":{"code":-32602,"message":"The transaction needs a recipient address (to)"}}"#
    );
    assert_eq!(main.checks, 0);
    main.script(&[Name::Serves; 3]);
    main.request(10, &named(1), "eth_sendTransaction", send_params(), &world);
    let asked = main.asked("approval.request");
    main.script(&[Name::Serves]);
    send_approve(&mut main, &asked, 10, &world);
    let sent: Value = serde_json::from_str(&main.answer(10)).unwrap();
    main.all_checked("honest");
    assert_eq!(sent["send"]["kind"], "dapp-send", "{sent}");
    assert_eq!(sent["send"]["tx"]["gas_limit"], "60000", "{sent}");
    let signed = sign_send(&mut main, 20, &sent["send"]);
    assert!(signed["result"]["raw"].is_string(), "{signed}");
}

/// A device's send (a Ledger's, a phone's, and a Safe's on Gnosis), moved
/// after the rule's choice (no prompt; nothing prepared) or after its
/// approve, before the grant is read again: `4100` and no `{ device }`, so
/// no token for main to spend. Honest at every check, `{ device }`.
#[test]
fn a_device_send_moved_gets_no_token() {
    for (index, kind, chain) in [(1, "ledger", 1), (2, "remote", 1), (1000, "safe", 100)] {
        let world = send_world(chain);
        for moved_at in [2, 3, 4] {
            let what = format!("{kind}, moved at check {moved_at}");
            let (_root, mut main) = Main::new(&send_grants(index), &[]);
            let mut names = vec![Name::Serves; moved_at];
            if moved_at < 4 {
                names.push(Name::Moved);
            }
            let (first, after) = names.split_at(3);
            main.script(first);
            main.request(10, &named(1), "eth_sendTransaction", send_params(), &world);
            if moved_at >= 3 {
                let asked = main.asked("approval.request");
                assert_eq!(asked["params"]["kind"], "eth.send", "{what}");
                main.script(after);
                send_approve(&mut main, &asked, 10, &world);
            }
            let answer = main.answer(10);
            main.all_checked(&what);
            let quoted = moved_at >= 3 && kind != "safe";
            assert_eq!(main.estimates, usize::from(quoted), "{what}");
            if moved_at < 4 {
                assert_eq!(answer, NO_ADDRESS, "{what}");
                continue;
            }
            let answer: Value = serde_json::from_str(&answer).unwrap();
            let device = &answer["device"];
            assert_eq!(device["type"], kind, "{what}: {answer}");
            assert!(device["token"].is_string(), "{what}");
        }
    }
}

/// The site's rule for sends, in Q9's form: `approve` calls to `TO`, with
/// no more value than 5, on chain 1.
fn send_ruled() -> Value {
    let now = load()["now"].as_u64().unwrap();
    let mut grants = send_grants(0);
    grants[NAME]["autoApprove"]["limited"] = json!({ "signing": null, "transactions": [{
        "to": TO, "selector": "0x095ea7b3", "chainId": 1, "maxValue": "5", "grantedAt": now,
    }] });
    grants
}

/// A core holding [`send_ruled`], its wall clock held at the vectors'
/// `now`.
fn send_ruled_core() -> (tempfile::TempDir, tempfile::TempDir, Main) {
    let now = load()["now"].as_u64().unwrap();
    let root = tempfile::tempdir().unwrap();
    let clock = root.path().join("wall");
    std::fs::write(&clock, now.to_string()).unwrap();
    let (core_root, main) = Main::new(
        &send_ruled(),
        &[("FREEDOM_CORED_TEST_WALL_CLOCK", clock.to_str().unwrap())],
    );
    (root, core_root, main)
}

/// A send the site's rule answers. Moved after the rule's choice (before
/// its quote: nothing prepared), or while main's recheck is out (caught by
/// the lookup after it, and main is asked no last recheck): `4100`, no
/// `{ send }`. With that lookup held and then answering that the name
/// still serves the key, main's last recheck decides: the tab gone into
/// the agent's custody (`agent_custody`), the document gone, or the binding
/// ended by another of its requests while that recheck is out (`4100`).
/// Honest, `{ send }` under the rule, which signs under `{ standing }`.
#[test]
fn a_rule_send_moved_or_rechecked_after_its_lookup_gets_no_send() {
    let world = send_world(1);
    let (_clock, _root, mut main) = send_ruled_core();
    main.script(&[Name::Serves, Name::Serves, Name::Moved]);
    main.request(10, &named(1), "eth_sendTransaction", send_params(), &world);
    assert_eq!(main.answer(10), NO_ADDRESS, "after the rule's choice");
    main.all_checked("after the rule's choice");
    assert_eq!(main.estimates, 0);

    let (_clock, _root, mut main) = send_ruled_core();
    main.script(&[Name::Serves; 3]);
    main.request(10, &named(1), "eth_sendTransaction", send_params(), &world);
    let recheck = main.asked("approval.recheck");
    main.all_checked("before the recheck");
    assert_eq!(main.estimates, 1);
    main.script(&[Name::Moved]);
    main.respond(&recheck, json!({ "live": true, "agent": false }));
    assert_eq!(main.answer(10), NO_ADDRESS, "during the recheck");
    main.all_checked("during the recheck");

    for case in ["honest", "custody", "gone", "ended"] {
        let (_clock, _root, mut main) = send_ruled_core();
        main.script(&[Name::Serves; 3]);
        main.request(10, &named(1), "eth_sendTransaction", send_params(), &world);
        let recheck = main.asked("approval.recheck");
        main.respond(&recheck, json!({ "live": true, "agent": false }));
        let held = main.held_call();
        main.node(&held, &resolve_body(IPNS_CONTENTHASH));
        let last = main.asked("approval.recheck");
        let mut answer = json!({ "live": true, "agent": false });
        match case {
            "custody" => answer["agent"] = json!(true),
            "gone" => answer["live"] = json!(false),
            "ended" => {
                main.script(&[Name::Moved]);
                main.request(11, &named(1), "eth_accounts", json!([]), &world);
                assert_eq!(main.answer(11), r#"{"result":[]}"#);
            }
            _ => {}
        }
        main.respond(&last, answer);
        let out: Value = serde_json::from_str(&main.answer(10)).unwrap();
        main.all_checked(case);
        match case {
            "honest" => {
                assert_eq!(out["send"]["standing"], true, "{out}");
                let signed = sign_send(&mut main, 20, &out["send"]);
                assert!(signed["result"]["raw"].is_string(), "{signed}");
            }
            "custody" => assert_eq!(out.to_string(), AGENT_CUSTODY, "{case}"),
            _ => assert_eq!(out.to_string(), NO_ADDRESS, "{case}"),
        }
    }
}

/// A rule's send with the vault locked: the name moved while main's
/// unlock prompt is open. The reference checks no name between its unlock
/// and its send's guard, so the send is quoted and main asked to recheck,
/// and the lookup after that recheck catches it: `4100`, no `{ send }`.
#[test]
fn a_rule_send_moved_during_the_unlock_gets_no_send() {
    let world = send_world(1);
    let (_clock, _root, mut main) = send_ruled_core();
    let locked = main.core.call_shell(5, "vault.lock", json!({}));
    assert!(locked["result"].is_object(), "{locked}");
    main.script(&[Name::Serves; 3]);
    main.request(10, &named(1), "eth_sendTransaction", send_params(), &world);
    let asked = main.asked("approval.request");
    assert_eq!(asked["params"]["kind"], "vault.unlock", "{asked}");
    assert_eq!(asked["params"]["view"]["reason"], "send");
    main.all_checked("before the unlock");
    assert_eq!(main.estimates, 0);
    let unlocked = main.core.call_shell(
        11,
        "vault.unlock",
        json!({ "password_b64": STANDARD.encode("testpass1") }),
    );
    assert!(unlocked["result"].is_object(), "{unlocked}");
    send_approve(&mut main, &asked, 10, &world);
    let recheck = main.asked("approval.recheck");
    assert_eq!(
        main.checks, 3,
        "no check between the unlock and the recheck"
    );
    main.script(&[Name::Moved]);
    main.respond(&recheck, json!({ "live": true, "agent": false }));
    assert_eq!(main.answer(10), NO_ADDRESS);
    main.all_checked("after the recheck");
}

/// A rule's send whose fee the check doesn't let through (main's own fee
/// reference lowered first, so the core's quote is far above it) goes to
/// its prompt after one more check, as the reference checks the name
/// before the prompt it falls back to: moved there, `4100` and no prompt;
/// honest, the prompt, its fee above the reference.
#[test]
fn a_rule_send_asked_for_its_fee_checks_the_name_first() {
    let world = send_world(1);
    for moved in [true, false] {
        let (_clock, _root, mut main) = send_ruled_core();
        main.gas_price = 2 * GWEI;
        main.priority = GWEI;
        main.core.send(&json!({
            "type": "request", "id": 5, "method": "chain.fee_reference",
            "params": { "chain_id": 1, "deadline_ms": 30_000 },
            "context": { "caller": "chrome" },
        }));
        let reference = main.next();
        assert!(reference["result"].is_object(), "{reference}");
        main.gas_price = 16 * GWEI;
        main.priority = 2 * GWEI;
        main.script(&[Name::Serves; 3]);
        main.script(&[if moved { Name::Moved } else { Name::Serves }]);
        main.request(10, &named(1), "eth_sendTransaction", send_params(), &world);
        if moved {
            assert_eq!(main.answer(10), NO_ADDRESS);
        } else {
            let asked = main.asked("approval.request");
            assert_eq!(asked["params"]["kind"], "eth.send", "{asked}");
            assert_eq!(
                asked["params"]["view"]["feeCheck"]["above"], true,
                "{asked}"
            );
        }
        main.all_checked(&format!("moved {moved}"));
        assert_eq!(main.estimates, 1);
    }
}
