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
//! Every `step: "APR-5f"` scenario of vectors/eip1193.json replays but the
//! send's, whose name checks are a later step's. Then the guarantees: a name moved at
//! each check point (before the prompt, while it is open, between the
//! approve and the effect, after the signature) refuses with nothing
//! written or signed; a binding ended by another request is read at main's
//! recheck; a name the core can't resolve fails closed; the binding ends
//! for the document, not for a new one; a page without a binding resolves
//! nothing; and a check has the request's deadline and cancel.

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
}

impl Main {
    /// A core whose dApp store has moved, holding `grants`, its vault
    /// imported from ABANDON and unlocked, naming read Direct from `n1`,
    /// and Gnosis read Direct from `e100`. `env` adds to the name hook.
    fn new(grants: &Value, env: &[(&str, &str)]) -> (tempfile::TempDir, Main) {
        Main::with_timeout(grants, env, 5000)
    }

    /// As [`Main::new`], naming's calls timing out after `timeout_ms`.
    fn with_timeout(
        grants: &Value,
        env: &[(&str, &str)],
        timeout_ms: u64,
    ) -> (tempfile::TempDir, Main) {
        let (root, data, locks) = dirs();
        let mut all = vec![("FREEDOM_CORED_TEST_EIP1193_NAMES_UNCACHED", "1")];
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
        let reply = core.call(4, "chain.configure", json!({ "chains": [chain] }));
        assert!(reply["result"]["generations"].is_object(), "{reply}");
        let main = Main {
            core,
            names: VecDeque::new(),
            checks: 0,
            recorded: naming_recorded(),
            events: Vec::new(),
        };
        (root, main)
    }

    fn script(&mut self, names: &[Name]) {
        self.names.extend(names.iter().copied());
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
                    let text = self.recorded[&method].clone();
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

/// The one scenario that waits: the send's. Its name checks are a later
/// step's, once device and rule sends (APR-5e-2) are in.
const PENDING: &[&str] = &["name-send-moved-during-prompt"];

#[test]
fn every_apr5f_scenario_replays_through_the_core() {
    let file = load();
    let now = file["now"].as_u64().unwrap();
    let (mut scenarios, mut requests, mut checks, mut prompts) = (0, 0, 0, 0);
    let mut pending = Vec::new();
    for scenario in file["scenarios"].as_array().unwrap() {
        if scenario["step"] != "APR-5f" {
            continue;
        }
        let id = scenario["id"].as_str().unwrap();
        if PENDING.contains(&id) {
            pending.push(id);
            continue;
        }
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
                    // Main's: the agent's route and custody.
                    "agent.request" | "custody" | "chain.request" | "grant.write" => {}
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
                assert_eq!(
                    asked["params"]["view"].to_string(),
                    prompt["args"]["view"].to_string(),
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
    assert_eq!(pending, PENDING);
    assert_eq!((scenarios, requests, checks, prompts), (7, 9, 16, 3));
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

/// A connected key moved at its third check, or its binding ended by
/// another request while main rechecks it: 4100, its last use unmarked.
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

    // A new document binds again: its connect marks the last use.
    main.script(&[Name::Serves, Name::Serves, Name::Serves]);
    main.request(30, &named(3), "eth_requestAccounts", json!([]), &world);
    let recheck = main.asked("approval.recheck");
    main.respond(&recheck, json!({ "live": true, "agent": false }));
    assert_eq!(main.answer(30), format!(r#"{{"result":["{ACCOUNT}"]}}"#));
    main.all_checked("new document");
    assert_ne!(main.file()[NAME]["lastUsed"], before[NAME]["lastUsed"]);
}

/// A chain switch: moved, or ended while main rechecks it: 4100, the
/// grant's chain unchanged, and main never asked to select the chain.
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

/// A signature the site's rule answers: moved after the vault's unlock
/// is known (before main's recheck), or after the signature: 4100, no
/// signature returned, the last use unmarked.
#[test]
fn a_rule_signature_moved_signs_nothing() {
    let now = load()["now"].as_u64().unwrap();
    let mut ruled = grants();
    ruled[NAME]["autoApprove"]["limited"] =
        json!({ "signing": { "grantedAt": now }, "transactions": [] });
    for moved_at in [3, 4] {
        let what = format!("moved at check {moved_at}");
        let root = tempfile::tempdir().unwrap();
        let clock = root.path().join("wall");
        std::fs::write(&clock, now.to_string()).unwrap();
        let (_core_root, mut main) = Main::new(
            &ruled,
            &[("FREEDOM_CORED_TEST_WALL_CLOCK", clock.to_str().unwrap())],
        );
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
        if moved_at == 4 {
            let recheck = main.asked("approval.recheck");
            main.script(after);
            main.respond(&recheck, json!({ "live": true, "agent": false }));
        }
        assert_eq!(main.answer(10), NO_ADDRESS, "{what}");
        main.all_checked(&what);
        assert_eq!(main.file(), before, "{what}: no last use");
    }
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
