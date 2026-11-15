//! `eip1193.request` end to end (design 0012, APR-5b): the real binary, with
//! the test playing main. Every `step: "APR-5b"` scenario of
//! vectors/eip1193.json is replayed: main's file holds the scenario's dApp
//! grant, each request goes under `page` with main's wallet state, each of
//! the core's reads reaches main as the effect the reference made, and main
//! answers it from that effect.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use base64::Engine as _;
use common::{Core, dirs, spawn};
use serde_json::{Value, json};

const SITE: &str = "https://app.example";

fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/eip1193.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A core whose `grant_root` holds main's dApp file, `grants` (none for
/// null), with chains 1, 100 and 8453 read Direct from one endpoint each
/// (`e<chain>`), and Sepolia configured with none.
fn core(grants: &Value) -> (tempfile::TempDir, Core) {
    let (root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    std::fs::create_dir_all(&core.grant_root).unwrap();
    if !grants.is_null() {
        let text = serde_json::to_string_pretty(grants).unwrap();
        std::fs::write(core.grant_root.join("dapp-permissions.json"), text).unwrap();
    }
    assert_eq!(core.hello_fragments()["result"]["protocol"], 2);
    let chain = |id: u64, name: &str, rpc: &[String]| {
        json!({
            "chain_id": id, "display_name": name,
            "read_order": ["direct"], "broadcast_order": ["direct"],
            "quorum": { "k": 3, "m": 2, "timeout_ms": 5000 },
            "rpc": rpc.iter().map(|e| json!({ "endpoint": e, "user_configured": false })).collect::<Vec<_>>(),
            "prover": null, "myotis": false, "blockscout": null,
        })
    };
    let chains = [
        chain(1, "Ethereum", &["e1".into()]),
        chain(100, "Gnosis", &["e100".into()]),
        chain(8453, "Base", &["e8453".into()]),
        chain(11155111, "Sepolia", &[]),
    ];
    let reply = core.call(2, "chain.configure", json!({ "chains": chains }));
    assert!(reply["result"]["generations"].is_object(), "{reply}");
    (root, core)
}

fn page(key: Option<&str>) -> Value {
    let origin = key.unwrap_or("");
    json!({ "caller": "page", "page": {
        "origin": origin, "top_origin": origin, "frame": 1, "navigation": 1, "agent": false,
    } })
}

/// `world` as main sends it, from the file's fixtures and the scenario's.
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
    })
}

fn send(core: &mut Core, id: u64, context: &Value, params: Value) {
    core.send(&json!({
        "type": "request", "id": id, "method": "eip1193.request", "params": params, "context": context,
    }));
}

/// The JSON-RPC body of the core's `shell.rpc` request.
fn body(request: &Value) -> Value {
    serde_json::from_str(request["params"]["body"].as_str().unwrap()).unwrap()
}

/// Main's `shell.rpc` result: the node's answer `text`.
fn rpc(text: &str) -> Value {
    json!({ "result": {
        "status": 200,
        "body": base64::engine::general_purpose::STANDARD.encode(text),
    } })
}

fn answer_rpc(core: &mut Core, request: &Value, outcome: Value) {
    let mut message = json!({ "type": "response", "id": request["id"] });
    for (key, value) in outcome.as_object().unwrap() {
        message[key] = value.clone();
    }
    core.send(&message);
}

/// Plays main until the response to `id`, answering each `shell.rpc` with
/// `answer` (`None` holds it); returns the response and the requests seen.
fn until(
    core: &mut Core,
    id: u64,
    mut answer: impl FnMut(&Value) -> Option<Value>,
) -> (Value, Vec<Value>) {
    let mut seen = Vec::new();
    loop {
        let message = core.recv();
        match message["type"].as_str() {
            Some("request") => {
                assert_eq!(message["method"], "shell.rpc", "{message}");
                if let Some(outcome) = answer(&message) {
                    answer_rpc(core, &message, outcome);
                }
                seen.push(message);
            }
            Some("cancel") => {}
            Some("response") if message["id"] == id => return (message, seen),
            _ => panic!("unexpected {message}"),
        }
    }
}

/// Main's answer to a read, from the effect the reference recorded: the
/// node's result, or its JSON-RPC error. A throw without a code (a router
/// text) is a transport failure here: the core's own text follows.
fn effect_answer(effect: &Value) -> Value {
    if let Some(answer) = effect.get("answer") {
        return rpc(&json!({ "jsonrpc": "2.0", "id": 1, "result": answer["result"] }).to_string());
    }
    let throws = &effect["throws"];
    if throws.get("code").is_none() {
        return json!({ "error": { "code": "network", "message": "Transport failure" } });
    }
    rpc(&json!({ "jsonrpc": "2.0", "id": 1, "error": throws }).to_string())
}

#[test]
fn every_apr5b_scenario_replays_through_the_core() {
    let file = load();
    let (mut scenarios, mut requests, mut exact) = (0, 0, 0);
    for scenario in file["scenarios"].as_array().unwrap() {
        if scenario["step"] != "APR-5b" {
            continue;
        }
        scenarios += 1;
        let id = scenario["id"].as_str().unwrap();
        let (_root, mut core) = core(&scenario["grants"]["before"]);
        let before = std::fs::read(core.grant_root.join("dapp-permissions.json")).ok();
        let world = world_of(&file, scenario);
        let context = page(scenario["world"]["documents"][0]["key"].as_str());
        let mut next = 10;
        for (i, recorded) in scenario["requests"].as_array().unwrap().iter().enumerate() {
            requests += 1;
            next += 1;
            let what = format!("{id} #{i} {}", recorded["method"]);
            let mut params = json!({ "method": recorded["method"] });
            if let Some(p) = recorded.get("params") {
                params["params"] = p.clone();
            }
            params["world"] = world.clone();
            send(&mut core, next, &context, params);
            let effects = recorded["effects"].as_array().unwrap();
            let (reply, seen) = until(&mut core, next, |request| {
                let effect = &effects[0];
                let args = &effect["args"];
                let asked = body(request);
                assert_eq!(
                    request["params"]["endpoint"],
                    format!("e{}", args["chainId"]),
                    "{what}"
                );
                assert_eq!(asked["method"], args["method"], "{what}");
                assert_eq!(asked["params"], args["params"], "{what}");
                Some(effect_answer(effect))
            });
            // A chain with no endpoint is asked nothing at main.
            let reaches_main = effects
                .first()
                .is_some_and(|e| [1, 100, 8453].contains(&e["args"]["chainId"].as_u64().unwrap()));
            assert_eq!(seen.len(), usize::from(reaches_main), "{what}");
            let result = &reply["result"];
            assert!(result.is_object(), "{what}: {reply}");
            let plain = effects
                .first()
                .is_some_and(|e| e.get("throws").is_some_and(|t| t.get("code").is_none()));
            let empty = effects
                .first()
                .is_some_and(|e| e["throws"]["message"] == "" && e["throws"]["code"] == 0);
            if empty {
                // A node's code 0 is none (-32603), as recorded; its empty
                // message is the router's own text by then, which the
                // reference's script skipped.
                assert_eq!(
                    result.to_string(),
                    r#"{"error":{"code":-32603,"message":"RPC request failed"}}"#,
                    "{what}"
                );
            } else if plain {
                // The router's text, which the reference scripted: here the
                // core's own for Direct's one failed endpoint, with the same
                // code.
                assert_eq!(
                    result.to_string(),
                    r#"{"error":{"code":-32603,"message":"fetch failed"}}"#,
                    "{what}"
                );
            } else {
                assert_eq!(result.to_string(), recorded["result"].to_string(), "{what}");
                exact += 1;
            }
        }
        // Main's file is main's: read, never written.
        assert_eq!(
            std::fs::read(core.grant_root.join("dapp-permissions.json")).ok(),
            before,
            "{id}"
        );
    }
    assert_eq!((scenarios, requests, exact), (15, 50, 48));
}

fn read_world() -> Value {
    json!({
        "enabled": true, "window_chain": 1, "wallets": [],
        "networks": { "1": { "name": "Ethereum", "available": true } },
    })
}

/// A configuration change that ends a page's read sends it again once, as
/// main's chain driver does; a second one ends it with the core's text.
#[test]
fn a_read_a_configuration_change_ends_goes_again_once() {
    let (_root, mut core) = core(&Value::Null);
    let reconfigure = |core: &mut Core, id: u64, timeout_ms: u64| {
        let chain = json!({
            "chain_id": 1, "display_name": "Ethereum",
            "read_order": ["direct"], "broadcast_order": ["direct"],
            "quorum": { "k": 3, "m": 2, "timeout_ms": timeout_ms },
            "rpc": [{ "endpoint": "e1", "user_configured": false }],
            "prover": null, "myotis": false, "blockscout": null,
        });
        core.send(&json!({
            "type": "request", "id": id, "method": "chain.configure",
            "params": { "chains": [chain] }, "context": { "caller": "chrome" },
        }));
    };
    let params = json!({ "method": "eth_blockNumber", "params": [], "world": read_world() });
    send(&mut core, 20, &page(Some(SITE)), params.clone());
    let first = core.recv();
    assert_eq!(first["method"], "shell.rpc", "{first}");
    reconfigure(&mut core, 21, 6000);
    let mut configured = false;
    let mut again = None;
    while !configured || again.is_none() {
        let message = core.recv();
        match message["type"].as_str() {
            Some("response") if message["id"] == 21 => configured = true,
            Some("request") => again = Some(message),
            Some("cancel") => {}
            _ => panic!("unexpected {message}"),
        }
    }
    let again = again.unwrap();
    assert_eq!(body(&again)["method"], "eth_blockNumber");
    answer_rpc(
        &mut core,
        &again,
        rpc(r#"{"jsonrpc":"2.0","id":1,"result":"0x10"}"#),
    );
    let (reply, _) = until(&mut core, 20, |_| None);
    assert_eq!(reply["result"], json!({ "result": "0x10" }), "{reply}");

    // Twice: the second change ends it.
    send(&mut core, 22, &page(Some(SITE)), params);
    assert_eq!(core.recv()["method"], "shell.rpc");
    reconfigure(&mut core, 23, 7000);
    // Sent again once.
    loop {
        let message = core.recv();
        match message["type"].as_str() {
            Some("request") => {
                assert_eq!(body(&message)["method"], "eth_blockNumber");
                break;
            }
            Some("response" | "cancel") => {}
            _ => panic!("unexpected {message}"),
        }
    }
    reconfigure(&mut core, 24, 8000);
    let (reply, _) = until(&mut core, 22, |_| None);
    assert_eq!(
        reply["result"],
        json!({ "error": { "code": -32603, "message": "The chain's configuration changed" } }),
        "{reply}"
    );
}

/// Main's cancel ends a page's read with 0001's `cancelled`, and its
/// exchange at main is cancelled.
#[test]
fn a_cancel_ends_a_pages_read() {
    let (_root, mut core) = core(&Value::Null);
    let params =
        json!({ "method": "eth_getBalance", "params": [SITE, "latest"], "world": read_world() });
    send(&mut core, 30, &page(Some(SITE)), params);
    let asked = core.recv();
    assert_eq!(asked["method"], "shell.rpc", "{asked}");
    core.send(&json!({ "type": "cancel", "id": 30 }));
    let mut cancelled = false;
    loop {
        let message = core.recv();
        match message["type"].as_str() {
            Some("cancel") if message["id"] == asked["id"] => cancelled = true,
            Some("response") if message["id"] == 30 => {
                assert_eq!(message["error"]["code"], "cancelled", "{message}");
                break;
            }
            _ => panic!("unexpected {message}"),
        }
    }
    assert!(cancelled);
}

/// `eip1193.request` is a page's alone, with its params' shape: anything
/// else is refused before the dispatcher runs.
#[test]
fn only_a_page_with_main_s_world_reaches_it() {
    let (_root, mut core) = core(&Value::Null);
    let params = json!({ "method": "eth_chainId", "world": read_world() });
    for (id, context) in [
        (40, json!({ "caller": "chrome" })),
        (41, json!({ "caller": "shell" })),
    ] {
        send(&mut core, id, &context, params.clone());
        assert_eq!(core.response(id)["error"]["code"], "forbidden");
    }
    for (id, bad) in [
        (42, json!({ "method": "eth_chainId" })),
        (
            43,
            json!({ "method": "eth_chainId", "world": { "enabled": true } }),
        ),
        (44, json!({ "method": 1, "world": read_world() })),
        (
            45,
            json!({ "method": "eth_chainId", "world": read_world(), "extra": 1 }),
        ),
    ] {
        send(&mut core, id, &page(Some(SITE)), bad);
        assert_eq!(
            core.response(id)["error"]["code"],
            "invalid_argument",
            "{id}"
        );
    }
    send(&mut core, 46, &page(Some(SITE)), params);
    assert_eq!(core.response(46)["result"], json!({ "result": "0x1" }));
}

/// `eth_accounts` reads the grant of the page's own key, and a document
/// with no key (an empty `origin`) reads none.
#[test]
fn accounts_read_the_pages_own_grant() {
    let grants = json!({ SITE: {
        "origin": SITE, "connectedAt": 1, "lastUsed": 1, "walletIndex": 0, "chainId": 1,
        "autoApprove": { "signing": false, "transactions": [] },
    } });
    let (_root, mut core) = core(&grants);
    let mut world = read_world();
    world["wallets"] =
        json!([{ "index": 0, "address": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94" }]);
    let params = json!({ "method": "eth_accounts", "params": [], "world": world });
    for (id, key, answer) in [
        (
            50,
            Some(SITE),
            json!(["0x9858EfFD232B4033E47d90003D41EC34EcaEda94"]),
        ),
        (51, None, json!([])),
        (52, Some("https://other.example"), json!([])),
    ] {
        send(&mut core, id, &page(key), params.clone());
        assert_eq!(
            core.response(id)["result"],
            json!({ "result": answer }),
            "{key:?}"
        );
    }
}

/// A read carries the page's key as its routing hint (`origin`; design
/// 0005, Deadlines and Adaptive bypass), as main's `chain.request` does: a
/// keyed read is interactive, so a source with another after it has 2 s,
/// and a route a source refused for capacity is closed to that key alone.
/// A keyless read has none: each source has the chain's whole timeout.
#[test]
fn a_read_carries_the_page_s_key_as_its_routing_hint() {
    let (_root, mut core) = core(&Value::Null);
    // Chain 1 read by a one-member quorum with 20 s, then Colibri, which
    // has no prover here and fails at once.
    let chain = json!({
        "chain_id": 1, "display_name": "Ethereum",
        "read_order": ["quorum", "colibri"], "broadcast_order": ["direct"],
        "quorum": { "k": 1, "m": 1, "timeout_ms": 20000 },
        "rpc": [{ "endpoint": "e1", "user_configured": false }],
        "prover": null, "myotis": false, "blockscout": null,
    });
    let reply = core.call(3, "chain.configure", json!({ "chains": [chain] }));
    assert!(reply["result"]["generations"].is_object(), "{reply}");
    let params = json!({ "method": "eth_blockNumber", "params": [], "world": read_world() });
    let block = rpc(r#"{"jsonrpc":"2.0","id":1,"result":"0x10"}"#);
    let busy = rpc(
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution gas limit reached"}}"#,
    );
    // The quorum member's exchange, with its deadline at main, answered.
    let read = |core: &mut Core, id: u64, key: Option<&str>, deadline_ms: u64, outcome: &Value| {
        send(core, id, &page(key), params.clone());
        let asked = core.recv();
        assert_eq!(asked["method"], "shell.rpc", "{id}: {asked}");
        assert_eq!(body(&asked)["method"], "eth_blockNumber", "{id}");
        // What is left of it: a few ms may have passed.
        let left = asked["params"]["deadline_ms"].as_u64().unwrap();
        assert!(
            left <= deadline_ms && left + 1000 > deadline_ms,
            "{id}: {asked}"
        );
        answer_rpc(core, &asked, outcome.clone());
        let (reply, seen) = until(core, id, |_| None);
        assert!(seen.is_empty(), "{id}: {seen:?}");
        reply["result"].clone()
    };

    // A keyless document's read isn't interactive, and closes no route.
    let result = read(&mut core, 60, None, 20000, &busy);
    assert_eq!(result["error"]["code"], -32603, "{result}");
    let result = read(&mut core, 61, None, 20000, &block);
    assert_eq!(result, json!({ "result": "0x10" }));
    // The page's is: its quorum member has 2 s, and a capacity refusal
    // closes the route to the page.
    let result = read(&mut core, 62, Some(SITE), 2000, &busy);
    assert_eq!(result["error"]["code"], -32603, "{result}");
    // Its next read skips the quorum: main is asked nothing.
    send(&mut core, 63, &page(Some(SITE)), params.clone());
    let (reply, seen) = until(&mut core, 63, |_| None);
    assert!(seen.is_empty(), "{seen:?}");
    assert_eq!(reply["result"]["error"]["code"], -32603, "{reply}");
    // Another key's route is its own.
    let result = read(&mut core, 64, Some("https://other.example"), 2000, &block);
    assert_eq!(result, json!({ "result": "0x10" }));
}
