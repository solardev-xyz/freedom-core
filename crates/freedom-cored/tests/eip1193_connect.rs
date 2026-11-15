//! A page's connect end to end (design 0012, APR-5c-1): the real binary,
//! with the test playing main. Every connect scenario of `step: "APR-5c"`
//! in vectors/eip1193.json is replayed: main answers the core's
//! `approval.recheck` live and its `approval.request` with the decision the
//! reference's prompt took, and the core's answer, the grant file it writes
//! and its `approval.changed` events are the reference's. Then the
//! guarantees: no grant without a decision, prompt ids and handles never
//! reused, the clock stopped while a prompt is open, a cancel, and the cap
//! on open prompts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::{Core, dirs, spawn_env};
use serde_json::{Value, json};

const SITE: &str = "https://app.example";

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

/// A core whose dApp store has moved, holding `grants` (none for null).
fn core_with(grants: &Value, env: &[(&str, &str)]) -> (tempfile::TempDir, Core) {
    let (root, data, locks) = dirs();
    let mut core = spawn_env("serve", &data, &locks, &[], env);
    std::fs::create_dir_all(&core.grant_root).unwrap();
    if !grants.is_null() {
        let text = serde_json::to_string_pretty(grants).unwrap();
        std::fs::write(core.grant_root.join("dapp-permissions.json"), text).unwrap();
    }
    core.grant_moved = vec!["dapp"];
    assert_eq!(core.hello_fragments()["result"]["protocol"], 2);
    (root, core)
}

fn page(key: Option<&str>) -> Value {
    let origin = key.unwrap_or("");
    json!({ "caller": "page", "page": {
        "origin": origin, "top_origin": origin, "frame": 1, "navigation": 1, "agent": false,
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

/// The test's world: Gnosis, two accounts.
fn plain_world() -> Value {
    json!({
        "enabled": true, "window_chain": 100, "active": 0,
        "wallets": [{ "index": 0, "address": "0xa" }, { "index": 1, "address": "0xb" }],
        "networks": { "100": { "name": "Gnosis", "available": true } },
    })
}

fn connect(core: &mut Core, id: u64, key: Option<&str>, world: &Value) {
    core.send(&json!({
        "type": "request", "id": id, "method": "eip1193.request",
        "params": { "method": "eth_requestAccounts", "params": [], "world": world },
        "context": page(key),
    }));
}

/// Main's answer to one of the core's requests.
fn respond(core: &mut Core, request: &Value, result: Value) {
    core.send(&json!({ "type": "response", "id": request["id"], "result": result }));
}

/// The next message, which must be one of the core's requests to main.
fn next_request(core: &mut Core) -> Value {
    let message = core.recv();
    assert_eq!(
        message["type"], "request",
        "expected a request, got {message}"
    );
    message
}

fn response(core: &mut Core, id: u64) -> Value {
    let message = core.recv();
    assert_eq!(message["type"], "response", "{message}");
    assert_eq!(message["id"], id, "{message}");
    message
}

/// The events the core sent since the last reply: read up to the reply to
/// a sentinel request.
fn events(core: &mut Core, id: u64) -> Vec<Value> {
    core.send(&json!({
        "type": "request", "id": id, "method": "eip1193.request",
        "params": { "method": "eth_chainId", "world": plain_world() },
        "context": page(None),
    }));
    let mut seen = Vec::new();
    loop {
        let message = core.recv();
        match message["type"].as_str() {
            Some("response") if message["id"] == id => return seen,
            Some("event") => seen.push(message),
            _ => panic!("unexpected {message}"),
        }
    }
}

fn handle(n: u64) -> String {
    format!("{n:064x}")
}

fn file_of(core: &Core) -> Value {
    std::fs::read_to_string(core.grant_root.join("dapp-permissions.json"))
        .map_or(Value::Null, |text| serde_json::from_str(&text).unwrap())
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

fn is_connect(scenario: &Value) -> bool {
    scenario["step"] == "APR-5c"
        && scenario["requests"].as_array().unwrap().iter().all(|r| {
            ["eth_requestAccounts", "eth_accounts"].contains(&r["method"].as_str().unwrap())
        })
}

#[test]
fn every_apr5c_connect_scenario_replays_through_the_core() {
    let file = load();
    let now = file["now"].as_u64().unwrap();
    let (mut scenarios, mut requests, mut prompts, mut ids) = (0, 0, 0, Vec::new());
    let mut handles = 0;
    for scenario in file["scenarios"].as_array().unwrap() {
        if !is_connect(scenario) {
            continue;
        }
        scenarios += 1;
        let id = scenario["id"].as_str().unwrap();
        let failing = scenario["requests"][0]["effects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["effect"] == "grant.write" && e.get("throws").is_some());
        let spec = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(spec.path(), "dapp:write\n").unwrap();
        let env: Vec<(&str, &str)> = if failing {
            vec![(
                "FREEDOM_CORED_TEST_GRANT_WRITE_FAIL",
                spec.path().to_str().unwrap(),
            )]
        } else {
            Vec::new()
        };
        let from = wall_ms();
        let (_root, mut core) = core_with(&scenario["grants"]["before"], &env);
        let world = world_of(&file, scenario);
        let key = scenario["world"]["documents"][0]["key"].as_str();
        let context = page(key);
        let mut next = 10;
        for (i, recorded) in scenario["requests"].as_array().unwrap().iter().enumerate() {
            requests += 1;
            next += 2;
            let what = format!("{id} #{i} {}", recorded["method"]);
            let effects = recorded["effects"].as_array().unwrap();
            core.send(&json!({
                "type": "request", "id": next, "method": "eip1193.request",
                "params": { "method": recorded["method"], "params": recorded["params"], "world": world },
                "context": context,
            }));
            let prompt = effects.iter().find(|e| e["effect"] == "prompt");
            let touch = effects.iter().any(|e| e["args"]["op"] == "updateLastUsed");
            if touch {
                let asked = next_request(&mut core);
                assert_eq!(asked["method"], "approval.recheck", "{what}");
                assert_eq!(
                    asked["params"],
                    json!({ "request": next, "page": context["page"] }),
                    "{what}"
                );
                respond(&mut core, &asked, json!({ "live": true, "agent": false }));
            }
            if let Some(prompt) = prompt {
                prompts += 1;
                let asked = next_request(&mut core);
                assert_eq!(asked["method"], "approval.request", "{what}");
                let params = &asked["params"];
                let prompt_id = params["prompt"].as_str().unwrap().to_owned();
                assert_eq!(prompt_id.len(), 32, "{what}");
                assert!(
                    prompt_id
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                );
                ids.push(prompt_id.clone());
                assert_eq!(params["request"], next, "{what}");
                assert_eq!(params["page"], context["page"], "{what}");
                assert_eq!(params["kind"], prompt["args"]["kind"], "{what}");
                assert_eq!(
                    params["view"].to_string(),
                    prompt["args"]["view"].to_string(),
                    "{what}"
                );
                let offered: Vec<Value> = prompt["args"]["view"]["accounts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| a["index"].clone())
                    .collect();
                assert_eq!(
                    params["choices"],
                    json!({ "walletIndex": offered }),
                    "{what}"
                );
                // Main's world as it answers: the scenario's changes made
                // while the prompt was open.
                let mut then = world.clone();
                for change in effects.iter().filter(|e| e["effect"] == "world") {
                    if let Some(index) = change["change"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("wallet-removed:")
                    {
                        let index: u64 = index.parse().unwrap();
                        then["wallets"]
                            .as_array_mut()
                            .unwrap()
                            .retain(|w| w["index"].as_u64() != Some(index));
                    }
                }
                let decision = &prompt["answer"];
                let answer = if decision.get("approve").is_some() {
                    handles += 1;
                    let mut answer = json!({
                        "prompt": prompt_id, "handle": handle(handles),
                        "approve": decision["approve"], "choices": decision["choices"],
                    });
                    if decision["approve"] == true {
                        answer["world"] = then;
                    }
                    answer
                } else if let Some(reason) = decision.get("closed") {
                    json!({ "prompt": prompt_id, "closed": reason })
                } else {
                    json!({ "prompt": prompt_id, "busy": true })
                };
                respond(&mut core, &asked, answer);
            }
            // A keyless connect, and one that asks nothing, reach main with
            // no request: the next message is the answer.
            let reply = response(&mut core, next);
            assert_eq!(
                reply["result"].to_string(),
                recorded["result"].to_string(),
                "{what}"
            );
            let granted = effects
                .iter()
                .any(|e| e["args"]["op"] == "grantPermission" && e.get("throws").is_none());
            let expected: Vec<Value> = if granted {
                vec![json!({ "type": "event", "event": "approval.changed",
                    "data": { "store": "dapp", "key": key } })]
            } else {
                Vec::new()
            };
            assert_eq!(events(&mut core, next + 1), expected, "{what}");
        }
        let to = wall_ms();
        assert_eq!(
            normalized(file_of(&core), from, to, now),
            scenario["grants"]["after"],
            "{id}"
        );
    }
    let distinct: std::collections::BTreeSet<&String> = ids.iter().collect();
    assert_eq!(distinct.len(), ids.len(), "a prompt id reused");
    assert_eq!((scenarios, requests, prompts), (13, 14, 11));
}

/// The row's "No grant without a decision": a connect answered closed,
/// busy or rejected, or approved without the choice, writes nothing; so
/// does an answer that isn't main's decision on that prompt (another
/// prompt's id, a handle seen before, a pick not offered), which fails the
/// request.
#[test]
fn no_grant_without_a_decision() {
    let (_root, mut core) = core_with(&Value::Null, &[]);
    let world = plain_world();
    let rejected = r#"{"error":{"code":4001,"message":"User rejected the request"}}"#;
    let busy = r#"{"error":{"code":-32002,"message":"Another wallet request is already pending"}}"#;
    let mismatch = |reply: &Value| {
        assert_eq!(reply["error"]["code"], "not_authorized", "{reply}");
        assert_eq!(reply["error"]["data"]["reason"], "mismatch", "{reply}");
    };
    let mut seen_ids = std::collections::BTreeSet::new();
    let mut ask = |core: &mut Core, id: u64| -> (Value, String) {
        connect(core, id, Some(SITE), &world);
        let asked = next_request(core);
        assert_eq!(asked["method"], "approval.request");
        let prompt = asked["params"]["prompt"].as_str().unwrap().to_owned();
        assert!(seen_ids.insert(prompt.clone()), "prompt id reused");
        (asked, prompt)
    };
    let approve = |prompt: &str, handle: &str, choices: Value| {
        json!({ "prompt": prompt, "handle": handle, "approve": true,
            "choices": choices, "world": plain_world() })
    };
    // Rejected, closed, busy.
    let (asked, prompt) = ask(&mut core, 10);
    respond(
        &mut core,
        &asked,
        json!({ "prompt": prompt, "handle": handle(1), "approve": false, "choices": {} }),
    );
    assert_eq!(response(&mut core, 10)["result"].to_string(), rejected);
    let (asked, prompt) = ask(&mut core, 11);
    respond(
        &mut core,
        &asked,
        json!({ "prompt": prompt, "closed": "cancelled" }),
    );
    assert_eq!(response(&mut core, 11)["result"].to_string(), rejected);
    let (asked, prompt) = ask(&mut core, 12);
    respond(&mut core, &asked, json!({ "prompt": prompt, "busy": true }));
    assert_eq!(response(&mut core, 12)["result"].to_string(), busy);
    // Approved without the choice, and with a pick not offered.
    for (id, choices) in [
        (13, json!({})),
        (14, json!({ "walletIndex": 7 })),
        (15, json!({ "walletIndex": 0, "x": 1 })),
    ] {
        let (asked, prompt) = ask(&mut core, id);
        respond(&mut core, &asked, approve(&prompt, &handle(id), choices));
        mismatch(&response(&mut core, id));
    }
    // Another prompt's id: two prompts open, each answered with the other's.
    let (first, first_id) = ask(&mut core, 16);
    let (second, second_id) = ask(&mut core, 17);
    respond(
        &mut core,
        &first,
        approve(&second_id, &handle(16), json!({ "walletIndex": 0 })),
    );
    mismatch(&response(&mut core, 16));
    respond(
        &mut core,
        &second,
        approve(&first_id, &handle(17), json!({ "walletIndex": 0 })),
    );
    mismatch(&response(&mut core, 17));
    // A handle an earlier answer named (the rejection's, then a mismatch's).
    for (id, used) in [(18, 1), (19, 13)] {
        let (asked, prompt) = ask(&mut core, id);
        respond(
            &mut core,
            &asked,
            approve(&prompt, &handle(used), json!({ "walletIndex": 0 })),
        );
        mismatch(&response(&mut core, id));
    }
    // Main's error for the request, and a recheck-shaped answer.
    let (asked, _) = ask(&mut core, 20);
    core.send(&json!({ "type": "response", "id": asked["id"],
        "error": { "code": "internal", "message": "x" } }));
    mismatch(&response(&mut core, 20));
    let (asked, _) = ask(&mut core, 21);
    respond(&mut core, &asked, json!({ "live": true, "agent": false }));
    mismatch(&response(&mut core, 21));
    assert!(events(&mut core, 30).is_empty(), "no approval.changed");
    assert_eq!(file_of(&core), Value::Null, "nothing written");
    // The same decision, well formed, does write.
    let (asked, prompt) = ask(&mut core, 31);
    respond(
        &mut core,
        &asked,
        approve(&prompt, &handle(31), json!({ "walletIndex": 1 })),
    );
    assert_eq!(
        response(&mut core, 31)["result"],
        json!({ "result": ["0xb"] })
    );
    assert_eq!(file_of(&core)[SITE]["walletIndex"], 1);
    assert_eq!(file_of(&core)[SITE]["chainId"], 100);
}

/// The clock stops while a prompt is open: with 300 ms in all, a prompt
/// decided after a second still connects. Outside a prompt it runs: a
/// recheck main holds past it answers the deadline, cancels the core's
/// request, and marks nothing; main's late answer is dropped.
#[test]
fn the_clock_stops_while_a_prompt_is_open() {
    let (_root, mut core) = core_with(
        &Value::Null,
        &[("FREEDOM_CORED_TEST_EIP1193_OVERALL_MS", "300")],
    );
    connect(&mut core, 10, Some(SITE), &plain_world());
    let asked = next_request(&mut core);
    std::thread::sleep(Duration::from_millis(1000));
    let prompt = asked["params"]["prompt"].clone();
    respond(
        &mut core,
        &asked,
        json!({ "prompt": prompt, "handle": handle(1),
        "approve": true, "choices": { "walletIndex": 0 }, "world": plain_world() }),
    );
    assert_eq!(
        response(&mut core, 10)["result"],
        json!({ "result": ["0xa"] })
    );
    let before = file_of(&core);
    assert_eq!(before[SITE]["walletIndex"], 0);
    assert_eq!(
        events(&mut core, 11).len(),
        1,
        "the connect's approval.changed"
    );
    // Connected now: the recheck held.
    connect(&mut core, 12, Some(SITE), &plain_world());
    let recheck = next_request(&mut core);
    assert_eq!(recheck["method"], "approval.recheck");
    let started = std::time::Instant::now();
    let mut cancelled = false;
    let reply = loop {
        let message = core.recv();
        match message["type"].as_str() {
            Some("cancel") => {
                assert_eq!(message["id"], recheck["id"]);
                cancelled = true;
            }
            Some("response") => break message,
            _ => panic!("unexpected {message}"),
        }
    };
    assert!(started.elapsed() >= Duration::from_millis(250));
    assert_eq!(reply["id"], 12);
    assert_eq!(
        reply["result"].to_string(),
        r#"{"error":{"code":-32603,"message":"The request's deadline passed"}}"#
    );
    assert!(cancelled, "the core cancels its recheck");
    respond(&mut core, &recheck, json!({ "live": true, "agent": false }));
    assert!(events(&mut core, 13).is_empty());
    assert_eq!(file_of(&core), before, "nothing marked");
}

/// A cancel of the page request at its prompt answers `cancelled` and
/// cancels the core's `approval.request`; main's late approve writes
/// nothing. A recheck answered not live marks nothing and answers 4100.
#[test]
fn a_cancel_or_a_document_gone_writes_nothing() {
    let grant = json!({ SITE: { "origin": SITE, "connectedAt": 1, "lastUsed": 1, "walletIndex": 0,
        "chainId": 100, "autoApprove": { "signing": false, "transactions": [] } } });
    let (_root, mut core) = core_with(&Value::Null, &[]);
    connect(&mut core, 10, Some(SITE), &plain_world());
    let asked = next_request(&mut core);
    core.send(&json!({ "type": "cancel", "id": 10 }));
    let cancel = core.recv();
    assert_eq!(cancel, json!({ "type": "cancel", "id": asked["id"] }));
    let reply = response(&mut core, 10);
    assert_eq!(reply["error"]["code"], "cancelled", "{reply}");
    respond(
        &mut core,
        &asked,
        json!({ "prompt": asked["params"]["prompt"], "handle": handle(1),
        "approve": true, "choices": { "walletIndex": 0 }, "world": plain_world() }),
    );
    assert!(events(&mut core, 11).is_empty());
    assert_eq!(file_of(&core), Value::Null);
    drop(core);

    let (_root, mut core) = core_with(&grant, &[]);
    connect(&mut core, 10, Some(SITE), &plain_world());
    let recheck = next_request(&mut core);
    respond(
        &mut core,
        &recheck,
        json!({ "live": false, "agent": false }),
    );
    assert_eq!(
        response(&mut core, 10)["result"].to_string(),
        r#"{"error":{"code":4100,"message":"This page has no address to connect from yet"}}"#
    );
    assert_eq!(file_of(&core), grant, "nothing marked");
}

/// A keyless document gets 4100 before any approval path, a store not
/// moved gets `not_moved` before any prompt, and the switch off 4900.
#[test]
fn refused_before_any_approval_path() {
    let (_root, mut core) = core_with(&Value::Null, &[]);
    connect(&mut core, 10, None, &plain_world());
    assert_eq!(
        response(&mut core, 10)["result"].to_string(),
        r#"{"error":{"code":4100,"message":"This page has no address to connect from yet"}}"#
    );
    let mut off = plain_world();
    off["enabled"] = json!(false);
    connect(&mut core, 11, Some(SITE), &off);
    assert_eq!(
        response(&mut core, 11)["result"].to_string(),
        r#"{"error":{"code":4900,"message":"Disconnected"}}"#
    );
    drop(core);
    let (_root, data, locks) = dirs();
    let mut core = spawn_env("serve", &data, &locks, &[], &[]);
    std::fs::create_dir_all(&core.grant_root).unwrap();
    core.hello_fragments();
    connect(&mut core, 10, Some(SITE), &plain_world());
    let reply = response(&mut core, 10);
    assert_eq!(reply["error"]["code"], "not_moved", "{reply}");
    assert_eq!(reply["error"]["data"]["store"], "dapp", "{reply}");
}

/// At most 64 `approval.request`s are open at once (*inferred*): the 65th
/// connect waits for room and goes, in order, once one is answered. A
/// recheck isn't a prompt, so a connected key's goes while the 64 are open.
#[test]
fn at_most_64_prompts_are_open_at_once() {
    const CONNECTED: &str = "https://connected.example";
    let grant = json!({ CONNECTED: { "origin": CONNECTED, "connectedAt": 1, "lastUsed": 1,
        "walletIndex": 0, "chainId": 100,
        "autoApprove": { "signing": false, "transactions": [] } } });
    let (_root, mut core) = core_with(&grant, &[]);
    let world = plain_world();
    let mut asked = Vec::new();
    for id in 100..164 {
        connect(&mut core, id, Some(SITE), &world);
        let request = next_request(&mut core);
        assert_eq!(request["method"], "approval.request");
        assert_eq!(request["params"]["request"], id);
        asked.push(request);
    }
    connect(&mut core, 164, Some(SITE), &world);
    connect(&mut core, 165, Some(CONNECTED), &world);
    let recheck = next_request(&mut core);
    assert_eq!(
        recheck["method"], "approval.recheck",
        "the 65th prompt waits"
    );
    assert_eq!(recheck["params"]["request"], 165);
    respond(&mut core, &recheck, json!({ "live": true, "agent": false }));
    assert_eq!(
        response(&mut core, 165)["result"],
        json!({ "result": ["0xa"] })
    );
    // Still no 65th: the sentinel's reply comes with no request before it.
    for event in events(&mut core, 200) {
        assert_eq!(event["event"], "approval.changed", "{event}");
    }
    // One answered: the 65th goes (main may see it before the answer).
    let first = &asked[0];
    respond(
        &mut core,
        first,
        json!({ "prompt": first["params"]["prompt"], "closed": "closed" }),
    );
    let (mut waited, mut answered) = (Value::Null, Value::Null);
    for _ in 0..2 {
        let message = core.recv();
        match message["type"].as_str() {
            Some("request") if waited.is_null() => waited = message,
            Some("response") if answered.is_null() => answered = message,
            _ => panic!("unexpected {message}"),
        }
    }
    assert_eq!(answered["id"], 100);
    assert_eq!(
        answered["result"].to_string(),
        r#"{"error":{"code":4001,"message":"User rejected the request"}}"#
    );
    assert_eq!(waited["method"], "approval.request");
    assert_eq!(waited["params"]["request"], 164);
    respond(
        &mut core,
        &waited,
        json!({ "prompt": waited["params"]["prompt"], "handle": handle(164),
        "approve": true, "choices": { "walletIndex": 1 }, "world": plain_world() }),
    );
    assert_eq!(
        response(&mut core, 164)["result"],
        json!({ "result": ["0xb"] })
    );
    assert_eq!(file_of(&core)[SITE]["walletIndex"], 1);
}

fn approve_with(asked: &Value, handle: &str) -> Value {
    json!({ "prompt": asked["params"]["prompt"], "handle": handle, "approve": true,
        "choices": { "walletIndex": 0 }, "world": plain_world() })
}

/// A cancelled prompt's late answer still spends its handle: another
/// prompt answered with that handle afterwards is crossed, and nothing is
/// written.
#[test]
fn a_late_answer_to_a_cancelled_prompt_spends_its_handle() {
    let (_root, mut core) = core_with(&Value::Null, &[]);
    connect(&mut core, 10, Some(SITE), &plain_world());
    let first = next_request(&mut core);
    connect(&mut core, 11, Some(SITE), &plain_world());
    let second = next_request(&mut core);
    core.send(&json!({ "type": "cancel", "id": 10 }));
    assert_eq!(core.recv(), json!({ "type": "cancel", "id": first["id"] }));
    assert_eq!(response(&mut core, 10)["error"]["code"], "cancelled");
    respond(&mut core, &first, approve_with(&first, &handle(7)));
    respond(&mut core, &second, approve_with(&second, &handle(7)));
    let reply = response(&mut core, 11);
    assert_eq!(reply["error"]["code"], "not_authorized", "{reply}");
    assert_eq!(reply["error"]["data"]["reason"], "mismatch", "{reply}");
    assert!(events(&mut core, 12).is_empty(), "no approval.changed");
    assert_eq!(file_of(&core), Value::Null, "nothing written");
}

/// Busy answers while one prompt stays open leave its id alone retained.
/// Cancelled, it leaves a tombstone until main's late answer, which then
/// leaves only the handle that answer named.
#[test]
fn busy_cycles_leave_the_retained_state_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("retained");
    let (_root, mut core) = core_with(
        &Value::Null,
        &[(
            "FREEDOM_CORED_TEST_EIP1193_RETAINED_MARKER",
            marker.to_str().unwrap(),
        )],
    );
    let retained = || std::fs::read_to_string(&marker).unwrap();
    let busy = r#"{"error":{"code":-32002,"message":"Another wallet request is already pending"}}"#;
    connect(&mut core, 10, Some(SITE), &plain_world());
    let held = next_request(&mut core);
    for id in 11..311 {
        connect(&mut core, id, Some(SITE), &plain_world());
        let asked = next_request(&mut core);
        respond(
            &mut core,
            &asked,
            json!({ "prompt": asked["params"]["prompt"], "busy": true }),
        );
        assert_eq!(response(&mut core, id)["result"].to_string(), busy);
    }
    assert_eq!(retained(), "1 0 0", "live ids, handles, tombstones");
    core.send(&json!({ "type": "cancel", "id": 10 }));
    assert_eq!(core.recv(), json!({ "type": "cancel", "id": held["id"] }));
    assert_eq!(response(&mut core, 10)["error"]["code"], "cancelled");
    assert_eq!(retained(), "1 0 1");
    respond(&mut core, &held, approve_with(&held, &handle(5)));
    assert!(events(&mut core, 400).is_empty());
    assert_eq!(retained(), "0 1 0");
    assert_eq!(file_of(&core), Value::Null, "nothing written");
}
