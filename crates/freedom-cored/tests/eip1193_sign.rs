//! A page's signature end to end (design 0012, APR-5d-1): the real binary,
//! with the test playing main and the vault holding the vectors' test key.
//! Every vault-prompt scenario of `step: "APR-5d"` in vectors/eip1193.json
//! is replayed: main answers the core's `approval.request` with the
//! decision the reference's prompt took, and the core's answer, the
//! signature included, and the grant file are the reference's, byte for
//! byte. The prompt's view is the reference's, byte for byte, but for a
//! typed-data view, which the vectors script (`named_type` and `chain`
//! only): there the view is fc-evm's own, its reports the scripted ones,
//! and the chains a warning quotes include the one its domain names. Then
//! the guarantees: a keyless document gets `4100` first, whatever its
//! params; nothing is signed on a crossed answer; no Ledger, phone or Safe
//! account reaches the vault, each getting `{ device }` for a message and
//! for typed data, with a token bound to what the page's request alone
//! says, the page and the handle; a grant index that is no account signs
//! nothing; typed data nested past fc-json is `Invalid parameters`; and a
//! locked vault signs nothing.
//!
//! APR-5d-2's ten scenarios (a rule answering, "Always allow", a Ledger)
//! replay with the reference's rule in Q9's form (`rule-legacy`: the core
//! answers only the limited rule), the wall clock at the vectors' `now`.
//! Then a rule's guarantees: custody or the document gone at the recheck
//! refuses with nothing signed, each form of main's answer to the unlock,
//! and Q9 through the dispatcher.

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

/// fc-eip1193's `tests/signs.rs` list: the scenarios a vault prompt
/// answers, or that end before one.
const VAULT_PROMPT: [&str; 14] = [
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

/// A core whose dApp store has moved (unless `moved` is false), holding
/// `grants` (none for null), its vault unlocked with the test key if
/// `unlocked`.
fn core_with(grants: &Value, moved: bool, unlocked: bool) -> (tempfile::TempDir, Core) {
    let (root, data, locks) = dirs();
    let mut core = spawn_env("serve", &data, &locks, &[], &[]);
    std::fs::create_dir_all(&core.grant_root).unwrap();
    if !grants.is_null() {
        let text = serde_json::to_string_pretty(grants).unwrap();
        std::fs::write(core.grant_root.join("dapp-permissions.json"), text).unwrap();
    }
    if moved {
        core.grant_moved = vec!["dapp"];
    }
    assert_eq!(core.hello_fragments()["result"]["protocol"], 2);
    if unlocked {
        let imported = core.call(
            2,
            "vault.import",
            json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(ABANDON) }),
        );
        assert!(imported["result"].is_object(), "{imported}");
        assert_eq!(core.event()["event"], "vault.unlocked");
    }
    (root, core)
}

fn page(key: Option<&str>, agent: Option<bool>) -> Value {
    let origin = key.unwrap_or("");
    let mut page = json!({ "origin": origin, "top_origin": origin, "frame": 1, "navigation": 1 });
    if let Some(agent) = agent {
        page["agent"] = json!(agent);
    }
    json!({ "caller": "page", "page": page })
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

fn request(core: &mut Core, id: u64, key: Option<&str>, agent: Option<bool>, body: &Value) {
    core.send(&json!({
        "type": "request", "id": id, "method": "eip1193.request",
        "params": body, "context": page(key, agent),
    }));
}

fn next_request(core: &mut Core) -> Value {
    let message = core.recv();
    assert_eq!(
        message["type"], "request",
        "expected a request, got {message}"
    );
    message
}

fn respond(core: &mut Core, request: &Value, result: Value) {
    core.send(&json!({ "type": "response", "id": request["id"], "result": result }));
}

fn response(core: &mut Core, id: u64) -> Value {
    let message = core.recv();
    assert_eq!(message["type"], "response", "{message}");
    assert_eq!(message["id"], id, "{message}");
    message
}

/// The approval.request answer main sends for a recorded decision.
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

/// fc-evm's view of the typed data a request sends: what the core shows.
fn own_view(typed: &Value, chain_id: u64) -> Value {
    let typed: Value = match typed {
        Value::String(text) => serde_json::from_str(text).unwrap(),
        other => other.clone(),
    };
    let mut types = typed["types"].clone();
    types.as_object_mut().unwrap().remove("EIP712Domain");
    let request = fc_evm::ViewRequest {
        primary_type: typed.get("primaryType"),
        chain_id: fc_evm::parse_unsigned(&chain_id.to_string()),
        max_len: 1 << 20,
    };
    let viewed =
        fc_evm::typed_data_view(&typed["domain"], &types, &typed["message"], &request).unwrap();
    serde_json::from_str(&viewed.view).unwrap()
}

#[test]
fn every_vault_prompt_scenario_replays_through_the_core() {
    let file = load();
    let (mut scenarios, mut requests, mut asked, mut signed) = (0, 0, 0, 0);
    for scenario in file["scenarios"].as_array().unwrap() {
        let name = scenario["id"].as_str().unwrap();
        if !VAULT_PROMPT.contains(&name) {
            continue;
        }
        scenarios += 1;
        let signs = scenario["requests"].as_array().unwrap().iter().any(|r| {
            r["effects"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["effect"] == "token.issue")
        });
        let (_root, mut core) = core_with(&scenario["grants"]["before"], true, signs);
        let world = world_of(&file, scenario);
        let agent = scenario["world"]["custody"].as_bool();
        let key = scenario["world"]["documents"][0]["key"].as_str();
        let chain_id = world["chain"]
            .as_u64()
            .or(world["window_chain"].as_u64())
            .unwrap_or(100);
        for (i, recorded) in scenario["requests"].as_array().unwrap().iter().enumerate() {
            requests += 1;
            let what = format!("{name} #{i} {}", recorded["method"]);
            let id = 100 + u64::try_from(i).unwrap();
            let mut body = json!({ "method": recorded["method"], "world": world });
            if let Some(p) = recorded.get("params") {
                body["params"] = p.clone();
            }
            request(&mut core, id, key, agent, &body);
            let effects = recorded["effects"].as_array().unwrap();
            let message = match effects.iter().find(|e| e["effect"] == "prompt") {
                None => response(&mut core, id),
                Some(prompt) => {
                    asked += 1;
                    let asked = next_request(&mut core);
                    assert_eq!(asked["method"], "approval.request", "{what}");
                    let params = &asked["params"];
                    assert_eq!(params["request"], id, "{what}");
                    assert_eq!(params["kind"], prompt["args"]["kind"], "{what}");
                    let device = ["ledger", "remote", "safe"]
                        .contains(&params["view"]["account"]["type"].as_str().unwrap_or(""));
                    let offered = if device {
                        json!({ "alwaysAllow": [false] })
                    } else {
                        json!({ "alwaysAllow": [false, true] })
                    };
                    assert_eq!(params["choices"], offered, "{what}");
                    let mut expected = prompt["args"]["view"].clone();
                    if expected.get("typedData").is_some() {
                        let shown = &params["view"]["typedData"]["view"];
                        assert_eq!(shown, &own_view(&body["params"][1], chain_id), "{what}");
                        let scripted = &expected["typedData"]["view"];
                        for report in ["named_type", "chain"] {
                            assert_eq!(shown[report], scripted[report], "{what}");
                        }
                        expected["typedData"]["view"] = shown.clone();
                        // The chains a mismatch quotes: the page's, and the
                        // one the real view's domain names.
                        if !expected["chains"].as_object().unwrap().is_empty() {
                            let domain = u64::from_str_radix(
                                shown["domain"]["chainId"]
                                    .as_str()
                                    .unwrap()
                                    .trim_start_matches("0x"),
                                16,
                            )
                            .unwrap();
                            let mut chains = serde_json::Map::new();
                            let mut ids = [chain_id, domain];
                            ids.sort_unstable();
                            for id in ids {
                                let name = &file["networks"][id.to_string()]["name"];
                                chains.insert(id.to_string(), json!({ "name": name }));
                            }
                            expected["chains"] = Value::Object(chains);
                        }
                    }
                    assert_eq!(params["view"].to_string(), expected.to_string(), "{what}");
                    // Main's world as it answers: a revoke made meanwhile.
                    for change in effects.iter().filter(|e| e["effect"] == "world") {
                        if change["change"] == "grant-revoked" {
                            let revoked = core.call_shell(
                                id + 50,
                                "approval.revoke",
                                json!({ "store": "dapp", "key": SITE, "what": "grant" }),
                            );
                            assert!(revoked.get("result").is_some(), "{revoked}");
                        }
                    }
                    let handle = format!("{:064x}", asked["id"].as_u64().unwrap());
                    let answer = answer_of(&params["prompt"], &handle, &prompt["answer"], &world);
                    respond(&mut core, &asked, answer);
                    core.until_response(id)
                }
            };
            if effects.iter().any(|e| e["effect"] == "token.issue") {
                signed += 1;
            }
            assert_eq!(
                message["result"].to_string(),
                recorded["result"].to_string(),
                "{what}: {message}"
            );
        }
        let after = &scenario["grants"]["after"];
        let file_now = grant_file(&core);
        if after.is_null() {
            assert!(file_now.is_null(), "{name}: {file_now}");
        } else {
            assert_eq!(file_now, *after, "{name}");
        }
    }
    assert_eq!((scenarios, requests, asked, signed), (14, 18, 9, 4));
}

fn connected(account: u64, signing: bool) -> Value {
    json!({ SITE: {
        "origin": SITE, "connectedAt": 1_763_000_000_000_u64, "lastUsed": 1_763_000_000_000_u64,
        "walletIndex": account, "chainId": 100,
        "autoApprove": { "signing": signing, "transactions": [] },
    } })
}

/// The dApp store holding each `(site, walletIndex)`, unruled.
fn grants(entries: &[(&str, Value)]) -> Value {
    let map: serde_json::Map<String, Value> = entries
        .iter()
        .map(|(site, index)| {
            let entry = json!({
                "origin": site, "connectedAt": 1_763_000_000_000_u64, "lastUsed": 1_763_000_000_000_u64,
                "walletIndex": index, "chainId": 100,
                "autoApprove": { "signing": false, "transactions": [] },
            });
            ((*site).to_owned(), entry)
        })
        .collect();
    Value::Object(map)
}

fn world() -> Value {
    json!({
        "enabled": true, "window_chain": 100, "active": 0,
        "wallets": [
            { "index": 0, "name": "Main Wallet", "address": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "type": "mnemonic" },
            { "index": 1, "name": "Ledger", "address": "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0", "type": "ledger" },
            { "index": 2, "name": "Phone", "address": "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A", "type": "remote" },
            { "index": 1000, "name": "Team Safe", "address": "0x4444444444444444444444444444444444444444", "type": "safe", "deployed": { "100": true } },
        ],
        "networks": { "100": { "name": "Gnosis", "available": true } },
    })
}

fn hello_sign() -> Value {
    json!({ "method": "personal_sign", "params": ["0x68656c6c6f"], "world": world() })
}

const HELLO_SIGNATURE: &str = "0x22f6b9cd7ff4f321e11181c4fe64adeea9469908fb514fbb6001fe022002dfda1f4ec9ea436bad14a7823806487d3aeb39b22e2556590922d6a8308971a17e991c";

fn approve(prompt: &Value, handle: &str, choices: Value) -> Value {
    json!({ "prompt": prompt, "handle": handle, "approve": true, "choices": choices, "world": world() })
}

/// A keyless document gets `4100` before anything else: before the
/// store's `not_moved`, and with nothing asked of main.
#[test]
fn a_keyless_document_gets_4100_first() {
    let (_root, mut core) = core_with(&connected(0, false), false, false);
    let no_address = json!({ "error": { "code": 4100, "message": "This page has no address to connect from yet" } });
    request(&mut core, 5, None, Some(false), &hello_sign());
    assert_eq!(response(&mut core, 5)["result"], no_address);
    // Whatever the params: missing, null, malformed, or typed data that
    // won't parse. The keyless answer comes before any of them is read.
    let address = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
    let params = [
        None,
        Some(json!(null)),
        Some(json!("0x68656c6c6f")),
        Some(json!([])),
        Some(json!({ "0": 1 })),
        Some(json!([{}, 7])),
        Some(json!([address])),
        Some(json!([address, "{not json"])),
        Some(json!([address, { "types": 1 }])),
    ];
    let mut id = 100;
    for method in ["personal_sign", "eth_signTypedData_v4"] {
        for param in &params {
            let mut body = json!({ "method": method, "world": world() });
            if let Some(param) = param {
                body["params"] = param.clone();
            }
            request(&mut core, id, None, Some(false), &body);
            assert_eq!(response(&mut core, id)["result"], no_address, "{body}");
            id += 1;
        }
    }
    // With a key, the unmoved store refuses before any prompt.
    request(&mut core, 200, Some(SITE), Some(false), &hello_sign());
    let refused = response(&mut core, 200);
    assert_eq!(refused["error"]["code"], "not_moved", "{refused}");
}

/// A crossed answer signs nothing: another prompt's id, a handle an
/// earlier answer named, or a pick not offered. Each fails its request with `mismatch`; the grant is
/// untouched, and the next approve still signs.
#[test]
fn a_crossed_answer_signs_nothing() {
    let (_root, mut core) = core_with(&connected(0, false), true, true);
    let before = grant_file(&core);
    let crossed = |core: &mut Core, id: u64, answer: &dyn Fn(&Value) -> Value| {
        request(core, id, Some(SITE), Some(false), &hello_sign());
        let asked = next_request(core);
        assert_eq!(asked["method"], "approval.request");
        respond(core, &asked, answer(&asked["params"]["prompt"]));
        let reply = core.until_response(id);
        assert_eq!(reply["error"]["code"], "not_authorized", "{reply}");
        assert_eq!(reply["error"]["data"]["reason"], "mismatch", "{reply}");
    };
    let used = "ab".repeat(32);
    crossed(&mut core, 10, &|_| {
        approve(&json!("00".repeat(16)), &"cd".repeat(32), json!({}))
    });
    crossed(&mut core, 11, &|p| {
        approve(p, &used, json!({ "alwaysAllow": "yes" }))
    });
    crossed(&mut core, 12, &|p| approve(p, &used, json!({})));
    crossed(&mut core, 13, &|p| {
        approve(p, &"ef".repeat(32), json!({ "other": 1 }))
    });
    assert_eq!(grant_file(&core), before);
    request(&mut core, 14, Some(SITE), Some(false), &hello_sign());
    let asked = next_request(&mut core);
    let p = asked["params"]["prompt"].clone();
    respond(
        &mut core,
        &asked,
        approve(&p, &"12".repeat(32), json!({ "alwaysAllow": false })),
    );
    assert_eq!(
        core.until_response(14)["result"],
        json!({ "result": HELLO_SIGNATURE })
    );
    assert_eq!(
        grant_file(&core),
        before,
        "\"Always allow\" unticked writes nothing"
    );
}

/// Approved with the vault locked: the core's refusal, nothing signed.
#[test]
fn a_locked_vault_signs_nothing() {
    let (_root, mut core) = core_with(&connected(0, false), true, false);
    request(&mut core, 30, Some(SITE), Some(false), &hello_sign());
    let asked = next_request(&mut core);
    let p = asked["params"]["prompt"].clone();
    respond(&mut core, &asked, approve(&p, &"34".repeat(32), json!({})));
    assert_eq!(
        core.until_response(30)["result"],
        json!({ "error": { "code": -32603, "message": "Vault is locked" } })
    );
}

/// "A decision crossed" with signatures (the row's case): two requests of
/// one document, both prompts open; the first answered with the second's
/// prompt id is refused, and the second's own approve signs it alone.
#[test]
fn a_decision_crossed_between_two_signatures() {
    let (_root, mut core) = core_with(&connected(0, false), true, true);
    request(&mut core, 40, Some(SITE), Some(false), &hello_sign());
    let first = next_request(&mut core);
    request(&mut core, 41, Some(SITE), Some(false), &hello_sign());
    let second = next_request(&mut core);
    let (p1, p2) = (
        first["params"]["prompt"].clone(),
        second["params"]["prompt"].clone(),
    );
    assert_ne!(p1, p2);
    respond(&mut core, &first, approve(&p2, &"56".repeat(32), json!({})));
    assert_eq!(
        core.until_response(40)["error"]["data"]["reason"],
        "mismatch"
    );
    respond(
        &mut core,
        &second,
        approve(&p2, &"78".repeat(32), json!({})),
    );
    assert_eq!(
        core.until_response(41)["result"],
        json!({ "result": HELLO_SIGNATURE })
    );
}

/// A grant whose `walletIndex` is no account index (a fraction, negative,
/// past `MAX_ACCOUNT`, not a number) signs nothing, though main's wallets
/// list it and the prompt shows it: the approve answers `Invalid wallet
/// index`, where a cast would have picked a vault key.
#[test]
fn an_index_that_is_no_account_signs_nothing() {
    let sites = [
        ("https://half.example", json!(0.5)),
        ("https://negative.example", json!(-1)),
        ("https://past.example", json!(2_147_483_648_u64)),
        ("https://text.example", json!("0")),
    ];
    let mut world = world();
    for (_, index) in &sites {
        world["wallets"].as_array_mut().unwrap().push(json!({
            "index": index, "name": "Odd", "type": "mnemonic",
            "address": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        }));
    }
    let (_root, mut core) = core_with(&grants(&sites), true, true);
    for (n, (site, index)) in sites.iter().enumerate() {
        let id = 60 + n as u64;
        let body = json!({ "method": "personal_sign", "params": ["0x68656c6c6f"], "world": world });
        request(&mut core, id, Some(site), Some(false), &body);
        let asked = next_request(&mut core);
        assert_eq!(asked["method"], "approval.request", "{index}: {asked}");
        let mut answer = approve(
            &asked["params"]["prompt"],
            &format!("{:02x}", 0x90 + n).repeat(32),
            json!({}),
        );
        answer["world"] = world.clone();
        respond(&mut core, &asked, answer);
        assert_eq!(
            core.until_response(id)["result"],
            json!({ "error": { "code": -32603, "message": "Invalid wallet index" } }),
            "{index}"
        );
    }
}

/// Typed data sent as text, valid but nested deeper than fc-json reads
/// (V8 reads it): `-32603` "Invalid parameters", before any prompt.
#[test]
fn typed_data_nested_past_fc_json_is_invalid_parameters() {
    let (_root, mut core) = core_with(&connected(0, false), true, false);
    let deep = format!("{}0{}", "[".repeat(600), "]".repeat(600));
    let body = json!({
        "method": "eth_signTypedData_v4",
        "params": ["0x9858EfFD232B4033E47d90003D41EC34EcaEda94", deep],
        "world": world(),
    });
    request(&mut core, 70, Some(SITE), Some(false), &body);
    assert_eq!(
        response(&mut core, 70)["result"],
        json!({ "error": { "code": -32603, "message": "Invalid parameters" } })
    );
}

/// APR-5d-2's scenarios: a rule answering, "Always allow", a Ledger.
const APR5D2: [&str; 10] = [
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
];

/// The vectors' wall clock, which every recorded time is.
const NOW: u64 = 1_763_000_000_000;

/// `rule-legacy`: the reference's signing rule, as Q9's limited rule given
/// at `granted`, with today's flag cleared, as the core writes it.
fn q9(mut grants: Value, granted: u64) -> Value {
    for entry in grants.as_object_mut().unwrap().values_mut() {
        let rules = &mut entry["autoApprove"];
        if rules["signing"] == true {
            rules["signing"] = json!(false);
            rules["limited"] = json!({ "signing": { "grantedAt": granted }, "transactions": [] });
        }
    }
    grants
}

/// A core as [`core_with`], with the wall clock at `wall` (rewritten
/// through the returned file) and its vault locked if `locked`.
fn core_at(grants: &Value, wall: u64, locked: bool) -> (tempfile::TempDir, Core, PathBuf) {
    let (root, data, locks) = dirs();
    let clock = root.path().join("wall");
    std::fs::write(&clock, wall.to_string()).unwrap();
    let env = [("FREEDOM_CORED_TEST_WALL_CLOCK", clock.to_str().unwrap())];
    let mut core = spawn_env("serve", &data, &locks, &[], &env);
    std::fs::create_dir_all(&core.grant_root).unwrap();
    let text = serde_json::to_string_pretty(grants).unwrap();
    std::fs::write(core.grant_root.join("dapp-permissions.json"), text).unwrap();
    core.grant_moved = vec!["dapp"];
    assert_eq!(core.hello_fragments()["result"]["protocol"], 2);
    let imported = core.call(
        2,
        "vault.import",
        json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(ABANDON) }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    if locked {
        let reply = core.call_shell(3, "vault.lock", json!({}));
        assert!(reply["result"].is_object(), "{reply}");
    }
    (root, core, clock)
}

/// The next message that isn't an event.
fn next_message(core: &mut Core) -> Value {
    loop {
        let message = core.recv();
        if message["type"] != "event" {
            return message;
        }
    }
}

fn unlock(core: &mut Core, id: u64) {
    let reply = core.call_shell(
        id,
        "vault.unlock",
        json!({ "password_b64": STANDARD.encode("testpass1") }),
    );
    assert!(reply["result"].is_object(), "{reply}");
}

/// The recheck main answers: `{ live, agent }`.
fn recheck(core: &mut Core, id: u64, live: bool, agent: bool) {
    let asked = next_message(core);
    assert_eq!(asked["method"], "approval.recheck", "{asked}");
    assert_eq!(asked["params"]["request"], id, "{asked}");
    respond(core, &asked, json!({ "live": live, "agent": agent }));
}

/// The typed-data view the core shows for a recorded one: fc-evm's own,
/// with the scripted reports, as the vault-prompt replay checks it.
fn shown_typed(file: &Value, expected: &mut Value, shown: &Value, typed: &Value) {
    assert_eq!(shown, &own_view(typed, 100));
    for report in ["named_type", "chain"] {
        assert_eq!(shown[report], expected["typedData"]["view"][report]);
    }
    expected["typedData"]["view"] = shown.clone();
    if !expected["chains"].as_object().unwrap().is_empty() {
        let mut chains = serde_json::Map::new();
        for id in [1, 100] {
            let name = &file["networks"][id.to_string()]["name"];
            chains.insert(id.to_string(), json!({ "name": name }));
        }
        expected["chains"] = Value::Object(chains);
    }
}

#[test]
fn every_apr5d2_scenario_replays_through_the_core() {
    let file = load();
    let (mut scenarios, mut requests, mut asked, mut ruled, mut devices) = (0, 0, 0, 0, 0);
    for scenario in file["scenarios"].as_array().unwrap() {
        let name = scenario["id"].as_str().unwrap();
        if !APR5D2.contains(&name) {
            continue;
        }
        assert_eq!(scenario["step"], "APR-5d", "{name}");
        scenarios += 1;
        let before = q9(scenario["grants"]["before"].clone(), NOW);
        let locked = scenario["world"]["vault"] == false;
        let (_root, mut core, _clock) = core_at(&before, NOW, locked);
        let world = world_of(&file, scenario);
        let agent = scenario["world"]["custody"].as_bool();
        assert_eq!(agent, Some(false), "{name}");
        let mut expected_after = before.clone();
        for (i, recorded) in scenario["requests"].as_array().unwrap().iter().enumerate() {
            requests += 1;
            let what = format!("{name} #{i} {}", recorded["method"]);
            let id = 100 + u64::try_from(i).unwrap();
            let mut body = json!({ "method": recorded["method"], "world": world });
            if let Some(p) = recorded.get("params") {
                body["params"] = p.clone();
            }
            let effects = recorded["effects"].as_array().unwrap();
            // A view the vectors script as `match` for typed data whose
            // domain names chain 1 (`sign-rule-answers`): the core's own
            // view matches it with the window on chain 1, and the signature
            // doesn't depend on the page's chain.
            if let Some(view) = effects
                .iter()
                .find(|e| e["effect"] == "core.typed_data_view")
            {
                let own = own_view(&body["params"][1], 100);
                if own["chain"] != view["answer"]["view"]["chain"] {
                    assert_eq!(view["answer"]["view"]["chain"], "match", "{what}");
                    assert_eq!(own_view(&body["params"][1], 1)["chain"], "match", "{what}");
                    body["world"]["window_chain"] = json!(1);
                }
            }
            request(&mut core, id, Some(SITE), agent, &body);
            let changes: Vec<&str> = effects
                .iter()
                .filter(|e| e["effect"] == "world")
                .map(|e| e["change"].as_str().unwrap())
                .collect();
            let prompt = effects.iter().find(|e| e["effect"] == "prompt");
            let signs = effects
                .iter()
                .any(|e| e["effect"] == "sign.message" || e["effect"] == "sign.typed_data");
            let mut expected = recorded["result"].clone();
            let message = match prompt {
                // The rule answers: no prompt, main's recheck, the signature.
                None => {
                    ruled += 1;
                    recheck(&mut core, id, true, false);
                    core.until_response(id)
                }
                Some(prompt) => {
                    asked += 1;
                    let ask = next_message(&mut core);
                    assert_eq!(ask["method"], "approval.request", "{what}: {ask}");
                    let params = &ask["params"];
                    assert_eq!(params["request"], id, "{what}");
                    let kind = prompt["args"]["kind"].as_str().unwrap();
                    assert_eq!(params["kind"], kind, "{what}");
                    let mut view = prompt["args"]["view"].clone();
                    if view.get("typedData").is_some() {
                        shown_typed(
                            &file,
                            &mut view,
                            &params["view"]["typedData"]["view"],
                            &body["params"][1],
                        );
                    }
                    assert_eq!(params["view"].to_string(), view.to_string(), "{what}");
                    let device = view["account"]["type"] == "ledger";
                    let choices = match (kind, device) {
                        ("vault.unlock", _) => json!({}),
                        (_, true) => json!({ "alwaysAllow": [false] }),
                        _ => json!({ "alwaysAllow": [false, true] }),
                    };
                    assert_eq!(params["choices"], choices, "{what}");
                    // Main's world as it answers.
                    for change in &changes {
                        match *change {
                            "vault-unlocked" => unlock(&mut core, id + 50),
                            "signing-rule-off" => {
                                let off = core.call_shell(
                                    id + 60,
                                    "approval.revoke",
                                    json!({ "store": "dapp", "key": SITE, "what": "signing" }),
                                );
                                assert!(off.get("result").is_some(), "{off}");
                                let rules = &mut expected_after[SITE]["autoApprove"];
                                rules["limited"]["signing"] = Value::Null;
                            }
                            "custody-entered" => {}
                            other => panic!("{what}: {other}"),
                        }
                    }
                    // The vault locked as the signature is made.
                    let throws = effects
                        .iter()
                        .find(|e| e["effect"] == "sign.message")
                        .and_then(|e| e.get("throws"));
                    if !device && throws.is_some() {
                        let reply = core.call_shell(id + 70, "vault.lock", json!({}));
                        assert!(reply["result"].is_object(), "{reply}");
                        // The core's own words for it; the reference's
                        // signer was scripted to throw this message.
                        assert_eq!(expected["error"]["message"], "The vault is locked");
                        expected["error"]["message"] = json!("Vault is locked");
                    }
                    let handle = format!("{:064x}", ask["id"].as_u64().unwrap());
                    let answer = answer_of(&params["prompt"], &handle, &prompt["answer"], &world);
                    respond(&mut core, &ask, answer);
                    let unlocked = kind == "vault.unlock" && prompt["answer"]["approve"] == true;
                    if unlocked {
                        recheck(&mut core, id, true, changes.contains(&"custody-entered"));
                    }
                    let reply = core.until_response(id);
                    if device && prompt["answer"]["approve"] == true {
                        devices += 1;
                        let device = &reply["result"]["device"];
                        let issue = effects
                            .iter()
                            .find(|e| e["effect"] == "token.issue")
                            .unwrap();
                        assert_eq!(device["type"], "ledger", "{what}: {reply}");
                        assert_eq!(device["kind"], issue["args"]["kind"], "{what}");
                        assert_eq!(device["account"], issue["args"]["account"], "{what}");
                        let payload = json!({ "message": issue["args"]["payload"] });
                        assert_eq!(device["payload"], payload, "{what}");
                        assert_eq!(device["handle"], handle.as_str(), "{what}");
                        // Main spends it for the device, as the reference
                        // spent `token-1`, under the page and its handle,
                        // with the reference's payload.
                        let spent = spend(
                            &mut core,
                            id + 80,
                            SITE,
                            &device["token"],
                            issue["args"]["kind"].as_str().unwrap(),
                            issue["args"]["account"].as_u64().unwrap(),
                            &payload,
                            &handle,
                        );
                        assert_eq!(spent["result"]["bound"], true, "{what}: {spent}");
                        // What main answers once the device has: the
                        // reference's result.
                        continue;
                    }
                    reply
                }
            };
            if signs && prompt.is_some_and(|p| p["answer"]["choices"]["alwaysAllow"] == true) {
                let ok = expected.get("result").is_some();
                if ok {
                    let rules = &mut expected_after[SITE]["autoApprove"];
                    rules["signing"] = json!(false);
                    rules["limited"] =
                        json!({ "signing": { "grantedAt": NOW }, "transactions": [] });
                }
            }
            assert_eq!(
                message["result"].to_string(),
                expected.to_string(),
                "{what}: {message}"
            );
        }
        assert_eq!(grant_file(&core), expected_after, "{name}");
    }
    assert_eq!(
        (scenarios, requests, asked, ruled, devices),
        (10, 12, 10, 2, 2)
    );
}

/// A site connected with `account` on Gnosis and Q9's signing rule given
/// at `granted` (none for `None`), or today's unlimited one if `today`.
fn ruled(site: &str, account: u64, granted: Option<u64>, today: bool) -> (String, Value) {
    let mut rules = json!({ "signing": today, "transactions": [] });
    if let Some(granted) = granted {
        rules["limited"] = json!({ "signing": { "grantedAt": granted }, "transactions": [] });
    }
    let entry = json!({
        "origin": site, "connectedAt": NOW, "lastUsed": NOW,
        "walletIndex": account, "chainId": 100, "autoApprove": rules,
    });
    (site.to_owned(), entry)
}

fn store(entries: Vec<(String, Value)>) -> Value {
    Value::Object(entries.into_iter().collect())
}

fn sign_from(core: &mut Core, id: u64, site: &str, agent: Option<bool>) {
    request(core, id, Some(site), agent, &hello_sign());
}

/// The next message is main's prompt for request `id`: its params.
fn prompted(core: &mut Core, id: u64) -> Value {
    let asked = next_message(core);
    assert_eq!(asked["method"], "approval.request", "{asked}");
    assert_eq!(asked["params"]["request"], id, "{asked}");
    asked
}

/// The rule answers request `id`: main's recheck, then the signature.
fn rule_signs(core: &mut Core, id: u64) {
    recheck(core, id, true, false);
    assert_eq!(
        core.until_response(id)["result"],
        json!({ "result": HELLO_SIGNATURE }),
        "{id}"
    );
}

/// The typed data `sign-typed-approved` sends, as text, and the hash the
/// reference showed for it: what a device's typed-data token must bind.
fn reference_typed(file: &Value) -> (Value, String) {
    let scenarios = file["scenarios"].as_array().unwrap();
    let scenario = scenarios
        .iter()
        .find(|s| s["id"] == "sign-typed-approved")
        .unwrap();
    let request = &scenario["requests"][0];
    let prompt = request["effects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["effect"] == "prompt")
        .unwrap();
    let hash = prompt["args"]["view"]["typedData"]["hash"]
        .as_str()
        .unwrap();
    (request["params"][1].clone(), hash.to_owned())
}

/// A typed-data token's payload, built from the page's typed data alone
/// as `toCoreTypedData` reads it: the domain, the types but
/// `EIP712Domain`, the message, the `primaryType`, and the page's chain.
fn core_payload(typed: &Value, chain_id: u64) -> Value {
    let typed: Value = match typed {
        Value::String(text) => serde_json::from_str(text).unwrap(),
        other => other.clone(),
    };
    let mut types = typed["types"].clone();
    types.as_object_mut().unwrap().remove("EIP712Domain");
    json!({
        "typed_data": { "domain": typed["domain"], "types": types, "message": typed["message"] },
        "primary_type": typed["primaryType"],
        "chain_id": chain_id.to_string(),
    })
}

/// Request `id` from `site`, approved on its prompt under `handle`: the
/// `{ device }` it answers.
fn device_approved(core: &mut Core, id: u64, site: &str, body: &Value, handle: &str) -> Value {
    request(core, id, Some(site), Some(false), body);
    let asked = prompted(core, id);
    assert_eq!(asked["params"]["kind"], "eth.sign", "{site}: {asked}");
    respond(
        core,
        &asked,
        approve(&asked["params"]["prompt"], handle, json!({})),
    );
    let reply = core.until_response(id);
    let answer = reply["result"].as_object().unwrap();
    assert_eq!(answer.len(), 1, "{site}: {reply}");
    answer["device"].clone()
}

/// No Ledger, phone or Safe account reaches the vault, though the vault is
/// unlocked holding keys at those indices, the Safe is on Gnosis, and each
/// site has Q9's signing rule: no rule answers a device's account, its
/// prompt offers "Always allow" unticked only, and an approve returns
/// `{ device }` with nothing signed. For a message and for typed data,
/// each token binds what the page's request alone says: the payload in
/// the core's form and the hash the reference shows (a Safe's: the Safe,
/// Gnosis, the method and the params as sent), the account, the page and
/// the handle. A fresh token under another handle binds nothing (and is
/// burnt); a separate one, presented as the request and its handle say,
/// binds once.
#[test]
fn no_device_account_reaches_the_vault() {
    const SAFE: &str = "0x4444444444444444444444444444444444444444";
    let (typed, hash) = reference_typed(&load());
    let typed_object: Value = serde_json::from_str(typed.as_str().unwrap()).unwrap();
    let sites = [
        (
            "https://ledger.example",
            1,
            "ledger",
            "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0",
            typed.clone(),
        ),
        (
            "https://phone.example",
            2,
            "remote",
            "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A",
            typed_object,
        ),
        ("https://safe.example", 1000, "safe", SAFE, typed.clone()),
    ];
    let entries = sites
        .iter()
        .map(|(site, index, ..)| ruled(site, *index, Some(NOW), false))
        .collect();
    let (_root, mut core, _clock) = core_at(&store(entries), NOW, false);
    let before = grant_file(&core);
    let mut id = 50;
    let mut handles = (0x10_u8..).map(|n| format!("{n:02x}").repeat(32));
    for (site, index, kind, address, typed) in &sites {
        // "Always allow" ticked is a pick not offered: crossed.
        sign_from(&mut core, id, site, Some(false));
        let asked = prompted(&mut core, id);
        assert_eq!(asked["params"]["kind"], "eth.sign");
        assert_eq!(asked["params"]["view"]["account"]["type"], *kind);
        assert_eq!(
            asked["params"]["choices"],
            json!({ "alwaysAllow": [false] })
        );
        let ticked = approve(
            &asked["params"]["prompt"],
            &handles.next().unwrap(),
            json!({ "alwaysAllow": true }),
        );
        respond(&mut core, &asked, ticked);
        let reply = core.until_response(id);
        assert_eq!(
            reply["error"]["data"]["reason"], "mismatch",
            "{site}: {reply}"
        );
        id += 1;
        let typed_body = json!({
            "method": "eth_signTypedData_v4", "params": [address, typed], "world": world(),
        });
        for body in [hello_sign(), typed_body] {
            let method = body["method"].as_str().unwrap();
            let what = format!("{site} {method}");
            // What the token must bind, from the page's request alone.
            let (token_kind, payload, expected_hash) = match (*kind, method) {
                ("safe", _) => (
                    "safe-message",
                    json!({ "safe": SAFE, "chain_id": "100", "method": method, "params": body["params"] }),
                    None,
                ),
                (_, "personal_sign") => {
                    ("sign-message", json!({ "message": "0x68656c6c6f" }), None)
                }
                _ => (
                    "sign-typed-data",
                    core_payload(&body["params"][1], 100),
                    Some(hash.as_str()),
                ),
            };
            // Two approves, each minting its own token.
            let (handle1, handle2) = (handles.next().unwrap(), handles.next().unwrap());
            let first = device_approved(&mut core, id, site, &body, &handle1);
            let second = device_approved(&mut core, id + 1, site, &body, &handle2);
            for (device, handle) in [(&first, &handle1), (&second, &handle2)] {
                let fields = device.as_object().unwrap();
                assert_eq!(
                    fields.len(),
                    6 + usize::from(expected_hash.is_some()),
                    "{what}: {device}"
                );
                assert_eq!(device["type"], *kind, "{what}");
                assert_eq!(device["kind"], token_kind, "{what}");
                assert_eq!(device["account"], *index, "{what}");
                assert_eq!(device["payload"], payload, "{what}");
                assert_eq!(
                    device.get("expected_hash").map(|h| h.as_str().unwrap()),
                    expected_hash,
                    "{what}"
                );
                assert_eq!(device["handle"], handle.as_str(), "{what}");
                let token = device["token"].as_str().unwrap();
                assert!(
                    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()),
                    "{what}"
                );
            }
            assert_ne!(first["token"], second["token"], "{what}");
            // The first, never presented before, under another handle:
            // it binds nothing, and is burnt.
            let spend_first = |core: &mut Core, id: u64, handle: &str| {
                spend(
                    core,
                    id,
                    site,
                    &first["token"],
                    token_kind,
                    *index,
                    &payload,
                    handle,
                )
            };
            let other = spend_first(&mut core, id + 2, &"cd".repeat(32));
            assert_eq!(
                other["error"]["data"]["reason"], "mismatch",
                "{what}: {other}"
            );
            let burnt = spend_first(&mut core, id + 3, &handle1);
            assert_eq!(
                burnt["error"]["data"]["reason"], "unknown_token",
                "{what}: {burnt}"
            );
            // The second, as the page's request and its handle say: bound,
            // once.
            let spend_second = |core: &mut Core, id: u64| {
                spend(
                    core,
                    id,
                    site,
                    &second["token"],
                    token_kind,
                    *index,
                    &payload,
                    &handle2,
                )
            };
            let spent = spend_second(&mut core, id + 4);
            assert_eq!(spent["result"]["bound"], true, "{what}: {spent}");
            let again = spend_second(&mut core, id + 5);
            assert_eq!(
                again["error"]["data"]["reason"], "unknown_token",
                "{what}: {again}"
            );
            id += 10;
        }
    }
    assert_eq!(grant_file(&core), before);
}

/// Main's `approval.spend` of a page-kind token for `site`.
#[allow(clippy::too_many_arguments)]
fn spend(
    core: &mut Core,
    id: u64,
    site: &str,
    token: &Value,
    kind: &str,
    account: u64,
    payload: &Value,
    handle: &str,
) -> Value {
    core.send(&json!({
        "type": "request", "id": id, "method": "approval.spend",
        "params": {
            "token": token, "kind": kind, "account": account,
            "payload": payload, "handle": handle,
        },
        "context": page(Some(site), Some(false)),
    }));
    core.until_response(id)
}

/// A rule's request is rechecked just before its effect: a tab gone into
/// custody, or the document gone, refuses it with nothing signed and the
/// key's last use unmarked. In custody when it came (or with custody
/// unknown) no rule answers it: the user is asked.
#[test]
fn a_rule_refuses_in_custody_or_with_its_document_gone() {
    let (_root, mut core, clock) =
        core_at(&store(vec![ruled(SITE, 0, Some(NOW), false)]), NOW, false);
    std::fs::write(&clock, (NOW + 1000).to_string()).unwrap();
    let before = grant_file(&core);
    let custody = json!({ "error": { "code": 4100, "message": "The origin is not authorized for this operation", "data": { "reason": "agent_custody" } } });
    sign_from(&mut core, 10, SITE, Some(false));
    recheck(&mut core, 10, true, true);
    assert_eq!(core.until_response(10)["result"], custody);
    sign_from(&mut core, 11, SITE, Some(false));
    recheck(&mut core, 11, false, false);
    assert_eq!(
        core.until_response(11)["result"],
        json!({ "error": { "code": 4100, "message": "This page has no address to connect from yet" } })
    );
    assert_eq!(grant_file(&core), before, "nothing marked");
    for (id, agent) in [(12, Some(true)), (13, None)] {
        sign_from(&mut core, id, SITE, agent);
        let asked = prompted(&mut core, id);
        assert_eq!(asked["params"]["kind"], "eth.sign");
        respond(
            &mut core,
            &asked,
            json!({ "prompt": asked["params"]["prompt"], "closed": "closed" }),
        );
        assert_eq!(core.until_response(id)["result"]["error"]["code"], 4001);
    }
    // Live and outside custody: signed, and the last use marked.
    sign_from(&mut core, 14, SITE, Some(false));
    rule_signs(&mut core, 14);
    assert_eq!(grant_file(&core)[SITE]["lastUsed"], NOW + 1000);
}

/// The unlock a rule's request asks for while the vault is locked, in each
/// form main answers it (Inferred 5): rejected or closed, `4001` "User
/// cancelled unlock"; busy, `-32002`, the busy answer and not the cancel;
/// a pick on the approve, crossed (`mismatch`). Approved with the vault
/// still locked, the recheck comes and the vault refuses the signature:
/// nothing signed, the last use unmarked. Once unlocked, the rule signs
/// and marks it.
#[test]
fn every_unlock_answer_through_a_rule() {
    let (_root, mut core, clock) =
        core_at(&store(vec![ruled(SITE, 0, Some(NOW), false)]), NOW, true);
    std::fs::write(&clock, (NOW + 1000).to_string()).unwrap();
    let before = grant_file(&core);
    let unlock_asked = |core: &mut Core, id: u64| {
        sign_from(core, id, SITE, Some(false));
        let asked = prompted(core, id);
        let params = &asked["params"];
        assert_eq!(params["kind"], "vault.unlock", "{asked}");
        let view = json!({ "account": world()["wallets"][0], "reason": "sign" });
        assert_eq!(params["view"], view, "{asked}");
        assert_eq!(params["choices"], json!({}), "{asked}");
        asked
    };
    let cancelled = json!({ "error": { "code": 4001, "message": "User cancelled unlock" } });
    let busy = json!({ "error": { "code": -32002, "message": "Another wallet request is already pending" } });
    let answers = [
        (
            10,
            json!({ "handle": "a1".repeat(32), "approve": false, "choices": {} }),
            &cancelled,
        ),
        (11, json!({ "closed": "closed" }), &cancelled),
        (12, json!({ "busy": true }), &busy),
    ];
    for (id, mut answer, expected) in answers {
        let asked = unlock_asked(&mut core, id);
        answer["prompt"] = asked["params"]["prompt"].clone();
        respond(&mut core, &asked, answer);
        assert_eq!(core.until_response(id)["result"], *expected, "{id}");
    }
    // A pick on the unlock's approve: crossed, with nothing asked after it.
    let asked = unlock_asked(&mut core, 13);
    let picked = approve(
        &asked["params"]["prompt"],
        &"a2".repeat(32),
        json!({ "alwaysAllow": false }),
    );
    respond(&mut core, &asked, picked);
    let reply = next_message(&mut core);
    assert_eq!(reply["type"], "response", "{reply}");
    assert_eq!(reply["error"]["data"]["reason"], "mismatch", "{reply}");
    // Approved with the vault still locked: the recheck, then the vault's
    // refusal.
    let asked = unlock_asked(&mut core, 14);
    respond(
        &mut core,
        &asked,
        approve(&asked["params"]["prompt"], &"a3".repeat(32), json!({})),
    );
    recheck(&mut core, 14, true, false);
    assert_eq!(
        core.until_response(14)["result"],
        json!({ "error": { "code": -32603, "message": "Vault is locked" } })
    );
    assert_eq!(grant_file(&core), before, "nothing signed or marked");
    // Unlocked: the rule signs, and marks the last use.
    unlock(&mut core, 90);
    sign_from(&mut core, 95, SITE, Some(false));
    rule_signs(&mut core, 95);
    assert_eq!(grant_file(&core)[SITE]["lastUsed"], NOW + 1000);
}

/// Q9 through the dispatcher: a request only today's unlimited rule, an
/// expired rule or a rule past its rate would answer opens a prompt, never
/// a refusal, and one approved there isn't counted; an "Always allow" in
/// its answer writes the limited rule and clears today's in one write.
#[test]
fn q9_through_the_dispatcher() {
    const DAY: u64 = 86_400_000;
    let expired = NOW - 30 * DAY;
    let entries = vec![
        ruled("https://today.example", 0, None, true),
        ruled("https://expired.example", 0, Some(expired), false),
        ruled(SITE, 0, Some(expired + 1), false),
    ];
    let (_root, mut core, _clock) = core_at(&store(entries), NOW, false);
    let mut id = 10;
    for site in ["https://today.example", "https://expired.example"] {
        sign_from(&mut core, id, site, Some(false));
        let asked = prompted(&mut core, id);
        assert_eq!(asked["params"]["kind"], "eth.sign", "{site}");
        respond(
            &mut core,
            &asked,
            json!({ "prompt": asked["params"]["prompt"], "closed": "closed" }),
        );
        assert_eq!(core.until_response(id)["result"]["error"]["code"], 4001);
        id += 1;
    }
    // A burst of 5 the rule answers; the 6th is asked, and approved there
    // it signs uncounted, so the 7th is asked too.
    for _ in 0..5 {
        sign_from(&mut core, id, SITE, Some(false));
        rule_signs(&mut core, id);
        id += 1;
    }
    for n in 0..2 {
        sign_from(&mut core, id, SITE, Some(false));
        let asked = prompted(&mut core, id);
        let handle = format!("{:02x}", 0xc0 + n).repeat(32);
        respond(
            &mut core,
            &asked,
            approve(&asked["params"]["prompt"], &handle, json!({})),
        );
        assert_eq!(
            core.until_response(id)["result"],
            json!({ "result": HELLO_SIGNATURE })
        );
        id += 1;
    }
    // "Always allow" for today's rule: the limited rule, today's cleared,
    // in one write and one `approval.changed`; then the rule answers.
    core.events();
    sign_from(&mut core, id, "https://today.example", Some(false));
    let asked = prompted(&mut core, id);
    let ticked = approve(
        &asked["params"]["prompt"],
        &"d1".repeat(32),
        json!({ "alwaysAllow": true }),
    );
    respond(&mut core, &asked, ticked);
    assert_eq!(
        core.until_response(id)["result"],
        json!({ "result": HELLO_SIGNATURE })
    );
    let rules = &grant_file(&core)["https://today.example"]["autoApprove"];
    assert_eq!(
        *rules,
        json!({ "signing": false, "transactions": [], "limited": { "signing": { "grantedAt": NOW }, "transactions": [] } })
    );
    let changed = core.event();
    assert_eq!(changed["event"], "approval.changed", "{changed}");
    id += 1;
    sign_from(&mut core, id, "https://today.example", Some(false));
    rule_signs(&mut core, id);
}

/// The rate judged again at the effect: six requests the rule would
/// answer, all waiting on main's rechecks at once, each chosen while none
/// was counted. Five sign; the sixth, past the rate by its effect, is
/// asked of the user (Q9: never a refusal).
#[test]
fn a_rule_past_its_rate_at_the_effect_asks() {
    let (_root, mut core, _clock) =
        core_at(&store(vec![ruled(SITE, 0, Some(NOW), false)]), NOW, false);
    let mut rechecks = Vec::new();
    for id in 20..26 {
        sign_from(&mut core, id, SITE, Some(false));
        let asked = next_message(&mut core);
        assert_eq!(asked["method"], "approval.recheck", "{asked}");
        rechecks.push(asked);
    }
    for (asked, id) in rechecks.iter().zip(20..) {
        respond(&mut core, asked, json!({ "live": true, "agent": false }));
        if id < 25 {
            assert_eq!(
                core.until_response(id)["result"],
                json!({ "result": HELLO_SIGNATURE })
            );
        }
    }
    let asked = prompted(&mut core, 25);
    assert_eq!(asked["params"]["kind"], "eth.sign");
    respond(
        &mut core,
        &asked,
        approve(&asked["params"]["prompt"], &"e1".repeat(32), json!({})),
    );
    assert_eq!(
        core.until_response(25)["result"],
        json!({ "result": HELLO_SIGNATURE })
    );
}
