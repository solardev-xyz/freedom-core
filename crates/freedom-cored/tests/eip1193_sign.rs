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
//! params; nothing is signed on a crossed answer; "Always allow" isn't
//! offered yet; a rule's or a device's request is APR-5d-2's, and no
//! Ledger, phone or Safe account reaches the vault; a grant index that is
//! no account signs nothing; typed data nested past fc-json is `Invalid
//! parameters`; and a locked vault signs nothing.

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
                    assert_eq!(
                        params["choices"],
                        json!({ "alwaysAllow": [false] }),
                        "{what}"
                    );
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
/// earlier answer named, or a pick not offered ("Always allow", until
/// APR-5d-2). Each fails its request with `mismatch`; the grant is
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
        approve(p, &used, json!({ "alwaysAllow": true }))
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

/// A request the site's rule would answer outside custody, and a device's,
/// are APR-5d-2's: `4200`, nothing asked. In custody (or with custody
/// unknown) the rule doesn't answer, and the user is asked.
#[test]
fn a_rule_or_a_device_is_apr5d2s() {
    let unsupported = json!({ "error": { "code": 4200, "message": "Method not supported" } });
    let (_root, mut core) = core_with(&connected(0, true), true, false);
    request(&mut core, 20, Some(SITE), Some(false), &hello_sign());
    assert_eq!(response(&mut core, 20)["result"], unsupported);
    for (id, agent) in [(21, Some(true)), (22, None)] {
        request(&mut core, id, Some(SITE), agent, &hello_sign());
        let asked = next_request(&mut core);
        assert_eq!(asked["method"], "approval.request", "{asked}");
        respond(
            &mut core,
            &asked,
            json!({ "prompt": asked["params"]["prompt"], "closed": "closed" }),
        );
        assert_eq!(core.until_response(id)["result"]["error"]["code"], 4001);
    }
    let (_root, mut core) = core_with(&connected(1, false), true, false);
    request(&mut core, 23, Some(SITE), Some(false), &hello_sign());
    assert_eq!(response(&mut core, 23)["result"], unsupported);
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

/// A Ledger's, a phone's or a Safe's account never reaches the vault, the
/// Safe on Gnosis (where it may sign) and the vault unlocked, holding keys
/// at those indices: `4200`, and no `approval.request` (the very next
/// message is the answer), so nothing to approve and nothing signed.
#[test]
fn no_device_account_reaches_the_vault() {
    let unsupported = json!({ "error": { "code": 4200, "message": "Method not supported" } });
    let sites = [
        ("https://ledger.example", json!(1)),
        ("https://phone.example", json!(2)),
        ("https://safe.example", json!(1000)),
    ];
    let (_root, mut core) = core_with(&grants(&sites), true, true);
    let before = grant_file(&core);
    for (id, (site, _)) in (50..).zip(&sites) {
        request(&mut core, id, Some(site), Some(false), &hello_sign());
        assert_eq!(response(&mut core, id)["result"], unsupported, "{site}");
    }
    assert_eq!(grant_file(&core), before);
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
