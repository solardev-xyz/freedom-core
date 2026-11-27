//! SAFE-3's field through the real binary (design 0016, C1): main's
//! `core.hello` declares `safe3`, and a site's `eth_sendTransaction` for a
//! Safe account reads the Safe's eight setup reads (each from both
//! endpoints, the nonce last) before its prompt, which shows the whole
//! SafeTx and its hash; the approve answers `{ device }` with design 0016's
//! `safe-send` for the page and the handle, which `safe.propose` under
//! `page` spends for that SafeTx only, on that page and with that handle,
//! once. A refusal of the reads answers the page before any prompt. Under
//! the field `approval.issue` refuses `executor-send`, `sign.transaction`
//! under `shell` a Safe's deployment without its token, and the board's
//! states say whether an entry is the core's proposal. Without the field
//! the same send answers as before. The test plays main and Gnosis, with
//! `vectors/safe.json`'s `one-of-two` flow.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::*;
use fc_evm::{U256, keccak256, to_hex};
use fc_safe::constants::{FALLBACK_HANDLER, PROXY_FACTORY, SENTINEL, SINGLETON};
use serde_json::{Value, json};

const SITE: &str = "https://app.example";
const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// The Safe's wallet index: the first hardware index.
const SAFE: u64 = 1_000_000;
/// `safe_unverified`'s text (design 0016, "Chain reads").
const UNVERIFIED: &str = "Freedom couldn't verify this Safe on Gnosis, so it won't sign. Try \
     again, or add an RPC provider in Settings.";

fn flow() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/safe.json");
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let flow = vectors["flows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|flow| flow["id"] == "one-of-two")
        .unwrap()
        .clone();
    let mut flow = flow;
    flow["owners"] = json!([
        vectors["owners"]["A"]["address"],
        vectors["owners"]["B"]["address"]
    ]);
    flow
}

/// The flow's SafeTx entry, as the reference writes it after its start.
fn pending(flow: &Value) -> Value {
    flow["steps"][0]["pending"].clone()
}

fn owners(flow: &Value) -> Vec<[u8; 20]> {
    flow["owners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|owner| fc_evm::parse_address(owner.as_str().unwrap()).unwrap())
        .collect()
}

fn page_of(frame: u64, navigation: u64) -> Value {
    json!({ "caller": "page", "page": {
        "origin": SITE, "top_origin": SITE, "frame": frame, "navigation": navigation,
        "agent": false,
    } })
}

fn page() -> Value {
    page_of(1, 1)
}

fn send(core: &mut Core, id: u64, context: Value, method: &str, params: Value) {
    core.send(&json!({
        "type": "request", "id": id, "method": method, "params": params, "context": context,
    }));
}

fn shell(core: &mut Core, id: u64, method: &str, params: Value) -> Value {
    core.call_shell(id, method, params)
}

/// How the test's Gnosis is configured.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Gnosis {
    /// Two endpoints in a quorum of two: every read verified.
    Quorum,
    /// One endpoint, Direct: no read is evidence.
    Direct,
}

/// A core for the flow: the vault imported, a second account and the
/// flow's Safe added through the core's `accounts.*`, marked deployed when
/// `marked`; the site connected to the Safe; Gnosis as `gnosis`; and the
/// hello's `safe3` as `safe3`.
fn start(safe3: bool, gnosis: Gnosis, marked: bool) -> (tempfile::TempDir, Core, Value) {
    let flow = flow();
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("identity")).unwrap();
    let mut core = spawn(
        "serve",
        &root.path().join("identity"),
        &root.path().join("locks"),
        &[],
    );
    std::fs::create_dir_all(&core.grant_root).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let grants = json!({ SITE: {
        "origin": SITE, "connectedAt": now, "lastUsed": now, "walletIndex": SAFE, "chainId": 100,
        "autoApprove": { "signing": false, "transactions": [] },
    } });
    std::fs::write(
        core.grant_root.join("dapp-permissions.json"),
        grants.to_string(),
    )
    .unwrap();
    let mut hello = json!({
        "protocol": 2, "shell_version": "test", "auto_lock_ms": 900_000,
        "frames": ["stream"], "grant_root": core.grant_root,
        "grant_moved": ["dapp"], "store_moved": ["vault_meta", "safe_pending"],
    });
    if safe3 {
        hello["safe3"] = json!(true);
    }
    let answered = shell(&mut core, 1, "core.hello", hello);
    // The field taken is echoed; without it, the answer is as before.
    let echoed = answered["result"].get("safe3").cloned();
    assert_eq!(echoed, safe3.then(|| json!(true)), "{answered}");
    let imported = shell(
        &mut core,
        2,
        "vault.import",
        json!({
            "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(ABANDON),
            "overwrite": true, "user_knows_password": true,
        }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    let second = shell(
        &mut core,
        3,
        "accounts.add_mnemonic",
        json!({ "name": "B" }),
    );
    assert_eq!(second["result"]["wallet"]["address"], flow["owners"][1]);
    let added = shell(
        &mut core,
        4,
        "accounts.add_safe",
        json!({ "address": flow["safe"]["address"], "owners": [0, 1], "threshold": 1,
                "salt_nonce": "0", "name": "Team Safe" }),
    );
    assert_eq!(added["result"]["wallet"]["index"], SAFE, "{added}");
    if marked {
        let reply = shell(
            &mut core,
            5,
            "accounts.mark_safe_deployed",
            json!({ "index": SAFE, "chain_id": 100 }),
        );
        assert!(reply["result"].is_object(), "{reply}");
    }
    let rpc = match gnosis {
        Gnosis::Quorum => json!([
            { "endpoint": "https://a.example", "user_configured": false },
            { "endpoint": "https://b.example", "user_configured": false },
        ]),
        Gnosis::Direct => json!([{ "endpoint": "https://a.example", "user_configured": false }]),
    };
    let read_order = match gnosis {
        Gnosis::Quorum => json!(["quorum", "direct"]),
        Gnosis::Direct => json!(["direct"]),
    };
    let chain = json!({
        "chain_id": 100, "display_name": "Gnosis Chain",
        "read_order": read_order, "broadcast_order": ["direct"],
        "quorum": { "k": 2, "m": 2, "timeout_ms": 5000 },
        "rpc": rpc, "prover": null, "myotis": false, "blockscout": null,
    });
    let configured = shell(
        &mut core,
        6,
        "chain.configure",
        json!({ "chains": [chain] }),
    );
    assert!(configured["result"].is_object(), "{configured}");
    (root, core, flow)
}

fn word(bytes: &[u8]) -> String {
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(bytes);
    to_hex(&word)
}

fn words(words: &[String]) -> Value {
    Value::String(format!(
        "0x{}",
        words
            .iter()
            .map(|w| w.trim_start_matches("0x").to_owned())
            .collect::<String>()
    ))
}

/// What Gnosis answers each read: the Safe of `owners`, 1 of 2, as Freedom
/// made it, at nonce 3.
fn answer(method: &str, params: &Value, owners: &[[u8; 20]]) -> Value {
    let data = params[0]["data"].as_str().unwrap_or("");
    let slot = params[1].as_str().unwrap_or("");
    let uint = |n: u64| word(&n.to_be_bytes());
    match method {
        "eth_getCode" => json!("0x6080604052"),
        "eth_getStorageAt" if slot == to_hex(&[0u8; 32]) => words(&[word(&SINGLETON)]),
        "eth_getStorageAt" if slot == to_hex(&fc_safe::reads::FALLBACK_HANDLER_SLOT) => {
            words(&[word(&FALLBACK_HANDLER)])
        }
        "eth_getStorageAt" => words(&[uint(0)]),
        "eth_call" if data == "0xa0e67e2b" => {
            let mut list = vec![uint(0x20), uint(owners.len() as u64)];
            list.extend(owners.iter().map(|owner| word(owner)));
            words(&list)
        }
        "eth_call" if data == "0xe75235b8" => words(&[uint(1)]),
        "eth_call" if data.starts_with("0xcc2f8452") => {
            words(&[uint(0x40), word(&SENTINEL), uint(0)])
        }
        "eth_call" if data == "0xaffed0e0" => words(&[uint(3)]),
        other => panic!("{other} {params}"),
    }
}

/// Plays main and Gnosis until request `id`'s response or a request to
/// main other than a read (a prompt): every `shell.rpc` answered alike by
/// each endpoint. What came, and the reads' methods, in order.
fn until_main(core: &mut Core, id: u64, owners: &[[u8; 20]]) -> (Value, Vec<String>) {
    let mut methods = Vec::new();
    loop {
        let message = core.recv();
        match (message["type"].as_str(), message["method"].as_str()) {
            (Some("event"), _) => {}
            (Some("request"), Some("shell.rpc")) => {
                let body: Value =
                    serde_json::from_str(message["params"]["body"].as_str().unwrap()).unwrap();
                let method = body["method"].as_str().unwrap();
                methods.push(method.to_owned());
                let text = json!({
                    "jsonrpc": "2.0", "id": body["id"],
                    "result": answer(method, &body["params"], owners),
                });
                core.send(&json!({
                    "type": "response", "id": message["id"],
                    "result": { "status": 200, "body": STANDARD.encode(text.to_string()) },
                }));
            }
            (Some("request"), _) => return (message, methods),
            (Some("response"), _) if message["id"] == id => return (message, methods),
            _ => panic!("unexpected {message}"),
        }
    }
}

/// The site's `eth_sendTransaction` of the flow's call, from `context`.
fn site_send(core: &mut Core, id: u64, flow: &Value, context: Value) {
    let value: u128 = flow["tx"]["value"].as_str().unwrap().parse().unwrap();
    let body = json!({
        "method": "eth_sendTransaction",
        "world": {
            "enabled": true, "chain": null, "window_chain": 100,
            "wallets": [{ "index": SAFE, "name": "Team Safe", "address": flow["safe"]["address"],
                          "type": "safe" }],
            "networks": { "100": { "name": "Gnosis", "available": true, "symbol": "xDAI" } },
        },
        "params": [{ "to": flow["tx"]["to"], "value": format!("{value:#x}"), "data": flow["tx"]["data"] }],
    });
    send(core, id, context, "eip1193.request", body);
}

/// The site's send asked and approved with `handle`: its prompt, the
/// reads before it, and the page's answer.
fn approved(core: &mut Core, id: u64, flow: &Value, handle: &str) -> (Value, Vec<String>, Value) {
    let owners = owners(flow);
    site_send(core, id, flow, page());
    let (asked, methods) = until_main(core, id, &owners);
    assert_eq!(asked["method"], "approval.request", "{asked}");
    let answer = json!({
        "prompt": asked["params"]["prompt"], "handle": handle, "approve": true,
        "choices": {}, "world": { "enabled": true, "chain": null, "window_chain": 100,
            "wallets": [], "networks": {} },
    });
    core.send(&json!({ "type": "response", "id": asked["id"], "result": answer }));
    let (done, more) = until_main(core, id, &owners);
    assert!(more.is_empty(), "{more:?}");
    (asked, methods, done)
}

/// `safe.propose` as main calls it on a `{ device }`'s `safe-send`, under
/// `context`, naming `hash` and presenting `token` with `handle`.
fn propose(
    core: &mut Core,
    id: u64,
    context: Value,
    hash: &Value,
    token: &Value,
    handle: &str,
) -> Value {
    send(
        core,
        id,
        context,
        "safe.propose",
        json!({ "safe": SAFE, "safe_tx_hash": hash,
                "authorization": { "token": token, "handle": handle } }),
    );
    let owners = owners(&flow());
    until_main(core, id, &owners).0
}

fn handle(n: u64) -> String {
    format!("{n:064x}")
}

/// Under the field the site's Safe send reads the eight setup reads before
/// its prompt, from both endpoints, the nonce last; the prompt shows the
/// SafeTx at that nonce whole, with its hash, beside the call, its executor
/// paying and "Always allow" unticked; the approve answers `{ device }`
/// with design 0016's `safe-send` for the Safe, Gnosis, that SafeTx and its
/// hash. `safe.propose` under `page` spends it only on the page and with
/// the handle it was minted for, and only for that SafeTx: another page,
/// another handle, or another SafeTx the page prepared itself is a
/// `mismatch`, the token burnt, so it never spends after. Spent as minted,
/// the vault owner signs and the entry is the core's proposal, as the
/// board's `proposed` says; an entry main's own path wrote isn't.
#[test]
fn a_site_safe_send_under_the_field_binds_the_safe_tx_it_showed() {
    let (_root, mut core, flow) = start(true, Gnosis::Quorum, true);
    let pending = pending(&flow);
    let (asked, methods, done) = approved(&mut core, 10, &flow, &handle(10));
    assert_eq!(methods.len(), 16, "{methods:?}");
    assert_eq!(methods[..2], ["eth_getCode"; 2]);
    assert_eq!(methods[14..], ["eth_call"; 2]);
    let view = &asked["params"]["view"];
    assert_eq!(asked["params"]["kind"], "eth.send");
    assert_eq!(view["safeTx"], pending["safeTxData"], "{asked}");
    assert_eq!(view["safeTx"]["nonce"], 3);
    assert_eq!(view["safeTxHash"], pending["safeTxHash"]);
    assert_eq!(view["tx"], flow["tx"]);
    assert_eq!(view["fee"], json!({ "paidBy": "executor" }));
    assert_eq!(view["alwaysAllow"], false);
    assert_eq!(
        asked["params"]["choices"],
        json!({ "alwaysAllow": [false], "feeAcknowledged": [false, true] })
    );
    let device = &done["result"]["device"];
    assert_eq!(device["type"], "safe", "{done}");
    assert_eq!(device["kind"], "safe-send");
    assert_eq!(device["account"], SAFE);
    assert_eq!(device["handle"], handle(10));
    assert_eq!(
        device["payload"],
        json!({ "safe": flow["safe"]["address"], "chain_id": "100",
                "safe_tx": pending["safeTxData"], "safe_tx_hash": pending["safeTxHash"] })
    );
    let hash = &device["payload"]["safe_tx_hash"];
    // Another page (a navigation later): refused, and burnt.
    let refused = propose(
        &mut core,
        11,
        page_of(1, 2),
        hash,
        &device["token"],
        &handle(10),
    );
    assert_eq!(refused["error"]["data"]["reason"], "mismatch", "{refused}");
    let refused = propose(&mut core, 12, page(), hash, &device["token"], &handle(10));
    assert_eq!(
        refused["error"]["data"]["reason"], "unknown_token",
        "{refused}"
    );
    // Another handle: refused, and burnt.
    let (_, _, done) = approved(&mut core, 20, &flow, &handle(20));
    let token = done["result"]["device"]["token"].clone();
    let refused = propose(&mut core, 21, page(), hash, &token, &handle(21));
    assert_eq!(refused["error"]["data"]["reason"], "mismatch", "{refused}");
    let refused = propose(&mut core, 22, page(), hash, &token, &handle(20));
    assert_eq!(
        refused["error"]["data"]["reason"], "unknown_token",
        "{refused}"
    );
    // Another SafeTx, which the page prepared itself: refused, and burnt.
    send(
        &mut core,
        30,
        page(),
        "safe.prepare",
        json!({ "safe": SAFE, "chain_id": 100,
                "tx": { "to": flow["tx"]["to"], "value": "1", "data": "0x" } }),
    );
    let (other, _) = until_main(&mut core, 30, &owners(&flow));
    let other_hash = other["result"]["safe_tx_hash"].clone();
    assert!(other_hash.is_string(), "{other}");
    assert_ne!(&other_hash, hash);
    let (_, _, done) = approved(&mut core, 31, &flow, &handle(31));
    let token = done["result"]["device"]["token"].clone();
    let refused = propose(&mut core, 32, page(), &other_hash, &token, &handle(31));
    assert_eq!(refused["error"]["data"]["reason"], "mismatch", "{refused}");
    let refused = propose(&mut core, 33, page(), hash, &token, &handle(31));
    assert_eq!(
        refused["error"]["data"]["reason"], "unknown_token",
        "{refused}"
    );
    // `approval.spend` spends none: D6's form is `safe.propose`'s alone.
    let (_, _, done) = approved(&mut core, 40, &flow, &handle(40));
    let device = done["result"]["device"].clone();
    send(
        &mut core,
        41,
        page(),
        "approval.spend",
        json!({ "token": device["token"], "kind": "safe-send", "account": SAFE,
                "payload": device["payload"], "handle": handle(40) }),
    );
    let refused = core.until_response(41);
    assert_eq!(refused["error"]["data"]["reason"], "mismatch", "{refused}");
    // As minted: the vault owner signs, and the entry is the core's.
    let (_, _, done) = approved(&mut core, 50, &flow, &handle(50));
    let token = done["result"]["device"]["token"].clone();
    let state = propose(&mut core, 51, page(), hash, &token, &handle(50));
    let state = &state["result"];
    assert_eq!(state["safeTxHash"], pending["safeTxHash"], "{state}");
    assert_eq!(state["collected"], 1);
    assert_eq!(state["proposed"], true);
    let file: Value = serde_json::from_str(
        &std::fs::read_to_string(core.grant_root.join("safe-pending.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        file[SAFE.to_string()]["coreProposal"]["safeTxHash"],
        pending["safeTxHash"]
    );
    let reply = core.call(52, "safe.pending", json!({}));
    assert_eq!(reply["result"]["states"][0]["proposed"], true, "{reply}");
    // An entry main's own path wrote has no mark: not the core's.
    let discarded = shell(&mut core, 53, "safe.discard", json!({ "safe": SAFE }));
    assert!(discarded["result"].is_object(), "{discarded}");
    let mut unmarked = pending.clone();
    unmarked["createdAt"] = json!(5);
    std::fs::write(
        core.grant_root.join("safe-pending.json"),
        json!({ SAFE.to_string(): unmarked }).to_string(),
    )
    .unwrap();
    let reply = core.call(54, "safe.pending", json!({}));
    assert_eq!(reply["result"]["states"][0]["proposed"], false, "{reply}");
}

/// Without the field the same send answers as before SAFE-3: its prompt
/// opens with no read, shows no SafeTx, and its approve answers `{ device }`
/// with APR-4's `safe-send` for the call, which `approval.spend` turns into
/// a Safe approval; the board's states carry no `proposed`.
#[test]
fn a_site_safe_send_without_the_field_answers_as_before() {
    let (_root, mut core, flow) = start(false, Gnosis::Quorum, true);
    let (asked, methods, done) = approved(&mut core, 10, &flow, &handle(10));
    assert!(methods.is_empty(), "{methods:?}");
    let view = asked["params"]["view"].as_object().unwrap();
    assert!(!view.contains_key("safeTx"), "{asked}");
    assert!(!view.contains_key("safeTxHash"));
    let device = &done["result"]["device"];
    assert_eq!(
        device["payload"],
        json!({ "safe": flow["safe"]["address"], "chain_id": "100", "tx": flow["tx"] }),
        "{done}"
    );
    send(
        &mut core,
        11,
        page(),
        "approval.spend",
        json!({ "token": device["token"], "kind": "safe-send", "account": SAFE,
                "payload": device["payload"], "handle": handle(10) }),
    );
    let spent = core.until_response(11);
    assert!(spent["result"]["safe"].is_string(), "{spent}");
    let mut entry = pending(&flow);
    entry["createdAt"] = json!(5);
    std::fs::write(
        core.grant_root.join("safe-pending.json"),
        json!({ SAFE.to_string(): entry }).to_string(),
    )
    .unwrap();
    let reply = core.call(12, "safe.pending", json!({}));
    let state = reply["result"]["states"][0].as_object().unwrap();
    assert!(!state.contains_key("proposed"), "{reply}");
}

/// Under the field a refusal of `safe.prepare`'s checks or reads answers
/// the page `-32603` with the core's text before any prompt: a Safe the
/// record doesn't mark deployed reads nothing; with one endpoint, no read
/// is evidence, and the code read ends the check.
#[test]
fn a_site_safe_send_the_core_refuses_opens_no_prompt() {
    let (_root, mut core, flow) = start(true, Gnosis::Quorum, false);
    site_send(&mut core, 10, &flow, page());
    let (done, methods) = until_main(&mut core, 10, &owners(&flow));
    assert!(methods.is_empty(), "{methods:?}");
    assert_eq!(
        done["result"],
        json!({ "error": { "code": -32603, "message": "Activate this account on Gnosis first." } }),
        "{done}"
    );
    let (_root, mut core, flow) = start(true, Gnosis::Direct, true);
    site_send(&mut core, 10, &flow, page());
    let (done, methods) = until_main(&mut core, 10, &owners(&flow));
    assert_eq!(methods, ["eth_getCode"], "{done}");
    assert_eq!(
        done["result"],
        json!({ "error": { "code": -32603, "message": UNVERIFIED } }),
        "{done}"
    );
}

/// Under the field `sign.transaction` under `shell` signs a Safe's
/// deployment, `createProxyWithNonce` to the pinned factory, only with its
/// `executor-send` token: main's word is refused `no_token` with nothing
/// signed, while another transaction still signs on it. `approval.issue`
/// mints no `executor-send` or APR-4 `safe-send`. Without the field main's
/// word signs the deployment, as before.
#[test]
fn a_deployment_under_shell_needs_its_token_under_the_field() {
    let setup =
        fc_safe::Setup::new(owners(&flow()).into_iter().collect::<Vec<[u8; 20]>>(), 1).unwrap();
    let deployment = setup.deployment(&U256::from_u64(0));
    assert_eq!(deployment.to, PROXY_FACTORY);
    assert_eq!(
        deployment.data[..4],
        keccak256(b"createProxyWithNonce(address,bytes,uint256)")[..4]
    );
    let tx = |to: &str| {
        json!({
            "type": 2, "chain_id": "100", "nonce": "0", "gas_limit": "300000", "to": to,
            "value": "0", "data": to_hex(&deployment.data),
            "max_fee_per_gas": "7000000000", "max_priority_fee_per_gas": "1000000000",
        })
    };
    let sign = |core: &mut Core, id: u64, to: &str| {
        shell(
            core,
            id,
            "sign.transaction",
            json!({ "key": { "kind": "account", "index": 0 }, "tx": tx(to) }),
        )
    };
    let factory = to_hex(&PROXY_FACTORY);
    let (_root, mut core, flow) = start(true, Gnosis::Quorum, false);
    let refused = sign(&mut core, 10, &factory);
    assert_eq!(refused["error"]["code"], "not_authorized", "{refused}");
    assert_eq!(refused["error"]["data"]["reason"], "no_token");
    let signed = sign(&mut core, 11, "0x58A57ed9d8d624cBD12e2C467D34787555bB1b25");
    assert!(signed["result"]["raw"].is_string(), "{signed}");
    for (id, kind, payload) in [
        (12, "executor-send", json!({ "tx": tx(&factory) })),
        (
            13,
            "safe-send",
            json!({ "safe": flow["safe"]["address"], "chain_id": "100", "tx": flow["tx"] }),
        ),
    ] {
        let mut payload = payload;
        if let Some(tx) = payload.get_mut("tx").and_then(Value::as_object_mut) {
            tx.remove("nonce");
        }
        let refused = shell(
            &mut core,
            id,
            "approval.issue",
            json!({ "kind": kind, "account": if kind == "safe-send" { SAFE } else { 0 },
                    "payload": payload, "fee_ack": true }),
        );
        assert_eq!(refused["error"]["code"], "forbidden", "{kind} {refused}");
    }
    let (_root, mut core, _) = start(false, Gnosis::Quorum, false);
    let signed = sign(&mut core, 10, &factory);
    assert!(signed["result"]["raw"].is_string(), "{signed}");
}
