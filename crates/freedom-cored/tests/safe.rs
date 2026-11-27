//! SAFE-2's S2 methods through the real binary (design 0016, API):
//! `safe.create` writes the record with no chain read; `safe.deployed`
//! marks a Safe deployed on a receipt two endpoints agree on, and
//! `safe.status` then reads its setup (no nonce), each read through the
//! core's own chain machine and main's `shell.rpc`; the callers each method
//! admits; `not_moved` before `vault_meta` is in `store_moved`. S3's
//! `safe.prepare` and `safe.propose`, and S4's `safe.execute`, whose
//! prepared send `sign.transaction` signs only as prepared, and
//! `safe.executed`. The test plays main.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;

use base64::Engine as _;
use common::*;
use fc_evm::{U256, checksum_address, keccak256, to_hex};
use fc_safe::Setup;
use fc_safe::constants::{FALLBACK_HANDLER, PROXY_FACTORY, SENTINEL, SINGLETON};
use serde_json::{Value, json};

const A: &str = "0x1111111111111111111111111111111111111111";
const B: &str = "0x2222222222222222222222222222222222222222";
const SAFE: u64 = 1_000_000;
const HASH: &str = "0xabababababababababababababababababababababababababababababababab";

fn setup() -> Setup {
    Setup::new(
        vec![
            fc_wallet_state::address_bytes(A).unwrap(),
            fc_wallet_state::address_bytes(B).unwrap(),
        ],
        1,
    )
    .unwrap()
}

fn safe_address() -> [u8; 20] {
    setup().address(&U256::from_u64(7))
}

/// Two vault accounts, and with `safe` a Safe of both, 1 of 2, salt 7.
fn meta(safe: bool) -> Value {
    let mut wallets = vec![
        json!({ "index": 0, "name": "Wallet 1", "address": A }),
        json!({ "index": 1, "name": "Wallet 2", "address": B }),
    ];
    if safe {
        wallets.push(json!({
            "index": SAFE, "name": "Safe 1", "address": checksum_address(&safe_address()),
            "type": "safe", "owners": [0, 1], "threshold": 1, "saltNonce": "7", "deployed": {},
        }));
    }
    json!({
        "userKnowsPassword": true,
        "addresses": { "userWallet": A, "beeWallet": B },
        "derivedWallets": wallets,
        "activeWalletIndex": 0,
        "nextHardwareWalletIndex": SAFE + u64::from(safe),
    })
}

fn context(caller: &str) -> Value {
    match caller {
        "page" => json!({ "caller": "page", "page": {
            "origin": "https://app.example", "top_origin": "https://app.example",
            "frame": 1, "navigation": 1, "agent": false,
        } }),
        caller => json!({ "caller": caller }),
    }
}

/// A core over `root` with `vault-meta.json` from `meta`, and `stores` in
/// `store_moved`.
fn start(root: &Path, meta: &Value, stores: &[&'static str]) -> Core {
    std::fs::create_dir_all(root.join("identity")).unwrap();
    std::fs::write(
        root.join("identity").join("vault-meta.json"),
        meta.to_string(),
    )
    .unwrap();
    let mut core = spawn("serve", &root.join("identity"), &root.join("locks"), &[]);
    std::fs::create_dir_all(&core.grant_root).unwrap();
    core.store_moved = stores.to_vec();
    assert!(core.hello()["result"].is_object());
    core
}

fn record(root: &Path, index: u64) -> Value {
    let text = std::fs::read_to_string(root.join("identity").join("vault-meta.json")).unwrap();
    let meta: Value = serde_json::from_str(&text).unwrap();
    meta["derivedWallets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["index"] == index)
        .cloned()
        .unwrap()
}

fn send(core: &mut Core, id: u64, caller: &str, method: &str, params: Value) {
    core.send(&json!({
        "type": "request", "id": id, "method": method, "params": params,
        "context": context(caller),
    }));
}

/// A call no `shell.*` request may come before: its response.
fn call(core: &mut Core, id: u64, caller: &str, method: &str, params: Value) -> Value {
    send(core, id, caller, method, params);
    core.response(id)
}

#[test]
fn create_writes_the_record_and_reads_nothing() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &meta(false), &["vault_meta"]);
    let params = json!({ "name": "Treasury", "owners": [0, 1], "threshold": 1 });
    // `response` refuses any request to main before the reply: no read.
    let reply = call(&mut core, 2, "chrome", "safe.create", params.clone());
    let wallet = &reply["result"]["wallet"];
    assert_eq!(wallet["index"], SAFE, "{reply}");
    assert_eq!(wallet["type"], "safe");
    assert_eq!(wallet["name"], "Treasury");
    assert_eq!(wallet["owners"], json!([0, 1]));
    assert_eq!(wallet["deployed"], json!({}));
    let salt = U256::parse_decimal(wallet["saltNonce"].as_str().unwrap()).unwrap();
    assert!(salt.bits() <= 128);
    assert_eq!(wallet["address"], checksum_address(&setup().address(&salt)));
    assert_eq!(&record(root.path(), SAFE), wallet);
    // Main's own may create too; a page may not.
    let reply = call(&mut core, 3, "shell", "safe.create", params.clone());
    assert_eq!(reply["result"]["wallet"]["index"], SAFE + 1, "{reply}");
    let reply = call(&mut core, 4, "page", "safe.create", params.clone());
    assert_eq!(reply["error"]["code"], "forbidden");
    // The record's checks are `addSafeWallet`'s.
    let reply = call(
        &mut core,
        5,
        "chrome",
        "safe.create",
        json!({ "name": "", "owners": [0, SAFE], "threshold": 1 }),
    );
    assert_eq!(reply["error"]["message"], "A Safe cannot own another Safe");
}

#[test]
fn nothing_before_vault_meta_moves_and_deployed_is_mains() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &meta(true), &[]);
    let before = std::fs::read(root.path().join("identity").join("vault-meta.json")).unwrap();
    for (id, method, params) in [
        (
            2,
            "safe.create",
            json!({ "name": "", "owners": [0, 1], "threshold": 1 }),
        ),
        (3, "safe.status", json!({ "safe": SAFE })),
        (4, "safe.deploy", json!({ "safe": SAFE })),
        (5, "safe.deployed", json!({ "safe": SAFE, "hash": HASH })),
        (6, "safe.pending", json!({})),
        (7, "safe.discard", json!({ "safe": SAFE })),
        (
            8,
            "safe.prepare",
            json!({ "safe": SAFE, "chain_id": 100, "tx": { "to": A, "value": "1", "data": "0x" } }),
        ),
        (
            9,
            "safe.propose",
            json!({ "safe": SAFE, "safe_tx_hash": HASH, "authorization": { "token": "00".repeat(32) } }),
        ),
        (10, "safe.execute", json!({ "safe": SAFE })),
        (
            11,
            "safe.executed",
            json!({ "safe": SAFE, "safe_tx_hash": HASH, "hash": HASH }),
        ),
    ] {
        let reply = call(&mut core, id, "shell", method, params);
        assert_eq!(reply["error"]["code"], "not_moved", "{method} {reply}");
        assert_eq!(reply["error"]["data"]["store"], "vault_meta");
    }
    assert_eq!(
        std::fs::read(root.path().join("identity").join("vault-meta.json")).unwrap(),
        before
    );
    let reply = call(
        &mut core,
        12,
        "chrome",
        "safe.deployed",
        json!({ "safe": SAFE, "hash": HASH }),
    );
    assert_eq!(reply["error"]["code"], "forbidden");
    let reply = call(
        &mut core,
        13,
        "chrome",
        "safe.executed",
        json!({ "safe": SAFE, "safe_tx_hash": HASH, "hash": HASH }),
    );
    assert_eq!(reply["error"]["code"], "forbidden");
    let reply = call(
        &mut core,
        14,
        "page",
        "safe.execute",
        json!({ "safe": SAFE }),
    );
    assert_eq!(reply["error"]["code"], "forbidden");
}

fn word(bytes: &[u8]) -> String {
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(bytes);
    to_hex(&word)
}

/// What Gnosis answers each read: the receipt, the code, and the setup
/// as Freedom made it.
fn answer(method: &str, params: &Value) -> Value {
    let data = params[0]["data"].as_str().unwrap_or("");
    let slot = params[1].as_str().unwrap_or("");
    let words = |words: &[String]| {
        Value::String(format!(
            "0x{}",
            words
                .iter()
                .map(|w| w.trim_start_matches("0x").to_owned())
                .collect::<String>()
        ))
    };
    let uint = |n: u64| word(&n.to_be_bytes());
    match method {
        "eth_getTransactionReceipt" => json!({
            "transactionHash": HASH, "status": "0x1",
            "logs": [{
                "address": to_hex(&PROXY_FACTORY),
                "topics": [
                    to_hex(&keccak256(b"ProxyCreation(address,address)")),
                    word(&safe_address()),
                ],
                "data": word(&SINGLETON),
            }],
        }),
        "eth_getCode" => json!("0x6080604052"),
        "eth_getStorageAt" if slot == to_hex(&[0u8; 32]) => words(&[word(&SINGLETON)]),
        "eth_getStorageAt" if slot == to_hex(&fc_safe::reads::FALLBACK_HANDLER_SLOT) => {
            words(&[word(&FALLBACK_HANDLER)])
        }
        "eth_getStorageAt" => words(&[uint(0)]),
        "eth_call" if data == "0xa0e67e2b" => words(&[
            uint(0x20),
            uint(2),
            word(&fc_wallet_state::address_bytes(A).unwrap()),
            word(&fc_wallet_state::address_bytes(B).unwrap()),
        ]),
        "eth_call" if data == "0xe75235b8" => words(&[uint(1)]),
        "eth_call" if data.starts_with("0xcc2f8452") => {
            words(&[uint(0x40), word(&SENTINEL), uint(0)])
        }
        "eth_call" if data == "0xaffed0e0" => words(&[uint(3)]),
        other => panic!("{other} {params}"),
    }
}

/// Plays main until request `id`'s response: every `shell.rpc` read
/// answered by both endpoints alike. The reads' methods, in order.
fn served(core: &mut Core, id: u64) -> (Value, Vec<String>) {
    let mut methods = Vec::new();
    loop {
        let message = core.recv();
        match message["type"].as_str() {
            Some("response") if message["id"] == id => return (message, methods),
            Some("request") => {
                assert_eq!(message["method"], "shell.rpc", "{message}");
                let body: Value =
                    serde_json::from_str(message["params"]["body"].as_str().unwrap()).unwrap();
                let method = body["method"].as_str().unwrap();
                methods.push(method.to_owned());
                let text = json!({
                    "jsonrpc": "2.0", "id": body["id"], "result": answer(method, &body["params"]),
                });
                core.send(&json!({
                    "type": "response", "id": message["id"],
                    "result": {
                        "status": 200,
                        "body": base64::engine::general_purpose::STANDARD.encode(text.to_string()),
                    },
                }));
            }
            Some("event") => {}
            _ => panic!("unexpected {message}"),
        }
    }
}

#[test]
fn a_receipt_two_endpoints_agree_on_marks_the_safe_and_status_reads_its_setup() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &meta(true), &["vault_meta"]);
    let gnosis = json!({
        "chain_id": 100, "display_name": "Gnosis Chain",
        "read_order": ["quorum", "direct"], "broadcast_order": ["direct"],
        "quorum": { "k": 2, "m": 2, "timeout_ms": 5000 },
        "rpc": [
            { "endpoint": "https://a.example", "user_configured": false },
            { "endpoint": "https://b.example", "user_configured": false },
        ],
        "prover": null, "myotis": false, "blockscout": null,
    });
    let configured = call(
        &mut core,
        2,
        "shell",
        "chain.configure",
        json!({ "chains": [gnosis] }),
    );
    assert!(configured["result"].is_object(), "{configured}");
    send(
        &mut core,
        3,
        "shell",
        "safe.deployed",
        json!({ "safe": SAFE, "hash": HASH }),
    );
    let (reply, methods) = served(&mut core, 3);
    assert_eq!(reply["result"], json!({ "deployed": true }), "{reply}");
    // The receipt, from both endpoints, alone decides.
    assert_eq!(methods, ["eth_getTransactionReceipt"; 2]);
    assert_eq!(
        record(root.path(), SAFE)["deployed"],
        json!({ "100": { "verified": true } })
    );
    // Marked: the status reads the code and the six setup reads, each
    // from both endpoints, and no nonce.
    send(
        &mut core,
        4,
        "chrome",
        "safe.status",
        json!({ "safe": SAFE }),
    );
    let (reply, methods) = served(&mut core, 4);
    assert_eq!(
        reply["result"],
        json!({
            "deployed": true, "chainId": 100, "executorIndex": 0, "executorAddress": A,
            "executorBalance": null, "estimatedCost": null, "needsFunds": false,
            "setup": { "state": "unchanged" },
        }),
        "{reply}"
    );
    assert_eq!(methods.len(), 14, "{methods:?}");
    assert_eq!(methods[..2], ["eth_getCode"; 2]);
    // The deployment of a deployed Safe sends nothing.
    let reply = call(
        &mut core,
        5,
        "chrome",
        "safe.deploy",
        json!({ "safe": SAFE }),
    );
    assert_eq!(reply["result"], json!({ "deployed": true }));
}

#[test]
fn pending_and_discard_serve_the_store() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &meta(true), &["vault_meta", "safe_pending"]);
    let file = core.grant_root.join("safe-pending.json");
    // An entry for the Safe's SafeTx, as the reference writes one (S3's
    // codec sets aside any other).
    let tx = fc_safe::SafeTx::new(
        fc_wallet_state::address_bytes(A).unwrap(),
        U256::from_u64(1),
        vec![],
        0,
    )
    .unwrap();
    let hash = to_hex(&tx.hash(&safe_address()).unwrap());
    let entry = json!({
        "chainId": 100, "safeAddress": checksum_address(&safe_address()),
        "safeTxData": tx.fields(), "safeTxHash": hash, "threshold": 1, "signatures": [],
        "createdAt": 5,
    });
    std::fs::write(&file, json!({ SAFE.to_string(): entry }).to_string()).unwrap();
    let reply = call(&mut core, 2, "chrome", "safe.pending", json!({}));
    let states = reply["result"]["states"].as_array().unwrap();
    assert_eq!(states.len(), 1, "{reply}");
    assert_eq!(states[0]["safeTxHash"], hash);
    assert_eq!(states[0]["executorIndex"], 0);
    let reply = call(
        &mut core,
        3,
        "chrome",
        "safe.discard",
        json!({ "safe": SAFE, "safe_tx_hash": "0xbb" }),
    );
    assert_eq!(reply["error"]["data"]["safe"], "SAFE_DISCARDED", "{reply}");
    let reply = call(
        &mut core,
        4,
        "chrome",
        "safe.discard",
        json!({ "safe": SAFE, "safe_tx_hash": hash }),
    );
    assert_eq!(reply["result"], json!({}), "{reply}");
    assert_eq!(std::fs::read(&file).unwrap(), b"{}");
    // An unreadable file is set aside once moved.
    std::fs::write(&file, b"{not json").unwrap();
    let reply = call(&mut core, 5, "chrome", "safe.pending", json!({}));
    assert_eq!(reply["result"]["states"], json!([]));
    assert!(
        core.grant_root
            .join("safe-pending.json.unreadable")
            .exists()
    );
    let reply = call(&mut core, 6, "page", "safe.pending", json!({}));
    assert_eq!(reply["error"]["code"], "forbidden");
}

// --- SAFE-2's S3: a Safe transaction prepared and proposed ------------------

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn vectors() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/safe.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// What Gnosis answers each read of the Safe of `owners`, 1 of 2, as
/// Freedom made it, at nonce 3.
fn answer_for(method: &str, params: &Value, owners: &[[u8; 20]]) -> Value {
    let data = params[0]["data"].as_str().unwrap_or("");
    if method == "eth_call" && data == "0xa0e67e2b" {
        let mut words = vec![word(&[0x20]), word(&[owners.len() as u8])];
        words.extend(owners.iter().map(|owner| word(owner)));
        return Value::String(format!(
            "0x{}",
            words
                .iter()
                .map(|w| w.trim_start_matches("0x").to_owned())
                .collect::<String>()
        ));
    }
    answer(method, params)
}

/// Plays main until request `id`'s response, every `shell.rpc` read
/// answered alike by both endpoints for the Safe of `owners`. The reads'
/// methods, in order.
fn served_for(core: &mut Core, id: u64, owners: &[[u8; 20]]) -> (Value, Vec<String>) {
    let mut methods = Vec::new();
    loop {
        let message = core.recv();
        match message["type"].as_str() {
            Some("response") if message["id"] == id => return (message, methods),
            Some("request") => {
                assert_eq!(message["method"], "shell.rpc", "{message}");
                let body: Value =
                    serde_json::from_str(message["params"]["body"].as_str().unwrap()).unwrap();
                let method = body["method"].as_str().unwrap();
                methods.push(method.to_owned());
                let text = json!({
                    "jsonrpc": "2.0", "id": body["id"],
                    "result": answer_for(method, &body["params"], owners),
                });
                core.send(&json!({
                    "type": "response", "id": message["id"],
                    "result": {
                        "status": 200,
                        "body": base64::engine::general_purpose::STANDARD.encode(text.to_string()),
                    },
                }));
            }
            Some("event") => {}
            _ => panic!("unexpected {message}"),
        }
    }
}

fn gnosis_of_two() -> Value {
    json!({
        "chain_id": 100, "display_name": "Gnosis Chain",
        "read_order": ["quorum", "direct"], "broadcast_order": ["direct"],
        "quorum": { "k": 2, "m": 2, "timeout_ms": 5000 },
        "rpc": [
            { "endpoint": "https://a.example", "user_configured": false },
            { "endpoint": "https://b.example", "user_configured": false },
        ],
        "prover": null, "myotis": false, "blockscout": null,
    })
}

/// The vector flow `one-of-two` over the wire: the vault imported, a
/// second account and the flow's Safe added through the core's own
/// `accounts.*`, marked deployed; `safe.prepare` reads the eight setup
/// reads from both endpoints, the nonce last; `approval.issue` mints the
/// `safe-send` over the SafeTx it answered (D6), and `safe.propose` reads
/// them again, has the vault owner sign, and writes the reference's entry.
/// A restart reads it back.
#[test]
fn a_safe_tx_is_prepared_proposed_and_reloaded() {
    let v = vectors();
    let flow = v["flows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|flow| flow["id"] == "one-of-two")
        .unwrap()
        .clone();
    let start_step = &flow["steps"][0];
    let pending = &start_step["pending"];
    let owners: Vec<[u8; 20]> = ["A", "B"]
        .iter()
        .map(|name| fc_evm::parse_address(v["owners"][name]["address"].as_str().unwrap()).unwrap())
        .collect();
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("identity")).unwrap();
    let mut core = spawn(
        "serve",
        &root.path().join("identity"),
        &root.path().join("locks"),
        &[],
    );
    std::fs::create_dir_all(&core.grant_root).unwrap();
    core.store_moved = vec!["vault_meta", "safe_pending"];
    assert!(core.hello()["result"].is_object());
    let imported = call(
        &mut core,
        2,
        "shell",
        "vault.import",
        json!({
            "password_b64": base64::engine::general_purpose::STANDARD.encode("testpass1"),
            "mnemonic_b64": base64::engine::general_purpose::STANDARD.encode(ABANDON),
            "overwrite": true, "user_knows_password": true,
        }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    let second = call(
        &mut core,
        3,
        "shell",
        "accounts.add_mnemonic",
        json!({ "name": "B" }),
    );
    assert_eq!(second["result"]["wallet"]["index"], 1, "{second}");
    assert_eq!(
        second["result"]["wallet"]["address"],
        v["owners"]["B"]["address"]
    );
    let safe = call(
        &mut core,
        4,
        "shell",
        "accounts.add_safe",
        json!({ "address": flow["safe"]["address"], "owners": [0, 1], "threshold": 1, "salt_nonce": "0" }),
    );
    let index = safe["result"]["wallet"]["index"].as_u64().unwrap();
    let marked = call(
        &mut core,
        5,
        "shell",
        "accounts.mark_safe_deployed",
        json!({ "index": index, "chain_id": 100 }),
    );
    assert!(marked["result"].is_object(), "{marked}");
    let configured = call(
        &mut core,
        6,
        "shell",
        "chain.configure",
        json!({ "chains": [gnosis_of_two()] }),
    );
    assert!(configured["result"].is_object(), "{configured}");
    // Prepared: the eight reads, each from both endpoints, the nonce last.
    send(
        &mut core,
        7,
        "chrome",
        "safe.prepare",
        json!({ "safe": index, "chain_id": 100, "tx": flow["tx"] }),
    );
    let (reply, methods) = served_for(&mut core, 7, &owners);
    let answer = &reply["result"];
    assert_eq!(answer["safe_tx"], pending["safeTxData"], "{reply}");
    assert_eq!(answer["safe_tx_hash"], pending["safeTxHash"]);
    assert_eq!(methods.len(), 16, "{methods:?}");
    assert_eq!(methods[..2], ["eth_getCode"; 2]);
    // The nonce, `eth_call` to `nonce()`, last.
    assert_eq!(methods[14..], ["eth_call"; 2]);
    // Main mints the `safe-send` over what it answered.
    let issued = call(
        &mut core,
        8,
        "shell",
        "approval.issue",
        json!({
            "kind": "safe-send", "account": index,
            "payload": {
                "safe": flow["safe"]["address"], "chain_id": "100",
                "safe_tx": answer["safe_tx"], "safe_tx_hash": answer["safe_tx_hash"],
            },
        }),
    );
    let token = issued["result"]["token"].as_str().unwrap().to_owned();
    // A page can't propose with main's token.
    let reply = call(
        &mut core,
        9,
        "page",
        "safe.propose",
        json!({ "safe": index, "safe_tx_hash": answer["safe_tx_hash"],
                "authorization": { "token": token, "handle": "a1".repeat(32) } }),
    );
    assert_eq!(reply["error"]["code"], "not_authorized", "{reply}");
    // That burnt it: a new one, presented by main.
    let issued = call(
        &mut core,
        10,
        "shell",
        "approval.issue",
        json!({
            "kind": "safe-send", "account": index,
            "payload": {
                "safe": flow["safe"]["address"], "chain_id": "100",
                "safe_tx": answer["safe_tx"], "safe_tx_hash": answer["safe_tx_hash"],
            },
        }),
    );
    let token = issued["result"]["token"].as_str().unwrap().to_owned();
    send(
        &mut core,
        11,
        "shell",
        "safe.propose",
        json!({ "safe": index, "safe_tx_hash": answer["safe_tx_hash"],
                "authorization": { "token": token }, "display": pending["display"] }),
    );
    let (reply, methods) = served_for(&mut core, 11, &owners);
    let state = reply["result"].clone();
    assert_eq!(state["collected"], 1, "{reply}");
    assert_eq!(state["safeTxHash"], pending["safeTxHash"]);
    assert_eq!(methods.len(), 16);
    let file: Value = serde_json::from_str(
        &std::fs::read_to_string(core.grant_root.join("safe-pending.json")).unwrap(),
    )
    .unwrap();
    let mut entry = file[index.to_string()].clone();
    assert!(entry["createdAt"].is_u64(), "{entry}");
    entry.as_object_mut().unwrap().shift_remove("createdAt");
    assert_eq!(entry, *pending);
    // A restart reads it back, the vault locked.
    drop(core);
    let mut core = spawn(
        "serve",
        &root.path().join("identity"),
        &root.path().join("locks"),
        &[],
    );
    core.store_moved = vec!["vault_meta", "safe_pending"];
    assert!(core.hello()["result"].is_object());
    let reply = call(&mut core, 2, "chrome", "safe.pending", json!({}));
    assert_eq!(reply["result"]["states"], json!([state]), "{reply}");
}

// --- SAFE-2's S4: the pending SafeTx executed --------------------------------

/// Plays main and Gnosis until request `id`'s response: the Safe's reads as
/// [`served_for`] answers them, the executor's estimate (200,000 gas), and
/// the fee quote's `eth_gasPrice` (16 gwei) and `eth_maxPriorityFeePerGas`
/// (2 gwei), each from both endpoints; any other method isn't served. The
/// reads' methods, in order.
fn served_exec(core: &mut Core, id: u64, owners: &[[u8; 20]]) -> (Value, Vec<String>) {
    let mut methods = Vec::new();
    loop {
        let message = core.recv();
        match message["type"].as_str() {
            Some("response") if message["id"] == id => return (message, methods),
            Some("request") => {
                assert_eq!(message["method"], "shell.rpc", "{message}");
                let body: Value =
                    serde_json::from_str(message["params"]["body"].as_str().unwrap()).unwrap();
                let method = body["method"].as_str().unwrap();
                methods.push(method.to_owned());
                let mut text = json!({ "jsonrpc": "2.0", "id": body["id"] });
                match method {
                    "eth_estimateGas" => text["result"] = json!("0x30d40"),
                    "eth_gasPrice" => text["result"] = json!(format!("{:#x}", 16_000_000_000u64)),
                    "eth_maxPriorityFeePerGas" => {
                        text["result"] = json!(format!("{:#x}", 2_000_000_000u64));
                    }
                    "eth_getCode" | "eth_getStorageAt" | "eth_call" => {
                        text["result"] = answer_for(method, &body["params"], owners);
                    }
                    _ => {
                        text["error"] =
                            json!({ "code": -32601, "message": "the method does not exist" });
                    }
                }
                core.send(&json!({
                    "type": "response", "id": message["id"],
                    "result": {
                        "status": 200,
                        "body": base64::engine::general_purpose::STANDARD.encode(text.to_string()),
                    },
                }));
            }
            Some("event") => {}
            _ => panic!("unexpected {message}"),
        }
    }
}

/// The vector flow `one-of-two` executed over the wire: proposed as above;
/// `safe.execute` reads the eight again, then the executor's quote, and
/// answers the executor's send with the calldata the reference sent and its
/// `executor-send` token. Main's `sign.transaction` with a field changed is
/// refused and burns it; a new one signs as prepared, at main's nonce, and
/// `safe.executed` clears the entry.
#[test]
fn a_proposed_safe_tx_is_executed_through_the_prepared_send() {
    let v = vectors();
    let flow = v["flows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|flow| flow["id"] == "one-of-two")
        .unwrap()
        .clone();
    let sent = &flow["steps"][1]["sent"][0];
    let owners: Vec<[u8; 20]> = ["A", "B"]
        .iter()
        .map(|name| fc_evm::parse_address(v["owners"][name]["address"].as_str().unwrap()).unwrap())
        .collect();
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("identity")).unwrap();
    let mut core = spawn(
        "serve",
        &root.path().join("identity"),
        &root.path().join("locks"),
        &[],
    );
    std::fs::create_dir_all(&core.grant_root).unwrap();
    core.store_moved = vec!["vault_meta", "safe_pending"];
    assert!(core.hello()["result"].is_object());
    let imported = call(
        &mut core,
        2,
        "shell",
        "vault.import",
        json!({
            "password_b64": base64::engine::general_purpose::STANDARD.encode("testpass1"),
            "mnemonic_b64": base64::engine::general_purpose::STANDARD.encode(ABANDON),
            "overwrite": true, "user_knows_password": true,
        }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    call(
        &mut core,
        3,
        "shell",
        "accounts.add_mnemonic",
        json!({ "name": "B" }),
    );
    let safe = call(
        &mut core,
        4,
        "shell",
        "accounts.add_safe",
        json!({ "address": flow["safe"]["address"], "owners": [0, 1], "threshold": 1, "salt_nonce": "0" }),
    );
    let index = safe["result"]["wallet"]["index"].as_u64().unwrap();
    call(
        &mut core,
        5,
        "shell",
        "accounts.mark_safe_deployed",
        json!({ "index": index, "chain_id": 100 }),
    );
    call(
        &mut core,
        6,
        "shell",
        "chain.configure",
        json!({ "chains": [gnosis_of_two()] }),
    );
    send(
        &mut core,
        7,
        "shell",
        "safe.prepare",
        json!({ "safe": index, "chain_id": 100, "tx": flow["tx"] }),
    );
    let (reply, _) = served_for(&mut core, 7, &owners);
    let answer = reply["result"].clone();
    let issued = call(
        &mut core,
        8,
        "shell",
        "approval.issue",
        json!({
            "kind": "safe-send", "account": index,
            "payload": {
                "safe": flow["safe"]["address"], "chain_id": "100",
                "safe_tx": answer["safe_tx"], "safe_tx_hash": answer["safe_tx_hash"],
            },
        }),
    );
    send(
        &mut core,
        9,
        "shell",
        "safe.propose",
        json!({ "safe": index, "safe_tx_hash": answer["safe_tx_hash"],
                "authorization": { "token": issued["result"]["token"] } }),
    );
    let (reply, _) = served_for(&mut core, 9, &owners);
    assert_eq!(reply["result"]["collected"], 1, "{reply}");
    // Executed: the eight again, the nonce last, then the quote.
    send(
        &mut core,
        10,
        "shell",
        "safe.execute",
        json!({ "safe": index, "safe_tx_hash": answer["safe_tx_hash"] }),
    );
    let (reply, methods) = served_exec(&mut core, 10, &owners);
    assert_eq!(methods[..2], ["eth_getCode"; 2], "{methods:?}");
    assert_eq!(
        methods[14..16],
        ["eth_call"; 2],
        "the nonce last: {methods:?}"
    );
    assert!(methods[16..].contains(&"eth_estimateGas".to_owned()));
    let send_of = |reply: &Value| {
        let send = reply["result"]["send"].clone();
        assert!(send.is_object(), "{reply}");
        send
    };
    let prepared = send_of(&reply);
    assert_eq!(prepared["kind"], "executor-send");
    assert_eq!(prepared["account"], 0);
    let tx = &prepared["tx"];
    assert_eq!(tx["to"], sent["to"]);
    assert_eq!(tx["value"], "0");
    assert_eq!(tx["data"], sent["data"]);
    assert_eq!(tx["gas_limit"], "240000");
    // Main signs it at its nonce, with one field changed: refused, burnt.
    let sign = |core: &mut Core, id: u64, send: &Value, edit: &dyn Fn(&mut Value)| {
        let mut tx = send["tx"].clone();
        tx["nonce"] = json!("5");
        edit(&mut tx);
        call(
            core,
            id,
            "shell",
            "sign.transaction",
            json!({
                "key": { "kind": "account", "index": send["account"] }, "tx": tx,
                "authorization": { "token": send["token"], "kind": send["kind"] },
            }),
        )
    };
    let refused = sign(&mut core, 11, &prepared, &|tx| tx["value"] = json!("1"));
    assert_eq!(refused["error"]["code"], "not_authorized", "{refused}");
    assert_eq!(refused["error"]["data"]["reason"], "mismatch");
    let refused = sign(&mut core, 12, &prepared, &|_| {});
    assert_eq!(
        refused["error"]["data"]["reason"], "unknown_token",
        "{refused}"
    );
    // Without a token, main's word signs no `execTransaction`.
    let mut bare = prepared["tx"].clone();
    bare["nonce"] = json!("5");
    let refused = call(
        &mut core,
        13,
        "shell",
        "sign.transaction",
        json!({ "key": { "kind": "account", "index": 0 }, "tx": bare }),
    );
    assert_eq!(refused["error"]["data"]["reason"], "no_token", "{refused}");
    // A new prepared send signs as prepared.
    send(
        &mut core,
        14,
        "shell",
        "safe.execute",
        json!({ "safe": index }),
    );
    let (reply, _) = served_exec(&mut core, 14, &owners);
    let prepared = send_of(&reply);
    let signed = sign(&mut core, 15, &prepared, &|_| {});
    assert!(signed["result"].is_object(), "{signed}");
    let hash = signed["result"]["hash"].clone();
    assert!(hash.is_string(), "{signed}");
    // Main broadcast it: the entry is cleared.
    let reply = call(
        &mut core,
        16,
        "shell",
        "safe.executed",
        json!({ "safe": index, "safe_tx_hash": answer["safe_tx_hash"], "hash": hash }),
    );
    assert_eq!(reply["result"], json!({}), "{reply}");
    let file: Value = serde_json::from_str(
        &std::fs::read_to_string(core.grant_root.join("safe-pending.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(file, json!({}));
    let reply = call(&mut core, 17, "chrome", "safe.pending", json!({}));
    assert_eq!(reply["result"]["states"], json!([]));
}
