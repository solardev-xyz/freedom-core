//! SAFE-2's S6 through the real binary (design 0016, SAFE-2's tests,
//! *Owners*): owners who sign after a proposal. A 2-of-3 Safe of two vault
//! accounts and a Ledger, proposed while the vault is locked: the Ledger
//! owner signs the pending SafeTx through `safe.sign_owner` on the device
//! lane (the vault still locked), each read through the core's own chain
//! machine and main's `shell.rpc`, each APDU a `shell.ledger_apdu` main
//! relays to a scripted device; then, unlocked, the board's sweep has the
//! vault owner sign until the threshold. A page's Safe message the same
//! way, through `safe.message_sign`, completed with the reference's join.
//! The test plays main and Gnosis.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

/// fc-ledger's scripted device (abandon-12) and its runner, the same the
/// crate's own vector tests run.
#[path = "../../fc-ledger/tests/common/mod.rs"]
mod device;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::*;
use device::{Device, Owned};
use fc_evm::{U256, checksum_address, to_hex};
use fc_safe::constants::{FALLBACK_HANDLER, SENTINEL, SINGLETON};
use fc_safe::{OwnerSignature, Setup, Signatures};
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// The Ledger's path: abandon-12's key there, which no vault account has.
const LEDGER_PATH: &str = "44'/60'/0'/3";
const VAULT_PATH: &str = "44'/60'/0'/0/0";
const HANDLE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const CONFIRM_MS: u64 = 300_000;
const APDU_MS: u64 = 15_000;

fn context(caller: &str) -> Value {
    match caller {
        "page" => json!({ "caller": "page", "page": {
            "origin": "https://app.example", "top_origin": "https://app.example",
            "frame": 1, "navigation": 1, "agent": false,
        } }),
        caller => json!({ "caller": caller }),
    }
}

fn send(core: &mut Core, id: u64, caller: &str, method: &str, params: Value) {
    core.send(&json!({
        "type": "request", "id": id, "method": method, "params": params,
        "context": context(caller),
    }));
}

/// A call no `shell.*` request may come before: its result.
fn call(core: &mut Core, id: u64, caller: &str, method: &str, params: Value) -> Value {
    send(core, id, caller, method, params);
    let reply = core.response(id);
    assert!(reply["result"].is_object(), "{method}: {reply}");
    reply["result"].clone()
}

fn word(bytes: &[u8]) -> String {
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(bytes);
    to_hex(&word)[2..].to_owned()
}

/// What Gnosis answers each setup read of the Safe of `owners` with
/// `threshold`, as Freedom made it, at nonce 3.
fn answer(method: &str, params: &Value, owners: &[[u8; 20]], threshold: u8) -> Value {
    let data = params[0]["data"].as_str().unwrap_or("");
    let slot = params[1].as_str().unwrap_or("");
    let words = |words: Vec<String>| Value::String(format!("0x{}", words.concat()));
    let uint = |n: u64| word(&n.to_be_bytes());
    match method {
        "eth_getCode" => json!("0x6080604052"),
        "eth_getStorageAt" if slot == to_hex(&[0u8; 32]) => words(vec![word(&SINGLETON)]),
        "eth_getStorageAt" if slot == to_hex(&fc_safe::reads::FALLBACK_HANDLER_SLOT) => {
            words(vec![word(&FALLBACK_HANDLER)])
        }
        "eth_getStorageAt" => words(vec![uint(0)]),
        "eth_call" if data == "0xa0e67e2b" => {
            let mut list = vec![uint(0x20), uint(owners.len() as u64)];
            list.extend(owners.iter().map(|owner| word(owner)));
            words(list)
        }
        "eth_call" if data == "0xe75235b8" => words(vec![uint(u64::from(threshold))]),
        "eth_call" if data.starts_with("0xcc2f8452") => {
            words(vec![uint(0x40), word(&SENTINEL), uint(0)])
        }
        "eth_call" if data == "0xaffed0e0" => words(vec![uint(3)]),
        other => panic!("{other} {params}"),
    }
}

/// One `shell.ledger_apdu` the core sent.
#[derive(Debug, Clone)]
struct Asked {
    parent: u64,
    apdu: Vec<u8>,
    deadline_ms: u64,
}

/// Plays main until request `id`'s response: every `shell.rpc` read
/// answered alike by both endpoints for the Safe of `owners`, every
/// `shell.ledger_apdu` relayed to `ledger`, as main does (a `6D00` to the
/// first `E0 1A` with `hash_only: "shown"`). The reads' methods, and the
/// APDUs.
fn played(
    core: &mut Core,
    id: u64,
    owners: &[[u8; 20]],
    ledger: &mut Device,
) -> (Value, Vec<String>, Vec<Asked>) {
    let (mut methods, mut apdus) = (Vec::new(), Vec::new());
    loop {
        let message = core.recv();
        match (message["type"].as_str(), message["method"].as_str()) {
            (Some("response"), _) if message["id"] == id => return (message, methods, apdus),
            (Some("request"), Some("shell.rpc")) => {
                let body: Value =
                    serde_json::from_str(message["params"]["body"].as_str().unwrap()).unwrap();
                let method = body["method"].as_str().unwrap();
                methods.push(method.to_owned());
                let text = json!({
                    "jsonrpc": "2.0", "id": body["id"],
                    "result": answer(method, &body["params"], owners, 2),
                });
                core.send(&json!({
                    "type": "response", "id": message["id"],
                    "result": { "status": 200, "body": STANDARD.encode(text.to_string()) },
                }));
            }
            (Some("request"), Some("shell.ledger_apdu")) => {
                let params = &message["params"];
                let asked = Asked {
                    parent: params["for"].as_u64().unwrap(),
                    apdu: device::unhex(params["apdu"].as_str().unwrap()),
                    deadline_ms: params["deadline_ms"].as_u64().unwrap(),
                };
                let answered = ledger.answer(&asked.apdu);
                let result = match device::relay(apdus.len(), &asked.apdu, answered) {
                    Owned::Answer(bytes, shown) => {
                        let mut result = json!({ "answer": device::hex(&bytes) });
                        if shown {
                            result["hash_only"] = json!("shown");
                        }
                        result
                    }
                    other => panic!("{other:?}"),
                };
                apdus.push(asked);
                core.send(&json!({ "type": "response", "id": message["id"], "result": result }));
            }
            (Some("event"), _) => {}
            _ => panic!("unexpected {message}"),
        }
    }
}

/// The APDUs fc-ledger's operation over `typed` (a Safe's typed data, its
/// domain and its primary type alone) sends to a device holding the
/// account at [`LEDGER_PATH`]: what the lane must have carried.
fn stream(typed: &Value, primary: &str, hash: &[u8; 32]) -> Vec<Vec<u8>> {
    let types = json!({ primary: typed["types"][primary].clone() });
    let mut op = fc_ledger::Operation::sign_typed_data(
        device::account_at(LEDGER_PATH),
        &typed["domain"],
        &types,
        &typed["message"],
        hash,
    )
    .unwrap();
    let mut ledger = signing(*hash);
    let run = device::run_device(&mut op, &mut ledger);
    assert!(run.done.is_ok());
    run.apdus
}

/// A Ledger with the Ethereum app open, holding abandon-12, whose
/// `E0 0C 00 01` signs `hash`.
fn signing(hash: [u8; 32]) -> Device {
    let mut ledger = Device::default();
    ledger.typed_hash = Some(hash);
    ledger
}

/// Each APDU named request `id` in `for`, and only the last, the one the
/// user confirms, waits 5 minutes.
fn lane_shape(apdus: &[Asked], id: u64) {
    assert!(apdus.len() > 3, "{apdus:?}");
    for (at, asked) in apdus.iter().enumerate() {
        assert_eq!(asked.parent, id);
        let wait = if at + 1 == apdus.len() {
            CONFIRM_MS
        } else {
            APDU_MS
        };
        assert_eq!(asked.deadline_ms, wait, "APDU {at}");
    }
}

/// The signature abandon-12's key at `path` makes over `hash`, as the
/// vault and the scripted device both make it.
fn signature_at(path: &str, hash: &[u8; 32]) -> [u8; 65] {
    let key = device::key_at(&fc_ledger::LedgerPath::parse(path).unwrap());
    fc_evm::sign_digest(key.signing_key(), hash).unwrap()
}

fn signed_at(path: &str, hash: &[u8; 32]) -> String {
    to_hex(&signature_at(path, hash))
}

fn hash_of(text: &Value) -> [u8; 32] {
    fc_evm::parse_bytes(text.as_str().unwrap(), "hash")
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn a_ledger_owner_signs_later_on_the_lane_and_the_sweep_after_unlock() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("identity")).unwrap();
    let mut core = spawn_env(
        "serve",
        &root.path().join("identity"),
        &root.path().join("locks"),
        &[],
        &[MAINS_WORD],
    );
    std::fs::create_dir_all(&core.grant_root).unwrap();
    core.store_moved = vec!["vault_meta", "safe_pending"];
    assert!(core.hello()["result"].is_object());
    let password = STANDARD.encode("testpass1");
    call(
        &mut core,
        2,
        "shell",
        "vault.import",
        json!({
            "password_b64": password, "mnemonic_b64": STANDARD.encode(ABANDON),
            "overwrite": true, "user_knows_password": true,
        }),
    );
    let b = call(
        &mut core,
        3,
        "shell",
        "accounts.add_mnemonic",
        json!({ "name": "B" }),
    );
    assert_eq!(b["wallet"]["index"], 1);
    let ledger_address = device::account_at(LEDGER_PATH).address;
    let added = call(
        &mut core,
        4,
        "shell",
        "accounts.add_ledger",
        json!({ "address": checksum_address(&ledger_address), "path": LEDGER_PATH }),
    );
    let ledger_index = added["wallet"]["index"].as_u64().unwrap();
    let owners = [
        device::account_at(VAULT_PATH).address,
        fc_evm::parse_address(b["wallet"]["address"].as_str().unwrap()).unwrap(),
        ledger_address,
    ];
    let setup = Setup::new(owners.to_vec(), 2).unwrap();
    let safe_address = checksum_address(&setup.address(&U256::from_u64(7)));
    let safe = call(
        &mut core,
        5,
        "shell",
        "accounts.add_safe",
        json!({ "address": safe_address, "owners": [0, 1, ledger_index], "threshold": 2,
                "salt_nonce": "7" }),
    );
    let index = safe["wallet"]["index"].as_u64().unwrap();
    call(
        &mut core,
        6,
        "shell",
        "accounts.mark_safe_deployed",
        json!({ "index": index, "chain_id": 100 }),
    );
    call(
        &mut core,
        7,
        "shell",
        "chain.configure",
        json!({ "chains": [{
            "chain_id": 100, "display_name": "Gnosis Chain",
            "read_order": ["quorum", "direct"], "broadcast_order": ["direct"],
            "quorum": { "k": 2, "m": 2, "timeout_ms": 5000 },
            "rpc": [
                { "endpoint": "https://a.example", "user_configured": false },
                { "endpoint": "https://b.example", "user_configured": false },
            ],
            "prover": null, "myotis": false, "blockscout": null,
        }] }),
    );
    call(&mut core, 8, "shell", "vault.lock", json!({}));

    // Proposed while the vault is locked: no owner signs.
    let mut unused = Device::default();
    let tx = json!({ "to": checksum_address(&[0x77; 20]), "value": "1000", "data": "0x" });
    send(
        &mut core,
        9,
        "chrome",
        "safe.prepare",
        json!({ "safe": index, "chain_id": 100, "tx": tx }),
    );
    let (reply, _, _) = played(&mut core, 9, &owners, &mut unused);
    let prepared = reply["result"].clone();
    let hash = hash_of(&prepared["safe_tx_hash"]);
    let token = call(
        &mut core,
        10,
        "shell",
        "approval.issue",
        json!({
            "kind": "safe-send", "account": index,
            "payload": {
                "safe": safe_address, "chain_id": "100",
                "safe_tx": prepared["safe_tx"], "safe_tx_hash": prepared["safe_tx_hash"],
            },
        }),
    )["token"]
        .clone();
    send(
        &mut core,
        11,
        "shell",
        "safe.propose",
        json!({ "safe": index, "safe_tx_hash": prepared["safe_tx_hash"],
                "authorization": { "token": token } }),
    );
    let (reply, _, _) = played(&mut core, 11, &owners, &mut unused);
    assert_eq!(reply["result"]["collected"], 0, "{reply}");

    // The Ledger owner, the vault still locked: the eight reads, then the
    // lane, fc-ledger's stream over the pending SafeTx.
    let mut ledger = signing(hash);
    send(
        &mut core,
        12,
        "chrome",
        "safe.sign_owner",
        json!({ "safe": index, "owner": ledger_index, "safe_tx_hash": prepared["safe_tx_hash"] }),
    );
    let (reply, methods, apdus) = played(&mut core, 12, &owners, &mut ledger);
    let state = &reply["result"];
    assert_eq!(state["collected"], 1, "{reply}");
    assert_eq!(methods.len(), 16, "{methods:?}");
    assert_eq!(methods[14..], ["eth_call"; 2], "the nonce last");
    lane_shape(&apdus, 12);
    let file: Value = serde_json::from_str(
        &std::fs::read_to_string(core.grant_root.join("safe-pending.json")).unwrap(),
    )
    .unwrap();
    let entry = &file[index.to_string()];
    let sent: Vec<Vec<u8>> = apdus.iter().map(|asked| asked.apdu.clone()).collect();
    assert_eq!(sent, stream(&entry["typedData"], "SafeTx", &hash));
    assert_eq!(
        entry["signatures"],
        json!([{ "signer": checksum_address(&ledger_address),
                 "data": signed_at(LEDGER_PATH, &hash) }])
    );

    // Unlocked, the board's sweep: the vault owner A, to the threshold.
    call(
        &mut core,
        13,
        "shell",
        "vault.unlock",
        json!({ "password_b64": password }),
    );
    send(
        &mut core,
        14,
        "shell",
        "safe.sign_owner",
        json!({ "safe": index }),
    );
    let (reply, methods, apdus) = played(&mut core, 14, &owners, &mut unused);
    assert_eq!(reply["result"]["collected"], 2, "{reply}");
    assert_eq!(methods.len(), 16);
    assert!(apdus.is_empty());
    let file: Value = serde_json::from_str(
        &std::fs::read_to_string(core.grant_root.join("safe-pending.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        file[index.to_string()]["signatures"][1],
        json!({ "signer": checksum_address(&owners[0]), "data": signed_at(VAULT_PATH, &hash) })
    );
    // A page never reaches it.
    send(
        &mut core,
        15,
        "page",
        "safe.sign_owner",
        json!({ "safe": index }),
    );
    assert_eq!(core.response(15)["error"]["code"], "forbidden");

    // A page's Safe message, started while the vault is locked.
    let request = json!({ "method": "personal_sign", "params": ["From a Ledger", safe_address] });
    let token = call(
        &mut core,
        16,
        "page",
        "approval.issue",
        json!({
            "kind": "safe-message", "account": index, "handle": HANDLE,
            "payload": {
                "safe": safe_address, "chain_id": "100",
                "method": "personal_sign", "params": request["params"],
            },
        }),
    )["token"]
        .clone();
    call(&mut core, 17, "shell", "vault.lock", json!({}));
    send(
        &mut core,
        18,
        "page",
        "safe.message_start",
        json!({ "safe": index, "request": request,
                "authorization": { "token": token, "handle": HANDLE } }),
    );
    let (reply, _, _) = played(&mut core, 18, &owners, &mut unused);
    let session = reply["result"]["session"].as_str().unwrap().to_owned();
    let message_hash = hash_of(&reply["result"]["state"]["hash"]);
    assert_eq!(reply["result"]["state"]["collected"], 0, "{reply}");
    let mut ledger = signing(message_hash);
    send(
        &mut core,
        19,
        "chrome",
        "safe.message_sign",
        json!({ "safe": index, "session": session, "owner": ledger_index }),
    );
    let (reply, methods, apdus) = played(&mut core, 19, &owners, &mut ledger);
    assert_eq!(reply["result"]["collected"], 1, "{reply}");
    assert_eq!(methods.len(), 16);
    lane_shape(&apdus, 19);
    let digest = fc_evm::eip191_digest(b"From a Ledger");
    let typed = fc_safe::SafeMessage::new(digest).typed_data(&setup.address(&U256::from_u64(7)));
    let sent: Vec<Vec<u8>> = apdus.iter().map(|asked| asked.apdu.clone()).collect();
    assert_eq!(sent, stream(&typed, "SafeMessage", &message_hash));
    call(
        &mut core,
        20,
        "shell",
        "vault.unlock",
        json!({ "password_b64": password }),
    );
    send(
        &mut core,
        21,
        "shell",
        "safe.message_sign",
        json!({ "safe": index, "session": session }),
    );
    let (reply, _, _) = played(&mut core, 21, &owners, &mut unused);
    assert_eq!(reply["result"]["complete"], true, "{reply}");
    let done = call(
        &mut core,
        22,
        "shell",
        "safe.message_complete",
        json!({ "safe": index, "session": session }),
    );
    // The reference's join: one signature per owner, sorted by owner.
    let mut joined = Signatures::new();
    for (path, owner) in [(LEDGER_PATH, ledger_address), (VAULT_PATH, owners[0])] {
        let signature = signature_at(path, &message_hash);
        joined.add(OwnerSignature::check(&message_hash, &signature, &owner, &owners).unwrap());
    }
    assert_eq!(done["signature"], to_hex(&joined.joined()));
}
