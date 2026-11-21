//! A page request's wallet list is the core's own once `vault_meta` is
//! moved (G20b): the dispatcher reads `accounts.list`'s list, read only from
//! the records' snapshot with its mnemonic addresses derived against the
//! vault state the snapshot belongs to (the stored ones while locked), and
//! the record's active index, in place of main's `world.wallets` and
//! `world.active`. So a Ledger main calls a mnemonic account still takes
//! the device path, `eth_accounts` and a connect's offer are the core's,
//! and an approve's `world` is replaced too. Without the name main's list
//! stands, as before.
//!
//! The list belongs to one vault: an import held after its new metadata is
//! on disk still answers the old vault's list, the new one once the loop
//! has the result, and none while a failed install's journal remains.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// A second vault's mnemonic (BIP-39's test vectors).
const LEGAL: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const SAFE: &str = "0x4444444444444444444444444444444444444444";
const TO: &str = "0xabababababababababababababababababababab";
const GWEI: u64 = 1_000_000_000;

/// The records' indices, as `accounts.add_*` hands them out.
const LEDGER: u32 = 1_000_000;
const PHONE: u32 = 1_000_001;
const SAFE_INDEX: u32 = 1_000_002;
/// A mnemonic record whose stored address isn't its key's.
const SPARE: u32 = 4;

fn bytes_of(mnemonic: &str, index: u32) -> [u8; 20] {
    let seed = fc_keys::Mnemonic::parse(mnemonic).unwrap().to_seed();
    let key = fc_keys::freedom::derive_user_wallet(&seed, index).unwrap();
    fc_evm::address_of(key.signing_key())
}

/// `mnemonic`'s account `index`, checksummed.
fn address_of(mnemonic: &str, index: u32) -> String {
    fc_evm::checksum_address(&bytes_of(mnemonic, index))
}

/// The abandon vault's account `index`: a device's address, or the vault's.
fn address(index: u32) -> String {
    address_of(ABANDON, index)
}

fn site(name: &str) -> String {
    format!("https://{name}.example")
}

/// The dApp store holding each `(site, walletIndex)`.
fn grants(entries: &[(&str, u32)]) -> Value {
    let map: serde_json::Map<String, Value> = entries
        .iter()
        .map(|(name, index)| {
            let entry = json!({
                "origin": site(name), "connectedAt": 1_763_000_000_000_u64,
                "lastUsed": 1_763_000_000_000_u64, "walletIndex": index, "chainId": 100,
                "autoApprove": { "signing": false, "transactions": [] },
            });
            (site(name), entry)
        })
        .collect();
    Value::Object(map)
}

/// A core over `root` whose dApp store has moved holding `grants`, with
/// `vault_meta` moved or not, and the abandon vault imported.
fn start(root: &Path, moved: bool, grants: &Value, env: &[(&str, &str)]) -> (Core, u64) {
    let mut core = spawn_env(
        "serve",
        &root.join("identity"),
        &root.join("locks"),
        &[],
        env,
    );
    std::fs::create_dir_all(&core.grant_root).unwrap();
    let text = serde_json::to_string_pretty(grants).unwrap();
    std::fs::write(core.grant_root.join("dapp-permissions.json"), text).unwrap();
    core.grant_moved = vec!["dapp"];
    if moved {
        core.store_moved = vec!["vault_meta"];
    }
    let hello = core.hello();
    assert!(hello["result"].is_object(), "{hello}");
    let mut id = 10;
    import(&mut core, &mut id, ABANDON);
    (core, id)
}

fn call(core: &mut Core, id: &mut u64, method: &str, params: Value) -> Value {
    *id += 1;
    core.send(&json!({
        "type": "request", "id": *id, "method": method, "params": params,
        "context": { "caller": "shell" },
    }));
    core.response(*id)
}

fn result(reply: &Value) -> &Value {
    assert!(reply["result"].is_object(), "{reply}");
    &reply["result"]
}

fn import_params(mnemonic: &str) -> Value {
    json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(mnemonic),
        "overwrite": true, "user_knows_password": true })
}

fn import(core: &mut Core, id: &mut u64, mnemonic: &str) -> Value {
    let reply = call(core, id, "vault.import", import_params(mnemonic));
    result(&reply);
    reply
}

fn add(core: &mut Core, id: &mut u64, method: &str, params: Value) -> u32 {
    let reply = call(core, id, method, params);
    result(&reply)["wallet"]["index"].as_u64().unwrap() as u32
}

fn meta_path(root: &Path) -> std::path::PathBuf {
    root.join("identity").join("vault-meta.json")
}

/// The core's records: a Ledger, a phone and an undeployed Safe beside the
/// vault's main account, then a mnemonic record at [`SPARE`] storing
/// another key's address, added to the file and taken in by the next
/// `accounts.*` request.
fn add_records(core: &mut Core, id: &mut u64, root: &Path) {
    let ledger = add(
        core,
        id,
        "accounts.add_ledger",
        json!({ "address": address(7), "path": "44'/60'/0'/0/0" }),
    );
    let phone = add(
        core,
        id,
        "accounts.add_remote",
        json!({ "address": address(9) }),
    );
    let safe = add(
        core,
        id,
        "accounts.add_safe",
        json!({ "address": SAFE, "owners": [0, LEDGER], "threshold": 1, "salt_nonce": "0" }),
    );
    assert_eq!((ledger, phone, safe), (LEDGER, PHONE, SAFE_INDEX));
    let mut meta: Value =
        serde_json::from_str(&std::fs::read_to_string(meta_path(root)).unwrap()).unwrap();
    meta["derivedWallets"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "index": SPARE, "name": "Spare", "address": address(11) }));
    std::fs::write(meta_path(root), serde_json::to_string(&meta).unwrap()).unwrap();
    result(&call(core, id, "accounts.list", json!({})));
}

fn context(key: &str) -> Value {
    json!({ "caller": "page", "page": {
        "origin": key, "top_origin": key, "frame": 1, "navigation": 1, "agent": false,
    } })
}

/// Main's world: `wallets` as main lists them, on Gnosis.
fn world(wallets: Value) -> Value {
    json!({
        "enabled": true, "window_chain": 100, "active": 0, "paused": true, "wallets": wallets,
        "networks": { "100": { "name": "Gnosis", "available": true, "symbol": "xDAI" } },
    })
}

fn ask(core: &mut Core, id: &mut u64, key: &str, body: Value) -> u64 {
    *id += 1;
    core.send(&json!({
        "type": "request", "id": *id, "method": "eip1193.request",
        "params": body, "context": context(key),
    }));
    *id
}

/// What main sees next of page request `id`: the core's prompt, or the
/// request's answer. A chain read is answered as a node would.
fn next(core: &mut Core, id: u64) -> Value {
    loop {
        let message = core.recv();
        match (message["type"].as_str(), message["method"].as_str()) {
            (Some("event"), _) => {}
            (Some("request"), Some("shell.rpc")) => {
                let answer = node(&message);
                core.send(&json!({ "type": "response", "id": message["id"], "result": answer }));
            }
            (Some("request"), Some("approval.request")) => return message,
            (Some("response"), _) if message["id"] == id => return message,
            _ => panic!("unexpected {message}"),
        }
    }
}

/// A node's answer to a chain read: the estimate, the gas price and the
/// priority fee.
fn node(request: &Value) -> Value {
    let body: Value = serde_json::from_str(request["params"]["body"].as_str().unwrap()).unwrap();
    let outcome = match body["method"].as_str().unwrap() {
        "eth_estimateGas" => json!({ "result": "0x5208" }),
        "eth_gasPrice" => json!({ "result": format!("{:#x}", 16 * GWEI) }),
        "eth_maxPriorityFeePerGas" => json!({ "result": format!("{:#x}", 2 * GWEI) }),
        _ => json!({ "error": { "code": -32601, "message": "the method does not exist" } }),
    };
    let mut text = json!({ "jsonrpc": "2.0", "id": body["id"] });
    for (key, value) in outcome.as_object().unwrap() {
        text[key] = value.clone();
    }
    json!({ "status": 200, "body": STANDARD.encode(text.to_string()) })
}

/// The page's answer to request `id`.
fn answered(core: &mut Core, id: u64) -> Value {
    let reply = next(core, id);
    assert_eq!(reply["type"], "response", "{reply}");
    reply["result"].clone()
}

/// `eth_accounts` for `key`.
fn accounts(core: &mut Core, id: &mut u64, key: &str, wallets: &Value) -> Value {
    let sent = ask(
        core,
        id,
        key,
        json!({ "method": "eth_accounts", "world": world(wallets.clone()) }),
    );
    answered(core, sent)["result"].clone()
}

/// Main approves prompt `asked` with `choices`, sending `wallets` as its
/// world: the page's answer.
fn approve(core: &mut Core, id: u64, asked: &Value, choices: Value, wallets: Value) -> Value {
    let handle = format!("{:064x}", 1000 + asked["id"].as_u64().unwrap());
    let answer = json!({ "prompt": asked["params"]["prompt"], "handle": handle,
        "approve": true, "choices": choices, "world": world(wallets) });
    core.send(&json!({ "type": "response", "id": asked["id"], "result": answer }));
    answered(core, id)
}

fn wallet(index: u32, address: &str, kind: &str) -> Value {
    json!({ "index": index, "name": "W", "address": address, "type": kind })
}

/// Main calls the Ledger a mnemonic account: once moved, the core's record
/// sends a signature down the device path (`{ device }`, nothing signed),
/// and a Safe's send to its prompt unquoted. Without the name, main's word
/// takes both to the vault, as before: the signature is the vault's key at
/// the Ledger's index, and the send is quoted first.
#[test]
fn a_device_main_calls_mnemonic_takes_the_device_path() {
    let entries = [("ledger", LEDGER), ("safe", SAFE_INDEX)];
    let main_says = json!([
        wallet(0, &address(0), "mnemonic"),
        wallet(LEDGER, &address(7), "mnemonic"),
        wallet(SAFE_INDEX, SAFE, "mnemonic"),
    ]);
    let sign = json!({ "method": "personal_sign", "params": ["0x68656c6c6f", address(7)],
        "world": world(main_says.clone()) });
    let send = json!({ "method": "eth_sendTransaction", "world": world(main_says.clone()),
        "params": [{ "to": TO, "value": "0x1", "data": "0x" }] });
    for moved in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let (mut core, mut id) = start(root.path(), moved, &grants(&entries), &[]);
        if moved {
            add_records(&mut core, &mut id, root.path());
        }
        let sent = ask(&mut core, &mut id, &site("ledger"), sign.clone());
        let asked = next(&mut core, sent);
        assert_eq!(asked["params"]["kind"], "eth.sign", "{asked}");
        let account = &asked["params"]["view"]["account"];
        let signed = approve(&mut core, sent, &asked, json!({}), main_says.clone());
        if moved {
            assert_eq!(account["type"], "ledger", "{asked}");
            assert_eq!(
                asked["params"]["choices"],
                json!({ "alwaysAllow": [false] })
            );
            let device = &signed["device"];
            assert_eq!(device["type"], "ledger", "{signed}");
            assert_eq!(device["account"], LEDGER, "{signed}");
            assert_eq!(device["kind"], "sign-message", "{signed}");
        } else {
            assert_eq!(account["type"], "mnemonic", "{asked}");
            let text = signed["result"].as_str().unwrap();
            let signature: [u8; 65] = fc_evm::parse_bytes(text, "signature")
                .unwrap()
                .try_into()
                .unwrap();
            let digest = fc_evm::eip191_digest(b"hello");
            let signer = fc_evm::recover_address(&digest, &signature).unwrap();
            assert_eq!(signer, bytes_of(ABANDON, LEDGER), "{signed}");
        }

        // The Safe's send.
        if !moved {
            let chains = [json!({
                "chain_id": 100, "display_name": "Gnosis",
                "read_order": ["direct"], "broadcast_order": ["direct"],
                "quorum": { "k": 3, "m": 2, "timeout_ms": 5000 },
                "rpc": [{ "endpoint": "e100", "user_configured": false }],
                "prover": null, "myotis": false, "blockscout": null,
            })];
            result(&call(
                &mut core,
                &mut id,
                "chain.configure",
                json!({ "chains": chains }),
            ));
        }
        let sent = ask(&mut core, &mut id, &site("safe"), send.clone());
        let asked = next(&mut core, sent);
        assert_eq!(asked["method"], "approval.request", "{asked}");
        let account = &asked["params"]["view"]["account"];
        if moved {
            assert_eq!(account["type"], "safe", "{asked}");
            assert_eq!(
                asked["params"]["view"]["fee"]["paidBy"], "executor",
                "{asked}"
            );
            let approved = approve(&mut core, sent, &asked, json!({}), main_says.clone());
            let device = &approved["device"];
            assert_eq!(device["type"], "safe", "{approved}");
            assert_eq!(device["kind"], "safe-send", "{approved}");
            assert_eq!(device["account"], SAFE_INDEX, "{approved}");
        } else {
            assert_eq!(account["type"], "mnemonic", "{asked}");
            assert!(
                asked["params"]["view"]["fee"]["estimate"].is_string(),
                "{asked}"
            );
        }
    }
}

/// `eth_accounts` and a connect read the core's list once moved: the
/// record's address for a grant's index, nothing for an index only main
/// lists, the mnemonic accounts' addresses derived while unlocked and
/// stored while locked; the connect offers the core's connectable accounts
/// with its active index the default, and its approve takes the account
/// from the core's list though main's answer lacks it. Without the name,
/// main's list answers.
#[test]
fn accounts_and_a_connect_read_the_core_s_list() {
    let entries = [("ledger", LEDGER), ("seven", 7), ("spare", SPARE)];
    // Main's list: wrong addresses, and an index the core doesn't have.
    let main_says = json!([
        wallet(0, &address(5), "mnemonic"),
        wallet(LEDGER, &address(9), "ledger"),
        wallet(7, &address(7), "mnemonic"),
        wallet(SPARE, &address(12), "mnemonic"),
    ]);
    let root = tempfile::tempdir().unwrap();
    let (mut core, mut id) = start(root.path(), true, &grants(&entries), &[]);
    add_records(&mut core, &mut id, root.path());
    result(&call(
        &mut core,
        &mut id,
        "accounts.set_active",
        json!({ "index": PHONE }),
    ));
    assert_eq!(
        accounts(&mut core, &mut id, &site("ledger"), &main_says),
        json!([address(7)])
    );
    assert_eq!(
        accounts(&mut core, &mut id, &site("seven"), &main_says),
        json!([])
    );
    assert_eq!(
        accounts(&mut core, &mut id, &site("spare"), &main_says),
        json!([address(SPARE)])
    );
    result(&call(&mut core, &mut id, "vault.lock", json!({})));
    assert_eq!(
        accounts(&mut core, &mut id, &site("spare"), &main_says),
        json!([address(11)])
    );
    result(&call(
        &mut core,
        &mut id,
        "vault.unlock",
        json!({ "password_b64": STANDARD.encode("testpass1") }),
    ));

    // A connect: the core's accounts (the undeployed Safe can't serve a
    // dApp), its active index the default.
    let body = json!({ "method": "eth_requestAccounts", "world": world(main_says.clone()) });
    let sent = ask(&mut core, &mut id, &site("new"), body.clone());
    let asked = next(&mut core, sent);
    assert_eq!(asked["params"]["kind"], "eth.connect", "{asked}");
    let view = &asked["params"]["view"];
    let offered: Vec<(Value, Value)> = view["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|account| (account["index"].clone(), account["address"].clone()))
        .collect();
    assert_eq!(
        offered,
        [
            (json!(0), json!(address(0))),
            (json!(LEDGER), json!(address(7))),
            (json!(PHONE), json!(address(9))),
            (json!(SPARE), json!(address(SPARE))),
        ]
    );
    assert_eq!(view["defaultIndex"], PHONE, "{asked}");
    assert_eq!(
        asked["params"]["choices"],
        json!({ "walletIndex": [0, LEDGER, PHONE, SPARE] })
    );
    // Main's answer lists no Ledger: the core's list still has it.
    let main_answers = json!([wallet(0, &address(5), "mnemonic")]);
    let connected = approve(
        &mut core,
        sent,
        &asked,
        json!({ "walletIndex": LEDGER }),
        main_answers,
    );
    assert_eq!(connected["result"], json!([address(7)]), "{connected}");
    let written: Value = serde_json::from_str(
        &std::fs::read_to_string(core.grant_root.join("dapp-permissions.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(written[site("new")]["walletIndex"], LEDGER);
    drop(core);

    // Without the name: main's list, as before.
    let root = tempfile::tempdir().unwrap();
    let (mut core, mut id) = start(root.path(), false, &grants(&entries), &[]);
    assert_eq!(
        accounts(&mut core, &mut id, &site("ledger"), &main_says),
        json!([address(9)])
    );
    assert_eq!(
        accounts(&mut core, &mut id, &site("seven"), &main_says),
        json!([address(7)])
    );
    let sent = ask(&mut core, &mut id, &site("new"), body);
    let asked = next(&mut core, sent);
    assert_eq!(
        asked["params"]["choices"],
        json!({ "walletIndex": [0, LEDGER, 7, SPARE] })
    );
    assert_eq!(asked["params"]["view"]["defaultIndex"], 0, "{asked}");
}

fn wait_for(path: &Path) {
    let until = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(Instant::now() < until, "{} never came", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The list belongs to the vault the request runs against: an import held
/// after its new metadata is installed still answers the old vault's
/// address and its phone, and the new vault's once the loop has its
/// result. A failed install leaves its journal: the list is empty, as
/// main's `walletList` reads a failing list, until recovery finishes it.
#[test]
fn a_request_reads_one_vault_s_list_through_an_import() {
    let root = tempfile::tempdir().unwrap();
    let hold = root.path().join("hold");
    let fail = root.path().join("fail");
    std::fs::write(&hold, "").unwrap();
    std::fs::write(&fail, "").unwrap();
    let env = [
        ("FREEDOM_CORED_TEST_STEP_HOLD", hold.to_str().unwrap()),
        (
            "FREEDOM_CORED_TEST_GRANT_WRITE_FAIL",
            fail.to_str().unwrap(),
        ),
    ];
    let entries = [("main", 0), ("phone", LEDGER)];
    let (mut core, mut id) = start(root.path(), true, &grants(&entries), &env);
    let phone = add(
        &mut core,
        &mut id,
        "accounts.add_remote",
        json!({ "address": address(9) }),
    );
    assert_eq!(phone, LEDGER);
    let none = json!([]);
    let seen = |core: &mut Core, id: &mut u64| {
        (
            accounts(core, id, &site("main"), &none),
            accounts(core, id, &site("phone"), &none),
        )
    };
    let old = (json!([address(0)]), json!([address(9)]));
    assert_eq!(seen(&mut core, &mut id), old);
    std::fs::write(&hold, "after-meta-install-meta").unwrap();
    id += 1;
    let importing = id;
    core.send(&json!({
        "type": "request", "id": importing, "method": "vault.import",
        "params": import_params(LEGAL), "context": { "caller": "shell" },
    }));
    let held = root.path().join("hold.held");
    wait_for(&held);
    let on_disk = std::fs::read_to_string(meta_path(root.path())).unwrap();
    assert!(!on_disk.contains(&address(9)), "{on_disk}");
    assert_eq!(seen(&mut core, &mut id), old);
    std::fs::write(root.path().join("hold.release"), "").unwrap();
    let imported = core.until_response(importing);
    result(&imported);
    std::fs::write(&hold, "").unwrap();
    assert_eq!(
        seen(&mut core, &mut id),
        (json!([address_of(LEGAL, 0)]), json!([]))
    );

    // A failed install: its journal stays, and the list is empty.
    std::fs::write(&fail, "vault_meta_journal:meta-rename\n").unwrap();
    let imported = import(&mut core, &mut id, ABANDON);
    assert_eq!(imported["result"]["durable"], false, "{imported}");
    assert_eq!(seen(&mut core, &mut id), (json!([]), json!([])));
    std::fs::write(&fail, "").unwrap();
    result(&call(&mut core, &mut id, "accounts.list", json!({})));
    assert_eq!(seen(&mut core, &mut id), (json!([address(0)]), json!([])));
}
