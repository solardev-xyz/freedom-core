//! The core reads its own account records (G20): once `core.hello` names
//! `vault_meta` in `store_moved`, the checks that took main's word on an
//! account's kind or address read `vault-meta.json`'s record instead, and
//! refuse a claim that disagrees: `approval.issue`'s `phone`,
//! `approval.check`'s `account_kind`, `x402.authorize`'s `device` and
//! `phone.job`'s `address`. Without the name main owns the file, and the
//! same claims, against the same file, are taken as before.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SITE: &str = "https://app.example";
const SELLER: &str = "https://paid.example";
const USDC: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAY_TO: &str = "0x209693bc6afc0c5328ba36faf03c514ef312287c";
const TO: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const SAFE: &str = "0x1111111111111111111111111111111111111111";

/// The records' indices.
const LEDGER: u32 = 1_000_000;
const PHONE: u32 = 1_000_001;
const SAFE_INDEX: u32 = 1_000_002;
/// A hardware index no record holds (a deleted device's).
const GONE: u32 = 1_000_009;

fn key(index: u32) -> fc_keys::Secp256k1Key {
    let seed = fc_keys::Mnemonic::parse(ABANDON).unwrap().to_seed();
    fc_keys::freedom::derive_user_wallet(&seed, index).unwrap()
}

/// A device's address: the abandon mnemonic's account `index`, checksummed.
fn address(index: u32) -> String {
    fc_evm::checksum_address(&fc_evm::address_of(key(index).signing_key()))
}

fn ledger_address() -> String {
    address(7)
}

fn phone_address() -> String {
    address(9)
}

fn shell() -> Value {
    json!({ "caller": "shell" })
}

fn page() -> Value {
    json!({ "caller": "page", "page": {
        "origin": SITE, "top_origin": SITE, "frame": 1, "navigation": 1, "agent": false,
    } })
}

fn call_as(core: &mut Core, id: &mut u64, context: &Value, method: &str, params: Value) -> Value {
    *id += 1;
    core.send(&json!({
        "type": "request", "id": *id, "method": method, "params": params, "context": context,
    }));
    core.response(*id)
}

fn call(core: &mut Core, id: &mut u64, method: &str, params: Value) -> Value {
    call_as(core, id, &shell(), method, params)
}

fn result(reply: &Value) -> &Value {
    assert!(reply["result"].is_object(), "{reply}");
    &reply["result"]
}

/// Refused `invalid_argument` for the account's record.
fn disagrees(reply: &Value) {
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
    let message = reply["error"]["message"].as_str().unwrap();
    assert!(message.ends_with("(vault-meta.json)"), "{reply}");
}

fn meta_path(root: &Path) -> PathBuf {
    root.join("identity").join("vault-meta.json")
}

/// The records: the vault's main account, a Ledger, a phone and a Safe.
fn write_records(root: &Path) {
    let text = serde_json::to_string_pretty(&json!({
        "userKnowsPassword": true,
        "createdAt": "2026-11-21T00:00:00.000Z",
        "addresses": { "userWallet": address(0), "beeWallet": address(1) },
        "derivedWallets": [
            { "index": 0, "name": "Main Wallet", "address": address(0) },
            { "index": LEDGER, "name": "Ledger", "address": ledger_address(), "type": "ledger",
              "path": "44'/60'/0'/0/0", "addressCheck": "matched" },
            { "index": PHONE, "name": "Phone", "address": phone_address(), "type": "remote",
              "addressCheck": "matched" },
            { "index": SAFE_INDEX, "name": "Safe", "address": SAFE, "type": "safe",
              "owners": [0, LEDGER], "threshold": 1, "saltNonce": "0", "deployed": {} },
        ],
        "activeWalletIndex": 0,
        "nextHardwareWalletIndex": SAFE_INDEX + 1,
    }))
    .unwrap();
    std::fs::create_dir_all(root.join("identity")).unwrap();
    std::fs::write(meta_path(root), text).unwrap();
}

/// A core over `root`, `vault_meta` moved or not, with `grant_moved`.
fn start(root: &Path, moved: bool, grants: &[&'static str]) -> Core {
    let mut core = spawn_env(
        "serve",
        &root.join("identity"),
        &root.join("locks"),
        &[],
        &[],
    );
    std::fs::create_dir_all(&core.grant_root).unwrap();
    if moved {
        core.store_moved = vec!["vault_meta"];
    }
    core.grant_moved = grants.to_vec();
    let hello = core.hello();
    let echo = if moved {
        json!(["vault_meta"])
    } else {
        json!([])
    };
    assert_eq!(hello["result"]["store_moved"], echo, "{hello}");
    core
}

/// The abandon vault, imported and unlocked; then the records in place of
/// the file the import wrote.
fn unlocked(root: &Path, core: &mut Core, id: &mut u64) {
    let reply = call(
        core,
        id,
        "vault.import",
        json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(ABANDON),
            "overwrite": true, "user_knows_password": true }),
    );
    assert!(reply["result"].is_object(), "{reply}");
    write_records(root);
}

fn send(account: u32, phone: Option<bool>) -> Value {
    let mut params = json!({ "kind": "wallet-send", "account": account, "payload": { "tx": {
        "type": 2, "chain_id": "1", "gas_limit": "21000", "to": TO, "value": "1", "data": "0x",
        "max_fee_per_gas": "7000000000", "max_priority_fee_per_gas": "1000000000",
    } } });
    if let Some(phone) = phone {
        params["phone"] = json!(phone);
    }
    params
}

/// Minted: whether the fee check judged it.
fn fee_checked(reply: &Value) -> bool {
    assert!(result(reply)["token"].is_string(), "{reply}");
    result(reply).get("fee_check").is_some()
}

/// `approval.issue`'s `phone`: with `vault_meta` moved it must be the
/// record's, either way; without, main's word skips the fee check even for
/// an account the file says is the vault's.
#[test]
fn a_send_s_phone_flag_is_the_record_s() {
    let root = tempfile::tempdir().unwrap();
    write_records(root.path());
    let mut core = start(root.path(), true, &[]);
    let mut id = 10;
    // Agreeing: a phone's send skips the fee check, a vault's is judged.
    assert!(!fee_checked(&call(
        &mut core,
        &mut id,
        "approval.issue",
        send(PHONE, Some(true))
    )));
    assert!(fee_checked(&call(
        &mut core,
        &mut id,
        "approval.issue",
        send(0, None)
    )));
    assert!(fee_checked(&call(
        &mut core,
        &mut id,
        "approval.issue",
        send(0, Some(false))
    )));
    assert!(fee_checked(&call(
        &mut core,
        &mut id,
        "approval.issue",
        send(LEDGER, None)
    )));
    // Disagreeing: refused, nothing minted.
    for (account, phone) in [
        (0, Some(true)),
        (1, Some(true)),
        (LEDGER, Some(true)),
        (SAFE_INDEX, Some(true)),
        (GONE, Some(true)),
        (PHONE, None),
        (PHONE, Some(false)),
    ] {
        let reply = call(&mut core, &mut id, "approval.issue", send(account, phone));
        disagrees(&reply);
    }
    // A record changed under the core is read at the next request.
    std::fs::write(meta_path(root.path()), b"{}").unwrap();
    disagrees(&call(
        &mut core,
        &mut id,
        "approval.issue",
        send(PHONE, Some(true)),
    ));
    assert!(fee_checked(&call(
        &mut core,
        &mut id,
        "approval.issue",
        send(PHONE, None)
    )));
    drop(core);

    // Main's file, main's word: the same claims, against the same records.
    let root = tempfile::tempdir().unwrap();
    write_records(root.path());
    let mut core = start(root.path(), false, &[]);
    let mut id = 10;
    assert!(!fee_checked(&call(
        &mut core,
        &mut id,
        "approval.issue",
        send(0, Some(true))
    )));
    assert!(!fee_checked(&call(
        &mut core,
        &mut id,
        "approval.issue",
        send(GONE, Some(true))
    )));
    assert!(fee_checked(&call(
        &mut core,
        &mut id,
        "approval.issue",
        send(PHONE, None)
    )));
}

fn check(core: &mut Core, id: &mut u64, account: u32, kind: &str) -> Value {
    call_as(
        core,
        id,
        &page(),
        "approval.check",
        json!({ "request": { "kind": "message", "account": account, "account_kind": kind,
            "message": "0x68656c6c6f" } }),
    )
}

/// `approval.check`'s `account_kind`: the record's once moved, main's word
/// before.
#[test]
fn a_check_s_account_kind_is_the_record_s() {
    let root = tempfile::tempdir().unwrap();
    write_records(root.path());
    let mut core = start(root.path(), true, &[]);
    let mut id = 10;
    for (account, kind) in [
        (0, "vault"),
        (1, "vault"),
        (LEDGER, "ledger"),
        (PHONE, "phone"),
        (SAFE_INDEX, "safe"),
    ] {
        let reply = check(&mut core, &mut id, account, kind);
        assert_eq!(result(&reply)["covered"], false, "{account} {kind}");
    }
    for (account, kind) in [
        (0, "phone"),
        (0, "ledger"),
        (LEDGER, "vault"),
        (PHONE, "vault"),
        (PHONE, "ledger"),
        (SAFE_INDEX, "vault"),
        (GONE, "vault"),
        (GONE, "ledger"),
    ] {
        disagrees(&check(&mut core, &mut id, account, kind));
    }
    drop(core);

    let root = tempfile::tempdir().unwrap();
    write_records(root.path());
    let mut core = start(root.path(), false, &[]);
    let mut id = 10;
    for (account, kind) in [(0, "phone"), (PHONE, "vault"), (GONE, "ledger")] {
        let reply = check(&mut core, &mut id, account, kind);
        assert_eq!(result(&reply)["covered"], false, "{account} {kind}");
    }
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A cap over USDC on Base for the seller, `30000` with none spent.
fn cap_file(root: &Path) {
    let now = now_s();
    let dir = root.join("userData");
    std::fs::create_dir_all(&dir).unwrap();
    let key = format!("8453:{}", USDC.to_lowercase());
    let text = serde_json::to_string_pretty(&json!({ SELLER: { key: {
        "capAmount": "30000", "spentAmount": "0", "createdAt": now - 100, "expiresAt": now + 3600,
    } } }))
    .unwrap();
    std::fs::write(dir.join("x402-permissions.json"), text).unwrap();
}

fn spent(root: &Path) -> String {
    let text =
        std::fs::read_to_string(root.join("userData").join("x402-permissions.json")).unwrap();
    let caps: Value = serde_json::from_str(&text).unwrap();
    let key = format!("8453:{}", USDC.to_lowercase());
    caps[SELLER][key]["spentAmount"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// A payment of `1000` from `account` under the cap, with `device`.
fn pay(core: &mut Core, id: &mut u64, account: u32, device: Option<Value>) -> Value {
    *id += 1;
    let mut params = json!({
        "account": account,
        "detection": { "tab": 1, "id": format!("d{id}"), "url": format!("{SELLER}/a") },
        "requirements": {
            "x402Version": 2,
            "resource": { "url": format!("{SELLER}/a"), "description": "An article" },
            "accepts": [{
                "scheme": "exact", "network": "eip155:8453", "amount": "1000", "asset": USDC,
                "payTo": PAY_TO, "maxTimeoutSeconds": 60,
                "extra": { "name": "USD Coin", "version": "2" },
            }],
        },
        "authorization": { "cap": { "agent": false, "attributable": true } },
    });
    if let Some(device) = device {
        params["device"] = device;
    }
    call(core, id, "x402.authorize", params)
}

fn device(kind: &str, address: &str) -> Option<Value> {
    Some(json!({ "kind": kind, "address": address }))
}

/// Handed to the device at `from`, the cap charged.
fn handed(reply: &Value, from: &str) {
    let typed = &result(reply)["device"]["typed_data"];
    assert_eq!(typed["message"]["from"], from, "{reply}");
    assert_eq!(result(reply)["charged"], true);
}

/// `x402.authorize`'s `device`: once moved, the record's as the
/// reference's `paymentDevice` names it, and a request that disagrees is
/// refused before the cap is charged; before, main's word.
#[test]
fn a_payment_s_device_is_the_record_s() {
    let root = tempfile::tempdir().unwrap();
    cap_file(root.path());
    let mut core = start(root.path(), true, &["x402"]);
    let mut id = 10;
    unlocked(root.path(), &mut core, &mut id);
    // Agreeing: a Ledger's and a phone's at their records' addresses (any
    // case), and the vault's with no device, signed by the core.
    handed(
        &pay(
            &mut core,
            &mut id,
            LEDGER,
            device("ledger", &ledger_address()),
        ),
        &ledger_address(),
    );
    handed(
        &pay(
            &mut core,
            &mut id,
            PHONE,
            device("phone", &phone_address().to_lowercase()),
        ),
        &phone_address(),
    );
    let paid = pay(&mut core, &mut id, 0, None);
    assert!(result(&paid)["payload"].is_object(), "{paid}");
    assert_eq!(spent(root.path()), "3000");
    // Disagreeing: refused, and the cap isn't charged.
    for (account, claimed) in [
        (LEDGER, None),
        (LEDGER, device("phone", &ledger_address())),
        (LEDGER, device("ledger", &phone_address())),
        (PHONE, None),
        (PHONE, device("ledger", &phone_address())),
        (PHONE, device("phone", &ledger_address())),
        (0, device("ledger", &ledger_address())),
        (0, device("phone", &address(0))),
        (SAFE_INDEX, None),
        (SAFE_INDEX, device("ledger", SAFE)),
        (GONE, None),
        (GONE, device("ledger", &ledger_address())),
    ] {
        let reply = pay(&mut core, &mut id, account, claimed.clone());
        disagrees(&reply);
        assert_eq!(spent(root.path()), "3000", "{account} {claimed:?}");
    }
    drop(core);

    // Main's word: a device for an account the file says is the vault's.
    let root = tempfile::tempdir().unwrap();
    cap_file(root.path());
    write_records(root.path());
    let mut core = start(root.path(), false, &["x402"]);
    let mut id = 10;
    handed(
        &pay(&mut core, &mut id, 0, device("phone", &phone_address())),
        &phone_address(),
    );
    handed(
        &pay(
            &mut core,
            &mut id,
            GONE,
            device("ledger", &ledger_address()),
        ),
        &ledger_address(),
    );
    assert_eq!(spent(root.path()), "2000");
}

fn job(core: &mut Core, id: &mut u64, account: u32, address: &str) -> Value {
    call(
        core,
        id,
        "phone.job",
        json!({ "account": account, "address": address, "method": "message",
            "payload": { "message": "0x68656c6c6f" }, "target": 42 }),
    )
}

/// `phone.job`'s account and address: once moved, a phone's record and its
/// address; before, main's word.
#[test]
fn a_phone_job_s_address_is_the_record_s() {
    let root = tempfile::tempdir().unwrap();
    write_records(root.path());
    let mut core = start(root.path(), true, &[]);
    let mut id = 10;
    let opened = job(&mut core, &mut id, PHONE, &phone_address().to_lowercase());
    assert!(result(&opened)["job"].is_string(), "{opened}");
    for (account, address) in [
        (PHONE, ledger_address()),
        (LEDGER, ledger_address()),
        (0, address(0)),
        (SAFE_INDEX, SAFE.to_owned()),
        (GONE, phone_address()),
        (7, phone_address()),
    ] {
        disagrees(&job(&mut core, &mut id, account, &address));
    }
    // While a vault journal remains the file may be a replaced vault's:
    // `storage`, until it is gone.
    let journal = root.path().join("identity").join("vault-meta-journal.json");
    std::fs::write(&journal, b"{}").unwrap();
    let reply = job(&mut core, &mut id, PHONE, &phone_address());
    assert_eq!(reply["error"]["code"], "storage", "{reply}");
    assert_eq!(reply["error"]["data"]["file"], "vault_meta");
    std::fs::remove_file(&journal).unwrap();
    assert!(result(&job(&mut core, &mut id, PHONE, &phone_address()))["job"].is_string());
    // An unreadable file reads as none, and stays where it is: only the
    // store's own requests set it aside.
    std::fs::write(meta_path(root.path()), b"not json").unwrap();
    disagrees(&job(&mut core, &mut id, PHONE, &phone_address()));
    assert_eq!(std::fs::read(meta_path(root.path())).unwrap(), b"not json");
    drop(core);

    let root = tempfile::tempdir().unwrap();
    write_records(root.path());
    let mut core = start(root.path(), false, &[]);
    let mut id = 10;
    for (account, address) in [(PHONE, ledger_address()), (0, phone_address())] {
        let opened = job(&mut core, &mut id, account, &address);
        assert!(result(&opened)["job"].is_string(), "{opened}");
    }
}
