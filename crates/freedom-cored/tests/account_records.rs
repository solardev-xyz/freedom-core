//! The core reads its own account records (G20): once `core.hello` names
//! `vault_meta` in `store_moved`, the checks that took main's word on an
//! account's kind or address read `vault-meta.json`'s record instead, and
//! refuse a claim that disagrees: `approval.issue`'s `phone`,
//! `approval.check`'s `account_kind`, `x402.authorize`'s `device` and
//! `phone.job`'s `address`. Without the name main owns the file, and the
//! same claims, against the same file, are taken as before.
//!
//! The records are the loop's snapshot, bound to the vault state the
//! checks run against: a create or import held at each step of its install
//! shows the old pair, and its result the new one, never one of each.
//!
//! `sign.*` reads them too (G20b): once moved, the vault signs only for an
//! index below the hardware range with a mnemonic record or none, and
//! refuses any other with the reference's text before the key is derived.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// A second vault's mnemonic (BIP-39's test vectors).
const LEGAL: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const SITE: &str = "https://app.example";
const SELLER: &str = "https://paid.example";
const USDC: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAY_TO: &str = "0x209693bc6afc0c5328ba36faf03c514ef312287c";
const TO: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const SAFE: &str = "0x1111111111111111111111111111111111111111";

/// The records' indices, as `accounts.add_*` hands them out.
const LEDGER: u32 = 1_000_000;
const PHONE: u32 = 1_000_001;
const SAFE_INDEX: u32 = 1_000_002;
/// A hardware index no record holds (a deleted device's).
const GONE: u32 = 1_000_009;

fn key(mnemonic: &str, index: u32) -> fc_keys::Secp256k1Key {
    let seed = fc_keys::Mnemonic::parse(mnemonic).unwrap().to_seed();
    fc_keys::freedom::derive_user_wallet(&seed, index).unwrap()
}

fn bytes_of(mnemonic: &str, index: u32) -> [u8; 20] {
    fc_evm::address_of(key(mnemonic, index).signing_key())
}

/// The abandon mnemonic's account `index`, checksummed: a device's address.
fn address(index: u32) -> String {
    fc_evm::checksum_address(&bytes_of(ABANDON, index))
}

fn ledger_address() -> String {
    address(7)
}

fn phone_address() -> String {
    address(9)
}

/// ethers' `getIcapAddress`: the address as a base-36 number, at least 30
/// digits, behind `XE` and its check digits.
fn icap(bytes: &[u8; 20]) -> String {
    let mut number = bytes.to_vec();
    let mut digits = Vec::new();
    while number.iter().any(|byte| *byte != 0) {
        let mut rest = 0u32;
        for byte in number.iter_mut() {
            let value = (rest << 8) | u32::from(*byte);
            *byte = (value / 36) as u8;
            rest = value % 36;
        }
        digits.push(
            std::char::from_digit(rest, 36)
                .unwrap()
                .to_ascii_uppercase(),
        );
    }
    while digits.len() < 30 {
        digits.push('0');
    }
    let body: String = digits.iter().rev().collect();
    let mut rest = 0u32;
    for c in format!("{body}XE00").chars() {
        for digit in c.to_digit(36).unwrap().to_string().bytes() {
            rest = (rest * 10 + u32::from(digit - b'0')) % 97;
        }
    }
    format!("XE{:02}{body}", 98 - rest)
}

/// Every form ethers' `isAddress` takes for one address: checksummed, its
/// digits alone, lower and upper case with and without `0x`, and ICAP.
fn forms(bytes: &[u8; 20]) -> Vec<String> {
    let checksummed = fc_evm::checksum_address(bytes);
    vec![
        checksummed.clone(),
        checksummed[2..].to_owned(),
        checksummed.to_lowercase(),
        checksummed[2..].to_lowercase(),
        format!("0x{}", checksummed[2..].to_uppercase()),
        checksummed[2..].to_uppercase(),
        icap(bytes),
    ]
}

/// The same address with a bad checksum: one letter's case flipped.
fn bad_checksum(bytes: &[u8; 20]) -> String {
    let checksummed = fc_evm::checksum_address(bytes);
    let at = checksummed[2..]
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap()
        + 2;
    let mut flipped = checksummed.clone().into_bytes();
    flipped[at] ^= 0x20;
    String::from_utf8(flipped).unwrap()
}

fn shell() -> Value {
    json!({ "caller": "shell" })
}

fn page() -> Value {
    json!({ "caller": "page", "page": {
        "origin": SITE, "top_origin": SITE, "frame": 1, "navigation": 1, "agent": false,
    } })
}

fn send_as(core: &mut Core, id: &mut u64, context: &Value, method: &str, params: Value) -> u64 {
    *id += 1;
    core.send(&json!({
        "type": "request", "id": *id, "method": method, "params": params, "context": context,
    }));
    *id
}

fn call_as(core: &mut Core, id: &mut u64, context: &Value, method: &str, params: Value) -> Value {
    let sent = send_as(core, id, context, method, params);
    core.response(sent)
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

/// Refused `storage` for the records: a vault journal remained.
fn pending(reply: &Value) {
    assert_eq!(reply["error"]["code"], "storage", "{reply}");
    assert_eq!(reply["error"]["data"]["file"], "vault_meta", "{reply}");
}

fn meta_path(root: &Path) -> PathBuf {
    root.join("identity").join("vault-meta.json")
}

/// The records in main's file: the vault's main account, a Ledger, a phone
/// and a Safe.
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
fn start(root: &Path, moved: bool, grants: &[&'static str], env: &[(&str, &str)]) -> Core {
    let mut core = spawn_env(
        "serve",
        &root.join("identity"),
        &root.join("locks"),
        &[],
        env,
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

fn import_params(mnemonic: &str) -> Value {
    json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(mnemonic),
        "overwrite": true, "user_knows_password": true })
}

/// `mnemonic`'s vault, imported and unlocked, with its fresh metadata.
fn import(core: &mut Core, id: &mut u64, mnemonic: &str) -> Value {
    let reply = call(core, id, "vault.import", import_params(mnemonic));
    assert!(reply["result"].is_object(), "{reply}");
    reply
}

/// An `accounts.add_*`: the record's index.
fn add(core: &mut Core, id: &mut u64, method: &str, params: Value) -> u32 {
    let reply = call(core, id, method, params);
    result(&reply)["wallet"]["index"].as_u64().unwrap() as u32
}

/// The core's records, through its own methods: a Ledger, a phone and a
/// Safe beside the vault's main account.
fn add_records(core: &mut Core, id: &mut u64) {
    let ledger = add(
        core,
        id,
        "accounts.add_ledger",
        json!({ "address": ledger_address(), "path": "44'/60'/0'/0/0" }),
    );
    let phone = add(
        core,
        id,
        "accounts.add_remote",
        json!({ "address": phone_address() }),
    );
    let safe = add(
        core,
        id,
        "accounts.add_safe",
        json!({ "address": SAFE, "owners": [0, LEDGER], "threshold": 1, "salt_nonce": "0" }),
    );
    assert_eq!((ledger, phone, safe), (LEDGER, PHONE, SAFE_INDEX));
}

/// A moved core with the abandon vault and the records.
fn moved_core(root: &Path, grants: &[&'static str], env: &[(&str, &str)]) -> (Core, u64) {
    let mut core = start(root, true, grants, env);
    let mut id = 10;
    import(&mut core, &mut id, ABANDON);
    add_records(&mut core, &mut id);
    (core, id)
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

fn issue(core: &mut Core, id: &mut u64, account: u32, phone: Option<bool>) -> Value {
    call(core, id, "approval.issue", send(account, phone))
}

/// Minted: whether the fee check judged it.
fn fee_checked(reply: &Value) -> bool {
    assert!(result(reply)["token"].is_string(), "{reply}");
    result(reply).get("fee_check").is_some()
}

/// `approval.issue`'s `phone`: with `vault_meta` moved it must be the
/// record's, either way, and the record is read again after a change;
/// without, main's word skips the fee check even for an account the file
/// says is the vault's.
#[test]
fn a_send_s_phone_flag_is_the_record_s() {
    let root = tempfile::tempdir().unwrap();
    // `dapp` moved: a removal forgets the account's grants first.
    let (mut core, mut id) = moved_core(root.path(), &["dapp"], &[]);
    // Agreeing: a phone's send skips the fee check, a vault's is judged.
    assert!(!fee_checked(&issue(&mut core, &mut id, PHONE, Some(true))));
    assert!(fee_checked(&issue(&mut core, &mut id, 0, None)));
    assert!(fee_checked(&issue(&mut core, &mut id, 0, Some(false))));
    assert!(fee_checked(&issue(&mut core, &mut id, LEDGER, None)));
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
        disagrees(&issue(&mut core, &mut id, account, phone));
    }
    // The phone's record removed: the next check reads it gone.
    let removed = call(
        &mut core,
        &mut id,
        "accounts.remove",
        json!({ "index": PHONE, "swarm_references": [] }),
    );
    result(&removed);
    disagrees(&issue(&mut core, &mut id, PHONE, Some(true)));
    assert!(fee_checked(&issue(&mut core, &mut id, PHONE, None)));
    drop(core);

    // Main's file, main's word: the same claims, against the same records.
    let root = tempfile::tempdir().unwrap();
    write_records(root.path());
    let mut core = start(root.path(), false, &[], &[]);
    let mut id = 10;
    assert!(!fee_checked(&issue(&mut core, &mut id, 0, Some(true))));
    assert!(!fee_checked(&issue(&mut core, &mut id, GONE, Some(true))));
    assert!(fee_checked(&issue(&mut core, &mut id, PHONE, None)));
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

fn checked(reply: &Value) {
    assert_eq!(result(reply)["covered"], false, "{reply}");
}

/// `approval.check`'s `account_kind`: the record's once moved, main's word
/// before.
#[test]
fn a_check_s_account_kind_is_the_record_s() {
    let root = tempfile::tempdir().unwrap();
    let (mut core, mut id) = moved_core(root.path(), &[], &[]);
    for (account, kind) in [
        (0, "vault"),
        (1, "vault"),
        (LEDGER, "ledger"),
        (PHONE, "phone"),
        (SAFE_INDEX, "safe"),
    ] {
        checked(&check(&mut core, &mut id, account, kind));
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
    let mut core = start(root.path(), false, &[], &[]);
    let mut id = 10;
    for (account, kind) in [(0, "phone"), (PHONE, "vault"), (GONE, "ledger")] {
        checked(&check(&mut core, &mut id, account, kind));
    }
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn cap_key() -> String {
    format!("8453:{}", USDC.to_lowercase())
}

/// A cap over USDC on Base for the seller, `30000` with none spent.
fn cap_file(root: &Path) {
    let now = now_s();
    let dir = root.join("userData");
    std::fs::create_dir_all(&dir).unwrap();
    let text = serde_json::to_string_pretty(&json!({ SELLER: { cap_key(): {
        "capAmount": "30000", "spentAmount": "0", "createdAt": now - 100, "expiresAt": now + 3600,
    } } }))
    .unwrap();
    std::fs::write(dir.join("x402-permissions.json"), text).unwrap();
}

fn spent(root: &Path) -> String {
    let text =
        std::fs::read_to_string(root.join("userData").join("x402-permissions.json")).unwrap();
    let caps: Value = serde_json::from_str(&text).unwrap();
    caps[SELLER][cap_key()]["spentAmount"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn pay_params(id: u64, account: u32, device: Option<Value>) -> Value {
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
    params
}

/// A payment of `1000` from `account` under the cap, with `device`.
fn pay(core: &mut Core, id: &mut u64, account: u32, device: Option<Value>) -> Value {
    let params = pay_params(*id + 1, account, device);
    call(core, id, "x402.authorize", params)
}

fn device(kind: &str, address: &str) -> Option<Value> {
    Some(json!({ "kind": kind, "address": address }))
}

/// Handed to the device at `from`, the cap charged.
fn handed(reply: &Value, from: &[u8; 20]) {
    let typed = &result(reply)["device"]["typed_data"];
    assert_eq!(
        typed["message"]["from"],
        fc_evm::checksum_address(from),
        "{reply}"
    );
    assert_eq!(result(reply)["charged"], true);
}

/// Signed by the core with the key at `from`: the authorization names it,
/// and its signature recovers to it.
fn signed_by(reply: &Value, from: &[u8; 20]) {
    let payload = &result(reply)["payload"];
    let authorization = &payload["payload"]["authorization"];
    assert_eq!(
        authorization["from"],
        fc_evm::checksum_address(from),
        "{reply}"
    );
    let domain = json!({
        "name": "USD Coin", "version": "2", "chainId": 8453,
        "verifyingContract": fc_evm::checksum_address(&fc_evm::parse_address(&USDC.to_lowercase()).unwrap()),
    });
    let types = json!({ "TransferWithAuthorization": [
        { "name": "from", "type": "address" }, { "name": "to", "type": "address" },
        { "name": "value", "type": "uint256" }, { "name": "validAfter", "type": "uint256" },
        { "name": "validBefore", "type": "uint256" }, { "name": "nonce", "type": "bytes32" },
    ] });
    let digest = fc_evm::typed_data_hash(&domain, &types, authorization).unwrap();
    let text = payload["payload"]["signature"].as_str().unwrap();
    let signature: [u8; 65] = fc_evm::parse_bytes(text, "signature")
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(&fc_evm::recover_address(&digest, &signature).unwrap(), from);
}

/// `x402.authorize`'s `device`: once moved, the record's as the
/// reference's `paymentDevice` names it, and a request that disagrees is
/// refused before the cap is charged; before, main's word.
#[test]
fn a_payment_s_device_is_the_record_s() {
    let root = tempfile::tempdir().unwrap();
    cap_file(root.path());
    let (mut core, mut id) = moved_core(root.path(), &["x402"], &[]);
    let ledger = bytes_of(ABANDON, 7);
    let phone = bytes_of(ABANDON, 9);
    // Agreeing: a Ledger's and a phone's at their records' addresses, and
    // the vault's with no device, signed by the core.
    handed(
        &pay(
            &mut core,
            &mut id,
            LEDGER,
            device("ledger", &ledger_address()),
        ),
        &ledger,
    );
    handed(
        &pay(
            &mut core,
            &mut id,
            PHONE,
            device("phone", &phone_address().to_lowercase()),
        ),
        &phone,
    );
    signed_by(&pay(&mut core, &mut id, 0, None), &bytes_of(ABANDON, 0));
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
    let mut core = start(root.path(), false, &["x402"], &[]);
    let mut id = 10;
    handed(
        &pay(&mut core, &mut id, 0, device("phone", &phone_address())),
        &phone,
    );
    handed(
        &pay(
            &mut core,
            &mut id,
            GONE,
            device("ledger", &ledger_address()),
        ),
        &ledger,
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

fn opened(reply: &Value) {
    assert!(result(reply)["job"].is_string(), "{reply}");
}

/// `phone.job`'s account and address: once moved, a phone's record and its
/// address; before, main's word. An unreadable file reads as none and stays
/// where it is.
#[test]
fn a_phone_job_s_address_is_the_record_s() {
    let root = tempfile::tempdir().unwrap();
    let (mut core, mut id) = moved_core(root.path(), &[], &[]);
    opened(&job(
        &mut core,
        &mut id,
        PHONE,
        &phone_address().to_lowercase(),
    ));
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
    drop(core);

    // An unreadable file, moved: no records, and the file left in place.
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("identity")).unwrap();
    std::fs::write(meta_path(root.path()), b"not json").unwrap();
    let mut core = start(root.path(), true, &[], &[]);
    let mut id = 10;
    disagrees(&job(&mut core, &mut id, PHONE, &phone_address()));
    assert_eq!(std::fs::read(meta_path(root.path())).unwrap(), b"not json");
    drop(core);

    let root = tempfile::tempdir().unwrap();
    write_records(root.path());
    let mut core = start(root.path(), false, &[], &[]);
    let mut id = 10;
    for (account, address) in [(PHONE, ledger_address()), (0, phone_address())] {
        opened(&job(&mut core, &mut id, account, &address));
    }
}

/// A record's address in any form `isAddress` took classifies as its
/// device, and a claim in any accepted form agrees with it; a claim with a
/// bad checksum is no address. The test's ICAP encoder is ethers'.
#[test]
fn every_accepted_address_form_agrees() {
    let example = fc_evm::parse_address("0x8ba1f109551bD432803012645Ac136ddd64DBA72").unwrap();
    assert_eq!(icap(&example), "XE65GB6LDNXYOFTX0NSV3FUWKOWIXAMJK36");
    let root = tempfile::tempdir().unwrap();
    cap_file(root.path());
    let mut core = start(root.path(), true, &["x402"], &[]);
    let mut id = 10;
    import(&mut core, &mut id, ABANDON);
    // One phone record per stored form, each its own address, and a Ledger
    // stored as ICAP.
    let mut phones = Vec::new();
    for (n, stored) in (20..).zip(0..7) {
        let bytes = bytes_of(ABANDON, n);
        let text = forms(&bytes)[stored].clone();
        let index = add(
            &mut core,
            &mut id,
            "accounts.add_remote",
            json!({ "address": text }),
        );
        phones.push((index, bytes, text));
    }
    let ledger = bytes_of(ABANDON, 30);
    let ledger_index = add(
        &mut core,
        &mut id,
        "accounts.add_ledger",
        json!({ "address": icap(&ledger), "path": "44'/60'/0'/0/1" }),
    );
    for (index, bytes, stored) in &phones {
        // The record is a phone's, whatever form it was stored in.
        assert!(
            !fee_checked(&issue(&mut core, &mut id, *index, Some(true))),
            "{stored}"
        );
        checked(&check(&mut core, &mut id, *index, "phone"));
        // A claim in any form agrees; one with a bad checksum is refused.
        for claim in forms(bytes) {
            opened(&job(&mut core, &mut id, *index, &claim));
        }
        let reply = job(&mut core, &mut id, *index, &bad_checksum(bytes));
        assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
        assert_eq!(reply["error"]["message"], "address: expected an address");
    }
    // x402's claims: a prefixless and an ICAP phone, and the ICAP Ledger,
    // each claimed in another form.
    let (index, bytes, _) = &phones[1];
    handed(
        &pay(&mut core, &mut id, *index, device("phone", &icap(bytes))),
        bytes,
    );
    let (index, bytes, _) = &phones[6];
    let lower = fc_evm::checksum_address(bytes)[2..].to_lowercase();
    handed(
        &pay(&mut core, &mut id, *index, device("phone", &lower)),
        bytes,
    );
    checked(&check(&mut core, &mut id, ledger_index, "ledger"));
    let checksummed = fc_evm::checksum_address(&ledger);
    handed(
        &pay(
            &mut core,
            &mut id,
            ledger_index,
            device("ledger", &checksummed),
        ),
        &ledger,
    );
    let reply = pay(
        &mut core,
        &mut id,
        ledger_index,
        device("ledger", &bad_checksum(&ledger)),
    );
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
    assert_eq!(
        reply["error"]["message"],
        "device.address: expected an address"
    );
    assert_eq!(spent(root.path()), "3000");
}

/// The steps of a vault and metadata install (design 0013, "The vault and
/// its metadata, one write").
const STEPS: [&str; 7] = [
    "before-meta-stage",
    "before-meta-journal",
    "before-meta-journal-rename",
    "after-meta-journal",
    "after-meta-install-vault",
    "after-meta-install-meta",
    "after-meta-done",
];

fn wait_for(path: &Path) {
    let until = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(Instant::now() < until, "{} never came", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// What the four checks see, for the phone record the old vault has and
/// the new one lacks: `true` for the old pair, `false` for the new.
fn sees_old_pair(core: &mut Core, id: &mut u64, vault: &str, phone: u32) -> bool {
    let issued = issue(core, id, phone, Some(true));
    let checked = check(core, id, phone, "phone");
    let job = job(core, id, phone, &phone_address());
    let paid = pay(core, id, 0, None);
    // The phone's index: a device's to the old vault, gone from the new.
    let signed = sign_as(core, id, "sign.message", phone);
    let old = issued["result"]["token"].is_string();
    let expected = if old { ON_DEVICE } else { DEVICE_GONE };
    refused_as(&signed, expected);
    for reply in [&checked, &job] {
        assert_eq!(reply["result"].is_object(), old, "{reply}");
        if !old {
            disagrees(reply);
        }
    }
    if !old {
        disagrees(&issued);
    }
    // The payment is the vault's, signed with the key of the vault whose
    // records the checks saw.
    signed_by(&paid, &bytes_of(vault, 0));
    old
}

/// A live import held at each step of its install: the checks see the old
/// vault's records and the old vault's key while it runs, and the new
/// vault's records and key once the loop has its result, never one of
/// each. A failed install leaves its journal: the checks answer `storage`
/// until recovery finishes it.
#[test]
fn a_check_sees_one_vault_s_records_through_an_import() {
    let root = tempfile::tempdir().unwrap();
    cap_file(root.path());
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
    let mut core = start(root.path(), true, &["x402"], &env);
    let mut id = 10;
    import(&mut core, &mut id, ABANDON);
    let held = root.path().join("hold.held");
    let release = root.path().join("hold.release");
    let mut vaults = [ABANDON, LEGAL];
    for step in STEPS {
        let [old, new] = vaults;
        let phone = add(
            &mut core,
            &mut id,
            "accounts.add_remote",
            json!({ "address": phone_address() }),
        );
        assert!(sees_old_pair(&mut core, &mut id, old, phone), "{step}");
        // The import of the other vault, held at `step`.
        std::fs::write(&hold, step).unwrap();
        let importing = send_as(
            &mut core,
            &mut id,
            &shell(),
            "vault.import",
            import_params(new),
        );
        wait_for(&held);
        // At the later steps the new metadata is on disk already: the
        // checks still see the old pair, with the old key.
        let on_disk = std::fs::read_to_string(meta_path(root.path())).unwrap();
        let installed = matches!(step, "after-meta-install-meta" | "after-meta-done");
        assert_eq!(
            !on_disk.contains(&phone_address()),
            installed,
            "{step}: {on_disk}"
        );
        assert!(sees_old_pair(&mut core, &mut id, old, phone), "{step}");
        std::fs::write(&release, "").unwrap();
        let imported = core.until_response(importing);
        assert!(imported["result"].is_object(), "{step}: {imported}");
        assert!(imported["result"].get("durable").is_none(), "{imported}");
        std::fs::write(&hold, "").unwrap();
        std::fs::remove_file(&held).unwrap();
        std::fs::remove_file(&release).unwrap();
        // The loop has the new vault: its records, and its key.
        assert!(!sees_old_pair(&mut core, &mut id, new, phone), "{step}");
        vaults = [new, old];
    }
    // A failed install keeps its journal: `storage`, nothing signed.
    let [old, new] = vaults;
    let phone = add(
        &mut core,
        &mut id,
        "accounts.add_remote",
        json!({ "address": phone_address() }),
    );
    assert!(sees_old_pair(&mut core, &mut id, old, phone));
    std::fs::write(&fail, "vault_meta_journal:meta-rename\n").unwrap();
    let imported = import(&mut core, &mut id, new);
    assert_eq!(imported["result"]["durable"], false, "{imported}");
    pending(&issue(&mut core, &mut id, phone, Some(true)));
    pending(&check(&mut core, &mut id, phone, "phone"));
    pending(&job(&mut core, &mut id, phone, &phone_address()));
    pending(&sign_as(&mut core, &mut id, "sign.message", 0));
    let before = spent(root.path());
    pending(&pay(&mut core, &mut id, 0, None));
    assert_eq!(spent(root.path()), before);
    // Recovery, at the next `accounts.*` request: the new pair.
    std::fs::write(&fail, "").unwrap();
    result(&call(&mut core, &mut id, "accounts.list", json!({})));
    assert!(!sees_old_pair(&mut core, &mut id, new, phone));
}

/// `getSigner`'s and `withVaultAccount`'s refusals (G20b).
const DEVICE_GONE: &str = "Device account no longer exists; reconnect the device";
const SAFE_SIGNS: &str =
    "Safe accounts cannot sign directly \u{2014} execute through the Safe flow";
const ON_DEVICE: &str = "This account keeps its key on another device; sign via its device signer";

/// Typed data of one empty struct.
fn typed() -> Value {
    json!({ "domain": {}, "types": { "M": [] }, "message": {} })
}

/// `method` for account `index`, under `shell`.
fn sign_as(core: &mut Core, id: &mut u64, method: &str, index: u32) -> Value {
    let key = json!({ "kind": "account", "index": index });
    let params = match method {
        "sign.message" => json!({ "key": key, "message": "0x68656c6c6f" }),
        "sign.transaction" => json!({ "key": key, "tx": {
            "type": 2, "chain_id": "1", "nonce": "0", "gas_limit": "21000", "to": TO,
            "value": "1", "data": "0x", "max_fee_per_gas": "2", "max_priority_fee_per_gas": "1",
        } }),
        _ => {
            let hashed = call(
                core,
                id,
                "typed_data.hash",
                json!({ "typed_data": typed() }),
            );
            let hash = result(&hashed)["hash"].clone();
            json!({ "key": key, "typed_data": typed(), "expected_hash": hash })
        }
    };
    call(core, id, method, params)
}

/// Signed by account `index` of `mnemonic`: a message's signature recovers
/// to it; a transaction and typed data are signed.
fn signed_as(reply: &Value, method: &str, mnemonic: &str, index: u32) {
    match method {
        "sign.message" => {
            let text = result(reply)["signature"].as_str().unwrap();
            let signature: [u8; 65] = fc_evm::parse_bytes(text, "signature")
                .unwrap()
                .try_into()
                .unwrap();
            let digest = fc_evm::eip191_digest(b"hello");
            assert_eq!(
                fc_evm::recover_address(&digest, &signature).unwrap(),
                bytes_of(mnemonic, index),
                "{index}: {reply}"
            );
        }
        "sign.transaction" => assert!(result(reply)["raw"].is_string(), "{reply}"),
        _ => assert!(result(reply)["signature"].is_string(), "{reply}"),
    }
}

/// Refused `invalid_argument` with the reference's text.
fn refused_as(reply: &Value, message: &str) {
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
    assert_eq!(reply["error"]["message"], message, "{reply}");
}

const SIGNS: [&str; 3] = ["sign.message", "sign.transaction", "sign.typed_data"];

/// Records `accounts.add_*` can't make, added to the file as it stands:
/// a type the reference doesn't know, below the hardware range and in it,
/// and a mnemonic record in it.
fn add_odd_records(root: &Path) {
    let text = std::fs::read_to_string(meta_path(root)).unwrap();
    let mut meta: Value = serde_json::from_str(&text).unwrap();
    let wallets = meta["derivedWallets"].as_array_mut().unwrap();
    wallets.push(json!({ "index": 3, "name": "Odd", "address": address(3), "type": "other" }));
    wallets.push(json!({ "index": 1_000_003, "name": "High", "type": "mnemonic" }));
    wallets.push(json!({ "index": 1_000_004, "name": "High odd", "type": "other" }));
    std::fs::write(
        meta_path(root),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .unwrap();
}

/// Each index that isn't the vault's, and the reference's refusal of it.
const NOT_THE_VAULT_S: [(u32, &str); 7] = [
    (LEDGER, ON_DEVICE),
    (PHONE, ON_DEVICE),
    (SAFE_INDEX, SAFE_SIGNS),
    (GONE, DEVICE_GONE),
    (3, ON_DEVICE),
    (1_000_003, ON_DEVICE),
    (1_000_004, ON_DEVICE),
];

/// `sign.*` once moved: the vault signs for its main account and for an
/// index below the hardware range with no record, and refuses a Ledger's,
/// a phone's, a Safe's, a deleted device's, another type's and a mnemonic
/// record's in the hardware range, each with the reference's text, before
/// any key is derived: a locked vault refuses them the same, and its own
/// index `vault_locked`. Without `vault_meta`, against the same file, the
/// vault signs for every index, as before.
#[test]
fn the_vault_signs_only_for_its_own_records() {
    let root = tempfile::tempdir().unwrap();
    let (mut core, mut id) = moved_core(root.path(), &[], &[]);
    add_odd_records(root.path());
    // The next `accounts.*` request takes the records again.
    result(&call(&mut core, &mut id, "accounts.list", json!({})));
    for method in SIGNS {
        for index in [0, 5] {
            signed_as(
                &sign_as(&mut core, &mut id, method, index),
                method,
                ABANDON,
                index,
            );
        }
        for (index, refusal) in NOT_THE_VAULT_S {
            refused_as(&sign_as(&mut core, &mut id, method, index), refusal);
        }
    }
    result(&call(&mut core, &mut id, "vault.lock", json!({})));
    for method in SIGNS {
        for (index, refusal) in NOT_THE_VAULT_S {
            refused_as(&sign_as(&mut core, &mut id, method, index), refusal);
        }
        let locked = sign_as(&mut core, &mut id, method, 0);
        assert_eq!(locked["error"]["code"], "vault_locked", "{locked}");
    }
    drop(core);

    // Main's file: the same records, and main's word on what to sign.
    let mut core = start(root.path(), false, &[], &[]);
    let mut id = 10;
    let unlocked = call(
        &mut core,
        &mut id,
        "vault.unlock",
        json!({ "password_b64": STANDARD.encode("testpass1") }),
    );
    result(&unlocked);
    for method in SIGNS {
        for (index, _) in NOT_THE_VAULT_S {
            signed_as(
                &sign_as(&mut core, &mut id, method, index),
                method,
                ABANDON,
                index,
            );
        }
    }
}

/// `x402.authorize`'s params for a payment from `account` under a token.
fn token_pay_params(tag: u64, account: u32, token: &str) -> Value {
    let mut params = pay_params(tag, account, None);
    params["authorization"] = json!({ "token": token });
    params["accept_index"] = json!(0);
    params
}

/// An `x402-payment` token binding `params`' account, detection and entry.
fn x402_token(core: &mut Core, id: &mut u64, params: &Value) -> String {
    let payload = json!({ "detection": params["detection"], "accept_index": 0,
        "accept": params["requirements"]["accepts"][0] });
    let issued = call(
        core,
        id,
        "approval.issue",
        json!({ "kind": "x402-payment", "account": params["account"], "payload": payload }),
    );
    result(&issued)["token"].as_str().unwrap().to_owned()
}

fn unknown_token(reply: &Value) {
    assert_eq!(reply["error"]["code"], "not_authorized", "{reply}");
    assert_eq!(reply["error"]["data"]["reason"], "unknown_token", "{reply}");
}

/// `x402.authorize` once moved (G20b): the vault pays only for its own
/// accounts, so a mnemonic record in the hardware range is refused with
/// `withVaultAccount`'s text, under the cap or a token, before the token is
/// judged or the cap charged; the token is burnt all the same. The vault's
/// own account still pays.
#[test]
fn a_payment_from_a_hardware_index_never_takes_the_vault_key() {
    let root = tempfile::tempdir().unwrap();
    cap_file(root.path());
    let (mut core, mut id) = moved_core(root.path(), &["x402"], &[]);
    add_odd_records(root.path());
    result(&call(&mut core, &mut id, "accounts.list", json!({})));
    refused_as(&pay(&mut core, &mut id, 1_000_003, None), ON_DEVICE);
    assert_eq!(spent(root.path()), "0");
    let params = token_pay_params(90, 1_000_003, "");
    let token = x402_token(&mut core, &mut id, &params);
    let paid = call(
        &mut core,
        &mut id,
        "x402.authorize",
        token_pay_params(90, 1_000_003, &token),
    );
    refused_as(&paid, ON_DEVICE);
    // Burnt: the vault account's otherwise matching request finds no token,
    // where a live one would be another account's (`mismatch`).
    unknown_token(&call(
        &mut core,
        &mut id,
        "x402.authorize",
        token_pay_params(90, 0, &token),
    ));
    assert_eq!(spent(root.path()), "0");
    signed_by(&pay(&mut core, &mut id, 0, None), &bytes_of(ABANDON, 0));
    assert_eq!(spent(root.path()), "1000");
}

const HANDLE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

/// `sign.message` of "hello" for account 3 under `page`, by `authorization`.
fn page_sign(core: &mut Core, id: &mut u64, authorization: Value) -> Value {
    let params = json!({ "key": { "kind": "account", "index": 3 }, "message": "0x68656c6c6f",
            "authorization": authorization });
    call_as(core, id, &page(), "sign.message", params)
}

/// Account 3's record given `type`, taken in by the next `accounts.*`.
fn retype(core: &mut Core, id: &mut u64, root: &Path, kind: &str) {
    let mut meta: Value =
        serde_json::from_str(&std::fs::read_to_string(meta_path(root)).unwrap()).unwrap();
    for wallet in meta["derivedWallets"].as_array_mut().unwrap() {
        if wallet["index"] == 3 {
            wallet["type"] = json!(kind);
        }
    }
    std::fs::write(meta_path(root), serde_json::to_string(&meta).unwrap()).unwrap();
    result(&call(core, id, "accounts.list", json!({})));
}

/// `sign.*`'s record refusal comes before the authorization: a request for
/// an account the vault doesn't sign for counts none of a limited rule's
/// five uses, and a page token it presents is burnt without being judged
/// (one presented under another handle is refused for the record, not as a
/// mismatch). Once the record is the vault's, neither token signs the
/// matching request, a fresh one does, and the rule answers five times.
#[test]
fn a_refused_signature_spends_no_rule_use_and_burns_its_token() {
    let root = tempfile::tempdir().unwrap();
    let granted = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        - 600_000;
    let dapp = json!({ SITE: {
        "origin": SITE, "connectedAt": 1_762_000_000_000_u64, "lastUsed": 1_762_000_000_000_u64,
        "walletIndex": 3, "chainId": 100,
        "autoApprove": { "signing": false, "transactions": [],
            "limited": { "signing": { "grantedAt": granted }, "transactions": [] } },
    } });
    std::fs::create_dir_all(root.path().join("userData")).unwrap();
    std::fs::write(
        root.path().join("userData").join("dapp-permissions.json"),
        dapp.to_string(),
    )
    .unwrap();
    let (mut core, mut id) = moved_core(root.path(), &["dapp"], &[MAINS_WORD]);
    add_odd_records(root.path());
    result(&call(&mut core, &mut id, "accounts.list", json!({})));
    let mint = |core: &mut Core, id: &mut u64| {
        let params = json!({ "kind": "sign-message", "account": 3,
            "payload": { "message": "0x68656c6c6f" }, "handle": HANDLE });
        let issued = call_as(core, id, &page(), "approval.issue", params);
        result(&issued)["token"].as_str().unwrap().to_owned()
    };
    let (first, second) = (mint(&mut core, &mut id), mint(&mut core, &mut id));
    // Account 3 is `other`: refused for its record, whatever authorizes it.
    let standing = json!({ "standing": {} });
    refused_as(&page_sign(&mut core, &mut id, standing.clone()), ON_DEVICE);
    let presented = json!({ "token": first, "handle": HANDLE });
    refused_as(&page_sign(&mut core, &mut id, presented), ON_DEVICE);
    let elsewhere = json!({ "token": second, "handle": "b2".repeat(32) });
    refused_as(&page_sign(&mut core, &mut id, elsewhere), ON_DEVICE);
    // The vault's account now: the burnt tokens bind nothing.
    retype(&mut core, &mut id, root.path(), "mnemonic");
    for token in [&first, &second] {
        let presented = json!({ "token": token, "handle": HANDLE });
        unknown_token(&page_sign(&mut core, &mut id, presented));
    }
    let fresh = json!({ "token": mint(&mut core, &mut id), "handle": HANDLE });
    signed_as(
        &page_sign(&mut core, &mut id, fresh),
        "sign.message",
        ABANDON,
        3,
    );
    // All five of the rule's uses, then its rate.
    for _ in 0..5 {
        let signed = page_sign(&mut core, &mut id, standing.clone());
        signed_as(&signed, "sign.message", ABANDON, 3);
    }
    let sixth = page_sign(&mut core, &mut id, standing);
    assert_eq!(sixth["error"]["data"]["reason"], "rate_limited", "{sixth}");
}

/// Two ICAPs of 31 digits past 2^160, which `isAddress` takes (and the
/// core's `accounts.add_*` with it) and `getAddress` reads as 41 hex digits.
const PHONE_ICAP: &str = "XE54ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
const LEDGER_ICAP: &str = "XE62YZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";

/// Refused where 20 bytes are needed.
fn not_twenty_bytes(reply: &Value, field: &str) {
    assert_eq!(reply["error"]["code"], "invalid_argument", "{reply}");
    assert_eq!(
        reply["error"]["message"],
        format!("{field}: not an address of 20 bytes"),
        "{reply}"
    );
}

/// A device record whose address is an ICAP past 20 bytes is still its
/// device (the kind is its `type`'s, as `getSigner`'s is), and a claim
/// that `getAddress` reads the same agrees with it; where 20 bytes are
/// needed (a phone job's request, x402's authorization) it is refused
/// there, nothing spent or charged.
#[test]
fn an_icap_past_twenty_bytes_is_still_its_device() {
    let root = tempfile::tempdir().unwrap();
    cap_file(root.path());
    let mut core = start(root.path(), true, &["x402"], &[]);
    let mut id = 10;
    import(&mut core, &mut id, ABANDON);
    let phone = add(
        &mut core,
        &mut id,
        "accounts.add_remote",
        json!({ "address": PHONE_ICAP }),
    );
    let ledger = add(
        &mut core,
        &mut id,
        "accounts.add_ledger",
        json!({ "address": LEDGER_ICAP, "path": "44'/60'/0'/0/0" }),
    );
    // The kind.
    assert!(!fee_checked(&issue(&mut core, &mut id, phone, Some(true))));
    disagrees(&issue(&mut core, &mut id, phone, None));
    assert!(fee_checked(&issue(&mut core, &mut id, ledger, None)));
    checked(&check(&mut core, &mut id, phone, "phone"));
    checked(&check(&mut core, &mut id, ledger, "ledger"));
    disagrees(&check(&mut core, &mut id, phone, "vault"));
    disagrees(&check(&mut core, &mut id, ledger, "phone"));
    // The address: the same `getAddress`, in either case of its body,
    // agrees, and then a job needs 20 bytes.
    let lower = format!("XE{}", PHONE_ICAP[2..].to_lowercase());
    for claim in [PHONE_ICAP, lower.as_str()] {
        not_twenty_bytes(&job(&mut core, &mut id, phone, claim), "address");
    }
    disagrees(&job(&mut core, &mut id, phone, LEDGER_ICAP));
    disagrees(&job(&mut core, &mut id, phone, &phone_address()));
    // x402: the same, before anything is charged.
    not_twenty_bytes(
        &pay(&mut core, &mut id, ledger, device("ledger", LEDGER_ICAP)),
        "device.address",
    );
    not_twenty_bytes(
        &pay(&mut core, &mut id, phone, device("phone", &lower)),
        "device.address",
    );
    disagrees(&pay(
        &mut core,
        &mut id,
        ledger,
        device("ledger", PHONE_ICAP),
    ));
    disagrees(&pay(&mut core, &mut id, ledger, None));
    disagrees(&pay(
        &mut core,
        &mut id,
        phone,
        device("ledger", PHONE_ICAP),
    ));
    assert_eq!(spent(root.path()), "0");
}

/// An import killed after its journal's commit: the next start's recovery
/// installs its vault and metadata. With that recovery held past the
/// hello, the hello's own snapshot found the journal; the records the
/// checks read right after the hello's reply are the recovered ones, not
/// `storage`.
#[test]
fn startup_recovery_s_records_answer_right_after_the_hello() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), true, &[], &[]);
    let mut id = 10;
    import(&mut core, &mut id, ABANDON);
    let phone = add(
        &mut core,
        &mut id,
        "accounts.add_remote",
        json!({ "address": phone_address() }),
    );
    opened(&job(&mut core, &mut id, phone, &phone_address()));
    drop(core);
    // The other vault's import, killed after its commit.
    let mut core = start(
        root.path(),
        true,
        &[],
        &[("FREEDOM_CORED_TEST_SECRETS_CRASH", "after-meta-journal")],
    );
    send_as(
        &mut core,
        &mut id,
        &shell(),
        "vault.import",
        import_params(LEGAL),
    );
    assert_eq!(core.exit_code(Duration::from_secs(10)), 99);
    drop(core);
    let journal = root.path().join("identity").join("vault-meta-journal.json");
    assert!(journal.exists());
    assert!(
        std::fs::read_to_string(meta_path(root.path()))
            .unwrap()
            .contains(&phone_address())
    );
    // The next start, its recovery held until after the hello came.
    let mut core = start(
        root.path(),
        true,
        &[],
        &[("FREEDOM_CORED_TEST_SNAPSHOT_DELAY_MS", "1500")],
    );
    assert!(!journal.exists());
    assert!(
        !std::fs::read_to_string(meta_path(root.path()))
            .unwrap()
            .contains(&phone_address())
    );
    // The recovered records: the new vault's main account, and no phone.
    checked(&check(&mut core, &mut id, 0, "vault"));
    disagrees(&check(&mut core, &mut id, phone, "phone"));
    disagrees(&job(&mut core, &mut id, phone, &phone_address()));
    disagrees(&issue(&mut core, &mut id, phone, Some(true)));
    assert!(fee_checked(&issue(&mut core, &mut id, phone, None)));
}
