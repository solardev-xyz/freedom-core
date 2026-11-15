//! Design 0012's x402 payments through the real binary (X402-1):
//! `x402.authorize` and `x402.settle`, answering `not_moved` until `x402` is
//! in `grant_moved`; a token paying exactly the tab, detection, entry,
//! account and grant it binds; a cap charged before its signature, one of
//! two concurrent charges signed, `withheld` giving it back; no cap in
//! custody or for an unattributed request, expired, or behind a clock set
//! back; one cap per seller; the asset's case; a failed charge write
//! signing nothing; and each payload signed by the account it names.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// Account 0 of the abandon mnemonic (keys.json); account 1's differs.
const ACCOUNT_0: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const USDC: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAY_TO: &str = "0x209693bc6afc0c5328ba36faf03c514ef312287c";
const SELLER: &str = "https://paid.example";

fn shell() -> Value {
    json!({ "caller": "shell" })
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

fn refused(reply: &Value, code: &str, reason: Option<&str>) {
    assert_eq!(reply["error"]["code"], code, "{reply}");
    if let Some(reason) = reason {
        assert_eq!(reply["error"]["data"]["reason"], reason, "{reply}");
    }
}

fn start(root: &Path, moved: &[&'static str], env: &[(&str, &str)]) -> Core {
    let mut core = spawn_env(
        "serve",
        &root.join("identity"),
        &root.join("locks"),
        &[],
        env,
    );
    std::fs::create_dir_all(&core.grant_root).unwrap();
    core.grant_moved = moved.to_vec();
    assert_eq!(core.hello()["result"]["protocol"], 2);
    core
}

fn unlock(core: &mut Core, id: &mut u64) {
    let imported = call(
        core,
        id,
        "vault.import",
        json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(ABANDON) }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    assert_eq!(core.event()["event"], "vault.unlocked");
}

fn entry(asset: &str, amount: &str) -> Value {
    json!({
        "scheme": "exact", "network": "eip155:8453", "amount": amount, "asset": asset,
        "payTo": PAY_TO, "maxTimeoutSeconds": 60, "extra": { "name": "USD Coin", "version": "2" },
    })
}

fn requirements(accepts: Vec<Value>) -> Value {
    json!({
        "x402Version": 2,
        "resource": { "url": format!("{SELLER}/article"), "description": "An article" },
        "accepts": accepts,
    })
}

fn detection(tab: u64, url: &str) -> Value {
    json!({ "tab": tab, "id": format!("d{tab}"), "url": url })
}

/// An `x402-payment` token for `account`, the detection, the entry and the
/// grant (main's, under `shell`, from APS-5).
fn token(
    core: &mut Core,
    id: &mut u64,
    account: u32,
    detection: &Value,
    index: usize,
    accept: &Value,
    grant: Option<Value>,
) -> String {
    let mut payload = json!({ "detection": detection, "accept_index": index, "accept": accept });
    if let Some(grant) = grant {
        payload["grant"] = grant;
    }
    let reply = call(
        core,
        id,
        "approval.issue",
        json!({ "kind": "x402-payment", "account": account, "payload": payload }),
    );
    result(&reply)["token"].as_str().unwrap().to_owned()
}

#[allow(clippy::too_many_arguments)]
fn pay_with_token(
    core: &mut Core,
    id: &mut u64,
    token: &str,
    account: u32,
    detection: &Value,
    requirements: &Value,
    index: usize,
    grant: Option<Value>,
) -> Value {
    let mut params = json!({
        "account": account, "detection": detection, "requirements": requirements,
        "accept_index": index, "authorization": { "token": token },
    });
    if let Some(grant) = grant {
        params["grant"] = grant;
    }
    call(core, id, "x402.authorize", params)
}

fn cap_params(detection: &Value, requirements: &Value, agent: bool, attributable: bool) -> Value {
    json!({
        "account": 0, "detection": detection, "requirements": requirements,
        "authorization": { "cap": { "agent": agent, "attributable": attributable } },
    })
}

fn pay_with_cap(core: &mut Core, id: &mut u64, detection: &Value, requirements: &Value) -> Value {
    call(
        core,
        id,
        "x402.authorize",
        cap_params(detection, requirements, false, true),
    )
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hex(text: &str) -> Vec<u8> {
    let digits = text.strip_prefix("0x").unwrap();
    (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).unwrap())
        .collect()
}

/// The payload's EIP-3009 authorization, checked: signed by `from` over its
/// own fields, for the entry, with the wall clock's window.
fn check_payload(payload: &Value, from: &str, accept: &Value) {
    assert_eq!(payload["x402Version"], 2);
    assert_eq!(&payload["accepted"], accept);
    let authorization = &payload["payload"]["authorization"];
    assert_eq!(authorization["from"], from);
    assert_eq!(authorization["value"], accept["amount"]);
    assert_eq!(authorization["validAfter"], "0");
    let before: u64 = authorization["validBefore"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(before.abs_diff(now_s() + 60) <= 5, "{before}");
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
    let signature: [u8; 65] = hex(payload["payload"]["signature"].as_str().unwrap())
        .try_into()
        .unwrap();
    let signer = fc_evm::recover_address(&digest, &signature).unwrap();
    assert_eq!(fc_evm::checksum_address(&signer), from);
}

fn file(core: &Core) -> Option<String> {
    std::fs::read_to_string(core.grant_root.join("x402-permissions.json")).ok()
}

fn caps(core: &Core) -> Value {
    file(core).map_or(json!({}), |text| serde_json::from_str(&text).unwrap())
}

fn changed(core: &mut Core, id: &mut u64) -> Vec<Value> {
    let _ = call_as(
        core,
        id,
        &json!({ "caller": "chrome" }),
        "vault.status",
        json!({}),
    );
    std::mem::take(&mut core.events)
        .into_iter()
        .map(|event| event["data"].clone())
        .collect()
}

fn key_of(asset: &str) -> String {
    format!("8453:{}", asset.to_lowercase())
}

/// Until `x402` is in `grant_moved`, both methods answer `not_moved` and
/// change nothing; the presented token is burnt all the same. Only main
/// (`shell`) reaches them.
#[test]
fn before_the_move_nothing_is_paid() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &["dapp", "swarm", "radicle"], &[]);
    let mut id = 10;
    unlock(&mut core, &mut id);
    let accept = entry(USDC, "10000");
    let reqs = requirements(vec![accept.clone()]);
    let tab = detection(1, &format!("{SELLER}/article"));
    let t = token(&mut core, &mut id, 0, &tab, 0, &accept, None);
    let reply = pay_with_token(&mut core, &mut id, &t, 0, &tab, &reqs, 0, None);
    refused(&reply, "not_moved", None);
    assert_eq!(reply["error"]["data"]["store"], "x402");
    refused(
        &pay_with_cap(&mut core, &mut id, &tab, &reqs),
        "not_moved",
        None,
    );
    let settle = call(
        &mut core,
        &mut id,
        "x402.settle",
        json!({ "reservation": "00", "outcome": "withheld" }),
    );
    refused(&settle, "not_moved", None);
    let revoke = call(
        &mut core,
        &mut id,
        "approval.revoke",
        json!({ "store": "x402", "key": SELLER, "what": "grant" }),
    );
    refused(&revoke, "not_moved", None);
    assert!(
        std::fs::read_dir(&core.grant_root)
            .unwrap()
            .next()
            .is_none()
    );
    assert!(changed(&mut core, &mut id).is_empty());
    // The token went with its presentation.
    let again = call(
        &mut core,
        &mut id,
        "approval.discard",
        json!({ "token": t }),
    );
    assert!(again["result"].is_object());
    for caller in [
        json!({ "caller": "chrome" }),
        json!({ "caller": "page", "page": {
        "origin": SELLER, "top_origin": SELLER, "frame": 1, "navigation": 1, "agent": false } }),
    ] {
        for method in ["x402.authorize", "x402.settle"] {
            let reply = call_as(&mut core, &mut id, &caller, method, json!({}));
            refused(&reply, "forbidden", None);
        }
    }
}

/// A token pays exactly what it binds: another tab, another entry, another
/// account or another grant is a mismatch, which burns it; the grant it
/// binds is written as bound, after the signature, and the payment charged
/// to it.
#[test]
fn a_token_pays_what_it_binds() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &["x402"], &[]);
    let mut id = 10;
    unlock(&mut core, &mut id);
    let first = entry(USDC, "10000");
    let second = json!({
        "scheme": "exact", "network": "eip155:1", "amount": "10000",
        "asset": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "payTo": PAY_TO,
        "maxTimeoutSeconds": 60, "extra": { "name": "USD Coin", "version": "2" },
    });
    let reqs = requirements(vec![first.clone(), second.clone()]);
    let tab_a = detection(1, &format!("{SELLER}/article"));
    let tab_b = detection(2, &format!("{SELLER}/article"));
    let grant = json!({ "cap_amount": "30000", "window_seconds": 3600 });
    // Tab A's token, for tab B; entry 0's, for entry 1; account 0's, for
    // account 1 (an account switch); one grant's, for another.
    let cases: [(Value, usize, u32, Option<Value>); 4] = [
        (tab_b.clone(), 0, 0, Some(grant.clone())),
        (tab_a.clone(), 1, 0, Some(grant.clone())),
        (tab_a.clone(), 0, 1, Some(grant.clone())),
        (
            tab_a.clone(),
            0,
            0,
            Some(json!({ "cap_amount": "30001", "window_seconds": 3600 })),
        ),
    ];
    for (tab, index, account, presented_grant) in cases {
        let t = token(
            &mut core,
            &mut id,
            0,
            &tab_a,
            0,
            &first,
            Some(grant.clone()),
        );
        let reply = pay_with_token(
            &mut core,
            &mut id,
            &t,
            account,
            &tab,
            &reqs,
            index,
            presented_grant,
        );
        refused(&reply, "not_authorized", Some("mismatch"));
        // Burnt by the mismatch.
        let again = pay_with_token(
            &mut core,
            &mut id,
            &t,
            0,
            &tab_a,
            &reqs,
            0,
            Some(grant.clone()),
        );
        refused(&again, "not_authorized", Some("unknown_token"));
    }
    assert_eq!(file(&core), None);
    assert!(changed(&mut core, &mut id).is_empty());
    let t = token(
        &mut core,
        &mut id,
        0,
        &tab_a,
        0,
        &first,
        Some(grant.clone()),
    );
    let reply = pay_with_token(
        &mut core,
        &mut id,
        &t,
        0,
        &tab_a,
        &reqs,
        0,
        Some(grant.clone()),
    );
    let paid = result(&reply);
    check_payload(&paid["payload"], ACCOUNT_0, &first);
    assert_eq!(paid["accept_index"], 0);
    assert_eq!(paid["charged"], true);
    assert_eq!(paid["grant"], json!({ "added": true }));
    let cap = &caps(&core)[SELLER][key_of(USDC)];
    assert_eq!(cap["capAmount"], "30000");
    assert_eq!(cap["spentAmount"], "10000");
    assert_eq!(
        cap["expiresAt"].as_u64().unwrap() - cap["createdAt"].as_u64().unwrap(),
        3600
    );
    // The grant, then the charge.
    assert_eq!(
        changed(&mut core, &mut id),
        [
            json!({ "store": "x402", "key": SELLER }),
            json!({ "store": "x402", "key": SELLER })
        ]
    );
    // Spent: once.
    let again = pay_with_token(&mut core, &mut id, &t, 0, &tab_a, &reqs, 0, Some(grant));
    refused(&again, "not_authorized", Some("unknown_token"));
    // Account 1's token signs as account 1.
    let t = token(&mut core, &mut id, 1, &tab_a, 0, &first, None);
    let reply = pay_with_token(&mut core, &mut id, &t, 1, &tab_a, &reqs, 0, None);
    let from = result(&reply)["payload"]["payload"]["authorization"]["from"].clone();
    assert_ne!(from, ACCOUNT_0);
    check_payload(&result(&reply)["payload"], from.as_str().unwrap(), &first);
}

/// A cap is charged before its signature: of two payments sent together
/// that it covers one of, one signs; `withheld` gives the charge back and
/// the next one signs; `sent` keeps it. One cap per seller: payments for
/// one seller's URLs, from any page, charge the cap keyed on its origin.
#[test]
fn a_cap_is_charged_as_it_signs() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &["x402"], &[]);
    let mut id = 10;
    unlock(&mut core, &mut id);
    let accept = entry(USDC, "10000");
    let reqs = requirements(vec![accept.clone()]);
    let tab = detection(1, &format!("{SELLER}/a"));
    let grant = json!({ "cap_amount": "20000", "window_seconds": 3600 });
    let t = token(&mut core, &mut id, 0, &tab, 0, &accept, Some(grant.clone()));
    result(&pay_with_token(
        &mut core,
        &mut id,
        &t,
        0,
        &tab,
        &reqs,
        0,
        Some(grant),
    ));
    let _ = changed(&mut core, &mut id);
    // 10,000 left: two at once, from two tabs (two embedding pages) and
    // two of the seller's URLs.
    let one = detection(2, &format!("{SELLER}/b?x=1"));
    let two = detection(3, &format!("{SELLER}:443/c"));
    let (a, b) = (id + 1, id + 2);
    id += 2;
    core.send(
        &json!({ "type": "request", "id": a, "method": "x402.authorize",
        "params": cap_params(&one, &reqs, false, true), "context": shell() }),
    );
    core.send(
        &json!({ "type": "request", "id": b, "method": "x402.authorize",
        "params": cap_params(&two, &reqs, false, true), "context": shell() }),
    );
    let replies = [core.response(a), core.response(b)];
    let signed: Vec<&Value> = replies.iter().filter(|r| r["result"].is_object()).collect();
    assert_eq!(signed.len(), 1, "{replies:?}");
    let other = replies.iter().find(|r| r["error"].is_object()).unwrap();
    refused(other, "not_authorized", Some("cap"));
    check_payload(&signed[0]["result"]["payload"], ACCOUNT_0, &accept);
    assert_eq!(signed[0]["result"]["charged"], true);
    assert_eq!(caps(&core)[SELLER][key_of(USDC)]["spentAmount"], "20000");
    assert_eq!(
        changed(&mut core, &mut id),
        [json!({ "store": "x402", "key": SELLER })]
    );
    // Another seller has no cap.
    let elsewhere = detection(4, "https://other.example/a");
    refused(
        &pay_with_cap(&mut core, &mut id, &elsewhere, &reqs),
        "not_authorized",
        Some("cap"),
    );
    // Withheld: given back, once.
    let reservation = signed[0]["result"]["reservation"]
        .as_str()
        .unwrap()
        .to_owned();
    let settled = call(
        &mut core,
        &mut id,
        "x402.settle",
        json!({ "reservation": reservation, "outcome": "withheld" }),
    );
    assert_eq!(result(&settled)["refunded"], true);
    assert_eq!(caps(&core)[SELLER][key_of(USDC)]["spentAmount"], "10000");
    assert_eq!(
        changed(&mut core, &mut id),
        [json!({ "store": "x402", "key": SELLER })]
    );
    let again = call(
        &mut core,
        &mut id,
        "x402.settle",
        json!({ "reservation": reservation, "outcome": "withheld" }),
    );
    refused(&again, "invalid_argument", None);
    // Sent: kept.
    let reply = pay_with_cap(&mut core, &mut id, &one, &reqs);
    let reservation = result(&reply)["reservation"].as_str().unwrap().to_owned();
    let settled = call(
        &mut core,
        &mut id,
        "x402.settle",
        json!({ "reservation": reservation, "outcome": "sent" }),
    );
    assert_eq!(result(&settled)["refunded"], false);
    assert_eq!(caps(&core)[SELLER][key_of(USDC)]["spentAmount"], "20000");
    refused(
        &pay_with_cap(&mut core, &mut id, &one, &reqs),
        "not_authorized",
        Some("cap"),
    );
    let _ = changed(&mut core, &mut id);
    // Under a cap the core picks the entry, and no grant comes with it.
    let before = file(&core);
    for (field, value) in [
        ("accept_index", json!(0)),
        ("grant", json!({ "cap_amount": "1", "window_seconds": 60 })),
    ] {
        let mut params = cap_params(&one, &reqs, false, true);
        params[field] = value;
        refused(
            &call(&mut core, &mut id, "x402.authorize", params),
            "invalid_argument",
            None,
        );
    }
    // Agent custody, and a request main can't attribute: nothing charged.
    for (agent, attributable, reason) in [(true, true, "custody"), (false, false, "no_rule")] {
        let reply = call(
            &mut core,
            &mut id,
            "x402.authorize",
            cap_params(&one, &reqs, agent, attributable),
        );
        refused(&reply, "not_authorized", Some(reason));
    }
    assert_eq!(file(&core), before);
    assert!(changed(&mut core, &mut id).is_empty());
}

/// The asset's case: a cap granted for an entry in mixed case is the cap a
/// lowercase entry charges and a mixed-case revoke drops, its key lowercase
/// in the file. A charge given back after its cap was revoked and granted
/// again gives nothing back.
#[test]
fn the_asset_is_one_cap_in_any_case() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &["x402"], &[]);
    let mut id = 10;
    unlock(&mut core, &mut id);
    let mixed = entry(USDC, "10000");
    let lower = entry(&USDC.to_lowercase(), "10000");
    let tab = detection(1, &format!("{SELLER}/a"));
    let grant = json!({ "cap_amount": "50000", "window_seconds": 3600 });
    let t = token(&mut core, &mut id, 0, &tab, 0, &mixed, Some(grant.clone()));
    result(&pay_with_token(
        &mut core,
        &mut id,
        &t,
        0,
        &tab,
        &requirements(vec![mixed.clone()]),
        0,
        Some(grant.clone()),
    ));
    let text = file(&core).unwrap();
    assert!(
        text.contains(&key_of(USDC)) && !text.contains(USDC),
        "{text}"
    );
    let reply = pay_with_cap(&mut core, &mut id, &tab, &requirements(vec![lower.clone()]));
    assert_eq!(result(&reply)["charged"], true);
    let reservation = result(&reply)["reservation"].as_str().unwrap().to_owned();
    assert_eq!(caps(&core)[SELLER][key_of(USDC)]["spentAmount"], "20000");
    // Revoked in mixed case, granted again: the old charge isn't the new
    // cap's to give back.
    let revoke = call(
        &mut core,
        &mut id,
        "approval.revoke",
        json!({
            "store": "x402", "key": SELLER, "what": { "cap": { "chain_id": 8453, "asset": USDC } },
        }),
    );
    assert_eq!(result(&revoke)["revoked"], true);
    assert_eq!(caps(&core), json!({}));
    let t = token(&mut core, &mut id, 0, &tab, 0, &lower, Some(grant.clone()));
    result(&pay_with_token(
        &mut core,
        &mut id,
        &t,
        0,
        &tab,
        &requirements(vec![lower]),
        0,
        Some(grant),
    ));
    assert_eq!(caps(&core)[SELLER][key_of(USDC)]["spentAmount"], "10000");
    let settled = call(
        &mut core,
        &mut id,
        "x402.settle",
        json!({ "reservation": reservation, "outcome": "withheld" }),
    );
    assert_eq!(result(&settled)["refunded"], false);
    assert_eq!(caps(&core)[SELLER][key_of(USDC)]["spentAmount"], "10000");
    // Every cap of the seller.
    let revoke = call(
        &mut core,
        &mut id,
        "approval.revoke",
        json!({ "store": "x402", "key": SELLER, "what": "grant" }),
    );
    assert_eq!(result(&revoke)["revoked"], true);
    assert_eq!(caps(&core), json!({}));
}

/// A cap expired, or behind a wall clock set back (created after now),
/// covers nothing and stays in the file; a locked vault charges nothing;
/// a charge whose write fails signs nothing and isn't applied.
#[test]
fn no_signature_without_a_charge_that_stands() {
    let root = tempfile::tempdir().unwrap();
    let hook = root.path().join("hook");
    let hook_env = hook.to_string_lossy().into_owned();
    let now = now_s();
    let dir = root.path().join("userData");
    std::fs::create_dir_all(&dir).unwrap();
    let record = |created: u64, expires: u64| json!({ "capAmount": "50000", "spentAmount": "0", "createdAt": created, "expiresAt": expires });
    let text = serde_json::to_string_pretty(&json!({
        SELLER: { key_of(USDC): record(now - 100, now + 3600) },
        "https://later.example": { key_of(USDC): record(now + 1000, now + 5000) },
        "https://stale.example": { key_of(USDC): record(now - 100, now + 3) },
    }))
    .unwrap();
    std::fs::write(dir.join("x402-permissions.json"), &text).unwrap();
    let mut core = start(
        root.path(),
        &["x402"],
        &[("FREEDOM_CORED_TEST_GRANT_WRITE_FAIL", &hook_env)],
    );
    let mut id = 10;
    let reqs = requirements(vec![entry(USDC, "10000")]);
    let tab = detection(1, &format!("{SELLER}/a"));
    // Locked: nothing charged.
    let reply = pay_with_cap(&mut core, &mut id, &tab, &reqs);
    refused(&reply, "vault_locked", None);
    assert_eq!(file(&core).as_deref(), Some(text.as_str()));
    unlock(&mut core, &mut id);
    // Behind a clock set back: covers nothing, and stays.
    let later = detection(2, "https://later.example/a");
    refused(
        &pay_with_cap(&mut core, &mut id, &later, &reqs),
        "not_authorized",
        Some("cap"),
    );
    std::thread::sleep(std::time::Duration::from_secs(4));
    let stale = detection(3, "https://stale.example/a");
    refused(
        &pay_with_cap(&mut core, &mut id, &stale, &reqs),
        "not_authorized",
        Some("cap"),
    );
    assert_eq!(file(&core).as_deref(), Some(text.as_str()));
    for step in ["write", "fsync", "rename"] {
        std::fs::write(&hook, format!("x402:{step}")).unwrap();
        let reply = pay_with_cap(&mut core, &mut id, &tab, &reqs);
        refused(&reply, "storage", None);
        assert_eq!(
            reply["error"]["data"],
            json!({ "store": "x402", "applied": false })
        );
        assert_eq!(file(&core).as_deref(), Some(text.as_str()), "{step}");
    }
    assert!(changed(&mut core, &mut id).is_empty());
    std::fs::write(&hook, "").unwrap();
    // Not applied in memory either: the whole cap is there to charge.
    for spent in ["10000", "20000", "30000", "40000", "50000"] {
        let reply = pay_with_cap(&mut core, &mut id, &tab, &reqs);
        assert_eq!(result(&reply)["charged"], true);
        assert_eq!(caps(&core)[SELLER][key_of(USDC)]["spentAmount"], spent);
    }
    refused(
        &pay_with_cap(&mut core, &mut id, &tab, &reqs),
        "not_authorized",
        Some("cap"),
    );
    // A flush that fails after the rename: signed, and not durable.
    let reqs = requirements(vec![entry(USDC, "1")]);
    let t = token(
        &mut core,
        &mut id,
        0,
        &tab,
        0,
        &entry(USDC, "1"),
        Some(json!({ "cap_amount": "5", "window_seconds": 60 })),
    );
    std::fs::write(&hook, "x402:flush").unwrap();
    let reply = pay_with_token(
        &mut core,
        &mut id,
        &t,
        0,
        &tab,
        &reqs,
        0,
        Some(json!({ "cap_amount": "5", "window_seconds": 60 })),
    );
    assert_eq!(result(&reply)["durable"], false);
    assert_eq!(
        result(&reply)["grant"],
        json!({ "added": true, "durable": false })
    );
    assert_eq!(caps(&core)[SELLER][key_of(USDC)]["spentAmount"], "1");
}
