//! Design 0012's "A device send's rule" through the real binary (#373): a
//! flagged `dapp-send` spent under `page` for a device account (a Ledger, a
//! phone) gives a one-use finalize receipt, and `approval.remember {
//! receipt }`, from the same document, writes the rule its "Always allow"
//! asked for once main has the device's signature and has recorded the
//! send. A receipt that is unknown, expired, presented twice, evicted,
//! another document's, from a caller other than `page`, or outlived by a
//! narrowing of the page's grant writes nothing; nor does a spend whose
//! device refused, or a restart.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use common::*;
use serde_json::{Value, json};

const HANDLE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SITE: &str = "https://app.example";
const TO: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const APPROVE: &str = "0x095ea7b30000000000000000000000000000000000000000000000000000000000000001";
const DIGITS: &str = "0123456789abcdef";

fn page_as(origin: &str, frame: u64, navigation: u64) -> Value {
    page_in(origin, origin, frame, navigation)
}

/// A page whose document is framed in `top_origin`'s.
fn page_in(origin: &str, top_origin: &str, frame: u64, navigation: u64) -> Value {
    json!({ "caller": "page", "page": {
        "origin": origin, "top_origin": top_origin, "frame": frame, "navigation": navigation, "agent": false,
    } })
}

fn site() -> Value {
    page_as(SITE, 1, 1)
}

fn chrome() -> Value {
    json!({ "caller": "chrome" })
}

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

/// A core with `grant_moved`, its grant root created. No vault: a device's
/// send needs none.
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

/// Every file in `dir`, with its bytes.
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let bytes = std::fs::read(entry.path()).unwrap_or_default();
            (entry.file_name().to_string_lossy().into_owned(), bytes)
        })
        .collect()
}

fn tx_with(value: &str, data: &str) -> Value {
    json!({
        "type": 2, "chain_id": "100", "nonce": "7", "gas_limit": "60000", "to": TO,
        "value": value, "data": data,
        "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000000",
    })
}

fn tx(value: &str) -> Value {
    tx_with(value, APPROVE)
}

/// How a device account's send is minted and spent.
#[derive(Clone, Copy)]
enum Device {
    Ledger,
    Phone,
}

/// A device's send as main runs it: the `dapp-send` minted on the user's
/// approval, then spent by `approval.spend` before the device is asked.
/// The spend's result.
fn device_spend(
    core: &mut Core,
    id: &mut u64,
    context: &Value,
    device: Device,
    account: u32,
    tx: Value,
    remember: bool,
) -> Value {
    let payload = json!({ "tx": tx, "remember": remember });
    let mut issue =
        json!({ "kind": "dapp-send", "account": account, "handle": HANDLE, "payload": payload });
    if let Device::Phone = device {
        issue["phone"] = json!(true);
    }
    let issued = call_as(core, id, context, "approval.issue", issue);
    let token = result(&issued)["token"].as_str().unwrap().to_owned();
    let spent = call_as(
        core,
        id,
        context,
        "approval.spend",
        json!({ "token": token, "kind": "dapp-send", "account": account,
            "handle": HANDLE, "payload": payload }),
    );
    result(&spent).clone()
}

/// A flagged Ledger send of `value` for account 0, from `SITE`: its
/// receipt.
fn receipt(core: &mut Core, id: &mut u64, value: &str) -> String {
    let spent = device_spend(core, id, &site(), Device::Ledger, 0, tx(value), true);
    assert_eq!(spent["bound"], true, "{spent}");
    let receipt = spent["receipt"].as_str().unwrap().to_owned();
    assert_eq!(receipt.len(), 32, "{spent}");
    assert!(receipt.bytes().all(|b| DIGITS.as_bytes().contains(&b)));
    receipt
}

fn remember(core: &mut Core, id: &mut u64, context: &Value, receipt: &str) -> Value {
    call_as(
        core,
        id,
        context,
        "approval.remember",
        json!({ "receipt": receipt }),
    )
}

fn connect(core: &mut Core, id: &mut u64, account: u32) {
    let granted = call_as(
        core,
        id,
        &site(),
        "approval.grant",
        json!({ "store": "dapp", "change": { "op": "connect", "account": account, "chain_id": 100 } }),
    );
    assert_eq!(
        result(&granted)["grant"]["walletIndex"],
        account,
        "{granted}"
    );
}

/// The `approval.changed` events so far.
fn changed(core: &mut Core, id: &mut u64) -> Vec<Value> {
    let _ = call_as(core, id, &chrome(), "vault.status", json!({}));
    std::mem::take(&mut core.events)
        .into_iter()
        .map(|event| event["data"].clone())
        .collect()
}

/// Whether the site's rule answers a send of `value`. A phone's send isn't
/// judged by the fee check, so this asks only the rule.
fn check_send(core: &mut Core, id: &mut u64, value: &str) -> Value {
    check_send_as(core, id, &site(), 0, value)
}

/// As [`check_send`], for `account` and the page `context`.
fn check_send_as(
    core: &mut Core,
    id: &mut u64,
    context: &Value,
    account: u32,
    value: &str,
) -> Value {
    let reply = call_as(
        core,
        id,
        context,
        "approval.check",
        json!({ "request": { "kind": "transaction", "account": account, "account_kind": "phone", "tx": tx(value) },
            "chain_id": 100, "paused": false }),
    );
    result(&reply).clone()
}

/// `approval.grant` of a dApp `change` for `context`'s own key.
fn grant_as(core: &mut Core, id: &mut u64, context: &Value, change: Value) -> Value {
    let granted = call_as(
        core,
        id,
        context,
        "approval.grant",
        json!({ "store": "dapp", "change": change }),
    );
    result(&granted).clone()
}

fn no_rule() -> Value {
    json!({ "covered": false, "reason": "no_rule" })
}

fn stored(core: &Core) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(core.grant_root.join("dapp-permissions.json")).unwrap(),
    )
    .unwrap()
}

/// A connected site, its connect's event taken.
fn connected(root: &Path, env: &[(&str, &str)]) -> (Core, u64) {
    let mut core = start(root, &["dapp"], env);
    let mut id = 10;
    connect(&mut core, &mut id, 0);
    assert_eq!(changed(&mut core, &mut id).len(), 1);
    (core, id)
}

/// The happy path: a Ledger's send, then a phone's. The spend writes
/// nothing; the receipt, presented once by its page, writes one limited
/// rule with one `approval.changed`, which `approval.check` then answers.
/// `approval.grant` still can't write a transaction rule.
#[test]
fn a_device_send_s_receipt_writes_its_rule() {
    let root = tempfile::tempdir().unwrap();
    let (mut core, mut id) = connected(root.path(), &[]);
    let dir = core.grant_root.clone();
    assert_eq!(check_send(&mut core, &mut id, "3"), no_rule());
    let before = snapshot(&dir);
    let ledger = receipt(&mut core, &mut id, "3");
    // The spend writes no rule: the device hasn't signed yet.
    assert_eq!(snapshot(&dir), before);
    assert!(changed(&mut core, &mut id).is_empty());
    assert_eq!(check_send(&mut core, &mut id, "3"), no_rule());
    // Signed on the device, and recorded: main presents the receipt.
    let reply = remember(&mut core, &mut id, &site(), &ledger);
    assert_eq!(*result(&reply), json!({ "rule": { "added": true } }));
    assert_eq!(
        changed(&mut core, &mut id),
        [json!({ "store": "dapp", "key": SITE })]
    );
    let rules = &stored(&core)[SITE]["autoApprove"]["limited"]["transactions"];
    assert_eq!(rules.as_array().unwrap().len(), 1, "{rules}");
    assert_eq!(rules[0]["to"], TO);
    assert_eq!(rules[0]["selector"], "0x095ea7b3");
    assert_eq!(rules[0]["chainId"], 100);
    assert_eq!(rules[0]["maxValue"], "3");
    assert!(rules[0]["grantedAt"].is_number());
    assert_eq!(
        check_send(&mut core, &mut id, "3"),
        json!({ "covered": true })
    );
    assert_eq!(check_send(&mut core, &mut id, "4"), no_rule());
    // Presented twice: nothing more.
    refused(
        &remember(&mut core, &mut id, &site(), &ledger),
        "not_authorized",
        Some("unknown_token"),
    );
    assert!(changed(&mut core, &mut id).is_empty());
    // A phone's send: the same, and its rule replaces the Ledger's.
    let phone = device_spend(&mut core, &mut id, &site(), Device::Phone, 0, tx("5"), true);
    let phone = phone["receipt"].as_str().unwrap().to_owned();
    let reply = remember(&mut core, &mut id, &site(), &phone);
    assert_eq!(*result(&reply), json!({ "rule": { "added": true } }));
    assert_eq!(changed(&mut core, &mut id).len(), 1);
    let rules = &stored(&core)[SITE]["autoApprove"]["limited"]["transactions"];
    assert_eq!(rules.as_array().unwrap().len(), 1, "{rules}");
    assert_eq!(rules[0]["maxValue"], "5");
    assert_eq!(
        check_send(&mut core, &mut id, "5"),
        json!({ "covered": true })
    );
    // A plain transfer has no selector: no rule, as at `sign.transaction`.
    let transfer = device_spend(
        &mut core,
        &mut id,
        &site(),
        Device::Ledger,
        0,
        tx_with("1", "0x"),
        true,
    );
    let transfer = transfer["receipt"].as_str().unwrap().to_owned();
    let reply = remember(&mut core, &mut id, &site(), &transfer);
    assert_eq!(
        *result(&reply),
        json!({ "rule": { "added": false, "reason": "no_rule" } })
    );
    assert!(changed(&mut core, &mut id).is_empty());
    // `approval.grant` still writes no transaction rule.
    refused(
        &call_as(
            &mut core,
            &mut id,
            &site(),
            "approval.grant",
            json!({ "store": "dapp", "change": { "op": "transaction" } }),
        ),
        "forbidden",
        None,
    );
}

/// A spend that isn't a flagged `dapp-send` under `page` gives no receipt:
/// a `dapp-send` without "Always allow", a wallet's send, a page's
/// message.
#[test]
fn only_a_flagged_page_send_gives_a_receipt() {
    let root = tempfile::tempdir().unwrap();
    let (mut core, mut id) = connected(root.path(), &[]);
    for device in [Device::Ledger, Device::Phone] {
        let spent = device_spend(&mut core, &mut id, &site(), device, 0, tx("3"), false);
        assert_eq!(spent, json!({ "bound": true }));
    }
    let issued = call_as(
        &mut core,
        &mut id,
        &shell(),
        "approval.issue",
        json!({ "kind": "wallet-send", "account": 0, "payload": { "tx": tx("3") } }),
    );
    let token = result(&issued)["token"].as_str().unwrap().to_owned();
    let spent = call_as(
        &mut core,
        &mut id,
        &shell(),
        "approval.spend",
        json!({ "token": token, "kind": "wallet-send", "account": 0, "payload": { "tx": tx("3") } }),
    );
    assert_eq!(*result(&spent), json!({ "bound": true }));
    let message = json!({ "message": "0x68656c6c6f" });
    let issued = call_as(
        &mut core,
        &mut id,
        &site(),
        "approval.issue",
        json!({ "kind": "sign-message", "account": 0, "handle": HANDLE, "payload": message }),
    );
    let token = result(&issued)["token"].as_str().unwrap().to_owned();
    let spent = call_as(
        &mut core,
        &mut id,
        &site(),
        "approval.spend",
        json!({ "token": token, "kind": "sign-message", "account": 0, "handle": HANDLE, "payload": message }),
    );
    assert_eq!(*result(&spent), json!({ "bound": true }));
}

/// A receipt presented by another origin, frame or navigation is refused
/// (`mismatch`) and consumed: its own page can't present it after. One the
/// core never gave, or no receipt at all, is `unknown_token`; a malformed
/// request is `invalid_argument`, and consumes the receipt it names.
#[test]
fn another_document_s_receipt_writes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let (mut core, mut id) = connected(root.path(), &[]);
    let dir = core.grant_root.clone();
    let before = snapshot(&dir);
    for other in [
        page_as("https://other.example", 1, 1),
        page_as(SITE, 2, 1),
        page_as(SITE, 1, 2),
    ] {
        let receipt = receipt(&mut core, &mut id, "3");
        refused(
            &remember(&mut core, &mut id, &other, &receipt),
            "not_authorized",
            Some("mismatch"),
        );
        refused(
            &remember(&mut core, &mut id, &site(), &receipt),
            "not_authorized",
            Some("unknown_token"),
        );
    }
    for unknown in [
        "0".repeat(32),
        "not a receipt".to_owned(),
        String::new(),
        receipt(&mut core, &mut id, "3").to_uppercase(),
    ] {
        refused(
            &remember(&mut core, &mut id, &site(), &unknown),
            "not_authorized",
            Some("unknown_token"),
        );
    }
    let receipt = receipt(&mut core, &mut id, "3");
    for malformed in [
        json!({ "receipt": receipt, "account": 0 }),
        json!({ "receipt": 7 }),
        json!({}),
    ] {
        refused(
            &call_as(&mut core, &mut id, &site(), "approval.remember", malformed),
            "invalid_argument",
            None,
        );
    }
    refused(
        &remember(&mut core, &mut id, &site(), &receipt),
        "not_authorized",
        Some("unknown_token"),
    );
    // A page request without its page context.
    let receipt = self::receipt(&mut core, &mut id, "3");
    refused(
        &remember(&mut core, &mut id, &json!({ "caller": "page" }), &receipt),
        "invalid_argument",
        None,
    );
    assert_eq!(snapshot(&dir), before);
    assert!(changed(&mut core, &mut id).is_empty());
    assert_eq!(check_send(&mut core, &mut id, "3"), no_rule());
}

/// `chrome` and `shell` can't present a receipt (the method table): it
/// stays for its page, which then writes the rule.
#[test]
fn chrome_and_shell_can_t_present_a_receipt() {
    let root = tempfile::tempdir().unwrap();
    let (mut core, mut id) = connected(root.path(), &[]);
    let receipt = receipt(&mut core, &mut id, "3");
    for context in [chrome(), shell()] {
        refused(
            &remember(&mut core, &mut id, &context, &receipt),
            "forbidden",
            None,
        );
    }
    assert!(changed(&mut core, &mut id).is_empty());
    let reply = remember(&mut core, &mut id, &site(), &receipt);
    assert_eq!(*result(&reply), json!({ "rule": { "added": true } }));
}

/// A narrowing between the spend and the receipt wins: a disconnect (the
/// page's or the chrome's), a rule turned off, or the account's deletion
/// drops the key's receipts, and a connect made again doesn't bring them
/// back. A grant that no longer exposes the account writes nothing
/// (`not_exposed`), and the receipt is gone.
#[test]
fn a_narrowing_after_the_spend_writes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let (mut core, mut id) = connected(root.path(), &[]);
    let revokes = [
        (
            site(),
            "approval.revoke",
            json!({ "store": "dapp", "key": SITE, "what": "grant" }),
        ),
        (
            chrome(),
            "approval.revoke",
            json!({ "store": "dapp", "key": SITE, "what": "grant" }),
        ),
        (
            chrome(),
            "approval.revoke",
            json!({ "store": "dapp", "key": SITE,
                "what": { "transaction": { "to": TO, "selector": "0x095ea7b3", "chain_id": 100 } } }),
        ),
        (
            site(),
            "approval.revoke",
            json!({ "store": "dapp", "key": SITE, "what": "signing" }),
        ),
        (
            shell(),
            "approval.forget_account",
            json!({ "wallet_index": 0 }),
        ),
    ];
    for (context, method, params) in revokes {
        let receipt = receipt(&mut core, &mut id, "3");
        let revoked = call_as(&mut core, &mut id, &context, method, params.clone());
        assert!(revoked["result"].is_object(), "{params}: {revoked}");
        // Connected again before the device's answer comes back.
        connect(&mut core, &mut id, 0);
        let _ = changed(&mut core, &mut id);
        refused(
            &remember(&mut core, &mut id, &site(), &receipt),
            "not_authorized",
            Some("unknown_token"),
        );
        assert!(changed(&mut core, &mut id).is_empty(), "{params}");
        assert_eq!(check_send(&mut core, &mut id, "3"), no_rule(), "{params}");
    }
    // Another site's revoke leaves this site's receipt.
    let receipt = receipt(&mut core, &mut id, "3");
    let revoked = call_as(
        &mut core,
        &mut id,
        &chrome(),
        "approval.revoke",
        json!({ "store": "dapp", "key": "https://other.example", "what": "grant" }),
    );
    assert!(revoked["result"].is_object(), "{revoked}");
    let reply = remember(&mut core, &mut id, &site(), &receipt);
    assert_eq!(*result(&reply), json!({ "rule": { "added": true } }));
    assert_eq!(changed(&mut core, &mut id).len(), 1);
    let off = call_as(
        &mut core,
        &mut id,
        &site(),
        "approval.revoke",
        json!({ "store": "dapp", "key": SITE,
            "what": { "transaction": { "to": TO, "selector": "0x095ea7b3", "chain_id": 100 } } }),
    );
    assert_eq!(*result(&off), json!({ "revoked": true }));
    let _ = changed(&mut core, &mut id);
    // The grant moved to another account: not exposed, and consumed.
    let receipt = self::receipt(&mut core, &mut id, "3");
    let moved = call_as(
        &mut core,
        &mut id,
        &site(),
        "approval.grant",
        json!({ "store": "dapp", "change": { "op": "account", "account": 1 } }),
    );
    assert!(moved["result"].is_object(), "{moved}");
    let _ = changed(&mut core, &mut id);
    let reply = remember(&mut core, &mut id, &site(), &receipt);
    assert_eq!(
        *result(&reply),
        json!({ "rule": { "added": false, "reason": "not_exposed" } })
    );
    assert!(changed(&mut core, &mut id).is_empty());
    refused(
        &remember(&mut core, &mut id, &site(), &receipt),
        "not_authorized",
        Some("unknown_token"),
    );
    assert_eq!(check_send(&mut core, &mut id, "3"), no_rule());
}

/// A receipt binds the document and the account its own spend named: here
/// an embedded origin under another top origin, frame 7, navigation 9 and
/// account 3, none of them the other tests' values. Only that document
/// presents it (each of the origin, the frame and the navigation changed
/// alone is a `mismatch`), and its rule is written, for that origin's key,
/// only once the key's grant exposes account 3.
#[test]
fn a_receipt_binds_its_own_spend_s_document_and_account() {
    const DEX: &str = "https://dex.example";
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &["dapp"], &[]);
    let mut id = 10;
    let framed = page_in(DEX, "https://portal.example", 7, 9);
    let granted = grant_as(
        &mut core,
        &mut id,
        &framed,
        json!({ "op": "connect", "account": 0, "chain_id": 100 }),
    );
    assert_eq!(granted["grant"]["walletIndex"], 0, "{granted}");
    let _ = changed(&mut core, &mut id);
    let spend = |core: &mut Core, id: &mut u64| {
        let spent = device_spend(core, id, &framed, Device::Ledger, 3, tx("3"), true);
        spent["receipt"].as_str().unwrap().to_owned()
    };
    // Its own document, while the grant exposes account 0: not account 3's.
    let receipt = spend(&mut core, &mut id);
    let reply = remember(&mut core, &mut id, &framed, &receipt);
    assert_eq!(
        *result(&reply),
        json!({ "rule": { "added": false, "reason": "not_exposed" } })
    );
    // Each of its facts changed alone: another document's, and consumed.
    for other in [
        page_in(SITE, "https://portal.example", 7, 9),
        page_in(DEX, "https://portal.example", 1, 9),
        page_in(DEX, "https://portal.example", 7, 1),
    ] {
        let receipt = spend(&mut core, &mut id);
        refused(
            &remember(&mut core, &mut id, &other, &receipt),
            "not_authorized",
            Some("mismatch"),
        );
        refused(
            &remember(&mut core, &mut id, &framed, &receipt),
            "not_authorized",
            Some("unknown_token"),
        );
    }
    assert!(changed(&mut core, &mut id).is_empty());
    assert_eq!(
        check_send_as(&mut core, &mut id, &framed, 3, "3")["covered"],
        false
    );
    // The grant moved to account 3: its own document writes the rule, for
    // its own key.
    let moved = grant_as(
        &mut core,
        &mut id,
        &framed,
        json!({ "op": "account", "account": 3 }),
    );
    assert_eq!(moved["grant"]["walletIndex"], 3, "{moved}");
    let _ = changed(&mut core, &mut id);
    let receipt = spend(&mut core, &mut id);
    let reply = remember(&mut core, &mut id, &framed, &receipt);
    assert_eq!(*result(&reply), json!({ "rule": { "added": true } }));
    assert_eq!(
        changed(&mut core, &mut id),
        [json!({ "store": "dapp", "key": DEX })]
    );
    let file = stored(&core);
    assert_eq!(
        file[DEX]["autoApprove"]["limited"]["transactions"][0]["maxValue"],
        "3"
    );
    assert!(file.get(SITE).is_none(), "{file}");
    assert!(file.get("https://portal.example").is_none(), "{file}");
    assert_eq!(
        check_send_as(&mut core, &mut id, &framed, 3, "3"),
        json!({ "covered": true })
    );
    assert_eq!(
        check_send_as(&mut core, &mut id, &framed, 0, "3")["covered"],
        false
    );
}

/// `approval.forget_account` drops the account's receipts itself, not only
/// those of the keys it revokes: a receipt for account 1, spent while the
/// key's grant exposes account 0, writes nothing once account 1 is
/// deleted, even after the grant moves to account 1. Without the deletion
/// the same sequence writes the rule.
#[test]
fn forgetting_an_account_drops_its_receipts() {
    let root = tempfile::tempdir().unwrap();
    let (mut core, mut id) = connected(root.path(), &[]);
    let to_account = |core: &mut Core, id: &mut u64, account: u32| {
        let moved = grant_as(
            core,
            id,
            &site(),
            json!({ "op": "account", "account": account }),
        );
        assert_eq!(moved["grant"]["walletIndex"], account, "{moved}");
        let _ = changed(core, id);
    };
    let spend = |core: &mut Core, id: &mut u64| {
        let spent = device_spend(core, id, &site(), Device::Ledger, 1, tx("3"), true);
        spent["receipt"].as_str().unwrap().to_owned()
    };
    // Without the deletion: written once the grant exposes account 1.
    let receipt = spend(&mut core, &mut id);
    to_account(&mut core, &mut id, 1);
    let reply = remember(&mut core, &mut id, &site(), &receipt);
    assert_eq!(*result(&reply), json!({ "rule": { "added": true } }));
    let off = call_as(
        &mut core,
        &mut id,
        &site(),
        "approval.revoke",
        json!({ "store": "dapp", "key": SITE,
            "what": { "transaction": { "to": TO, "selector": "0x095ea7b3", "chain_id": 100 } } }),
    );
    assert_eq!(*result(&off), json!({ "revoked": true }));
    to_account(&mut core, &mut id, 0);
    // With it: account 1 deleted while the grant exposes account 0, so no
    // key is revoked.
    let receipt = spend(&mut core, &mut id);
    let gone = call_as(
        &mut core,
        &mut id,
        &shell(),
        "approval.forget_account",
        json!({ "wallet_index": 1 }),
    );
    assert_eq!(*result(&gone), json!({ "keys": [] }));
    assert!(changed(&mut core, &mut id).is_empty());
    to_account(&mut core, &mut id, 1);
    refused(
        &remember(&mut core, &mut id, &site(), &receipt),
        "not_authorized",
        Some("unknown_token"),
    );
    assert!(changed(&mut core, &mut id).is_empty());
    assert_eq!(
        check_send_as(&mut core, &mut id, &site(), 1, "3"),
        no_rule()
    );
}

/// At most 64 receipts are open: the 65th spend drops the oldest.
#[test]
fn the_oldest_receipt_is_evicted_past_64() {
    let root = tempfile::tempdir().unwrap();
    let (mut core, mut id) = connected(root.path(), &[]);
    let receipts: Vec<String> = (0..65).map(|_| receipt(&mut core, &mut id, "3")).collect();
    refused(
        &remember(&mut core, &mut id, &site(), &receipts[0]),
        "not_authorized",
        Some("unknown_token"),
    );
    assert!(changed(&mut core, &mut id).is_empty());
    let reply = remember(&mut core, &mut id, &site(), &receipts[1]);
    assert_eq!(*result(&reply), json!({ "rule": { "added": true } }));
    let reply = remember(&mut core, &mut id, &site(), &receipts[64]);
    assert_eq!(*result(&reply), json!({ "rule": { "added": true } }));
}

/// A receipt expires (its life shortened by the test hook: the wire has no
/// clock to inject), and an expired one is consumed. One presented within
/// its life writes the rule.
#[test]
fn a_receipt_expires() {
    let root = tempfile::tempdir().unwrap();
    let (mut core, mut id) = connected(
        root.path(),
        &[("FREEDOM_CORED_TEST_RECEIPT_TTL_MS", "1500")],
    );
    let late = receipt(&mut core, &mut id, "3");
    std::thread::sleep(Duration::from_millis(2000));
    refused(
        &remember(&mut core, &mut id, &site(), &late),
        "not_authorized",
        Some("expired"),
    );
    refused(
        &remember(&mut core, &mut id, &site(), &late),
        "not_authorized",
        Some("unknown_token"),
    );
    assert!(changed(&mut core, &mut id).is_empty());
    assert_eq!(check_send(&mut core, &mut id, "3"), no_rule());
    let prompt = receipt(&mut core, &mut id, "3");
    let reply = remember(&mut core, &mut id, &site(), &prompt);
    assert_eq!(*result(&reply), json!({ "rule": { "added": true } }));
}

/// The device refused the signature, so main never presents the receipt:
/// no rule. A restart forgets every receipt.
#[test]
fn a_refused_signature_or_a_restart_writes_no_rule() {
    let root = tempfile::tempdir().unwrap();
    let (mut core, mut id) = connected(root.path(), &[]);
    let dir = core.grant_root.clone();
    let before = snapshot(&dir);
    let _refused = receipt(&mut core, &mut id, "3");
    let kept = receipt(&mut core, &mut id, "3");
    assert_eq!(snapshot(&dir), before);
    assert!(changed(&mut core, &mut id).is_empty());
    assert_eq!(check_send(&mut core, &mut id, "3"), no_rule());
    drop(core);
    let mut core = start(root.path(), &["dapp"], &[]);
    refused(
        &remember(&mut core, &mut id, &site(), &kept),
        "not_authorized",
        Some("unknown_token"),
    );
    assert_eq!(snapshot(&dir), before);
    assert!(changed(&mut core, &mut id).is_empty());
    assert_eq!(check_send(&mut core, &mut id, "3"), no_rule());
}

/// Before the dApp file moves, main still writes it: a receipt answers
/// `not_moved`, and nothing in the grant root changes.
#[test]
fn before_the_move_a_receipt_writes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &[], &[]);
    let dir = core.grant_root.clone();
    std::fs::write(
        dir.join("dapp-permissions.json"),
        serde_json::to_string_pretty(&json!({ SITE: {
            "origin": SITE, "connectedAt": 1_762_000_000_000_u64, "lastUsed": 1_762_000_000_000_u64,
            "walletIndex": 0, "chainId": 100, "autoApprove": { "signing": false, "transactions": [] },
        } }))
        .unwrap(),
    )
    .unwrap();
    let before = snapshot(&dir);
    let mut id = 10;
    let receipt = receipt(&mut core, &mut id, "3");
    let reply = remember(&mut core, &mut id, &site(), &receipt);
    assert_eq!(
        *result(&reply),
        json!({ "rule": { "added": false, "reason": "not_moved" } })
    );
    assert_eq!(snapshot(&dir), before);
    assert!(changed(&mut core, &mut id).is_empty());
}

/// A failed write: before the rename the rule isn't applied (`not_saved`,
/// no event); after a failed directory flush it is, `durable: false`.
#[test]
fn a_failed_write_says_so() {
    let root = tempfile::tempdir().unwrap();
    let hook = root.path().join("hook");
    let hook_env = hook.to_string_lossy().into_owned();
    let (mut core, mut id) = connected(
        root.path(),
        &[("FREEDOM_CORED_TEST_GRANT_WRITE_FAIL", &hook_env)],
    );
    std::fs::write(&hook, "dapp:rename").unwrap();
    let receipt = self::receipt(&mut core, &mut id, "3");
    let reply = remember(&mut core, &mut id, &site(), &receipt);
    assert_eq!(
        *result(&reply),
        json!({ "rule": { "added": false, "reason": "not_saved" } })
    );
    assert!(changed(&mut core, &mut id).is_empty());
    assert_eq!(check_send(&mut core, &mut id, "3"), no_rule());
    std::fs::write(&hook, "dapp:flush").unwrap();
    let receipt = self::receipt(&mut core, &mut id, "3");
    let reply = remember(&mut core, &mut id, &site(), &receipt);
    assert_eq!(
        *result(&reply),
        json!({ "rule": { "added": true, "durable": false } })
    );
    assert_eq!(changed(&mut core, &mut id).len(), 1);
    assert_eq!(
        check_send(&mut core, &mut id, "3"),
        json!({ "covered": true })
    );
}
