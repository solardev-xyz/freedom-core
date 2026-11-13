//! Design 0012's grant stores through the real binary (APR-3b): the hello's
//! `grant_root` and `grant_moved`; the four files read from APR-3, main's
//! own until each moves (`not_moved`, nothing in `grant_root` touched); a
//! moved file written atomically, `0600`, renamed aside when unreadable
//! (on Windows, another account's file too), within the bounds, with one
//! `approval.changed` per change and the failed-write rule at each step;
//! today's rules answering until `dapp` moves; a flagged `dapp-send`'s
//! rule; and an `intent-replace` spent at `sign.transaction`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const HANDLE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SITE: &str = "https://app.example";
const TO: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const APPROVE: &str = "0x095ea7b30000000000000000000000000000000000000000000000000000000000000001";
const INTENT: &str = "7b0c6c1e-0c62-4a6e-9a49-0d6a3f6d1a07";
const STORES: [(&str, &str); 4] = [
    ("dapp", "dapp-permissions.json"),
    ("swarm", "swarm-permissions.json"),
    ("radicle", "radicle-permissions.json"),
    ("x402", "x402-permissions.json"),
];

fn page_as(origin: &str, agent: bool) -> Value {
    json!({ "caller": "page", "page": {
        "origin": origin, "top_origin": origin, "frame": 1, "navigation": 1, "agent": agent,
    } })
}

fn site() -> Value {
    page_as(SITE, false)
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

fn refused(reply: &Value, code: &str) {
    assert_eq!(reply["error"]["code"], code, "{reply}");
}

fn account(index: u32) -> Value {
    json!({ "kind": "account", "index": index })
}

/// A core with `grant_moved`, its grant root created; unlocked if asked.
fn start(root: &Path, moved: &[&'static str], unlock: bool, env: &[(&str, &str)]) -> Core {
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
    if unlock {
        let imported = core.call(
            2,
            "vault.import",
            json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(ABANDON) }),
        );
        assert!(imported["result"].is_object(), "{imported}");
        assert_eq!(core.event()["event"], "vault.unlocked");
    }
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

/// A dApp file as main writes it today: connected with account 0 on chain
/// 100, with today's signing flag and a transaction rule.
fn today_dapp() -> String {
    serde_json::to_string_pretty(&json!({ SITE: {
        "origin": SITE, "connectedAt": 1_762_000_000_000_u64, "lastUsed": 1_762_000_000_000_u64,
        "walletIndex": 0, "chainId": 100,
        "autoApprove": { "signing": true, "transactions": [
            { "to": TO, "selector": "0x095ea7b3", "chainId": 100, "maxValue": "5" },
        ] },
    } }))
    .unwrap()
}

fn tx(value: &str) -> Value {
    json!({
        "type": 2, "chain_id": "100", "nonce": "7", "gas_limit": "60000", "to": TO,
        "value": value, "data": APPROVE,
        "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000000",
    })
}

fn check_message(core: &mut Core, id: &mut u64, context: &Value) -> Value {
    let reply = call_as(
        core,
        id,
        context,
        "approval.check",
        json!({ "request": { "kind": "message", "account": 0, "account_kind": "vault", "message": "0x68656c6c6f" } }),
    );
    result(&reply).clone()
}

fn check_send(core: &mut Core, id: &mut u64, value: &str) -> Value {
    // A phone's send isn't judged by the fee check, so no evidence is
    // needed for the rule itself.
    let reply = call_as(
        core,
        id,
        &site(),
        "approval.check",
        json!({ "request": { "kind": "transaction", "account": 0, "account_kind": "phone", "tx": tx(value) },
            "chain_id": 100, "paused": false }),
    );
    result(&reply).clone()
}

fn not_covered(reason: &str) -> Value {
    json!({ "covered": false, "reason": reason })
}

fn hello_reply(root: &Path, params: Value) -> (Value, i32) {
    let mut core = spawn("serve", &root.join("identity"), &root.join("locks"), &[]);
    let reply = core.call_shell(1, "core.hello", params);
    let code = if reply["error"].is_object() {
        core.exit_code(Duration::from_secs(5))
    } else {
        0
    };
    (reply, code)
}

/// The hello needs `grant_root`, an absolute path, and names only known
/// stores in `grant_moved`; otherwise `invalid_argument`, and the core exits.
/// A root that doesn't exist yet is fine: its files are missing.
#[test]
fn the_hello_names_the_grant_root() {
    let root = tempfile::tempdir().unwrap();
    let base =
        json!({ "protocol": 2, "shell_version": "t", "auto_lock_ms": 0, "frames": ["stream"] });
    let with = |extra: Value| {
        let mut params = base.clone();
        for (key, value) in extra.as_object().unwrap() {
            params[key] = value.clone();
        }
        params
    };
    let absent = root.path().join("absent");
    for params in [
        base.clone(),
        with(json!({ "grant_root": "relative/userData" })),
        with(json!({ "grant_root": format!("{}/../userData", root.path().display()) })),
        with(json!({ "grant_root": 7 })),
        with(json!({ "grant_root": absent, "grant_moved": ["dapp", "cookies"] })),
    ] {
        let (reply, code) = hello_reply(root.path(), params.clone());
        assert_eq!(
            reply["error"]["code"], "invalid_argument",
            "{params}: {reply}"
        );
        assert_eq!(code, 76, "{params}");
    }
    let (reply, _) = hello_reply(
        root.path(),
        with(json!({ "grant_root": absent, "grant_moved": ["dapp", "swarm", "radicle", "x402"] })),
    );
    assert_eq!(reply["result"]["protocol"], 2, "{reply}");
    assert!(!absent.exists());
}

/// Before a file moves, every write method answers `not_moved` with its
/// store, from each caller that may call it, and nothing in `grant_root`
/// changes: not the files, a temp file beside them, nor an unreadable one.
#[test]
fn before_the_move_main_is_the_only_writer() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &[], false, &[]);
    let dir = core.grant_root.clone();
    std::fs::write(dir.join("dapp-permissions.json"), today_dapp()).unwrap();
    std::fs::write(dir.join("swarm-permissions.json"), b"{ not json").unwrap();
    std::fs::write(dir.join(".radicle-permissions.json.1.0.tmp"), b"{}").unwrap();
    let before = snapshot(&dir);
    let mut id = 10;
    let not_moved = |reply: &Value, store: &str| {
        assert_eq!(reply["error"]["code"], "not_moved", "{reply}");
        assert_eq!(reply["error"]["data"]["store"], store, "{reply}");
    };
    for (store, change) in [
        (
            "dapp",
            json!({ "op": "connect", "account": 0, "chain_id": 1 }),
        ),
        ("dapp", json!({ "op": "signing" })),
        ("swarm", json!({ "op": "connect" })),
        ("radicle", json!({ "op": "flag", "flag": "node" })),
    ] {
        let reply = call_as(
            &mut core,
            &mut id,
            &site(),
            "approval.grant",
            json!({ "store": store, "change": change }),
        );
        not_moved(&reply, store);
    }
    let reply = call_as(
        &mut core,
        &mut id,
        &shell(),
        "approval.grant",
        json!({ "store": "swarm", "change": { "op": "flag", "key": SITE, "flag": "publish" } }),
    );
    not_moved(&reply, "swarm");
    for (store, _) in STORES {
        for context in [site(), chrome(), shell()] {
            let reply = call_as(
                &mut core,
                &mut id,
                &context,
                "approval.revoke",
                json!({ "store": store, "key": SITE, "what": "grant" }),
            );
            not_moved(&reply, store);
        }
    }
    for store in ["dapp", "swarm", "radicle"] {
        let reply = call_as(
            &mut core,
            &mut id,
            &site(),
            "approval.touch",
            json!({ "store": store }),
        );
        not_moved(&reply, store);
    }
    let reply = call_as(
        &mut core,
        &mut id,
        &shell(),
        "approval.forget_account",
        json!({ "wallet_index": 0 }),
    );
    not_moved(&reply, "dapp");
    // Grant writes are refused for the chrome (the method table), an x402
    // cap for everyone, and a transaction rule always.
    refused(
        &call_as(
            &mut core,
            &mut id,
            &chrome(),
            "approval.grant",
            json!({ "store": "dapp", "change": { "op": "signing" } }),
        ),
        "forbidden",
    );
    refused(
        &call_as(
            &mut core,
            &mut id,
            &site(),
            "approval.grant",
            json!({ "store": "x402", "change": { "op": "connect" } }),
        ),
        "forbidden",
    );
    refused(
        &call_as(
            &mut core,
            &mut id,
            &site(),
            "approval.grant",
            json!({ "store": "dapp", "change": { "op": "transaction" } }),
        ),
        "forbidden",
    );
    // Main sends no events for a store the core doesn't write.
    let _ = call_as(&mut core, &mut id, &chrome(), "vault.status", json!({}));
    assert!(core.events.is_empty(), "{:?}", core.events);
    assert_eq!(snapshot(&dir), before);
}

/// Before the move the core reads the file main last renamed into place, at
/// each check: today's rules answer as the reference answers them, a grant
/// removed stops answering, a missing file is an empty store, and an
/// unreadable one (or a symlink) reads as empty and stays where it is.
#[test]
fn main_s_file_answers_at_the_next_check() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &[], true, &[]);
    let dir = core.grant_root.clone();
    let file = dir.join("dapp-permissions.json");
    let mut id = 10;
    assert_eq!(
        check_message(&mut core, &mut id, &site()),
        not_covered("no_rule")
    );
    // Renamed into place by another process, as main writes it.
    std::fs::write(dir.join("staged"), today_dapp()).unwrap();
    std::fs::rename(dir.join("staged"), &file).unwrap();
    assert_eq!(
        check_message(&mut core, &mut id, &site()),
        json!({ "covered": true })
    );
    assert_eq!(
        check_message(&mut core, &mut id, &page_as(SITE, true)),
        not_covered("custody")
    );
    assert_eq!(
        check_send(&mut core, &mut id, "5"),
        json!({ "covered": true })
    );
    // Today's rule caps `value` with its `maxValue`.
    assert_eq!(check_send(&mut core, &mut id, "6"), not_covered("no_rule"));
    // Today's rules have no rate: more than R-6's burst still signs.
    for _ in 0..7 {
        let signed = call_as(
            &mut core,
            &mut id,
            &site(),
            "sign.message",
            json!({ "key": account(0), "message": "0x68656c6c6f", "authorization": { "standing": {} } }),
        );
        assert!(result(&signed)["signature"].is_string(), "{signed}");
    }
    // Another account than the grant's: no rule.
    let other = call_as(
        &mut core,
        &mut id,
        &site(),
        "sign.message",
        json!({ "key": account(1), "message": "0x68656c6c6f", "authorization": { "standing": {} } }),
    );
    assert_eq!(other["error"]["data"]["reason"], "no_rule", "{other}");
    // The chrome reads the records.
    let records = call_as(
        &mut core,
        &mut id,
        &chrome(),
        "approval.grants",
        json!({ "store": "dapp" }),
    );
    assert_eq!(result(&records)["records"][0]["walletIndex"], 0);
    // An unreadable file reads as empty, and stays.
    std::fs::write(&file, b"{ torn").unwrap();
    assert_eq!(
        check_message(&mut core, &mut id, &site()),
        not_covered("no_rule")
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"{ torn");
    // A symlink to a good file isn't followed.
    #[cfg(unix)]
    {
        std::fs::write(dir.join("elsewhere"), today_dapp()).unwrap();
        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere"), &file).unwrap();
        assert_eq!(
            check_message(&mut core, &mut id, &site()),
            not_covered("no_rule")
        );
        assert!(file.symlink_metadata().unwrap().file_type().is_symlink());
    }
    // Removed: no rule.
    std::fs::remove_file(&file).unwrap();
    assert_eq!(
        check_message(&mut core, &mut id, &site()),
        not_covered("no_rule")
    );
    assert!(!dir.join("dapp-permissions.json.unreadable").exists());
}

/// Makes the SID `sid` `path`'s owner (`icacls /setowner`), which takes an
/// administrator's restore privilege, as CI's runner has.
#[cfg(windows)]
fn set_owner(path: &Path, sid: &str) {
    let output = std::process::Command::new("icacls")
        .arg(path)
        .arg("/setowner")
        .arg(format!("*{sid}"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "icacls /setowner {sid} (run as an administrator): {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// The dApp store's records, as the chrome reads them.
#[cfg(windows)]
fn dapp_records(core: &mut Core, id: &mut u64) -> Value {
    let records = call_as(
        core,
        id,
        &chrome(),
        "approval.grants",
        json!({ "store": "dapp" }),
    );
    result(&records)["records"].clone()
}

/// On Windows, as on Unix, a file another account owns reads as an empty
/// store (freedom-core#360): main's stays where it is, and a moved one is
/// renamed aside at the hello, as any moved file that can't be read.
/// BUILTIN\Users stands for the other account: a group the user is in, and
/// never the user.
#[cfg(windows)]
#[test]
fn a_file_another_account_owns_reads_as_empty() {
    // Before the move: read, then not once another account owns it.
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &[], true, &[]);
    let dir = core.grant_root.clone();
    let file = dir.join("dapp-permissions.json");
    let mut id = 10;
    std::fs::write(&file, today_dapp()).unwrap();
    assert_eq!(
        check_message(&mut core, &mut id, &site()),
        json!({ "covered": true })
    );
    assert_eq!(dapp_records(&mut core, &mut id)[0]["walletIndex"], 0);
    set_owner(&file, "S-1-5-32-545");
    assert_eq!(
        check_message(&mut core, &mut id, &site()),
        not_covered("no_rule")
    );
    assert_eq!(dapp_records(&mut core, &mut id), json!([]));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), today_dapp());
    assert!(!dir.join("dapp-permissions.json.unreadable").exists());
    drop(core);

    // Moved: renamed aside, the store empty.
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("userData");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("dapp-permissions.json");
    std::fs::write(&file, today_dapp()).unwrap();
    set_owner(&file, "S-1-5-32-545");
    let mut core = start(root.path(), &["dapp"], true, &[]);
    let mut id = 10;
    assert_eq!(dapp_records(&mut core, &mut id), json!([]));
    assert_eq!(
        check_message(&mut core, &mut id, &site()),
        not_covered("no_rule")
    );
    assert!(!file.exists());
    assert_eq!(
        std::fs::read_to_string(dir.join("dapp-permissions.json.unreadable")).unwrap(),
        today_dapp()
    );
}

/// Before the move, a flagged `dapp-send` signs, writes no rule, and says
/// so (`not_moved`); main writes today's rule as it does today.
#[test]
fn a_flagged_send_before_the_move_writes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &[], true, &[]);
    let dir = core.grant_root.clone();
    std::fs::write(dir.join("dapp-permissions.json"), today_dapp()).unwrap();
    let before = snapshot(&dir);
    let mut id = 10;
    let issued = call_as(
        &mut core,
        &mut id,
        &site(),
        "approval.issue",
        json!({ "kind": "dapp-send", "account": 0, "handle": HANDLE,
            "payload": { "tx": tx("1"), "remember": true } }),
    );
    let token = result(&issued)["token"].as_str().unwrap().to_owned();
    let signed = call_as(
        &mut core,
        &mut id,
        &site(),
        "sign.transaction",
        json!({ "key": account(0), "tx": tx("1"), "authorization": { "token": token, "handle": HANDLE } }),
    );
    assert!(result(&signed)["raw"].is_string(), "{signed}");
    assert_eq!(
        result(&signed)["rule"],
        json!({ "added": false, "reason": "not_moved" })
    );
    assert_eq!(snapshot(&dir), before);
}

fn grant(core: &mut Core, id: &mut u64, context: &Value, store: &str, change: Value) -> Value {
    call_as(
        core,
        id,
        context,
        "approval.grant",
        json!({ "store": store, "change": change }),
    )
}

fn changed(core: &mut Core, id: &mut u64) -> Vec<Value> {
    let _ = call_as(core, id, &chrome(), "vault.status", json!({}));
    std::mem::take(&mut core.events)
        .into_iter()
        .map(|event| event["data"].clone())
        .collect()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Once `dapp` moves, the core writes it: atomically, `0600`, one
/// `approval.changed` per change, read again after a restart. Q9's limited
/// rules answer, today's don't. A flagged send writes its rule only for an
/// account the page's grant exposes. Revokes: the chrome's for any key, a
/// page's for its own.
#[test]
fn a_moved_dapp_file_is_the_core_s() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("userData");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("dapp-permissions.json"), today_dapp()).unwrap();
    std::fs::write(
        dir.join(".dapp-permissions.json.4242.0.tmp"),
        b"left by a crash",
    )
    .unwrap();
    let mut core = start(root.path(), &["dapp"], true, &[]);
    let file = dir.join("dapp-permissions.json");
    // The core's temp files are cleaned at start.
    assert!(!dir.join(".dapp-permissions.json.4242.0.tmp").exists());
    let mut id = 10;
    // Today's rule answers nothing once the file has moved.
    assert_eq!(
        check_message(&mut core, &mut id, &site()),
        not_covered("no_rule")
    );
    let granted = grant(
        &mut core,
        &mut id,
        &site(),
        "dapp",
        json!({ "op": "connect", "account": 0, "chain_id": 100 }),
    );
    assert_eq!(result(&granted)["grant"]["walletIndex"], 0, "{granted}");
    assert_eq!(
        changed(&mut core, &mut id),
        [json!({ "store": "dapp", "key": SITE })]
    );
    #[cfg(unix)]
    assert_eq!(mode(&file), 0o600);
    let signing = grant(
        &mut core,
        &mut id,
        &site(),
        "dapp",
        json!({ "op": "signing" }),
    );
    assert!(
        result(&signing)["grant"]["autoApprove"]["limited"]["signing"]["grantedAt"].is_number()
    );
    assert_eq!(changed(&mut core, &mut id).len(), 1);
    assert_eq!(
        check_message(&mut core, &mut id, &site()),
        json!({ "covered": true })
    );
    // The file holds what the store holds, as JS writes it.
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(
        text.starts_with("{\n  \"https://app.example\": {\n"),
        "{text}"
    );
    // A flagged send writes its rule as it signs.
    let issue = |core: &mut Core, id: &mut u64, account: u32, remember: bool| {
        let issued = call_as(
            core,
            id,
            &site(),
            "approval.issue",
            json!({ "kind": "dapp-send", "account": account, "handle": HANDLE,
                "payload": { "tx": tx("3"), "remember": remember } }),
        );
        result(&issued)["token"].as_str().unwrap().to_owned()
    };
    let sign = |core: &mut Core, id: &mut u64, account_index: u32, token: String| {
        let signed = call_as(
            core,
            id,
            &site(),
            "sign.transaction",
            json!({ "key": account(account_index), "tx": tx("3"),
                "authorization": { "token": token, "handle": HANDLE } }),
        );
        result(&signed).clone()
    };
    let token = issue(&mut core, &mut id, 0, false);
    assert!(sign(&mut core, &mut id, 0, token).get("rule").is_none());
    assert!(changed(&mut core, &mut id).is_empty());
    let token = issue(&mut core, &mut id, 1, true);
    assert_eq!(
        sign(&mut core, &mut id, 1, token)["rule"],
        json!({ "added": false, "reason": "not_exposed" })
    );
    let token = issue(&mut core, &mut id, 0, true);
    assert_eq!(
        sign(&mut core, &mut id, 0, token)["rule"],
        json!({ "added": true })
    );
    assert_eq!(changed(&mut core, &mut id).len(), 1);
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let rule = &stored[SITE]["autoApprove"]["limited"]["transactions"][0];
    assert_eq!(rule["maxValue"], "3");
    assert_eq!(rule["selector"], "0x095ea7b3");
    // Today's rule for the same call is cleared in the same write.
    assert_eq!(stored[SITE]["autoApprove"]["transactions"], json!([]));
    assert_eq!(
        check_send(&mut core, &mut id, "3"),
        json!({ "covered": true })
    );
    assert_eq!(check_send(&mut core, &mut id, "4"), not_covered("no_rule"));
    // A restart reads the file again.
    drop(core);
    let mut core = start(root.path(), &["dapp"], false, &[]);
    assert_eq!(
        check_message(&mut core, &mut id, &site()),
        json!({ "covered": true })
    );
    // A page revokes only its own grant; the chrome any.
    refused(
        &call_as(
            &mut core,
            &mut id,
            &page_as("https://other.example", false),
            "approval.revoke",
            json!({ "store": "dapp", "key": SITE, "what": "signing" }),
        ),
        "forbidden",
    );
    let off = call_as(
        &mut core,
        &mut id,
        &chrome(),
        "approval.revoke",
        json!({ "store": "dapp", "key": SITE, "what": "signing" }),
    );
    assert_eq!(*result(&off), json!({ "revoked": true }));
    assert_eq!(
        check_message(&mut core, &mut id, &site()),
        not_covered("no_rule")
    );
    let gone = call_as(
        &mut core,
        &mut id,
        &shell(),
        "approval.forget_account",
        json!({ "wallet_index": 0 }),
    );
    assert_eq!(result(&gone)["keys"], json!([SITE]));
    assert_eq!(changed(&mut core, &mut id).len(), 2);
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(stored, json!({}));
}

/// A moved file that can't be read is renamed aside once, and its store
/// starts empty; a file past a bound is unreadable too. A write that would
/// pass a bound is refused, the store unchanged.
#[test]
fn bounds_and_unreadable_moved_files() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("userData");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("swarm-permissions.json"), b"[1, 2]").unwrap();
    let site_entry = |origin: &str| {
        json!({ "origin": origin, "connectedAt": 1, "lastUsed": 1,
            "autoApprove": { "node": false, "signing": false }, "signing": false })
    };
    let mut many = serde_json::Map::new();
    for n in 0..4096 {
        let origin = format!("https://s{n}.example");
        many.insert(origin.clone(), site_entry(&origin));
    }
    let full = serde_json::to_string_pretty(&Value::Object(many.clone())).unwrap();
    std::fs::write(dir.join("radicle-permissions.json"), &full).unwrap();
    many.insert(
        "https://s4096.example".into(),
        site_entry("https://s4096.example"),
    );
    let past = serde_json::to_string_pretty(&Value::Object(many)).unwrap();
    std::fs::write(dir.join("x402-permissions.json"), b"\"not an object\"").unwrap();
    // 256 of today's rules on one key: read.
    let rules: Vec<Value> = (0..256)
        .map(|n| json!({ "to": format!("0x{n:040x}"), "selector": "0x12345678", "chainId": 100, "maxValue": "0" }))
        .collect();
    let dapp = json!({ SITE: { "origin": SITE, "connectedAt": 1, "lastUsed": 1, "walletIndex": 0,
        "chainId": 100, "autoApprove": { "signing": false, "transactions": rules } } });
    std::fs::write(dir.join("dapp-permissions.json"), dapp.to_string()).unwrap();
    let mut core = start(
        root.path(),
        &["dapp", "swarm", "radicle", "x402"],
        true,
        &[],
    );
    let mut id = 10;
    assert_eq!(
        std::fs::read(dir.join("swarm-permissions.json.unreadable")).unwrap(),
        b"[1, 2]"
    );
    assert!(!dir.join("swarm-permissions.json").exists());
    assert!(dir.join("x402-permissions.json.unreadable").exists());
    // 4,096 keys: read, and a 4,097th refused with the store unchanged.
    let radicle = call_as(
        &mut core,
        &mut id,
        &chrome(),
        "approval.grants",
        json!({ "store": "radicle" }),
    );
    assert_eq!(result(&radicle)["records"].as_array().unwrap().len(), 4096);
    refused(
        &grant(
            &mut core,
            &mut id,
            &page_as("https://s4096.example", false),
            "radicle",
            json!({ "op": "connect" }),
        ),
        "invalid_argument",
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("radicle-permissions.json")).unwrap(),
        full
    );
    assert!(changed(&mut core, &mut id).is_empty());
    // A 257th rule on one key: refused, as the flagged send's reply says.
    let issued = call_as(
        &mut core,
        &mut id,
        &site(),
        "approval.issue",
        json!({ "kind": "dapp-send", "account": 0, "handle": HANDLE,
            "payload": { "tx": tx("0"), "remember": true } }),
    );
    let token = result(&issued)["token"].as_str().unwrap().to_owned();
    let signed = call_as(
        &mut core,
        &mut id,
        &site(),
        "sign.transaction",
        json!({ "key": account(0), "tx": tx("0"), "authorization": { "token": token, "handle": HANDLE } }),
    );
    assert_eq!(
        result(&signed)["rule"],
        json!({ "added": false, "reason": "bounds" })
    );
    drop(core);
    // A file past the key bound, at the next start: renamed aside.
    std::fs::write(dir.join("radicle-permissions.json"), &past).unwrap();
    let mut core = start(root.path(), &["radicle"], false, &[]);
    assert_eq!(
        std::fs::read_to_string(dir.join("radicle-permissions.json.unreadable")).unwrap(),
        past
    );
    let radicle = call_as(
        &mut core,
        &mut id,
        &chrome(),
        "approval.grants",
        json!({ "store": "radicle" }),
    );
    assert_eq!(result(&radicle)["records"], json!([]));
}

/// A failed write, by a hook at each step: before the rename the error is
/// reported and the file is unchanged; a widening isn't active, a narrowing
/// is, and says it isn't saved; after the rename a failed flush is
/// `durable: false`, the change in place. For each site store.
#[test]
fn failed_writes_follow_the_rule() {
    let root = tempfile::tempdir().unwrap();
    let hook = root.path().join("hook");
    let hook_env = hook.to_string_lossy().into_owned();
    let mut core = start(
        root.path(),
        &["dapp", "swarm", "radicle"],
        false,
        &[("FREEDOM_CORED_TEST_GRANT_WRITE_FAIL", &hook_env)],
    );
    let dir = core.grant_root.clone();
    let mut id = 10;
    for (store, connect) in [
        (
            "dapp",
            json!({ "op": "connect", "account": 0, "chain_id": 100 }),
        ),
        ("swarm", json!({ "op": "connect" })),
        ("radicle", json!({ "op": "connect" })),
    ] {
        let file = dir.join(format!("{store}-permissions.json"));
        let records = |core: &mut Core, id: &mut u64| {
            let reply = call_as(
                core,
                id,
                &chrome(),
                "approval.grants",
                json!({ "store": store }),
            );
            result(&reply)["records"].as_array().unwrap().len()
        };
        for step in ["write", "fsync", "rename"] {
            std::fs::write(&hook, format!("{store}:{step}")).unwrap();
            let reply = grant(&mut core, &mut id, &site(), store, connect.clone());
            assert_eq!(reply["error"]["code"], "storage", "{store} {step}: {reply}");
            assert_eq!(
                reply["error"]["data"],
                json!({ "store": store, "applied": false })
            );
            assert_eq!(records(&mut core, &mut id), 0, "{store} {step}");
            assert!(!file.exists(), "{store} {step}");
            assert!(changed(&mut core, &mut id).is_empty());
        }
        std::fs::write(&hook, format!("{store}:flush")).unwrap();
        let reply = grant(&mut core, &mut id, &site(), store, connect.clone());
        assert_eq!(result(&reply)["durable"], false, "{reply}");
        assert!(file.exists());
        assert_eq!(records(&mut core, &mut id), 1);
        assert_eq!(changed(&mut core, &mut id).len(), 1);
        let saved = std::fs::read(&file).unwrap();
        // A narrowing whose write fails is active, and not saved.
        std::fs::write(&hook, format!("{store}:rename")).unwrap();
        let reply = call_as(
            &mut core,
            &mut id,
            &chrome(),
            "approval.revoke",
            json!({ "store": store, "key": SITE, "what": "grant" }),
        );
        assert_eq!(reply["error"]["code"], "storage", "{reply}");
        assert_eq!(
            reply["error"]["data"],
            json!({ "store": store, "applied": true })
        );
        assert_eq!(records(&mut core, &mut id), 0);
        assert_eq!(std::fs::read(&file).unwrap(), saved);
        assert_eq!(changed(&mut core, &mut id).len(), 1);
        std::fs::write(&hook, "").unwrap();
    }
    // A restart reads the files as they were left: the narrowings weren't
    // saved.
    drop(core);
    let mut core = start(root.path(), &["dapp", "swarm", "radicle"], false, &[]);
    for store in ["dapp", "swarm", "radicle"] {
        let reply = call_as(
            &mut core,
            &mut id,
            &chrome(),
            "approval.grants",
            json!({ "store": store }),
        );
        assert_eq!(
            result(&reply)["records"].as_array().unwrap().len(),
            1,
            "{store}"
        );
    }
}

/// `sign.transaction` spends an `intent-replace` with `{ token, intent: { id
/// } }`: the token's account, the intent's id and the transaction (its
/// nonce, payment and fees) must be the signed ones. Each bound field
/// changed refuses; the right one signs.
#[test]
fn an_intent_replace_signs_its_intent_again() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &[], true, &[]);
    let mut id = 10;
    let replacement = || {
        json!({
            "type": 2, "chain_id": "100", "nonce": "7", "gas_limit": "21000", "to": TO,
            "value": "1", "data": "0x", "max_fee_per_gas": "3000000000",
            "max_priority_fee_per_gas": "1500000000",
        })
    };
    let mint = |core: &mut Core, id: &mut u64, account: Option<u32>| {
        let mut params = json!({ "kind": "intent-replace", "payload": {
            "intent_id": INTENT, "sender": "0x9858effd232b4033e47d90003d41ec34ecaeda94", "tx": replacement(),
        } });
        if let Some(account) = account {
            params["account"] = json!(account);
        }
        let issued = call_as(core, id, &shell(), "approval.issue", params);
        result(&issued)["token"].as_str().unwrap().to_owned()
    };
    let sign = |core: &mut Core, id: &mut u64, key: u32, tx: Value, authorization: Value| {
        call_as(
            core,
            id,
            &shell(),
            "sign.transaction",
            json!({ "key": account(key), "tx": tx, "authorization": authorization }),
        )
    };
    let changed_tx = |field: &str, value: &str| {
        let mut tx = replacement();
        tx[field] = json!(value);
        tx
    };
    let cases = [
        (0, replacement(), json!({ "id": "another-intent-01" })),
        (1, replacement(), json!({ "id": INTENT })),
        (0, changed_tx("nonce", "8"), json!({ "id": INTENT })),
        (
            0,
            changed_tx("to", "0x0000000000000000000000000000000000000001"),
            json!({ "id": INTENT }),
        ),
        (0, changed_tx("value", "2"), json!({ "id": INTENT })),
        (0, changed_tx("data", "0x01"), json!({ "id": INTENT })),
        (0, changed_tx("chain_id", "1"), json!({ "id": INTENT })),
        (0, changed_tx("gas_limit", "21001"), json!({ "id": INTENT })),
        (
            0,
            changed_tx("max_fee_per_gas", "3000000001"),
            json!({ "id": INTENT }),
        ),
        (
            0,
            changed_tx("max_priority_fee_per_gas", "1500000001"),
            json!({ "id": INTENT }),
        ),
    ];
    for (key, tx, intent) in cases {
        let token = mint(&mut core, &mut id, Some(0));
        let reply = sign(
            &mut core,
            &mut id,
            key,
            tx.clone(),
            json!({ "token": token, "intent": intent }),
        );
        assert_eq!(
            reply["error"]["data"]["reason"], "mismatch",
            "{key} {tx} {intent}: {reply}"
        );
    }
    // Without its intent, or minted without an account, it signs nothing.
    let token = mint(&mut core, &mut id, Some(0));
    let reply = sign(
        &mut core,
        &mut id,
        0,
        replacement(),
        json!({ "token": token }),
    );
    assert_eq!(reply["error"]["data"]["reason"], "mismatch", "{reply}");
    let token = mint(&mut core, &mut id, None);
    let reply = sign(
        &mut core,
        &mut id,
        0,
        replacement(),
        json!({ "token": token, "intent": { "id": INTENT } }),
    );
    assert_eq!(reply["error"]["data"]["reason"], "mismatch", "{reply}");
    // The right one signs, once.
    let token = mint(&mut core, &mut id, Some(0));
    let authorization = json!({ "token": token, "intent": { "id": INTENT } });
    let reply = sign(&mut core, &mut id, 0, replacement(), authorization.clone());
    assert!(result(&reply)["raw"].is_string(), "{reply}");
    let again = sign(&mut core, &mut id, 0, replacement(), authorization);
    assert_eq!(again["error"]["data"]["reason"], "unknown_token", "{again}");
    // An intent names no other kind's token.
    let issued = call_as(
        &mut core,
        &mut id,
        &shell(),
        "approval.issue",
        json!({ "kind": "wallet-send", "account": 0, "payload": { "tx": replacement() } }),
    );
    let token = result(&issued)["token"].as_str().unwrap().to_owned();
    let reply = sign(
        &mut core,
        &mut id,
        0,
        replacement(),
        json!({ "token": token, "intent": { "id": INTENT } }),
    );
    assert_eq!(reply["error"]["data"]["reason"], "mismatch", "{reply}");
}

/// A narrowing whose write fails stands in memory, and so does what goes
/// with it: a full revoke forgets the site's rate buckets, so a grant made
/// again starts full. A neutral change (a last use) whose write fails sends
/// no `approval.changed`, as a saved one sends none.
#[test]
fn a_failed_revoke_forgets_the_buckets_and_a_failed_touch_sends_nothing() {
    let root = tempfile::tempdir().unwrap();
    let hook = root.path().join("hook");
    let hook_env = hook.to_string_lossy().into_owned();
    let mut core = start(
        root.path(),
        &["dapp"],
        true,
        &[("FREEDOM_CORED_TEST_GRANT_WRITE_FAIL", &hook_env)],
    );
    let mut id = 10;
    let connect_and_sign = |core: &mut Core, id: &mut u64| {
        let connected = grant(
            core,
            id,
            &site(),
            "dapp",
            json!({ "op": "connect", "account": 0, "chain_id": 100 }),
        );
        assert_eq!(result(&connected)["grant"]["walletIndex"], 0, "{connected}");
        let signing = grant(core, id, &site(), "dapp", json!({ "op": "signing" }));
        assert!(result(&signing)["grant"].is_object(), "{signing}");
    };
    let sign = |core: &mut Core, id: &mut u64| {
        call_as(
            core,
            id,
            &site(),
            "sign.message",
            json!({ "key": account(0), "message": "0x68656c6c6f", "authorization": { "standing": {} } }),
        )
    };
    connect_and_sign(&mut core, &mut id);
    // Q9's rate: the burst signs, then the bucket is empty.
    let mut signed = 0;
    loop {
        let reply = sign(&mut core, &mut id);
        if reply.get("error").is_some() {
            assert_eq!(reply["error"]["data"]["reason"], "rate_limited", "{reply}");
            break;
        }
        assert!(result(&reply)["signature"].is_string(), "{reply}");
        signed += 1;
        assert!(signed <= 10, "no rate on a limited rule");
    }
    changed(&mut core, &mut id);
    // A last use whose write fails: a storage error, and no event.
    std::fs::write(&hook, "dapp:rename").unwrap();
    let touched = call_as(
        &mut core,
        &mut id,
        &site(),
        "approval.touch",
        json!({ "store": "dapp" }),
    );
    assert_eq!(touched["error"]["code"], "storage", "{touched}");
    assert!(changed(&mut core, &mut id).is_empty());
    // A revoke whose write fails stands, with its event, and forgets the
    // buckets.
    let revoked = call_as(
        &mut core,
        &mut id,
        &chrome(),
        "approval.revoke",
        json!({ "store": "dapp", "key": SITE, "what": "grant" }),
    );
    assert_eq!(
        revoked["error"]["data"],
        json!({ "store": "dapp", "applied": true }),
        "{revoked}"
    );
    assert_eq!(changed(&mut core, &mut id).len(), 1);
    std::fs::write(&hook, "").unwrap();
    connect_and_sign(&mut core, &mut id);
    let again = sign(&mut core, &mut id);
    assert!(result(&again)["signature"].is_string(), "{again}");
}
