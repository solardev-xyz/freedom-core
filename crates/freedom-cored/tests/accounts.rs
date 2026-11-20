//! `accounts.*` over `vault-meta.json` through the real binary (design
//! 0013, "`vault-meta.json`" and "One writer per store"; PRF-5c-1).
//!
//! Every `vectors/stores.json` `vault_meta` step whose change has a method
//! is replayed over the wire, and the answer and the file's text after it
//! are the reference's, byte for byte. The vectors' identity core answers
//! made-up addresses (account `n` is `0x…` of `0x1000 + n`); the test
//! renames each to the address the core derives from the `abandon` vault,
//! the same length, everywhere in the run. The steps with no method in
//! this step (a vault's create, import or unlock, 5c-2's; the reference's
//! internal `addDeviceWallet` and lookups) put the reference's text in
//! place, as main's own writes would.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSWORD: &str = "testpass1";
const FILE: &str = "vault-meta.json";
const SITE: &str = "https://app.example";
const SAFE: &str = "0x1111111111111111111111111111111111111111";
const OTHER_SAFE: &str = "0x2222222222222222222222222222222222222222";
const TO: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const ZERO: &str = "0x0000000000000000000000000000000000000000";
const HOOK: &str = "FREEDOM_CORED_TEST_GRANT_WRITE_FAIL";

/// Every method with a valid request, and whether the chrome reaches it.
fn every_method() -> Vec<(&'static str, Value, bool)> {
    vec![
        ("accounts.list", json!({}), true),
        ("accounts.meta", json!({}), true),
        ("accounts.active", json!({}), true),
        ("accounts.add_mnemonic", json!({ "name": "Spare" }), true),
        (
            "accounts.add_ledger",
            json!({ "address": "0xA1A1a1a1A1A1A1A1A1a1a1a1a1a1A1A1a1A1a1a1", "path": "44'/60'/0'/0/0" }),
            false,
        ),
        (
            "accounts.add_remote",
            json!({ "address": "0xB1B1B1B1b1B1b1b1b1B1B1B1B1b1b1B1b1b1B1B1" }),
            false,
        ),
        (
            "accounts.record_address_check",
            json!({ "type": "ledger", "index": 1_000_000, "matched": false }),
            false,
        ),
        (
            "accounts.add_safe",
            json!({ "address": SAFE, "owners": [0, 1], "threshold": 1, "salt_nonce": "0" }),
            false,
        ),
        (
            "accounts.mark_safe_deployed",
            json!({ "index": 1_000_000, "chain_id": 100 }),
            false,
        ),
        ("accounts.set_active", json!({ "index": 0 }), true),
        (
            "accounts.rename",
            json!({ "index": 0, "name": "Main" }),
            true,
        ),
        (
            "accounts.remove",
            json!({ "index": 1, "swarm_references": [] }),
            true,
        ),
    ]
}

fn message(id: u64, context: &Value, method: &str, params: Value) -> Value {
    json!({ "type": "request", "id": id, "method": method, "params": params, "context": context })
}

fn call_as(core: &mut Core, id: &mut u64, context: &Value, method: &str, params: Value) -> Value {
    *id += 1;
    core.send(&message(*id, context, method, params));
    core.response(*id)
}

fn chrome() -> Value {
    json!({ "caller": "chrome" })
}

fn shell() -> Value {
    json!({ "caller": "shell" })
}

fn page() -> Value {
    json!({ "caller": "page", "page": {
        "origin": SITE, "top_origin": SITE, "frame": 1, "navigation": 1, "agent": false,
    } })
}

fn result(reply: &Value) -> &Value {
    assert!(reply["result"].is_object(), "{reply}");
    &reply["result"]
}

fn code(reply: &Value) -> &str {
    reply["error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("{reply}"))
}

/// A core over `root`'s identity directory, with `store_moved` and
/// `grant_moved`.
fn start(
    root: &Path,
    stores: &[&'static str],
    grants: &[&'static str],
    env: &[(&str, &str)],
) -> (Core, Value) {
    let mut core = spawn_env(
        "serve",
        &root.join("identity"),
        &root.join("locks"),
        &[],
        env,
    );
    std::fs::create_dir_all(&core.grant_root).unwrap();
    core.store_moved = stores.to_vec();
    core.grant_moved = grants.to_vec();
    let hello = core.hello();
    (core, hello)
}

/// The `abandon` vault, imported (and so unlocked).
fn import(core: &mut Core, id: &mut u64) {
    let reply = call_as(
        core,
        id,
        &shell(),
        "vault.import",
        json!({ "password_b64": STANDARD.encode(PASSWORD), "mnemonic_b64": STANDARD.encode(ABANDON), "overwrite": true }),
    );
    assert!(reply["result"].is_object(), "{reply}");
}

fn meta_path(root: &Path) -> PathBuf {
    root.join("identity").join(FILE)
}

fn read_meta(root: &Path) -> Option<String> {
    std::fs::read_to_string(meta_path(root)).ok()
}

fn write_meta(root: &Path, text: &str) {
    std::fs::create_dir_all(root.join("identity")).unwrap();
    std::fs::write(meta_path(root), text).unwrap();
}

/// What is in the identity directory: each entry's name, bytes, and
/// modification time. A spy on the core's writes: one that wrote, renamed,
/// removed or left a temp file changes it.
fn snapshot(root: &Path) -> BTreeMap<String, (Vec<u8>, std::time::SystemTime)> {
    std::fs::read_dir(root.join("identity"))
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let path = entry.path();
            let bytes = if path.is_file() {
                std::fs::read(&path).unwrap()
            } else {
                Vec::new()
            };
            let modified = entry.metadata().unwrap().modified().unwrap();
            (entry.file_name().into_string().unwrap(), (bytes, modified))
        })
        .collect()
}

/// A JSON value as JS's `JSON.stringify` writes it, in its own key order.
fn js_text(value: &Value) -> String {
    fc_json::parse(&value.to_string()).unwrap().stringify()
}

/// The vectors' made-up address for account `n`.
fn fake(account: u64) -> String {
    format!("0x{:040x}", 0x1000 + account)
}

/// The vectors' accounts whose addresses a run's identity core answered.
fn derived_accounts(run: &Value) -> Vec<u64> {
    let mut accounts = vec![0];
    for step in run["steps"].as_array().unwrap() {
        for call in step["calls"].as_array().unwrap() {
            if call["fn"] == "vault.addresses" && call.get("answer").is_some() {
                for wallet in call["answer"]["user_wallets"].as_array().unwrap() {
                    let account = wallet["account"].as_u64().unwrap();
                    assert_eq!(
                        wallet["address"],
                        fake(account),
                        "the vectors' address scheme"
                    );
                    accounts.push(account);
                }
            }
        }
    }
    accounts.sort_unstable();
    accounts.dedup();
    accounts
}

/// The core's address for each account.
fn real_addresses(core: &mut Core, id: &mut u64, accounts: &[u64]) -> Vec<(String, String)> {
    let reply = call_as(
        core,
        id,
        &shell(),
        "keys.addresses",
        json!({ "accounts": accounts, "publishers": [] }),
    );
    result(&reply)["user_wallets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|wallet| {
            let account = wallet["account"].as_u64().unwrap();
            let address = wallet["address"].as_str().unwrap().to_owned();
            assert_eq!(address.len(), 42);
            (fake(account), address)
        })
        .collect()
}

fn renamed(text: &str, names: &[(String, String)]) -> String {
    names.iter().fold(text.to_owned(), |text, (fake, real)| {
        text.replace(fake, real)
    })
}

fn renamed_value(value: &Value, names: &[(String, String)]) -> Value {
    serde_json::from_str(&renamed(&value.to_string(), names)).unwrap()
}

/// The method and request of a vector step's core operation, or none when
/// this step has no method for it.
fn request_of(core_op: &Value) -> Option<(&'static str, Value, &'static str)> {
    let args = core_op["args"].as_array().unwrap();
    let arg = |i: usize| args.get(i).cloned();
    let with_name = |mut params: Value, name: Option<Value>| {
        if let Some(name) = name {
            params["name"] = name;
        }
        params
    };
    Some(match core_op["op"].as_str().unwrap() {
        "list" => ("accounts.list", json!({}), "wallets"),
        "active_index" => ("accounts.active", json!({}), "index"),
        "add_mnemonic" => (
            "accounts.add_mnemonic",
            with_name(json!({}), arg(1)),
            "wallet",
        ),
        "add_ledger" => (
            "accounts.add_ledger",
            with_name(json!({ "address": args[1], "path": args[2] }), arg(0)),
            "wallet",
        ),
        "add_remote" => (
            "accounts.add_remote",
            with_name(json!({ "address": args[1] }), arg(0)),
            "wallet",
        ),
        "record_address_check" => (
            "accounts.record_address_check",
            json!({ "type": args[0], "index": args[1], "matched": args[2] }),
            "address_check",
        ),
        "add_safe" => {
            let p = &args[1];
            let mut params = json!({});
            for (from, to) in [
                ("address", "address"),
                ("owners", "owners"),
                ("threshold", "threshold"),
                ("saltNonce", "salt_nonce"),
            ] {
                if let Some(value) = p.get(from) {
                    params[to] = value.clone();
                }
            }
            ("accounts.add_safe", with_name(params, arg(0)), "wallet")
        }
        "mark_safe_deployed" => (
            "accounts.mark_safe_deployed",
            json!({ "index": args[0], "chain_id": args[1] }),
            "",
        ),
        "set_active" => ("accounts.set_active", json!({ "index": args[0] }), ""),
        "rename" => (
            "accounts.rename",
            with_name(json!({ "index": args[0] }), arg(1)),
            "",
        ),
        "remove" => {
            let references: Vec<Value> = args[1]
                .as_array()
                .unwrap()
                .iter()
                .map(|origin| json!({ "origin": origin, "identityId": "id", "active": true }))
                .collect();
            (
                "accounts.remove",
                json!({ "index": args[0], "swarm_references": references }),
                "",
            )
        }
        // A vault's create, import or unlock (PRF-5c-2), the reference's
        // internal `addDeviceWallet`, and its lookups: no method.
        "new_vault"
        | "migrate_addresses"
        | "add_device"
        | "record"
        | "find_by_address"
        | "next_hardware_index" => return None,
        other => panic!("an operation the test doesn't know: {other}"),
    })
}

fn set_unlocked(core: &mut Core, id: &mut u64, unlocked: bool) {
    let reply = if unlocked {
        call_as(
            core,
            id,
            &chrome(),
            "vault.unlock",
            json!({ "password_b64": STANDARD.encode(PASSWORD) }),
        )
    } else {
        call_as(core, id, &chrome(), "vault.lock", json!({}))
    };
    assert!(reply["result"].is_object(), "{reply}");
}

/// Every `vault_meta` vector step with a method, through the daemon: the
/// answer, or the refusal's message and code, and the file's text after
/// it, byte for byte.
#[test]
fn every_vault_meta_vector_through_the_daemon() {
    // The malformed cases nest deeper than serde_json reads: the runs only.
    let vectors = fc_json::parse(include_str!("../../../vectors/stores.json")).unwrap();
    let runs = vectors.get("vault_meta").unwrap().get("runs").unwrap();
    let runs: Value = serde_json::from_str(&runs.stringify()).unwrap();
    let mut replayed: BTreeMap<&str, usize> = BTreeMap::new();
    for run in runs.as_array().unwrap() {
        let name = run["id"].as_str().unwrap();
        let root = tempfile::tempdir().unwrap();
        // The dApp file moved too, as on every browser that names
        // `vault_meta`: `accounts.remove` forgets its grants first.
        let (mut core, hello) = start(root.path(), &["vault_meta"], &["dapp"], &[]);
        assert_eq!(hello["result"]["store_moved"], json!(["vault_meta"]));
        let mut id = 1;
        import(&mut core, &mut id);
        let names = real_addresses(&mut core, &mut id, &derived_accounts(run));
        if let Some(start) = run["start"].as_str() {
            write_meta(root.path(), &renamed(start, &names));
        }
        let mut unlocked = true;
        for (n, step) in run["steps"].as_array().unwrap().iter().enumerate() {
            let at = format!("{name} step {n} ({})", step["op"]);
            if let Some(wanted) = step["world"]["unlocked"].as_bool()
                && wanted != unlocked
            {
                set_unlocked(&mut core, &mut id, wanted);
                unlocked = wanted;
            }
            let before = read_meta(root.path());
            let text = step["text"].as_str().map(|text| renamed(text, &names));
            let Some((method, params, member)) = Some(&step["core"])
                .filter(|c| !c.is_null())
                .and_then(request_of)
            else {
                // Refused by main before the core (a device's answer), a
                // lookup, or a change with no method here.
                if step["wrote"] == true {
                    write_meta(root.path(), text.as_deref().unwrap());
                }
                assert_eq!(read_meta(root.path()), text, "{at}");
                continue;
            };
            if method == "accounts.add_mnemonic" {
                assert_eq!(step["core"]["args"][0], unlocked, "{at}");
            }
            let params = renamed_value(&params, &names);
            let reply = call_as(&mut core, &mut id, &shell(), method, params);
            if let Some(error) = step.get("error") {
                assert_eq!(code(&reply), "invalid_argument", "{at}: {reply}");
                assert_eq!(reply["error"]["message"], error["message"], "{at}");
                match error["code"].as_str() {
                    Some(c) => assert_eq!(reply["error"]["data"]["code"], c, "{at}"),
                    None => assert!(reply["error"]["data"]["code"].is_null(), "{at}"),
                }
                assert_eq!(
                    read_meta(root.path()),
                    before,
                    "{at}: a refusal writes nothing"
                );
            } else {
                let got = result(&reply);
                let expected = renamed_value(&step["result"], &names);
                if member.is_empty() {
                    assert!(expected.is_null(), "{at}");
                    assert_eq!(*got, json!({}), "{at}");
                } else {
                    assert_eq!(js_text(&got[member]), js_text(&expected), "{at}");
                    assert_eq!(got.as_object().unwrap().len(), 1, "{at}: {got}");
                }
            }
            assert_eq!(read_meta(root.path()), text, "{at}");
            *replayed.entry(method).or_default() += 1;
        }
    }
    // Every method but the reads' `accounts.meta` has steps.
    for method in every_method().iter().map(|(m, _, _)| *m) {
        if method != "accounts.meta" {
            assert!(replayed.get(method).copied().unwrap_or(0) > 0, "{method}");
        }
    }
}

/// The hello echoes `vault_meta` once named, and no name whose methods
/// this build lacks; an unknown name is refused, and the core exits.
#[test]
fn the_hello_echoes_vault_meta() {
    let root = tempfile::tempdir().unwrap();
    let (core, hello) = start(
        root.path(),
        &[
            "intents",
            "vault_meta",
            "payments",
            "safe_pending",
            "vault_meta",
        ],
        &[],
        &[],
    );
    assert_eq!(
        hello["result"]["store_moved"],
        json!(["vault_meta", "payments"]),
        "{hello}"
    );
    drop(core);
    let (mut core, hello) = start(root.path(), &["vault_meta", "profiles"], &[], &[]);
    assert_eq!(code(&hello), "invalid_argument", "{hello}");
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);
}

/// Before `vault_meta` is named the reads are served, `accounts.list`'s
/// default answered but not written, and every write answers `not_moved`
/// with nothing in the directory changed; an unreadable file reads as
/// missing and stays. Once named, it is renamed aside. The chrome reaches
/// no shell method, and a page no method at all.
#[test]
fn callers_and_not_moved() {
    let root = tempfile::tempdir().unwrap();
    let (mut core, hello) = start(root.path(), &[], &[], &[]);
    assert_eq!(hello["result"]["store_moved"], json!([]), "{hello}");
    let mut id = 1;
    import(&mut core, &mut id);
    let main = real_addresses(&mut core, &mut id, &[0]).remove(0).1;
    let text = format!(
        "{{\n  \"userKnowsPassword\": true,\n  \"addresses\": {{\n    \"userWallet\": \"{main}\"\n  }}\n}}"
    );
    write_meta(root.path(), &text);
    let before = snapshot(root.path());
    let listed = call_as(&mut core, &mut id, &chrome(), "accounts.list", json!({}));
    assert_eq!(
        result(&listed)["wallets"],
        json!([{ "index": 0, "name": "Main Wallet", "address": main, "type": "mnemonic" }])
    );
    let meta = call_as(&mut core, &mut id, &chrome(), "accounts.meta", json!({}));
    assert_eq!(
        result(&meta)["meta"],
        serde_json::from_str::<Value>(&text).unwrap()
    );
    let active = call_as(&mut core, &mut id, &chrome(), "accounts.active", json!({}));
    assert_eq!(*result(&active), json!({ "index": 0 }));
    for (method, params, chrome_too) in every_method() {
        for context in [page(), chrome(), shell()] {
            let reply = call_as(&mut core, &mut id, &context, method, params.clone());
            let caller = context["caller"].as_str().unwrap();
            let reaches = caller == "shell" || (caller == "chrome" && chrome_too);
            if !reaches {
                assert_eq!(code(&reply), "forbidden", "{method} {caller}: {reply}");
            } else if ["accounts.list", "accounts.meta", "accounts.active"].contains(&method) {
                assert!(reply["result"].is_object(), "{method} {caller}: {reply}");
            } else {
                assert_eq!(code(&reply), "not_moved", "{method} {caller}: {reply}");
                assert_eq!(reply["error"]["data"]["store"], "vault_meta");
            }
        }
    }
    assert_eq!(
        snapshot(root.path()),
        before,
        "nothing written before the move"
    );
    // An unreadable file reads as missing, and stays.
    write_meta(root.path(), "{\"derivedWallets\": 7}");
    let listed = call_as(&mut core, &mut id, &shell(), "accounts.list", json!({}));
    assert_eq!(result(&listed)["wallets"], json!([]));
    let meta = call_as(&mut core, &mut id, &shell(), "accounts.meta", json!({}));
    assert_eq!(result(&meta)["meta"], Value::Null);
    assert_eq!(read_meta(root.path()).unwrap(), "{\"derivedWallets\": 7}");
    assert!(
        !root
            .path()
            .join("identity")
            .join("vault-meta.json.unreadable")
            .exists()
    );
    drop(core);
    // Named: set aside at the first read, the bytes kept.
    let (mut core, _) = start(root.path(), &["vault_meta"], &[], &[]);
    let listed = call_as(&mut core, &mut id, &shell(), "accounts.list", json!({}));
    assert_eq!(result(&listed)["wallets"], json!([]));
    assert_eq!(read_meta(root.path()), None);
    assert_eq!(
        std::fs::read_to_string(
            root.path()
                .join("identity")
                .join("vault-meta.json.unreadable")
        )
        .unwrap(),
        "{\"derivedWallets\": 7}"
    );
}

/// A write that fails at its temp file's write, its fsync or the rename
/// answers `storage` and leaves the file as it was, with no temp file; a
/// failed flush after the rename answers the change with `durable: false`.
/// `accounts.list`'s default write fails as a change's does.
#[test]
fn a_failed_write_at_each_step() {
    let root = tempfile::tempdir().unwrap();
    let hook = root.path().join("hook");
    std::fs::write(&hook, "").unwrap();
    let hook_env = hook.to_str().unwrap().to_owned();
    let (mut core, _) = start(root.path(), &["vault_meta"], &[], &[(HOOK, &hook_env)]);
    let mut id = 1;
    import(&mut core, &mut id);
    let text = "{\n  \"userKnowsPassword\": true\n}";
    write_meta(root.path(), text);
    for step in ["write", "fsync", "rename"] {
        std::fs::write(&hook, format!("vault_meta:{step}\n")).unwrap();
        let before = snapshot(root.path());
        let listed = call_as(&mut core, &mut id, &shell(), "accounts.list", json!({}));
        assert_eq!(code(&listed), "storage", "{step}: {listed}");
        assert_eq!(listed["error"]["data"]["file"], "vault_meta");
        assert_eq!(snapshot(root.path()), before, "{step}");
    }
    std::fs::write(&hook, "vault_meta:flush\n").unwrap();
    let listed = call_as(&mut core, &mut id, &shell(), "accounts.list", json!({}));
    assert_eq!(result(&listed)["durable"], false, "{listed}");
    assert!(read_meta(root.path()).unwrap().contains("derivedWallets"));
    for step in ["write", "fsync", "rename"] {
        std::fs::write(&hook, format!("vault_meta:{step}\n")).unwrap();
        let before = snapshot(root.path());
        let reply = call_as(
            &mut core,
            &mut id,
            &chrome(),
            "accounts.rename",
            json!({ "index": 0, "name": "Renamed" }),
        );
        assert_eq!(code(&reply), "storage", "{step}: {reply}");
        assert_eq!(snapshot(root.path()), before, "{step}");
    }
    std::fs::write(&hook, "vault_meta:flush\n").unwrap();
    let reply = call_as(
        &mut core,
        &mut id,
        &chrome(),
        "accounts.rename",
        json!({ "index": 0, "name": "Renamed" }),
    );
    assert_eq!(*result(&reply), json!({ "durable": false }));
    assert!(read_meta(root.path()).unwrap().contains("\"Renamed\""));
    std::fs::write(&hook, "").unwrap();
    let reply = call_as(
        &mut core,
        &mut id,
        &chrome(),
        "accounts.set_active",
        json!({ "index": 0 }),
    );
    assert_eq!(*result(&reply), json!({}));
}

fn safe_tx(safe: &str) -> Value {
    let field = |name: &str, kind: &str| json!({ "name": name, "type": kind });
    json!({
        "domain": { "chainId": "100", "verifyingContract": safe },
        "types": { "SafeTx": [
            field("to", "address"), field("value", "uint256"), field("data", "bytes"),
            field("operation", "uint8"), field("safeTxGas", "uint256"), field("baseGas", "uint256"),
            field("gasPrice", "uint256"), field("gasToken", "address"),
            field("refundReceiver", "address"), field("nonce", "uint256"),
        ]},
        "message": {
            "to": TO, "value": "1000", "data": "0xa9059cbb", "operation": "0",
            "safeTxGas": "0", "baseGas": "0", "gasPrice": "0",
            "gasToken": ZERO, "refundReceiver": ZERO, "nonce": "0",
        },
    })
}

/// A wallet `safe-send`'s Safe approval for `safe`, under `shell`.
fn send_approval(core: &mut Core, id: &mut u64, safe: &str) -> String {
    let mut params = json!({ "kind": "safe-send", "account": 0, "payload": {
        "safe": safe, "chain_id": "100", "tx": { "to": TO, "value": "1000", "data": "0xa9059cbb" },
    } });
    let issued = call_as(core, id, &shell(), "approval.issue", params.clone());
    params["token"] = result(&issued)["token"].clone();
    let spent = call_as(core, id, &shell(), "approval.spend", params);
    result(&spent)["safe"].as_str().unwrap().to_owned()
}

/// Account 0's `sign.typed_data` of `safe`'s SafeTx under the approval.
fn owner_signs(core: &mut Core, id: &mut u64, safe: &str, approval: &str) -> Value {
    let typed = safe_tx(safe);
    let hash = fc_evm::to_hex(
        &fc_evm::typed_data_hash(&typed["domain"], &typed["types"], &typed["message"]).unwrap(),
    );
    call_as(
        core,
        id,
        &shell(),
        "sign.typed_data",
        json!({ "key": { "kind": "account", "index": 0 }, "typed_data": typed,
            "expected_hash": hash, "authorization": { "safe": approval } }),
    )
}

/// `accounts.remove`'s refusals change nothing; a Safe's removal ends its
/// open approvals (no other Safe's), removes the record, resets the active
/// account, and forgets the account's dApp grants, in the one request.
#[test]
fn removing_a_safe_ends_its_approvals_and_forgets_its_grants() {
    let root = tempfile::tempdir().unwrap();
    let grant_root = root.path().join("userData");
    std::fs::create_dir_all(&grant_root).unwrap();
    let dapp = json!({ SITE: {
        "origin": SITE, "connectedAt": 1, "lastUsed": 1, "walletIndex": 1_000_000, "chainId": 100,
    } });
    std::fs::write(
        grant_root.join("dapp-permissions.json"),
        serde_json::to_string_pretty(&dapp).unwrap(),
    )
    .unwrap();
    let meta = json!({
        "userKnowsPassword": true,
        "derivedWallets": [
            { "index": 0, "name": "Main Wallet" },
            { "index": 1_000_000, "name": "Team", "address": SAFE, "type": "safe",
              "owners": [0, 1_000_001], "threshold": 1, "saltNonce": "0", "deployed": {} },
            { "index": 1_000_001, "name": "Phone 1", "type": "remote",
              "address": "0xB1B1B1B1b1B1b1b1b1B1B1B1B1b1b1B1b1b1B1B1", "addressCheck": "matched" },
        ],
        "activeWalletIndex": 1_000_000,
        "nextHardwareWalletIndex": 1_000_002,
    });
    write_meta(root.path(), &serde_json::to_string_pretty(&meta).unwrap());
    let (mut core, _) = start(root.path(), &["vault_meta"], &["dapp"], &[MAINS_WORD]);
    let mut id = 1;
    import(&mut core, &mut id);
    let approval = send_approval(&mut core, &mut id, SAFE);
    let other = send_approval(&mut core, &mut id, OTHER_SAFE);
    let before = snapshot(root.path());
    let dapp_before = std::fs::read(grant_root.join("dapp-permissions.json")).unwrap();
    for (index, references, message) in [
        (0, json!([]), "Cannot delete the main wallet (index 0)"),
        (
            1_000_001,
            json!([]),
            "This account is an owner of \"Team\" \u{2014} delete that Safe account first",
        ),
        (
            1_000_000,
            json!([{ "origin": "https://feed.example" }]),
            "Cannot delete wallet with index 1000000; it is active or pinned to Swarm feeds for https://feed.example. Switch the affected publisher identities before deleting this wallet.",
        ),
        (7, json!([]), "Wallet with index 7 does not exist"),
    ] {
        let reply = call_as(
            &mut core,
            &mut id,
            &chrome(),
            "accounts.remove",
            json!({ "index": index, "swarm_references": references }),
        );
        assert_eq!(code(&reply), "invalid_argument", "{reply}");
        assert_eq!(reply["error"]["message"], message);
    }
    assert_eq!(
        call_as(
            &mut core,
            &mut id,
            &chrome(),
            "accounts.remove",
            json!({ "index": 1_000_000, "swarm_references": [{ "origin": "https://feed.example" }] }),
        )["error"]["data"]["code"],
        "SWARM_PUBLISHER_IDENTITY_WALLET_IN_USE"
    );
    // A malformed reference list is no list at all.
    let reply = call_as(
        &mut core,
        &mut id,
        &chrome(),
        "accounts.remove",
        json!({ "index": 1_000_000 }),
    );
    assert_eq!(code(&reply), "invalid_argument", "{reply}");
    assert_eq!(snapshot(root.path()), before, "a refusal writes nothing");
    assert_eq!(
        std::fs::read(grant_root.join("dapp-permissions.json")).unwrap(),
        dapp_before
    );
    core.events.clear();
    let removed = call_as(
        &mut core,
        &mut id,
        &chrome(),
        "accounts.remove",
        json!({ "index": 1_000_000, "swarm_references": [] }),
    );
    assert_eq!(*result(&removed), json!({}));
    let after: Value = serde_json::from_str(&read_meta(root.path()).unwrap()).unwrap();
    assert_eq!(after["activeWalletIndex"], 0);
    let indices: Vec<&Value> = after["derivedWallets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| &w["index"])
        .collect();
    assert_eq!(indices, [&json!(0), &json!(1_000_001)]);
    // The grant forgotten, with its event.
    let stored: Value = serde_json::from_str(
        &std::fs::read_to_string(grant_root.join("dapp-permissions.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(stored, json!({}));
    let _ = call_as(&mut core, &mut id, &chrome(), "vault.status", json!({}));
    assert!(
        core.events
            .iter()
            .any(|e| e["event"] == "approval.changed" && e["data"]["key"] == SITE),
        "{:?}",
        core.events
    );
    // The removed Safe's approval is gone; another Safe's still signs.
    let reply = owner_signs(&mut core, &mut id, SAFE, &approval);
    assert!(reply.get("result").is_none(), "{reply}");
    let reply = owner_signs(&mut core, &mut id, OTHER_SAFE, &other);
    assert!(result(&reply)["signature"].is_string(), "{reply}");
}

/// The dApp grants file with one grant per `(site, account)`.
fn write_dapp(grant_root: &Path, grants: &[(&str, u32)]) {
    let mut file = serde_json::Map::new();
    for (site, account) in grants {
        file.insert(
            (*site).to_owned(),
            json!({ "origin": site, "connectedAt": 1, "lastUsed": 1, "walletIndex": account, "chainId": 100 }),
        );
    }
    std::fs::write(
        grant_root.join("dapp-permissions.json"),
        serde_json::to_string_pretty(&Value::Object(file)).unwrap(),
    )
    .unwrap();
}

/// The sites the dApp grants file names.
fn dapp_sites(grant_root: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(grant_root.join("dapp-permissions.json")).unwrap();
    let file: Value = serde_json::from_str(&text).unwrap();
    file.as_object().unwrap().keys().cloned().collect()
}

/// A mnemonic account added over the wire: its index.
fn add_mnemonic(core: &mut Core, id: &mut u64, name: &str) -> u64 {
    let reply = call_as(
        core,
        id,
        &chrome(),
        "accounts.add_mnemonic",
        json!({ "name": name }),
    );
    result(&reply)["wallet"]["index"].as_u64().unwrap()
}

fn remove(core: &mut Core, id: &mut u64, index: u64) -> Value {
    call_as(
        core,
        id,
        &chrome(),
        "accounts.remove",
        json!({ "index": index, "swarm_references": [] }),
    )
}

/// The indices `vault-meta.json` lists.
fn listed_indices(root: &Path) -> Vec<u64> {
    let meta: Value = serde_json::from_str(&read_meta(root).unwrap()).unwrap();
    meta["derivedWallets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["index"].as_u64().unwrap())
        .collect()
}

/// `accounts-remove-forget-first`: a forget whose write fails refuses the
/// removal, with the account and the grant's file as they were, and so
/// does a retry while the file is still behind memory. Once the forget
/// reaches the file the removal goes, and an account given the same index
/// later finds no grant of the old one's after a restart.
#[test]
fn a_failed_forget_refuses_the_removal() {
    let root = tempfile::tempdir().unwrap();
    let grant_root = root.path().join("userData");
    std::fs::create_dir_all(&grant_root).unwrap();
    write_dapp(&grant_root, &[(SITE, 1), ("https://main.example", 0)]);
    let hook = root.path().join("hook");
    std::fs::write(&hook, "").unwrap();
    let hook_env = hook.to_str().unwrap().to_owned();
    let env = [(HOOK, hook_env.as_str())];
    let (mut core, _) = start(root.path(), &["vault_meta"], &["dapp"], &env);
    let mut id = 1;
    import(&mut core, &mut id);
    write_meta(root.path(), "{\n  \"userKnowsPassword\": true\n}");
    assert_eq!(add_mnemonic(&mut core, &mut id, "Second"), 1);
    let meta_before = read_meta(root.path());
    let dapp_before = std::fs::read(grant_root.join("dapp-permissions.json")).unwrap();
    std::fs::write(&hook, "dapp:write\n").unwrap();
    // The first attempt, and a retry: memory forgot the grant at the
    // first, so the retry has no change of its own, and writes all the same.
    for attempt in 0..2 {
        let reply = remove(&mut core, &mut id, 1);
        assert_eq!(code(&reply), "storage", "{attempt}: {reply}");
        assert_eq!(reply["error"]["data"]["store"], "dapp", "{reply}");
        assert_eq!(read_meta(root.path()), meta_before, "{attempt}");
        assert_eq!(listed_indices(root.path()), [0, 1]);
        assert_eq!(
            std::fs::read(grant_root.join("dapp-permissions.json")).unwrap(),
            dapp_before,
            "{attempt}: the grant stays in the file"
        );
    }
    std::fs::write(&hook, "").unwrap();
    assert_eq!(*result(&remove(&mut core, &mut id, 1)), json!({}));
    assert_eq!(listed_indices(root.path()), [0]);
    assert_eq!(dapp_sites(&grant_root), ["https://main.example"]);
    // The index is handed out again. Once the file has caught up, a
    // removal with nothing to forget doesn't write it.
    assert_eq!(add_mnemonic(&mut core, &mut id, "Third"), 1);
    std::fs::write(&hook, "dapp:write\n").unwrap();
    assert_eq!(*result(&remove(&mut core, &mut id, 1)), json!({}));
    std::fs::write(&hook, "").unwrap();
    assert_eq!(add_mnemonic(&mut core, &mut id, "Fourth"), 1);
    drop(core);
    let (mut core, _) = start(root.path(), &["vault_meta"], &["dapp"], &env);
    let mut id = 1;
    set_unlocked(&mut core, &mut id, true);
    let records = call_as(
        &mut core,
        &mut id,
        &chrome(),
        "approval.grants",
        json!({ "store": "dapp" }),
    );
    let records = result(&records)["records"].as_array().unwrap().clone();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["walletIndex"], 0, "{records:?}");
    assert_eq!(dapp_sites(&grant_root), ["https://main.example"]);
}

/// A forget that reached the file, then a failed metadata write: the
/// account is still there, with no grant. The answer is `durable: false`
/// when either store's flush failed. With `vault_meta` moved and the dApp
/// file not, the removal is `not_moved` for the dApp file, and nothing
/// changes.
#[test]
fn a_forget_then_a_failed_metadata_write_and_durability() {
    let root = tempfile::tempdir().unwrap();
    let grant_root = root.path().join("userData");
    std::fs::create_dir_all(&grant_root).unwrap();
    write_dapp(&grant_root, &[(SITE, 1), ("https://two.example", 2)]);
    let hook = root.path().join("hook");
    std::fs::write(&hook, "").unwrap();
    let hook_env = hook.to_str().unwrap().to_owned();
    let (mut core, _) = start(
        root.path(),
        &["vault_meta"],
        &["dapp"],
        &[(HOOK, &hook_env)],
    );
    let mut id = 1;
    import(&mut core, &mut id);
    write_meta(root.path(), "{\n  \"userKnowsPassword\": true\n}");
    assert_eq!(add_mnemonic(&mut core, &mut id, "Second"), 1);
    assert_eq!(add_mnemonic(&mut core, &mut id, "Third"), 2);
    let meta_before = read_meta(root.path());
    std::fs::write(&hook, "vault_meta:write\n").unwrap();
    let reply = remove(&mut core, &mut id, 1);
    assert_eq!(code(&reply), "storage", "{reply}");
    assert_eq!(reply["error"]["data"]["file"], "vault_meta", "{reply}");
    assert_eq!(read_meta(root.path()), meta_before);
    assert_eq!(listed_indices(root.path()), [0, 1, 2]);
    assert_eq!(dapp_sites(&grant_root), ["https://two.example"]);
    // The dApp file's flush fails: the metadata's is durable, the answer not.
    std::fs::write(&hook, "dapp:flush\n").unwrap();
    assert_eq!(
        *result(&remove(&mut core, &mut id, 2)),
        json!({ "durable": false })
    );
    assert_eq!(listed_indices(root.path()), [0, 1]);
    assert!(dapp_sites(&grant_root).is_empty());
    // The metadata's flush fails, with nothing left to forget.
    std::fs::write(&hook, "vault_meta:flush\n").unwrap();
    assert_eq!(
        *result(&remove(&mut core, &mut id, 1)),
        json!({ "durable": false })
    );
    assert_eq!(listed_indices(root.path()), [0]);
    drop(core);
    // The dApp file still main's: refused, the account and grant there.
    let root = tempfile::tempdir().unwrap();
    let grant_root = root.path().join("userData");
    std::fs::create_dir_all(&grant_root).unwrap();
    write_dapp(&grant_root, &[(SITE, 1)]);
    let (mut core, _) = start(root.path(), &["vault_meta"], &[], &[]);
    let mut id = 1;
    import(&mut core, &mut id);
    write_meta(root.path(), "{\n  \"userKnowsPassword\": true\n}");
    assert_eq!(add_mnemonic(&mut core, &mut id, "Second"), 1);
    let meta_before = read_meta(root.path());
    let dapp_before = std::fs::read(grant_root.join("dapp-permissions.json")).unwrap();
    let reply = remove(&mut core, &mut id, 1);
    assert_eq!(code(&reply), "not_moved", "{reply}");
    assert_eq!(reply["error"]["data"]["store"], "dapp", "{reply}");
    assert_eq!(read_meta(root.path()), meta_before);
    assert_eq!(
        std::fs::read(grant_root.join("dapp-permissions.json")).unwrap(),
        dapp_before
    );
}
