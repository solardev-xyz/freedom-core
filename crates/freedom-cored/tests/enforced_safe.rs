//! Design 0012's Safe signatures through the real binary (APR-4b). Under
//! any caller, the core signs no `SafeTx` or `SafeMessage` typed data, and
//! no transaction calling `execTransaction`, without a token that binds it
//! or a Safe approval of the caller's own kind: a page's under `page` with
//! its origin, frame and navigation, a wallet's under `shell`. Main's word
//! and a standing rule sign none. The first owner fixes the SafeTx or
//! SafeMessage; the executor signs within the fee check, or with an
//! `executor-send` token, and its signature ends the approval;
//! `approval.end` ends one, and a signature racing it either finishes
//! before the end replies or is refused; at most 64 are kept, and none
//! across a restart.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const HANDLE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SITE: &str = "https://app.example";
const SAFE: &str = "0x1111111111111111111111111111111111111111";
const OTHER_SAFE: &str = "0x2222222222222222222222222222222222222222";
const TO: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const ZERO: &str = "0x0000000000000000000000000000000000000000";
/// EIP-191's digest of `hello`: the SafeMessage a `personal_sign` of it
/// makes.
const DIGEST: &str = "0x50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750";
/// Max fees per gas against the served reference's quote of 1.9 gwei:
/// within the fee check, and above three times it.
const CHEAP: &str = "2000000000";
const DEAR: &str = "7000000000";

fn page_as(origin: &str, frame: u64, navigation: u64) -> Value {
    json!({ "caller": "page", "page": {
        "origin": origin, "top_origin": origin, "frame": frame, "navigation": navigation, "agent": false,
    } })
}

fn site() -> Value {
    page_as(SITE, 1, 1)
}

/// The site's document in each other form: another origin, frame and
/// navigation.
fn other_documents() -> [Value; 3] {
    [
        page_as("https://other.example", 1, 1),
        page_as(SITE, 2, 1),
        page_as(SITE, 1, 2),
    ]
}

fn chrome() -> Value {
    json!({ "caller": "chrome" })
}

fn shell() -> Value {
    json!({ "caller": "shell" })
}

/// A core with its grant root, holding `dapp` (the dApp file's text) if
/// given, the vault locked.
fn start(root: &Path, dapp: Option<&str>) -> Core {
    let mut core = spawn("serve", &root.join("identity"), &root.join("locks"), &[]);
    std::fs::create_dir_all(&core.grant_root).unwrap();
    if let Some(dapp) = dapp {
        std::fs::write(core.grant_root.join("dapp-permissions.json"), dapp).unwrap();
    }
    assert_eq!(core.hello()["result"]["protocol"], 2);
    core
}

/// A new vault from the `abandon` mnemonic, unlocked.
fn imported(root: &Path, dapp: Option<&str>) -> Core {
    let mut core = start(root, dapp);
    let mut id = 1;
    let reply = call_as(
        &mut core,
        &mut id,
        &shell(),
        "vault.import",
        json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(ABANDON) }),
    );
    assert!(reply["result"].is_object(), "{reply}");
    core
}

/// The same vault after a restart, unlocked.
fn restarted(root: &Path) -> Core {
    let mut core = start(root, None);
    let mut id = 1;
    let reply = call_as(
        &mut core,
        &mut id,
        &shell(),
        "vault.unlock",
        json!({ "password_b64": STANDARD.encode("testpass1") }),
    );
    assert!(reply["result"].is_object(), "{reply}");
    core
}

fn message(id: u64, context: &Value, method: &str, params: Value) -> Value {
    json!({ "type": "request", "id": id, "method": method, "params": params, "context": context })
}

fn call_as(core: &mut Core, id: &mut u64, context: &Value, method: &str, params: Value) -> Value {
    *id += 1;
    core.send(&message(*id, context, method, params));
    core.response(*id)
}

fn result(reply: &Value) -> &Value {
    assert!(reply["result"].is_object(), "{reply}");
    &reply["result"]
}

/// Refused with `code` (and `reason`), and nothing signed.
fn refused(reply: &Value, code: &str, reason: Option<&str>) {
    assert_eq!(reply["error"]["code"], code, "{reply}");
    if let Some(reason) = reason {
        assert_eq!(reply["error"]["data"]["reason"], reason, "{reply}");
    }
    assert!(reply.get("result").is_none(), "{reply}");
}

/// Signed: a typed-data signature or a raw transaction.
fn signs(reply: &Value) {
    let result = result(reply);
    assert!(
        result["signature"].is_string() || result["raw"].is_string(),
        "{reply}"
    );
}

fn account(index: u32) -> Value {
    json!({ "kind": "account", "index": index })
}

fn safe_send(safe: &str) -> Value {
    json!({ "safe": safe, "chain_id": "100", "tx": { "to": TO, "value": "1000", "data": "0xa9059cbb" } })
}

/// The SafeTx [`safe_send`] approves for `safe`, at `nonce`, as the
/// reference builds one call: operation 0, no refund.
fn safe_tx(safe: &str, nonce: u64) -> Value {
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
            "gasToken": ZERO, "refundReceiver": ZERO, "nonce": nonce.to_string(),
        },
    })
}

fn safe_message(safe: &str, chain_id: &str, digest: &str) -> Value {
    json!({
        "domain": { "chainId": chain_id, "verifyingContract": safe },
        "types": { "SafeMessage": [{ "name": "message", "type": "bytes" }] },
        "message": { "message": digest },
    })
}

/// The SafeMessage a site's `safe-message` for `hello` approves.
fn hello() -> Value {
    safe_message(SAFE, "100", DIGEST)
}

fn mail() -> Value {
    json!({
        "domain": { "name": "Ether Mail", "chainId": "100" },
        "types": { "Mail": [{ "name": "contents", "type": "string" }] },
        "message": { "contents": "Hello" },
    })
}

/// The EIP-712 hash `sign.typed_data` confirms, computed outside the core.
fn typed_hash(typed: &Value) -> String {
    fc_evm::to_hex(
        &fc_evm::typed_data_hash(&typed["domain"], &typed["types"], &typed["message"]).unwrap(),
    )
}

/// A Safe approval's authorization.
fn safe(approval: &str) -> Option<Value> {
    Some(json!({ "safe": approval }))
}

/// An owner's (account `index`) `sign.typed_data` of `typed`.
fn owner(
    core: &mut Core,
    id: &mut u64,
    context: &Value,
    index: u32,
    typed: &Value,
    authorization: Option<Value>,
) -> Value {
    let mut params =
        json!({ "key": account(index), "typed_data": typed, "expected_hash": typed_hash(typed) });
    if let Some(authorization) = authorization {
        params["authorization"] = authorization;
    }
    call_as(core, id, context, "sign.typed_data", params)
}

/// The executor's (account 2) `sign.transaction` of `tx`.
fn executor(
    core: &mut Core,
    id: &mut u64,
    context: &Value,
    tx: &Value,
    authorization: Option<Value>,
) -> Value {
    let mut params = json!({ "key": account(2), "tx": tx });
    if let Some(authorization) = authorization {
        params["authorization"] = authorization;
    }
    call_as(core, id, context, "sign.transaction", params)
}

/// The SafeTx an `execTransaction` call carries: each field as hex
/// digits, `data` as its bytes'.
#[derive(Clone)]
struct Exec {
    to: String,
    value: String,
    data: String,
    operation: String,
    safe_tx_gas: String,
    base_gas: String,
    gas_price: String,
    gas_token: String,
    refund_receiver: String,
}

impl Exec {
    /// The SafeTx [`safe_send`] approves.
    fn approved() -> Exec {
        Exec {
            to: TO[2..].to_owned(),
            value: "3e8".to_owned(),
            data: "a9059cbb".to_owned(),
            operation: "0".to_owned(),
            safe_tx_gas: "0".to_owned(),
            base_gas: "0".to_owned(),
            gas_price: "0".to_owned(),
            gas_token: "0".to_owned(),
            refund_receiver: "0".to_owned(),
        }
    }

    /// The approved SafeTx with each of its fields changed in turn.
    fn changed() -> Vec<(&'static str, Exec)> {
        let other = OTHER_SAFE[2..].to_owned();
        let with = |change: &dyn Fn(&mut Exec)| {
            let mut exec = Exec::approved();
            change(&mut exec);
            exec
        };
        vec![
            ("to", with(&|e| e.to.clone_from(&other))),
            ("value", with(&|e| e.value = "3e9".to_owned())),
            ("data", with(&|e| e.data = "a9059cbc".to_owned())),
            ("operation", with(&|e| e.operation = "1".to_owned())),
            ("safeTxGas", with(&|e| e.safe_tx_gas = "1".to_owned())),
            ("baseGas", with(&|e| e.base_gas = "1".to_owned())),
            ("gasPrice", with(&|e| e.gas_price = "1".to_owned())),
            ("gasToken", with(&|e| e.gas_token.clone_from(&other))),
            (
                "refundReceiver",
                with(&|e| e.refund_receiver.clone_from(&other)),
            ),
        ]
    }

    /// `execTransaction(…)`, as ethers encodes it, with 65 bytes of
    /// signatures.
    fn call(&self) -> String {
        let word = |hex: &str| format!("{hex:0>64}");
        let len = self.data.len() / 2;
        let padded = len.div_ceil(32) * 32;
        let mut call = String::from("0x6a761202");
        call += &word(&self.to);
        call += &word(&self.value);
        call += &word("140");
        for field in [
            &self.operation,
            &self.safe_tx_gas,
            &self.base_gas,
            &self.gas_price,
            &self.gas_token,
            &self.refund_receiver,
        ] {
            call += &word(field);
        }
        call += &word(&format!("{:x}", 10 * 32 + 32 + padded));
        call += &word(&format!("{len:x}"));
        call += &format!("{:0<width$}", self.data, width = padded * 2);
        call += &word("41");
        call += &format!("{:0<192}", "5a".repeat(65));
        call
    }
}

/// The executor's transaction: `execTransaction` to `safe` on chain 100,
/// `value` 0, with `max_fee` per gas.
fn executor_tx(safe: &str, exec: &Exec, max_fee: &str) -> Value {
    json!({
        "type": 2, "chain_id": "100", "nonce": "9", "gas_limit": "200000", "to": safe, "value": "0",
        "data": exec.call(), "max_fee_per_gas": max_fee, "max_priority_fee_per_gas": "1000000000",
    })
}

fn token_of(reply: &Value) -> String {
    result(reply)["token"].as_str().unwrap().to_owned()
}

/// A token of `kind` for `payload`, minted under `context` and spent there
/// for its Safe approval.
fn approval_of(core: &mut Core, id: &mut u64, context: &Value, mut params: Value) -> String {
    if context["caller"] == "page" {
        params["handle"] = json!(HANDLE);
    }
    let token = token_of(&call_as(
        core,
        id,
        context,
        "approval.issue",
        params.clone(),
    ));
    params["token"] = json!(token);
    let spent = call_as(core, id, context, "approval.spend", params);
    let approval = result(&spent)["safe"].as_str().unwrap().to_owned();
    assert_eq!(approval.len(), 32);
    approval
}

/// A `safe-send`'s Safe approval for `safe`: a wallet's under `shell`, a
/// site's under `page`.
fn send_approval(core: &mut Core, id: &mut u64, context: &Value, safe: &str) -> String {
    let params = json!({ "kind": "safe-send", "account": 0, "payload": safe_send(safe) });
    approval_of(core, id, context, params)
}

/// A site's `safe-message` approval for a `personal_sign` of `hello` by
/// [`SAFE`] on chain 100.
fn message_approval(core: &mut Core, id: &mut u64, context: &Value) -> String {
    let params = json!({ "kind": "safe-message", "account": 0, "payload": {
        "safe": SAFE, "chain_id": "100", "method": "personal_sign", "params": ["0x68656c6c6f", SAFE],
    } });
    approval_of(core, id, context, params)
}

/// An `executor-send` token for `tx`, minted under `shell` with the fee
/// acknowledged, as main mints it once the user confirms the fee.
fn executor_send(core: &mut Core, id: &mut u64, tx: &Value) -> Option<Value> {
    let minted = call_as(
        core,
        id,
        &shell(),
        "approval.issue",
        json!({ "kind": "executor-send", "account": 2, "payload": { "tx": tx }, "fee_ack": true }),
    );
    Some(json!({ "token": token_of(&minted), "kind": "executor-send" }))
}

/// The JSON-RPC body of a `shell.rpc` request's method.
fn rpc_method(request: &Value) -> String {
    if request["method"] != "shell.rpc" {
        return String::new();
    }
    let body: Value = serde_json::from_str(request["params"]["body"].as_str().unwrap()).unwrap();
    body["method"].as_str().unwrap().to_owned()
}

fn rpc_result(result: &str) -> Value {
    let text = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
    json!({ "result": { "status": 200, "body": STANDARD.encode(text) } })
}

/// Chain 100 with Myotis, Colibri's prover and two endpoints, and its fee
/// reference served as main relays it: two endpoints quoting 1.9 gwei, the
/// evidence the executor's fee is judged against ([`CHEAP`], [`DEAR`]).
fn serve_fee_reference(core: &mut Core, id: &mut u64) {
    let chain = json!({
        "chain_id": 100, "display_name": "Gnosis",
        "read_order": ["myotis", "colibri", "quorum", "direct"], "broadcast_order": ["direct"],
        "quorum": { "k": 3, "m": 2, "timeout_ms": 5000 },
        "rpc": [
            { "endpoint": "a", "user_configured": false },
            { "endpoint": "b", "user_configured": false },
        ],
        "prover": { "endpoint": "p1", "zk": true }, "myotis": true, "blockscout": null,
    });
    let configured = call_as(
        core,
        id,
        &chrome(),
        "chain.configure",
        json!({ "chains": [chain] }),
    );
    assert!(configured["result"].is_object(), "{configured}");
    call_as(
        core,
        id,
        &chrome(),
        "chain.availability",
        json!({ "chain_id": 100, "ready": true }),
    );
    *id += 1;
    let asked = *id;
    core.send(&message(
        asked,
        &chrome(),
        "chain.fee_reference",
        json!({ "chain_id": 100, "deadline_ms": 30_000 }),
    ));
    let reply = loop {
        let request = core.recv();
        match request["type"].as_str() {
            Some("request") => {
                let endpoint = request["params"]["endpoint"].as_str().unwrap_or("");
                let outcome = match (request["method"].as_str(), rpc_method(&request).as_str()) {
                    (Some("shell.verified"), _) => json!({ "result": { "result": {
                        "number": "0x1312d00", "timestamp": "0x6553f100", "baseFeePerGas": "0x3b9aca00",
                    } } }),
                    (_, "eth_gasPrice") if endpoint == "a" => rpc_result(r#""0x3b9aca00""#),
                    (_, "eth_gasPrice") => rpc_result(r#""0x77359400""#),
                    (_, "eth_maxPriorityFeePerGas") if endpoint == "a" => {
                        rpc_result(r#""0x5f5e100""#)
                    }
                    (_, "eth_maxPriorityFeePerGas") => rpc_result(r#""0xbebc200""#),
                    (_, other) => panic!("{other}"),
                };
                let mut answer = json!({ "type": "response", "id": request["id"] });
                for (key, value) in outcome.as_object().unwrap() {
                    answer[key] = value.clone();
                }
                core.send(&answer);
            }
            Some("response") if request["id"] == asked => break request,
            Some("event") => {}
            _ => panic!("unexpected {request}"),
        }
    };
    assert_eq!(
        reply["result"]["quote"]["maxFeePerGas"], "1900000000",
        "{reply}"
    );
    assert_eq!(reply["result"]["quote"]["answered"], 2, "{reply}");
}

/// Under any caller, a Safe's signature needs its approval or a token
/// that binds it: main's word refuses a SafeTx, a SafeMessage and an
/// `execTransaction` under `shell` (before any key, the vault locked
/// included), as `page` and `chrome` are refused without one; a standing
/// rule answers none of them, though it covers the same request's call and
/// `approval.check` says so. Main's own other signatures still sign on its
/// word; a page's SafeTx signs under its `sign-typed-data` token, a page's
/// `execTransaction` under its `dapp-send`, and the wallet's under its
/// `wallet-send`.
#[test]
fn a_safes_signature_needs_its_approval_or_a_token() {
    let root = tempfile::tempdir().unwrap();
    // The site may sign, and send `execTransaction` to the Safe.
    let rules = json!({ "signing": true, "transactions": [
        { "to": SAFE, "selector": "0x6a761202", "chainId": 100, "maxValue": "5" },
    ] });
    let file = serde_json::to_string_pretty(&json!({ SITE: {
        "origin": SITE, "connectedAt": 1_762_000_000_000_u64, "lastUsed": 1_762_000_000_000_u64,
        "walletIndex": 0, "chainId": 100, "autoApprove": rules,
    } }))
    .unwrap();
    let mut core = imported(root.path(), Some(&file));
    let mut id = 10;
    serve_fee_reference(&mut core, &mut id);
    let exec = executor_tx(SAFE, &Exec::approved(), CHEAP);
    for context in [shell(), chrome(), site()] {
        for typed in [safe_tx(SAFE, 1), hello()] {
            refused(
                &owner(&mut core, &mut id, &context, 0, &typed, None),
                "not_authorized",
                Some("no_token"),
            );
        }
        refused(
            &executor(&mut core, &mut id, &context, &exec, None),
            "not_authorized",
            Some("no_token"),
        );
    }
    // Main's own other typed data and transactions sign on its word.
    signs(&owner(&mut core, &mut id, &shell(), 0, &mail(), None));
    let mut plain = exec.clone();
    plain["data"] = json!("0xa9059cbb");
    signs(&executor(&mut core, &mut id, &shell(), &plain, None));

    // A standing rule answers the site's typed data and its call to the
    // Safe, but no Safe's signature.
    let standing = Some(json!({ "standing": { "paused": false } }));
    let mut params = json!({ "key": account(0), "typed_data": mail(),
        "expected_hash": typed_hash(&mail()), "chain_id": "100", "authorization": standing });
    signs(&call_as(
        &mut core,
        &mut id,
        &site(),
        "sign.typed_data",
        params.clone(),
    ));
    for typed in [safe_tx(SAFE, 1), hello()] {
        params["typed_data"] = typed.clone();
        params["expected_hash"] = json!(typed_hash(&typed));
        refused(
            &call_as(
                &mut core,
                &mut id,
                &site(),
                "sign.typed_data",
                params.clone(),
            ),
            "not_authorized",
            Some("no_rule"),
        );
    }
    refused(
        &executor(&mut core, &mut id, &site(), &exec, standing.clone()),
        "not_authorized",
        Some("no_rule"),
    );
    // `approval.check` agrees: the rule covers the site's typed data, but
    // no Safe's signature, a Ledger's included; a Safe account's own
    // message is still a rule's, through its approval.
    let check = |core: &mut Core, id: &mut u64, request: Value| {
        let reply = call_as(
            core,
            id,
            &site(),
            "approval.check",
            json!({ "request": request, "chain_id": 100, "paused": false }),
        );
        result(&reply).clone()
    };
    let no_rule = json!({ "covered": false, "reason": "no_rule" });
    let typed = |typed: Value, kind: &str| json!({ "kind": "typed_data", "account": 0, "account_kind": kind, "typed_data": typed });
    assert_eq!(
        check(&mut core, &mut id, typed(mail(), "vault")),
        json!({ "covered": true })
    );
    assert_eq!(
        check(&mut core, &mut id, typed(safe_tx(SAFE, 1), "vault")),
        no_rule
    );
    assert_eq!(check(&mut core, &mut id, typed(hello(), "ledger")), no_rule);
    assert_eq!(
        check(&mut core, &mut id, typed(safe_tx(SAFE, 1), "safe")),
        json!({ "covered": true })
    );
    let send = json!({ "kind": "transaction", "account": 0, "account_kind": "vault", "tx": exec });
    assert_eq!(check(&mut core, &mut id, send), no_rule);

    // A page's own `eth_signTypedData_v4` of a SafeTx, for a Safe the
    // wallet doesn't hold: its `sign-typed-data` token signs it, once.
    let minted = call_as(
        &mut core,
        &mut id,
        &site(),
        "approval.issue",
        json!({ "kind": "sign-typed-data", "account": 0, "handle": HANDLE,
            "payload": { "typed_data": safe_tx(OTHER_SAFE, 4) } }),
    );
    let token = json!({ "token": token_of(&minted), "handle": HANDLE });
    signs(&owner(
        &mut core,
        &mut id,
        &site(),
        0,
        &safe_tx(OTHER_SAFE, 4),
        Some(token.clone()),
    ));
    refused(
        &owner(
            &mut core,
            &mut id,
            &site(),
            0,
            &safe_tx(OTHER_SAFE, 4),
            Some(token),
        ),
        "not_authorized",
        Some("unknown_token"),
    );
    // A page's own `execTransaction`, under the `dapp-send` that binds it;
    // the wallet's, under its `wallet-send`.
    let minted = call_as(
        &mut core,
        &mut id,
        &site(),
        "approval.issue",
        json!({ "kind": "dapp-send", "account": 2, "handle": HANDLE, "payload": { "tx": exec } }),
    );
    let token = json!({ "token": token_of(&minted), "kind": "dapp-send", "handle": HANDLE });
    signs(&executor(&mut core, &mut id, &site(), &exec, Some(token)));
    let minted = call_as(
        &mut core,
        &mut id,
        &shell(),
        "approval.issue",
        json!({ "kind": "wallet-send", "account": 2, "payload": { "tx": exec } }),
    );
    let token = json!({ "token": token_of(&minted), "kind": "wallet-send" });
    signs(&executor(&mut core, &mut id, &shell(), &exec, Some(token)));

    // Refused before any key: while locked, main's word is still
    // `not_authorized`, not `vault_locked`.
    result(&call_as(
        &mut core,
        &mut id,
        &shell(),
        "vault.lock",
        json!({}),
    ));
    refused(
        &owner(&mut core, &mut id, &shell(), 0, &safe_tx(SAFE, 1), None),
        "not_authorized",
        Some("no_token"),
    );
    refused(
        &executor(&mut core, &mut id, &shell(), &exec, None),
        "not_authorized",
        Some("no_token"),
    );
    refused(
        &owner(&mut core, &mut id, &shell(), 0, &mail(), None),
        "vault_locked",
        None,
    );
}

/// The vault owners of a wallet's Safe send, under `shell`: refused with
/// another Safe's approval, and for a Safe, chain, `to`, `value` or `data`
/// other than the token's; the first fixes the SafeTx, after which another
/// is refused, and the second local owner and one at a later board sign
/// the same. A site's Safe message: refused for another digest, Safe or
/// chain; every owner signs only its SafeMessage.
#[test]
fn the_first_owner_fixes_what_every_owner_signs() {
    let root = tempfile::tempdir().unwrap();
    let mut core = imported(root.path(), None);
    let mut id = 10;
    let approval = send_approval(&mut core, &mut id, &shell(), SAFE);
    let other = send_approval(&mut core, &mut id, &shell(), OTHER_SAFE);
    refused(
        &owner(
            &mut core,
            &mut id,
            &shell(),
            0,
            &safe_tx(SAFE, 7),
            safe(&other),
        ),
        "not_authorized",
        Some("mismatch"),
    );
    let changes: [(&str, &str, Value); 5] = [
        ("domain", "verifyingContract", json!(OTHER_SAFE)),
        ("domain", "chainId", json!("1")),
        ("message", "to", json!(OTHER_SAFE)),
        ("message", "value", json!("1001")),
        ("message", "data", json!("0xa9059cbc")),
    ];
    for (part, field, value) in &changes {
        let mut typed = safe_tx(SAFE, 7);
        typed[part][field] = value.clone();
        refused(
            &owner(&mut core, &mut id, &shell(), 0, &typed, safe(&approval)),
            "not_authorized",
            Some("mismatch"),
        );
    }
    // The first owner fixes nonce 7's SafeTx.
    signs(&owner(
        &mut core,
        &mut id,
        &shell(),
        0,
        &safe_tx(SAFE, 7),
        safe(&approval),
    ));
    refused(
        &owner(
            &mut core,
            &mut id,
            &shell(),
            1,
            &safe_tx(SAFE, 8),
            safe(&approval),
        ),
        "not_authorized",
        Some("mismatch"),
    );
    signs(&owner(
        &mut core,
        &mut id,
        &shell(),
        1,
        &safe_tx(SAFE, 7),
        safe(&approval),
    ));
    // A later board, after other approvals and signatures: the same.
    let later = message_approval(&mut core, &mut id, &site());
    signs(&owner(
        &mut core,
        &mut id,
        &site(),
        0,
        &hello(),
        safe(&later),
    ));
    refused(
        &owner(
            &mut core,
            &mut id,
            &shell(),
            3,
            &safe_tx(SAFE, 6),
            safe(&approval),
        ),
        "not_authorized",
        Some("mismatch"),
    );
    signs(&owner(
        &mut core,
        &mut id,
        &shell(),
        3,
        &safe_tx(SAFE, 7),
        safe(&approval),
    ));

    // A site's Safe message: another digest, Safe or chain, at the first
    // owner's signature and at every later one.
    let approval = message_approval(&mut core, &mut id, &site());
    let elsewhere = [
        safe_message(SAFE, "100", &format!("0x{}", "00".repeat(32))),
        safe_message(OTHER_SAFE, "100", DIGEST),
        safe_message(SAFE, "1", DIGEST),
        safe_tx(SAFE, 7),
    ];
    for index in [0, 1, 3] {
        for typed in &elsewhere {
            refused(
                &owner(&mut core, &mut id, &site(), index, typed, safe(&approval)),
                "not_authorized",
                Some("mismatch"),
            );
        }
        signs(&owner(
            &mut core,
            &mut id,
            &site(),
            index,
            &hello(),
            safe(&approval),
        ));
    }
}

/// The executor of a wallet's Safe send, under `shell`, with the fee
/// reference served: refused for another Safe, a `value`, another chain and
/// each SafeTx field changed; over the fee threshold refused, and signed
/// with an `executor-send` token, which ends the approval; within it,
/// signed with the approval, which its signature ends. The wallet's own
/// Safe send signs its owners and its executor.
#[test]
fn the_executor_signs_within_the_fee_check_or_with_its_token() {
    let root = tempfile::tempdir().unwrap();
    let mut core = imported(root.path(), None);
    let mut id = 10;
    serve_fee_reference(&mut core, &mut id);
    let approval = send_approval(&mut core, &mut id, &shell(), SAFE);
    signs(&owner(
        &mut core,
        &mut id,
        &shell(),
        0,
        &safe_tx(SAFE, 7),
        safe(&approval),
    ));
    let cheap = executor_tx(SAFE, &Exec::approved(), CHEAP);
    let mut refusals = vec![
        (
            "another Safe",
            executor_tx(OTHER_SAFE, &Exec::approved(), CHEAP),
        ),
        ("a value", {
            let mut tx = cheap.clone();
            tx["value"] = json!("1");
            tx
        }),
        ("another chain", {
            let mut tx = cheap.clone();
            tx["chain_id"] = json!("1");
            tx
        }),
    ];
    for (field, exec) in Exec::changed() {
        refusals.push((field, executor_tx(SAFE, &exec, CHEAP)));
    }
    for (what, tx) in &refusals {
        let reply = executor(&mut core, &mut id, &shell(), tx, safe(&approval));
        assert_eq!(
            reply["error"]["data"]["reason"], "mismatch",
            "{what}: {reply}"
        );
        refused(&reply, "not_authorized", None);
    }
    // Over the fee threshold: the approval doesn't sign it; the user's
    // `executor-send` does, and ends the approval.
    let dear = executor_tx(SAFE, &Exec::approved(), DEAR);
    refused(
        &executor(&mut core, &mut id, &shell(), &dear, safe(&approval)),
        "not_authorized",
        Some("fee_check"),
    );
    let token = executor_send(&mut core, &mut id, &dear);
    signs(&executor(&mut core, &mut id, &shell(), &dear, token));
    refused(
        &executor(&mut core, &mut id, &shell(), &cheap, safe(&approval)),
        "not_authorized",
        Some("unknown_token"),
    );
    refused(
        &owner(
            &mut core,
            &mut id,
            &shell(),
            1,
            &safe_tx(SAFE, 7),
            safe(&approval),
        ),
        "not_authorized",
        Some("unknown_token"),
    );

    // The wallet's next Safe send: both owners, then the executor within
    // the fee check, whose signature ends the approval.
    let approval = send_approval(&mut core, &mut id, &shell(), SAFE);
    for index in [0, 1] {
        signs(&owner(
            &mut core,
            &mut id,
            &shell(),
            index,
            &safe_tx(SAFE, 8),
            safe(&approval),
        ));
    }
    signs(&executor(
        &mut core,
        &mut id,
        &shell(),
        &cheap,
        safe(&approval),
    ));
    refused(
        &executor(&mut core, &mut id, &shell(), &cheap, safe(&approval)),
        "not_authorized",
        Some("unknown_token"),
    );
    refused(
        &owner(
            &mut core,
            &mut id,
            &shell(),
            3,
            &safe_tx(SAFE, 8),
            safe(&approval),
        ),
        "not_authorized",
        Some("unknown_token"),
    );
}

/// Whose approval: a site's is refused under `shell`, under `chrome`, and
/// under `page` with another origin, frame or navigation, at an owner's
/// signature and at the executor's, and signs for its own document; a
/// wallet's is refused under `page`.
#[test]
fn an_approval_signs_only_for_its_holder() {
    let root = tempfile::tempdir().unwrap();
    let mut core = imported(root.path(), None);
    let mut id = 10;
    serve_fee_reference(&mut core, &mut id);
    let cheap = executor_tx(SAFE, &Exec::approved(), CHEAP);
    let sites = send_approval(&mut core, &mut id, &site(), SAFE);
    let message = message_approval(&mut core, &mut id, &site());
    let mut strangers = vec![shell(), chrome()];
    strangers.extend(other_documents());
    for context in &strangers {
        refused(
            &owner(
                &mut core,
                &mut id,
                context,
                0,
                &safe_tx(SAFE, 2),
                safe(&sites),
            ),
            "not_authorized",
            Some("mismatch"),
        );
        refused(
            &owner(&mut core, &mut id, context, 0, &hello(), safe(&message)),
            "not_authorized",
            Some("mismatch"),
        );
        refused(
            &executor(&mut core, &mut id, context, &cheap, safe(&sites)),
            "not_authorized",
            Some("mismatch"),
        );
    }
    signs(&owner(
        &mut core,
        &mut id,
        &site(),
        0,
        &safe_tx(SAFE, 2),
        safe(&sites),
    ));
    signs(&owner(
        &mut core,
        &mut id,
        &site(),
        0,
        &hello(),
        safe(&message),
    ));
    // The executor, for the site's document only, after an owner signed.
    for context in &strangers {
        refused(
            &executor(&mut core, &mut id, context, &cheap, safe(&sites)),
            "not_authorized",
            Some("mismatch"),
        );
    }
    signs(&executor(&mut core, &mut id, &site(), &cheap, safe(&sites)));

    // A wallet's approval: never under `page`, from any document, nor
    // under `chrome`.
    let wallets = send_approval(&mut core, &mut id, &shell(), OTHER_SAFE);
    let theirs = executor_tx(OTHER_SAFE, &Exec::approved(), CHEAP);
    for context in [site(), page_as("https://other.example", 1, 1), chrome()] {
        refused(
            &owner(
                &mut core,
                &mut id,
                &context,
                0,
                &safe_tx(OTHER_SAFE, 2),
                safe(&wallets),
            ),
            "not_authorized",
            Some("mismatch"),
        );
        refused(
            &executor(&mut core, &mut id, &context, &theirs, safe(&wallets)),
            "not_authorized",
            Some("mismatch"),
        );
    }
    signs(&owner(
        &mut core,
        &mut id,
        &shell(),
        0,
        &safe_tx(OTHER_SAFE, 2),
        safe(&wallets),
    ));
    signs(&executor(
        &mut core,
        &mut id,
        &shell(),
        &theirs,
        safe(&wallets),
    ));
}

/// Ended: after `approval.end`, an owner's signature and the executor's
/// are refused, and a second end answers `{}`, as an unknown id's does;
/// main's ends before a SafeTx's discard, a SafeMessage's cancel and a
/// SafeMessage's completion leave nothing to sign with; a second `safe-send`
/// approval for a Safe ends the first, and leaves its messages.
#[test]
fn an_ended_approval_signs_nothing() {
    let root = tempfile::tempdir().unwrap();
    let mut core = imported(root.path(), None);
    let mut id = 10;
    serve_fee_reference(&mut core, &mut id);
    let cheap = executor_tx(SAFE, &Exec::approved(), CHEAP);
    let end = |core: &mut Core, id: &mut u64, context: &Value, approval: &str| {
        let ended = call_as(
            core,
            id,
            context,
            "approval.end",
            json!({ "safe": approval }),
        );
        assert_eq!(*result(&ended), json!({}));
    };
    let gone = |core: &mut Core, id: &mut u64, context: &Value, approval: &str, typed: &Value| {
        refused(
            &owner(core, id, context, 1, typed, safe(approval)),
            "not_authorized",
            Some("unknown_token"),
        );
    };
    // `approval.end`, twice, and an id never known, under each caller.
    for context in [shell(), site()] {
        let approval = send_approval(&mut core, &mut id, &context, SAFE);
        signs(&owner(
            &mut core,
            &mut id,
            &context,
            0,
            &safe_tx(SAFE, 3),
            safe(&approval),
        ));
        end(&mut core, &mut id, &context, &approval);
        gone(&mut core, &mut id, &context, &approval, &safe_tx(SAFE, 3));
        refused(
            &executor(&mut core, &mut id, &context, &cheap, safe(&approval)),
            "not_authorized",
            Some("unknown_token"),
        );
        end(&mut core, &mut id, &context, &approval);
    }
    end(&mut core, &mut id, &chrome(), &"0f".repeat(16));
    end(&mut core, &mut id, &shell(), "not an id");

    // A SafeTx's discard: main ends its approval first. Its next owner and
    // its executor are refused.
    let discarded = send_approval(&mut core, &mut id, &site(), SAFE);
    signs(&owner(
        &mut core,
        &mut id,
        &site(),
        0,
        &safe_tx(SAFE, 4),
        safe(&discarded),
    ));
    end(&mut core, &mut id, &site(), &discarded);
    gone(&mut core, &mut id, &site(), &discarded, &safe_tx(SAFE, 4));
    refused(
        &executor(&mut core, &mut id, &site(), &cheap, safe(&discarded)),
        "not_authorized",
        Some("unknown_token"),
    );
    // A SafeMessage's cancel (the user's, or its document gone), before any
    // owner signed.
    let cancelled = message_approval(&mut core, &mut id, &site());
    end(&mut core, &mut id, &site(), &cancelled);
    gone(&mut core, &mut id, &site(), &cancelled, &hello());
    // A SafeMessage's completion: the threshold's last signature made,
    // main ends it before joining them.
    let completed = message_approval(&mut core, &mut id, &site());
    for index in [0, 3] {
        signs(&owner(
            &mut core,
            &mut id,
            &site(),
            index,
            &hello(),
            safe(&completed),
        ));
    }
    end(&mut core, &mut id, &site(), &completed);
    gone(&mut core, &mut id, &site(), &completed, &hello());

    // A second `safe-send` approval for a Safe ends the first, at an owner
    // and at the executor, whoever held it; a message for the Safe stays.
    let message = message_approval(&mut core, &mut id, &site());
    let first = send_approval(&mut core, &mut id, &shell(), SAFE);
    signs(&owner(
        &mut core,
        &mut id,
        &shell(),
        0,
        &safe_tx(SAFE, 5),
        safe(&first),
    ));
    let second = send_approval(&mut core, &mut id, &site(), SAFE);
    gone(&mut core, &mut id, &shell(), &first, &safe_tx(SAFE, 5));
    refused(
        &executor(&mut core, &mut id, &shell(), &cheap, safe(&first)),
        "not_authorized",
        Some("unknown_token"),
    );
    signs(&owner(
        &mut core,
        &mut id,
        &site(),
        0,
        &safe_tx(SAFE, 5),
        safe(&second),
    ));
    signs(&owner(
        &mut core,
        &mut id,
        &site(),
        0,
        &hello(),
        safe(&message),
    ));
}

/// Two requests sent in one write, as main may send them; their replies,
/// in the order they came.
fn together(
    core: &mut Core,
    id: &mut u64,
    first: (&Value, &str, Value),
    second: (&Value, &str, Value),
) -> [Value; 2] {
    let ids = [*id + 1, *id + 2];
    *id += 2;
    let mut bytes = frame(&message(ids[0], first.0, first.1, first.2));
    bytes.extend(frame(&message(ids[1], second.0, second.1, second.2)));
    core.send_raw(&bytes);
    let mut replies = Vec::new();
    while replies.len() < 2 {
        let reply = core.recv();
        if reply["type"] == "response" {
            replies.push(reply);
        }
    }
    assert_eq!(replies[0]["id"], ids[0], "{replies:?}");
    assert_eq!(replies[1]["id"], ids[1], "{replies:?}");
    [replies.remove(0), replies.remove(0)]
}

/// An end racing a signature: sent together, at an owner's call and at the
/// executor's, the signature sent first finishes before the end replies;
/// the one sent after is refused, and nothing signs with the approval once
/// the end has replied.
#[test]
fn an_end_racing_a_signature_finishes_first_or_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let mut core = imported(root.path(), None);
    let mut id = 10;
    serve_fee_reference(&mut core, &mut id);
    let cheap = executor_tx(SAFE, &Exec::approved(), CHEAP);
    let typed = safe_tx(SAFE, 6);
    let owner_params = |index: u32, approval: &str| {
        json!({ "key": account(index), "typed_data": typed,
            "expected_hash": typed_hash(&typed), "authorization": { "safe": approval } })
    };
    let executor_params = |approval: &str| json!({ "key": account(2), "tx": cheap, "authorization": { "safe": approval } });
    for context in [shell(), site()] {
        // The owner's signature, then the end.
        let approval = send_approval(&mut core, &mut id, &context, SAFE);
        let [signed, ended] = together(
            &mut core,
            &mut id,
            (&context, "sign.typed_data", owner_params(0, &approval)),
            (&context, "approval.end", json!({ "safe": approval })),
        );
        signs(&signed);
        assert_eq!(*result(&ended), json!({}));
        refused(
            &owner(&mut core, &mut id, &context, 1, &typed, safe(&approval)),
            "not_authorized",
            Some("unknown_token"),
        );
        // The end, then the owner's signature.
        let approval = send_approval(&mut core, &mut id, &context, SAFE);
        let [ended, late] = together(
            &mut core,
            &mut id,
            (&context, "approval.end", json!({ "safe": approval })),
            (&context, "sign.typed_data", owner_params(0, &approval)),
        );
        assert_eq!(*result(&ended), json!({}));
        refused(&late, "not_authorized", Some("unknown_token"));
        // The executor's signature, then the end; and the end, then the
        // executor's, an owner having signed.
        let approval = send_approval(&mut core, &mut id, &context, SAFE);
        signs(&owner(
            &mut core,
            &mut id,
            &context,
            0,
            &typed,
            safe(&approval),
        ));
        let [signed, ended] = together(
            &mut core,
            &mut id,
            (&context, "sign.transaction", executor_params(&approval)),
            (&context, "approval.end", json!({ "safe": approval })),
        );
        signs(&signed);
        assert_eq!(*result(&ended), json!({}));
        let approval = send_approval(&mut core, &mut id, &context, SAFE);
        signs(&owner(
            &mut core,
            &mut id,
            &context,
            0,
            &typed,
            safe(&approval),
        ));
        let [ended, late] = together(
            &mut core,
            &mut id,
            (&context, "approval.end", json!({ "safe": approval })),
            (&context, "sign.transaction", executor_params(&approval)),
        );
        assert_eq!(*result(&ended), json!({}));
        refused(&late, "not_authorized", Some("unknown_token"));
        refused(
            &owner(&mut core, &mut id, &context, 1, &typed, safe(&approval)),
            "not_authorized",
            Some("unknown_token"),
        );
    }
}

/// At most 64 approvals are kept: the oldest goes once 64 newer are open.
/// None outlives a restart: an owner that hasn't signed needs a new
/// `safe-send` token, and the executor an `executor-send` token.
#[test]
fn sixty_four_approvals_are_kept_and_none_across_a_restart() {
    let root = tempfile::tempdir().unwrap();
    let mut core = imported(root.path(), None);
    let mut id = 10;
    // Each its own Safe: a Safe's newer `safe-send` would end its older.
    let safe_of = |n: u64| format!("0x{:040x}", 0x1000 + n);
    let oldest = send_approval(&mut core, &mut id, &shell(), &safe_of(0));
    let next = message_approval(&mut core, &mut id, &site());
    for n in 2..64 {
        send_approval(&mut core, &mut id, &shell(), &safe_of(n));
    }
    // 64 open: the oldest still signs.
    signs(&owner(
        &mut core,
        &mut id,
        &shell(),
        0,
        &safe_tx(&safe_of(0), 1),
        safe(&oldest),
    ));
    let newest = send_approval(&mut core, &mut id, &shell(), &safe_of(64));
    refused(
        &owner(
            &mut core,
            &mut id,
            &shell(),
            1,
            &safe_tx(&safe_of(0), 1),
            safe(&oldest),
        ),
        "not_authorized",
        Some("unknown_token"),
    );
    signs(&owner(
        &mut core,
        &mut id,
        &site(),
        0,
        &hello(),
        safe(&next),
    ));
    signs(&owner(
        &mut core,
        &mut id,
        &shell(),
        0,
        &safe_tx(&safe_of(64), 1),
        safe(&newest),
    ));

    // A restart: the newest approval, an owner having signed, is gone at
    // the next owner and at the executor.
    drop(core);
    let mut core = restarted(root.path());
    let mut id = 10;
    let theirs = safe_tx(&safe_of(64), 1);
    let tx = executor_tx(&safe_of(64), &Exec::approved(), CHEAP);
    refused(
        &owner(&mut core, &mut id, &shell(), 1, &theirs, safe(&newest)),
        "not_authorized",
        Some("unknown_token"),
    );
    refused(
        &owner(&mut core, &mut id, &site(), 1, &hello(), safe(&next)),
        "not_authorized",
        Some("unknown_token"),
    );
    refused(
        &executor(&mut core, &mut id, &shell(), &tx, safe(&newest)),
        "not_authorized",
        Some("unknown_token"),
    );
    refused(
        &executor(&mut core, &mut id, &shell(), &tx, None),
        "not_authorized",
        Some("no_token"),
    );
    // The owner, with a new `safe-send` token from the board; the
    // executor, with an `executor-send` token.
    let renewed = send_approval(&mut core, &mut id, &shell(), &safe_of(64));
    signs(&owner(
        &mut core,
        &mut id,
        &shell(),
        1,
        &theirs,
        safe(&renewed),
    ));
    let token = executor_send(&mut core, &mut id, &tx);
    signs(&executor(&mut core, &mut id, &shell(), &tx, token));
}
