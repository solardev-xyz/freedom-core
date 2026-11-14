//! Design 0012's approvals through the real binary (APR-3a): tokens over
//! the wire with each caller kind, a page's token bound to its document,
//! Safe approvals for owners and the executor, and `sign.*` checking an
//! authorization. That a page's and the chrome's signatures need one
//! (APR-4a) is `tests/enforced.rs`'s.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const HANDLE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SAFE: &str = "0x1111111111111111111111111111111111111111";
const OTHER_SAFE: &str = "0x2222222222222222222222222222222222222222";
const TO: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const ZERO: &str = "0x0000000000000000000000000000000000000000";

fn unlocked() -> (tempfile::TempDir, Core) {
    let (root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let imported = core.call(
        2,
        "vault.import",
        json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(ABANDON) }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    assert_eq!(core.event()["event"], "vault.unlocked");
    (root, core)
}

fn page(origin: &str, frame: u64, navigation: u64) -> Value {
    json!({ "caller": "page", "page": {
        "origin": origin, "top_origin": origin, "frame": frame, "navigation": navigation, "agent": false,
    } })
}

fn site() -> Value {
    page("https://app.example", 1, 1)
}

fn chrome() -> Value {
    json!({ "caller": "chrome" })
}

fn shell() -> Value {
    json!({ "caller": "shell" })
}

/// One request with `context`, and its response.
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

fn account(index: u32) -> Value {
    json!({ "kind": "account", "index": index })
}

fn send_tx() -> Value {
    json!({
        "type": 2,
        "chain_id": "100",
        "nonce": "3",
        "gas_limit": "21000",
        "to": TO,
        "value": "1000",
        "data": "0x",
        "max_fee_per_gas": "2000000000",
        "max_priority_fee_per_gas": "1000000000",
    })
}

fn mail() -> Value {
    json!({
        "domain": { "name": "Ether Mail", "chainId": "100" },
        "types": { "Mail": [{ "name": "contents", "type": "string" }] },
        "message": { "contents": "Hello" },
    })
}

fn safe_send(safe: &str) -> Value {
    json!({ "safe": safe, "chain_id": "100", "tx": { "to": TO, "value": "1000", "data": "0xa9059cbb" } })
}

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

fn safe_message(safe: &str, digest: &str) -> Value {
    safe_message_on(safe, "100", digest)
}

fn safe_message_on(safe: &str, chain_id: &str, digest: &str) -> Value {
    json!({
        "domain": { "chainId": chain_id, "verifyingContract": safe },
        "types": { "SafeMessage": [{ "name": "message", "type": "bytes" }] },
        "message": { "message": digest },
    })
}

/// `typed_data.hash`'s hash of `typed`.
fn hash(core: &mut Core, id: &mut u64, typed: &Value) -> String {
    let reply = call_as(
        core,
        id,
        &chrome(),
        "typed_data.hash",
        json!({ "typed_data": typed }),
    );
    result(&reply)["hash"].as_str().unwrap().to_owned()
}

/// `execTransaction` to the SafeTx of [`safe_send`], with 65 bytes of
/// signatures, as ethers encodes it.
fn exec_call() -> String {
    format!(
        "0x6a761202{:0>64}{:0>64}{:0>64}{}{:0>64}{:0>64}{:0<64}{:0>64}{}{}",
        &TO[2..],
        "3e8",
        "140",
        "0".repeat(6 * 64),
        "180",
        "4",
        "a9059cbb",
        "41",
        "5a".repeat(65),
        "0".repeat(62),
    )
}

fn executor_tx(safe: &str) -> Value {
    json!({
        "type": 2, "chain_id": "100", "nonce": "9", "gas_limit": "200000", "to": safe, "value": "0",
        "data": exec_call(), "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000000",
    })
}

fn issue(core: &mut Core, id: &mut u64, context: &Value, params: Value) -> Value {
    call_as(core, id, context, "approval.issue", params)
}

fn token_of(reply: &Value) -> String {
    result(reply)["token"].as_str().unwrap().to_owned()
}

/// Page kinds only under `page`, wallet kinds only under `shell`, and
/// `chrome` none; a page caller needs its `PageContext` and the handle.
#[test]
fn each_caller_mints_only_its_kinds() {
    let (_root, mut core) = unlocked();
    let mut id = 10;
    let message = json!({ "kind": "sign-message", "account": 0, "payload": { "message": "0x01" } });
    for context in [chrome(), shell()] {
        refused(
            &issue(&mut core, &mut id, &context, message.clone()),
            "forbidden",
            None,
        );
        let mut with_handle = message.clone();
        with_handle["handle"] = json!(HANDLE);
        refused(
            &issue(&mut core, &mut id, &context, with_handle),
            "forbidden",
            None,
        );
    }
    let wallet = json!({ "kind": "wallet-send", "account": 0, "payload": { "tx": send_tx() }, "handle": HANDLE });
    refused(
        &issue(&mut core, &mut id, &site(), wallet),
        "forbidden",
        None,
    );
    // No handle, a handle in upper case, no PageContext.
    refused(
        &issue(&mut core, &mut id, &site(), message.clone()),
        "invalid_argument",
        None,
    );
    let mut upper = message.clone();
    upper["handle"] = json!(HANDLE.to_uppercase());
    refused(
        &issue(&mut core, &mut id, &site(), upper),
        "invalid_argument",
        None,
    );
    let mut with_handle = message.clone();
    with_handle["handle"] = json!(HANDLE);
    refused(
        &issue(
            &mut core,
            &mut id,
            &json!({ "caller": "page" }),
            with_handle.clone(),
        ),
        "invalid_argument",
        None,
    );
    // A wallet's handle is refused; a wallet send without one mints, under
    // shell only.
    let mut wallet = json!({ "kind": "wallet-send", "account": 0, "payload": { "tx": send_tx() }, "handle": HANDLE });
    refused(
        &issue(&mut core, &mut id, &shell(), wallet.clone()),
        "invalid_argument",
        None,
    );
    wallet.as_object_mut().unwrap().remove("handle");
    refused(
        &issue(&mut core, &mut id, &chrome(), wallet.clone()),
        "forbidden",
        None,
    );
    let minted = issue(&mut core, &mut id, &shell(), wallet);
    assert_eq!(token_of(&minted).len(), 64);
    assert_eq!(result(&minted)["expires_in_ms"], 120_000);
    // Without a fee reference, the check has nothing to compare with.
    assert_eq!(result(&minted)["fee_check"]["comparable"], false);
    let minted = issue(&mut core, &mut id, &site(), with_handle);
    assert_eq!(token_of(&minted).len(), 64);
    assert!(result(&minted).get("fee_check").is_none());
    // Chrome mints no wallet kind (APS-3) and no x402 payment (APS-5):
    // what shell mints, chrome is refused, and so is every other wallet
    // kind, before its payload is read.
    for (kind, payload) in [
        ("wallet-send", json!({ "tx": send_tx() })),
        ("executor-send", json!({ "tx": send_tx() })),
        ("safe-send", safe_send(SAFE)),
    ] {
        let params = json!({ "kind": kind, "account": 0, "payload": payload });
        refused(
            &issue(&mut core, &mut id, &chrome(), params.clone()),
            "forbidden",
            None,
        );
        assert_eq!(
            token_of(&issue(&mut core, &mut id, &shell(), params)).len(),
            64
        );
    }
    for kind in [
        "intent-resend",
        "intent-replace",
        "intent-close",
        "x402-payment",
    ] {
        let params = json!({ "kind": kind, "payload": {} });
        refused(
            &issue(&mut core, &mut id, &chrome(), params),
            "forbidden",
            None,
        );
    }
    // Unknown kinds and members.
    let unknown = json!({ "kind": "x402-cap-update", "account": 0, "payload": {} });
    refused(
        &issue(&mut core, &mut id, &shell(), unknown),
        "invalid_argument",
        None,
    );
    let extra =
        json!({ "kind": "wallet-send", "account": 0, "payload": { "tx": send_tx() }, "page": 1 });
    refused(
        &issue(&mut core, &mut id, &shell(), extra),
        "invalid_argument",
        None,
    );
}

/// A page's token signs once, for its own document: another origin,
/// frame or navigation is refused, and burns it.
#[test]
fn a_page_token_signs_only_its_document() {
    let (_root, mut core) = unlocked();
    let mut id = 10;
    let plain = call_as(
        &mut core,
        &mut id,
        &shell(),
        "sign.message",
        json!({ "key": account(0), "message": "0x68656c6c6f" }),
    );
    let signature = result(&plain)["signature"].clone();
    let mint = |core: &mut Core, id: &mut u64| {
        let params = json!({
            "kind": "sign-message", "account": 0, "payload": { "message": "0x68656C6C6F" }, "handle": HANDLE,
        });
        token_of(&issue(core, id, &site(), params))
    };
    let sign = |core: &mut Core, id: &mut u64, context: &Value, token: &str| {
        call_as(
            core,
            id,
            context,
            "sign.message",
            json!({ "key": account(0), "message": "0x68656c6c6f", "authorization": { "token": token, "handle": HANDLE } }),
        )
    };
    for other in [
        page("https://other.example", 1, 1),
        page("https://app.example", 2, 1),
        page("https://app.example", 1, 2),
    ] {
        let token = mint(&mut core, &mut id);
        refused(
            &sign(&mut core, &mut id, &other, &token),
            "not_authorized",
            Some("mismatch"),
        );
        refused(
            &sign(&mut core, &mut id, &site(), &token),
            "not_authorized",
            Some("unknown_token"),
        );
    }
    // Under chrome and shell: no wallet kind binds a message.
    for context in [chrome(), shell()] {
        let token = mint(&mut core, &mut id);
        let reply = call_as(
            &mut core,
            &mut id,
            &context,
            "sign.message",
            json!({ "key": account(0), "message": "0x68656c6c6f", "authorization": { "token": token } }),
        );
        refused(&reply, "not_authorized", Some("mismatch"));
    }
    // Another handle, and another account.
    let token = mint(&mut core, &mut id);
    let other_handle = json!({ "key": account(0), "message": "0x68656c6c6f",
        "authorization": { "token": token, "handle": "b".repeat(64) } });
    refused(
        &call_as(&mut core, &mut id, &site(), "sign.message", other_handle),
        "not_authorized",
        Some("mismatch"),
    );
    let token = mint(&mut core, &mut id);
    let other_account = json!({ "key": account(1), "message": "0x68656c6c6f",
        "authorization": { "token": token, "handle": HANDLE } });
    refused(
        &call_as(&mut core, &mut id, &site(), "sign.message", other_account),
        "not_authorized",
        Some("mismatch"),
    );
    // Its own document: the same signature as without one, once.
    let token = mint(&mut core, &mut id);
    let signed = sign(&mut core, &mut id, &site(), &token);
    assert_eq!(result(&signed)["signature"], signature);
    refused(
        &sign(&mut core, &mut id, &site(), &token),
        "not_authorized",
        Some("unknown_token"),
    );
    refused(
        &sign(&mut core, &mut id, &site(), ""),
        "not_authorized",
        Some("no_token"),
    );
    // Without an authorization a page's signature is refused (APR-4a), and
    // without its PageContext it is malformed.
    let bare = json!({ "key": account(0), "message": "0x68656c6c6f" });
    refused(
        &call_as(&mut core, &mut id, &site(), "sign.message", bare.clone()),
        "not_authorized",
        Some("no_token"),
    );
    refused(
        &call_as(
            &mut core,
            &mut id,
            &json!({ "caller": "page" }),
            "sign.message",
            bare,
        ),
        "invalid_argument",
        None,
    );
    // A standing rule reads the dApp grants: with no file, none answers.
    let standing = json!({ "key": account(0), "message": "0x68656c6c6f", "authorization": { "standing": { "paused": false } } });
    refused(
        &call_as(&mut core, &mut id, &site(), "sign.message", standing),
        "not_authorized",
        Some("no_rule"),
    );
}

/// A presented token is burnt however the request ends: a malformed
/// request, a locked vault, a discard, a malformed discard and a page's
/// discard without its `PageContext`.
#[test]
fn a_presented_token_is_burnt_whatever_the_outcome() {
    let (_root, mut core) = unlocked();
    let mut id = 10;
    let mint = |core: &mut Core, id: &mut u64| {
        let params = json!({ "kind": "wallet-send", "account": 0, "payload": { "tx": send_tx() } });
        token_of(&issue(core, id, &shell(), params))
    };
    let sign = |core: &mut Core, id: &mut u64, tx: Value, token: &str| {
        call_as(
            core,
            id,
            &shell(),
            "sign.transaction",
            json!({ "key": account(0), "tx": tx, "authorization": { "token": token, "kind": "wallet-send" } }),
        )
    };
    let token = mint(&mut core, &mut id);
    let mut broken = send_tx();
    broken["to"] = json!("0x12");
    refused(
        &sign(&mut core, &mut id, broken, &token),
        "invalid_argument",
        None,
    );
    refused(
        &sign(&mut core, &mut id, send_tx(), &token),
        "not_authorized",
        Some("unknown_token"),
    );
    // Discarded.
    let token = mint(&mut core, &mut id);
    assert!(
        result(&call_as(
            &mut core,
            &mut id,
            &chrome(),
            "approval.discard",
            json!({ "token": token })
        ))
        .is_object()
    );
    refused(
        &sign(&mut core, &mut id, send_tx(), &token),
        "not_authorized",
        Some("unknown_token"),
    );
    // A discard with another member, and a page's without its
    // PageContext: refused, and the token burnt all the same.
    for (params, context) in [
        (json!({ "extra": 1 }), shell()),
        (json!({}), json!({ "caller": "page" })),
    ] {
        let token = mint(&mut core, &mut id);
        let mut params = params;
        params["token"] = json!(token);
        refused(
            &call_as(&mut core, &mut id, &context, "approval.discard", params),
            "invalid_argument",
            None,
        );
        refused(
            &sign(&mut core, &mut id, send_tx(), &token),
            "not_authorized",
            Some("unknown_token"),
        );
    }
    // A page's end needs its PageContext too.
    refused(
        &call_as(
            &mut core,
            &mut id,
            &json!({ "caller": "page" }),
            "approval.end",
            json!({ "safe": "00".repeat(16) }),
        ),
        "invalid_argument",
        None,
    );
    // Under chrome, though shell minted it.
    let token = mint(&mut core, &mut id);
    let reply = call_as(
        &mut core,
        &mut id,
        &chrome(),
        "sign.transaction",
        json!({ "key": account(0), "tx": send_tx(), "authorization": { "token": token, "kind": "wallet-send" } }),
    );
    refused(&reply, "not_authorized", Some("mismatch"));
    // Another nonce is the same send; another value isn't.
    let token = mint(&mut core, &mut id);
    let mut other = send_tx();
    other["value"] = json!("1001");
    refused(
        &sign(&mut core, &mut id, other, &token),
        "not_authorized",
        Some("mismatch"),
    );
    let token = mint(&mut core, &mut id);
    let mut renonced = send_tx();
    renonced["nonce"] = json!("4");
    assert!(result(&sign(&mut core, &mut id, renonced, &token))["raw"].is_string());
    // Locked: checked before the key, and burnt.
    let token = mint(&mut core, &mut id);
    assert!(
        result(&call_as(
            &mut core,
            &mut id,
            &chrome(),
            "vault.lock",
            json!({})
        ))
        .is_object()
    );
    refused(
        &sign(&mut core, &mut id, send_tx(), &token),
        "vault_locked",
        None,
    );
    refused(
        &sign(&mut core, &mut id, send_tx(), &token),
        "not_authorized",
        Some("unknown_token"),
    );
}

/// `sign.transaction`'s token names the kind it was minted as (design 0012,
/// API): presented as another kind, as a kind `sign.transaction` doesn't
/// spend, or naming none, it is refused (`mismatch`) and burnt, under the
/// caller that minted it; named as itself, it signs, once.
#[test]
fn a_transaction_token_signs_only_as_its_kind() {
    let (_root, mut core) = unlocked();
    let mut id = 10;
    let mint = |core: &mut Core, id: &mut u64, kind: &str| {
        let (context, params) = match kind {
            "dapp-send" => (
                site(),
                json!({ "kind": kind, "account": 0, "payload": { "tx": send_tx() }, "handle": HANDLE }),
            ),
            _ => (
                shell(),
                json!({ "kind": kind, "account": 0, "payload": { "tx": send_tx() } }),
            ),
        };
        token_of(&issue(core, id, &context, params))
    };
    // Under the caller that minted the token, with the handle for a page's.
    let sign = |core: &mut Core, id: &mut u64, minted: &str, token: &str, kind: Option<&str>| {
        let (context, mut authorization) = match minted {
            "dapp-send" => (site(), json!({ "token": token, "handle": HANDLE })),
            _ => (shell(), json!({ "token": token })),
        };
        if let Some(kind) = kind {
            authorization["kind"] = json!(kind);
        }
        call_as(
            core,
            id,
            &context,
            "sign.transaction",
            json!({ "key": account(0), "tx": send_tx(), "authorization": authorization }),
        )
    };
    let kinds = ["wallet-send", "executor-send", "dapp-send"];
    for minted in kinds {
        let others = kinds
            .into_iter()
            .filter(|kind| *kind != minted)
            .map(Some)
            .chain([Some("intent-replace"), Some("sign-message"), None]);
        for named in others {
            let token = mint(&mut core, &mut id, minted);
            let reply = sign(&mut core, &mut id, minted, &token, named);
            refused(&reply, "not_authorized", Some("mismatch"));
            assert!(reply.get("result").is_none(), "{minted} as {named:?}");
            // Burnt: not even its own kind spends it now.
            refused(
                &sign(&mut core, &mut id, minted, &token, Some(minted)),
                "not_authorized",
                Some("unknown_token"),
            );
        }
        let token = mint(&mut core, &mut id, minted);
        let signed = sign(&mut core, &mut id, minted, &token, Some(minted));
        assert!(result(&signed)["raw"].is_string(), "{minted}: {signed}");
        refused(
            &sign(&mut core, &mut id, minted, &token, Some(minted)),
            "not_authorized",
            Some("unknown_token"),
        );
    }
    // A wallet kind named under a page, and a page's under shell: the
    // token's caller decides, whatever it names.
    let token = mint(&mut core, &mut id, "wallet-send");
    let reply = call_as(
        &mut core,
        &mut id,
        &site(),
        "sign.transaction",
        json!({ "key": account(0), "tx": send_tx(),
            "authorization": { "token": token, "kind": "wallet-send", "handle": HANDLE } }),
    );
    refused(&reply, "not_authorized", Some("mismatch"));
    refused(
        &sign(
            &mut core,
            &mut id,
            "wallet-send",
            &token,
            Some("wallet-send"),
        ),
        "not_authorized",
        Some("unknown_token"),
    );
    let token = mint(&mut core, &mut id, "dapp-send");
    let reply = call_as(
        &mut core,
        &mut id,
        &shell(),
        "sign.transaction",
        json!({ "key": account(0), "tx": send_tx(),
            "authorization": { "token": token, "kind": "dapp-send" } }),
    );
    refused(&reply, "not_authorized", Some("mismatch"));
    refused(
        &sign(&mut core, &mut id, "dapp-send", &token, Some("dapp-send")),
        "not_authorized",
        Some("unknown_token"),
    );
    // A kind that isn't a kind's name, a kind beside an intent, and a kind
    // on a method that spends one kind alone: malformed, and burnt all the
    // same.
    for kind in [
        json!("Wallet-Send"),
        json!("x402-cap-update"),
        json!(""),
        json!(1),
        json!(null),
    ] {
        let token = mint(&mut core, &mut id, "wallet-send");
        let reply = call_as(
            &mut core,
            &mut id,
            &shell(),
            "sign.transaction",
            json!({ "key": account(0), "tx": send_tx(),
                "authorization": { "token": token, "kind": kind } }),
        );
        refused(&reply, "invalid_argument", None);
        refused(
            &sign(
                &mut core,
                &mut id,
                "wallet-send",
                &token,
                Some("wallet-send"),
            ),
            "not_authorized",
            Some("unknown_token"),
        );
    }
    let token = mint(&mut core, &mut id, "wallet-send");
    let reply = call_as(
        &mut core,
        &mut id,
        &shell(),
        "sign.transaction",
        json!({ "key": account(0), "tx": send_tx(),
            "authorization": { "token": token, "kind": "wallet-send", "intent": { "id": "intent-0001" } } }),
    );
    refused(&reply, "invalid_argument", None);
    refused(
        &sign(
            &mut core,
            &mut id,
            "wallet-send",
            &token,
            Some("wallet-send"),
        ),
        "not_authorized",
        Some("unknown_token"),
    );
    let params = json!({ "kind": "sign-message", "account": 0, "payload": { "message": "0x68656c6c6f" }, "handle": HANDLE });
    let token = token_of(&issue(&mut core, &mut id, &site(), params));
    let message = |token: &str, kind: Option<&str>| {
        let mut authorization = json!({ "token": token, "handle": HANDLE });
        if let Some(kind) = kind {
            authorization["kind"] = json!(kind);
        }
        json!({ "key": account(0), "message": "0x68656c6c6f", "authorization": authorization })
    };
    refused(
        &call_as(
            &mut core,
            &mut id,
            &site(),
            "sign.message",
            message(&token, Some("sign-message")),
        ),
        "invalid_argument",
        None,
    );
    refused(
        &call_as(
            &mut core,
            &mut id,
            &site(),
            "sign.message",
            message(&token, None),
        ),
        "not_authorized",
        Some("unknown_token"),
    );
}

/// A page request the Agent answers, in a tab it holds, is a page request
/// (design 0012, "Enforced or advised (Q8)"): the Agent's decision mints the
/// request's page-kind token, which signs under `page` with the live
/// `PageContext` and `agent: true`, and nowhere else; no standing rule
/// answers it.
#[test]
fn an_agent_answered_page_request_signs_under_page() {
    let (_root, mut core) = unlocked();
    let mut id = 10;
    let mut agent = site();
    agent["page"]["agent"] = json!(true);
    let send = json!({ "kind": "dapp-send", "account": 0, "payload": { "tx": send_tx() }, "handle": HANDLE });
    let sign_send = |core: &mut Core, id: &mut u64, context: &Value, authorization: Value| {
        call_as(
            core,
            id,
            context,
            "sign.transaction",
            json!({ "key": account(0), "tx": send_tx(), "authorization": authorization }),
        )
    };
    // Under shell, and as a wallet's send: refused, and burnt.
    let token = token_of(&issue(&mut core, &mut id, &agent, send.clone()));
    refused(
        &sign_send(
            &mut core,
            &mut id,
            &shell(),
            json!({ "token": token, "kind": "dapp-send" }),
        ),
        "not_authorized",
        Some("mismatch"),
    );
    let token = token_of(&issue(&mut core, &mut id, &agent, send.clone()));
    refused(
        &sign_send(
            &mut core,
            &mut id,
            &shell(),
            json!({ "token": token, "kind": "wallet-send" }),
        ),
        "not_authorized",
        Some("mismatch"),
    );
    // Under page, with its PageContext and `agent: true`: signs.
    let token = token_of(&issue(&mut core, &mut id, &agent, send));
    let signed = sign_send(
        &mut core,
        &mut id,
        &agent,
        json!({ "token": token, "kind": "dapp-send", "handle": HANDLE }),
    );
    assert!(result(&signed)["raw"].is_string(), "{signed}");
    let params = json!({ "kind": "sign-message", "account": 0, "payload": { "message": "0x68656c6c6f" }, "handle": HANDLE });
    let token = token_of(&issue(&mut core, &mut id, &agent, params));
    let signed = call_as(
        &mut core,
        &mut id,
        &agent,
        "sign.message",
        json!({ "key": account(0), "message": "0x68656c6c6f",
            "authorization": { "token": token, "handle": HANDLE } }),
    );
    assert!(result(&signed)["signature"].is_string(), "{signed}");
    // A standing rule answers no tab the Agent holds.
    let standing = json!({ "key": account(0), "message": "0x68656c6c6f",
        "authorization": { "standing": { "paused": false } } });
    refused(
        &call_as(&mut core, &mut id, &agent, "sign.message", standing),
        "not_authorized",
        Some("custody"),
    );
}

/// A page's typed data: the token binds the core's hash and view, which
/// `approval.issue` returns, and `sign.typed_data` signs that hash.
#[test]
fn a_typed_data_token_signs_its_hash() {
    let (_root, mut core) = unlocked();
    let mut id = 10;
    let params = json!({ "kind": "sign-typed-data", "account": 0, "payload": { "typed_data": mail() }, "handle": HANDLE });
    let minted = issue(&mut core, &mut id, &site(), params.clone());
    let expected = hash(&mut core, &mut id, &mail());
    assert_eq!(result(&minted)["hash"], expected.as_str());
    assert!(result(&minted)["view"].is_object());
    let sign = |core: &mut Core, id: &mut u64, typed: Value, token: &str| {
        call_as(
            core,
            id,
            &site(),
            "sign.typed_data",
            json!({ "key": account(0), "typed_data": typed, "expected_hash": expected,
                "authorization": { "token": token, "handle": HANDLE } }),
        )
    };
    let signed = sign(&mut core, &mut id, mail(), &token_of(&minted));
    assert!(result(&signed)["signature"].is_string());
    // An undeclared member: the same hash, another request.
    let mut undeclared = mail();
    undeclared["message"]["extra"] = json!(1);
    let token = token_of(&issue(&mut core, &mut id, &site(), params));
    refused(
        &sign(&mut core, &mut id, undeclared, &token),
        "not_authorized",
        Some("mismatch"),
    );
}

/// A Safe approval from a wallet `safe-send`: used only under `shell`; the
/// first owner fixes the SafeTx; the executor within the fee check; ended
/// by `approval.end`, which answers `{}` again.
#[test]
fn a_wallet_safe_approval_covers_its_owners_and_executor() {
    let (_root, mut core) = unlocked();
    let mut id = 10;
    let params = json!({ "kind": "safe-send", "account": 0, "payload": safe_send(SAFE) });
    let token = token_of(&issue(&mut core, &mut id, &shell(), params.clone()));
    let mut spend = params.clone();
    spend["token"] = json!(token);
    // Spent only by the caller kind that minted it.
    refused(
        &call_as(&mut core, &mut id, &chrome(), "approval.spend", spend),
        "not_authorized",
        Some("mismatch"),
    );
    let token = token_of(&issue(&mut core, &mut id, &shell(), params.clone()));
    let mut spend = params.clone();
    spend["token"] = json!(token);
    let spent = call_as(
        &mut core,
        &mut id,
        &shell(),
        "approval.spend",
        spend.clone(),
    );
    assert_eq!(result(&spent)["bound"], true);
    let safe = result(&spent)["safe"].as_str().unwrap().to_owned();
    assert_eq!(safe.len(), 32);
    refused(
        &call_as(&mut core, &mut id, &shell(), "approval.spend", spend),
        "not_authorized",
        Some("unknown_token"),
    );

    let owner = |core: &mut Core, id: &mut u64, context: &Value, typed: Value, safe: &str| {
        let expected = hash(core, id, &typed);
        call_as(
            core,
            id,
            context,
            "sign.typed_data",
            json!({ "key": account(0), "typed_data": typed, "expected_hash": expected, "authorization": { "safe": safe } }),
        )
    };
    // Under chrome and under page; another Safe.
    refused(
        &owner(&mut core, &mut id, &chrome(), safe_tx(SAFE, 5), &safe),
        "not_authorized",
        Some("mismatch"),
    );
    refused(
        &owner(&mut core, &mut id, &site(), safe_tx(SAFE, 5), &safe),
        "not_authorized",
        Some("mismatch"),
    );
    refused(
        &owner(&mut core, &mut id, &shell(), safe_tx(OTHER_SAFE, 5), &safe),
        "not_authorized",
        Some("mismatch"),
    );
    let first = owner(&mut core, &mut id, &shell(), safe_tx(SAFE, 5), &safe);
    assert!(result(&first)["signature"].is_string());
    // The second owner signs the same SafeTx, and no other.
    let expected = hash(&mut core, &mut id, &safe_tx(SAFE, 5));
    let second = call_as(
        &mut core,
        &mut id,
        &shell(),
        "sign.typed_data",
        json!({ "key": account(1), "typed_data": safe_tx(SAFE, 5),
            "expected_hash": expected, "authorization": { "safe": safe } }),
    );
    assert!(result(&second)["signature"].is_string());
    refused(
        &owner(&mut core, &mut id, &shell(), safe_tx(SAFE, 6), &safe),
        "not_authorized",
        Some("mismatch"),
    );
    // The executor: never as a message; without a fee reference, the fee
    // needs the user's `executor-send` token.
    let message =
        json!({ "key": account(0), "message": "0x01", "authorization": { "safe": safe } });
    refused(
        &call_as(&mut core, &mut id, &shell(), "sign.message", message),
        "not_authorized",
        Some("mismatch"),
    );
    let execute = |core: &mut Core, id: &mut u64, context: &Value, tx: Value, safe: &str| {
        call_as(
            core,
            id,
            context,
            "sign.transaction",
            json!({ "key": account(2), "tx": tx, "authorization": { "safe": safe } }),
        )
    };
    refused(
        &execute(&mut core, &mut id, &shell(), executor_tx(OTHER_SAFE), &safe),
        "not_authorized",
        Some("mismatch"),
    );
    refused(
        &execute(&mut core, &mut id, &chrome(), executor_tx(SAFE), &safe),
        "not_authorized",
        Some("mismatch"),
    );
    refused(
        &execute(&mut core, &mut id, &shell(), executor_tx(SAFE), &safe),
        "not_authorized",
        Some("fee_check"),
    );
    // Ended: refused, and a second end, and an unknown id, answer `{}`.
    for _ in 0..2 {
        let ended = call_as(
            &mut core,
            &mut id,
            &shell(),
            "approval.end",
            json!({ "safe": safe }),
        );
        assert_eq!(*result(&ended), json!({}));
    }
    let unknown = call_as(
        &mut core,
        &mut id,
        &page("https://x.example", 1, 1),
        "approval.end",
        json!({ "safe": "nope" }),
    );
    assert_eq!(*result(&unknown), json!({}));
    refused(
        &owner(&mut core, &mut id, &shell(), safe_tx(SAFE, 5), &safe),
        "not_authorized",
        Some("unknown_token"),
    );
    refused(
        &execute(&mut core, &mut id, &shell(), executor_tx(SAFE), &safe),
        "not_authorized",
        Some("unknown_token"),
    );
}

/// A site's Safe approvals: for its own document only, a newer `safe-send`
/// for the Safe ends the older one, and a Safe message signs its digest.
#[test]
fn a_site_safe_approval_is_its_documents() {
    let (_root, mut core) = unlocked();
    let mut id = 10;
    let params =
        json!({ "kind": "safe-send", "account": 0, "payload": safe_send(SAFE), "handle": HANDLE });
    let spend_as = |core: &mut Core, id: &mut u64, context: &Value, params: &Value| {
        let token = token_of(&issue(core, id, &site(), params.clone()));
        let mut spend = params.clone();
        spend["token"] = json!(token);
        call_as(core, id, context, "approval.spend", spend)
    };
    // A site's token through approval.spend: another origin, frame or
    // navigation is refused.
    for other in [
        page("https://other.example", 1, 1),
        page("https://app.example", 2, 1),
        page("https://app.example", 1, 2),
        chrome(),
    ] {
        refused(
            &spend_as(&mut core, &mut id, &other, &params),
            "not_authorized",
            Some("mismatch"),
        );
    }
    let older = spend_as(&mut core, &mut id, &site(), &params);
    let older = result(&older)["safe"].as_str().unwrap().to_owned();
    let newer = spend_as(&mut core, &mut id, &site(), &params);
    let newer = result(&newer)["safe"].as_str().unwrap().to_owned();
    let owner = |core: &mut Core, id: &mut u64, context: &Value, typed: Value, safe: &str| {
        let expected = hash(core, id, &typed);
        call_as(
            core,
            id,
            context,
            "sign.typed_data",
            json!({ "key": account(0), "typed_data": typed, "expected_hash": expected, "authorization": { "safe": safe } }),
        )
    };
    refused(
        &owner(&mut core, &mut id, &site(), safe_tx(SAFE, 1), &older),
        "not_authorized",
        Some("unknown_token"),
    );
    for other in [
        page("https://app.example", 1, 2),
        page("https://app.example", 2, 1),
        shell(),
    ] {
        refused(
            &owner(&mut core, &mut id, &other, safe_tx(SAFE, 1), &newer),
            "not_authorized",
            Some("mismatch"),
        );
    }
    assert!(
        result(&owner(
            &mut core,
            &mut id,
            &site(),
            safe_tx(SAFE, 1),
            &newer
        ))["signature"]
            .is_string()
    );

    // A Safe message: its digest is EIP-191's of `hello`, for the Safe and
    // chain main read from the Safe's record. Without them, no token.
    let mut message = json!({ "kind": "safe-message", "account": 0, "handle": HANDLE,
        "payload": { "method": "personal_sign", "params": ["0x68656c6c6f", SAFE] } });
    refused(
        &issue(&mut core, &mut id, &site(), message.clone()),
        "invalid_argument",
        None,
    );
    message["payload"]["safe"] = json!(SAFE);
    message["payload"]["chain_id"] = json!("100");
    let spent = spend_as(&mut core, &mut id, &site(), &message);
    let safe = result(&spent)["safe"].as_str().unwrap().to_owned();
    let digest = "0x50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750";
    let other = "0x".to_owned() + &"00".repeat(32);
    // Another digest; and the approved digest for Safe B, on another
    // chain, or both: refused at the first owner's signature and at a
    // later one.
    let elsewhere = [
        safe_message(SAFE, &other),
        safe_message(OTHER_SAFE, digest),
        safe_message_on(SAFE, "1", digest),
        safe_message_on(OTHER_SAFE, "1", digest),
    ];
    for typed in &elsewhere {
        refused(
            &owner(&mut core, &mut id, &site(), typed.clone(), &safe),
            "not_authorized",
            Some("mismatch"),
        );
    }
    assert!(
        result(&owner(
            &mut core,
            &mut id,
            &site(),
            safe_message(SAFE, digest),
            &safe
        ))["signature"]
            .is_string()
    );
    for typed in &elsewhere {
        refused(
            &owner(&mut core, &mut id, &site(), typed.clone(), &safe),
            "not_authorized",
            Some("mismatch"),
        );
    }
    let later = owner(
        &mut core,
        &mut id,
        &site(),
        safe_message(SAFE, digest),
        &safe,
    );
    assert!(result(&later)["signature"].is_string());
    // A Safe message a standing rule answers: with no file, none does.
    let standing = json!({ "standing": {}, "kind": "safe-message", "account": 0,
        "payload": { "safe": SAFE, "chain_id": "100", "method": "personal_sign", "params": ["0x01"] } });
    refused(
        &call_as(
            &mut core,
            &mut id,
            &site(),
            "approval.spend",
            standing.clone(),
        ),
        "not_authorized",
        Some("no_rule"),
    );
    refused(
        &call_as(&mut core, &mut id, &shell(), "approval.spend", standing),
        "forbidden",
        None,
    );
}

fn sized(count: usize, len: usize) -> Value {
    json!({
        "domain": {},
        "types": { "M": [{ "name": "v", "type": "uint8[]" }, { "name": "s", "type": "string" }] },
        "message": { "v": vec![0; count], "s": "x".repeat(len) },
    })
}

/// `approval.issue`'s reply is longer than `sign.typed_data`'s: a token
/// binds only a view whose reply fits one frame at the largest ID, so the
/// longest view `sign.typed_data` takes gets none, and the core stays up.
#[test]
fn a_typed_data_token_fits_its_reply() {
    const MAX_ID: u64 = (1 << 53) - 1;
    const FRAME: usize = 1 << 20;
    let (_root, mut core) = unlocked();
    let mut id = 10;
    let signing = format!(
        r#"{{"type":"response","id":{MAX_ID},"result":{{"signature":"0x{}","view":}}}}"#,
        "00".repeat(65)
    )
    .len();
    let issuing = format!(
        r#"{{"type":"response","id":{MAX_ID},"result":{{"expires_in_ms":120000,"hash":"0x{}","view":,"token":"{}"}}}}"#,
        "00".repeat(32),
        "0".repeat(64)
    )
    .len();
    let view_len = |reply: &Value| {
        serde_json::to_string(&reply["result"]["view"])
            .unwrap()
            .len()
    };
    let probe = call_as(
        &mut core,
        &mut id,
        &chrome(),
        "typed_data.hash",
        json!({ "typed_data": sized(90_000, 0) }),
    );
    let longest = FRAME - signing - view_len(&probe);
    let issue_sized = |core: &mut Core, id: &mut u64, len: usize| {
        let params = json!({ "kind": "sign-typed-data", "account": 0, "handle": HANDLE,
            "payload": { "typed_data": sized(90_000, len) } });
        issue(core, id, &site(), params)
    };
    let refused_reply = issue_sized(&mut core, &mut id, longest);
    refused(&refused_reply, "invalid_argument", None);
    let fits = longest - (issuing - signing);
    let minted = issue_sized(&mut core, &mut id, fits);
    assert_eq!(view_len(&minted), FRAME - issuing);
    assert_eq!(token_of(&minted).len(), 64);
    refused(
        &issue_sized(&mut core, &mut id, fits + 1),
        "invalid_argument",
        None,
    );
}
