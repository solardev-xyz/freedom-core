//! Design 0012's Q8 through the real binary (APR-4a): a page's vault
//! signature needs an authorization the core checks itself, a page-kind
//! token for its document and its request or a standing rule within Q9's
//! limits; the chrome's needs a wallet-kind token; anything else is refused
//! with `not_authorized` before a key is touched. Main's own signature,
//! under `shell`, signs as before.
//!
//! A token's expiry and a standing send over the fee threshold run under
//! injected clocks and fee evidence, in `signing.rs`'s unit tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const HANDLE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SITE: &str = "https://app.example";
const TO: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
/// `approve(…)`: a contract call a transaction rule's selector names.
const APPROVE: &str = "0x095ea7b30000000000000000000000000000000000000000000000000000000000000001";
/// Q9's expiry: a rule answers for 30 days from its `grantedAt`.
const THIRTY_DAYS_MS: u64 = 2_592_000_000;

fn page_as(origin: &str, frame: u64, navigation: u64, agent: Option<bool>) -> Value {
    let mut page = json!({
        "origin": origin, "top_origin": origin, "frame": frame, "navigation": navigation,
    });
    if let Some(agent) = agent {
        page["agent"] = json!(agent);
    }
    json!({ "caller": "page", "page": page })
}

fn site() -> Value {
    page_as(SITE, 1, 1, Some(false))
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

/// One request sent as written: `params` is JSON text, parsed by the core
/// from these bytes.
fn call_text(core: &mut Core, id: &mut u64, context: &Value, method: &str, params: &str) -> Value {
    *id += 1;
    let text = format!(
        r#"{{"type":"request","id":{},"method":"{method}","params":{params},"context":{context}}}"#,
        *id
    );
    core.send_raw(&raw_frame(1, text.as_bytes()));
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

fn account(index: u32) -> Value {
    json!({ "kind": "account", "index": index })
}

fn wall_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A core with `grant_moved`, its grant root holding `dapp` (the dApp
/// file's text) if given, and unlocked.
fn start(root: &Path, moved: &[&'static str], dapp: Option<&str>) -> Core {
    let mut core = spawn("serve", &root.join("identity"), &root.join("locks"), &[]);
    std::fs::create_dir_all(&core.grant_root).unwrap();
    if let Some(dapp) = dapp {
        std::fs::write(core.grant_root.join("dapp-permissions.json"), dapp).unwrap();
    }
    core.grant_moved = moved.to_vec();
    assert_eq!(core.hello()["result"]["protocol"], 2);
    let imported = core.call(
        2,
        "vault.import",
        json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(ABANDON) }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    assert_eq!(core.event()["event"], "vault.unlocked");
    core
}

fn send_tx(value: &str, data: &str) -> Value {
    json!({
        "type": 2, "chain_id": "100", "nonce": "3", "gas_limit": "60000", "to": TO,
        "value": value, "data": data,
        "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000000",
    })
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

/// The three vault signing methods a page asks for.
#[derive(Debug, Clone, Copy)]
enum Method {
    Transaction,
    Message,
    TypedData,
}

impl Method {
    const ALL: [Method; 3] = [Method::Transaction, Method::Message, Method::TypedData];

    fn name(self) -> &'static str {
        match self {
            Method::Transaction => "sign.transaction",
            Method::Message => "sign.message",
            Method::TypedData => "sign.typed_data",
        }
    }

    /// Its page kind, and what the token binds.
    fn mint(self) -> Value {
        let (kind, payload) = match self {
            Method::Transaction => ("dapp-send", json!({ "tx": send_tx("1000", "0x") })),
            Method::Message => ("sign-message", json!({ "message": "0x68656c6c6f" })),
            Method::TypedData => ("sign-typed-data", json!({ "typed_data": mail() })),
        };
        json!({ "kind": kind, "account": 0, "payload": payload, "handle": HANDLE })
    }

    /// The request for account `index`, with `authorization` if given.
    fn params(self, index: u32, authorization: Option<Value>) -> Value {
        let mut params = match self {
            Method::Transaction => json!({ "key": account(index), "tx": send_tx("1000", "0x") }),
            Method::Message => json!({ "key": account(index), "message": "0x68656c6c6f" }),
            Method::TypedData => json!({
                "key": account(index), "typed_data": mail(), "expected_hash": typed_hash(&mail()),
            }),
        };
        if let Some(authorization) = authorization {
            params["authorization"] = authorization;
        }
        params
    }

    /// A page's token as this method presents it: `sign.transaction` names
    /// its kind.
    fn page_token(self, token: &str) -> Value {
        match self {
            Method::Transaction => json!({ "token": token, "kind": "dapp-send", "handle": HANDLE }),
            _ => json!({ "token": token, "handle": HANDLE }),
        }
    }

    /// What was signed: the raw transaction, or the 65-byte signature.
    fn signed(self, reply: &Value) -> String {
        let field = match self {
            Method::Transaction => "raw",
            _ => "signature",
        };
        result(reply)[field].as_str().unwrap().to_owned()
    }
}

fn mint(core: &mut Core, id: &mut u64, method: Method) -> String {
    let reply = call_as(core, id, &site(), "approval.issue", method.mint());
    result(&reply)["token"].as_str().unwrap().to_owned()
}

/// A wallet's send token, as main mints it under `shell`.
fn wallet_token(core: &mut Core, id: &mut u64) -> String {
    let params =
        json!({ "kind": "wallet-send", "account": 0, "payload": { "tx": send_tx("1000", "0x") } });
    let reply = call_as(core, id, &shell(), "approval.issue", params);
    result(&reply)["token"].as_str().unwrap().to_owned()
}

/// Each method under `page`: refused without a token, with another
/// document's (frame, navigation), another site's, another account's, and
/// a wallet's; its own signs once, what main's own signature of the same
/// request is, and again is refused.
#[test]
fn a_page_signature_needs_its_token() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &[], None);
    let mut id = 10;
    for method in Method::ALL {
        let name = method.name();
        let own = call_as(&mut core, &mut id, &shell(), name, method.params(0, None));
        let own = method.signed(&own);
        refused(
            &call_as(&mut core, &mut id, &site(), name, method.params(0, None)),
            "not_authorized",
            Some("no_token"),
        );
        for other in [
            page_as(SITE, 2, 1, Some(false)),
            page_as(SITE, 1, 2, Some(false)),
            page_as("https://other.example", 1, 1, Some(false)),
        ] {
            let token = mint(&mut core, &mut id, method);
            let authorization = Some(method.page_token(&token));
            refused(
                &call_as(
                    &mut core,
                    &mut id,
                    &other,
                    name,
                    method.params(0, authorization.clone()),
                ),
                "not_authorized",
                Some("mismatch"),
            );
            // Burnt by the refusal.
            refused(
                &call_as(
                    &mut core,
                    &mut id,
                    &site(),
                    name,
                    method.params(0, authorization),
                ),
                "not_authorized",
                Some("unknown_token"),
            );
        }
        let token = mint(&mut core, &mut id, method);
        refused(
            &call_as(
                &mut core,
                &mut id,
                &site(),
                name,
                method.params(1, Some(method.page_token(&token))),
            ),
            "not_authorized",
            Some("mismatch"),
        );
        // A wallet's token, main's own, under `page`.
        let token = wallet_token(&mut core, &mut id);
        let authorization = match method {
            Method::Transaction => json!({ "token": token, "kind": "wallet-send" }),
            _ => json!({ "token": token }),
        };
        refused(
            &call_as(
                &mut core,
                &mut id,
                &site(),
                name,
                method.params(0, Some(authorization)),
            ),
            "not_authorized",
            Some("mismatch"),
        );
        // Its own: signs once, as main's own does.
        let token = mint(&mut core, &mut id, method);
        let authorization = Some(method.page_token(&token));
        let signed = call_as(
            &mut core,
            &mut id,
            &site(),
            name,
            method.params(0, authorization.clone()),
        );
        assert_eq!(method.signed(&signed), own, "{name}");
        refused(
            &call_as(
                &mut core,
                &mut id,
                &site(),
                name,
                method.params(0, authorization),
            ),
            "not_authorized",
            Some("unknown_token"),
        );
        // An empty token is none.
        refused(
            &call_as(
                &mut core,
                &mut id,
                &site(),
                name,
                method.params(0, Some(method.page_token(""))),
            ),
            "not_authorized",
            Some("no_token"),
        );
    }
}

/// The authorization is checked before any key is derived: with the vault
/// locked, a page's signature without one, or with a token for another
/// document, and the chrome's without one, are `not_authorized`, where
/// main's own is `vault_locked`. A page's own token, presented while
/// locked, reaches the key, which is locked, and is burnt.
#[test]
fn refused_before_the_key_and_burnt_while_locked() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &[], None);
    let mut id = 10;
    let tokens: Vec<(Method, String, String)> = Method::ALL
        .into_iter()
        .map(|method| {
            let own = mint(&mut core, &mut id, method);
            let other = mint(&mut core, &mut id, method);
            (method, own, other)
        })
        .collect();
    assert!(
        result(&call_as(
            &mut core,
            &mut id,
            &shell(),
            "vault.lock",
            json!({})
        ))
        .is_object()
    );
    for (method, own, other) in &tokens {
        let name = method.name();
        refused(
            &call_as(&mut core, &mut id, &site(), name, method.params(0, None)),
            "not_authorized",
            Some("no_token"),
        );
        refused(
            &call_as(&mut core, &mut id, &chrome(), name, method.params(0, None)),
            "not_authorized",
            Some("no_token"),
        );
        refused(
            &call_as(&mut core, &mut id, &shell(), name, method.params(0, None)),
            "vault_locked",
            None,
        );
        refused(
            &call_as(
                &mut core,
                &mut id,
                &page_as(SITE, 1, 2, Some(false)),
                name,
                method.params(0, Some(method.page_token(other))),
            ),
            "not_authorized",
            Some("mismatch"),
        );
        refused(
            &call_as(
                &mut core,
                &mut id,
                &site(),
                name,
                method.params(0, Some(method.page_token(own))),
            ),
            "vault_locked",
            None,
        );
    }
    let soc = json!({ "key": { "kind": "publisher", "origin_index": 0 },
        "identifier": format!("0x{}", "ab".repeat(32)), "payload": "0x01" });
    refused(
        &call_as(&mut core, &mut id, &chrome(), "swarm.sign_soc", soc.clone()),
        "not_authorized",
        Some("no_token"),
    );
    refused(
        &call_as(&mut core, &mut id, &shell(), "swarm.sign_soc", soc),
        "vault_locked",
        None,
    );
    // Unlocked again: every token presented while locked is gone.
    let unlocked = call_as(
        &mut core,
        &mut id,
        &shell(),
        "vault.unlock",
        json!({ "password_b64": STANDARD.encode("testpass1") }),
    );
    assert!(result(&unlocked).is_object());
    for (method, own, other) in &tokens {
        for token in [own, other] {
            refused(
                &call_as(
                    &mut core,
                    &mut id,
                    &site(),
                    method.name(),
                    method.params(0, Some(method.page_token(token))),
                ),
                "not_authorized",
                Some("unknown_token"),
            );
        }
    }
}

/// The chrome signs nothing without a wallet-kind token, and mints none
/// (APS-3): each method and a SOC are refused without one, with main's
/// wallet-send token (another caller's), with a page's token, with a
/// standing rule and with a Safe approval. Main's own signature, under
/// `shell`, signs without one, as before.
#[test]
fn the_chrome_needs_a_wallet_kind_token() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &[], None);
    let mut id = 10;
    let minted = call_as(
        &mut core,
        &mut id,
        &chrome(),
        "approval.issue",
        json!({ "kind": "wallet-send", "account": 0, "payload": { "tx": send_tx("1000", "0x") } }),
    );
    refused(&minted, "forbidden", None);
    for method in Method::ALL {
        let name = method.name();
        refused(
            &call_as(&mut core, &mut id, &chrome(), name, method.params(0, None)),
            "not_authorized",
            Some("no_token"),
        );
        let token = wallet_token(&mut core, &mut id);
        let wallet = match method {
            Method::Transaction => json!({ "token": token, "kind": "wallet-send" }),
            _ => json!({ "token": token }),
        };
        refused(
            &call_as(
                &mut core,
                &mut id,
                &chrome(),
                name,
                method.params(0, Some(wallet.clone())),
            ),
            "not_authorized",
            Some("mismatch"),
        );
        // Burnt: main can't spend it after the chrome presented it.
        refused(
            &call_as(
                &mut core,
                &mut id,
                &shell(),
                name,
                method.params(0, Some(wallet)),
            ),
            "not_authorized",
            Some("unknown_token"),
        );
        let token = mint(&mut core, &mut id, method);
        let page = match method {
            Method::Transaction => json!({ "token": token, "kind": "dapp-send" }),
            _ => json!({ "token": token }),
        };
        refused(
            &call_as(
                &mut core,
                &mut id,
                &chrome(),
                name,
                method.params(0, Some(page)),
            ),
            "not_authorized",
            Some("mismatch"),
        );
        refused(
            &call_as(
                &mut core,
                &mut id,
                &chrome(),
                name,
                method.params(0, Some(json!({ "standing": { "paused": false } }))),
            ),
            "not_authorized",
            Some("no_rule"),
        );
        let safe = call_as(
            &mut core,
            &mut id,
            &chrome(),
            name,
            method.params(0, Some(json!({ "safe": "00".repeat(16) }))),
        );
        refused(&safe, "not_authorized", None);
        // Main's own: signs without one.
        let own = call_as(&mut core, &mut id, &shell(), name, method.params(0, None));
        assert!(!method.signed(&own).is_empty());
        // A standing rule answers only a page, under `shell` too.
        refused(
            &call_as(
                &mut core,
                &mut id,
                &shell(),
                name,
                method.params(0, Some(json!({ "standing": { "paused": false } }))),
            ),
            "not_authorized",
            Some("no_rule"),
        );
    }
    let soc = json!({ "key": { "kind": "publisher", "origin_index": 0 },
        "identifier": format!("0x{}", "ab".repeat(32)), "payload": "0x01" });
    refused(
        &call_as(&mut core, &mut id, &chrome(), "swarm.sign_soc", soc.clone()),
        "not_authorized",
        Some("no_token"),
    );
    let own = call_as(&mut core, &mut id, &shell(), "swarm.sign_soc", soc);
    assert!(result(&own)["signature"].is_string());
}

fn approvals_vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/approvals.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// APR-1's typed-data text `id`, as the JSON text of its `typed_data`,
/// byte for byte as the vector holds it. (Its object forms are JS's: over
/// the wire every request is a text.)
fn typed_text(vectors: &Value, id: &str) -> String {
    let case = vectors["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == id)
        .unwrap_or_else(|| panic!("{id}"));
    let text = case["core"]["payload_text"].as_str().unwrap();
    text.strip_prefix(r#"{"typed_data":"#)
        .and_then(|text| text.strip_suffix('}'))
        .unwrap_or_else(|| panic!("{id}: {text}"))
        .to_owned()
}

/// `token-typed-parse` over the wire: a token issued for one of APR-1's
/// texts of a request signs `sign.typed_data` sent in any other, each
/// parsed by the core from its own bytes, and every signature, one for
/// each token, is the same 65 bytes. A text whose `types` lists the type
/// names in another order has the same hash and another view, so each
/// token is refused for the other, with nothing signed.
#[test]
fn typed_data_in_other_texts_signs_alike() {
    let root = tempfile::tempdir().unwrap();
    let mut core = start(root.path(), &[], None);
    let mut id = 10;
    let vectors = approvals_vectors();
    let alike: Vec<String> = [
        "sign-typed-data/text",
        "sign-typed-data/text-spacing",
        "sign-typed-data/text-key-order",
        "sign-typed-data/text-escapes",
    ]
    .iter()
    .map(|id| typed_text(&vectors, id))
    .collect();
    let reordered: Vec<String> = ["sign-typed-data/text-type-order"]
        .iter()
        .map(|id| typed_text(&vectors, id))
        .collect();
    // Each text is another text.
    for (i, a) in alike.iter().chain(&reordered).enumerate() {
        for b in alike.iter().chain(&reordered).skip(i + 1) {
            assert_ne!(a, b);
        }
    }
    let mint = |core: &mut Core, id: &mut u64, typed: &str| {
        let params = format!(
            r#"{{"kind":"sign-typed-data","account":0,"handle":"{HANDLE}","payload":{{"typed_data":{typed}}}}}"#
        );
        let reply = call_text(core, id, &site(), "approval.issue", &params);
        let minted = result(&reply);
        (
            minted["token"].as_str().unwrap().to_owned(),
            minted["hash"].as_str().unwrap().to_owned(),
        )
    };
    let sign = |core: &mut Core, id: &mut u64, typed: &str, token: &str, hash: &str| {
        let params = format!(
            r#"{{"key":{{"kind":"account","index":0}},"expected_hash":"{hash}","authorization":{{"token":"{token}","handle":"{HANDLE}"}},"typed_data":{typed}}}"#
        );
        call_text(core, id, &site(), "sign.typed_data", &params)
    };
    let (_, hash) = mint(&mut core, &mut id, &alike[0]);
    let own = call_text(
        &mut core,
        &mut id,
        &shell(),
        "sign.typed_data",
        &format!(
            r#"{{"key":{{"kind":"account","index":0}},"expected_hash":"{hash}","typed_data":{}}}"#,
            alike[0]
        ),
    );
    let signature = result(&own)["signature"].as_str().unwrap().to_owned();
    assert_eq!(signature.len(), 2 + 65 * 2);
    for one in &alike {
        for other in &alike {
            let (token, minted_hash) = mint(&mut core, &mut id, one);
            assert_eq!(minted_hash, hash);
            let signed = sign(&mut core, &mut id, other, &token, &hash);
            assert_eq!(
                result(&signed)["signature"],
                signature.as_str(),
                "{one} / {other}"
            );
        }
    }
    for reordered in &reordered {
        for one in &alike {
            for (a, b) in [(one, reordered), (reordered, one)] {
                let (token, minted_hash) = mint(&mut core, &mut id, a);
                assert_eq!(minted_hash, hash);
                refused(
                    &sign(&mut core, &mut id, b, &token, &hash),
                    "not_authorized",
                    Some("mismatch"),
                );
            }
        }
        // Its own token signs it: the same hash, so the same signature.
        let (token, _) = mint(&mut core, &mut id, reordered);
        let signed = sign(&mut core, &mut id, reordered, &token, &hash);
        assert_eq!(result(&signed)["signature"], signature.as_str());
    }
}

/// A dApp entry for `origin`, connected with account 0 on chain 100, as
/// the file holds it; `auto_approve` its `autoApprove`.
fn dapp_entry(origin: &str, auto_approve: Value) -> Value {
    json!({
        "origin": origin, "connectedAt": 1_762_000_000_000_u64, "lastUsed": 1_762_000_000_000_u64,
        "walletIndex": 0, "chainId": 100, "autoApprove": auto_approve,
    })
}

/// Today's rules, as main writes them: the signing flag, and `approve` to
/// `TO` on chain 100 up to 5 wei.
fn today_rules() -> Value {
    json!({ "signing": true, "transactions": [
        { "to": TO, "selector": "0x095ea7b3", "chainId": 100, "maxValue": "5" },
    ] })
}

fn standing(paused: Option<bool>) -> Value {
    match paused {
        Some(paused) => json!({ "standing": { "paused": paused } }),
        None => json!({ "standing": {} }),
    }
}

fn sign_message(core: &mut Core, id: &mut u64, context: &Value, message: &str) -> Value {
    call_as(
        core,
        id,
        context,
        "sign.message",
        json!({ "key": account(0), "message": message, "authorization": standing(None) }),
    )
}

fn sign_typed(core: &mut Core, id: &mut u64, typed: &Value, chain_id: Option<&str>) -> Value {
    let mut params = json!({ "key": account(0), "typed_data": typed,
        "expected_hash": typed_hash(typed), "authorization": standing(None) });
    if let Some(chain_id) = chain_id {
        params["chain_id"] = json!(chain_id);
    }
    call_as(core, id, &site(), "sign.typed_data", params)
}

fn sign_send(
    core: &mut Core,
    id: &mut u64,
    origin: &str,
    tx: Value,
    paused: Option<bool>,
) -> Value {
    call_as(
        core,
        id,
        &page_as(origin, 1, 1, Some(false)),
        "sign.transaction",
        json!({ "key": account(0), "tx": tx, "authorization": standing(paused) }),
    )
}

/// A standing rule answers a page's signature only where it covers it,
/// here today's rules before the dApp file moves: refused in custody (and
/// with custody unknown), for 32 bytes, for a warned view, while paused (or
/// with no pause sent), for a send the fee check doesn't allow (no fee
/// reference), for a plain transfer and above the rule's value.
#[test]
fn a_standing_rule_answers_only_what_it_covers() {
    let root = tempfile::tempdir().unwrap();
    let file =
        serde_json::to_string_pretty(&json!({ SITE: dapp_entry(SITE, today_rules()) })).unwrap();
    let mut core = start(root.path(), &[], Some(&file));
    let mut id = 10;
    // A message and typed data the rule covers.
    assert!(
        result(&sign_message(&mut core, &mut id, &site(), "0x68656c6c6f"))["signature"].is_string()
    );
    assert!(result(&sign_typed(&mut core, &mut id, &mail(), Some("100")))["signature"].is_string());
    // Custody, and custody not sent.
    for context in [page_as(SITE, 1, 1, Some(true)), page_as(SITE, 1, 1, None)] {
        refused(
            &sign_message(&mut core, &mut id, &context, "0x68656c6c6f"),
            "not_authorized",
            Some("custody"),
        );
    }
    // 32 bytes: what a chunk signature signs (#89).
    refused(
        &sign_message(
            &mut core,
            &mut id,
            &site(),
            &format!("0x{}", "11".repeat(32)),
        ),
        "not_authorized",
        Some("warning"),
    );
    // A warned view: the domain's chain isn't the page's, or there is none.
    refused(
        &sign_typed(&mut core, &mut id, &mail(), Some("1")),
        "not_authorized",
        Some("warning"),
    );
    let mut chainless = mail();
    chainless["domain"]
        .as_object_mut()
        .unwrap()
        .remove("chainId");
    refused(
        &sign_typed(&mut core, &mut id, &chainless, Some("100")),
        "not_authorized",
        Some("warning"),
    );
    // A send the rule names: paused, or no pause sent.
    for paused in [Some(true), None] {
        refused(
            &sign_send(&mut core, &mut id, SITE, send_tx("5", APPROVE), paused),
            "not_authorized",
            Some("paused"),
        );
    }
    // Not paused, with no fee reference served: the fee check stops it.
    refused(
        &sign_send(&mut core, &mut id, SITE, send_tx("5", APPROVE), Some(false)),
        "not_authorized",
        Some("fee_check"),
    );
    // A plain transfer, and a value above the rule's.
    refused(
        &sign_send(&mut core, &mut id, SITE, send_tx("5", "0x"), Some(false)),
        "not_authorized",
        Some("no_rule"),
    );
    refused(
        &sign_send(&mut core, &mut id, SITE, send_tx("6", APPROVE), Some(false)),
        "not_authorized",
        Some("no_rule"),
    );
    // Another site's rule doesn't answer.
    refused(
        &sign_message(
            &mut core,
            &mut id,
            &page_as("https://other.example", 1, 1, Some(false)),
            "0x68656c6c6f",
        ),
        "not_authorized",
        Some("no_rule"),
    );
}

/// Once the dApp file has moved, Q9's limits: a limited rule answers
/// within its 30 days and its `maxValue`, and at most R-6's burst of 5,
/// messages and typed data sharing one bucket; an expired one, and today's
/// unlimited rules alone, answer nothing.
#[test]
fn q9_limits_the_standing_rules() {
    let root = tempfile::tempdir().unwrap();
    let now = wall_ms();
    let live = now - THIRTY_DAYS_MS + 600_000;
    let expired = now - THIRTY_DAYS_MS - 600_000;
    let limited = |granted_at: u64| {
        json!({
            "signing": false, "transactions": [],
            "limited": {
                "signing": { "grantedAt": granted_at },
                "transactions": [
                    { "to": TO, "selector": "0x095ea7b3", "chainId": 100, "maxValue": "3", "grantedAt": granted_at },
                ],
            },
        })
    };
    let old = "https://old.example";
    let gone = "https://expired.example";
    let file = serde_json::to_string_pretty(&json!({
        SITE: dapp_entry(SITE, limited(live)),
        old: dapp_entry(old, today_rules()),
        gone: dapp_entry(gone, limited(expired)),
    }))
    .unwrap();
    let mut core = start(root.path(), &["dapp"], Some(&file));
    let mut id = 10;
    // Today's unlimited rules alone, and an expired limited rule: no rule.
    for origin in [old, gone] {
        let page = page_as(origin, 1, 1, Some(false));
        refused(
            &sign_message(&mut core, &mut id, &page, "0x68656c6c6f"),
            "not_authorized",
            Some("no_rule"),
        );
        refused(
            &sign_send(
                &mut core,
                &mut id,
                origin,
                send_tx("1", APPROVE),
                Some(false),
            ),
            "not_authorized",
            Some("no_rule"),
        );
    }
    // The live rule: a value above its `maxValue` has no rule; one within
    // it is covered, and goes on to the fee check, which stops it without
    // a fee reference.
    refused(
        &sign_send(&mut core, &mut id, SITE, send_tx("4", APPROVE), Some(false)),
        "not_authorized",
        Some("no_rule"),
    );
    refused(
        &sign_send(&mut core, &mut id, SITE, send_tx("3", APPROVE), Some(false)),
        "not_authorized",
        Some("fee_check"),
    );
    // Its rate: five signatures, then the sixth, typed data in the same
    // bucket, is past it.
    for _ in 0..4 {
        assert!(
            result(&sign_message(&mut core, &mut id, &site(), "0x68656c6c6f"))["signature"]
                .is_string()
        );
    }
    assert!(result(&sign_typed(&mut core, &mut id, &mail(), Some("100")))["signature"].is_string());
    refused(
        &sign_typed(&mut core, &mut id, &mail(), Some("100")),
        "not_authorized",
        Some("rate_limited"),
    );
    refused(
        &sign_message(&mut core, &mut id, &site(), "0x68656c6c6f"),
        "not_authorized",
        Some("rate_limited"),
    );
    // The sends' bucket is another: still covered up to the fee check.
    refused(
        &sign_send(&mut core, &mut id, SITE, send_tx("3", APPROVE), Some(false)),
        "not_authorized",
        Some("fee_check"),
    );
    // A page's token still signs past the rule's rate: the user's prompt.
    let minted = call_as(
        &mut core,
        &mut id,
        &site(),
        "approval.issue",
        Method::Message.mint(),
    );
    let token = result(&minted)["token"].as_str().unwrap().to_owned();
    let signed = call_as(
        &mut core,
        &mut id,
        &site(),
        "sign.message",
        Method::Message.params(0, Some(Method::Message.page_token(&token))),
    );
    assert!(result(&signed)["signature"].is_string());
}
