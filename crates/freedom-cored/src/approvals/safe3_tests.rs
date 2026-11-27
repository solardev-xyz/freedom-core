//! SAFE-3's field in the approvals (design 0016, C1): with `safe3` set,
//! `approval.issue` refuses `executor-send` and APR-4's `safe-send`,
//! `approval.spend` refuses APR-4's `safe-send` and burns it, and
//! `sign.transaction` under `shell` signs a transaction to the pinned
//! Safe proxy factory only with its `executor-send` token. Without the
//! field each is as before.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

const CLOCKS: Clocks = Clocks {
    vault_ms: 10_000,
    wall_ms: 1_700_000_000_000,
};
const SAFE: &str = "0x4444444444444444444444444444444444444444";
const TO: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const HANDLE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

fn reply(payload: &[u8]) -> Value {
    serde_json::from_slice(payload).unwrap()
}

fn shell() -> Context {
    Context::shell()
}

fn site() -> PageContext {
    serde_json::from_value(json!({
        "origin": "https://app.example", "top_origin": "https://app.example",
        "frame": 1, "navigation": 1, "agent": false,
    }))
    .unwrap()
}

fn page() -> Context {
    Context {
        caller: CallerKind::Page,
        page: Some(site()),
    }
}

fn reason(error: &ErrorBody) -> String {
    assert_eq!(error.code, ErrorCode::NotAuthorized, "{error:?}");
    error.data.as_ref().unwrap()["reason"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// APR-4's `safe-send` payload.
fn legacy() -> Value {
    json!({ "safe": SAFE, "chain_id": "100", "tx": { "to": TO, "value": "1", "data": "0x" } })
}

/// Design 0016's `safe-send` payload (D6), for a SafeTx at nonce 3.
fn built() -> Value {
    let safe = fc_evm::parse_address(SAFE).unwrap();
    let tx = fc_safe::SafeTx::new(
        fc_evm::parse_address(TO).unwrap(),
        U256::from_u64(1),
        vec![],
        3,
    )
    .unwrap();
    json!({
        "safe": SAFE, "chain_id": "100", "safe_tx": tx.fields(),
        "safe_tx_hash": fc_evm::to_hex(&tx.hash(&safe).unwrap()),
    })
}

fn wallet_send(to: &str, data: &str) -> Value {
    json!({ "tx": {
        "type": 2, "chain_id": "100", "gas_limit": "240000", "to": to, "value": "0",
        "data": data, "max_fee_per_gas": "7000000000", "max_priority_fee_per_gas": "1000000000",
    } })
}

/// A Safe's deployment, as `safe.deploy` prepares it: `createProxyWithNonce`
/// to the pinned factory.
fn deployment() -> Value {
    let setup = fc_safe::Setup::new(
        vec![
            fc_evm::parse_address("0x1111111111111111111111111111111111111111").unwrap(),
            fc_evm::parse_address("0x2222222222222222222222222222222222222222").unwrap(),
        ],
        1,
    )
    .unwrap();
    let deployment = setup.deployment(&U256::from_u64(7));
    wallet_send(
        &fc_evm::to_hex(&deployment.to),
        &fc_evm::to_hex(&deployment.data),
    )
}

fn issue(approvals: &mut Approvals, kind: &str, payload: &Value) -> Result<String, ErrorBody> {
    let params = json!({ "kind": kind, "account": 0, "payload": payload, "fee_ack": true });
    approvals
        .request(1, "approval.issue", &params, &shell(), CLOCKS)
        .map(|issued| {
            reply(&issued)["result"]["token"]
                .as_str()
                .unwrap()
                .to_owned()
        })
}

fn spend(
    approvals: &mut Approvals,
    context: &Context,
    token: &str,
    payload: &Value,
    handle: Option<&str>,
) -> Result<Value, ErrorBody> {
    let mut params =
        json!({ "token": token, "kind": "safe-send", "account": 0, "payload": payload });
    if let Some(handle) = handle {
        params["handle"] = json!(handle);
    }
    approvals
        .request(2, "approval.spend", &params, context, CLOCKS)
        .map(|spent| reply(&spent))
}

/// `approval.issue` under SAFE-3's field mints no `executor-send` (the core
/// mints it with the send it prepared) and no `safe-send` of APR-4's form,
/// and nothing is left outstanding; design 0016's form still mints. Without
/// the field both mint, as before.
#[test]
fn issue_refuses_executor_send_and_the_legacy_safe_send_under_the_field() {
    let mut approvals = Approvals::new();
    assert!(issue(&mut approvals, "executor-send", &wallet_send(TO, "0x")).is_ok());
    assert!(issue(&mut approvals, "safe-send", &legacy()).is_ok());
    assert!(issue(&mut approvals, "safe-send", &built()).is_ok());
    let outstanding = approvals.tokens.outstanding();
    approvals.set_safe3(true);
    for (kind, payload) in [
        ("executor-send", wallet_send(TO, "0x")),
        ("executor-send", deployment()),
        ("safe-send", legacy()),
    ] {
        let refused = issue(&mut approvals, kind, &payload).unwrap_err();
        assert_eq!(refused.code, ErrorCode::Forbidden, "{kind}");
        assert!(refused.message.contains("SAFE-3"), "{refused:?}");
    }
    assert_eq!(approvals.tokens.outstanding(), outstanding);
    assert!(issue(&mut approvals, "safe-send", &built()).is_ok());
    // The wallet's own sends are untouched.
    assert!(issue(&mut approvals, "wallet-send", &wallet_send(TO, "0x")).is_ok());
}

/// `approval.spend` under SAFE-3's field gives no Safe approval for APR-4's
/// `safe-send`, minted before the field by main or for a page: refused
/// `mismatch`, and the token burnt. Without the field it is spent as
/// before.
#[test]
fn spend_refuses_the_legacy_safe_send_under_the_field() {
    let mut approvals = Approvals::new();
    let before = issue(&mut approvals, "safe-send", &legacy()).unwrap();
    let spent = spend(&mut approvals, &shell(), &before, &legacy(), None).unwrap();
    assert!(spent["result"]["safe"].is_string(), "{spent}");
    let wallet = issue(&mut approvals, "safe-send", &legacy()).unwrap();
    let site_token = approvals
        .page_token(&site(), HANDLE, Kind::SafeSend, 0, &legacy(), CLOCKS)
        .unwrap();
    approvals.set_safe3(true);
    let refused = spend(&mut approvals, &shell(), &wallet, &legacy(), None).unwrap_err();
    assert_eq!(reason(&refused), "mismatch");
    let refused = spend(
        &mut approvals,
        &page(),
        &site_token,
        &legacy(),
        Some(HANDLE),
    )
    .unwrap_err();
    assert_eq!(reason(&refused), "mismatch");
    // Burnt: without the field they are gone too.
    approvals.set_safe3(false);
    let refused = spend(&mut approvals, &shell(), &wallet, &legacy(), None).unwrap_err();
    assert_eq!(reason(&refused), "unknown_token");
    let refused = spend(
        &mut approvals,
        &page(),
        &site_token,
        &legacy(),
        Some(HANDLE),
    )
    .unwrap_err();
    assert_eq!(reason(&refused), "unknown_token");
}

/// `sign.transaction` under `shell` with SAFE-3's field signs a transaction
/// to the pinned factory only with `{ token, kind: "executor-send" }`:
/// main's word, a wallet-send's token, an intent, a Safe approval or a
/// standing rule is refused `no_token` before the authorization is read;
/// the `executor-send` the core minted for the deployment then spends with
/// its binding, and one minted for another transaction is a `mismatch`.
/// Without the field, under another caller, or to another address, nothing
/// changes here.
#[test]
fn a_deployment_under_shell_needs_its_executor_send_token() {
    let mut approvals = Approvals::new();
    let tx_json = {
        let mut tx = deployment()["tx"].clone();
        tx["nonce"] = json!("4");
        tx
    };
    let tx = Transaction::from_json(&tx_json).unwrap();
    let signed = || Signed::Transaction {
        account: 0,
        tx_json: &tx_json,
        tx: &tx,
    };
    let token = json!({ "token": "00".repeat(32), "kind": "executor-send" });
    // Without the field: main's word, as SAFE-2's S4 has it.
    assert!(
        approvals
            .deployment_check(&shell(), None, &signed())
            .is_ok()
    );
    assert!(without_authorization(&shell(), &signed()).is_ok());
    approvals.set_safe3(true);
    for authorization in [
        None,
        Some(json!({ "token": "00".repeat(32), "kind": "wallet-send" })),
        Some(json!({ "token": "00".repeat(32) })),
        Some(json!({ "token": "00".repeat(32), "kind": "executor-send", "intent": { "id": "x" } })),
        Some(json!({ "safe": "00".repeat(16) })),
        Some(json!({ "standing": {} })),
        Some(json!("executor-send")),
    ] {
        let refused = approvals
            .deployment_check(&shell(), authorization.as_ref(), &signed())
            .unwrap_err();
        assert_eq!(reason(&refused), "no_token", "{authorization:?}");
        assert!(
            refused.message.contains("createProxyWithNonce"),
            "{refused:?}"
        );
    }
    assert!(
        approvals
            .deployment_check(&shell(), Some(&token), &signed())
            .is_ok()
    );
    // Any call to the factory, not only the deployment.
    let other_json = {
        let mut tx = tx_json.clone();
        tx["data"] = json!("0x53e5d935");
        tx
    };
    let other = Transaction::from_json(&other_json).unwrap();
    let refused = approvals
        .deployment_check(
            &shell(),
            None,
            &Signed::Transaction {
                account: 0,
                tx_json: &other_json,
                tx: &other,
            },
        )
        .unwrap_err();
    assert_eq!(reason(&refused), "no_token");
    // The chrome's and a page's need their own tokens anyway; another
    // address under `shell` is main's word.
    let chrome = Context {
        caller: CallerKind::Chrome,
        page: None,
    };
    assert!(approvals.deployment_check(&chrome, None, &signed()).is_ok());
    assert!(approvals.deployment_check(&page(), None, &signed()).is_ok());
    let plain_json = {
        let mut tx = tx_json.clone();
        tx["to"] = json!(TO);
        tx
    };
    let plain = Transaction::from_json(&plain_json).unwrap();
    let plain_signed = Signed::Transaction {
        account: 0,
        tx_json: &plain_json,
        tx: &plain,
    };
    assert!(
        approvals
            .deployment_check(&shell(), None, &plain_signed)
            .is_ok()
    );
    // The core's own token for the deployment spends once, with its
    // binding: one for another send is a mismatch.
    let minted = approvals
        .executor_token(0, &deployment()["tx"], CLOCKS)
        .unwrap();
    let authorization = json!({ "token": minted.as_str(), "kind": "executor-send" });
    assert!(
        approvals
            .deployment_check(&shell(), Some(&authorization), &signed())
            .is_ok()
    );
    assert!(
        approvals
            .authorize(&shell(), &authorization, signed(), CLOCKS)
            .is_ok()
    );
    let other_token = approvals
        .executor_token(0, &wallet_send(TO, "0x")["tx"], CLOCKS)
        .unwrap();
    let authorization = json!({ "token": other_token.as_str(), "kind": "executor-send" });
    let refused = approvals
        .authorize(&shell(), &authorization, signed(), CLOCKS)
        .unwrap_err();
    assert_eq!(reason(&refused), "mismatch");
}
