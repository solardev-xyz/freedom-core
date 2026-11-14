//! The Phase 2 signing methods (design 0002): `sign.transaction`,
//! `sign.message`, `sign.typed_data`, `swarm.sign_soc`, and the public
//! `typed_data.hash`.
//!
//! Each does all its public work first (parsing, validation, RLP, BMT,
//! hashing, within fc-evm's limits), then derives the key only to sign one
//! digest (and, for a chunk, take its address), and assembles the result
//! after the key is gone. It runs inline, on the event loop. No secret is
//! held while untrusted input is processed, and no key byte leaves this
//! module.
//!
//! `sign.transaction`, `sign.message` and `sign.typed_data` take an
//! `authorization` (design 0012, API): a token, a Safe approval or a
//! standing rule, checked by [`crate::approvals`] once the public work is
//! done and before the key is derived. A token is burnt however the
//! request ends. A page's signature and the chrome's need one (Q8,
//! APR-4a), and are refused with `not_authorized` without it; main's own,
//! under `shell`, signs as before, but for a Safe's: typed data declaring a
//! `SafeTx` or a `SafeMessage`, or a transaction calling `execTransaction`,
//! signs under any caller only with a token that binds it or a Safe
//! approval of the caller's own kind (APR-4b). `swarm.sign_soc` under
//! `page` needs `{ swarm, soc }`, checked at the same point against the
//! page's Swarm grant (APR-4c); main's own SOC, under `shell`, signs as
//! before, and the chrome's is refused. A `page` caller sends its
//! `PageContext`.
//!
//! Typed data comes with the view of exactly what is signed (#88), which
//! fc-evm writes as JSON text in the pass that hashes; the reply carries it
//! as written. `sign.typed_data` signs only the digest the caller confirmed
//! (`expected_hash`), and both typed-data methods refuse data whose signing
//! reply, at the largest request ID, wouldn't fit one frame.

use std::sync::OnceLock;

use fc_evm::{Transaction, ViewRequest, checksum_address, parse_bytes, to_hex};
use fc_keys::Secp256k1Key;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::message::Context;
use fc_vault::state::VaultState;

use crate::approvals::{After, Approvals, Clocks, Signed};
use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};

pub const METHODS: [&str; 5] = [
    "sign.transaction",
    "sign.message",
    "sign.typed_data",
    "swarm.sign_soc",
    "typed_data.hash",
];

fn invalid(message: impl Into<String>) -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, message.into())
}

fn evm_error(error: fc_evm::Error) -> ErrorBody {
    match error {
        fc_evm::Error::Signing => crate::vault::internal(),
        other => invalid(other.to_string()),
    }
}

/// Which keys a method may use (design 0002, "Key references"): accounts
/// sign transactions, messages and typed data; the Bee wallet and publisher
/// keys sign single-owner chunks, and nothing else does. An account's
/// 32-byte `sign.message` is exactly a chunk signature, so a chunk signature
/// is bound to a real chunk only from a key that signs nothing else (#89).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Allowed {
    AccountsOnly,
    ChunkKeysOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyRef {
    Account(u32),
    BeeWallet,
    Publisher(u32),
}

/// The params object, with exactly the given fields.
fn object<'a>(
    params: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>, ErrorBody> {
    let object = params
        .as_object()
        .ok_or_else(|| invalid("Invalid parameters"))?;
    if let Some(unknown) = object
        .keys()
        .find(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(invalid(format!(
            "unknown field {}",
            fc_evm::shortened(unknown)
        )));
    }
    if let Some(missing) = required.iter().find(|key| !object.contains_key(**key)) {
        return Err(invalid(format!("missing field {missing}")));
    }
    Ok(object)
}

fn index(value: Option<&Value>) -> Result<u32, ErrorBody> {
    value
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n <= 0x7fff_ffff)
        .ok_or_else(|| invalid("Index out of range"))
}

fn key_ref(value: &Value, allowed: Allowed) -> Result<KeyRef, ErrorBody> {
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let key = match kind {
        "account" => {
            object(value, &["kind", "index"], &[])?;
            KeyRef::Account(index(value.get("index"))?)
        }
        "bee_wallet" => {
            object(value, &["kind"], &[])?;
            KeyRef::BeeWallet
        }
        "publisher" => {
            object(value, &["kind", "origin_index"], &[])?;
            KeyRef::Publisher(index(value.get("origin_index"))?)
        }
        _ => return Err(invalid("unknown key kind")),
    };
    match (allowed, key) {
        (Allowed::AccountsOnly, KeyRef::Account(_))
        | (Allowed::ChunkKeysOnly, KeyRef::BeeWallet | KeyRef::Publisher(_)) => Ok(key),
        (Allowed::AccountsOnly, _) => Err(invalid("this key can only sign single-owner chunks")),
        (Allowed::ChunkKeysOnly, _) => Err(invalid("account keys don't sign single-owner chunks")),
    }
}

/// Derives the key now; it wipes on drop.
fn derive(state: &VaultState, key: KeyRef) -> Result<Secp256k1Key, ErrorBody> {
    let derived = match key {
        KeyRef::Account(index) => state.user_wallet(index),
        KeyRef::Publisher(origin) => state.publisher(origin),
        KeyRef::BeeWallet => state.freedom_keys().map(|keys| keys.bee_wallet),
    };
    derived.map_err(crate::vault::locked_or_internal)
}

/// Derives the key, signs the 32-byte digest, and drops (wipes) the key:
/// every public part of a request is done before or after this.
fn sign_with(state: &VaultState, key: KeyRef, digest: &[u8; 32]) -> Result<[u8; 65], ErrorBody> {
    let derived = derive(state, key)?;
    fc_evm::sign_digest(derived.signing_key(), digest).map_err(evm_error)
}

/// `{ domain, types, message }`, exactly.
fn typed_data(value: &Value) -> Result<(&Value, &Value, &Value), ErrorBody> {
    let object = object(value, &["domain", "types", "message"], &[])?;
    Ok((&object["domain"], &object["types"], &object["message"]))
}

/// `sign.typed_data`'s result.
#[derive(Serialize)]
struct SignedView<'a> {
    signature: String,
    view: &'a RawValue,
}

/// `typed_data.hash`'s result.
#[derive(Serialize)]
struct HashedView<'a> {
    hash: String,
    view: &'a RawValue,
}

/// The longest view either typed-data method accepts: the signing response
/// `{"type":"response","id":…,"result":{"signature":…,"view":…}}`, as the
/// core writes it, with the largest ID a request may have (2^53 - 1), must
/// fit one frame (#88, deviation `view-size`). `{ hash, view }` is 71 bytes
/// shorter, so `typed_data.hash` refuses exactly what `sign.typed_data`
/// would, whatever either request's ID.
pub fn max_view_len() -> usize {
    static LIMIT: OnceLock<usize> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        // The envelope around a 1-byte view: everything but the view has a
        // fixed length.
        signing_reply_len(&[0; 65], "0").map_or(0, |len| {
            fc_protocol::frame::MAX_PAYLOAD.saturating_sub(len.saturating_sub(1))
        })
    })
}

/// The length of the signing response at the largest ID, as written.
fn signing_reply_len(signature: &[u8; 65], view: &str) -> Option<usize> {
    let view = RawValue::from_string(view.to_owned()).ok()?;
    let result = SignedView {
        signature: to_hex(signature),
        view: &view,
    };
    let mut out = Vec::new();
    fc_protocol::message::write_result(&mut out, fc_protocol::message::MAX_ID, &result).ok()?;
    Some(out.len())
}

/// The typed-data parameters both methods share: the digest and its view.
fn typed_data_view(fields: &Map<String, Value>) -> Result<fc_evm::TypedDataView, ErrorBody> {
    let (domain, types, message) = typed_data(&fields["typed_data"])?;
    let chain_id = match fields.get("chain_id") {
        None => None,
        Some(Value::String(text)) => Some(
            fc_evm::parse_unsigned(text)
                .ok_or_else(|| invalid("chain_id: expected an unsigned quantity"))?,
        ),
        Some(_) => return Err(invalid("chain_id: expected a quantity string")),
    };
    let request = ViewRequest {
        // Any JSON value, null included: only a string can match.
        primary_type: fields.get("primary_type"),
        chain_id,
        max_len: max_view_len(),
    };
    fc_evm::typed_data_view(domain, types, message, &request).map_err(evm_error)
}

fn view_value(view: String) -> Result<Box<RawValue>, ErrorBody> {
    RawValue::from_string(view).map_err(|_| crate::vault::internal())
}

fn raw(result: &impl Serialize) -> Result<Box<RawValue>, ErrorBody> {
    serde_json::value::to_raw_value(result).map_err(|_| crate::vault::internal())
}

fn string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, ErrorBody> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{field}: expected a string")))
}

/// What a signing method needs beside its params: the approvals it checks
/// an authorization against, the caller, and the clocks.
pub struct Checks<'a> {
    pub approvals: &'a mut Approvals,
    pub context: &'a Context,
    pub clocks: Clocks,
}

/// The methods that take an `authorization`, and a page's `PageContext`.
/// A token presented to any of them is burnt, `swarm.sign_soc`'s included,
/// though no token kind binds a SOC.
const AUTHORIZED: [&str; 4] = [
    "sign.transaction",
    "sign.message",
    "sign.typed_data",
    "swarm.sign_soc",
];

/// An account key's index.
fn account_index(key: KeyRef) -> Result<u32, ErrorBody> {
    match key {
        KeyRef::Account(index) => Ok(index),
        _ => Err(crate::vault::internal()),
    }
}

/// Checks the request's `authorization` for what it signs (design 0012,
/// Q8): a page's and the chrome's signatures need one (APR-4a), and a
/// Safe's under any caller (APR-4b); main's own under `shell` has one
/// checked when it comes.
fn authorize(
    checks: &mut Checks<'_>,
    fields: &Map<String, Value>,
    signed: Signed<'_>,
) -> Result<After, ErrorBody> {
    match fields.get("authorization") {
        None => crate::approvals::without_authorization(checks.context, &signed)
            .map(|()| After::Nothing),
        Some(authorization) => {
            checks
                .approvals
                .authorize(checks.context, authorization, signed, checks.clocks)
        }
    }
}

/// Handles one of [`METHODS`]; returns the JSON result, as written.
pub fn handle(
    state: &VaultState,
    checks: &mut Checks<'_>,
    method: &str,
    params: Option<&str>,
) -> Result<Box<RawValue>, ErrorBody> {
    // Numbers as JSON.parse reads them: typed data must hash the integer
    // ethers signs and the approval UI shows (#87).
    let params: Value =
        fc_evm::parse_json(params.unwrap_or("{}")).map_err(|_| invalid("Invalid parameters"))?;
    // A presented token is burnt however the request ends (design 0012,
    // "Tokens"): one the check spent is already gone.
    let presented = AUTHORIZED
        .contains(&method)
        .then(|| crate::approvals::presented_token(&params, true))
        .flatten();
    let result = handle_parsed(state, checks, method, &params);
    if let Some(token) = presented {
        checks.approvals.burn(&token);
    }
    result
}

fn handle_parsed(
    state: &VaultState,
    checks: &mut Checks<'_>,
    method: &str,
    params: &Value,
) -> Result<Box<RawValue>, ErrorBody> {
    if AUTHORIZED.contains(&method) {
        crate::approvals::page_context(checks.context)?;
    }
    match method {
        "sign.typed_data" => {
            let fields = object(
                params,
                &["key", "typed_data", "expected_hash"],
                &["primary_type", "chain_id", "authorization"],
            )?;
            let key = key_ref(&fields["key"], Allowed::AccountsOnly)?;
            let expected: [u8; 32] = parse_bytes(string(fields, "expected_hash")?, "expected_hash")
                .map_err(evm_error)?
                .try_into()
                .map_err(|_| invalid("expected_hash: expected 32 bytes"))?;
            let hashed = typed_data_view(fields)?;
            // The digest the user confirmed, or nothing: checked before any
            // key is derived.
            if hashed.hash != expected {
                return Err(invalid(
                    "typed data hash is not the confirmed one (expected_hash)",
                ));
            }
            let after = authorize(
                checks,
                fields,
                Signed::TypedData {
                    account: account_index(key)?,
                    fields,
                    hash: &hashed.hash,
                    view: &hashed,
                },
            )?;
            let signature = sign_with(state, key, &hashed.hash)?;
            let _ = checks.approvals.signed(after, checks.clocks);
            let view = view_value(hashed.view)?;
            raw(&SignedView {
                signature: to_hex(&signature),
                view: &view,
            })
        }
        "typed_data.hash" => {
            let fields = object(params, &["typed_data"], &["primary_type", "chain_id"])?;
            let hashed = typed_data_view(fields)?;
            let view = view_value(hashed.view)?;
            raw(&HashedView {
                hash: to_hex(&hashed.hash),
                view: &view,
            })
        }
        _ => other(state, checks, method, params).and_then(|result| raw(&result)),
    }
}

/// The methods without a view.
fn other(
    state: &VaultState,
    checks: &mut Checks<'_>,
    method: &str,
    params: &Value,
) -> Result<Value, ErrorBody> {
    match method {
        "sign.transaction" => {
            let fields = object(params, &["key", "tx"], &["authorization"])?;
            let key = key_ref(&fields["key"], Allowed::AccountsOnly)?;
            let tx = Transaction::from_json(&fields["tx"]).map_err(evm_error)?;
            let prepared = tx.prepare().map_err(evm_error)?;
            let after = authorize(
                checks,
                fields,
                Signed::Transaction {
                    account: account_index(key)?,
                    tx_json: &fields["tx"],
                    tx: &tx,
                },
            )?;
            let signature = sign_with(state, key, &prepared.digest())?;
            // A flagged `dapp-send`'s rule, written as it signs (design
            // 0012, `token-remember`): the reply says what became of it.
            let rule = checks.approvals.signed(after, checks.clocks);
            let signed = prepared.finish(&signature).map_err(evm_error)?;
            let mut result = json!({ "raw": to_hex(&signed.raw), "hash": to_hex(&signed.hash) });
            if let Some(rule) = rule {
                result["rule"] = rule;
            }
            Ok(result)
        }
        "sign.message" => {
            let fields = object(params, &["key", "message"], &["authorization"])?;
            let key = key_ref(&fields["key"], Allowed::AccountsOnly)?;
            let message = parse_bytes(string(fields, "message")?, "message").map_err(evm_error)?;
            let after = authorize(
                checks,
                fields,
                Signed::Message {
                    account: account_index(key)?,
                    message: &fields["message"],
                },
            )?;
            let signature = sign_with(state, key, &fc_evm::eip191_digest(&message))?;
            let _ = checks.approvals.signed(after, checks.clocks);
            Ok(json!({ "signature": to_hex(&signature) }))
        }
        "swarm.sign_soc" => {
            let fields = object(
                params,
                &["key", "identifier", "payload"],
                &["span", "authorization"],
            )?;
            let key = key_ref(&fields["key"], Allowed::ChunkKeysOnly)?;
            let identifier: [u8; 32] = parse_bytes(string(fields, "identifier")?, "identifier")
                .map_err(evm_error)?
                .try_into()
                .map_err(|_| invalid("identifier: expected 32 bytes"))?;
            let payload = parse_bytes(string(fields, "payload")?, "payload").map_err(evm_error)?;
            let span = match fields.get("span") {
                None => None,
                Some(Value::String(text)) => Some(
                    fc_evm::parse_unsigned(text)
                        .and_then(|span| span.to_u64())
                        .ok_or_else(|| invalid("span: expected a u64 quantity"))?,
                ),
                Some(_) => return Err(invalid("span: expected a quantity string")),
            };
            let prepared = fc_swarm::prepare_soc(&identifier, span, &payload)
                .map_err(|e| invalid(e.to_string()))?;
            // A page's SOC needs its Swarm grant (design 0012, APR-4c),
            // checked after the public work and before the key.
            match fields.get("authorization") {
                Some(authorization) => {
                    checks
                        .approvals
                        .authorize_soc(checks.context, authorization, checks.clocks)?;
                }
                None => crate::approvals::soc_without_authorization(checks.context)?,
            }
            let (signature, owner) = {
                // The key lives only for the signature and its address.
                let derived = derive(state, key)?;
                let signature = fc_evm::sign_digest(derived.signing_key(), &prepared.digest())
                    .map_err(evm_error)?;
                (signature, fc_evm::address_of(derived.signing_key()))
            };
            let signed = prepared.finish(signature, owner);
            Ok(json!({
                "signature": to_hex(&signed.signature),
                "owner": checksum_address(&signed.owner),
                "chunk_address": to_hex(&signed.chunk_address),
                "soc_address": to_hex(&signed.soc_address),
                "span": signed.span.to_string(),
            }))
        }
        _ => Err(invalid("unknown method")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use fc_protocol::message::{CallerKind, PageContext};

    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const HANDLE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    const TO: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
    const MINTED: Clocks = Clocks {
        vault_ms: 10_000,
        wall_ms: 1_700_000_000_000,
    };

    fn unlocked() -> VaultState {
        let mut state = VaultState::new();
        let ticket = state.ticket();
        let prepared = fc_vault::state::Prepared::new(fc_keys::Mnemonic::parse(ABANDON).unwrap());
        state.install(ticket, prepared, 0, 0).unwrap();
        state
    }

    fn site() -> Context {
        Context {
            caller: CallerKind::Page,
            page: Some(PageContext {
                origin: "https://app.example".to_owned(),
                top_origin: "https://app.example".to_owned(),
                frame: 1,
                navigation: 1,
                agent: Some(false),
            }),
        }
    }

    fn sign(
        state: &VaultState,
        approvals: &mut Approvals,
        clocks: Clocks,
        method: &str,
        params: &Value,
    ) -> Result<Value, ErrorBody> {
        let context = site();
        let mut checks = Checks {
            approvals,
            context: &context,
            clocks,
        };
        handle(state, &mut checks, method, Some(&params.to_string()))
            .map(|raw| serde_json::from_str(raw.get()).unwrap())
    }

    fn reason(refused: &ErrorBody) -> String {
        assert_eq!(refused.code, ErrorCode::NotAuthorized, "{refused:?}");
        refused.data.as_ref().unwrap()["reason"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn tx(max_fee: &str, data: &str) -> Value {
        json!({
            "type": 2, "chain_id": "100", "nonce": "3", "gas_limit": "60000", "to": TO,
            "value": "1", "data": data,
            "max_fee_per_gas": max_fee, "max_priority_fee_per_gas": "1000000000",
        })
    }

    fn mail() -> Value {
        json!({
            "domain": { "name": "Ether Mail", "chainId": "100" },
            "types": { "Mail": [{ "name": "contents", "type": "string" }] },
            "message": { "contents": "Hello" },
        })
    }

    /// A method's request, given the token it presents.
    type Request = Box<dyn Fn(&str) -> Value>;

    /// Each method's page-kind token and its request, with the token.
    fn requests() -> [(&'static str, Value, Request); 3] {
        let typed = mail();
        let hash = fc_evm::to_hex(
            &fc_evm::typed_data_hash(&typed["domain"], &typed["types"], &typed["message"]).unwrap(),
        );
        let account = json!({ "kind": "account", "index": 0 });
        let (a, b, c) = (account.clone(), account.clone(), account);
        [
            (
                "sign.transaction",
                json!({ "kind": "dapp-send", "account": 0, "handle": HANDLE,
                    "payload": { "tx": tx("2000000000", "0x") } }),
                Box::new(move |token: &str| {
                    json!({ "key": a, "tx": tx("2000000000", "0x"),
                        "authorization": { "token": token, "kind": "dapp-send", "handle": HANDLE } })
                }),
            ),
            (
                "sign.message",
                json!({ "kind": "sign-message", "account": 0, "handle": HANDLE,
                    "payload": { "message": "0x68656c6c6f" } }),
                Box::new(move |token: &str| {
                    json!({ "key": b, "message": "0x68656c6c6f",
                        "authorization": { "token": token, "handle": HANDLE } })
                }),
            ),
            (
                "sign.typed_data",
                json!({ "kind": "sign-typed-data", "account": 0, "handle": HANDLE,
                    "payload": { "typed_data": mail() } }),
                Box::new(move |token: &str| {
                    json!({ "key": c, "typed_data": mail(), "expected_hash": hash,
                        "authorization": { "token": token, "handle": HANDLE } })
                }),
            ),
        ]
    }

    fn issue(approvals: &mut Approvals, params: &Value) -> String {
        let reply = approvals
            .request(1, "approval.issue", params, &site(), MINTED)
            .unwrap();
        let reply: Value = serde_json::from_slice(&reply).unwrap();
        reply["result"]["token"].as_str().unwrap().to_owned()
    }

    /// Design 0012, APR-4: a page's token signs for two minutes of the
    /// vault's clock, each method's at 119,999 ms after minting, and is
    /// refused as `expired` at 120,000, before any key is derived: with the
    /// vault locked too, and burnt.
    #[test]
    fn an_expired_token_signs_nothing() {
        let state = unlocked();
        let locked = VaultState::new();
        let mut approvals = Approvals::new();
        let at = |ms: u64| Clocks {
            vault_ms: MINTED.vault_ms + ms,
            ..MINTED
        };
        for (method, mint, request) in requests() {
            let token = issue(&mut approvals, &mint);
            let signed = sign(
                &state,
                &mut approvals,
                at(119_999),
                method,
                &request(&token),
            );
            assert!(signed.is_ok(), "{method}: {signed:?}");
            for state in [&state, &locked] {
                let token = issue(&mut approvals, &mint);
                let expired = sign(state, &mut approvals, at(120_000), method, &request(&token));
                assert_eq!(reason(&expired.unwrap_err()), "expired", "{method}");
                let again = sign(state, &mut approvals, at(0), method, &request(&token));
                assert_eq!(reason(&again.unwrap_err()), "unknown_token", "{method}");
            }
        }
    }

    /// `chain.fee_reference`'s reply, as served, quoting `per_gas`.
    fn quote(id: u64, per_gas: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": "response",
            "id": id,
            "result": {
                "header": null,
                "lowest_priority": null,
                "quote": { "source": "direct", "type": "eip1559", "maxFeePerGas": per_gas, "answered": 2 },
                "generation": 0,
            },
        }))
        .unwrap()
    }

    /// Design 0012, APR-4: a standing rule answers a page's send only
    /// within the fee check, against the newest fee reference the core
    /// served for the chain: within three times its quote the send signs,
    /// above it the rule is refused (`fee_check`), and so it is once the
    /// reference is more than 60 s old.
    #[test]
    fn a_standing_send_over_the_fee_threshold_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let file = json!({ "https://app.example": {
            "origin": "https://app.example", "connectedAt": 1_762_000_000_000_u64,
            "lastUsed": 1_762_000_000_000_u64, "walletIndex": 0, "chainId": 100,
            "autoApprove": { "signing": false, "transactions": [
                { "to": TO, "selector": "0x095ea7b3", "chainId": 100, "maxValue": "5" },
            ] },
        } });
        std::fs::write(
            root.path().join("dapp-permissions.json"),
            serde_json::to_string_pretty(&file).unwrap(),
        )
        .unwrap();
        let mut approvals = Approvals::new();
        approvals.configure_grants(root.path().to_path_buf(), Vec::new(), MINTED.wall_ms);
        let state = unlocked();
        let approve = "0x095ea7b30000000000000000000000000000000000000000000000000000000000000001";
        let send = |max_fee: &str| {
            json!({ "key": { "kind": "account", "index": 0 }, "tx": tx(max_fee, approve),
                "authorization": { "standing": { "paused": false } } })
        };
        // No reference yet: nothing to judge against.
        let none = sign(
            &state,
            &mut approvals,
            MINTED,
            "sign.transaction",
            &send("2000000000"),
        );
        assert_eq!(reason(&none.unwrap_err()), "fee_check");
        approvals.fee_asked(5, Some(r#"{"chain_id":100,"deadline_ms":15000}"#), 9_000);
        approvals.fee_answered(5, &quote(5, "2000000000"));
        let within = sign(
            &state,
            &mut approvals,
            MINTED,
            "sign.transaction",
            &send("2000000000"),
        );
        assert!(within.unwrap()["raw"].is_string());
        let above = sign(
            &state,
            &mut approvals,
            MINTED,
            "sign.transaction",
            &send("7000000000"),
        );
        assert_eq!(reason(&above.unwrap_err()), "fee_check");
        // A plain transfer at the same fee: no rule names it.
        let mut plain = send("2000000000");
        plain["tx"]["data"] = json!("0x");
        let plain = sign(&state, &mut approvals, MINTED, "sign.transaction", &plain);
        assert_eq!(reason(&plain.unwrap_err()), "no_rule");
        let stale = Clocks {
            vault_ms: 9_000 + 60_001,
            ..MINTED
        };
        let old = sign(
            &state,
            &mut approvals,
            stale,
            "sign.transaction",
            &send("2000000000"),
        );
        assert_eq!(reason(&old.unwrap_err()), "fee_check");
    }
}
