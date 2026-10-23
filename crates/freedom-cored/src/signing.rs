//! The Phase 2 signing methods (design 0002): `sign.transaction`,
//! `sign.message`, `sign.typed_data`, `swarm.sign_soc`, and the public
//! `typed_data.hash`.
//!
//! Each does all its public work first (parsing, validation, RLP, BMT,
//! hashing, within fc-evm's limits), then derives the key only to sign one
//! digest (and, for a chunk, take its address), and assembles the result
//! after the key is gone. It runs inline, as `compat.*` does. No secret is
//! held while untrusted input is processed, and no key byte leaves this
//! module.
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
use fc_vault::state::VaultState;
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

/// Which keys a method may use (design 0002, "Key references").
#[derive(Clone, Copy, PartialEq, Eq)]
enum Allowed {
    AccountsOnly,
    AnyKey,
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
    if allowed == Allowed::AccountsOnly && !matches!(key, KeyRef::Account(_)) {
        return Err(invalid("this key can only sign single-owner chunks"));
    }
    Ok(key)
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

/// Handles one of [`METHODS`]; returns the JSON result, as written.
pub fn handle(
    state: &VaultState,
    method: &str,
    params: Option<&str>,
) -> Result<Box<RawValue>, ErrorBody> {
    // Numbers as JSON.parse reads them: typed data must hash the integer
    // ethers signs and the approval UI shows (#87).
    let params: Value =
        fc_evm::parse_json(params.unwrap_or("{}")).map_err(|_| invalid("Invalid parameters"))?;
    match method {
        "sign.typed_data" => {
            let fields = object(
                &params,
                &["key", "typed_data", "expected_hash"],
                &["primary_type", "chain_id"],
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
            let view = view_value(hashed.view)?;
            let signature = sign_with(state, key, &hashed.hash)?;
            raw(&SignedView {
                signature: to_hex(&signature),
                view: &view,
            })
        }
        "typed_data.hash" => {
            let fields = object(&params, &["typed_data"], &["primary_type", "chain_id"])?;
            let hashed = typed_data_view(fields)?;
            let view = view_value(hashed.view)?;
            raw(&HashedView {
                hash: to_hex(&hashed.hash),
                view: &view,
            })
        }
        _ => other(state, method, &params).and_then(|result| raw(&result)),
    }
}

/// The methods without a view.
fn other(state: &VaultState, method: &str, params: &Value) -> Result<Value, ErrorBody> {
    match method {
        "sign.transaction" => {
            let fields = object(params, &["key", "tx"], &[])?;
            let key = key_ref(&fields["key"], Allowed::AccountsOnly)?;
            let prepared = Transaction::from_json(&fields["tx"])
                .and_then(|tx| tx.prepare())
                .map_err(evm_error)?;
            let signature = sign_with(state, key, &prepared.digest())?;
            let signed = prepared.finish(&signature).map_err(evm_error)?;
            Ok(json!({ "raw": to_hex(&signed.raw), "hash": to_hex(&signed.hash) }))
        }
        "sign.message" => {
            let fields = object(params, &["key", "message"], &[])?;
            let key = key_ref(&fields["key"], Allowed::AccountsOnly)?;
            let message = parse_bytes(string(fields, "message")?, "message").map_err(evm_error)?;
            let signature = sign_with(state, key, &fc_evm::eip191_digest(&message))?;
            Ok(json!({ "signature": to_hex(&signature) }))
        }
        "swarm.sign_soc" => {
            let fields = object(params, &["key", "identifier", "payload"], &["span"])?;
            let key = key_ref(&fields["key"], Allowed::AnyKey)?;
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
