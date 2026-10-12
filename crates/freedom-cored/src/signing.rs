//! The Phase 2 signing methods (design 0002): `sign.transaction`,
//! `sign.message`, `sign.typed_data`, `swarm.sign_soc`, and the public
//! `typed_data.hash`.
//!
//! Each does all its public work first (parsing, validation, hashing, within
//! fc-evm's limits), and only then derives the key and makes one signature,
//! inline, as `compat.*` does. No secret is held while untrusted input is
//! processed, and no key byte leaves this module.

use fc_evm::{Transaction, checksum_address, parse_bytes, to_hex};
use fc_keys::Secp256k1Key;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_vault::state::VaultState;
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
        return Err(invalid(format!("unknown field {unknown}")));
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

/// `{ domain, types, message }`, exactly.
fn typed_data(value: &Value) -> Result<(&Value, &Value, &Value), ErrorBody> {
    let object = object(value, &["domain", "types", "message"], &[])?;
    Ok((&object["domain"], &object["types"], &object["message"]))
}

fn string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, ErrorBody> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{field}: expected a string")))
}

/// Handles one of [`METHODS`]; returns the JSON result.
pub fn handle(state: &VaultState, method: &str, raw: Option<&str>) -> Result<Value, ErrorBody> {
    let params: Value =
        serde_json::from_str(raw.unwrap_or("{}")).map_err(|_| invalid("Invalid parameters"))?;
    match method {
        "sign.transaction" => {
            let fields = object(&params, &["key", "tx"], &[])?;
            let key = key_ref(&fields["key"], Allowed::AccountsOnly)?;
            let tx = Transaction::from_json(&fields["tx"]).map_err(evm_error)?;
            let signed = tx
                .sign(derive(state, key)?.signing_key())
                .map_err(evm_error)?;
            Ok(json!({ "raw": to_hex(&signed.raw), "hash": to_hex(&signed.hash) }))
        }
        "sign.message" => {
            let fields = object(&params, &["key", "message"], &[])?;
            let key = key_ref(&fields["key"], Allowed::AccountsOnly)?;
            let message = parse_bytes(string(fields, "message")?, "message").map_err(evm_error)?;
            let digest = fc_evm::eip191_digest(&message);
            let signature = fc_evm::sign_digest(derive(state, key)?.signing_key(), &digest)
                .map_err(evm_error)?;
            Ok(json!({ "signature": to_hex(&signature) }))
        }
        "sign.typed_data" => {
            let fields = object(&params, &["key", "typed_data"], &[])?;
            let key = key_ref(&fields["key"], Allowed::AccountsOnly)?;
            let (domain, types, message) = typed_data(&fields["typed_data"])?;
            let digest = fc_evm::typed_data_hash(domain, types, message).map_err(evm_error)?;
            let signature = fc_evm::sign_digest(derive(state, key)?.signing_key(), &digest)
                .map_err(evm_error)?;
            Ok(json!({ "signature": to_hex(&signature) }))
        }
        "typed_data.hash" => {
            let fields = object(&params, &["typed_data"], &[])?;
            let (domain, types, message) = typed_data(&fields["typed_data"])?;
            let hash = fc_evm::typed_data_hash(domain, types, message).map_err(evm_error)?;
            Ok(json!({ "hash": to_hex(&hash) }))
        }
        "swarm.sign_soc" => {
            let fields = object(&params, &["key", "identifier", "payload"], &["span"])?;
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
            if payload.is_empty() || payload.len() > fc_swarm::CHUNK_SIZE {
                return Err(invalid(format!(
                    "payload size {} outside 1..=4096",
                    payload.len()
                )));
            }
            let signed = fc_swarm::sign_soc(
                derive(state, key)?.signing_key(),
                &identifier,
                span,
                &payload,
            )
            .map_err(|e| match e {
                fc_swarm::Error::Signing => crate::vault::internal(),
                other => invalid(other.to_string()),
            })?;
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
