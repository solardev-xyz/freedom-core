//! What a token binds: the request in the form the core will sign it, its
//! own parse of the `sign.*` parameters (design 0012, "Tokens"), never
//! main's display form.
//!
//! [`bind`] reads a request into its facts, as the reference's `bindingFor`
//! does (`signing-confirmation.js`), and digests them. It runs when a token
//! is minted and again when it is spent, so the two can't drift. The facts
//! are canonical JSON ([`crate::canonical`]): quantities in decimal,
//! addresses, bytes and hashes in lowercase hex, long inputs (a message, the
//! typed-data request and its view, a Safe message's params, an x402 entry)
//! as SHA-256 digests of their canonical forms.

use fc_evm::{Transaction, TypedDataView, U256, ViewRequest, parse_address, parse_bytes, to_hex};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use crate::canonical;
use crate::error::Error;
use crate::kind::{Kind, PageRule, Scope};

/// The largest chain id a token binds: the reference's `chain()` refuses
/// anything that isn't a positive safe integer, so the core does too.
pub const MAX_CHAIN_ID: u64 = (1 << 53) - 1;

/// The largest nonce: a JS safe integer, as ethers and the reference keep
/// it (fc-evm's own bound on `sign.transaction`).
pub const MAX_NONCE: u64 = (1 << 53) - 1;

/// The most hashes an `intent-close` binds: the reference's
/// `MAX_CLOSE_HASHES`, above the intent store's bound on an intent's
/// signatures.
pub const MAX_CLOSE_HASHES: usize = 64;

/// The largest account index: what `sign.*`'s key references take
/// (freedom-cored's `signing.rs`, `index`).
pub const MAX_ACCOUNT: u32 = 0x7fff_ffff;

/// 0011's handle: the 32 random bytes main issued for a prompt. Its text is
/// 64 lowercase hex digits, as the reference's `HANDLE` pattern requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle([u8; 32]);

impl Handle {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Handle(bytes)
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut bytes = [0u8; 32];
        if !lower_hex_32(text, &mut bytes) {
            return Err(invalid("A page confirmation needs its handle"));
        }
        Ok(Handle(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The handle's text: 64 lowercase hex digits, no `0x`.
    pub fn to_text(&self) -> String {
        to_hex(&self.0)[2..].to_owned()
    }
}

/// 64 lowercase hex digits, exactly, as 32 bytes, written into `out`,
/// which the caller owns (a presented token's buffer wipes on drop): no copy
/// is returned, so none is left behind. Whether `text` is such digits; when
/// it isn't, `out` is untouched.
pub(crate) fn lower_hex_32(text: &str, out: &mut [u8; 32]) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 64 || !bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return false;
    }
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    let (pairs, _) = bytes.as_chunks::<2>();
    for (byte, [high, low]) in out.iter_mut().zip(pairs) {
        *byte = (digit(*high) << 4) | digit(*low);
    }
    true
}

/// The page a page kind is for: `PageContext`'s `origin`, `frame` and
/// `navigation` (0011), and the handle of the prompt the user decided. A
/// token presented with another page is refused, so a token can't outlive
/// its document's number (`token-page`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The document's permission key (0011's `key`).
    pub origin: String,
    /// `frameTreeNodeId`.
    pub frame: u64,
    /// Main's document number.
    pub navigation: u64,
    pub handle: Handle,
}

/// A request to confirm, or to spend a confirmation on: the kind, the
/// account and the payload, as JSON in the core's form (below), and the
/// page for a page kind.
///
/// The payload is the `sign.*` parameters but the key, for the kinds the
/// core signs, and the core's own form for the others:
///
/// | Kind | `account` | `payload` |
/// |---|---|---|
/// | `wallet-send`, `executor-send` | the account's index | `{ tx }`: `sign.transaction`'s `tx`, whose `nonce` is optional and never bound |
/// | `dapp-send` | the account's index | `{ tx, remember? }`: as `wallet-send`, and whether "Always allow" was ticked, a boolean the token keeps beside its digest |
/// | `sign-message` | the account's index | `{ message }`: `sign.message`'s bytes, as hex |
/// | `sign-typed-data` | the account's index | `{ typed_data, primary_type?, chain_id? }`, as `sign.typed_data` takes them |
/// | `safe-send` | the Safe's index | `{ safe, chain_id, tx: { to, value, data } }`: the Safe's address and the SafeTx |
/// | `safe-message` | the Safe's index | `{ safe, chain_id, method, params }`: the Safe's address and chain, and the dApp's request |
/// | `intent-resend` | none | `{ intent_id, chain_id, sender, nonce, hash }` |
/// | `intent-replace` | none, or the index of the account that signs it again, which `sign.transaction` requires | `{ intent_id, sender, tx }`: `tx` as `sign.transaction` takes it, its `nonce` required and bound |
/// | `intent-close` | none | `{ intent_id, chain_id, sender, nonce, hashes }` |
/// | `x402-payment` | the account's index | `{ detection: { tab, id, url }, accept_index, accept, grant? }`; `grant` is `null` or `{ cap_amount, window_seconds }` |
///
/// An account is a JSON integer from 0 to 2^31 - 1. Quantities (`chain_id`,
/// `nonce`, a SafeTx's `value`) are strings, decimal or `0x` hex, as
/// `sign.transaction`'s. Every object is closed: an unknown member is
/// refused.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub kind: Kind,
    pub account: Option<&'a Value>,
    pub payload: &'a Value,
    pub page: Option<&'a Page>,
}

/// What the binding needs beside the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The longest typed-data view, in bytes (fc-evm's `ViewRequest`):
    /// freedom-cored's `max_view_len`, so a view the core couldn't reply
    /// with gets no token.
    pub max_view_len: usize,
}

/// A request's facts and their digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    kind: Kind,
    scope: Scope,
    facts: String,
    digest: [u8; 32],
    typed_data: Option<TypedDataView>,
    remember: bool,
    sender: Option<String>,
}

impl Binding {
    /// For `dapp-send`: whether "Always allow" was ticked (`remember`),
    /// which the token keeps outside its digest.
    pub fn remember(&self) -> bool {
        self.remember
    }

    /// For `intent-replace`: the sender's address it binds, main's word at
    /// minting, as `0x` and lowercase hex.
    pub fn sender(&self) -> Option<&str> {
        self.sender.as_deref()
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The facts the token binds, as canonical JSON. Nothing in them is
    /// secret.
    pub fn facts(&self) -> &str {
        &self.facts
    }

    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// For `sign-typed-data`: the EIP-712 hash, which `sign.typed_data`'s
    /// `expected_hash` must equal, and the view of what is signed (#88).
    pub fn typed_data(&self) -> Option<&TypedDataView> {
        self.typed_data.as_ref()
    }

    pub(crate) fn into_typed_data(self) -> Option<TypedDataView> {
        self.typed_data
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

fn evm(error: fc_evm::Error) -> Error {
    invalid(error.to_string())
}

/// The facts of `request`, or why it can't be confirmed.
pub fn bind(request: &Request<'_>, limits: &Limits) -> Result<Binding, Error> {
    let kind = request.kind;
    let scope = match (kind.page_rule(), request.page) {
        (PageRule::Required, None) => return Err(Error::PageRequired(kind.name())),
        (PageRule::Forbidden, Some(_)) => return Err(Error::PageForbidden(kind.name())),
        (_, Some(_)) => Scope::Page,
        (_, None) => Scope::Wallet,
    };
    let page = request.page.map(page_facts).transpose()?;
    let account = if kind.takes_account() {
        Some(account(request.account)?)
    } else {
        match request.account {
            None | Some(Value::Null) => None,
            // An `intent-replace` may bind the account that signs it again,
            // which `sign.transaction` then requires (design 0012, Tokens):
            // the reference's record names only the sender's address.
            Some(given) if kind == Kind::IntentReplace => Some(account(Some(given))?),
            Some(_) => return Err(invalid(format!("{}: binds no account", kind.name()))),
        }
    };
    let mut typed_data = None;
    let mut remember = false;
    let mut sender = None;
    let payload = request.payload;
    let body = match kind {
        Kind::WalletSend | Kind::ExecutorSend => {
            let fields = object(payload, "payload", &["tx"], &[])?;
            json!({ "tx": transaction(&fields["tx"], Nonce::Unbound)? })
        }
        Kind::DappSend => {
            // "Always allow" rides in the token, not in its digest: the
            // token keeps the flag it was minted with, and
            // `sign.transaction`, which names no flag, reads it from there
            // (design 0012, `token-remember`).
            let fields = object(payload, "payload", &["tx"], &["remember"])?;
            remember = match fields.get("remember") {
                None => false,
                Some(Value::Bool(flag)) => *flag,
                Some(_) => return Err(invalid("remember: expected a boolean")),
            };
            json!({ "tx": transaction(&fields["tx"], Nonce::Unbound)? })
        }
        Kind::SignMessage => {
            let fields = object(payload, "payload", &["message"], &[])?;
            let message = bytes(&fields["message"], "message")?;
            json!({ "message_sha256": sha256_hex(&message), "message_length": message.len() })
        }
        Kind::SignTypedData => {
            let (facts, view) = typed(payload, limits)?;
            typed_data = Some(view);
            facts
        }
        Kind::SafeSend => {
            let fields = object(payload, "payload", &["safe", "chain_id", "tx"], &[])?;
            let tx = object(&fields["tx"], "tx", &["to", "value", "data"], &[])?;
            json!({
                "safe": address(&fields["safe"], "safe")?,
                "chain_id": chain(&fields["chain_id"], "chain_id")?,
                "to": address(&tx["to"], "to")?,
                "value": quantity(&tx["value"], "value")?.to_decimal(),
                "data": to_hex(&bytes(&tx["data"], "data")?),
            })
        }
        Kind::SafeMessage => {
            let fields = object(
                payload,
                "payload",
                &["safe", "chain_id", "method", "params"],
                &[],
            )?;
            let safe = address(&fields["safe"], "safe")?;
            let chain_id = chain(&fields["chain_id"], "chain_id")?;
            let method = fields["method"]
                .as_str()
                .ok_or_else(|| invalid("Signature request is required"))?;
            if !fields["params"].is_array() {
                return Err(invalid("Signature request is required"));
            }
            json!({
                "safe": safe,
                "chain_id": chain_id,
                "method": method,
                "params_sha256": hex32(&canonical::digest(&fields["params"])),
            })
        }
        Kind::IntentResend => {
            let fields = object(
                payload,
                "payload",
                &["intent_id", "chain_id", "sender", "nonce", "hash"],
                &[],
            )?;
            json!({
                "intent_id": intent_id(&fields["intent_id"])?,
                "chain_id": chain(&fields["chain_id"], "chain_id")?,
                "sender": address(&fields["sender"], "sender")?,
                "nonce": nonce(&fields["nonce"])?,
                "hash": hash(&fields["hash"], "hash")?,
            })
        }
        Kind::IntentReplace => {
            let fields = object(payload, "payload", &["intent_id", "sender", "tx"], &[])?;
            let address = address(&fields["sender"], "sender")?;
            sender = Some(address.clone());
            json!({
                "intent_id": intent_id(&fields["intent_id"])?,
                "sender": address,
                "tx": transaction(&fields["tx"], Nonce::Bound)?,
            })
        }
        Kind::IntentClose => {
            let fields = object(
                payload,
                "payload",
                &["intent_id", "chain_id", "sender", "nonce", "hashes"],
                &[],
            )?;
            let hashes = fields["hashes"]
                .as_array()
                .filter(|hashes| !hashes.is_empty() && hashes.len() <= MAX_CLOSE_HASHES)
                .ok_or_else(|| invalid("Invalid hashes"))?
                .iter()
                .map(|value| hash(value, "hashes").map(Value::String))
                .collect::<Result<Vec<_>, _>>()?;
            json!({
                "intent_id": intent_id(&fields["intent_id"])?,
                "chain_id": chain(&fields["chain_id"], "chain_id")?,
                "sender": address(&fields["sender"], "sender")?,
                "nonce": nonce(&fields["nonce"])?,
                "hashes": hashes,
            })
        }
        Kind::X402Payment => x402(payload)?,
    };
    let facts = json!({
        "kind": kind.name(),
        "account": account,
        "request": body,
        "page": page,
    });
    let facts = canonical::text(&facts);
    let digest = Sha256::digest(facts.as_bytes()).into();
    Ok(Binding {
        kind,
        scope,
        facts,
        digest,
        typed_data,
        remember,
        sender,
    })
}

fn page_facts(page: &Page) -> Result<Value, Error> {
    if page.origin.is_empty() {
        return Err(invalid("A page confirmation needs its origin"));
    }
    Ok(json!({
        "origin": page.origin,
        "frame": page.frame,
        "navigation": page.navigation,
        "handle": page.handle.to_text(),
    }))
}

/// `value` as an object with exactly these members.
pub(crate) fn object<'a>(
    value: &'a Value,
    what: &str,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>, Error> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what}: expected an object")))?;
    if let Some(unknown) = object
        .keys()
        .find(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(invalid(format!(
            "{what}: unknown field {}",
            fc_evm::shortened(unknown)
        )));
    }
    if let Some(missing) = required.iter().find(|key| !object.contains_key(**key)) {
        return Err(invalid(format!("{what}: missing field {missing}")));
    }
    Ok(object)
}

/// A JSON integer from 0 to [`MAX_ACCOUNT`].
fn account(value: Option<&Value>) -> Result<u32, Error> {
    value
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n <= MAX_ACCOUNT)
        .ok_or_else(|| invalid("Invalid account index"))
}

/// A quantity string, decimal or `0x` hex, as `sign.transaction` reads one.
pub(crate) fn quantity(value: &Value, field: &str) -> Result<U256, Error> {
    value
        .as_str()
        .and_then(fc_evm::parse_unsigned)
        .ok_or_else(|| invalid(format!("Invalid {field}")))
}

/// A chain id: a quantity from 1 to [`MAX_CHAIN_ID`], in decimal.
fn chain(value: &Value, field: &str) -> Result<String, Error> {
    quantity(value, field)?
        .to_u64()
        .filter(|n| (1..=MAX_CHAIN_ID).contains(n))
        .map(|n| n.to_string())
        .ok_or_else(|| invalid("Invalid chainId"))
}

/// A nonce: a quantity up to [`MAX_NONCE`], in decimal.
fn nonce(value: &Value) -> Result<String, Error> {
    quantity(value, "nonce")?
        .to_u64()
        .filter(|n| *n <= MAX_NONCE)
        .map(|n| n.to_string())
        .ok_or_else(|| invalid("Invalid nonce"))
}

/// An address, as `sign.transaction` reads one (a mixed-case one must carry
/// its EIP-55 checksum), in lowercase.
fn address(value: &Value, field: &str) -> Result<String, Error> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid(format!("Invalid {field}")))?;
    let address = parse_address(text).map_err(|_| invalid(format!("Invalid {field}")))?;
    Ok(to_hex(&address))
}

/// `0x` hex bytes, as `sign.*` reads them.
pub(crate) fn bytes(value: &Value, field: &str) -> Result<Vec<u8>, Error> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid(format!("Invalid {field}")))?;
    parse_bytes(text, field).map_err(evm)
}

/// A 32-byte hash in `0x` hex, any case, in lowercase.
fn hash(value: &Value, field: &str) -> Result<String, Error> {
    let bytes = bytes(value, field).map_err(|_| invalid("Invalid transaction hash"))?;
    if bytes.len() != 32 {
        return Err(invalid("Invalid transaction hash"));
    }
    Ok(to_hex(&bytes))
}

/// An intent's id, as the reference's `intentId` takes it.
fn intent_id(value: &Value) -> Result<&str, Error> {
    value
        .as_str()
        .filter(|id| {
            (8..=64).contains(&id.len())
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
        .ok_or_else(|| invalid("Invalid intent id"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex32(&Sha256::digest(bytes).into())
}

fn hex32(digest: &[u8; 32]) -> String {
    to_hex(digest)
}

/// Whether a transaction's nonce is part of what it binds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Nonce {
    /// The wallet's and a page's sends: main chooses the nonce after the
    /// confirmation, under the account's lock (0012, "Tokens"). One, if
    /// given, is read as `sign.transaction` reads it, and not bound.
    Unbound,
    /// `intent-replace`: signed again at the intent's nonce.
    Bound,
}

/// A transaction as `sign.transaction` reads it ([`Transaction::from_json`]),
/// and its facts: every field but the nonce (unless bound), the type with
/// its fee fields. Its chain id must be a JS safe integer, as the
/// reference's `chain()` requires.
fn transaction(value: &Value, nonce_rule: Nonce) -> Result<Value, Error> {
    let fields = value
        .as_object()
        .ok_or_else(|| invalid("Transaction is required"))?;
    let tx = if fields.contains_key("nonce") {
        Transaction::from_json(value).map_err(evm)?
    } else if nonce_rule == Nonce::Bound {
        return Err(invalid("Invalid nonce"));
    } else {
        // Read as it will be signed, whatever nonce main then chooses.
        let mut with_nonce = fields.clone();
        with_nonce.insert("nonce".into(), Value::String("0".into()));
        Transaction::from_json(&Value::Object(with_nonce)).map_err(evm)?
    };
    let chain_id = tx
        .chain_id()
        .to_u64()
        .filter(|n| *n <= MAX_CHAIN_ID)
        .ok_or_else(|| invalid("Invalid chainId"))?;
    let mut facts = json!({
        "type": tx.tx_type(),
        "chain_id": chain_id.to_string(),
        "to": tx.to().map(|to| to_hex(to)),
        "value": tx.value().to_decimal(),
        "data": to_hex(tx.data()),
        "gas_limit": tx.gas_limit().to_decimal(),
    });
    if let Value::Object(map) = &mut facts {
        if let Some(gas_price) = tx.gas_price() {
            map.insert("gas_price".into(), gas_price.to_decimal().into());
        }
        if let Some((max_fee, priority)) = tx.eip1559_fees() {
            map.insert("max_fee_per_gas".into(), max_fee.to_decimal().into());
            map.insert(
                "max_priority_fee_per_gas".into(),
                priority.to_decimal().into(),
            );
        }
        if nonce_rule == Nonce::Bound {
            map.insert("nonce".into(), tx.nonce().to_string().into());
        }
    }
    Ok(facts)
}

/// `sign-typed-data` (design 0012, "Typed data"): the EIP-712 hash; a
/// SHA-256 of the request's canonical JSON as `sign.typed_data` receives
/// it, `typed_data` with every object's keys sorted and every member kept,
/// undeclared ones at any depth included, then `primary_type` and
/// `chain_id`; and a SHA-256 of the view.
fn typed(payload: &Value, limits: &Limits) -> Result<(Value, TypedDataView), Error> {
    let fields = object(
        payload,
        "payload",
        &["typed_data"],
        &["primary_type", "chain_id"],
    )?;
    let typed_data = object(
        &fields["typed_data"],
        "typed_data",
        &["domain", "types", "message"],
        &[],
    )?;
    let chain_id = fields
        .get("chain_id")
        .map(|value| quantity(value, "chain_id"))
        .transpose()?;
    let view = fc_evm::typed_data_view(
        &typed_data["domain"],
        &typed_data["types"],
        &typed_data["message"],
        &ViewRequest {
            primary_type: fields.get("primary_type"),
            chain_id,
            max_len: limits.max_view_len,
        },
    )
    .map_err(evm)?;
    // The request as it is signed: the chain by its value, so `"0x1"` and
    // `"1"` are one request, as they are one chain to the view.
    let mut request = Map::new();
    request.insert("typed_data".into(), fields["typed_data"].clone());
    if let Some(primary_type) = fields.get("primary_type") {
        request.insert("primary_type".into(), primary_type.clone());
    }
    if let Some(chain_id) = &chain_id {
        request.insert("chain_id".into(), chain_id.to_decimal().into());
    }
    let facts = json!({
        "hash": hex32(&view.hash),
        "request_sha256": hex32(&canonical::digest(&Value::Object(request))),
        "view_sha256": sha256_hex(view.view.as_bytes()),
    });
    Ok((facts, view))
}

/// `x402-payment`: the account (bound beside), the detection (the tab, its
/// id and the URL), the chosen entry (its index, scheme, network, asset,
/// amount and `payTo`, and a digest of the whole entry) and the grant, or
/// none (#1016).
fn x402(payload: &Value) -> Result<Value, Error> {
    let fields = object(
        payload,
        "payload",
        &["detection", "accept_index", "accept"],
        &["grant"],
    )?;
    let detection = object(
        &fields["detection"],
        "detection",
        &["tab", "id", "url"],
        &[],
    )?;
    let tab = detection["tab"]
        .as_u64()
        .ok_or_else(|| invalid("Invalid tab"))?;
    let id = detection["id"]
        .as_str()
        .filter(|id| {
            (1..=128).contains(&id.len())
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
        })
        .ok_or_else(|| invalid("Invalid detection id"))?;
    let url = text(&detection["url"], "url")?;
    let accept_index = fields["accept_index"]
        .as_u64()
        .ok_or_else(|| invalid("Invalid payment option"))?;
    let accept = fields["accept"]
        .as_object()
        .ok_or_else(|| invalid("Payment option is required"))?;
    // V2 entries carry `amount`; V1 entries `maxAmountRequired`.
    let amount = match accept.get("amount") {
        None | Some(Value::Null) => accept.get("maxAmountRequired"),
        some => some,
    };
    let amount = match amount {
        Some(Value::String(text)) => fc_evm::parse_unsigned(text).map(|n| n.to_decimal()),
        Some(Value::Number(n)) => n.as_u64().map(|n| n.to_string()),
        _ => None,
    }
    .ok_or_else(|| invalid("Invalid amount"))?;
    let grant = match fields.get("grant") {
        None | Some(Value::Null) => Value::Null,
        Some(grant) => {
            let grant = object(grant, "grant", &["cap_amount", "window_seconds"], &[])?;
            let cap_amount = grant["cap_amount"]
                .as_str()
                .filter(|cap| !cap.is_empty() && cap.bytes().all(|b| b.is_ascii_digit()))
                .ok_or_else(|| invalid("Invalid grant"))?;
            let window = &grant["window_seconds"];
            if !window
                .as_f64()
                .is_some_and(|seconds| seconds.is_finite() && seconds > 0.0)
            {
                return Err(invalid("Invalid grant"));
            }
            json!({ "cap_amount": cap_amount, "window_seconds": window })
        }
    };
    Ok(json!({
        "tab": tab,
        "detection_id": id,
        "url": url,
        "accept_index": accept_index,
        "scheme": text(accept.get("scheme").unwrap_or(&Value::Null), "scheme")?,
        "network": text(accept.get("network").unwrap_or(&Value::Null), "network")?,
        "asset": text(accept.get("asset").unwrap_or(&Value::Null), "asset")?,
        "amount": amount,
        "pay_to": text(accept.get("payTo").unwrap_or(&Value::Null), "payTo")?,
        "accept_sha256": hex32(&canonical::digest(&fields["accept"])),
        "grant": grant,
    }))
}

/// A non-empty string, compared exactly.
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, Error> {
    value
        .as_str()
        .filter(|text| !text.is_empty())
        .ok_or_else(|| invalid(format!("Invalid {field}")))
}
