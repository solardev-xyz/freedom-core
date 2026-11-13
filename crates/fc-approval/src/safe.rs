//! Safe approvals (design 0012, "A page's Safe and Swarm signatures"): what
//! a spent `safe-send` or `safe-message` token gives the signatures it
//! stands for, the vault owners' and the executor's.
//!
//! - **Recorded** at the token's spend ([`SafeApprovals::record`]), with
//!   the token's facts and whose it is: a page kind's for that page
//!   (`PageContext`'s origin, frame and navigation), used only under
//!   `page`; a wallet `safe-send`'s, used only under `shell`.
//! - **An id** of 16 random bytes, sent as 32 lowercase hex digits: a bearer
//!   secret like a token, never in `Debug` output, wiped when it ends, and
//!   compared in constant time against every open approval.
//! - **The owners** sign through `sign.typed_data` ([`SafeApprovals::check_owner`]).
//!   The first signs the SafeTx the token approved (its Safe, chain, `to`,
//!   `value` and `data`, under the request's nonce); its signature fixes
//!   that hash ([`SafeApprovals::owner_signed`]), and every later owner
//!   signs only it. Every owner of a Safe message signs the SafeMessage of
//!   the Safe and chain the token approved, over the digest computed at the
//!   spend: a domain with another `chainId` or `verifyingContract` is
//!   refused, at the first signature and every later one.
//! - **The executor** signs `execTransaction` to the Safe, with `value` 0
//!   and the approved SafeTx, field for field, while the fee check allows it
//!   ([`SafeApprovals::check_executor`]); its signature ends the approval.
//! - **Ended** by [`SafeApprovals::end`], by a newer `safe-send` approval
//!   for the same Safe, and by the executor's signature. At most
//!   [`MAX_SAFE_APPROVALS`] are open, the oldest dropped.
//!
//! The SafeTx is the one protocol-kit's `createTransaction` makes for one
//! call, as the reference builds it (`safe-executor.js`): operation 0
//! (`CALL`), no refund (`safeTxGas`, `baseGas` and `gasPrice` 0, both
//! addresses zero). The SafeMessage is `safe-messages.js`'s: the Safe's
//! domain (`chainId`, `verifyingContract`) and `{ message: digest }`.

use std::fmt;

use fc_evm::{
    Transaction, TypedDataView, U256, ViewRequest, eip191_digest, keccak256, parse_address,
    parse_bytes, parse_json, parse_unsigned, to_hex, typed_data_hash, typed_data_view,
};
use rand_core::TryCryptoRng;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::bind::{self, MAX_CHAIN_ID};
use crate::error::Error;
use crate::fee::{Evidence, Fees, judge_fees, reference_fee};

/// How many Safe approvals are open at once; the oldest is dropped.
pub const MAX_SAFE_APPROVALS: usize = 64;

/// The selector of Safe's `execTransaction`.
fn exec_selector() -> [u8; 4] {
    let hash = keccak256(
        b"execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
    );
    [hash[0], hash[1], hash[2], hash[3]]
}

/// A Safe approval's id.
pub struct SafeId(Zeroizing<[u8; 16]>);

impl SafeId {
    /// The id's text, for the reply that carries it to its caller.
    pub fn to_text(&self) -> Zeroizing<String> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = Zeroizing::new(String::with_capacity(32));
        for byte in self.0.iter() {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 0xf)]));
        }
        text
    }
}

impl fmt::Debug for SafeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SafeId(..)")
    }
}

/// 32 lowercase hex digits, exactly, into `out`; whether `text` is such.
fn lower_hex_16(text: &str, out: &mut [u8; 16]) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 32 || !bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return false;
    }
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    let (pairs, _) = bytes.as_chunks::<2>();
    for (byte, [high, low]) in out.iter_mut().zip(pairs) {
        *byte = (digit(*high) << 4) | digit(*low);
    }
    true
}

fn constant_time_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// Whose approval it is, and who may present it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holder {
    /// A page kind's (a site's `safe-send`, a `safe-message`): presented
    /// only under `page`, with this origin, frame and navigation.
    Page {
        origin: String,
        frame: u64,
        navigation: u64,
    },
    /// A wallet `safe-send`'s: presented only under `shell`.
    Wallet,
}

/// What the token approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Approved {
    /// A `safe-send`'s SafeTx: the Safe, its chain and the call.
    Send {
        safe: [u8; 20],
        chain_id: u64,
        to: [u8; 20],
        value: U256,
        data: Vec<u8>,
    },
    /// A `safe-message`'s Safe, its chain, and the digest: EIP-191's for a
    /// message, the EIP-712 hash for typed data, as a verifier computes it.
    Message {
        safe: [u8; 20],
        chain_id: u64,
        digest: [u8; 32],
    },
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

impl Approved {
    /// A `safe-send`'s payload (`{ safe, chain_id, tx: { to, value, data } }`),
    /// as its token bound it.
    pub fn send(payload: &Value) -> Result<Approved, Error> {
        let fields = bind::object(payload, "payload", &["safe", "chain_id", "tx"], &[])?;
        let tx = bind::object(&fields["tx"], "tx", &["to", "value", "data"], &[])?;
        let (safe, chain_id) = safe_and_chain(fields)?;
        Ok(Approved::Send {
            safe,
            chain_id,
            to: address(&tx["to"], "to")?,
            value: bind::quantity(&tx["value"], "value")?,
            data: bind::bytes(&tx["data"], "data")?,
        })
    }

    /// A `safe-message`'s payload (`{ safe, chain_id, method, params }`:
    /// the Safe's address and chain, which main reads from the Safe's
    /// record as the reference does before any owner signs, and the dApp's
    /// request), as its token bound it: the Safe, its chain, and the digest
    /// its SafeMessage carries, as the reference's `requestDigest` computes
    /// it (`safe-messages.js`):
    /// - `personal_sign`: EIP-191 over `params[0]`, `0x` hex as its bytes
    ///   (`normalizeMessage`), any other text as its UTF-8;
    /// - `eth_signTypedData_v4`: the EIP-712 hash of `params[1]`, an object
    ///   or its JSON text, with `domain` as `{}` when it is falsy and
    ///   `types` without `EIP712Domain` (`toCoreTypedData`).
    pub fn message(payload: &Value) -> Result<Approved, Error> {
        let fields = bind::object(
            payload,
            "payload",
            &["safe", "chain_id", "method", "params"],
            &[],
        )?;
        let (safe, chain_id) = safe_and_chain(fields)?;
        let params = fields["params"]
            .as_array()
            .ok_or_else(|| invalid("Signature request is required"))?;
        let digest = match fields["method"].as_str() {
            Some("personal_sign") => {
                let message = params
                    .first()
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("Message is required"))?;
                eip191_digest(&message_bytes(message)?)
            }
            Some("eth_signTypedData_v4") => typed_digest(params.get(1))?,
            _ => return Err(invalid("Unsupported signing method for Safe accounts")),
        };
        Ok(Approved::Message {
            safe,
            chain_id,
            digest,
        })
    }

    /// A `safe-send`'s Safe: a Safe has one pending SafeTx.
    fn sent_safe(&self) -> Option<&[u8; 20]> {
        match self {
            Approved::Send { safe, .. } => Some(safe),
            Approved::Message { .. } => None,
        }
    }
}

/// What a Safe message signs, as a standing rule judges it (design 0012,
/// "The rules": a Safe message goes as a message or typed data, for the
/// Safe's grant).
#[derive(Debug, Clone)]
pub enum SafeSigned {
    /// `personal_sign`: the bytes, as `normalizeMessage` reads them.
    Message(Vec<u8>),
    /// `eth_signTypedData_v4`: the core's view of the typed data, which
    /// says whether it warns.
    TypedData(TypedDataView),
}

/// A `safe-message`'s payload (`{ safe, chain_id, method, params }`) as a
/// standing rule reads it: the message's bytes, or the view of its typed
/// data (`domain` as `{}` when falsy, `types` without `EIP712Domain`, the
/// request's `primaryType`) on the Safe's chain, the one the page asked on.
pub fn standing_signed(payload: &Value, max_view_len: usize) -> Result<SafeSigned, Error> {
    let fields = bind::object(
        payload,
        "payload",
        &["safe", "chain_id", "method", "params"],
        &[],
    )?;
    let (_, chain_id) = safe_and_chain(fields)?;
    let params = fields["params"]
        .as_array()
        .ok_or_else(|| invalid("Signature request is required"))?;
    match fields["method"].as_str() {
        Some("personal_sign") => {
            let message = params
                .first()
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("Message is required"))?;
            Ok(SafeSigned::Message(message_bytes(message)?))
        }
        Some("eth_signTypedData_v4") => {
            let parsed;
            let typed = match params.get(1) {
                Some(Value::String(text)) => {
                    parsed = parse_json(text).map_err(|_| invalid("Typed data is not JSON"))?;
                    &parsed
                }
                Some(value) => value,
                None => return Err(invalid("Typed data is required")),
            };
            let typed = typed
                .as_object()
                .ok_or_else(|| invalid("Typed data is required"))?;
            let empty = Value::Object(Map::new());
            let domain = if falsy(typed.get("domain")) {
                &empty
            } else {
                &typed["domain"]
            };
            let mut types = typed
                .get("types")
                .and_then(Value::as_object)
                .cloned()
                .ok_or_else(|| invalid("types: expected an object"))?;
            types.shift_remove("EIP712Domain");
            let message = typed
                .get("message")
                .ok_or_else(|| invalid("missing field message"))?;
            let view = typed_data_view(
                domain,
                &Value::Object(types),
                message,
                &ViewRequest {
                    primary_type: typed.get("primaryType"),
                    chain_id: Some(U256::from_u64(chain_id)),
                    max_len: max_view_len,
                },
            )
            .map_err(|e| invalid(e.to_string()))?;
            Ok(SafeSigned::TypedData(view))
        }
        _ => Err(invalid("Unsupported signing method for Safe accounts")),
    }
}

/// The payload's Safe and its chain, as the binding reads them.
fn safe_and_chain(fields: &Map<String, Value>) -> Result<([u8; 20], u64), Error> {
    let chain_id = bind::quantity(&fields["chain_id"], "chain_id")?
        .to_u64()
        .filter(|n| (1..=MAX_CHAIN_ID).contains(n))
        .ok_or_else(|| invalid("Invalid chainId"))?;
    Ok((address(&fields["safe"], "safe")?, chain_id))
}

fn address(value: &Value, field: &str) -> Result<[u8; 20], Error> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid(format!("Invalid {field}")))?;
    parse_address(text).map_err(|_| invalid(format!("Invalid {field}")))
}

/// `normalizeMessage`: `0x` and pairs of hex digits as bytes, any other
/// text as its UTF-8.
fn message_bytes(message: &str) -> Result<Vec<u8>, Error> {
    match message.strip_prefix("0x") {
        Some(digits) => {
            if !digits.len().is_multiple_of(2) || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid("Invalid hex message"));
            }
            parse_bytes(message, "message").map_err(|_| invalid("Invalid hex message"))
        }
        None => Ok(message.as_bytes().to_vec()),
    }
}

/// JavaScript's falsiness, for a JSON value.
fn falsy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => !b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|n| n == 0.0),
        Some(Value::String(s)) => s.is_empty(),
        Some(_) => false,
    }
}

fn typed_digest(typed: Option<&Value>) -> Result<[u8; 32], Error> {
    let parsed;
    let typed = match typed {
        Some(Value::String(text)) => {
            parsed = parse_json(text).map_err(|_| invalid("Typed data is not JSON"))?;
            &parsed
        }
        Some(value) => value,
        None => return Err(invalid("Typed data is required")),
    };
    let typed = typed
        .as_object()
        .ok_or_else(|| invalid("Typed data is required"))?;
    let empty = Value::Object(Map::new());
    let domain = if falsy(typed.get("domain")) {
        &empty
    } else {
        &typed["domain"]
    };
    let mut types = typed
        .get("types")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| invalid("types: expected an object"))?;
    types.shift_remove("EIP712Domain");
    let message = typed
        .get("message")
        .ok_or_else(|| invalid("missing field message"))?;
    typed_data_hash(domain, &Value::Object(types), message).map_err(|e| invalid(e.to_string()))
}

/// Why a Safe approval doesn't cover a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SafeRefusal {
    /// Never recorded, ended, or dropped (`unknown_token`).
    #[error("unknown or ended Safe approval")]
    Unknown,
    /// Presented by another caller or page, or for another request
    /// (`mismatch`).
    #[error("request differs from what was approved")]
    Mismatch,
    /// The executor's fee isn't one the check approves on its own
    /// (`fee_check`): the user confirms it with an `executor-send` token.
    #[error("the fee needs the user's confirmation")]
    FeeCheck,
}

/// An owner's signature the approval covers: [`SafeApprovals::owner_signed`]
/// takes it once the signature is made.
#[derive(Debug)]
pub struct OwnerCheck {
    id: Zeroizing<[u8; 16]>,
    hash: [u8; 32],
}

/// The executor's transaction the approval covers:
/// [`SafeApprovals::executor_signed`] takes it once it is signed.
#[derive(Debug)]
pub struct ExecutorCheck {
    id: Zeroizing<[u8; 16]>,
}

struct Entry {
    id: Zeroizing<[u8; 16]>,
    holder: Holder,
    approved: Approved,
    /// The SafeTx's EIP-712 hash, once an owner signed it. A SafeMessage's
    /// is known from the spend.
    fixed: Option<[u8; 32]>,
}

/// The open Safe approvals, oldest first. Kept in memory only: after a
/// restart an owner that hasn't signed, or the executor, needs a new
/// confirmation (`safe-approval`).
#[derive(Default)]
pub struct SafeApprovals {
    entries: Vec<Entry>,
}

impl fmt::Debug for SafeApprovals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafeApprovals")
            .field("open", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl SafeApprovals {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many are open.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Records an approval and returns its id. A `safe-send`'s ends the
    /// same Safe's older `safe-send` approval, as a Safe has one pending
    /// SafeTx; past [`MAX_SAFE_APPROVALS`] the oldest is dropped. A failed
    /// RNG records nothing and ends nothing.
    pub fn record<R: TryCryptoRng + ?Sized>(
        &mut self,
        holder: Holder,
        approved: Approved,
        rng: &mut R,
    ) -> Result<SafeId, Error> {
        let mut id = Zeroizing::new([0u8; 16]);
        rng.try_fill_bytes(&mut id[..])
            .map_err(|_| Error::Randomness)?;
        if let Some(safe) = approved.sent_safe() {
            self.entries
                .retain(|entry| entry.approved.sent_safe() != Some(safe));
        }
        // An id is one entry: drawn again, it replaces the old one.
        if let Some(index) = self.position(&id) {
            self.entries.remove(index);
        }
        while self.entries.len() >= MAX_SAFE_APPROVALS {
            self.entries.remove(0);
        }
        self.entries.push(Entry {
            id: id.clone(),
            holder,
            approved,
            fixed: None,
        });
        Ok(SafeId(id))
    }

    /// Ends an approval: whether it was open. An id that isn't one ends
    /// nothing.
    pub fn end(&mut self, id: &str) -> bool {
        match self.presented(id) {
            Some(index) => {
                self.entries.remove(index);
                true
            }
            None => false,
        }
    }

    /// Whether an owner's `sign.typed_data` request is one the approval
    /// covers. `presenter` is the caller's [`Holder`] (`None` for
    /// `chrome`, which presents none); `typed_data` the request's
    /// `typed_data` object, and `hash` its EIP-712 hash as `sign.typed_data`
    /// computed it.
    pub fn check_owner(
        &self,
        id: &str,
        presenter: Option<&Holder>,
        typed_data: &Value,
        hash: &[u8; 32],
    ) -> Result<OwnerCheck, SafeRefusal> {
        let entry = self.entry(id, presenter)?;
        let expected = match (&entry.fixed, &entry.approved) {
            // The approved Safe's domain, at every owner's signature: the
            // request can't choose the Safe or the chain.
            (
                _,
                Approved::Message {
                    safe,
                    chain_id,
                    digest,
                },
            ) => {
                let chain_id = U256::from_u64(*chain_id);
                let domain = typed_data.get("domain").ok_or(SafeRefusal::Mismatch)?;
                let same_chain = domain.get("chainId").and_then(quantity) == Some(chain_id);
                let same_safe = domain
                    .get("verifyingContract")
                    .and_then(Value::as_str)
                    .and_then(|text| parse_address(text).ok())
                    .is_some_and(|verifying| verifying == *safe);
                if !(same_chain && same_safe) {
                    return Err(SafeRefusal::Mismatch);
                }
                safe_message_hash(safe, &chain_id, digest).ok_or(SafeRefusal::Mismatch)?
            }
            (Some(fixed), Approved::Send { .. }) => *fixed,
            (
                None,
                Approved::Send {
                    safe,
                    chain_id,
                    to,
                    value,
                    data,
                },
            ) => {
                let nonce = typed_data
                    .get("message")
                    .and_then(|message| message.get("nonce"))
                    .and_then(quantity)
                    .ok_or(SafeRefusal::Mismatch)?;
                safe_tx_hash(safe, &U256::from_u64(*chain_id), to, value, data, &nonce)
                    .ok_or(SafeRefusal::Mismatch)?
            }
        };
        if expected != *hash {
            return Err(SafeRefusal::Mismatch);
        }
        Ok(OwnerCheck {
            id: entry.id.clone(),
            hash: expected,
        })
    }

    /// An owner signed what [`SafeApprovals::check_owner`] checked: the
    /// first fixes a SafeTx's hash (a SafeMessage's is fixed at the spend).
    /// Nothing, if the approval has ended since.
    pub fn owner_signed(&mut self, check: OwnerCheck) {
        if let Some(index) = self.position(&check.id) {
            let entry = &mut self.entries[index];
            if matches!(entry.approved, Approved::Send { .. }) {
                entry.fixed.get_or_insert(check.hash);
            }
        }
    }

    /// Whether the executor's `sign.transaction` is one the approval
    /// covers: `execTransaction` to the Safe on its chain, `value` 0, the
    /// approved SafeTx field for field (any signatures), and fees the check
    /// approves on its own against `evidence` (the newest
    /// `chain.fee_reference` reply for the chain), as the reference's
    /// `quotedExecutorSend` requires (`autoApprove`).
    pub fn check_executor(
        &self,
        id: &str,
        presenter: Option<&Holder>,
        tx: &Transaction,
        evidence: Option<&Evidence>,
        wall_ms: u64,
        vault_ms: u64,
    ) -> Result<ExecutorCheck, SafeRefusal> {
        let entry = self.entry(id, presenter)?;
        let Approved::Send {
            safe,
            chain_id,
            to,
            value,
            data,
        } = &entry.approved
        else {
            return Err(SafeRefusal::Mismatch);
        };
        let covered = tx.to() == Some(safe)
            && tx.value().is_zero()
            && tx.chain_id().to_u64() == Some(*chain_id)
            && exec_signatures(tx.data())
                .is_some_and(|signatures| exec_call(to, value, data, signatures) == tx.data());
        if !covered {
            return Err(SafeRefusal::Mismatch);
        }
        let reference = reference_fee(evidence, wall_ms, vault_ms);
        if !judge_fees(&Fees::of(tx), reference.as_ref()).auto_approve {
            return Err(SafeRefusal::FeeCheck);
        }
        Ok(ExecutorCheck {
            id: entry.id.clone(),
        })
    }

    /// The executor signed: the approval ends.
    pub fn executor_signed(&mut self, check: ExecutorCheck) {
        if let Some(index) = self.position(&check.id) {
            self.entries.remove(index);
        }
    }

    /// The open approval for `id`, presented by `presenter`.
    fn entry(&self, id: &str, presenter: Option<&Holder>) -> Result<&Entry, SafeRefusal> {
        let entry = self
            .presented(id)
            .map(|index| &self.entries[index])
            .ok_or(SafeRefusal::Unknown)?;
        if presenter != Some(&entry.holder) {
            return Err(SafeRefusal::Mismatch);
        }
        Ok(entry)
    }

    fn presented(&self, id: &str) -> Option<usize> {
        let mut bytes = Zeroizing::new([0u8; 16]);
        if !lower_hex_16(id, &mut bytes) {
            return None;
        }
        self.position(&bytes)
    }

    fn position(&self, id: &[u8; 16]) -> Option<usize> {
        let mut found = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if constant_time_eq(&entry.id, id) && found.is_none() {
                found = Some(index);
            }
        }
        found
    }
}

/// A typed-data quantity: a decimal or `0x` string, or a JSON integer.
fn quantity(value: &Value) -> Option<U256> {
    match value {
        Value::String(text) => parse_unsigned(text),
        Value::Number(n) => n.as_u64().map(U256::from_u64),
        _ => None,
    }
}

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// The SafeTx's EIP-712 hash, as Safe 1.3.0 and later define it, for one
/// call with no refund.
fn safe_tx_hash(
    safe: &[u8; 20],
    chain_id: &U256,
    to: &[u8; 20],
    value: &U256,
    data: &[u8],
    nonce: &U256,
) -> Option<[u8; 32]> {
    let field = |name: &str, kind: &str| json!({ "name": name, "type": kind });
    let types = json!({
        "SafeTx": [
            field("to", "address"),
            field("value", "uint256"),
            field("data", "bytes"),
            field("operation", "uint8"),
            field("safeTxGas", "uint256"),
            field("baseGas", "uint256"),
            field("gasPrice", "uint256"),
            field("gasToken", "address"),
            field("refundReceiver", "address"),
            field("nonce", "uint256"),
        ],
    });
    let domain = json!({ "chainId": chain_id.to_decimal(), "verifyingContract": to_hex(safe) });
    let message = json!({
        "to": to_hex(to),
        "value": value.to_decimal(),
        "data": to_hex(data),
        "operation": "0",
        "safeTxGas": "0",
        "baseGas": "0",
        "gasPrice": "0",
        "gasToken": ZERO_ADDRESS,
        "refundReceiver": ZERO_ADDRESS,
        "nonce": nonce.to_decimal(),
    });
    typed_data_hash(&domain, &types, &message).ok()
}

/// The SafeMessage's EIP-712 hash (`getEip712MessageTypes` for 1.3.0 and
/// later).
fn safe_message_hash(safe: &[u8; 20], chain_id: &U256, digest: &[u8; 32]) -> Option<[u8; 32]> {
    let types = json!({ "SafeMessage": [{ "name": "message", "type": "bytes" }] });
    let domain = json!({ "chainId": chain_id.to_decimal(), "verifyingContract": to_hex(safe) });
    let message = json!({ "message": to_hex(digest) });
    typed_data_hash(&domain, &types, &message).ok()
}

fn word(bytes: &[u8]) -> [u8; 32] {
    let mut word = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    word[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
    word
}

fn padded(len: usize) -> usize {
    len.div_ceil(32).saturating_mul(32)
}

/// `execTransaction(to, value, data, 0, 0, 0, 0, 0, 0, signatures)`,
/// ABI-encoded as ethers encodes it.
fn exec_call(to: &[u8; 20], value: &U256, data: &[u8], signatures: &[u8]) -> Vec<u8> {
    let head = 10 * 32;
    let data_offset = head;
    let signatures_offset = head + 32 + padded(data.len());
    let mut call = Vec::with_capacity(4 + signatures_offset + 32 + padded(signatures.len()));
    call.extend_from_slice(&exec_selector());
    call.extend_from_slice(&word(to));
    call.extend_from_slice(&value.to_be_bytes());
    call.extend_from_slice(&word(&(data_offset as u64).to_be_bytes()));
    // operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver.
    call.extend_from_slice(&[0u8; 6 * 32]);
    call.extend_from_slice(&word(&(signatures_offset as u64).to_be_bytes()));
    for bytes in [data, signatures] {
        call.extend_from_slice(&word(&(bytes.len() as u64).to_be_bytes()));
        call.extend_from_slice(bytes);
        call.resize(call.len() + padded(bytes.len()) - bytes.len(), 0);
    }
    call
}

/// The signatures an `execTransaction` call carries, read from where its
/// own head puts them; `None` when it isn't one. The call is then compared
/// whole with [`exec_call`]'s encoding, so anything else in it is checked
/// there.
fn exec_signatures(call: &[u8]) -> Option<&[u8]> {
    let body = call.strip_prefix(&exec_selector()[..])?;
    let read = |at: usize| -> Option<usize> {
        let word = body.get(at..at.checked_add(32)?)?;
        let (high, low) = word.split_at(24);
        if high.iter().any(|b| *b != 0) {
            return None;
        }
        usize::try_from(u64::from_be_bytes(low.try_into().ok()?)).ok()
    };
    let offset = read(9 * 32)?;
    let len = read(offset)?;
    let start = offset.checked_add(32)?;
    body.get(start..start.checked_add(len)?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    struct Counter(u8);

    #[derive(Debug)]
    struct Never;

    impl fmt::Display for Never {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("never")
        }
    }

    impl std::error::Error for Never {}

    impl rand_core::TryRng for Counter {
        type Error = Never;

        fn try_next_u32(&mut self) -> Result<u32, Never> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Never> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Never> {
            self.0 = self.0.wrapping_add(1);
            dst.fill(self.0);
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for Counter {}

    const SAFE: &str = "0x1111111111111111111111111111111111111111";
    const OTHER_SAFE: &str = "0x2222222222222222222222222222222222222222";
    const TO: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

    fn send_payload(safe: &str) -> Value {
        json!({ "safe": safe, "chain_id": "100", "tx": { "to": TO, "value": "1000", "data": "0xa9059cbb" } })
    }

    fn page(navigation: u64) -> Holder {
        Holder::Page {
            origin: "https://app.example".into(),
            frame: 1,
            navigation,
        }
    }

    fn safe_tx(safe: &str, nonce: Value, operation: &str) -> Value {
        json!({
            "domain": { "chainId": 100, "verifyingContract": safe },
            "types": { "SafeTx": [
                { "name": "to", "type": "address" },
                { "name": "value", "type": "uint256" },
                { "name": "data", "type": "bytes" },
                { "name": "operation", "type": "uint8" },
                { "name": "safeTxGas", "type": "uint256" },
                { "name": "baseGas", "type": "uint256" },
                { "name": "gasPrice", "type": "uint256" },
                { "name": "gasToken", "type": "address" },
                { "name": "refundReceiver", "type": "address" },
                { "name": "nonce", "type": "uint256" },
            ]},
            "message": {
                "to": TO, "value": "1000", "data": "0xa9059cbb", "operation": operation,
                "safeTxGas": "0", "baseGas": "0", "gasPrice": "0",
                "gasToken": ZERO_ADDRESS, "refundReceiver": ZERO_ADDRESS, "nonce": nonce,
            },
        })
    }

    fn hash_of(typed: &Value) -> [u8; 32] {
        let mut types = typed["types"].as_object().unwrap().clone();
        types.shift_remove("EIP712Domain");
        typed_data_hash(&typed["domain"], &Value::Object(types), &typed["message"]).unwrap()
    }

    /// The SafeTx hash protocol-kit computes (`hashSafeTransaction` in
    /// the reference's `safe-executor.js`, protocol-kit 6 and ethers 6) for
    /// this SafeTx at nonce 7, checked with the reference checkout's
    /// modules.
    #[test]
    fn the_safe_tx_hash_is_protocol_kits() {
        let typed = safe_tx(SAFE, json!("7"), "0");
        assert_eq!(
            to_hex(&hash_of(&typed)),
            to_hex(
                &safe_tx_hash(
                    &parse_address(SAFE).unwrap(),
                    &U256::from_u64(100),
                    &parse_address(TO).unwrap(),
                    &U256::from_u64(1000),
                    &[0xa9, 0x05, 0x9c, 0xbb],
                    &U256::from_u64(7),
                )
                .unwrap()
            )
        );
        assert_eq!(to_hex(&hash_of(&typed)), SAFE_TX_HASH);
    }

    // ethers 6.17's `TypedDataEncoder.hash` and protocol-kit 8.0.7's
    // `calculateSafeTransactionHash` over the SafeTx above (1.4.1's
    // `getEip712TxTypes`), with freedom-browser's modules: both give this.
    const SAFE_TX_HASH: &str = "0x998cd39c6cfdaab308838998ee0456944f47c736e91444969dacc84abf967597";

    /// The SafeMessage hash for `hello` under the Safe on chain 100, as
    /// ethers 6.17 hashes it with protocol-kit 8.0.7's
    /// `getEip712MessageTypes('1.4.1')`.
    #[test]
    fn the_safe_message_hash_is_protocol_kits() {
        let hash = safe_message_hash(
            &parse_address(SAFE).unwrap(),
            &U256::from_u64(100),
            &eip191_digest(b"hello"),
        )
        .unwrap();
        assert_eq!(
            to_hex(&hash),
            "0x5f19309ed0ecec869313687ae3a6b8f9135c4d3997dc973eb66bc07f9374925d"
        );
    }

    /// `execTransaction`'s call as ethers 6.17's `Interface` encodes it
    /// (the reference's `EXEC_INTERFACE`), for the SafeTx above and 65
    /// bytes of signatures.
    #[test]
    fn the_exec_call_is_ethers() {
        let call = exec_call(
            &parse_address(TO).unwrap(),
            &U256::from_u64(1000),
            &[0xa9, 0x05, 0x9c, 0xbb],
            &[0x5a; 65],
        );
        let expected = format!(
            "0x6a761202{:0>64}{:0>64}{:0>64}{}{:0>64}{:0>64}{:0<64}{:0>64}{}{}",
            "833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "3e8",
            "140",
            "0".repeat(6 * 64),
            "180",
            "4",
            "a9059cbb",
            "41",
            "5a".repeat(65),
            "0".repeat(62),
        );
        assert_eq!(to_hex(&call), expected);
        assert_eq!(&exec_selector(), &[0x6a, 0x76, 0x12, 0x02]);
    }

    #[test]
    fn the_first_owner_fixes_the_safe_tx() {
        let mut safes = SafeApprovals::new();
        let mut rng = Counter(0);
        let approved = Approved::send(&send_payload(SAFE)).unwrap();
        let id = safes.record(page(1), approved, &mut rng).unwrap();
        let id = id.to_text();
        let nonce7 = safe_tx(SAFE, json!("7"), "0");
        let nonce8 = safe_tx(SAFE, json!(8), "0");
        // Another page, another navigation, a wallet's caller, chrome.
        for presenter in [Some(page(2)), Some(Holder::Wallet), None] {
            assert_eq!(
                safes
                    .check_owner(&id, presenter.as_ref(), &nonce7, &hash_of(&nonce7))
                    .unwrap_err(),
                SafeRefusal::Mismatch
            );
        }
        // Another Safe, another operation, a hash that isn't the request's.
        for typed in [
            safe_tx(OTHER_SAFE, json!("7"), "0"),
            safe_tx(SAFE, json!("7"), "1"),
        ] {
            assert_eq!(
                safes
                    .check_owner(&id, Some(&page(1)), &typed, &hash_of(&typed))
                    .unwrap_err(),
                SafeRefusal::Mismatch
            );
        }
        let check = safes
            .check_owner(&id, Some(&page(1)), &nonce7, &hash_of(&nonce7))
            .unwrap();
        // Until an owner has signed, another nonce is the token's SafeTx.
        assert!(
            safes
                .check_owner(&id, Some(&page(1)), &nonce8, &hash_of(&nonce8))
                .is_ok()
        );
        safes.owner_signed(check);
        assert_eq!(
            safes
                .check_owner(&id, Some(&page(1)), &nonce8, &hash_of(&nonce8))
                .unwrap_err(),
            SafeRefusal::Mismatch
        );
        assert!(
            safes
                .check_owner(&id, Some(&page(1)), &nonce7, &hash_of(&nonce7))
                .is_ok()
        );
        assert!(safes.end(&id));
        assert!(!safes.end(&id));
        assert_eq!(
            safes
                .check_owner(&id, Some(&page(1)), &nonce7, &hash_of(&nonce7))
                .unwrap_err(),
            SafeRefusal::Unknown
        );
    }

    /// A Safe message for [`SAFE`] on chain 100.
    fn safe_message_of(digest: u8) -> Approved {
        Approved::Message {
            safe: parse_address(SAFE).unwrap(),
            chain_id: 100,
            digest: [digest; 32],
        }
    }

    fn message_payload(method: &str, params: Value) -> Value {
        json!({ "safe": SAFE, "chain_id": "100", "method": method, "params": params })
    }

    fn envelope(safe: &str, chain_id: Value, digest: &[u8]) -> Value {
        json!({
            "domain": { "chainId": chain_id, "verifyingContract": safe },
            "types": { "SafeMessage": [{ "name": "message", "type": "bytes" }] },
            "message": { "message": to_hex(digest) },
        })
    }

    #[test]
    fn a_safe_message_signs_its_digest() {
        let mut safes = SafeApprovals::new();
        let mut rng = Counter(0);
        let payload = message_payload("personal_sign", json!(["0x68656c6c6f", SAFE]));
        let approved = Approved::message(&payload).unwrap();
        let digest = eip191_digest(b"hello");
        assert_eq!(
            approved,
            Approved::Message {
                safe: parse_address(SAFE).unwrap(),
                chain_id: 100,
                digest,
            }
        );
        // Its text is the same message (`normalizeMessage`).
        let text = message_payload("personal_sign", json!(["hello"]));
        assert_eq!(Approved::message(&text).unwrap(), approved);
        let id = safes.record(page(1), approved, &mut rng).unwrap().to_text();
        let other = envelope(SAFE, json!("100"), &eip191_digest(b"other"));
        assert_eq!(
            safes
                .check_owner(&id, Some(&page(1)), &other, &hash_of(&other))
                .unwrap_err(),
            SafeRefusal::Mismatch
        );
        let first = envelope(SAFE, json!("100"), &digest);
        let check = safes
            .check_owner(&id, Some(&page(1)), &first, &hash_of(&first))
            .unwrap();
        safes.owner_signed(check);
        // Every later owner signs the same SafeMessage, its chain spelled
        // as any quantity.
        for chain_id in [json!("100"), json!(100), json!("0x64")] {
            let later = envelope(SAFE, chain_id, &digest);
            assert!(
                safes
                    .check_owner(&id, Some(&page(1)), &later, &hash_of(&later))
                    .is_ok()
            );
        }
    }

    /// A Safe message is the approved Safe's, on its chain: Safe B's
    /// address, another chain, or both are refused at the first owner's
    /// signature and at every later one, each with its own correct hash
    /// and the approved digest.
    #[test]
    fn a_safe_message_is_the_approved_safes() {
        let mut safes = SafeApprovals::new();
        let mut rng = Counter(0);
        let digest = eip191_digest(b"hello");
        let approved = Approved::message(&message_payload("personal_sign", json!(["hello"])));
        let id = safes
            .record(page(1), approved.unwrap(), &mut rng)
            .unwrap()
            .to_text();
        let mut elsewhere = vec![
            envelope(OTHER_SAFE, json!("100"), &digest),
            envelope(SAFE, json!("1"), &digest),
            envelope(OTHER_SAFE, json!("1"), &digest),
        ];
        // A domain without its chain or its Safe, and none at all.
        let mut bare = envelope(SAFE, json!("100"), &digest);
        bare["domain"] = json!({ "verifyingContract": SAFE });
        elsewhere.push(bare.clone());
        bare["domain"] = json!({ "chainId": "100" });
        elsewhere.push(bare.clone());
        bare.as_object_mut().unwrap().remove("domain");
        let refused = |safes: &SafeApprovals, elsewhere: &[Value]| {
            for typed in elsewhere {
                let hash = typed_data_hash(
                    typed.get("domain").unwrap_or(&json!({})),
                    &typed["types"],
                    &typed["message"],
                )
                .unwrap();
                assert_eq!(
                    safes
                        .check_owner(&id, Some(&page(1)), typed, &hash)
                        .unwrap_err(),
                    SafeRefusal::Mismatch,
                    "{typed}"
                );
            }
        };
        refused(&safes, &elsewhere);
        refused(&safes, std::slice::from_ref(&bare));
        let first = envelope(SAFE, json!("100"), &digest);
        let check = safes
            .check_owner(&id, Some(&page(1)), &first, &hash_of(&first))
            .unwrap();
        safes.owner_signed(check);
        refused(&safes, &elsewhere);
        assert!(
            safes
                .check_owner(&id, Some(&page(1)), &first, &hash_of(&first))
                .is_ok()
        );
    }

    #[test]
    fn a_safe_message_digest_is_the_verifiers() {
        let typed = json!({
            "types": {
                "EIP712Domain": [{ "name": "name", "type": "string" }],
                "Mail": [{ "name": "contents", "type": "string" }],
            },
            "domain": { "name": "Ether Mail" },
            "primaryType": "Mail",
            "message": { "contents": "Hello" },
        });
        let expected = typed_data_hash(
            &json!({ "name": "Ether Mail" }),
            &json!({ "Mail": [{ "name": "contents", "type": "string" }] }),
            &json!({ "contents": "Hello" }),
        )
        .unwrap();
        for params in [
            json!([SAFE, typed.clone()]),
            json!([SAFE, typed.to_string()]),
        ] {
            let payload = message_payload("eth_signTypedData_v4", params);
            assert_eq!(
                Approved::message(&payload).unwrap(),
                Approved::Message {
                    safe: parse_address(SAFE).unwrap(),
                    chain_id: 100,
                    digest: expected,
                }
            );
        }
        let mut refused = vec![
            message_payload("eth_sign", json!([SAFE, "0x00"])),
            message_payload("personal_sign", json!(["0x6"])),
            message_payload("personal_sign", json!([7])),
            message_payload("eth_signTypedData_v4", json!([SAFE])),
            message_payload("personal_sign", json!("hello")),
        ];
        // The Safe and its chain are required, and checked.
        let hello = message_payload("personal_sign", json!(["hello"]));
        for (field, value) in [
            ("safe", None),
            ("chain_id", None),
            ("safe", Some(json!("0x12"))),
            ("chain_id", Some(json!("0"))),
            ("chain_id", Some(json!(100))),
            ("chain_id", Some(json!(format!("{}", MAX_CHAIN_ID + 1)))),
        ] {
            let mut payload = hello.clone();
            match value {
                Some(value) => payload[field] = value,
                None => {
                    payload.as_object_mut().unwrap().remove(field);
                }
            }
            refused.push(payload);
        }
        for payload in refused {
            assert!(Approved::message(&payload).is_err(), "{payload}");
        }
    }

    fn executor_tx(safe: &str, value: &str, call: &[u8], max_fee: &str) -> Transaction {
        Transaction::from_json(&json!({
            "type": 2,
            "chain_id": "100",
            "nonce": "4",
            "gas_limit": "100000",
            "to": safe,
            "value": value,
            "data": to_hex(call),
            "max_fee_per_gas": max_fee,
            "max_priority_fee_per_gas": "1000000000",
        }))
        .unwrap()
    }

    fn evidence(per_gas: &str) -> Evidence {
        Evidence::read(
            &json!({
                "header": null,
                "lowest_priority": null,
                "quote": { "source": "direct", "type": "eip1559", "maxFeePerGas": per_gas, "answered": 2 },
            }),
            1_000,
        )
    }

    #[test]
    fn the_executor_signs_the_approved_safe_tx_once() {
        let mut safes = SafeApprovals::new();
        let mut rng = Counter(0);
        let approved = Approved::send(&send_payload(SAFE)).unwrap();
        let id = safes
            .record(Holder::Wallet, approved, &mut rng)
            .unwrap()
            .to_text();
        let to = parse_address(TO).unwrap();
        let signatures = [0x5au8; 65];
        let call = exec_call(
            &to,
            &U256::from_u64(1000),
            &[0xa9, 0x05, 0x9c, 0xbb],
            &signatures,
        );
        assert_eq!(exec_signatures(&call), Some(&signatures[..]));
        let good = evidence("2000000000");
        let at = |safes: &SafeApprovals, tx: &Transaction, evidence: Option<&Evidence>| {
            safes.check_executor(&id, Some(&Holder::Wallet), tx, evidence, 0, 2_000)
        };
        let tx = executor_tx(SAFE, "0", &call, "2000000000");
        // Under page, and under chrome.
        assert_eq!(
            safes
                .check_executor(&id, Some(&page(1)), &tx, Some(&good), 0, 2_000)
                .unwrap_err(),
            SafeRefusal::Mismatch
        );
        assert_eq!(
            safes
                .check_executor(&id, None, &tx, Some(&good), 0, 2_000)
                .unwrap_err(),
            SafeRefusal::Mismatch
        );
        // Another Safe, a value, a changed SafeTx field.
        let mut operation = call.clone();
        operation[4 + 3 * 32 + 31] = 1;
        let mut refund = call.clone();
        refund[4 + 6 * 32 + 31] = 1;
        let other_value = exec_call(
            &to,
            &U256::from_u64(1001),
            &[0xa9, 0x05, 0x9c, 0xbb],
            &signatures,
        );
        let mut trailing = call.clone();
        trailing.push(0);
        for tx in [
            executor_tx(OTHER_SAFE, "0", &call, "2000000000"),
            executor_tx(SAFE, "1", &call, "2000000000"),
            executor_tx(SAFE, "0", &operation, "2000000000"),
            executor_tx(SAFE, "0", &refund, "2000000000"),
            executor_tx(SAFE, "0", &other_value, "2000000000"),
            executor_tx(SAFE, "0", &trailing, "2000000000"),
        ] {
            assert_eq!(
                at(&safes, &tx, Some(&good)).unwrap_err(),
                SafeRefusal::Mismatch
            );
        }
        // No evidence, and a fee above three times the reference.
        assert_eq!(at(&safes, &tx, None).unwrap_err(), SafeRefusal::FeeCheck);
        let dear = executor_tx(SAFE, "0", &call, "7000000000");
        assert_eq!(
            at(&safes, &dear, Some(&good)).unwrap_err(),
            SafeRefusal::FeeCheck
        );
        let check = at(&safes, &tx, Some(&good)).unwrap();
        safes.executor_signed(check);
        assert_eq!(
            at(&safes, &tx, Some(&good)).unwrap_err(),
            SafeRefusal::Unknown
        );
    }

    #[test]
    fn a_newer_send_ends_the_safes_older_one_and_64_are_kept() {
        let mut safes = SafeApprovals::new();
        let mut rng = Counter(0);
        let first = safes
            .record(
                page(1),
                Approved::send(&send_payload(SAFE)).unwrap(),
                &mut rng,
            )
            .unwrap()
            .to_text();
        let other = safes
            .record(
                page(1),
                Approved::send(&send_payload(OTHER_SAFE)).unwrap(),
                &mut rng,
            )
            .unwrap()
            .to_text();
        // A message for the same Safe neither ends its send nor is ended by
        // a newer one.
        let message = safes
            .record(page(1), safe_message_of(7), &mut rng)
            .unwrap()
            .to_text();
        let second = safes
            .record(
                page(1),
                Approved::send(&send_payload(SAFE)).unwrap(),
                &mut rng,
            )
            .unwrap()
            .to_text();
        assert!(!safes.end(&first));
        assert_eq!(safes.len(), 3);
        for _ in 0..MAX_SAFE_APPROVALS - 1 {
            safes.record(page(1), safe_message_of(1), &mut rng).unwrap();
        }
        assert_eq!(safes.len(), MAX_SAFE_APPROVALS);
        // The two oldest went.
        assert!(!safes.end(&other));
        assert!(!safes.end(&message));
        assert!(safes.end(&second));
        assert!(!safes.end("not an id"));
        assert_eq!(
            format!(
                "{:?}",
                safes
                    .record(Holder::Wallet, safe_message_of(0), &mut rng)
                    .unwrap()
            ),
            "SafeId(..)"
        );
    }

    /// A Safe message, as a standing rule reads it: a message's bytes, or
    /// the view of its typed data on the Safe's chain.
    #[test]
    fn a_safe_message_as_a_rule_reads_it() {
        let safe = "0x1111111111111111111111111111111111111111";
        let message = json!({ "safe": safe, "chain_id": "100", "method": "personal_sign", "params": ["hello", "0x11"] });
        match standing_signed(&message, 1 << 16).unwrap() {
            SafeSigned::Message(bytes) => assert_eq!(bytes, b"hello"),
            other => panic!("{other:?}"),
        }
        let typed = |chain_id: &str| {
            json!({ "safe": safe, "chain_id": chain_id, "method": "eth_signTypedData_v4", "params": ["0x11", {
                "types": { "EIP712Domain": [{ "name": "chainId", "type": "uint256" }],
                    "Order": [{ "name": "amount", "type": "uint256" }] },
                "domain": { "chainId": 100 }, "primaryType": "Order", "message": { "amount": "1" },
            }] })
        };
        let chain = |chain_id: &str| match standing_signed(&typed(chain_id), 1 << 16).unwrap() {
            SafeSigned::TypedData(view) => {
                let view: Value = serde_json::from_str(&view.view).unwrap();
                view["chain"].clone()
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(chain("100"), "match");
        assert_eq!(chain("1"), "mismatch");
        let other = json!({ "safe": safe, "chain_id": "100", "method": "eth_sign", "params": [] });
        assert!(standing_signed(&other, 1 << 16).is_err());
        let unbound = json!({ "method": "personal_sign", "params": ["hello"] });
        assert!(standing_signed(&unbound, 1 << 16).is_err());
    }
}
