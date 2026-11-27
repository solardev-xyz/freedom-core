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
//! before. The chrome reaches no SOC: from SWM-4 the method table admits
//! only `page` and `shell` to `swarm.sign_soc` (design 0015's amendment to
//! 0002), so its call is `forbidden` before any of this, and the row goes
//! at SWM-9. A `page` caller sends its `PageContext`.
//!
//! Once `core.hello` names `vault_meta` in `store_moved` (G20b), an account
//! key signs only for an index the core's own records give the vault: below
//! the hardware range, with a mnemonic record or none. A Ledger's, a
//! phone's, a Safe's, another type's or any hardware index is refused
//! `invalid_argument` with the reference's text (`getSigner`,
//! `withVaultAccount`), after the public work and before the authorization
//! or the key ([`crate::accounts::vault_signs`]); while a vault journal
//! remains the records answer `storage`. Before the move main routes a
//! device's account to its device, and its word stands.
//!
//! Typed data comes with the view of exactly what is signed (#88), which
//! fc-evm writes as JSON text in the pass that hashes; the reply carries it
//! as written. `sign.typed_data` signs only the digest the caller confirmed
//! (`expected_hash`), and both typed-data methods refuse data whose signing
//! reply, at the largest request ID, wouldn't fit one frame.
//!
//! **A Ledger key** (design 0016, "Accounts", API; LDG-2's L4), `{ kind:
//! "ledger", index, path?, address? }`, signs `sign.transaction`,
//! `sign.message` and `sign.typed_data` on the device lane, so each method
//! is split in two:
//! - **[`prepare`]** does everything a vault key's request does before its
//!   key: the public work, then the record (D9: only once `vault_meta` is
//!   moved, `not_moved` before; account `index`'s Ledger record, and a
//!   `path` or `address` given must be the record's), then fc-ledger's
//!   operation, which refuses what a Ledger can't carry
//!   (`device_failed`, `LEDGER_TOO_LARGE`, `LEDGER_EMPTY_MESSAGE` or
//!   `LEDGER_TYPE_NOT_CANONICAL`), then the authorization, checked and
//!   spent as for a vault key (a presented token burnt however the request
//!   ends, so a cancel finds it gone). A vault key then signs at once, as
//!   before ([`Prepared::Now`]); a Ledger key's operation goes to the lane
//!   with what the authorization does once signed ([`Prepared::Device`]).
//! - **[`finish`]**, once the device's signature came back and fc-ledger
//!   checked it (recovered against the record's address over the digest
//!   the user confirmed): what the authorization does on a signature
//!   ([`crate::approvals::Approvals::device_signed`]: a flagged
//!   `dapp-send`'s rule written, a Safe approval checked again and fixed or
//!   ended), and the reply, 0002's. A cancel or a failure on the device
//!   ends the request with nothing returned, and the authorization does
//!   nothing more.
//!
//! The vault isn't needed unlocked for a Ledger key, and no vault key is
//! derived for one. [`handle`] signs with the vault's keys alone, for the
//! callers that sign in one turn.

use std::sync::OnceLock;

use fc_evm::{SignedTransaction, Transaction, ViewRequest, checksum_address, parse_bytes, to_hex};
use fc_keys::Secp256k1Key;
use fc_ledger::{LedgerPath, Operation};
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

/// Which signers a call reaches: [`prepare`]'s, a Ledger's too; [`handle`]'s,
/// the vault's alone, which refuses a Ledger key as an unknown kind.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Signers {
    VaultOnly,
    WithLedger,
}

/// A Ledger key reference (design 0016, "Accounts"): the record's index,
/// and the path and address the caller says it has.
struct LedgerKey {
    index: u32,
    path: Option<LedgerPath>,
    address: Option<[u8; 20]>,
}

/// An account method's key.
enum Signer {
    Vault(KeyRef),
    Ledger(LedgerKey),
}

/// How the signature is made once authorized.
enum Signing {
    /// The vault's key, derived for the one digest.
    Vault(KeyRef),
    /// The device's operation, on the lane.
    Device(Operation),
}

/// A signing request, its public work done and its authorization checked.
pub enum Prepared {
    /// Its reply now: a vault key's signature, `typed_data.hash`'s or
    /// `swarm.sign_soc`'s result, or a refusal.
    Now(Result<Box<RawValue>, ErrorBody>),
    /// A Ledger key's operation, for the device lane: [`finish`] answers
    /// once the device signed.
    Device(Box<Device>),
}

/// A Ledger key's request on its way to the device lane.
pub struct Device {
    /// fc-ledger's operation, built from the request and the record.
    pub operation: Operation,
    /// What [`finish`] needs once it signed.
    pub pending: Pending,
}

/// What a Ledger signature's reply needs once the device signed: what its
/// authorization does then, and the reply's form.
pub struct Pending {
    after: After,
    reply: Reply,
}

/// Its kinds alone: a view is request data, and a Safe approval's ID a
/// credential, so neither is printed.
impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let after = match self.after {
            After::Nothing => "nothing",
            After::Owner(_) => "owner",
            After::Executor(_) => "executor",
            After::Remember(_) => "remember",
        };
        let reply = match self.reply {
            Reply::Transaction => "transaction",
            Reply::Message => "message",
            Reply::TypedData { .. } => "typed_data",
        };
        f.debug_struct("Pending")
            .field("after", &after)
            .field("reply", &reply)
            .finish()
    }
}

/// A Ledger signature's reply: 0002's for its method.
enum Reply {
    Transaction,
    Message,
    /// `sign.typed_data`'s, with the view of what was signed, as written.
    TypedData {
        view: String,
    },
}

/// A request's end in this turn, or its device operation.
enum Done {
    Reply(Box<RawValue>),
    Device(Box<Device>),
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

/// An account method's `key`: a vault account's, or, where the call
/// reaches one, a Ledger's.
fn account_key(value: &Value, signers: Signers) -> Result<Signer, ErrorBody> {
    if signers == Signers::WithLedger && value.get("kind").and_then(Value::as_str) == Some("ledger")
    {
        return ledger_key(value).map(Signer::Ledger);
    }
    key_ref(value, Allowed::AccountsOnly).map(Signer::Vault)
}

/// `{ kind: "ledger", index, path?, address? }`, exactly (design 0016,
/// API): a path in one of the schemes' texts, an address in any form a
/// record's may have.
fn ledger_key(value: &Value) -> Result<LedgerKey, ErrorBody> {
    let fields = object(value, &["kind", "index"], &["path", "address"])?;
    let index = index(fields.get("index"))?;
    let path = match fields.get("path") {
        None => None,
        Some(Value::String(text)) => Some(
            LedgerPath::parse(text).map_err(|_| invalid("path: not a Ledger account's path"))?,
        ),
        Some(_) => return Err(invalid("path: expected a string")),
    };
    let address = match fields.get("address") {
        None => None,
        Some(Value::String(text)) => Some(
            fc_wallet_state::address_bytes(text)
                .ok_or_else(|| invalid("address: expected an address"))?,
        ),
        Some(_) => return Err(invalid("address: expected a string")),
    };
    Ok(LedgerKey {
        index,
        path,
        address,
    })
}

/// The record a Ledger key signs with (D9): `not_moved` before
/// `vault_meta` is moved; account `index`'s Ledger record; and the `path`
/// and `address` the caller gave, each the record's.
fn ledger_record(checks: &Checks<'_>, key: &LedgerKey) -> Result<fc_ledger::Account, ErrorBody> {
    let account = checks.approvals.ledger_account(key.index)?;
    if key.path.as_ref().is_some_and(|path| *path != account.path) {
        return Err(invalid("path: not the Ledger account's"));
    }
    if key
        .address
        .is_some_and(|address| address != account.address)
    {
        return Err(invalid("address: not the Ledger account's"));
    }
    Ok(account)
}

/// fc-ledger's refusal before the first APDU: what a Ledger can't carry
/// is `device_failed` with its code (design 0016, API); anything else an
/// invalid request.
fn device_refusal(refusal: fc_ledger::Refusal) -> ErrorBody {
    match refusal.code() {
        Some(code) => crate::ledger::methods::device_failed(code),
        None => invalid(refusal.to_string()),
    }
}

/// How the request is signed, after its public work and before its
/// authorization: a vault account's index the core's records give the
/// vault ([`vault_account`]), or a Ledger's record and its operation,
/// `build` given the record. The account's index, for the authorization.
fn signing(
    checks: &Checks<'_>,
    signer: Signer,
    build: impl FnOnce(fc_ledger::Account) -> Result<Operation, fc_ledger::Refusal>,
) -> Result<(u32, Signing), ErrorBody> {
    match signer {
        Signer::Vault(key) => Ok((vault_account(checks, key)?, Signing::Vault(key))),
        Signer::Ledger(key) => {
            let account = ledger_record(checks, &key)?;
            let operation = build(account).map_err(device_refusal)?;
            Ok((key.index, Signing::Device(operation)))
        }
    }
}

/// A Ledger key's request, authorized, for the lane.
fn device(operation: Operation, after: After, reply: Reply) -> Done {
    Done::Device(Box::new(Device {
        operation,
        pending: Pending { after, reply },
    }))
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

/// A chunk key's reference, as `swarm.request`'s machines name it (design
/// 0015, SWM-4): the Bee wallet, or a publisher key at a hardened index.
fn chunk_key(key: fc_swarm_provider::machine::SignKey) -> Result<KeyRef, ErrorBody> {
    match key {
        fc_swarm_provider::machine::SignKey::BeeWallet => Ok(KeyRef::BeeWallet),
        fc_swarm_provider::machine::SignKey::Publisher(index) if index <= 0x7fff_ffff => {
            Ok(KeyRef::Publisher(index))
        }
        fc_swarm_provider::machine::SignKey::Publisher(_) => Err(invalid("Index out of range")),
    }
}

/// The owner of a chunk key (design 0015, `Need::Owner`): the key derived
/// only to take its address, then dropped (wiped).
pub(crate) fn chunk_owner(
    state: &VaultState,
    key: fc_swarm_provider::machine::SignKey,
) -> Result<[u8; 20], ErrorBody> {
    let derived = derive(state, chunk_key(key)?)?;
    Ok(fc_evm::address_of(derived.signing_key()))
}

/// A page's SOC inside `swarm.request` (design 0015, `Need::Sign`): its
/// public work first (fc-swarm's preparation, whose digest covers the
/// chunk the core computed), then the key derived only to sign that digest
/// and take its address. The signature and the owner.
pub(crate) fn chunk_signature(
    state: &VaultState,
    key: fc_swarm_provider::machine::SignKey,
    identifier: &[u8; 32],
    span: u64,
    payload: &[u8],
) -> Result<([u8; 65], [u8; 20]), ErrorBody> {
    let key = chunk_key(key)?;
    let prepared = fc_swarm::prepare_soc(identifier, Some(span), payload)
        .map_err(|e| invalid(e.to_string()))?;
    let derived = derive(state, key)?;
    let signature =
        fc_evm::sign_digest(derived.signing_key(), &prepared.digest()).map_err(evm_error)?;
    Ok((signature, fc_evm::address_of(derived.signing_key())))
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
pub(crate) fn typed_data_view(
    fields: &Map<String, Value>,
) -> Result<fc_evm::TypedDataView, ErrorBody> {
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

/// `typed_data.hash` for a page's typed data (design 0012, APR-5d-1): the
/// core's view, which the reference asked the core for with the same
/// params (`typedDataViewFor`), or the message of the error it answered.
pub(crate) fn page_typed_data_view(params: &str) -> Result<fc_eip1193::sign::TypedView, String> {
    let params = fc_evm::parse_json(params).map_err(|_| String::from("Invalid parameters"))?;
    object(&params, &["typed_data"], &["primary_type", "chain_id"])
        .and_then(typed_data_view)
        .map(|viewed| fc_eip1193::sign::TypedView {
            hash: to_hex(&viewed.hash),
            view: viewed.view,
        })
        .map_err(|body| body.message)
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
/// though no token kind binds a SOC; the chrome's call to
/// `swarm.sign_soc`, refused by the method table, presents none.
const AUTHORIZED: [&str; 4] = [
    "sign.transaction",
    "sign.message",
    "sign.typed_data",
    "swarm.sign_soc",
];

/// An account key's index, once the core's own records say the vault signs
/// for it (G20b): with `vault_meta` moved, a Ledger's, a phone's, a Safe's,
/// any other type's, or any hardware index is refused here, after the
/// public work and before the authorization is checked or any key derived
/// ([`crate::accounts::vault_signs`]). Before the move main's word stands.
fn vault_account(checks: &Checks<'_>, key: KeyRef) -> Result<u32, ErrorBody> {
    let KeyRef::Account(index) = key else {
        return Err(crate::vault::internal());
    };
    checks.approvals.vault_signs(index)?;
    Ok(index)
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

/// Handles one of [`METHODS`] with the vault's keys alone: the JSON
/// result, as written. A Ledger key is an unknown kind here, refused
/// before anything is spent; [`prepare`] reaches one.
pub fn handle(
    state: &VaultState,
    checks: &mut Checks<'_>,
    method: &str,
    params: Option<&str>,
) -> Result<Box<RawValue>, ErrorBody> {
    match run(state, checks, method, params, Signers::VaultOnly) {
        Prepared::Now(result) => result,
        Prepared::Device(_) => Err(crate::vault::internal()),
    }
}

/// Handles one of [`METHODS`] as far as this turn goes (design 0016, L4):
/// a vault key's request to its end, as [`handle`] does; a Ledger key's
/// to its operation for the device lane, authorized, which [`finish`]
/// answers once the device signed.
pub fn prepare(
    state: &VaultState,
    checks: &mut Checks<'_>,
    method: &str,
    params: Option<&str>,
) -> Prepared {
    run(state, checks, method, params, Signers::WithLedger)
}

fn run(
    state: &VaultState,
    checks: &mut Checks<'_>,
    method: &str,
    params: Option<&str>,
    signers: Signers,
) -> Prepared {
    // Numbers as JSON.parse reads them: typed data must hash the integer
    // ethers signs and the approval UI shows (#87).
    let Ok(params) = fc_evm::parse_json(params.unwrap_or("{}")) else {
        return Prepared::Now(Err(invalid("Invalid parameters")));
    };
    // A presented token is burnt however the request ends (design 0012,
    // "Tokens"): one the check spent is already gone, a Ledger key's
    // included, before its operation reaches the lane.
    let presented = AUTHORIZED
        .contains(&method)
        .then(|| crate::approvals::presented_token(&params, true))
        .flatten();
    let result = handle_parsed(state, checks, method, &params, signers);
    if let Some(token) = presented {
        checks.approvals.burn(&token);
    }
    match result {
        Ok(Done::Reply(result)) => Prepared::Now(Ok(result)),
        Ok(Done::Device(device)) => Prepared::Device(device),
        Err(error) => Prepared::Now(Err(error)),
    }
}

/// A Ledger key's request, once the device's signature came back and
/// fc-ledger checked it (design 0016, "Answers the core checks"): what the
/// authorization does on a signature, checked again where it is a Safe
/// approval's ([`Approvals::device_signed`]), then 0002's reply. A refusal
/// there returns nothing of the signature.
pub fn finish(
    approvals: &mut Approvals,
    clocks: Clocks,
    pending: Pending,
    signed: fc_ledger::Signed,
) -> Result<Box<RawValue>, ErrorBody> {
    let Pending { after, reply } = pending;
    match (reply, signed) {
        (Reply::Transaction, fc_ledger::Signed::Transaction(signed)) => {
            let rule = approvals.device_signed(after, clocks)?;
            raw(&transaction_result(&signed, rule))
        }
        (Reply::Message, fc_ledger::Signed::Signature(signature)) => {
            approvals.device_signed(after, clocks)?;
            raw(&json!({ "signature": to_hex(&signature) }))
        }
        (Reply::TypedData { view }, fc_ledger::Signed::Signature(signature)) => {
            approvals.device_signed(after, clocks)?;
            typed_reply(&signature, view)
        }
        // An operation ends with its own kind of result.
        _ => Err(crate::vault::internal()),
    }
}

/// `sign.transaction`'s result: the signed transaction, and what became of
/// a flagged `dapp-send`'s rule.
fn transaction_result(signed: &SignedTransaction, rule: Option<Value>) -> Value {
    let mut result = json!({ "raw": to_hex(&signed.raw), "hash": to_hex(&signed.hash) });
    if let Some(rule) = rule {
        result["rule"] = rule;
    }
    result
}

/// `sign.typed_data`'s result: the signature and the view, as written.
fn typed_reply(signature: &[u8; 65], view: String) -> Result<Box<RawValue>, ErrorBody> {
    let view = view_value(view)?;
    raw(&SignedView {
        signature: to_hex(signature),
        view: &view,
    })
}

fn handle_parsed(
    state: &VaultState,
    checks: &mut Checks<'_>,
    method: &str,
    params: &Value,
    signers: Signers,
) -> Result<Done, ErrorBody> {
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
            let signer = account_key(&fields["key"], signers)?;
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
            let (domain, types, message) = typed_data(&fields["typed_data"])?;
            let (account, signing) = signing(checks, signer, |account| {
                Operation::sign_typed_data(account, domain, types, message, &hashed.hash)
            })?;
            let after = authorize(
                checks,
                fields,
                Signed::TypedData {
                    account,
                    fields,
                    hash: &hashed.hash,
                    view: &hashed,
                },
            )?;
            let key = match signing {
                Signing::Device(operation) => {
                    let reply = Reply::TypedData { view: hashed.view };
                    return Ok(device(operation, after, reply));
                }
                Signing::Vault(key) => key,
            };
            let signature = sign_with(state, key, &hashed.hash)?;
            let _ = checks.approvals.signed(after, checks.clocks);
            typed_reply(&signature, hashed.view).map(Done::Reply)
        }
        "typed_data.hash" => {
            let fields = object(params, &["typed_data"], &["primary_type", "chain_id"])?;
            let hashed = typed_data_view(fields)?;
            let view = view_value(hashed.view)?;
            raw(&HashedView {
                hash: to_hex(&hashed.hash),
                view: &view,
            })
            .map(Done::Reply)
        }
        _ => other(state, checks, method, params, signers),
    }
}

/// The methods without a view.
fn other(
    state: &VaultState,
    checks: &mut Checks<'_>,
    method: &str,
    params: &Value,
    signers: Signers,
) -> Result<Done, ErrorBody> {
    match method {
        "sign.transaction" => {
            let fields = object(params, &["key", "tx"], &["authorization"])?;
            let signer = account_key(&fields["key"], signers)?;
            let tx = Transaction::from_json(&fields["tx"]).map_err(evm_error)?;
            let prepared = tx.prepare().map_err(evm_error)?;
            let (account, signing) = signing(checks, signer, |account| {
                Operation::sign_transaction(account, &tx)
            })?;
            let after = authorize(
                checks,
                fields,
                Signed::Transaction {
                    account,
                    tx_json: &fields["tx"],
                    tx: &tx,
                },
            )?;
            let key = match signing {
                Signing::Device(operation) => {
                    return Ok(device(operation, after, Reply::Transaction));
                }
                Signing::Vault(key) => key,
            };
            let signature = sign_with(state, key, &prepared.digest())?;
            // A flagged `dapp-send`'s rule, written as it signs (design
            // 0012, `token-remember`): the reply says what became of it.
            let rule = checks.approvals.signed(after, checks.clocks);
            let signed = prepared.finish(&signature).map_err(evm_error)?;
            raw(&transaction_result(&signed, rule)).map(Done::Reply)
        }
        "sign.message" => {
            let fields = object(params, &["key", "message"], &["authorization"])?;
            let signer = account_key(&fields["key"], signers)?;
            let message = parse_bytes(string(fields, "message")?, "message").map_err(evm_error)?;
            let (account, signing) = signing(checks, signer, |account| {
                Operation::sign_message(account, message.clone())
            })?;
            let after = authorize(
                checks,
                fields,
                Signed::Message {
                    account,
                    message: &fields["message"],
                    bytes: &message,
                },
            )?;
            let key = match signing {
                Signing::Device(operation) => {
                    return Ok(device(operation, after, Reply::Message));
                }
                Signing::Vault(key) => key,
            };
            let signature = sign_with(state, key, &fc_evm::eip191_digest(&message))?;
            let _ = checks.approvals.signed(after, checks.clocks);
            raw(&json!({ "signature": to_hex(&signature) })).map(Done::Reply)
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
            raw(&json!({
                "signature": to_hex(&signed.signature),
                "owner": checksum_address(&signed.owner),
                "chunk_address": to_hex(&signed.chunk_address),
                "soc_address": to_hex(&signed.soc_address),
                "span": signed.span.to_string(),
            }))
            .map(Done::Reply)
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
                transport_key: None,
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
