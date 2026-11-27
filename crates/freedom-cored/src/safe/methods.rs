//! The `safe.*` methods (design 0016, API; SAFE-2's S2 and S3): a Safe's
//! record made in the core, its status and deployment read through the
//! chain machine, the pending store's board views, and a Safe transaction
//! prepared and proposed. Every one answers `not_moved` (`data.store:
//! "vault_meta"`) until the hello names `vault_meta`: the record is the
//! core's to read and to mark.
//!
//! - **`safe.create { name, owners: [index], threshold }`** → `{ wallet }`
//!   (`createSafeAccount`): the owners' addresses from their records, a
//!   128-bit salt from the OS's RNG, the CREATE2 address from `fc-safe`,
//!   and `addSafeWallet`'s record, through `accounts.rs` on the vault
//!   queue, as `accounts.add_safe`. It reads no chain.
//! - **`safe.status { safe }`** → `getSafeStatus`'s fields, `{ deployed,
//!   chainId, executorIndex, executorAddress, executorBalance,
//!   estimatedCost, needsFunds }`, and `setup`, what the chain reads show
//!   of the Safe's setup, as data for the board ([`Outcome::state`]):
//!   `{ state: "unchanged" }`, `{ state: "changed", changed: [what] }`,
//!   `{ state: "unverified", read, why }` or `{ state: "not_deployed" }`.
//!   It signs nothing, so none of these is a refusal: `safe_changed`,
//!   `safe_unverified` and `not_deployed` refuse only the steps that sign
//!   or execute (S3 to S5). A Safe the record marks deployed (`deployed`
//!   stays `true`) has its code and six setup reads made through
//!   [`super::evidence`], and no nonce, which status doesn't show. An
//!   unmarked one has its code read: a verified empty code is
//!   `not_deployed`, and any other answer but a verified code is the
//!   code's read `unverified`; with no code, the executor's (the first
//!   vault owner's) balance, the deployment's estimate plus 20% and the
//!   fee quote give the activation's cost, each read for display only,
//!   its label kept. A code read nothing answered, for a Safe neither
//!   marked nor reported, has no `deployed` to give: it is refused
//!   `unverified` with `isDeployedOnChain`'s failure, as the reference
//!   throws.
//! - **`safe.deploy { safe, fee_ack? }`** → `{ send: { account, tx } }`,
//!   the executor's deployment in `sign.transaction`'s form without its
//!   nonce (`createProxyWithNonce` to the factory, value 0, the estimate
//!   plus 20%, the core's fee quote), or `{ fee_check }` when the fee
//!   check at approval stops it and `fee_ack` isn't `true`, or `{
//!   deployed: true }` for a Safe that already is. With no vault owner, or
//!   a balance below the cost, `SAFE_NEEDS_FUNDS`.
//! - **`safe.deployed { safe, hash }`** → `{ deployed }`, after main's
//!   receipt (D4, the deployed mark): the receipt read again through the
//!   chain machine, then the code. Marked only on verified evidence: a
//!   `verified` receipt with status 1 whose factory `ProxyCreation` log
//!   names the record's address, or a `verified` `eth_getCode` that isn't
//!   empty.
//! - **The session's mark:** an answer of deployment that isn't verified
//!   (code, or such a receipt) marks nothing: the Safe is reported
//!   deployed for as long as this core runs, with `verified: false` on
//!   `safe.deployed`'s answer, until a verified read decides (deviation
//!   `deployed-mark`). A verified empty code ends it. It is held only for
//!   a Safe the current records hold: none is added for an address no
//!   Safe record has, and each records' snapshot drops the Safes it no
//!   longer holds ([`Safes::records_changed`]), so it is bounded by the
//!   records.
//! - **`safe.pending {}`** → `{ states }` (`getAllSafeSendStates`), and
//!   **`safe.discard { safe, safe_tx_hash? }`** → `{}` (`cancelSafeSend`):
//!   the Safe's `safe-send` approvals ended, then its entry cleared, under
//!   the pending store's 1 MiB bound and its set-aside of an unreadable
//!   file (D3). The board shows each entry as S3's codec reads it for its
//!   Safe's record ([`super::entry`]): one it sets aside is left out, and
//!   only the signatures that count are counted.
//! - **`safe.prepare { safe, chain_id, tx: { to, value, data } }`** → `{
//!   safe_tx, safe_tx_hash, view }` (S3): refused for another chain than
//!   Gnosis (`unsupported`), for a Safe the record doesn't mark deployed
//!   (`not_deployed`, before any read) and for a call to the Safe itself
//!   (`self_call`, question 4); then the eight setup reads, each verified,
//!   the nonce last ([`Evidence::start`]), and the SafeTx for the call at
//!   that nonce ([`super::tx`]), kept for `safe.propose`.
//! - **`safe.propose { safe, safe_tx_hash, authorization, display? }`** →
//!   the board's state (S3): the SafeTx `safe.prepare` kept spends a
//!   `safe-send` token minted for it whole (D6), the setup and the nonce
//!   are read again, each verified, and the nonce must still be the
//!   SafeTx's; then, where no vault job is running, the vault owners sign
//!   at once while the vault is unlocked, and the entry is written
//!   ([`super::entry`]) unless another is pending meanwhile. It needs
//!   `safe_pending` moved too. A presented token is burnt however the
//!   request ends.
//! - **The Safe's hold:** from a `safe.propose`'s spend to its answer, the
//!   Safe is held: another `safe.propose` for it is `SAFE_PENDING_EXISTS`,
//!   as the reference's reservation answers, and `safe.discard`
//!   `SAFE_BUSY`, as `cancelSafeSend` answers while a step runs.
//! - **Refusals** are `invalid_argument` with `data.safe`: `unsupported`,
//!   `unverified` (a deployment or activation no read answered, or a read
//!   a step that signs rests on), `changed`, `not_deployed`, `self_call`,
//!   `nonce_behind`, `store_full`, or today's `SAFE_*` codes
//!   (`SAFE_ADDRESS_MISMATCH`, `SAFE_NEEDS_FUNDS`, `SAFE_DISCARDED`,
//!   `SAFE_PENDING_EXISTS`, `SAFE_BUSY`). `safe.status` reports `changed`,
//!   `unverified` and `not_deployed` as data, never as a refusal.
//! - **Time:** the chain-reading methods have the `session` class's 120 s
//!   from receipt (#520), each read the time left; past it, `deadline`. A
//!   cancel answers `cancelled`; a late reply changes nothing.
//! - **The mark's write** waits for no vault job to be running, as an
//!   `accounts.*` write runs at the vault queue's head: the vault takes
//!   [`Safes::take_marks`] and answers each with [`Safes::marked`]. So does
//!   a proposal's signing and write: [`Safes::take_writes`], then
//!   [`Safes::write`] with the vault's state.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use fc_evm::{U256, checksum_address, keccak256, parse_bytes, parse_unsigned, to_hex};
use fc_json::JsValue;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_safe::constants::{CHAIN_ID, PROXY_FACTORY};
use fc_safe::{Setup, parse_salt};
use fc_wallet_state::value_address_bytes;
use fc_wallet_state::vault_meta::VaultMeta;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use fc_protocol::message::Context;
use fc_vault::state::VaultState;

use super::entry;
use super::evidence::{Evidence, Outcome, Progress, Tags, Why};
use super::tx::{Call, Prepared, PreparedTxs};
use crate::accounts::Records;
use crate::approvals::{Approvals, Clocks};
use crate::phone::ChainRead;
use crate::safe_pending::{Failure, SafePending};
use crate::vault::{Out, error_payload};

/// The methods, in `core.hello`'s capability order.
pub const METHODS: [&str; 8] = [
    "safe.create",
    "safe.status",
    "safe.deploy",
    "safe.deployed",
    "safe.pending",
    "safe.discard",
    "safe.prepare",
    "safe.propose",
];

/// The chain-reading methods' bound: the `session` class's (#520).
pub const DEADLINE_MS: u64 = 120_000;

/// `ProxyCreation(SafeProxy indexed proxy, address singleton)`'s topic,
/// as `SafeProxyFactory` 1.4.1 emits it (safe-deployments 1.37.66).
const PROXY_CREATION: &str = "ProxyCreation(address,address)";

/// `not_deployed`'s text (design 0016, "Chain reads"): the refusal of the
/// steps that sign or execute (S3 to S5), never of `safe.status`.
pub const NOT_DEPLOYED_TEXT: &str = "Activate this account on Gnosis first.";

/// The reference's refusal of a send on another chain (`startSafeSend`).
const GNOSIS_ONLY_TEXT: &str = "Multi-signature accounts can only send on Gnosis";

/// `pendingExists()`'s text.
const PENDING_EXISTS_TEXT: &str =
    "A transaction is already waiting for signatures \u{2014} finish or discard it first";

/// `cancelSafeSend`'s, while a step holds the Safe.
const BUSY_TEXT: &str = "Wait for the current step to finish first";

/// The reference's `SAFE_DISCARDED` text.
const DISCARDED_TEXT: &str = "This transaction was discarded or replaced";

/// `store_full`'s (D3): the pending store's 1 MiB bound.
const STORE_FULL_TEXT: &str = "There is no room for another pending Safe transaction: finish or \
     discard one first.";

/// `safe_nonce_behind`'s (deviation `nonce-behind`).
const NONCE_BEHIND_TEXT: &str =
    "The Safe's nonce on Gnosis is below this transaction's, so Freedom won't sign it. Try again.";

/// `isDeployedOnChain`'s, for a code read no source answered.
const ACTIVATION_UNVERIFIED_TEXT: &str = "Freedom couldn't verify on Gnosis whether this account \
     is activated. Try again, or add an RPC provider in Settings.";

/// `confirmDeployment`'s, for a deployment no read confirms.
const DEPLOYMENT_UNVERIFIED_TEXT: &str = "Freedom sent the activation, but couldn't verify on \
     Gnosis that it went through. It checks again the next time you open this account. If it \
     stays unverified, add an RPC provider in Settings.";

const NO_EXECUTOR_TEXT: &str =
    "None of the owners is a browser account that could pay the activation fee";

fn invalid() -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters")
}

/// A Safe refusal: `invalid_argument` with `data.safe`.
fn refused(safe: &str, message: impl Into<String>) -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, message).with_data(json!({ "safe": safe }))
}

/// The reference's plain refusal: `invalid_argument` with its message.
fn plain(message: impl Into<String>) -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, message)
}

fn not_moved() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::NotMoved,
        "main still writes vault-meta.json (vault_meta isn't in store_moved)",
    )
    .with_data(json!({ "store": crate::accounts::STORE }))
}

/// The steps' `not_deployed` refusal (S3 to S5).
fn not_deployed() -> ErrorBody {
    refused("not_deployed", NOT_DEPLOYED_TEXT)
}

fn reply(id: u64, result: &Value) -> Out {
    let mut payload = Zeroizing::new(Vec::with_capacity(256));
    match fc_protocol::message::write_result(&mut *payload, id, result) {
        Ok(()) => Out::Send(payload),
        Err(_) => Out::Send(error_payload(id, &crate::vault::internal())),
    }
}

fn failed(id: u64, error: &ErrorBody) -> Out {
    Out::Send(error_payload(id, error))
}

/// A result as JS keeps it: an entry's display data, the board's state.
fn js_reply(id: u64, result: &JsValue) -> Out {
    let written = serde_json::value::RawValue::from_string(result.stringify())
        .map_err(|_| ())
        .and_then(|raw| {
            let mut payload = Zeroizing::new(Vec::with_capacity(256));
            fc_protocol::message::write_result(&mut *payload, id, &raw)
                .map(|()| payload)
                .map_err(|_| ())
        });
    match written {
        Ok(payload) => Out::Send(payload),
        Err(()) => failed(id, &crate::vault::internal()),
    }
}

/// The request's members: an object holding only `allowed`.
fn members<'a>(
    raw: Option<&str>,
    allowed: &[&str],
    value: &'a mut Value,
) -> Result<&'a serde_json::Map<String, Value>, ErrorBody> {
    *value = serde_json::from_str(raw.unwrap_or("{}")).map_err(|_| invalid())?;
    match value {
        Value::Object(map) if map.keys().all(|k| allowed.contains(&k.as_str())) => Ok(map),
        _ => Err(invalid()),
    }
}

/// A wallet index: an integer from 0 to `Number.MAX_SAFE_INTEGER`.
fn index_of(params: &serde_json::Map<String, Value>, key: &str) -> Result<u64, ErrorBody> {
    params
        .get(key)
        .and_then(Value::as_u64)
        .filter(|index| *index <= fc_wallet_state::safe_pending::MAX_INDEX)
        .ok_or_else(invalid)
}

/// A JS number's text for an index (`7`, never `7.0`).
fn index_value(index: u64) -> Value {
    json!(index)
}

// --- `safe.create` -------------------------------------------------------

/// `createSafeAccount`'s address and salt for `addSafeWallet`, from the
/// file the vault queue's head reads: each owner's address from its
/// record (`resolveOwnerAddresses`), a salt of 16 bytes from the OS's RNG
/// as decimal digits (`generateSaltNonce`), and the CREATE2 address,
/// checksummed, as `predictSafeAddress` gives it. The record's own checks
/// are `add_safe`'s, after.
pub fn created(
    meta: &VaultMeta,
    owners: &JsValue,
    threshold: &JsValue,
) -> Result<(JsValue, JsValue), ErrorBody> {
    const PRESET: &str = "A Safe needs 1 of 2 or 2 of 3 owners";
    let Some(owners) = owners.as_array() else {
        return Err(plain(PRESET));
    };
    let mut addresses = Vec::with_capacity(owners.len());
    for owner in owners {
        let record = match owner {
            JsValue::Number(index) => meta.record(*index),
            _ => None,
        };
        let Some(record) = record else {
            let text = owner.js_string().unwrap_or_default();
            return Err(plain(format!("Owner wallet index {text} does not exist")));
        };
        let address = record
            .get("address")
            .filter(|address| address.truthy())
            .ok_or_else(|| {
                let name = record
                    .get("name")
                    .and_then(|name| name.js_string().ok())
                    .unwrap_or_default();
                plain(format!(
                    "Owner \"{name}\" has no address yet \u{2014} unlock the vault once first"
                ))
            })?;
        addresses.push(value_address_bytes(address).ok_or_else(|| plain(PRESET))?);
    }
    let threshold = match threshold {
        JsValue::Number(n) if *n == 1.0 || *n == 2.0 => *n as usize,
        _ => return Err(plain(PRESET)),
    };
    let setup = Setup::new(addresses, threshold).map_err(|error| match error {
        fc_safe::Error::Owners(_) => plain("Duplicate owner accounts"),
        _ => plain(PRESET),
    })?;
    let salt = {
        use rand_core::TryRng as _;
        let mut bytes = [0u8; 32];
        crate::rng::OsRng
            .try_fill_bytes(&mut bytes[16..])
            .map_err(|_| crate::vault::internal())?;
        U256::from_be_slice(&bytes).ok_or_else(crate::vault::internal)?
    };
    let address = checksum_address(&setup.address(&salt));
    Ok((
        JsValue::string(address.as_str()),
        JsValue::string(salt.to_decimal().as_str()),
    ))
}

// --- A Safe's record --------------------------------------------------

/// The first vault owner, which pays (`pickDefaultExecutor`).
#[derive(Debug, Clone)]
struct Executor {
    index: u64,
    address: [u8; 20],
    /// Its address as its record stores it.
    text: String,
}

/// A Safe's record, read for one request: its address checked against its
/// owners, threshold and salt.
#[derive(Debug, Clone)]
struct Safe {
    index: u64,
    address: [u8; 20],
    setup: Setup,
    salt: U256,
    marked: bool,
    executor: Option<Executor>,
    /// The vault owners, in the record's order: each index and address.
    vault_owners: Vec<(u64, [u8; 20])>,
}

fn is_safe(record: &JsValue) -> bool {
    record.get("type").and_then(JsValue::as_str) == Some("safe")
}

/// `getSafeRecord(index)` and `resolveOwnerAddresses`, then the derived
/// address against the record's (`SAFE_ADDRESS_MISMATCH`), as the reference
/// checks it before a deployment or a SafeTx.
fn resolve(records: &Records, index: u64) -> Result<Safe, ErrorBody> {
    let not_a_safe = || plain(format!("Wallet {index} is not a Safe account"));
    let record = records
        .record(index as f64)?
        .filter(is_safe)
        .ok_or_else(not_a_safe)?;
    let owners = record
        .get("owners")
        .and_then(JsValue::as_array)
        .ok_or_else(not_a_safe)?;
    let mut addresses = Vec::with_capacity(owners.len());
    let mut executor = None;
    let mut vault_owners = Vec::new();
    for owner in owners {
        let JsValue::Number(at) = owner else {
            return Err(plain("Owner wallet index does not exist"));
        };
        let owner = records.record(*at)?.ok_or_else(|| {
            plain(format!(
                "Owner wallet index {} does not exist",
                fc_json::JsValue::Number(*at)
                    .js_string()
                    .unwrap_or_default()
            ))
        })?;
        let stored = owner.get("address").filter(|a| a.truthy());
        let address = stored.and_then(value_address_bytes).ok_or_else(|| {
            plain("An owner has no address yet \u{2014} unlock the vault once first")
        })?;
        if owner.get("type").and_then(JsValue::as_str) == Some("mnemonic")
            && at.fract() == 0.0
            && *at >= 0.0
        {
            vault_owners.push((*at as u64, address));
            if executor.is_none() {
                executor = Some(Executor {
                    index: *at as u64,
                    address,
                    text: stored
                        .and_then(|a| a.js_string().ok())
                        .unwrap_or_else(|| checksum_address(&address)),
                });
            }
        }
        addresses.push(address);
    }
    let threshold = match record.get("threshold") {
        Some(JsValue::Number(n)) if n.fract() == 0.0 && *n >= 0.0 => *n as usize,
        _ => usize::MAX,
    };
    let setup = Setup::new(addresses, threshold).map_err(|error| match error {
        fc_safe::Error::Unsupported(_) => refused("unsupported", error.to_string()),
        _ => plain(error.to_string()),
    })?;
    let salt = record
        .get("saltNonce")
        .and_then(JsValue::as_str)
        .ok_or_else(|| plain("Invalid Safe salt nonce"))
        .and_then(|salt| parse_salt(salt).map_err(|_| plain("Invalid Safe salt nonce")))?;
    let address = record
        .get("address")
        .and_then(value_address_bytes)
        .ok_or_else(not_a_safe)?;
    setup
        .check_address(&salt, &address)
        .map_err(|error| refused("SAFE_ADDRESS_MISMATCH", error.to_string()))?;
    let marked = matches!(
        record.get("deployed").and_then(|d| d.get("100")),
        Some(JsValue::Bool(true))
    );
    Ok(Safe {
        index,
        address,
        setup,
        salt,
        marked,
        executor,
        vault_owners,
    })
}

// --- Chain replies ------------------------------------------------------

/// A read's reply, as the chain thread wrote it.
enum Reply {
    /// The read's `result` (its node's answer, or the fee quote's object
    /// itself), and whether it is labelled verified.
    Answer {
        result: Value,
        verified: bool,
    },
    Failed(ErrorBody),
}

fn reply_of(payload: &[u8], whole: bool) -> Reply {
    let Ok(message) = serde_json::from_slice::<Value>(payload) else {
        return Reply::Failed(crate::vault::internal());
    };
    if let Some(error) = message.get("error") {
        return Reply::Failed(
            serde_json::from_value::<ErrorBody>(error.clone())
                .unwrap_or_else(|_| crate::vault::internal()),
        );
    }
    let Some(result) = message.get("result") else {
        return Reply::Failed(crate::vault::internal());
    };
    let verified = result.get("verified") == Some(&Value::Bool(true));
    let result = if whole {
        result.clone()
    } else {
        result.get("result").cloned().unwrap_or(Value::Null)
    };
    Reply::Answer { result, verified }
}

/// What a receipt shows of the deployment (D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Receipt {
    /// Verified, status 1, the factory's `ProxyCreation` naming the Safe.
    Proves,
    /// The same, but not verified: the session's mark only.
    Suggests,
    /// Anything else.
    Nothing,
}

/// Whether a receipt is the deployment's: of transaction `hash`, status
/// 1, with a log from the factory whose topics are `ProxyCreation` and the
/// Safe's address.
fn deploys(receipt: &Value, safe: &[u8; 20], hash: &[u8; 32]) -> bool {
    let hex = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .and_then(|t| parse_bytes(t, "").ok())
    };
    let status_one = receipt
        .get("status")
        .and_then(Value::as_str)
        .and_then(parse_unsigned)
        == Some(U256::from_u64(1));
    let same_tx = hex(receipt.get("transactionHash")).as_deref() == Some(hash.as_slice());
    let topic = keccak256(PROXY_CREATION.as_bytes());
    let named = fc_naming::abi::word_from_address(safe);
    let logged = receipt
        .get("logs")
        .and_then(Value::as_array)
        .is_some_and(|logs| {
            logs.iter().any(|log| {
                let from_factory =
                    hex(log.get("address")).as_deref() == Some(PROXY_FACTORY.as_slice());
                let topics = log.get("topics").and_then(Value::as_array);
                let topic_at = |i: usize| hex(topics.and_then(|t| t.get(i)));
                from_factory
                    && topic_at(0).as_deref() == Some(topic.as_slice())
                    && topic_at(1).as_deref() == Some(named.as_slice())
            })
        });
    status_one && same_tx && logged
}

/// What a code read shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Code {
    Verified {
        empty: bool,
    },
    Unverified {
        empty: bool,
    },
    /// No answer to judge: a failed read, or one that isn't hex; why, as
    /// the setup check names it.
    Failed(Why),
}

fn code_of(reply: &Reply) -> Code {
    let Reply::Answer { result, verified } = reply else {
        return Code::Failed(Why::Failed);
    };
    // `!code || code === '0x'`.
    let empty = match result {
        Value::Null => Some(true),
        Value::String(text) => parse_bytes(text, "")
            .ok()
            .map(|bytes| bytes.is_empty())
            .or(text.is_empty().then_some(true)),
        _ => None,
    };
    match (empty, verified) {
        (Some(empty), true) => Code::Verified { empty },
        (Some(empty), false) => Code::Unverified { empty },
        (None, true) => Code::Failed(Why::Unreadable(None)),
        (None, false) => Code::Failed(Why::Unverified),
    }
}

/// A code read that isn't evidence, as `safe.status`'s `setup` reports it.
fn code_unverified(code: Code) -> Outcome {
    let why = match code {
        Code::Failed(why) => why,
        _ => Why::Unverified,
    };
    Outcome::Unverified {
        read: fc_safe::Read::Code,
        why,
    }
}

/// What the reads decide of the deployment, each but the mark with what
/// `safe.status`'s `setup` reports of it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Deployment {
    /// Verified: marked for good.
    Mark,
    /// Reported deployed for the session, unverified.
    Session(Outcome),
    NotDeployed(Outcome),
    /// Nothing answered: no read to judge.
    Unknown,
}

// --- Requests in flight ---------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Status,
    Deploy { fee_ack: bool },
    Deployed { hash: [u8; 32] },
    Prepare,
    Propose,
}

/// What a `safe.prepare` or `safe.propose` carries beside its Safe.
enum Work {
    None,
    /// The call to build the SafeTx for.
    Prepare(Call),
    /// The SafeTx its token confirmed, and the caller's display data.
    Propose {
        prepared: Box<Prepared>,
        display: Option<JsValue>,
    },
}

/// Where a request stands.
enum Step {
    Receipt,
    Code {
        receipt: Receipt,
    },
    /// The mark is written ([`Safes::marked`]), then the request goes on.
    Mark,
    Setup(Box<Evidence>),
    Quote(Box<Quote>),
    /// The setup and the nonce are verified: the vault owners sign and the
    /// entry is written ([`Safes::write`]).
    Write,
}

/// The activation's reads: the estimate, the fee quote, the executor's
/// balance, and for a deployment the fee evidence when it is stale.
struct Quote {
    estimate: Option<Reply>,
    fee: Option<Reply>,
    balance: Option<Reply>,
    /// The fee evidence's read is out.
    reference: bool,
    /// What the code read showed, for `safe.status`'s `setup`.
    setup: Outcome,
}

/// Which of the activation's reads a tag is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Estimate,
    Fee,
    Balance,
    Reference,
}

struct Op {
    kind: Kind,
    safe: Safe,
    deadline: Instant,
    step: Step,
    work: Work,
}

/// The Safe methods' requests in flight, their reads, and the Safes
/// reported deployed for the session.
#[derive(Default)]
pub struct Safes {
    tags: Tags,
    ops: BTreeMap<u64, Op>,
    /// Each read out: its request, and the activation's part it is.
    reads: BTreeMap<u64, (u64, Option<Part>)>,
    /// Safes an unverified answer showed deployed: reported so until a
    /// verified read decides, and only while the records hold a Safe at
    /// the address ([`Safes::records_changed`]).
    session: BTreeSet<[u8; 20]>,
    /// Requests whose mark is due, for the vault to write.
    marks: Vec<u64>,
    /// The SafeTxs `safe.prepare` built, for `safe.propose`.
    prepared: PreparedTxs,
    /// Proposals whose signing and write are due, for the vault to run.
    writes: Vec<u64>,
}

/// What the methods read and change beyond their own state.
pub struct Ctx<'a> {
    /// The fee evidence, the fee check, the Safe approvals and the
    /// records' snapshot.
    pub approvals: &'a mut Approvals,
    pub pending: &'a SafePending,
    pub clocks: Clocks,
    pub now: Instant,
}

/// The answer `getSafeStatus` gives, balances and costs in wei, decimal,
/// and `setup`, what the reads show of the Safe's setup
/// ([`Outcome::state`]).
fn status(
    safe: &Safe,
    deployed: bool,
    balance: Option<&U256>,
    cost: Option<&U256>,
    needs_funds: bool,
    setup: &Outcome,
) -> Value {
    json!({
        "deployed": deployed,
        "chainId": CHAIN_ID,
        "executorIndex": safe.executor.as_ref().map(|e| index_value(e.index)),
        "executorAddress": safe.executor.as_ref().map(|e| e.text.clone()),
        "executorBalance": balance.map(U256::to_decimal),
        "estimatedCost": cost.map(U256::to_decimal),
        "needsFunds": needs_funds,
        "setup": setup.state(),
    })
}

/// Whether `records` hold a Safe at `address`: the session reports no
/// other.
fn holds_safe(records: Option<&Records>, address: &[u8; 20]) -> bool {
    let Some(Records::Read(meta)) = records else {
        return false;
    };
    meta.find_by_address(&JsValue::string(to_hex(address).as_str()))
        .is_some_and(|record| {
            is_safe(&record)
                && record.get("address").and_then(value_address_bytes) == Some(*address)
        })
}

impl Safes {
    pub fn new() -> Self {
        Safes::default()
    }

    /// The records' snapshot changed (G20): the session's reports kept
    /// only for the Safes `records` still hold, so a removed Safe's goes
    /// with its record.
    pub fn records_changed(&mut self, records: Option<&Records>) {
        self.session.retain(|address| holds_safe(records, address));
    }

    /// Whether this module serves `method` on the loop (`safe.create` runs
    /// on the vault queue).
    pub fn handles(method: &str) -> bool {
        METHODS.contains(&method) && method != "safe.create"
    }

    /// A request from `context`: its replies and reads. A token
    /// `safe.propose` presents is burnt however the request ends, as
    /// `sign.*` burns one (design 0012, "Tokens").
    pub fn request(
        &mut self,
        id: u64,
        method: &str,
        raw: Option<&str>,
        context: &Context,
        ctx: &mut Ctx,
    ) -> Vec<Out> {
        let presented = (method == "safe.propose")
            .then(|| serde_json::from_str::<Value>(raw.unwrap_or("{}")).ok())
            .flatten()
            .and_then(|params| crate::approvals::presented_token(&params, true));
        let out = match self.start(id, method, raw, context, ctx) {
            Ok(out) => out,
            Err(error) => vec![failed(id, &error)],
        };
        if let Some(token) = presented {
            ctx.approvals.burn(&token);
        }
        out
    }

    fn start(
        &mut self,
        id: u64,
        method: &str,
        raw: Option<&str>,
        context: &Context,
        ctx: &mut Ctx,
    ) -> Result<Vec<Out>, ErrorBody> {
        let records = ctx
            .approvals
            .account_records()
            .ok_or_else(not_moved)?
            .clone();
        let mut params = Value::Null;
        let (kind, index) = match method {
            "safe.pending" => {
                members(raw, &[], &mut params)?;
                let states = pending_states(&records, ctx.pending)?;
                let text = JsValue::Object(vec![("states".into(), JsValue::Array(states))]);
                let raw = serde_json::value::RawValue::from_string(text.stringify())
                    .map_err(|_| crate::vault::internal())?;
                let mut payload = Zeroizing::new(Vec::with_capacity(256));
                fc_protocol::message::write_result(&mut *payload, id, &raw)
                    .map_err(|_| crate::vault::internal())?;
                return Ok(vec![Out::Send(payload)]);
            }
            "safe.discard" => {
                let p = members(raw, &["safe", "safe_tx_hash"], &mut params)?;
                let index = index_of(p, "safe")?;
                // A step holds the Safe: `cancelSafeSend`'s refusal.
                if self.holds(index) {
                    return Err(refused("SAFE_BUSY", BUSY_TEXT));
                }
                let named = match p.get("safe_tx_hash") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(hash)) => Some(hash.clone()),
                    Some(_) => return Err(invalid()),
                };
                let answer = discard(&records, ctx, index, named.as_deref())?;
                return Ok(vec![reply(id, &answer)]);
            }
            "safe.status" => {
                let p = members(raw, &["safe"], &mut params)?;
                (Kind::Status, index_of(p, "safe")?)
            }
            "safe.deploy" => {
                let p = members(raw, &["safe", "fee_ack"], &mut params)?;
                let fee_ack = match p.get("fee_ack") {
                    None => false,
                    Some(Value::Bool(ack)) => *ack,
                    Some(_) => return Err(invalid()),
                };
                (Kind::Deploy { fee_ack }, index_of(p, "safe")?)
            }
            "safe.prepare" => {
                crate::approvals::page_context(context)?;
                let p = members(raw, &["safe", "chain_id", "tx"], &mut params)?;
                let index = index_of(p, "safe")?;
                let chain_id = match p.get("chain_id") {
                    Some(Value::Number(n)) => n.as_u64(),
                    Some(Value::String(text)) => parse_unsigned(text).and_then(|n| n.to_u64()),
                    _ => return Err(invalid()),
                };
                let call = Call::of(p.get("tx").ok_or_else(invalid)?)?;
                let safe = resolve(&records, index)?;
                if chain_id != Some(CHAIN_ID) {
                    return Err(refused("unsupported", GNOSIS_ONLY_TEXT));
                }
                if !safe.marked {
                    return Err(not_deployed());
                }
                call.check_not_self(&safe.address)?;
                return Ok(self.check(id, Kind::Prepare, safe, Work::Prepare(call), ctx.now));
            }
            "safe.propose" => {
                crate::approvals::page_context(context)?;
                ctx.pending.check_moved()?;
                let p = members(
                    raw,
                    &["safe", "safe_tx_hash", "authorization", "display"],
                    &mut params,
                )?;
                let index = index_of(p, "safe")?;
                let hash = p
                    .get("safe_tx_hash")
                    .and_then(Value::as_str)
                    .and_then(|text| parse_bytes(text, "safe_tx_hash").ok())
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .ok_or_else(invalid)?;
                let authorization = p.get("authorization").ok_or_else(invalid)?;
                // `display` as JS keeps it: opaque, stored as given.
                let display = fc_json::parse(raw.unwrap_or("{}"))
                    .map_err(|_| invalid())?
                    .get("display")
                    .cloned();
                let safe = resolve(&records, index)?;
                if !safe.marked {
                    return Err(not_deployed());
                }
                // One pending SafeTx per Safe: another proposal holding it,
                // or an entry that reads (one the codec sets aside gives
                // way, as the board shows none).
                if self.holds(index) || pending_entry(ctx.pending, &safe).is_some() {
                    return Err(refused("SAFE_PENDING_EXISTS", PENDING_EXISTS_TEXT));
                }
                let prepared = self
                    .prepared
                    .get(index, &safe.address, &hash)
                    .cloned()
                    .ok_or_else(|| refused("SAFE_DISCARDED", DISCARDED_TEXT))?;
                super::tx::not_self(prepared.tx.to(), &safe.address)?;
                ctx.approvals.spend_safe_tx(
                    context,
                    authorization,
                    index,
                    &prepared.token_payload(),
                    ctx.clocks,
                )?;
                self.prepared.take(index, &safe.address, &hash);
                let work = Work::Propose {
                    prepared: Box::new(prepared),
                    display,
                };
                return Ok(self.check(id, Kind::Propose, safe, work, ctx.now));
            }
            "safe.deployed" => {
                let p = members(raw, &["safe", "hash"], &mut params)?;
                let hash = p
                    .get("hash")
                    .and_then(Value::as_str)
                    .and_then(|text| parse_bytes(text, "hash").ok())
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .ok_or_else(invalid)?;
                (Kind::Deployed { hash }, index_of(p, "safe")?)
            }
            _ => return Err(ErrorBody::new(ErrorCode::UnknownMethod, "Unknown method")),
        };
        let safe = resolve(&records, index)?;
        let mut op = Op {
            kind,
            safe,
            deadline: ctx.now + Duration::from_millis(DEADLINE_MS),
            step: Step::Receipt,
            work: Work::None,
        };
        let out = match kind {
            Kind::Deployed { hash } => {
                let params = format!(r#"["{}"]"#, to_hex(&hash));
                let read = self.read(id, None, "eth_getTransactionReceipt", params, &op, ctx.now);
                vec![read]
            }
            Kind::Status | Kind::Deploy { .. } if op.safe.marked => {
                return Ok(self.deployed(id, op, ctx));
            }
            Kind::Status | Kind::Deploy { .. } => {
                op.step = Step::Code {
                    receipt: Receipt::Nothing,
                };
                vec![self.code_read(id, &op, ctx.now)]
            }
            Kind::Prepare | Kind::Propose => return Err(crate::vault::internal()),
        };
        self.ops.insert(id, op);
        Ok(out)
    }

    /// One of a request's reads, with the time it has left.
    fn read(
        &mut self,
        id: u64,
        part: Option<Part>,
        method: &'static str,
        params: String,
        op: &Op,
        now: Instant,
    ) -> Out {
        let tag = self.tags.next();
        self.reads.insert(tag, (id, part));
        Out::ChainRead(ChainRead {
            tag,
            chain_id: CHAIN_ID,
            method,
            params,
            deadline_ms: left_ms(op, now),
        })
    }

    fn code_read(&mut self, id: u64, op: &Op, now: Instant) -> Out {
        let params = format!(r#"["{}","latest"]"#, to_hex(&op.safe.address));
        self.read(id, None, "eth_getCode", params, op, now)
    }

    /// The chain thread answered read `tag`: `payload` its reply, and
    /// `past_due` whether it failed at or after its deadline.
    pub fn chain_read(
        &mut self,
        tag: u64,
        payload: &[u8],
        past_due: bool,
        ctx: &mut Ctx,
    ) -> Vec<Out> {
        let Some((id, part)) = self.reads.remove(&tag) else {
            return Vec::new();
        };
        // Fee evidence is the approvals', whatever became of its request.
        if part == Some(Part::Reference) {
            ctx.approvals.fee_answered(tag, payload);
        }
        let Some(mut op) = self.ops.remove(&id) else {
            return Vec::new();
        };
        if past_due {
            self.forget(id);
            return vec![failed(id, &deadline())];
        }
        let step = std::mem::replace(&mut op.step, Step::Mark);
        match step {
            Step::Receipt => {
                let Kind::Deployed { hash } = op.kind else {
                    return vec![failed(id, &crate::vault::internal())];
                };
                let receipt = match reply_of(payload, false) {
                    Reply::Answer { result, verified }
                        if deploys(&result, &op.safe.address, &hash) =>
                    {
                        if verified {
                            Receipt::Proves
                        } else {
                            Receipt::Suggests
                        }
                    }
                    _ => Receipt::Nothing,
                };
                if receipt == Receipt::Proves {
                    return self.mark(id, op);
                }
                op.step = Step::Code { receipt };
                let read = self.code_read(id, &op, ctx.now);
                self.ops.insert(id, op);
                vec![read]
            }
            Step::Code { receipt } => {
                let code = code_of(&reply_of(payload, false));
                self.judged(id, op, receipt, code, ctx)
            }
            Step::Setup(mut evidence) => {
                match evidence.answered(tag, payload, false, &mut self.tags) {
                    Progress::Waiting => {
                        op.step = Step::Setup(evidence);
                        self.ops.insert(id, op);
                        Vec::new()
                    }
                    Progress::Reads(reads) => {
                        op.step = Step::Setup(evidence);
                        self.ops.insert(id, op);
                        reads
                            .into_iter()
                            .map(|read| {
                                self.reads.insert(read.tag, (id, None));
                                Out::ChainRead(read)
                            })
                            .collect()
                    }
                    Progress::Done(outcome) => self.setup_done(id, op, outcome),
                }
            }
            Step::Quote(mut quote) => {
                let reply = reply_of(payload, part == Some(Part::Fee));
                match part {
                    Some(Part::Estimate) => quote.estimate = Some(reply),
                    Some(Part::Fee) => quote.fee = Some(reply),
                    Some(Part::Balance) => quote.balance = Some(reply),
                    Some(Part::Reference) => quote.reference = false,
                    None => {}
                }
                if quote.estimate.is_none()
                    || quote.fee.is_none()
                    || quote.balance.is_none()
                    || quote.reference
                {
                    op.step = Step::Quote(quote);
                    self.ops.insert(id, op);
                    return Vec::new();
                }
                vec![self.quoted(id, &op, &quote, ctx)]
            }
            // No read is out while the mark or the write is due: a stray
            // reply changes nothing.
            Step::Mark | Step::Write => {
                self.ops.insert(id, op);
                Vec::new()
            }
        }
    }

    /// The deployment as the reads show it (D4): marked on verified
    /// evidence, reported for the session on an unverified answer of it,
    /// and a verified empty code ends the session's report.
    fn judged(
        &mut self,
        id: u64,
        mut op: Op,
        receipt: Receipt,
        code: Code,
        ctx: &mut Ctx,
    ) -> Vec<Out> {
        let address = op.safe.address;
        let deployment = match code {
            Code::Verified { empty: false } => Deployment::Mark,
            Code::Verified { empty: true } => {
                self.session.remove(&address);
                Deployment::NotDeployed(Outcome::NotDeployed)
            }
            Code::Unverified { empty: false } => Deployment::Session(code_unverified(code)),
            _ if receipt == Receipt::Suggests => Deployment::Session(code_unverified(code)),
            _ if self.session.contains(&address) => Deployment::Session(code_unverified(code)),
            Code::Unverified { empty: true } => Deployment::NotDeployed(code_unverified(code)),
            Code::Failed(_) => Deployment::Unknown,
        };
        match deployment {
            Deployment::Mark => self.mark(id, op),
            Deployment::Session(seen) => {
                // Only for a Safe the records still hold: one removed while
                // the read was out adds nothing.
                if holds_safe(ctx.approvals.account_records(), &address) {
                    self.session.insert(address);
                }
                crate::log::warn(
                    "safe deployment reported unverified, for the session",
                    json!({}),
                );
                let answer = match op.kind {
                    Kind::Deployed { .. } => json!({ "deployed": true, "verified": false }),
                    Kind::Deploy { .. } => json!({ "deployed": true }),
                    Kind::Status => status(&op.safe, true, None, None, false, &seen),
                    // They read no code this way.
                    Kind::Prepare | Kind::Propose => {
                        return vec![failed(id, &crate::vault::internal())];
                    }
                };
                vec![reply(id, &answer)]
            }
            Deployment::Unknown => {
                let text = match op.kind {
                    Kind::Deployed { .. } => DEPLOYMENT_UNVERIFIED_TEXT,
                    _ => ACTIVATION_UNVERIFIED_TEXT,
                };
                vec![failed(id, &refused("unverified", text))]
            }
            Deployment::NotDeployed(seen) => match op.kind {
                Kind::Deployed { .. } => vec![reply(id, &json!({ "deployed": false }))],
                Kind::Prepare | Kind::Propose => vec![failed(id, &crate::vault::internal())],
                Kind::Status | Kind::Deploy { .. } => {
                    let Some(executor) = op.safe.executor.clone() else {
                        return vec![match op.kind {
                            Kind::Status => {
                                reply(id, &status(&op.safe, false, None, None, true, &seen))
                            }
                            _ => failed(id, &refused("SAFE_NEEDS_FUNDS", NO_EXECUTOR_TEXT)),
                        }];
                    };
                    let mut out = Vec::new();
                    let deployment = op.safe.setup.deployment(&op.safe.salt);
                    let estimate = json!([{
                        "from": checksum_address(&executor.address),
                        "to": checksum_address(&deployment.to),
                        "value": "0",
                        "data": to_hex(&deployment.data),
                    }]);
                    out.push(self.read(
                        id,
                        Some(Part::Estimate),
                        "eth_estimateGas",
                        estimate.to_string(),
                        &op,
                        ctx.now,
                    ));
                    out.push(self.read(
                        id,
                        Some(Part::Fee),
                        crate::chain::INTERNAL_FEE_QUOTE,
                        String::new(),
                        &op,
                        ctx.now,
                    ));
                    let balance = format!(r#"["{}","latest"]"#, to_hex(&executor.address));
                    out.push(self.read(
                        id,
                        Some(Part::Balance),
                        "eth_getBalance",
                        balance,
                        &op,
                        ctx.now,
                    ));
                    let mut quote = Quote {
                        estimate: None,
                        fee: None,
                        balance: None,
                        reference: false,
                        setup: seen,
                    };
                    if matches!(op.kind, Kind::Deploy { .. })
                        && !ctx.approvals.fee_fresh(CHAIN_ID, ctx.clocks.vault_ms)
                    {
                        let read = self.read(
                            id,
                            Some(Part::Reference),
                            crate::chain::INTERNAL_FEE_REFERENCE,
                            String::new(),
                            &op,
                            ctx.now,
                        );
                        if let Out::ChainRead(read) = &read {
                            ctx.approvals.fee_asked(
                                read.tag,
                                Some(&format!(r#"{{"chain_id":{CHAIN_ID}}}"#)),
                                ctx.clocks.vault_ms,
                            );
                        }
                        quote.reference = true;
                        out.push(read);
                    }
                    op.step = Step::Quote(Box::new(quote));
                    self.ops.insert(id, op);
                    out
                }
            },
        }
    }

    /// A Safe known deployed: `safe.deploy` has nothing to send;
    /// `safe.status` reads the code and the setup, and no nonce.
    fn deployed(&mut self, id: u64, mut op: Op, ctx: &mut Ctx) -> Vec<Out> {
        match op.kind {
            Kind::Deployed { .. } => vec![reply(id, &json!({ "deployed": true }))],
            Kind::Deploy { .. } => vec![reply(id, &json!({ "deployed": true }))],
            Kind::Prepare | Kind::Propose => vec![failed(id, &crate::vault::internal())],
            Kind::Status => {
                let (evidence, reads) = Evidence::start_status(
                    op.safe.address,
                    op.safe.setup.clone(),
                    left_ms(&op, ctx.now),
                    &mut self.tags,
                );
                op.step = Step::Setup(Box::new(evidence));
                self.ops.insert(id, op);
                reads
                    .into_iter()
                    .map(|read| {
                        self.reads.insert(read.tag, (id, None));
                        Out::ChainRead(read)
                    })
                    .collect()
            }
        }
    }

    /// Whether a `safe.propose` holds the Safe at wallet index `index`.
    fn holds(&self, index: u64) -> bool {
        self.ops
            .values()
            .any(|op| op.kind == Kind::Propose && op.safe.index == index)
    }

    /// A step that signs: the setup and the nonce, every read verified
    /// ([`Evidence::start`]), the nonce last.
    fn check(&mut self, id: u64, kind: Kind, safe: Safe, work: Work, now: Instant) -> Vec<Out> {
        let mut op = Op {
            kind,
            safe,
            deadline: now + Duration::from_millis(DEADLINE_MS),
            step: Step::Receipt,
            work,
        };
        let (evidence, reads) = Evidence::start(
            op.safe.address,
            op.safe.setup.clone(),
            left_ms(&op, now),
            &mut self.tags,
        );
        op.step = Step::Setup(Box::new(evidence));
        self.ops.insert(id, op);
        reads
            .into_iter()
            .map(|read| {
                self.reads.insert(read.tag, (id, None));
                Out::ChainRead(read)
            })
            .collect()
    }

    /// The setup reads are in: `safe.status`'s answer, which reports them
    /// as data; or, for a step that signs, its refusal unless the setup is
    /// the record's and every read verified (`safe_changed`,
    /// `safe_unverified`, `not_deployed`).
    fn setup_done(&mut self, id: u64, mut op: Op, outcome: Outcome) -> Vec<Out> {
        if op.kind == Kind::Status {
            return vec![reply(
                id,
                &status(&op.safe, true, None, None, false, &outcome),
            )];
        }
        let nonce = match outcome {
            Outcome::Unchanged { nonce } => nonce,
            Outcome::NotDeployed => return vec![failed(id, &not_deployed())],
            other => {
                let refusal = other.refusal().unwrap_or_else(crate::vault::internal);
                return vec![failed(id, &refusal)];
            }
        };
        match std::mem::replace(&mut op.work, Work::None) {
            // `safe.prepare`: the SafeTx at the verified nonce, kept.
            Work::Prepare(call) => {
                let answer = call
                    .at(&nonce)
                    .and_then(|tx| Prepared::new(op.safe.index, op.safe.address, tx))
                    .and_then(|prepared| {
                        let answer = prepared.answer()?;
                        self.prepared.keep(prepared);
                        Ok(answer)
                    });
                vec![match answer {
                    Ok(answer) => reply(id, &answer),
                    Err(error) => failed(id, &error),
                }]
            }
            // `safe.propose`: the confirmed SafeTx's nonce must still be
            // the Safe's. One below it is `safe_nonce_behind`; one the Safe
            // has passed can never execute, so it isn't stored: it was
            // replaced (`SAFE_DISCARDED`).
            Work::Propose { prepared, display } => match prepared.tx.nonce_state(&nonce) {
                fc_safe::NonceState::Ready => {
                    op.work = Work::Propose { prepared, display };
                    op.step = Step::Write;
                    self.ops.insert(id, op);
                    self.writes.push(id);
                    Vec::new()
                }
                fc_safe::NonceState::Behind => {
                    vec![failed(id, &refused("nonce_behind", NONCE_BEHIND_TEXT))]
                }
                fc_safe::NonceState::Superseded => {
                    vec![failed(id, &refused("SAFE_DISCARDED", DISCARDED_TEXT))]
                }
            },
            Work::None => vec![failed(id, &crate::vault::internal())],
        }
    }

    /// The proposals whose signing and write are due, for the vault to run
    /// where no vault job is running ([`Safes::write`]).
    pub fn take_writes(&mut self) -> Vec<u64> {
        let due = std::mem::take(&mut self.writes);
        due.into_iter()
            .filter(|id| self.ops.contains_key(id))
            .collect()
    }

    /// Proposal `id`'s signing and write, with the vault's `state`: its
    /// answer, the board's state.
    pub fn write(&mut self, id: u64, state: &VaultState, ctx: &mut Ctx) -> Vec<Out> {
        let Some(op) = self.ops.remove(&id) else {
            return Vec::new();
        };
        let Work::Propose { prepared, display } = op.work else {
            return vec![failed(id, &crate::vault::internal())];
        };
        match proposed(&op.safe, &prepared, display.as_ref(), state, ctx) {
            Ok(state) => vec![js_reply(id, &state)],
            Err(error) => vec![failed(id, &error)],
        }
    }

    /// Verified evidence: the mark is due, for the vault to write.
    fn mark(&mut self, id: u64, mut op: Op) -> Vec<Out> {
        op.step = Step::Mark;
        self.ops.insert(id, op);
        self.marks.push(id);
        Vec::new()
    }

    /// The requests whose mark is due: each request's Safe, by its index
    /// and address, which the vault checks against its record before it
    /// writes.
    pub fn take_marks(&mut self) -> Vec<(u64, u64, [u8; 20])> {
        std::mem::take(&mut self.marks)
            .into_iter()
            .filter_map(|id| {
                let op = self.ops.get(&id)?;
                Some((id, op.safe.index, op.safe.address))
            })
            .collect()
    }

    /// The vault wrote request `id`'s mark, or couldn't (`written`'s
    /// error): the request goes on, or answers the error.
    pub fn marked(&mut self, id: u64, written: Result<(), ErrorBody>, ctx: &mut Ctx) -> Vec<Out> {
        let Some(mut op) = self.ops.remove(&id) else {
            return Vec::new();
        };
        if let Err(error) = written {
            return vec![failed(id, &error)];
        }
        self.session.remove(&op.safe.address);
        op.safe.marked = true;
        crate::log::info("safe marked deployed, verified", json!({}));
        self.deployed(id, op, ctx)
    }

    /// The activation's reads are in: `safe.status`'s cost and whether the
    /// executor can pay, or `safe.deploy`'s prepared send.
    fn quoted(&mut self, id: u64, op: &Op, quote: &Quote, ctx: &mut Ctx) -> Out {
        let read_failed = |reply: &Option<Reply>, prefix: &str| match reply {
            Some(Reply::Failed(error)) => Some(ErrorBody::new(
                error.code,
                if prefix.is_empty() {
                    error.message.clone()
                } else {
                    format!("{prefix}: {}", error.message)
                },
            )),
            _ => None,
        };
        let failure = read_failed(&quote.estimate, "Gas estimation failed")
            .or_else(|| read_failed(&quote.fee, "Failed to get gas prices"))
            .or_else(|| read_failed(&quote.balance, ""));
        if let Some(error) = failure {
            return failed(id, &error);
        }
        let answer = |reply: &Option<Reply>| match reply {
            Some(Reply::Answer { result, .. }) => Some(result.clone()),
            _ => None,
        };
        let priced = answer(&quote.estimate)
            .zip(answer(&quote.fee))
            .ok_or_else(crate::vault::internal)
            .and_then(|(estimate, fee)| priced(&estimate, &fee));
        let balance = answer(&quote.balance)
            .as_ref()
            .and_then(Value::as_str)
            .and_then(parse_unsigned);
        let (priced, balance) = match (priced, balance) {
            (Ok(priced), Some(balance)) => (priced, balance),
            (Err(error), _) => return failed(id, &error),
            (_, None) => return failed(id, &plain("Invalid balance")),
        };
        let needs_funds = balance < priced.cost;
        let Some(executor) = &op.safe.executor else {
            return failed(id, &crate::vault::internal());
        };
        match op.kind {
            Kind::Status => reply(
                id,
                &status(
                    &op.safe,
                    false,
                    Some(&balance),
                    Some(&priced.cost),
                    needs_funds,
                    &quote.setup,
                ),
            ),
            Kind::Deploy { fee_ack } => {
                if needs_funds {
                    return failed(
                        id,
                        &refused(
                            "SAFE_NEEDS_FUNDS",
                            format!(
                                "Fund {} with at least {} xDAI to activate",
                                executor.text,
                                format_ether(&priced.cost)
                            ),
                        ),
                    );
                }
                let deployment = op.safe.setup.deployment(&op.safe.salt);
                let tx = priced.tx(&deployment.to, &deployment.data);
                let (verdict, ask_again) =
                    ctx.approvals
                        .page_fee_check(&tx.to_string(), Some(fee_ack), ctx.clocks);
                let verdict: Value = serde_json::from_str(&verdict).unwrap_or(Value::Null);
                if ask_again {
                    return reply(id, &json!({ "fee_check": verdict }));
                }
                reply(
                    id,
                    &json!({ "send": { "account": index_value(executor.index), "tx": tx } }),
                )
            }
            Kind::Deployed { .. } | Kind::Prepare | Kind::Propose => {
                failed(id, &crate::vault::internal())
            }
        }
    }

    /// Cancels request `id`: `cancelled`, its reads' replies ignored.
    pub fn cancel(&mut self, id: u64) -> Vec<Out> {
        if self.ops.remove(&id).is_none() {
            return Vec::new();
        }
        self.forget(id);
        vec![failed(
            id,
            &ErrorBody::new(ErrorCode::Cancelled, "Cancelled"),
        )]
    }

    /// Answers `deadline` for every request past its bound.
    pub fn tick(&mut self, now: Instant) -> Vec<Out> {
        let due: Vec<u64> = self
            .ops
            .iter()
            .filter(|(_, op)| now >= op.deadline)
            .map(|(id, _)| *id)
            .collect();
        due.into_iter()
            .map(|id| {
                self.ops.remove(&id);
                self.forget(id);
                failed(id, &deadline())
            })
            .collect()
    }

    /// The earliest request's bound.
    pub fn next_wakeup(&self) -> Option<Instant> {
        self.ops.values().map(|op| op.deadline).min()
    }

    /// Drops request `id`'s reads: their replies change nothing but the
    /// fee evidence.
    fn forget(&mut self, id: u64) {
        self.reads
            .retain(|_, (request, part)| *request != id || *part == Some(Part::Reference));
        self.marks.retain(|request| *request != id);
        self.writes.retain(|request| *request != id);
    }
}

fn deadline() -> ErrorBody {
    ErrorBody::new(ErrorCode::Deadline, "Deadline exceeded")
}

/// The time a request has left, at least 1 ms.
fn left_ms(op: &Op, now: Instant) -> u64 {
    let left = op.deadline.saturating_duration_since(now).as_millis();
    u64::try_from(left).unwrap_or(u64::MAX).max(1)
}

// --- The activation's cost ------------------------------------------------

/// The deployment priced: the estimate plus 20%, the quote's fees in the
/// type they imply, and the most it costs.
struct Priced {
    gas_limit: u64,
    fees: Fees,
    cost: U256,
}

enum Fees {
    Eip1559 { max_fee: U256, priority: U256 },
    Legacy { gas_price: U256 },
}

/// `estimateGas` (`BigInt(result) * 120n / 100n`) and `toFeeFields` on
/// the core's quote; the cost is `assessActivation`'s, the gas limit times
/// `maxFeePerGas ?? gasPrice`.
fn priced(estimate: &Value, quote: &Value) -> Result<Priced, ErrorBody> {
    let gas = estimate
        .as_str()
        .and_then(parse_unsigned)
        .and_then(|gas| gas.to_u64())
        .ok_or_else(|| plain("Gas estimation failed: invalid estimate"))?;
    let gas_limit = u64::try_from(u128::from(gas) * 120 / 100)
        .map_err(|_| plain("Gas estimation failed: invalid estimate"))?;
    let fee = |name: &str| {
        quote
            .get(name)
            .and_then(Value::as_str)
            .and_then(parse_unsigned)
    };
    let fees = if quote.get("type").and_then(Value::as_str) == Some("eip1559") {
        fee("maxFeePerGas")
            .zip(fee("maxPriorityFeePerGas"))
            .map(|(max_fee, priority)| Fees::Eip1559 { max_fee, priority })
    } else {
        fee("gasPrice").map(|gas_price| Fees::Legacy { gas_price })
    }
    .ok_or_else(|| plain("Unable to estimate the network fee"))?;
    let per_gas = match &fees {
        Fees::Eip1559 { max_fee, .. } => max_fee,
        Fees::Legacy { gas_price } => gas_price,
    };
    let cost = mul(gas_limit, per_gas).ok_or_else(|| plain("Invalid transaction fee"))?;
    Ok(Priced {
        gas_limit,
        fees,
        cost,
    })
}

impl Priced {
    /// The deployment in `sign.transaction`'s form, without its nonce.
    fn tx(&self, to: &[u8; 20], data: &[u8]) -> Value {
        let mut tx = json!({
            "type": match self.fees { Fees::Eip1559 { .. } => 2, Fees::Legacy { .. } => 0 },
            "chain_id": CHAIN_ID.to_string(),
            "gas_limit": self.gas_limit.to_string(),
            "to": checksum_address(to),
            "value": "0",
            "data": to_hex(data),
        });
        match &self.fees {
            Fees::Eip1559 { max_fee, priority } => {
                tx["max_fee_per_gas"] = json!(max_fee.to_decimal());
                tx["max_priority_fee_per_gas"] = json!(priority.to_decimal());
            }
            Fees::Legacy { gas_price } => tx["gas_price"] = json!(gas_price.to_decimal()),
        }
        tx
    }
}

/// `a × b`, or none past 2^256.
fn mul(a: u64, b: &U256) -> Option<U256> {
    let bytes = b.to_be_bytes();
    let mut product = U256::from_u64(0);
    // b's 64-bit limbs, least significant first, each times a, shifted.
    for limb in 0..4 {
        let start = 32 - 8 * (limb + 1);
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[start..start + 8]);
        let part = u128::from(a) * u128::from(u64::from_be_bytes(word));
        if part == 0 {
            continue;
        }
        let mut shifted = [0u8; 32];
        let part = part.to_be_bytes();
        // part × 2^(64·limb): its 16 bytes end `8·limb` bytes from the end.
        let end = 32 - 8 * limb;
        if end < 16 {
            if part[..16 - end].iter().any(|b| *b != 0) {
                return None;
            }
            shifted[..end].copy_from_slice(&part[16 - end..]);
        } else {
            shifted[end - 16..end].copy_from_slice(&part);
        }
        product = product.checked_add(&U256::from_be_slice(&shifted)?)?;
    }
    Some(product)
}

/// ethers' `formatEther`: the integer part, a point, and the fraction
/// without trailing zeros (at least one digit).
fn format_ether(wei: &U256) -> String {
    let digits = wei.to_decimal();
    let padded = format!("{digits:0>19}");
    let (whole, fraction) = padded.split_at(padded.len() - 18);
    let fraction = fraction.trim_end_matches('0');
    format!(
        "{whole}.{}",
        if fraction.is_empty() { "0" } else { fraction }
    )
}

// --- The pending store's views ---------------------------------------------

/// `getAllSafeSendStates()`: each pending entry's board state, oldest
/// first, as S3's codec reads it for its Safe's record ([`entry::read`]).
/// An entry it sets aside (no Safe record at its index, or one it doesn't
/// read for that Safe) is left out and logged; only the signatures that
/// count are counted.
fn pending_states(records: &Records, pending: &SafePending) -> Result<Vec<JsValue>, ErrorBody> {
    let mut states = Vec::new();
    for (index, value) in pending.entries() {
        let safe = match resolve(records, index) {
            Ok(safe) => safe,
            Err(error) if error.code == ErrorCode::Storage => return Err(error),
            Err(_) => {
                set_aside("record");
                continue;
            }
        };
        let read = match entry::read(&value, &safe.address, safe.setup.owners()) {
            Ok(read) => read,
            Err(why) => {
                set_aside(why.reason());
                continue;
            }
        };
        if read.refused > 0 {
            crate::log::warn(
                "a pending Safe entry's signatures that don't count: left out of it",
                json!({ "refused": read.refused }),
            );
        }
        match send_state(records, index, &value, &signers(&read), read.superseded)? {
            Some(state) => states.push(state),
            None => set_aside("shape"),
        }
    }
    // `sort((a, b) => a.createdAt - b.createdAt)`, stable: an entry whose
    // `createdAt` isn't a number goes last.
    states.sort_by(|a, b| created_at(a).total_cmp(&created_at(b)));
    Ok(states)
}

fn created_at(state: &JsValue) -> f64 {
    match state.get("createdAt") {
        Some(JsValue::Number(n)) if !n.is_nan() => *n,
        _ => f64::INFINITY,
    }
}

/// The owners whose signatures count, by address.
fn signers(read: &entry::Entry) -> Vec<[u8; 20]> {
    read.signatures
        .kept()
        .iter()
        .map(|kept| *kept.owner())
        .collect()
}

/// An entry the codec set aside: left out of the board, nothing signs it.
fn set_aside(reason: &str) {
    crate::log::warn(
        "a pending Safe entry set aside: left out, and nothing signs it",
        json!({ "reason": reason }),
    );
}

/// The Safe's pending entry, as the codec reads it for its record; none
/// when there is none, or when the codec sets it aside (logged).
fn pending_entry(pending: &SafePending, safe: &Safe) -> Option<entry::Entry> {
    let value = pending.entry(safe.index)?;
    match entry::read(&value, &safe.address, safe.setup.owners()) {
        Ok(read) => Some(read),
        Err(why) => {
            set_aside(why.reason());
            None
        }
    }
}

/// `safe.propose`'s signing and write, where no vault job is running: the
/// Safe's record as it stands now, which must still be the one the reads
/// checked; the vault owners' signatures (`collectFreeSignatures`); the
/// entry written, unless an entry that reads is pending meanwhile; then the
/// Safe's older `safe-send` approvals ended, as a new one ends them, since
/// a Safe has one pending SafeTx. The board's state, with `durable: false`
/// when the write's flush failed.
fn proposed(
    checked: &Safe,
    prepared: &Prepared,
    display: Option<&JsValue>,
    state: &VaultState,
    ctx: &mut Ctx,
) -> Result<JsValue, ErrorBody> {
    let records = ctx
        .approvals
        .account_records()
        .ok_or_else(not_moved)?
        .clone();
    let safe = resolve(&records, checked.index)?;
    if safe.address != checked.address || safe.setup != checked.setup {
        return Err(plain(format!(
            "Wallet {} is not a Safe account",
            safe.index
        )));
    }
    let threshold = safe.setup.threshold();
    let signatures = super::tx::vault_signatures(
        state,
        &records,
        &safe.vault_owners,
        safe.setup.owners(),
        &prepared.hash,
        threshold,
    );
    let written = entry::written(&entry::New {
        safe: &safe.address,
        tx: &prepared.tx,
        hash: &prepared.hash,
        threshold,
        display,
        signatures: &signatures,
        created_at_ms: ctx.clocks.wall_ms,
    })?;
    let durable = ctx
        .pending
        .set_where(safe.index, written.clone(), |current| match current {
            None => true,
            Some(current) => entry::read(current, &safe.address, safe.setup.owners()).is_err(),
        })
        .map_err(|failure| match failure {
            Failure::Bound(_) => refused("store_full", STORE_FULL_TEXT),
            other => other.error(),
        })?
        .ok_or_else(|| refused("SAFE_PENDING_EXISTS", PENDING_EXISTS_TEXT))?;
    ctx.approvals.end_safe_sends(&safe.address);
    crate::log::info(
        "a Safe transaction proposed",
        json!({ "signed": signatures.len() }),
    );
    let signers: Vec<[u8; 20]> = signatures.iter().map(|s| *s.owner()).collect();
    let mut answer = send_state(&records, safe.index, &written, &signers, false)?
        .ok_or_else(crate::vault::internal)?;
    if !durable {
        answer.set("durable", JsValue::Bool(false));
    }
    Ok(answer)
}

/// `getSafeSendState(index)` for `entry`, whose signatures that count are
/// `signers`' and which is `superseded` or not (the codec's reading).
fn send_state(
    records: &Records,
    index: u64,
    entry: &JsValue,
    signers: &[[u8; 20]],
    superseded: bool,
) -> Result<Option<JsValue>, ErrorBody> {
    let (JsValue::Object(_), Some(_)) =
        (entry, entry.get("signatures").and_then(JsValue::as_array))
    else {
        return Ok(None);
    };
    let owners: Vec<JsValue> = match records.record(index as f64)? {
        Some(record) if is_safe(&record) => record
            .get("owners")
            .and_then(JsValue::as_array)
            .map(<[JsValue]>::to_vec)
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let mut rows = Vec::with_capacity(owners.len());
    let mut executor = JsValue::Null;
    for owner in &owners {
        let record = match owner {
            JsValue::Number(at) => records.record(*at)?,
            _ => None,
        };
        let address = record
            .as_ref()
            .and_then(|r| r.get("address"))
            .filter(|a| a.truthy())
            .cloned()
            .unwrap_or(JsValue::Null);
        let kind = record
            .as_ref()
            .and_then(|r| r.get("type"))
            .filter(|t| t.truthy())
            .cloned()
            .unwrap_or_else(|| JsValue::string("mnemonic"));
        if matches!(executor, JsValue::Null)
            && kind.as_str() == Some("mnemonic")
            && record.is_some()
        {
            executor = owner.clone();
        }
        let signed =
            value_address_bytes(&address).is_some_and(|address| signers.contains(&address));
        rows.push(JsValue::Object(vec![
            ("index".into(), owner.clone()),
            ("address".into(), address),
            ("type".into(), kind),
            ("signed".into(), JsValue::Bool(signed)),
        ]));
    }
    let field = |key: &str| entry.get(key).cloned().unwrap_or(JsValue::Undefined);
    let call = |key: &str| {
        entry
            .get("safeTxData")
            .and_then(|data| data.get(key))
            .filter(|value| !matches!(value, JsValue::Undefined | JsValue::Null))
            .cloned()
            .unwrap_or(JsValue::Null)
    };
    Ok(Some(JsValue::Object(vec![
        ("safeIndex".into(), JsValue::Number(index as f64)),
        ("chainId".into(), field("chainId")),
        ("safeTxHash".into(), field("safeTxHash")),
        ("threshold".into(), field("threshold")),
        ("collected".into(), JsValue::Number(signers.len() as f64)),
        ("owners".into(), JsValue::Array(rows)),
        ("executorIndex".into(), executor),
        ("display".into(), field("display")),
        (
            "call".into(),
            JsValue::Object(vec![
                ("to".into(), call("to")),
                ("value".into(), call("value")),
                ("data".into(), call("data")),
            ]),
        ),
        ("createdAt".into(), field("createdAt")),
        (
            "status".into(),
            JsValue::string(if superseded { "superseded" } else { "awaiting" }),
        ),
    ])))
}

/// `cancelSafeSend(index, { safeTxHash })`: with `named`, only that SafeTx
/// (`SAFE_DISCARDED` otherwise, nothing discarded); the Safe's send
/// approvals ended, then its entry cleared. `{}`, and `durable: false`
/// when the clear's directory flush failed.
fn discard(
    records: &Records,
    ctx: &mut Ctx,
    index: u64,
    named: Option<&str>,
) -> Result<Value, ErrorBody> {
    ctx.pending.check_moved()?;
    let entry = ctx.pending.entry(index);
    if let Some(named) = named {
        let hash = entry
            .as_ref()
            .and_then(|e| e.get("safeTxHash"))
            .and_then(JsValue::as_str);
        if hash != Some(named) {
            return Err(refused(
                "SAFE_DISCARDED",
                "This transaction was discarded or replaced",
            ));
        }
    }
    if entry.is_none() {
        return Ok(json!({}));
    }
    let address = records
        .record(index as f64)?
        .filter(is_safe)
        .and_then(|record| record.get("address").and_then(value_address_bytes));
    if let Some(address) = address {
        ctx.approvals.end_safe_sends(&address);
    }
    let cleared = ctx
        .pending
        .clear(index)
        .map_err(|failure| failure.error())?;
    Ok(if cleared.durable {
        json!({})
    } else {
        json!({ "durable": false })
    })
}

#[cfg(test)]
mod tests;
