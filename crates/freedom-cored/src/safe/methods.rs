//! The `safe.*` methods (design 0016, API; SAFE-2's S2 to S6): a Safe's
//! record made in the core, its status and deployment read through the
//! chain machine, the pending store's board views, a Safe transaction
//! prepared, proposed, signed by the owners who sign later ([`owners`])
//! and executed, and a page's Safe message signed by the Safe's owners
//! ([`messages`]), a Ledger owner on the device lane. Every one answers
//! `not_moved` (`data.store: "vault_meta"`) until the hello names
//! `vault_meta`: the record is the core's to read and to mark.
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
//! - **`safe.deploy { safe, fee_ack? }`** → `{ send: { kind, account, tx,
//!   token } }`, the executor's deployment in `sign.transaction`'s form
//!   without its nonce (`createProxyWithNonce` to the factory, value 0, the
//!   estimate plus 20%, the core's fee quote) with its `executor-send`
//!   token, or `{ fee_check }`, or `{ deployed: true }` for a Safe that
//!   already is: judged and confirmed as an execution's send is (S4,
//!   below), the code and the balance read each time. `fee_ack: true` with
//!   its offer standing reads no estimate, fee quote or fee evidence: the
//!   offer is sent as shown while the balance covers its cost. With no
//!   vault owner, or a balance below the cost, `SAFE_NEEDS_FUNDS`, nothing
//!   minted. A deployment isn't a Safe's call, so main's word still signs
//!   one under `shell` without the token, as today's activation does until
//!   SAFE-3; presented, the token is checked.
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
//! - **`safe.execute { safe, fee_ack?, safe_tx_hash? }`** → `{ send }`,
//!   `{ fee_check }` or `{ superseded }` (S4): the pending SafeTx as the
//!   codec reads it (`safe_tx_hash`, when given, must name it), of a Safe
//!   the record marks deployed; the eight reads again, each verified, the
//!   nonce last; then the record and the entry read again, still the ones
//!   checked (`SAFE_DISCARDED` for an entry replaced meanwhile, as
//!   `executeSafePending` refuses it). A nonce past the SafeTx's ends the
//!   Safe's `safe-send` approvals and marks the entry `superseded`, as the
//!   reference writes it, and answers the board's state; one below it is
//!   `nonce_behind`. At the nonce, with the record's threshold of
//!   signatures that count, the executor's send.
//! - **The executor's send:** `execTransaction` to the Safe with every
//!   signature that counts, joined as `buildSignatureBytes` joins them,
//!   value 0, from the first vault owner, its gas the estimate plus 20%
//!   and its fees the core's quote, in `sign.transaction`'s form without
//!   its nonce. Judged as `quotedExecutorSend` judges it: a fee the check
//!   approves on its own (`autoApprove`) gets `{ send }` at once; any other
//!   `{ fee_check }`, the verdict at approval, and the core keeps that
//!   offer. `fee_ack: true` then gets `{ send }` for exactly that
//!   transaction, with no new quote, while the SafeTx and its calldata are
//!   the same, as `confirmedExecutorSend` signs the fee the user confirmed;
//!   otherwise it is quoted again, and a fee the check stops is offered
//!   again.
//! - **Its token:** `{ send: { kind: "executor-send", account, tx, token
//!   } }` carries an `executor-send` token the core minted for `tx`, its
//!   nonce unbound, as fc-eip1193's `{ send }` carries a `dapp-send`'s.
//!   `sign.transaction` spends it under `shell`, `{ token, kind:
//!   "executor-send" }`: any other field changed is `mismatch`. A Safe's
//!   `execTransaction` signs only with a token or a Safe approval (APR-4b),
//!   so the core's prepared send signs only with it. Each Safe has at most
//!   one outstanding: a newer one burns the older, and so do the Safe's
//!   discard, its SafeTx superseded or executed, and the record's removal.
//! - **`safe.executed { safe, safe_tx_hash, hash }`** → `{}` (S4): main's
//!   word, after its broadcast, that the SafeTx executed, as today. The
//!   Safe's `safe-send` approvals end, then its entry is cleared while it
//!   is still the SafeTx named: none pending is `{}`, another
//!   `SAFE_DISCARDED` with nothing cleared. It reads no chain.
//! - **`safe.message_start`**, **`.message_sign`**, **`.message_state`**,
//!   **`.message_cancel`** and **`.message_complete`** (S5): a page's
//!   `personal_sign` or `eth_signTypedData_v4` for a Safe, as a session of
//!   owner signatures over its SafeMessage ([`messages`]); a Ledger owner's
//!   on the device lane (S6).
//! - **`safe.sign_owner { safe, owner?, safe_tx_hash? }`** → the board's
//!   state (S6): the pending SafeTx signed by the vault owners that haven't
//!   signed (the board's sweep after a proposal made while the vault was
//!   locked), or by the owner named, a vault owner or a Ledger owner on the
//!   device lane, after the eight reads ([`owners`]).
//! - **The Safe's hold:** from a `safe.propose`'s spend to its answer, and
//!   from a `safe.execute`'s start to its answer, the Safe is held: another
//!   `safe.propose` for it is `SAFE_PENDING_EXISTS`, as the reference's
//!   reservation answers, `safe.discard` `SAFE_BUSY`, as `cancelSafeSend`
//!   answers while a step runs, and `safe.execute` `SAFE_BUSY`, as its
//!   `acquire` answers. Main keeps its own exclusion from `{ send }` to
//!   `safe.executed`. A message's step holds it too, from a
//!   `safe.message_start`'s spend and a `safe.message_sign`'s start to
//!   their answers, as the reference's one step per Safe covers sends and
//!   message sessions alike (`signature-collection.js`'s `acquire`): every
//!   other step of the Safe is `SAFE_BUSY` meanwhile, a `safe.propose` too.
//!   So does a `safe.sign_owner`, from its start to its answer, a Ledger
//!   owner's wait on the device included (S6).
//! - **Refusals** are `invalid_argument` with `data.safe`: `unsupported`,
//!   `unverified` (a deployment or activation no read answered, or a read
//!   a step that signs rests on), `changed`, `not_deployed`, `self_call`,
//!   `nonce_behind`, `store_full`, or today's `SAFE_*` codes
//!   (`SAFE_ADDRESS_MISMATCH`, `SAFE_NEEDS_FUNDS`, `SAFE_DISCARDED`,
//!   `SAFE_PENDING_EXISTS`, `SAFE_BUSY`, and a message's
//!   `SAFE_MESSAGE_EXISTS` and `SAFE_APPROVAL_NEEDED`). `safe.status` reports `changed`,
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

use serde::Serialize;
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
use messages::{Opening, Sessions};
use owners::Named;

/// The methods, in `core.hello`'s capability order.
pub const METHODS: [&str; 16] = [
    "safe.create",
    "safe.status",
    "safe.deploy",
    "safe.deployed",
    "safe.pending",
    "safe.discard",
    "safe.prepare",
    "safe.propose",
    "safe.execute",
    "safe.executed",
    "safe.message_start",
    "safe.message_sign",
    "safe.message_state",
    "safe.message_cancel",
    "safe.message_complete",
    "safe.sign_owner",
];

/// The kind of the token the executor's prepared send carries (S4).
pub const SEND_KIND: &str = "executor-send";

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

/// `beginStep`'s, for a step started while another holds the Safe.
const STEP_BUSY_TEXT: &str = "Another step of this transaction is still running";

/// `executeSafePending`'s, with nothing pending.
const NO_PENDING_TEXT: &str = "No pending transaction for this account";

/// `pickDefaultExecutor`'s, with no vault owner to pay.
const NO_EXECUTOR_TO_EXECUTE_TEXT: &str = "No browser account among the owners to act as executor \
     \u{2014} choose one that can pay gas";

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

/// A 32-byte hash: `0x` and 64 hex digits.
fn hash_param(params: &serde_json::Map<String, Value>, key: &str) -> Result<[u8; 32], ErrorBody> {
    params
        .get(key)
        .and_then(Value::as_str)
        .and_then(|text| parse_bytes(text, key).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(invalid)
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
    /// Every owner, in the record's order: each wallet index, as the record
    /// stores it, and address.
    owners: Vec<(f64, [u8; 20])>,
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
    let mut listed = Vec::with_capacity(owners.len());
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
        listed.push((*at, address));
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
        owners: listed,
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
    Deploy {
        fee_ack: bool,
    },
    Deployed {
        hash: [u8; 32],
    },
    Prepare,
    Propose,
    Execute {
        fee_ack: bool,
    },
    /// `safe.message_start` (S5).
    MessageStart,
    /// `safe.message_sign` (S5).
    MessageSign,
    /// `safe.sign_owner` (S6).
    SignOwner,
}

/// What a `safe.prepare`, `safe.propose` or `safe.execute` carries beside
/// its Safe.
enum Work {
    None,
    /// The call to build the SafeTx for.
    Prepare(Call),
    /// The SafeTx its token confirmed, and the caller's display data.
    Propose {
        prepared: Box<Prepared>,
        display: Option<JsValue>,
    },
    /// The pending SafeTx to execute, by its hash, as the codec read it
    /// before the reads.
    Execute {
        hash: [u8; 32],
    },
    /// Its executor's send being priced: the SafeTx's hash and the
    /// `execTransaction` calldata.
    Exec {
        hash: [u8; 32],
        data: Vec<u8>,
    },
    /// The session `safe.message_start` opens once its reads are in (S5).
    MessageStart(Box<Opening>),
    /// The session `safe.message_sign` signs, by its serial, and the owner
    /// named (S5; a Ledger owner from S6), or none for the sweep.
    MessageSign {
        serial: u64,
        owner: Option<Named>,
    },
    /// The pending SafeTx `safe.sign_owner` signs, by its hash, and the
    /// owner named, or none for the vault owners' sweep (S6).
    SignOwner {
        hash: [u8; 32],
        owner: Option<Named>,
    },
}

/// An executor's send the fee check stopped, offered at `{ fee_check }`
/// for the user to confirm: `fee_ack: true` mints for exactly it while it
/// sends the same thing, as `confirmedExecutorSend` signs the fee the user
/// confirmed.
struct Offer {
    safe: [u8; 20],
    /// The SafeTx an execution executes; none for the deployment.
    hash: Option<[u8; 32]>,
    account: u64,
    data: Vec<u8>,
    tx: Value,
    /// Its cost, the gas limit times `maxFeePerGas ?? gasPrice`: the
    /// executor's balance must still cover a deployment's when the user
    /// confirms it.
    cost: U256,
}

/// `{ send }`: the executor's prepared send and its token, which goes
/// last, into a buffer wiped when dropped, as `approval.issue`'s does.
#[derive(Serialize)]
struct SendReply<'a> {
    send: SendBody<'a>,
}

#[derive(Serialize)]
struct SendBody<'a> {
    kind: &'static str,
    account: u64,
    tx: &'a Value,
    token: &'a str,
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
    /// A Ledger owner's operation is on the device lane (S6): no read is
    /// out, and the reads' bound no longer applies; the lane's own bounds
    /// hold until [`Safes::device_ended`].
    Device,
}

/// The activation's or the execution's reads: the estimate, the fee
/// quote, for the activation the executor's balance, and for a deployment
/// or an execution the fee evidence when it is stale. A deployment's
/// confirmed offer reads the balance alone.
struct Quote {
    estimate: Option<Reply>,
    fee: Option<Reply>,
    balance: Option<Reply>,
    /// Whether the balance is read (the activation's).
    wants_balance: bool,
    /// The fee evidence's read is out.
    reference: bool,
    /// What the code read showed, for `safe.status`'s `setup`.
    setup: Outcome,
    /// The deployment's offer `fee_ack` confirms, as it stood when the
    /// request started: no estimate or fee quote is read for it
    /// ([`Safes::confirmed`]).
    offer: Option<Value>,
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
    /// The token of each Safe's outstanding prepared send (S4), by wallet
    /// index, with the Safe's address: burnt when a newer one is minted
    /// for the Safe, when its SafeTx is discarded, superseded or executed,
    /// and when the records no longer hold the Safe. A bearer secret, wiped
    /// when dropped and never logged.
    sends: BTreeMap<u64, ([u8; 20], Zeroizing<String>)>,
    /// The executor's sends the fee check stopped, by the Safe's wallet
    /// index, for `fee_ack` to confirm (S4).
    offers: BTreeMap<u64, Offer>,
    /// The Safes' message sessions, one per Safe, in memory only (S5).
    sessions: Sessions,
}

/// What the methods read and change beyond their own state.
pub struct Ctx<'a> {
    /// The fee evidence, the fee check, the Safe approvals and the
    /// records' snapshot.
    pub approvals: &'a mut Approvals,
    pub pending: &'a SafePending,
    pub clocks: Clocks,
    pub now: Instant,
    /// Whether the vault is unlocked now: a message's step that could sign
    /// nothing with it locked reads nothing (S5). The vault owners sign
    /// with the vault's state as it stands at the write.
    pub unlocked: bool,
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

/// Whether `records` hold, at wallet index `index`, the Safe at `address`.
fn holds_safe_at(records: Option<&Records>, index: u64, address: &[u8; 20]) -> bool {
    let Some(records) = records else {
        return false;
    };
    matches!(
        records.record(index as f64),
        Ok(Some(record)) if is_safe(&record)
            && record.get("address").and_then(value_address_bytes) == Some(*address)
    )
}

impl Safes {
    pub fn new() -> Self {
        Safes::default()
    }

    /// The records' snapshot changed (G20): the session's reports, the
    /// prepared sends' tokens and the offers kept only for the Safes
    /// `records` still hold, so a removed Safe's go with its record. The
    /// tokens of the sends dropped, for the caller to burn.
    #[must_use]
    pub fn records_changed(&mut self, records: Option<&Records>) -> Vec<Zeroizing<String>> {
        self.session.retain(|address| holds_safe(records, address));
        self.offers
            .retain(|index, offer| holds_safe_at(records, *index, &offer.safe));
        self.sessions
            .retain(|index, safe| holds_safe_at(records, index, safe));
        let (kept, dropped): (BTreeMap<_, _>, BTreeMap<_, _>) = std::mem::take(&mut self.sends)
            .into_iter()
            .partition(|(index, (safe, _))| holds_safe_at(records, *index, safe));
        self.sends = kept;
        dropped.into_values().map(|(_, token)| token).collect()
    }

    /// The Safe at wallet index `index` has no prepared send any more: its
    /// SafeTx was discarded, superseded or executed. Its token is burnt and
    /// its offer dropped.
    fn forget_send(&mut self, index: u64, approvals: &mut Approvals) {
        if let Some((_, token)) = self.sends.remove(&index) {
            approvals.burn(&token);
        }
        self.offers.remove(&index);
    }

    /// `{ send }` for the Safe `safe`: an `executor-send` token minted for
    /// `tx` (`sign.transaction`'s form without its nonce) for the executor
    /// at wallet index `account`, the Safe's earlier one burnt.
    fn send_reply(&mut self, id: u64, safe: &Safe, account: u64, tx: &Value, ctx: &mut Ctx) -> Out {
        let token = match ctx.approvals.executor_token(account, tx, ctx.clocks) {
            Ok(token) => token,
            Err(error) => return failed(id, &error),
        };
        let reply = SendReply {
            send: SendBody {
                kind: SEND_KIND,
                account,
                tx,
                token: &token,
            },
        };
        let size = tx.to_string().len().saturating_add(512);
        let mut payload = Zeroizing::new(Vec::with_capacity(size));
        if fc_protocol::message::write_result(&mut *payload, id, &reply).is_err() {
            ctx.approvals.burn(&token);
            return failed(id, &crate::vault::internal());
        }
        if let Some((_, older)) = self.sends.insert(safe.index, (safe.address, token)) {
            ctx.approvals.burn(&older);
        }
        Out::Send(payload)
    }

    /// Whether this module serves `method` on the loop (`safe.create` runs
    /// on the vault queue).
    pub fn handles(method: &str) -> bool {
        METHODS.contains(&method) && method != "safe.create"
    }

    /// A request from `context`: its replies and reads. A token
    /// `safe.propose` or `safe.message_start` presents is burnt however the
    /// request ends, as `sign.*` burns one (design 0012, "Tokens").
    pub fn request(
        &mut self,
        id: u64,
        method: &str,
        raw: Option<&str>,
        context: &Context,
        ctx: &mut Ctx,
    ) -> Vec<Out> {
        let presented = matches!(method, "safe.propose" | "safe.message_start")
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
            "safe.message_start" => {
                return self.message_start(id, raw, context, &records, ctx);
            }
            "safe.message_sign" => return self.message_sign(id, raw, &records, ctx),
            "safe.message_state" => return self.message_state(id, raw, &records),
            "safe.message_cancel" => return self.message_cancel(id, raw),
            "safe.message_complete" => return self.message_complete(id, raw),
            "safe.sign_owner" => return self.sign_owner(id, raw, &records, ctx),
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
                if self.busy(index) {
                    return Err(refused("SAFE_BUSY", BUSY_TEXT));
                }
                let named = match p.get("safe_tx_hash") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(hash)) => Some(hash.clone()),
                    Some(_) => return Err(invalid()),
                };
                let answer = discard(&records, ctx, index, named.as_deref())?;
                // Its prepared send, if any, signs nothing now.
                self.forget_send(index, ctx.approvals);
                return Ok(vec![reply(id, &answer)]);
            }
            "safe.execute" => {
                ctx.pending.check_moved()?;
                let p = members(raw, &["safe", "fee_ack", "safe_tx_hash"], &mut params)?;
                let index = index_of(p, "safe")?;
                let fee_ack = match p.get("fee_ack") {
                    None => false,
                    Some(Value::Bool(ack)) => *ack,
                    Some(_) => return Err(invalid()),
                };
                let named = match p.get("safe_tx_hash") {
                    None | Some(Value::Null) => None,
                    Some(_) => Some(hash_param(p, "safe_tx_hash")?),
                };
                let safe = resolve(&records, index)?;
                // `executeSafePending`'s order: the SafeTx named, one
                // pending, the deployed mark, then the step's hold.
                let entry = pending_entry(ctx.pending, &safe);
                if let Some(named) = named
                    && entry.as_ref().map(|entry| entry.hash) != Some(named)
                {
                    return Err(refused("SAFE_DISCARDED", DISCARDED_TEXT));
                }
                let Some(entry) = entry else {
                    return Err(plain(NO_PENDING_TEXT));
                };
                if !safe.marked {
                    return Err(not_deployed());
                }
                if self.busy(index) {
                    return Err(refused("SAFE_BUSY", STEP_BUSY_TEXT));
                }
                let work = Work::Execute { hash: entry.hash };
                return Ok(self.check(id, Kind::Execute { fee_ack }, safe, work, ctx.now));
            }
            "safe.executed" => {
                ctx.pending.check_moved()?;
                let p = members(raw, &["safe", "safe_tx_hash", "hash"], &mut params)?;
                let index = index_of(p, "safe")?;
                let named = hash_param(p, "safe_tx_hash")?;
                hash_param(p, "hash")?;
                let answer = executed(&records, ctx, index, &named)?;
                // Executed, or no longer pending: its send signs nothing.
                self.forget_send(index, ctx.approvals);
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
                // A message's step holds it: the one step per Safe.
                if self.busy(index) {
                    return Err(refused("SAFE_BUSY", STEP_BUSY_TEXT));
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
                let hash = hash_param(p, "hash")?;
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
            Kind::Prepare
            | Kind::Propose
            | Kind::Execute { .. }
            | Kind::MessageStart
            | Kind::MessageSign
            | Kind::SignOwner => {
                return Err(crate::vault::internal());
            }
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
                    Progress::Done(outcome) => self.setup_done(id, op, outcome, ctx),
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
                // A confirmed offer has no estimate or fee quote out.
                let priced = quote.offer.is_none();
                if (priced && (quote.estimate.is_none() || quote.fee.is_none()))
                    || (quote.wants_balance && quote.balance.is_none())
                    || quote.reference
                {
                    op.step = Step::Quote(quote);
                    self.ops.insert(id, op);
                    return Vec::new();
                }
                match quote.offer.take() {
                    Some(tx) => self.confirmed(id, op, tx, *quote, ctx),
                    None => vec![self.quoted(id, &op, &quote, ctx)],
                }
            }
            // No read is out while the mark or the write is due, or while
            // the device signs: a stray reply changes nothing.
            Step::Mark | Step::Write | Step::Device => {
                self.ops.insert(id, op);
                Vec::new()
            }
        }
    }

    /// The deployment as the reads show it (D4): marked on verified
    /// evidence, reported for the session on an unverified answer of it,
    /// and a verified empty code ends the session's report.
    fn judged(&mut self, id: u64, op: Op, receipt: Receipt, code: Code, ctx: &mut Ctx) -> Vec<Out> {
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
                    Kind::Prepare
                    | Kind::Propose
                    | Kind::Execute { .. }
                    | Kind::MessageStart
                    | Kind::MessageSign
                    | Kind::SignOwner => {
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
                Kind::Prepare
                | Kind::Propose
                | Kind::Execute { .. }
                | Kind::MessageStart
                | Kind::MessageSign
                | Kind::SignOwner => vec![failed(id, &crate::vault::internal())],
                Kind::Status | Kind::Deploy { .. } => {
                    let Some(executor) = op.safe.executor.clone() else {
                        return vec![match op.kind {
                            Kind::Status => {
                                reply(id, &status(&op.safe, false, None, None, true, &seen))
                            }
                            _ => failed(id, &refused("SAFE_NEEDS_FUNDS", NO_EXECUTOR_TEXT)),
                        }];
                    };
                    let deployment = op.safe.setup.deployment(&op.safe.salt);
                    // The offer the user confirmed: sent as offered, with
                    // no new estimate or quote, once the balance shows the
                    // executor can still pay it (S4).
                    if op.kind == (Kind::Deploy { fee_ack: true })
                        && let Some(offer) =
                            self.offer(&op.safe, None, executor.index, &deployment.data)
                    {
                        let tx = offer.tx.clone();
                        return self.confirm(id, op, &executor.address, tx, seen, ctx);
                    }
                    let call = Priced::call(&executor.address, &deployment.to, &deployment.data);
                    // Only a deployment is judged by the fee check.
                    let judged = matches!(op.kind, Kind::Deploy { .. });
                    self.quote(id, op, &call, Some(&executor.address), judged, seen, ctx)
                }
            },
        }
    }

    /// The activation's or the execution's quote, `op` waiting for it: the
    /// estimate of `call` (`eth_estimateGas`'s params), the core's fee
    /// quote, the executor's balance at `balance` (the activation's), and,
    /// when the send is `judged` by the fee check, the fee evidence if it
    /// is stale. `setup` is what the code read showed, for `safe.status`.
    #[allow(clippy::too_many_arguments)]
    fn quote(
        &mut self,
        id: u64,
        mut op: Op,
        call: &Value,
        balance: Option<&[u8; 20]>,
        judged: bool,
        setup: Outcome,
        ctx: &mut Ctx,
    ) -> Vec<Out> {
        let mut out = vec![
            self.read(
                id,
                Some(Part::Estimate),
                "eth_estimateGas",
                call.to_string(),
                &op,
                ctx.now,
            ),
            self.read(
                id,
                Some(Part::Fee),
                crate::chain::INTERNAL_FEE_QUOTE,
                String::new(),
                &op,
                ctx.now,
            ),
        ];
        if let Some(executor) = balance {
            let params = format!(r#"["{}","latest"]"#, to_hex(executor));
            out.push(self.read(
                id,
                Some(Part::Balance),
                "eth_getBalance",
                params,
                &op,
                ctx.now,
            ));
        }
        let mut quote = Quote {
            estimate: None,
            fee: None,
            balance: None,
            wants_balance: balance.is_some(),
            reference: false,
            setup,
            offer: None,
        };
        if judged && !ctx.approvals.fee_fresh(CHAIN_ID, ctx.clocks.vault_ms) {
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

    /// `safe.deploy { fee_ack: true }` with its offer standing (`tx`), `op`
    /// waiting for the executor's balance at `executor` alone: no estimate,
    /// fee quote or fee evidence is read for a fee the user confirmed.
    fn confirm(
        &mut self,
        id: u64,
        mut op: Op,
        executor: &[u8; 20],
        tx: Value,
        setup: Outcome,
        ctx: &mut Ctx,
    ) -> Vec<Out> {
        let params = format!(r#"["{}","latest"]"#, to_hex(executor));
        let read = self.read(
            id,
            Some(Part::Balance),
            "eth_getBalance",
            params,
            &op,
            ctx.now,
        );
        op.step = Step::Quote(Box::new(Quote {
            estimate: None,
            fee: None,
            balance: None,
            wants_balance: true,
            reference: false,
            setup,
            offer: Some(tx),
        }));
        self.ops.insert(id, op);
        vec![read]
    }

    /// A Safe known deployed: `safe.deploy` has nothing to send;
    /// `safe.status` reads the code and the setup, and no nonce.
    fn deployed(&mut self, id: u64, mut op: Op, ctx: &mut Ctx) -> Vec<Out> {
        match op.kind {
            Kind::Deployed { .. } => vec![reply(id, &json!({ "deployed": true }))],
            Kind::Deploy { .. } => vec![reply(id, &json!({ "deployed": true }))],
            Kind::Prepare
            | Kind::Propose
            | Kind::Execute { .. }
            | Kind::MessageStart
            | Kind::MessageSign
            | Kind::SignOwner => vec![failed(id, &crate::vault::internal())],
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

    /// Whether a `safe.propose` or a `safe.execute` holds the Safe at
    /// wallet index `index`.
    fn holds(&self, index: u64) -> bool {
        self.ops.values().any(|op| {
            matches!(op.kind, Kind::Propose | Kind::Execute { .. }) && op.safe.index == index
        })
    }

    /// Whether any step holds the Safe at wallet index `index`: a send's
    /// ([`Safes::holds`]), a message's (S5) or an owner's signature (S6),
    /// the reference's one step per Safe (`signature-collection.js`'s
    /// `acquire`).
    fn busy(&self, index: u64) -> bool {
        self.ops.values().any(|op| {
            matches!(
                op.kind,
                Kind::Propose
                    | Kind::Execute { .. }
                    | Kind::MessageStart
                    | Kind::MessageSign
                    | Kind::SignOwner
            ) && op.safe.index == index
        })
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
    fn setup_done(&mut self, id: u64, mut op: Op, outcome: Outcome, ctx: &mut Ctx) -> Vec<Out> {
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
            // `safe.execute`: the record and the entry still the ones
            // checked, then the SafeTx against the verified nonce.
            Work::Execute { hash } => {
                let (safe, entry) = match still(&op.safe, &hash, ctx) {
                    Ok(still) => still,
                    Err(error) => return vec![failed(id, &error)],
                };
                match entry.tx.nonce_state(&nonce) {
                    fc_safe::NonceState::Superseded => {
                        vec![match self.supersede(&safe, &entry, ctx) {
                            Ok(state) => {
                                js_reply(id, &JsValue::Object(vec![("superseded".into(), state)]))
                            }
                            Err(error) => failed(id, &error),
                        }]
                    }
                    fc_safe::NonceState::Behind => {
                        vec![failed(id, &refused("nonce_behind", NONCE_BEHIND_TEXT))]
                    }
                    fc_safe::NonceState::Ready => {
                        op.safe = safe;
                        self.execute(id, op, &entry, ctx)
                    }
                }
            }
            // A message's start: the session opened where no vault job is
            // running, with the vault's state ([`Safes::write`]).
            work @ Work::MessageStart(_) => {
                op.work = work;
                op.step = Step::Write;
                self.ops.insert(id, op);
                self.writes.push(id);
                Vec::new()
            }
            // A message's owners: signed where no vault job is running, or
            // a Ledger owner's operation to the lane (S6).
            Work::MessageSign { serial, owner } => self.message_checked(id, op, serial, owner, ctx),
            // `safe.sign_owner` (S6): the record and the entry still the
            // ones read, at the verified nonce.
            Work::SignOwner { hash, owner } => self.owner_checked(id, op, hash, owner, &nonce, ctx),
            Work::Exec { .. } | Work::None => vec![failed(id, &crate::vault::internal())],
        }
    }

    /// A pending SafeTx at the Safe's nonce (`entry`): with the record's
    /// threshold of signatures that count, its `execTransaction` calldata,
    /// every such signature joined; then the executor's send, at once for
    /// the offer `fee_ack` confirms, or after its quote.
    fn execute(&mut self, id: u64, mut op: Op, entry: &entry::Entry, ctx: &mut Ctx) -> Vec<Out> {
        let threshold = op.safe.setup.threshold();
        let joined = match entry.signatures.joined_at(threshold) {
            Ok(joined) => joined,
            // "Not enough signatures yet (1 of 2)".
            Err(error) => return vec![failed(id, &plain(error.to_string()))],
        };
        let Some(executor) = op.safe.executor.clone() else {
            return vec![failed(id, &plain(NO_EXECUTOR_TO_EXECUTE_TEXT))];
        };
        let data = fc_safe::exec_transaction(&entry.tx, &joined);
        if op.kind == (Kind::Execute { fee_ack: true })
            && let Some(tx) = self.offered(&op.safe, Some(entry.hash), executor.index, &data)
        {
            return vec![self.send_reply(id, &op.safe, executor.index, &tx, ctx)];
        }
        let call = Priced::call(&executor.address, &op.safe.address, &data);
        op.work = Work::Exec {
            hash: entry.hash,
            data,
        };
        self.quote(id, op, &call, None, true, Outcome::SetupUnchanged, ctx)
    }

    /// A SafeTx the Safe's verified nonce has passed can never execute
    /// (`executeSafePending`'s superseded): the Safe's `safe-send`
    /// approvals end first, as the reference ends its approval, then its
    /// entry is marked `superseded: true` as the reference writes it, while
    /// it is still the entry read. The board's state, `status:
    /// "superseded"`, with `durable: false` when the write's flush failed.
    fn supersede(
        &mut self,
        safe: &Safe,
        entry: &entry::Entry,
        ctx: &mut Ctx,
    ) -> Result<JsValue, ErrorBody> {
        let records = ctx
            .approvals
            .account_records()
            .ok_or_else(not_moved)?
            .clone();
        let current = ctx
            .pending
            .entry(safe.index)
            .filter(|current| {
                entry::read(current, &safe.address, safe.setup.owners())
                    .is_ok_and(|read| read.hash == entry.hash)
            })
            .ok_or_else(|| refused("SAFE_DISCARDED", DISCARDED_TEXT))?;
        ctx.approvals.end_safe_sends(&safe.address);
        self.forget_send(safe.index, ctx.approvals);
        let mut marked = current.clone();
        marked.set("superseded", JsValue::Bool(true));
        let durable = ctx
            .pending
            .set_where(safe.index, marked.clone(), |now| now == Some(&current))
            .map_err(|failure| match failure {
                Failure::Bound(_) => refused("store_full", STORE_FULL_TEXT),
                other => other.error(),
            })?
            .ok_or_else(|| refused("SAFE_DISCARDED", DISCARDED_TEXT))?;
        crate::log::info("a pending Safe transaction superseded", json!({}));
        let mut state = send_state(&records, safe.index, &marked, &signers(entry), true)?
            .ok_or_else(crate::vault::internal)?;
        if !durable {
            state.set("durable", JsValue::Bool(false));
        }
        Ok(state)
    }

    /// The proposals whose signing and write are due, and the message
    /// steps whose signing is (S5), for the vault to run where no vault job
    /// is running ([`Safes::write`]).
    pub fn take_writes(&mut self) -> Vec<u64> {
        let due = std::mem::take(&mut self.writes);
        due.into_iter()
            .filter(|id| self.ops.contains_key(id))
            .collect()
    }

    /// Proposal `id`'s signing and write, with the vault's `state`: its
    /// answer, the board's state. Or a message's step (S5): the session
    /// `safe.message_start` opens, or the owners `safe.message_sign` signs.
    /// Or `safe.sign_owner`'s (S6): its owners' signatures added to the
    /// pending entry. A Ledger owner's signature is the device's, kept
    /// since [`Safes::device_ended`].
    pub fn write(&mut self, id: u64, state: &VaultState, ctx: &mut Ctx) -> Vec<Out> {
        let Some(op) = self.ops.remove(&id) else {
            return Vec::new();
        };
        match op.work {
            Work::Propose { prepared, display } => {
                match proposed(&op.safe, &prepared, display.as_ref(), state, ctx) {
                    Ok(state) => vec![js_reply(id, &state)],
                    Err(error) => vec![failed(id, &error)],
                }
            }
            Work::MessageStart(opening) => vec![self.opened(id, &op.safe, *opening, state, ctx)],
            Work::MessageSign { serial, owner } => {
                vec![self.message_signed(id, &op.safe, serial, owner, state, ctx)]
            }
            Work::SignOwner { hash, owner } => {
                vec![self.owner_signed(id, &op.safe, hash, owner, state, ctx)]
            }
            _ => vec![failed(id, &crate::vault::internal())],
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
        let priced = match answer(&quote.estimate)
            .zip(answer(&quote.fee))
            .ok_or_else(crate::vault::internal)
            .and_then(|(estimate, fee)| priced(&estimate, &fee))
        {
            Ok(priced) => priced,
            Err(error) => return failed(id, &error),
        };
        let Some(executor) = &op.safe.executor else {
            return failed(id, &crate::vault::internal());
        };
        // The execution's send: no balance is read, as `quotedExecutorSend`
        // reads none.
        if let (Kind::Execute { .. }, Work::Exec { hash, data }) = (op.kind, &op.work) {
            return self.exec_priced(id, op, hash, data, &priced, ctx);
        }
        let balance = match answer(&quote.balance)
            .as_ref()
            .and_then(Value::as_str)
            .and_then(parse_unsigned)
        {
            Some(balance) => balance,
            None => return failed(id, &plain("Invalid balance")),
        };
        let needs_funds = balance < priced.cost;
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
            Kind::Deploy { .. } => {
                if needs_funds {
                    return failed(id, &needs_funds_error(&executor.text, &priced.cost));
                }
                // The executor's send, judged as an execution's is (S4). A
                // confirmed offer never reaches here ([`Safes::confirm`]):
                // `fee_ack` with none standing is quoted again, and a fee the
                // check stops is offered again.
                let deployment = op.safe.setup.deployment(&op.safe.salt);
                let tx = priced.tx(&deployment.to, &deployment.data);
                let (account, data) = (executor.index, &deployment.data);
                self.judge(id, &op.safe, None, account, data, tx, priced.cost, ctx)
            }
            Kind::Deployed { .. }
            | Kind::Prepare
            | Kind::Propose
            | Kind::Execute { .. }
            | Kind::MessageStart
            | Kind::MessageSign
            | Kind::SignOwner => failed(id, &crate::vault::internal()),
        }
    }

    /// The execution's send priced: `execTransaction` (`data`, for the
    /// SafeTx `hash`) to the Safe, value 0, judged by the fee check at
    /// approval as `quotedExecutorSend` judges it. A fee the check approves
    /// on its own (`autoApprove`) gets `{ send }` with its token; any other
    /// is offered, `{ fee_check }` with the verdict, and kept for
    /// `fee_ack` to confirm. The record and the entry must still be the
    /// ones checked.
    fn exec_priced(
        &mut self,
        id: u64,
        op: &Op,
        hash: &[u8; 32],
        data: &[u8],
        priced: &Priced,
        ctx: &mut Ctx,
    ) -> Out {
        let safe = match still(&op.safe, hash, ctx) {
            Ok((safe, _)) => safe,
            Err(error) => return failed(id, &error),
        };
        let Some(executor) = safe.executor.clone() else {
            return failed(id, &plain(NO_EXECUTOR_TO_EXECUTE_TEXT));
        };
        let tx = priced.tx(&safe.address, data);
        self.judge(
            id,
            &safe,
            Some(*hash),
            executor.index,
            data,
            tx,
            priced.cost,
            ctx,
        )
    }

    /// The executor's send `tx` for the Safe `safe`, judged by the fee
    /// check at approval as `quotedExecutorSend` judges it: a fee the check
    /// approves on its own (`autoApprove`: comparable, not above, not one
    /// endpoint's evidence) gets `{ send }` with its token; any other is
    /// offered, `{ fee_check }` with the verdict, nothing minted, and kept
    /// for `fee_ack` to confirm (`hash`: the SafeTx it executes; `data`
    /// what it sends; `cost` what `tx` costs at most).
    #[allow(clippy::too_many_arguments)]
    fn judge(
        &mut self,
        id: u64,
        safe: &Safe,
        hash: Option<[u8; 32]>,
        account: u64,
        data: &[u8],
        tx: Value,
        cost: U256,
        ctx: &mut Ctx,
    ) -> Out {
        let (verdict, _) = ctx
            .approvals
            .page_fee_check(&tx.to_string(), Some(false), ctx.clocks);
        let verdict: Value = serde_json::from_str(&verdict).unwrap_or(Value::Null);
        if verdict.get("autoApprove") == Some(&Value::Bool(true)) {
            return self.send_reply(id, safe, account, &tx, ctx);
        }
        crate::log::info(
            "a Safe executor's fee needs the user's confirmation",
            json!({}),
        );
        self.offers.insert(
            safe.index,
            Offer {
                safe: safe.address,
                hash,
                account,
                data: data.to_vec(),
                tx,
                cost,
            },
        );
        reply(id, &json!({ "fee_check": verdict }))
    }

    /// `safe.deploy { fee_ack: true }`'s balance is in (`quote.balance`).
    /// The offer it started with (`tx`) is checked first, before the reply
    /// is read at all: one replaced or dropped meanwhile is no longer the
    /// one the user confirmed, so it is quoted again, as with none
    /// standing, whatever the balance read answered. While it stands, it
    /// gets `{ send }` exactly as offered, as `confirmedExecutorSend` signs
    /// the fee the user confirmed, if the executor can still pay its cost;
    /// with too little, `SAFE_NEEDS_FUNDS` and nothing minted.
    fn confirmed(&mut self, id: u64, op: Op, tx: Value, quote: Quote, ctx: &mut Ctx) -> Vec<Out> {
        let Some(executor) = op.safe.executor.clone() else {
            return vec![failed(id, &crate::vault::internal())];
        };
        let deployment = op.safe.setup.deployment(&op.safe.salt);
        let standing = self
            .offer(&op.safe, None, executor.index, &deployment.data)
            .filter(|offer| offer.tx == tx)
            .map(|offer| offer.cost);
        let Some(cost) = standing else {
            let call = Priced::call(&executor.address, &deployment.to, &deployment.data);
            return self.quote(
                id,
                op,
                &call,
                Some(&executor.address),
                true,
                quote.setup,
                ctx,
            );
        };
        let balance = match quote.balance {
            Some(Reply::Answer { result, .. }) => result.as_str().and_then(parse_unsigned),
            // As `quoted` answers a failed balance read.
            Some(Reply::Failed(error)) => {
                return vec![failed(id, &ErrorBody::new(error.code, error.message))];
            }
            None => None,
        };
        let Some(balance) = balance else {
            return vec![failed(id, &plain("Invalid balance"))];
        };
        if balance < cost {
            return vec![failed(id, &needs_funds_error(&executor.text, &cost))];
        }
        crate::log::info(
            "a Safe executor's fee confirmed: its offer prepared",
            json!({}),
        );
        vec![self.send_reply(id, &op.safe, executor.index, &tx, ctx)]
    }

    /// The offer `fee_ack` confirms: the one the Safe `safe`'s executor at
    /// `account` was offered for sending `data` (for the SafeTx `hash`, or
    /// the deployment), while it still sends exactly that.
    fn offer(
        &self,
        safe: &Safe,
        hash: Option<[u8; 32]>,
        account: u64,
        data: &[u8],
    ) -> Option<&Offer> {
        self.offers.get(&safe.index).filter(|offer| {
            offer.safe == safe.address
                && offer.hash == hash
                && offer.account == account
                && offer.data == data
        })
    }

    /// An execution's offer `fee_ack` confirms, its transaction to send.
    fn offered(
        &self,
        safe: &Safe,
        hash: Option<[u8; 32]>,
        account: u64,
        data: &[u8],
    ) -> Option<Value> {
        let tx = self.offer(safe, hash, account, data)?.tx.clone();
        crate::log::info(
            "a Safe executor's fee confirmed: its offer prepared",
            json!({}),
        );
        Some(tx)
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

    /// Answers `deadline` for every request past its bound; one on the
    /// device lane has the lane's bounds instead (S6).
    pub fn tick(&mut self, now: Instant) -> Vec<Out> {
        let due: Vec<u64> = self
            .ops
            .iter()
            .filter(|(_, op)| !matches!(op.step, Step::Device) && now >= op.deadline)
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

    /// The earliest request's bound, the ones on the device lane aside.
    pub fn next_wakeup(&self) -> Option<Instant> {
        self.ops
            .values()
            .filter(|op| !matches!(op.step, Step::Device))
            .map(|op| op.deadline)
            .min()
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
    /// `eth_estimateGas`'s params for the executor at `from` sending `data`
    /// to `to` with no value, as `estimateGas({ from, to, value: '0', data
    /// })` asks.
    fn call(from: &[u8; 20], to: &[u8; 20], data: &[u8]) -> Value {
        json!([{
            "from": checksum_address(from),
            "to": checksum_address(to),
            "value": "0",
            "data": to_hex(data),
        }])
    }

    /// The executor's send in `sign.transaction`'s form, without its nonce.
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

/// `activateSafe`'s refusal of an executor (`executor`, its address's
/// text) that can't pay `cost`.
fn needs_funds_error(executor: &str, cost: &U256) -> ErrorBody {
    refused(
        "SAFE_NEEDS_FUNDS",
        format!(
            "Fund {executor} with at least {} xDAI to activate",
            format_ether(cost)
        ),
    )
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

/// The Safe's record as it stands now, still the one the reads checked,
/// and its pending entry as the codec reads it, still the SafeTx `hash`:
/// `SAFE_DISCARDED` for one discarded or replaced meanwhile, as
/// `executeSafePending` refuses it after its nonce read.
fn still(checked: &Safe, hash: &[u8; 32], ctx: &Ctx) -> Result<(Safe, entry::Entry), ErrorBody> {
    let records = ctx.approvals.account_records().ok_or_else(not_moved)?;
    let safe = resolve(records, checked.index)?;
    if safe.address != checked.address || safe.setup != checked.setup {
        return Err(plain(format!(
            "Wallet {} is not a Safe account",
            safe.index
        )));
    }
    let entry = pending_entry(ctx.pending, &safe)
        .filter(|entry| entry.hash == *hash)
        .ok_or_else(|| refused("SAFE_DISCARDED", DISCARDED_TEXT))?;
    Ok((safe, entry))
}

/// `safe.executed { safe, safe_tx_hash, hash }`: main's word, after its
/// broadcast, that the SafeTx `named` executed (`finishExecuted`). The
/// Safe's `safe-send` approvals end first, then its entry is cleared while
/// it is still that SafeTx: `{}`, with `durable: false` when the clear's
/// flush failed. With none pending, `{}` and nothing done; with another,
/// `SAFE_DISCARDED` and nothing cleared.
fn executed(
    records: &Records,
    ctx: &mut Ctx,
    index: u64,
    named: &[u8; 32],
) -> Result<Value, ErrorBody> {
    let Some(entry) = ctx.pending.entry(index) else {
        return Ok(json!({}));
    };
    let same = |entry: &JsValue| {
        entry
            .get("safeTxHash")
            .and_then(JsValue::as_str)
            .and_then(|text| parse_bytes(text, "safeTxHash").ok())
            .as_deref()
            == Some(named.as_slice())
    };
    if !same(&entry) {
        return Err(refused("SAFE_DISCARDED", DISCARDED_TEXT));
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
        .clear_where(index, |current| current.is_none_or(same))
        .map_err(|failure| failure.error())?
        .ok_or_else(|| refused("SAFE_DISCARDED", DISCARDED_TEXT))?;
    crate::log::info("a pending Safe transaction executed", json!({}));
    Ok(if cleared.durable {
        json!({})
    } else {
        json!({ "durable": false })
    })
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
    let (rows, executor) = owner_rows(records, index, signers)?;
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

/// The board's owner rows for the Safe at wallet index `index`, as
/// `ownersView` derives them from the live records: each owner's `{ index,
/// address, type, signed }` (`address` `null` when its record has none,
/// `type` `mnemonic` when it names none), `signed` when `signers` holds its
/// address; and the first vault owner's index, the executor, or `null`. A
/// Safe the records no longer hold has no rows.
fn owner_rows(
    records: &Records,
    index: u64,
    signers: &[[u8; 20]],
) -> Result<(Vec<JsValue>, JsValue), ErrorBody> {
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
    Ok((rows, executor))
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

mod messages;
mod owners;

#[cfg(test)]
mod tests;
