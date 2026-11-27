//! The first `safe.*` methods (design 0016, API; SAFE-2's S2): a Safe's
//! record made in the core, its status and deployment read through the
//! chain machine, and the pending store's board views. Every one answers
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
//!   estimatedCost, needsFunds }`. A Safe the record marks deployed has
//!   its setup and nonce read through [`super::evidence`] first, and only
//!   one that is the record's is answered: `safe_changed`,
//!   `safe_unverified` or `not_deployed` otherwise. An unmarked one has its
//!   code read; with none, the executor's (the first vault owner's)
//!   balance, the deployment's estimate plus 20% and the fee quote give
//!   the activation's cost, each read for display only, its label kept.
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
//!   `deployed-mark`). A verified empty code ends it.
//! - **`safe.pending {}`** → `{ states }` (`getAllSafeSendStates`), and
//!   **`safe.discard { safe, safe_tx_hash? }`** → `{}` (`cancelSafeSend`):
//!   the Safe's `safe-send` approvals ended, then its entry cleared, under
//!   the pending store's 1 MiB bound and its set-aside of an unreadable
//!   file (D3).
//! - **Refusals** are `invalid_argument` with `data.safe`: `unsupported`,
//!   `changed`, `unverified`, `not_deployed`, or today's `SAFE_*` codes
//!   (`SAFE_ADDRESS_MISMATCH`, `SAFE_NEEDS_FUNDS`, `SAFE_DISCARDED`).
//! - **Time:** the chain-reading methods have the `session` class's 120 s
//!   from receipt (#520), each read the time left; past it, `deadline`. A
//!   cancel answers `cancelled`; a late reply changes nothing.
//! - **The mark's write** waits for no vault job to be running, as an
//!   `accounts.*` write runs at the vault queue's head: the vault takes
//!   [`Safes::take_marks`] and answers each with [`Safes::marked`].

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

use super::evidence::{Evidence, Outcome, Progress, Tags};
use crate::accounts::Records;
use crate::approvals::{Approvals, Clocks};
use crate::phone::ChainRead;
use crate::safe_pending::SafePending;
use crate::vault::{Out, error_payload};

/// The methods, in `core.hello`'s capability order.
pub const METHODS: [&str; 6] = [
    "safe.create",
    "safe.status",
    "safe.deploy",
    "safe.deployed",
    "safe.pending",
    "safe.discard",
];

/// The chain-reading methods' bound: the `session` class's (#520).
pub const DEADLINE_MS: u64 = 120_000;

/// `ProxyCreation(SafeProxy indexed proxy, address singleton)`'s topic,
/// as `SafeProxyFactory` 1.4.1 emits it (safe-deployments 1.37.66).
const PROXY_CREATION: &str = "ProxyCreation(address,address)";

/// `not_deployed`'s text (proposed, design 0016, "Chain reads").
pub const NOT_DEPLOYED_TEXT: &str = "Activate this account on Gnosis first.";

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
        if executor.is_none()
            && owner.get("type").and_then(JsValue::as_str) == Some("mnemonic")
            && at.fract() == 0.0
            && *at >= 0.0
        {
            executor = Some(Executor {
                index: *at as u64,
                address,
                text: stored
                    .and_then(|a| a.js_string().ok())
                    .unwrap_or_else(|| checksum_address(&address)),
            });
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
    /// No answer to judge: a failed read, or one that isn't hex.
    Failed,
}

fn code_of(reply: &Reply) -> Code {
    let Reply::Answer { result, verified } = reply else {
        return Code::Failed;
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
        (None, _) => Code::Failed,
    }
}

/// What the reads decide of the deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Deployment {
    /// Verified: marked for good.
    Mark,
    /// Reported deployed for the session, unverified.
    Session,
    NotDeployed,
    /// Nothing answered: no read to judge.
    Unknown,
}

// --- Requests in flight ---------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Kind {
    Status,
    Deploy { fee_ack: bool },
    Deployed { hash: [u8; 32] },
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
}

/// The activation's reads: the estimate, the fee quote, the executor's
/// balance, and for a deployment the fee evidence when it is stale.
#[derive(Default)]
struct Quote {
    estimate: Option<Reply>,
    fee: Option<Reply>,
    balance: Option<Reply>,
    /// The fee evidence's read is out.
    reference: bool,
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
    /// verified read decides.
    session: BTreeSet<[u8; 20]>,
    /// Requests whose mark is due, for the vault to write.
    marks: Vec<u64>,
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

/// The answer `getSafeStatus` gives: balances and costs in wei, decimal.
fn status(
    safe: &Safe,
    deployed: bool,
    balance: Option<&U256>,
    cost: Option<&U256>,
    needs_funds: bool,
) -> Value {
    json!({
        "deployed": deployed,
        "chainId": CHAIN_ID,
        "executorIndex": safe.executor.as_ref().map(|e| index_value(e.index)),
        "executorAddress": safe.executor.as_ref().map(|e| e.text.clone()),
        "executorBalance": balance.map(U256::to_decimal),
        "estimatedCost": cost.map(U256::to_decimal),
        "needsFunds": needs_funds,
    })
}

impl Safes {
    pub fn new() -> Self {
        Safes::default()
    }

    /// Whether this module serves `method` on the loop (`safe.create` runs
    /// on the vault queue).
    pub fn handles(method: &str) -> bool {
        METHODS.contains(&method) && method != "safe.create"
    }

    /// A request: its replies and reads.
    pub fn request(&mut self, id: u64, method: &str, raw: Option<&str>, ctx: &mut Ctx) -> Vec<Out> {
        match self.start(id, method, raw, ctx) {
            Ok(out) => out,
            Err(error) => vec![failed(id, &error)],
        }
    }

    fn start(
        &mut self,
        id: u64,
        method: &str,
        raw: Option<&str>,
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
                    Progress::Done(outcome) => {
                        let answer = match outcome {
                            Outcome::Unchanged { .. } => {
                                Ok(status(&op.safe, true, None, None, false))
                            }
                            Outcome::NotDeployed => Err(not_deployed()),
                            refused => {
                                Err(refused.refusal().unwrap_or_else(crate::vault::internal))
                            }
                        };
                        vec![match answer {
                            Ok(answer) => reply(id, &answer),
                            Err(error) => failed(id, &error),
                        }]
                    }
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
            Step::Mark => vec![failed(id, &crate::vault::internal())],
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
                Deployment::NotDeployed
            }
            Code::Unverified { empty: false } => Deployment::Session,
            _ if receipt == Receipt::Suggests => Deployment::Session,
            _ if self.session.contains(&address) => Deployment::Session,
            Code::Unverified { empty: true } => Deployment::NotDeployed,
            Code::Failed => Deployment::Unknown,
        };
        match deployment {
            Deployment::Mark => self.mark(id, op),
            Deployment::Session => {
                self.session.insert(address);
                crate::log::warn(
                    "safe deployment reported unverified, for the session",
                    json!({}),
                );
                let answer = match op.kind {
                    Kind::Deployed { .. } => json!({ "deployed": true, "verified": false }),
                    Kind::Deploy { .. } => json!({ "deployed": true }),
                    Kind::Status => status(&op.safe, true, None, None, false),
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
            Deployment::NotDeployed => match op.kind {
                Kind::Deployed { .. } => vec![reply(id, &json!({ "deployed": false }))],
                Kind::Status | Kind::Deploy { .. } => {
                    let Some(executor) = op.safe.executor.clone() else {
                        return vec![match op.kind {
                            Kind::Status => reply(id, &status(&op.safe, false, None, None, true)),
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
                    let mut quote = Quote::default();
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
    /// `safe.status` reads the setup and the nonce first.
    fn deployed(&mut self, id: u64, mut op: Op, ctx: &mut Ctx) -> Vec<Out> {
        match op.kind {
            Kind::Deployed { .. } => vec![reply(id, &json!({ "deployed": true }))],
            Kind::Deploy { .. } => vec![reply(id, &json!({ "deployed": true }))],
            Kind::Status => {
                let (evidence, reads) = Evidence::start(
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
            Kind::Deployed { .. } => failed(id, &crate::vault::internal()),
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
/// first. An entry the view can't read (not an object, or `signatures`
/// not an array) is left out and logged: S3's codec sets such an entry
/// aside.
fn pending_states(records: &Records, pending: &SafePending) -> Result<Vec<JsValue>, ErrorBody> {
    let mut states = Vec::new();
    for (index, entry) in pending.entries() {
        match send_state(records, index, &entry)? {
            Some(state) => states.push(state),
            None => crate::log::warn(
                "a pending Safe entry the board can't read: left out",
                json!({}),
            ),
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

/// `getSafeSendState(index)` for `entry`.
fn send_state(
    records: &Records,
    index: u64,
    entry: &JsValue,
) -> Result<Option<JsValue>, ErrorBody> {
    let (JsValue::Object(_), Some(signatures)) =
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
        let signed = address.as_str().is_some_and(|address| {
            signatures.iter().any(|signature| {
                signature
                    .get("signer")
                    .and_then(JsValue::as_str)
                    .is_some_and(|signer| signer.eq_ignore_ascii_case(address))
            })
        });
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
    let superseded = entry.get("superseded").is_some_and(JsValue::truthy);
    Ok(Some(JsValue::Object(vec![
        ("safeIndex".into(), JsValue::Number(index as f64)),
        ("chainId".into(), field("chainId")),
        ("safeTxHash".into(), field("safeTxHash")),
        ("threshold".into(), field("threshold")),
        ("collected".into(), JsValue::Number(signatures.len() as f64)),
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
