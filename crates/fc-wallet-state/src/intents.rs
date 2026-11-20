//! The wallet's intent records (design 0013, "The intent journal"): the
//! rules of freedom-browser's `src/main/wallet/intent-store.js` over the
//! records of `wallet-intents.jsonl`. The line format, its checksum and the
//! file are `fc-store`'s journal; this module takes the records it reads.
//!
//! The replay (PRF-5e-2a): every record kind as a load checks it, the
//! signers the load owes, the fold after it, compaction to `held` and
//! `tombstone` lines, `LIMITS`, the budget the store admits new intents
//! against, and the views. The live writes (PRF-5e-2b, [`write`]): each
//! write method's line, its checks and refusals, its admission against the
//! budget, and what applying it changes, as pure functions over the state,
//! so the daemon only adds the file.
//!
//! Numbers are JavaScript's doubles, as the reference keeps them, so a time
//! or a nonce goes back into a line as the file had it. A load that breaks a
//! rule gives the reference's reason, word for word: the store moves the
//! file aside with it.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt::Display;

use fc_evm::{DecodeError, SignedTx, U256, decode_signed, keccak256, to_hex};
use fc_json::{JsString, JsValue};

pub mod write;

pub use write::{Room, Withdrawn, Write};

/// The store's bounds (`LIMITS`). Only `tombstones` changes what a load
/// keeps; the others bound live writes and the budget's limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub held_per_account: usize,
    pub held: usize,
    pub hashes_per_intent: usize,
    pub open_handoffs_per_intent: usize,
    pub tombstones: usize,
    pub raw_bytes: usize,
    pub journal_bytes: u64,
    pub read_bytes: u64,
}

/// The reference's `LIMITS`.
pub const LIMITS: Limits = Limits {
    held_per_account: 32,
    held: 256,
    hashes_per_intent: 8,
    open_handoffs_per_intent: 8,
    tombstones: 1024,
    raw_bytes: 128 * 1024,
    journal_bytes: 8 * 1024 * 1024,
    read_bytes: 16 * 1024 * 1024,
};

const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
const TEXT_ORIGIN: usize = 2048;
const TEXT_KEY: usize = 256;
const OUTCOME_SOURCE: usize = 64;
const OUTCOME_REASON_CLASS: usize = 128;
/// `{"v":1,"sha256":"`, the digest, `","record":`, and `}\n` around a
/// record's text (`encodeLine`).
const LINE_OVERHEAD: usize = 17 + 64 + 11 + 2;

/// Why a file's records are damaged: the reference's message, which it
/// reports and moves the file aside with.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Damaged(pub String);

/// Why the store refuses a write, or why a record breaks a rule: the
/// reference's `code` and message. A load reports the message alone
/// ([`Damaged`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct Refusal {
    /// `INTENT_*`, or empty where the reference throws one of JavaScript's
    /// own `TypeError`s, which have none: an argument of the wrong type,
    /// never a line it writes.
    pub code: &'static str,
    pub message: String,
}

impl From<Refusal> for Damaged {
    fn from(refusal: Refusal) -> Self {
        Damaged(refusal.message)
    }
}

fn refusal(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        code,
        message: message.into(),
    }
}

fn invalid(detail: impl Display) -> Refusal {
    refusal(
        "INTENT_INVALID",
        format!("Invalid wallet intent record: {detail}"),
    )
}

fn unknown(id: impl Display) -> Refusal {
    refusal("INTENT_UNKNOWN", format!("Unknown wallet intent {id}"))
}

/// The bytes of a record's journal line, its newline included.
pub fn line_bytes(record: &JsValue) -> usize {
    LINE_OVERHEAD + record.stringify().len()
}

fn object(props: Vec<(&str, JsValue)>) -> JsValue {
    JsValue::Object(
        props
            .into_iter()
            .map(|(k, v)| (JsString::from(k), v))
            .collect(),
    )
}

fn num(n: f64) -> JsValue {
    JsValue::Number(n)
}

fn text(s: &str) -> JsValue {
    JsValue::string(s)
}

fn opt<T>(value: Option<T>, f: impl FnOnce(T) -> JsValue) -> JsValue {
    value.map_or(JsValue::Null, f)
}

const LONGEST_ID: &str = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const LONGEST_HASH: &str = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// The longest handoff line (`LINE_MAX.handoff`).
pub fn handoff_line_max() -> usize {
    line_bytes(&object(vec![
        ("type", text("handoff")),
        ("run", text(LONGEST_ID)),
        ("at", num(MAX_SAFE_INTEGER)),
        ("intent_id", text(LONGEST_ID)),
        ("hash", text(LONGEST_HASH)),
        ("handoff_id", text(LONGEST_ID)),
    ]))
}

/// The longest outcome line (`LINE_MAX.outcome`).
pub fn outcome_line_max() -> usize {
    line_bytes(&object(vec![
        ("type", text("outcome")),
        ("run", text(LONGEST_ID)),
        ("at", num(MAX_SAFE_INTEGER)),
        ("intent_id", text(LONGEST_ID)),
        ("hash", text(LONGEST_HASH)),
        ("handoff_id", text(LONGEST_ID)),
        ("outcome", text("uncertain")),
        ("source", text(&"x".repeat(OUTCOME_SOURCE))),
        ("reason_class", text(&"x".repeat(OUTCOME_REASON_CLASS))),
    ]))
}

/// The longest settle, void or retire line (`LINE_MAX.terminal`).
pub fn terminal_line_max() -> usize {
    let head = |kind: &str| {
        vec![
            ("type", text(kind)),
            ("run", text(LONGEST_ID)),
            ("at", num(MAX_SAFE_INTEGER)),
            ("intent_id", text(LONGEST_ID)),
        ]
    };
    let mut settle = head("settle");
    settle.extend([
        ("label", text("failed")),
        ("hash", text(LONGEST_HASH)),
        ("block", num(MAX_SAFE_INTEGER)),
    ]);
    let mut retire = head("retire");
    retire.push(("block", num(MAX_SAFE_INTEGER)));
    [settle, head("void"), retire]
        .into_iter()
        .map(|props| line_bytes(&object(props)))
        .max()
        .unwrap_or(0)
}

/// Where an intent stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Held,
    Settled,
    Voided,
    Retired,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            State::Held => "held",
            State::Settled => "settled",
            State::Voided => "voided",
            State::Retired => "retired",
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    hash: String,
    raw: Option<String>,
    original: bool,
    fields: Option<JsValue>,
    at: Option<f64>,
    run: Option<JsString>,
}

impl Entry {
    fn via(&self) -> &'static str {
        if self.original {
            "original"
        } else {
            "replacement"
        }
    }
}

#[derive(Debug, Clone)]
struct Outcome {
    outcome: &'static str,
    source: Option<JsString>,
    reason_class: Option<JsString>,
    at: f64,
    run: JsString,
}

#[derive(Debug, Clone)]
struct Handoff {
    id: JsString,
    hash: String,
    at: f64,
    run: JsString,
    outcome: Option<Outcome>,
    /// The line as the file had it: compaction writes an open one again.
    record: JsValue,
}

#[derive(Debug, Clone, PartialEq)]
struct Context {
    kind: String,
    origin: Option<JsString>,
    key: Option<JsString>,
    wallet_index: Option<f64>,
}

#[derive(Debug, Clone)]
struct Settlement {
    label: &'static str,
    hash: Option<String>,
    block: Option<f64>,
    at: f64,
}

#[derive(Debug, Clone)]
struct Intent {
    id: JsString,
    chain_id: f64,
    sender: String,
    nonce: f64,
    context: Option<Context>,
    run: Option<JsString>,
    recovered: bool,
    sequence: u64,
    state: State,
    hashes: Vec<Entry>,
    /// This run's handoffs (while loading, the file's), in their order.
    handoffs: Vec<Handoff>,
    /// Handoffs folded away: `count` and `possibly_sent`.
    summary: (f64, bool),
    bracket: Option<(f64, String)>,
    unread_since: Option<f64>,
    settlement: Option<Settlement>,
    voided_at: Option<f64>,
    retirement: Option<(Option<f64>, f64)>,
    closed_at: Option<f64>,
    created_at: f64,
    updated_at: f64,
    /// `intent.sized`: its widest snapshot's size, and how many hashes it
    /// had. The reference sizes it again only with a new hash, so a
    /// withdrawn origin keeps counting until then.
    sized: Cell<Option<(usize, usize)>>,
}

impl Intent {
    fn same_account(&self, chain_id: f64, sender: &str) -> bool {
        self.chain_id == chain_id && self.sender == sender
    }

    fn handoff(&self, id: &JsString) -> Option<&Handoff> {
        self.handoffs.iter().find(|h| &h.id == id)
    }

    fn open(&self) -> impl Iterator<Item = &Handoff> {
        self.handoffs.iter().filter(|h| h.outcome.is_none())
    }

    fn finished(&self) -> impl Iterator<Item = &Handoff> {
        self.handoffs.iter().filter(|h| h.outcome.is_some())
    }

    /// `handoffTally`: the summary plus this run's handoffs.
    fn tally(&self) -> (f64, bool) {
        let sent = self
            .handoffs
            .iter()
            .any(|h| h.outcome.as_ref().is_none_or(|o| o.outcome != "not_sent"));
        (
            self.summary.0 + self.handoffs.len() as f64,
            self.summary.1 || sent,
        )
    }

    /// The summary as compaction writes it: finished handoffs folded in.
    fn folded(&self) -> (f64, bool) {
        let finished: Vec<&Handoff> = self.finished().collect();
        let sent = finished
            .iter()
            .any(|h| h.outcome.as_ref().is_some_and(|o| o.outcome != "not_sent"));
        (
            self.summary.0 + finished.len() as f64,
            self.summary.1 || sent,
        )
    }

    /// `close`: what it was, without its bytes; its open handoffs no
    /// longer owed.
    fn close(&mut self, at: f64) {
        self.summary = self.tally();
        self.handoffs.clear();
        for entry in &mut self.hashes {
            entry.raw = None;
            entry.fields = None;
        }
        self.bracket = None;
        self.unread_since = None;
        self.closed_at = Some(at);
        self.updated_at = at;
    }
}

/// A new held intent, not yet in the store (its `sequence` is the store's).
fn fresh(
    id: JsString,
    chain_id: f64,
    sender: String,
    nonce: f64,
    context: Option<Context>,
    run: Option<JsString>,
    at: f64,
) -> Intent {
    Intent {
        id,
        chain_id,
        sender,
        nonce,
        context,
        run,
        recovered: true,
        sequence: 0,
        state: State::Held,
        hashes: Vec::new(),
        handoffs: Vec::new(),
        summary: (0.0, false),
        bracket: None,
        unread_since: None,
        settlement: None,
        voided_at: None,
        retirement: None,
        closed_at: None,
        created_at: at,
        updated_at: at,
        sized: Cell::new(None),
    }
}

/// Why a closed intent takes nothing more, for the user (`closedText`).
fn closed_text(state: State) -> &'static str {
    match state {
        State::Voided => "This payment was voided.",
        State::Retired => "This payment was closed.",
        _ => "This payment is already settled.",
    }
}

/// `requireHeld`: a load names the state, a live write tells the user.
fn require_held(intent: &Intent, mode: Mode) -> Result<(), Refusal> {
    match intent.state {
        State::Held => Ok(()),
        state if !mode.live => Err(invalid(format_args!(
            "intent {} is {}",
            intent.id,
            state.name()
        ))),
        state => Err(refusal("INTENT_NOT_HELD", closed_text(state))),
    }
}

/// How a record is checked: as a load replays it, or as a live write,
/// with main's word on the account's reservation lock (design 0013: the
/// lock stays main's until APR-6).
#[derive(Debug, Clone, Copy)]
struct Mode {
    live: bool,
    lock: bool,
}

const LOADING: Mode = Mode {
    live: false,
    lock: false,
};

/// What applying a checked record does: the function a reference
/// `prepare*` returns. A load applies it at once; a write once its line is
/// on disk.
#[derive(Debug, Clone)]
enum Apply {
    Original(Box<Intent>),
    Replacement {
        id: JsString,
        entry: Entry,
        at: f64,
    },
    Handoff {
        id: JsString,
        handoff: Handoff,
        at: f64,
    },
    Outcome {
        id: JsString,
        handoff: JsString,
        outcome: Outcome,
        at: f64,
    },
    /// A settle (with its settlement), a void, or a retire (with its block).
    Close {
        id: JsString,
        state: State,
        settlement: Option<Settlement>,
        block: Option<f64>,
        at: f64,
    },
    Track {
        id: JsString,
        bracket: Option<(f64, String)>,
        unread_since: Option<f64>,
    },
}

// --- Reading a record's fields, as the reference checks them -------------

fn safe_integer(value: Option<&JsValue>) -> Option<f64> {
    match value {
        Some(JsValue::Number(n)) if n.fract() == 0.0 && n.abs() <= MAX_SAFE_INTEGER => Some(*n),
        _ => None,
    }
}

fn require_count(value: Option<&JsValue>, what: &str) -> Result<f64, Refusal> {
    safe_integer(value)
        .filter(|n| *n >= 0.0)
        .ok_or_else(|| invalid(format_args!("bad {what}")))
}

fn require_chain_id(value: Option<&JsValue>) -> Result<f64, Refusal> {
    safe_integer(value)
        .filter(|n| *n > 0.0)
        .ok_or_else(|| invalid("bad chain id"))
}

fn is_id(value: &JsString) -> bool {
    (8..=64).contains(&value.utf16_len())
        && value.units().all(|u| {
            u8::try_from(u).is_ok_and(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

fn require_id(value: Option<&JsValue>, what: &str) -> Result<JsString, Refusal> {
    match value.and_then(JsValue::as_js_string) {
        Some(id) if is_id(id) => Ok(id.clone()),
        _ => Err(invalid(format_args!("bad {what}"))),
    }
}

#[derive(Clone, Copy)]
enum Hex {
    Address,
    Hash,
    Bytes,
}

/// `requireHex`: the text lowercased, as the pattern takes it. No
/// character outside ASCII lowercases into the patterns' alphabet.
fn require_hex(value: Option<&JsValue>, pattern: Hex, what: &str) -> Result<String, Refusal> {
    let bad = || invalid(format_args!("bad {what}"));
    let s = value.and_then(JsValue::as_js_string).ok_or_else(bad)?;
    if !s.is_ascii() {
        return Err(bad());
    }
    let lower = s.to_ascii_lowercase();
    let digits = lower.strip_prefix("0x").ok_or_else(bad)?;
    let fits = match pattern {
        Hex::Address => digits.len() == 40,
        Hex::Hash => digits.len() == 64,
        Hex::Bytes => digits.len() % 2 == 0,
    };
    if fits && digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(lower)
    } else {
        Err(bad())
    }
}

fn optional_text(
    value: Option<&JsValue>,
    name: &str,
    limit: usize,
) -> Result<Option<JsString>, Refusal> {
    match value {
        None | Some(JsValue::Null) => Ok(None),
        Some(JsValue::String(s)) if s.utf16_len() > 0 && s.utf16_len() <= limit => {
            Ok(Some(s.clone()))
        }
        Some(_) => Err(invalid(format_args!("bad {name}"))),
    }
}

fn is_outcome_text(value: &JsValue, limit: usize) -> bool {
    value.as_js_string().is_some_and(|s| {
        s.utf16_len() <= limit
            && !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b" ._:/()-".contains(&b))
    })
}

fn is_plain_object(value: Option<&JsValue>) -> bool {
    matches!(value, Some(JsValue::Object(_)))
}

fn one_of(value: Option<&JsValue>, names: &[&'static str]) -> Option<&'static str> {
    let s = value.and_then(JsValue::as_str)?;
    names.iter().copied().find(|name| *name == s)
}

const OUTCOMES: [&str; 4] = ["sent", "uncertain", "rejected", "not_sent"];
const LABELS: [&str; 3] = ["paid", "failed", "taken"];

fn normalize_context(value: Option<&JsValue>) -> Result<Context, Refusal> {
    let Some(context @ JsValue::Object(_)) = value else {
        return Err(invalid("an original commit needs its context"));
    };
    let kind = context
        .get("kind")
        .and_then(JsValue::as_str)
        .filter(|k| {
            let mut bytes = k.bytes();
            k.len() <= 32
                && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
                && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        .ok_or_else(|| invalid("bad context kind"))?;
    let present = |key| context.get(key).filter(|v| !matches!(v, JsValue::Null));
    let wallet_index = match present("wallet_index").or_else(|| present("walletIndex")) {
        Some(index) => Some(require_count(Some(index), "wallet index")?),
        None => None,
    };
    Ok(Context {
        kind: kind.to_owned(),
        origin: optional_text(context.get("origin"), "origin", TEXT_ORIGIN)?,
        key: optional_text(context.get("key"), "key", TEXT_KEY)?,
        wallet_index,
    })
}

/// `trackOf`: the tracker's state in a `track` or `held` line.
/// A bracket (`number`, `hash`) and `unread_since`.
type Tracked = (Option<(f64, String)>, Option<f64>);

fn track_of(record: &JsValue) -> Result<Tracked, Refusal> {
    let bracket = match record.get("bracket") {
        None | Some(JsValue::Null) => None,
        Some(b @ JsValue::Object(_)) => Some((
            require_count(b.get("number"), "bracket block")?,
            require_hex(b.get("hash"), Hex::Hash, "bracket hash")?,
        )),
        Some(_) => return Err(invalid("bad bracket")),
    };
    let unread_since = match record.get("unread_since") {
        None | Some(JsValue::Null) => None,
        since => Some(require_count(since, "unread time")?),
    };
    Ok((bracket, unread_since))
}

fn decimal(n: &U256) -> JsValue {
    text(&n.to_decimal())
}

/// `fieldsOf`: the unsigned fields of a signed transaction, as stored.
fn fields_of(tx: &SignedTx) -> JsValue {
    let fees = tx.eip1559_fees();
    object(vec![
        ("type", num(f64::from(tx.tx_type()))),
        ("to", opt(tx.to(), |to| text(&to_hex(to)))),
        ("value", decimal(tx.value())),
        ("data", text(&to_hex(tx.data()))),
        ("gas_limit", decimal(tx.gas_limit())),
        ("max_fee_per_gas", opt(fees, |(max, _)| decimal(max))),
        (
            "max_priority_fee_per_gas",
            opt(fees, |(_, tip)| decimal(tip)),
        ),
        ("gas_price", opt(tx.gas_price(), decimal)),
    ])
}

fn bytes_of(raw: &str) -> Vec<u8> {
    fc_evm::parse_bytes(raw, "signed transaction").unwrap_or_default()
}

/// `verifySigned`: `raw` (lowercase hex) decodes to a signed, canonical
/// transaction of type 0 or 2 at the intent's nonce and chain, hashing to
/// its hash. Its fields, as stored.
fn verify_signed(raw: &str, chain_id: f64, nonce: f64, hash: &str) -> Result<JsValue, Refusal> {
    let bytes = bytes_of(raw);
    // ethers' own error escapes `tx.serialized` for an unserializable
    // transaction; the core reports its own text (deviation
    // `intent-unserializable`).
    let tx = decode_signed(&bytes).map_err(|error: DecodeError| invalid(error))?;
    if tx.nonce() as f64 != nonce {
        return Err(invalid(format_args!(
            "the transaction is signed at nonce {}, not {}",
            tx.nonce(),
            fc_json::number_to_string(nonce)
        )));
    }
    let chain = tx.chain_id().to_decimal();
    if chain != fc_json::number_to_string(chain_id) {
        return Err(invalid(format_args!(
            "the transaction is signed for chain {chain}, not {}",
            fc_json::number_to_string(chain_id)
        )));
    }
    if to_hex(&keccak256(&bytes)) != hash {
        return Err(invalid(
            "the transaction does not hash to the intent's hash",
        ));
    }
    Ok(fields_of(&tx))
}

/// `signerOf`: the address that signed `raw`, lowercase, or none.
fn signer_of(raw: &str) -> Option<String> {
    decode_signed(&bytes_of(raw))
        .ok()
        .and_then(|tx| tx.signer())
        .map(|address| to_hex(&address))
}

fn n(value: f64) -> String {
    fc_json::number_to_string(value)
}

// --- The store -------------------------------------------------------------

/// The intents a load gave, in the order the reference's `Map` has them.
#[derive(Debug, Clone)]
pub struct Intents {
    limits: Limits,
    by_id: BTreeMap<JsString, Intent>,
    sequence: u64,
}

/// A load's result: the intents, and whether the file differs from what
/// compaction writes, so the store rewrites it ([`Intents::compaction`]).
#[derive(Debug, Clone)]
pub struct Loaded {
    pub intents: Intents,
    pub compact: bool,
}

impl Intents {
    /// `doLoad` over the file's records: each checked as a live write would
    /// be, then the signer of every kept signature, then every handoff
    /// folded into its intent's summary (all are an earlier run's now).
    pub fn load(records: &[JsValue], limits: Limits) -> Result<Loaded, Damaged> {
        let mut intents = Intents {
            limits,
            by_id: BTreeMap::new(),
            sequence: 0,
        };
        let mut unrecovered = Vec::new();
        for record in records {
            intents.replay(record, &mut unrecovered)?;
        }
        intents.recover_signers(&unrecovered)?;
        intents.fold_loaded();
        let compacted = intents.compaction();
        let compact = compacted.len() != records.len()
            || compacted
                .iter()
                .zip(records)
                .any(|(a, b)| a.stringify() != b.stringify());
        Ok(Loaded { intents, compact })
    }

    fn in_order(&self) -> Vec<&Intent> {
        let mut all: Vec<&Intent> = self.by_id.values().collect();
        all.sort_by_key(|intent| intent.sequence);
        all
    }

    fn held_intents(&self) -> impl Iterator<Item = &Intent> {
        self.in_order()
            .into_iter()
            .filter(|i| i.state == State::Held)
    }

    fn held_of(&self, chain_id: f64, sender: &str) -> impl Iterator<Item = &Intent> {
        self.held_intents()
            .filter(move |i| i.same_account(chain_id, sender))
    }

    fn closed_intents(&self) -> Vec<&Intent> {
        let mut closed: Vec<&Intent> = self
            .by_id
            .values()
            .filter(|i| i.state != State::Held)
            .collect();
        closed.sort_by(|a, b| {
            let at = |i: &Intent| i.closed_at.unwrap_or(0.0);
            at(a).total_cmp(&at(b)).then(a.sequence.cmp(&b.sequence))
        });
        closed
    }

    /// The closed intents compaction keeps: the newest `tombstones` (all of
    /// them for 0, as JavaScript's `slice(-0)` gives).
    fn kept_closed(&self) -> Vec<&Intent> {
        let mut closed = self.closed_intents();
        let keep = self.limits.tombstones;
        if keep != 0 && closed.len() > keep {
            closed.drain(..closed.len() - keep);
        }
        closed
    }

    fn require_intent(&self, record: &JsValue) -> Result<JsString, Refusal> {
        let id = require_id(record.get("intent_id"), "intent id")?;
        if self.by_id.contains_key(&id) {
            Ok(id)
        } else {
            Err(unknown(&id))
        }
    }

    fn intent(&self, id: &JsString) -> Result<&Intent, Refusal> {
        self.by_id.get(id).ok_or_else(|| unknown(id))
    }

    #[allow(clippy::too_many_arguments)]
    fn insert(
        &mut self,
        id: JsString,
        chain_id: f64,
        sender: String,
        nonce: f64,
        context: Option<Context>,
        run: Option<JsString>,
        at: f64,
    ) -> &mut Intent {
        self.sequence += 1;
        let mut intent = fresh(id.clone(), chain_id, sender, nonce, context, run, at);
        intent.sequence = self.sequence;
        // A new id: every caller checked it isn't known.
        self.by_id.entry(id).or_insert(intent)
    }

    /// `checkNewIntent`: above the account's held nonces, with a key no
    /// held intent has. Live also checks the count bounds.
    fn check_new_intent(
        &self,
        chain_id: f64,
        sender: &str,
        nonce: f64,
        context: &Context,
        mode: Mode,
    ) -> Result<(), Refusal> {
        let held = self.held_of(chain_id, sender).count();
        if mode.live && held >= self.limits.held_per_account {
            return Err(refusal(
                "INTENT_ACCOUNT_LIMIT",
                format!(
                    "This account already has {held} payments waiting to confirm. \
                     Wait for some of them before sending another."
                ),
            ));
        }
        if mode.live && self.held_intents().count() >= self.limits.held {
            return Err(refusal(
                "INTENT_STORE_LIMIT",
                format!(
                    "The wallet already has {} payments waiting to confirm. \
                     Wait for some of them before sending another.",
                    self.limits.held
                ),
            ));
        }
        let highest = self
            .held_of(chain_id, sender)
            .fold(-1.0_f64, |max, i| max.max(i.nonce));
        if nonce <= highest {
            return Err(invalid(format_args!(
                "nonce {} is not above the account's held nonce {}",
                n(nonce),
                n(highest)
            )));
        }
        if let Some(key) = &context.key
            && self.held_intents().any(|i| {
                i.context
                    .as_ref()
                    .is_some_and(|c| c.key.as_ref() == Some(key))
            })
        {
            return Err(invalid("another held intent has the same key"));
        }
        Ok(())
    }

    /// `prepare(record, LOADING)()`.
    fn replay(
        &mut self,
        record: &JsValue,
        unrecovered: &mut Vec<(JsString, usize)>,
    ) -> Result<(), Refusal> {
        // `Object.hasOwn(PREPARE, record.type)` takes the type as a key.
        let kind = record
            .get("type")
            .unwrap_or(&JsValue::Undefined)
            .js_string()
            .map_err(|_| refusal("", "Cannot convert object to primitive value"))?;
        let known = [
            "commit",
            "held",
            "tombstone",
            "handoff",
            "outcome",
            "settle",
            "void",
            "retire",
            "track",
        ];
        if !known.contains(&kind.as_str()) {
            return Err(invalid("unknown record type"));
        }
        let at = require_count(record.get("at"), "time")?;
        let apply = match kind.as_str() {
            "held" => return self.held_snapshot(record, at, unrecovered),
            "tombstone" => return self.tombstone(record, at),
            "outcome" => match self.prepare_outcome(record, at, LOADING)? {
                Some(apply) => apply,
                None => return Ok(()),
            },
            _ => self.prepare(kind.as_str(), record, at, LOADING)?,
        };
        let id = self.apply_one(apply);
        if kind.as_str() == "commit"
            && let Some(intent) = self.by_id.get(&id)
        {
            unrecovered.push((id, intent.hashes.len() - 1));
        }
        Ok(())
    }

    /// `prepare` for the record kinds a live write can have, outcomes aside.
    fn prepare(&self, kind: &str, record: &JsValue, at: f64, mode: Mode) -> Result<Apply, Refusal> {
        match kind {
            "commit" => self.prepare_commit(record, at, mode),
            "handoff" => self.prepare_handoff(record, at, mode),
            "settle" => self.prepare_settle(record, at, mode),
            "void" => self.prepare_void(record, at, mode),
            "retire" => self.prepare_retire(record, at, mode),
            "track" => self.prepare_track(record, mode),
            _ => Err(invalid("unknown record type")),
        }
    }

    fn prepare_commit(&self, record: &JsValue, at: f64, mode: Mode) -> Result<Apply, Refusal> {
        let id = require_id(record.get("intent_id"), "intent id")?;
        let run = require_id(record.get("run"), "run")?;
        let chain_id = require_chain_id(record.get("chain_id"))?;
        let sender = require_hex(record.get("sender"), Hex::Address, "sender")?;
        let nonce = require_count(record.get("nonce"), "nonce")?;
        let hash = require_hex(record.get("hash"), Hex::Hash, "hash")?;
        let raw = require_hex(record.get("raw"), Hex::Bytes, "signed transaction")?;
        if mode.live && (raw.len() - 2) / 2 > self.limits.raw_bytes {
            return Err(refusal(
                "INTENT_TOO_LARGE",
                "This transaction is too large to send.",
            ));
        }
        let fields = verify_signed(&raw, chain_id, nonce, &hash)?;
        if mode.live && signer_of(&raw).as_deref() != Some(sender.as_str()) {
            return Err(invalid(
                "the transaction is not signed by the intent's sender",
            ));
        }
        if !mode.live && record.get("fields").map(JsValue::stringify) != Some(fields.stringify()) {
            return Err(invalid(format_args!(
                "the fields of {hash} do not match its transaction"
            )));
        }
        let via = record.get("via").and_then(JsValue::as_str);
        let entry = |original| Entry {
            hash: hash.clone(),
            raw: Some(raw.clone()),
            original,
            fields: Some(fields.clone()),
            at: Some(at),
            run: Some(run.clone()),
        };
        if via == Some("original") {
            // Closed ids included: closed is final.
            if self.by_id.contains_key(&id) {
                return Err(invalid(format_args!("intent {id} is already committed")));
            }
            let context = normalize_context(record.get("context"))?;
            self.check_new_intent(chain_id, &sender, nonce, &context, mode)?;
            let first = entry(true);
            let mut intent = fresh(id, chain_id, sender, nonce, Some(context), Some(run), at);
            intent.recovered = !mode.live;
            intent.hashes.push(first);
            return Ok(Apply::Original(Box::new(intent)));
        }
        if via != Some("replacement") {
            return Err(invalid("bad via"));
        }
        let Some(existing) = self.by_id.get(&id) else {
            return Err(invalid(format_args!(
                "a replacement for unknown intent {id}"
            )));
        };
        require_held(existing, mode)?;
        if existing.chain_id != chain_id || existing.sender != sender || existing.nonce != nonce {
            return Err(invalid(format_args!(
                "a replacement of intent {id} must keep its chain, sender and nonce"
            )));
        }
        if existing.hashes.iter().any(|known| known.hash == hash) {
            return Err(invalid(format_args!(
                "{hash} is already committed to intent {id}"
            )));
        }
        if mode.live && existing.hashes.len() >= self.limits.hashes_per_intent {
            return Err(refusal(
                "INTENT_REPLACEMENT_LIMIT",
                "This payment has been replaced too many times. Send it again as it is.",
            ));
        }
        let paying = existing.hashes.last().and_then(|e| e.fields.as_ref());
        let pays = |key| fields.get(key) == paying.and_then(|p| p.get(key));
        if !(pays("to") && pays("value") && pays("data")) {
            return Err(invalid(format_args!(
                "a replacement of intent {id} must pay what the original pays"
            )));
        }
        Ok(Apply::Replacement {
            id,
            entry: entry(false),
            at,
        })
    }

    /// A held intent in one line, as compaction writes it: replayed like an
    /// original commit, its latest bytes checked like any commit's.
    fn held_snapshot(
        &mut self,
        record: &JsValue,
        at: f64,
        unrecovered: &mut Vec<(JsString, usize)>,
    ) -> Result<(), Refusal> {
        let id = require_id(record.get("intent_id"), "intent id")?;
        let run = require_id(record.get("run"), "run")?;
        let chain_id = require_chain_id(record.get("chain_id"))?;
        let sender = require_hex(record.get("sender"), Hex::Address, "sender")?;
        let nonce = require_count(record.get("nonce"), "nonce")?;
        let hash = require_hex(record.get("hash"), Hex::Hash, "hash")?;
        let raw = require_hex(record.get("raw"), Hex::Bytes, "signed transaction")?;
        let fields = verify_signed(&raw, chain_id, nonce, &hash)?;
        if record.get("fields").map(JsValue::stringify) != Some(fields.stringify()) {
            return Err(invalid(format_args!(
                "the fields of {hash} do not match its transaction"
            )));
        }
        let listed = record
            .get("hashes")
            .and_then(JsValue::as_array)
            .unwrap_or(&[]);
        if listed.is_empty() {
            return Err(invalid(format_args!("intent {id} lists no hashes")));
        }
        let mut hashes = Vec::with_capacity(listed.len());
        for (index, item) in listed.iter().enumerate() {
            let bad = || invalid(format_args!("intent {id} lists a bad hash"));
            if !is_plain_object(Some(item)) {
                return Err(bad());
            }
            let via = if index == 0 {
                "original"
            } else {
                "replacement"
            };
            let item_at = safe_integer(item.get("at"));
            if item.get("via").and_then(JsValue::as_str) != Some(via) || item_at.is_none() {
                return Err(bad());
            }
            hashes.push(Entry {
                hash: require_hex(item.get("hash"), Hex::Hash, "hash")?,
                raw: None,
                original: index == 0,
                fields: None,
                at: item_at,
                run: Some(require_id(item.get("run"), "run")?),
            });
        }
        let mut seen: Vec<&str> = hashes.iter().map(|e| e.hash.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        if seen.len() != hashes.len() {
            return Err(invalid(format_args!("intent {id} lists a hash twice")));
        }
        let Some(latest) = hashes.last_mut().filter(|latest| latest.hash == hash) else {
            return Err(invalid(format_args!(
                "intent {id}'s bytes are not its latest hash"
            )));
        };
        latest.raw = Some(raw);
        latest.fields = Some(fields);
        let summary = record.get("handoffs");
        let possibly_sent = match summary.and_then(|s| s.get("possibly_sent")) {
            Some(JsValue::Bool(b)) if is_plain_object(summary) => *b,
            _ => {
                return Err(invalid(format_args!(
                    "intent {id} has a bad handoff summary"
                )));
            }
        };
        let count = require_count(summary.and_then(|s| s.get("count")), "handoff count")?;
        let (bracket, unread_since) = track_of(record)?;
        if self.by_id.contains_key(&id) {
            return Err(invalid(format_args!("intent {id} is already committed")));
        }
        let context = normalize_context(record.get("context"))?;
        self.check_new_intent(chain_id, &sender, nonce, &context, LOADING)?;
        let latest = hashes.len() - 1;
        let intent = self.insert(
            id.clone(),
            chain_id,
            sender,
            nonce,
            Some(context),
            Some(run),
            at,
        );
        intent.hashes = hashes;
        intent.summary = (count, possibly_sent);
        intent.bracket = bracket;
        intent.unread_since = unread_since;
        unrecovered.push((id, latest));
        Ok(())
    }

    /// A closed intent, as compaction keeps it: final, without its bytes.
    fn tombstone(&mut self, record: &JsValue, at: f64) -> Result<(), Refusal> {
        let id = require_id(record.get("intent_id"), "intent id")?;
        let chain_id = require_chain_id(record.get("chain_id"))?;
        let sender = require_hex(record.get("sender"), Hex::Address, "sender")?;
        let nonce = require_count(record.get("nonce"), "nonce")?;
        let state = match one_of(record.get("closed"), &["settled", "voided", "retired"]) {
            Some("settled") => State::Settled,
            Some("voided") => State::Voided,
            Some(_) => State::Retired,
            None => return Err(invalid("bad closed state")),
        };
        let label = one_of(record.get("label"), &LABELS);
        if (state == State::Settled && label.is_none())
            || (state != State::Settled && record.get("label").is_some())
        {
            return Err(invalid("bad label"));
        }
        let mut hashes = Vec::new();
        if state == State::Retired {
            let listed = record
                .get("hashes")
                .and_then(JsValue::as_array)
                .unwrap_or(&[]);
            if listed.is_empty() {
                return Err(invalid(format_args!("retired intent {id} lists no hashes")));
            }
            for item in listed {
                let hash = require_hex(Some(item), Hex::Hash, "hash")?;
                if hashes.contains(&hash) {
                    return Err(invalid(format_args!("intent {id} lists a hash twice")));
                }
                hashes.push(hash);
            }
        } else if record.get("hashes").is_some() {
            return Err(invalid(format_args!(
                "{} intent {id} keeps no hashes",
                state.name()
            )));
        }
        if self.by_id.contains_key(&id) {
            return Err(invalid(format_args!("intent {id} is already committed")));
        }
        let intent = self.insert(id, chain_id, sender, nonce, None, None, at);
        intent.state = state;
        intent.closed_at = Some(at);
        intent.hashes = hashes
            .into_iter()
            .enumerate()
            .map(|(index, hash)| Entry {
                hash,
                raw: None,
                original: index == 0,
                fields: None,
                at: None,
                run: None,
            })
            .collect();
        match state {
            State::Settled => {
                intent.settlement = Some(Settlement {
                    label: label.unwrap_or("paid"),
                    hash: None,
                    block: None,
                    at,
                });
            }
            State::Retired => intent.retirement = Some((None, at)),
            _ => intent.voided_at = Some(at),
        }
        Ok(())
    }

    fn prepare_handoff(&self, record: &JsValue, at: f64, mode: Mode) -> Result<Apply, Refusal> {
        let id = self.require_intent(record)?;
        let intent = self.intent(&id)?;
        require_held(intent, mode)?;
        let run = require_id(record.get("run"), "run")?;
        let handoff_id = require_id(record.get("handoff_id"), "handoff id")?;
        let hash = require_hex(record.get("hash"), Hex::Hash, "hash")?;
        let Some(entry) = intent.hashes.iter().find(|known| known.hash == hash) else {
            return Err(invalid(format_args!(
                "{hash} is not committed to intent {id}"
            )));
        };
        if mode.live && entry.raw.is_none() {
            return Err(invalid(format_args!(
                "the bytes of {hash} are no longer kept; send the latest"
            )));
        }
        if intent.handoff(&handoff_id).is_some() {
            return Err(invalid(format_args!(
                "handoff {handoff_id} is already recorded"
            )));
        }
        if mode.live && intent.open().count() >= self.limits.open_handoffs_per_intent {
            return Err(refusal(
                "INTENT_HANDOFF_LIMIT",
                "This payment is already being sent. Wait for that to finish.",
            ));
        }
        Ok(Apply::Handoff {
            id,
            handoff: Handoff {
                id: handoff_id,
                hash,
                at,
                run,
                outcome: None,
                record: record.clone(),
            },
            at,
        })
    }

    /// Live, an outcome the store no longer owes is ignored (none): one
    /// for an unknown or closed intent, for a handoff already folded into
    /// the summary, or a second one for the same handoff.
    fn prepare_outcome(
        &self,
        record: &JsValue,
        at: f64,
        mode: Mode,
    ) -> Result<Option<Apply>, Refusal> {
        let id = require_id(record.get("intent_id"), "intent id")?;
        let run = require_id(record.get("run"), "run")?;
        let intent = self.by_id.get(&id);
        // `intent?.handoffs.get(requireId(…))`: the id is checked only for a
        // known intent.
        let handoff_id = match intent {
            Some(_) => Some(require_id(record.get("handoff_id"), "handoff id")?),
            None => None,
        };
        let handoff = intent
            .zip(handoff_id.as_ref())
            .and_then(|(i, h)| i.handoff(h));
        let (Some(intent), Some(handoff_id)) = (intent, &handoff_id) else {
            if mode.live {
                return Ok(None);
            }
            return Err(invalid(format_args!("an outcome for unknown intent {id}")));
        };
        if intent.state != State::Held || handoff.is_none_or(|h| h.outcome.is_some()) {
            if mode.live {
                return Ok(None);
            }
            if intent.state != State::Held {
                return Err(invalid(format_args!(
                    "an outcome for {} intent {id}",
                    intent.state.name()
                )));
            }
            if handoff.is_none() {
                return Err(invalid(format_args!("unknown handoff {handoff_id}")));
            }
            return Err(invalid(format_args!(
                "handoff {handoff_id} already has its outcome"
            )));
        }
        let Some(handoff) = handoff else {
            return Ok(None);
        };
        if handoff.hash != require_hex(record.get("hash"), Hex::Hash, "hash")? {
            return Err(invalid(format_args!(
                "handoff {handoff_id} was of another hash"
            )));
        }
        if handoff.run != run {
            // Its reply was lost with the run that made it.
            return Err(invalid(format_args!(
                "handoff {handoff_id} was made by an earlier run of main"
            )));
        }
        let outcome =
            one_of(record.get("outcome"), &OUTCOMES).ok_or_else(|| invalid("bad outcome"))?;
        let mut texts = [None, None];
        for (slot, (name, limit)) in texts.iter_mut().zip([
            ("source", OUTCOME_SOURCE),
            ("reason_class", OUTCOME_REASON_CLASS),
        ]) {
            match record.get(name) {
                Some(JsValue::Null) => {}
                Some(value) if is_outcome_text(value, limit) => {
                    *slot = value.as_js_string().cloned()
                }
                _ => return Err(invalid(format_args!("bad {name}"))),
            }
        }
        let [source, reason_class] = texts;
        Ok(Some(Apply::Outcome {
            id,
            handoff: handoff_id.clone(),
            outcome: Outcome {
                outcome,
                source,
                reason_class,
                at,
                run,
            },
            at,
        }))
    }

    fn prepare_settle(&self, record: &JsValue, at: f64, mode: Mode) -> Result<Apply, Refusal> {
        let id = self.require_intent(record)?;
        require_id(record.get("run"), "run")?;
        let intent = self.intent(&id)?;
        require_held(intent, mode)?;
        let label = one_of(record.get("label"), &LABELS).ok_or_else(|| invalid("bad label"))?;
        let mut hash = None;
        if label == "taken" {
            if !matches!(record.get("hash"), None | Some(JsValue::Null)) {
                return Err(invalid("a taken intent has no transaction of its own"));
            }
        } else {
            let h = require_hex(record.get("hash"), Hex::Hash, "hash")?;
            if !intent.hashes.iter().any(|entry| entry.hash == h) {
                return Err(invalid(format_args!("{h} is not committed to intent {id}")));
            }
            hash = Some(h);
        }
        let block = require_count(record.get("block"), "block")?;
        Ok(Apply::Close {
            id,
            state: State::Settled,
            settlement: Some(Settlement {
                label,
                hash,
                block: Some(block),
                at,
            }),
            block: None,
            at,
        })
    }

    /// `voidRefusal`: why a void of `run` can't void the intent, or none.
    /// Live, an intent read from disk never qualifies.
    fn refusal(&self, intent: &Intent, run: &JsString, live: bool) -> Option<String> {
        if intent.state != State::Held {
            return Some(format!("it is {}", intent.state.name()));
        }
        if live && intent.recovered {
            return Some("it was recovered from disk, where a handoff may be missing".into());
        }
        if intent.summary.1 {
            return Some("an earlier handoff may have been sent".into());
        }
        let in_run = intent.run.as_ref() == Some(run)
            && intent
                .hashes
                .iter()
                .all(|entry| entry.run.as_ref() == Some(run))
            && intent
                .handoffs
                .iter()
                .all(|h| &h.run == run && h.outcome.as_ref().is_none_or(|o| &o.run == run));
        if !in_run {
            return Some("not all of it happened in this run of main".into());
        }
        for handoff in &intent.handoffs {
            match &handoff.outcome {
                None => {
                    return Some(
                        "a handoff has no recorded outcome, so it may have been sent".into(),
                    );
                }
                Some(o) if o.outcome != "not_sent" => {
                    return Some(format!(
                        "a handoff ended {}, so it may have been sent",
                        o.outcome
                    ));
                }
                Some(_) => {}
            }
        }
        self.held_of(intent.chain_id, &intent.sender)
            .find(|other| other.id != intent.id && other.nonce > intent.nonce)
            .map(|above| format!("held intent {} has a higher nonce", above.id))
    }

    fn prepare_void(&self, record: &JsValue, at: f64, mode: Mode) -> Result<Apply, Refusal> {
        let id = self.require_intent(record)?;
        let run = require_id(record.get("run"), "run")?;
        if mode.live && !mode.lock {
            return Err(refusal(
                "INTENT_LOCK_REQUIRED",
                "Voiding a payment needs its account's reservation lock.",
            ));
        }
        let intent = self.intent(&id)?;
        require_held(intent, mode)?;
        if let Some(why) = self.refusal(intent, &run, mode.live) {
            if !mode.live {
                return Err(invalid(format_args!("void of intent {id}: {why}")));
            }
            return Err(refusal(
                "INTENT_VOID_REFUSED",
                format!("This payment can't be voided: {why}."),
            ));
        }
        Ok(Apply::Close {
            id,
            state: State::Voided,
            settlement: None,
            block: None,
            at,
        })
    }

    fn prepare_retire(&self, record: &JsValue, at: f64, mode: Mode) -> Result<Apply, Refusal> {
        let id = self.require_intent(record)?;
        require_id(record.get("run"), "run")?;
        if mode.live && !mode.lock {
            return Err(refusal(
                "INTENT_LOCK_REQUIRED",
                "Closing a payment needs its account's reservation lock.",
            ));
        }
        require_held(self.intent(&id)?, mode)?;
        let block = require_count(record.get("block"), "block")?;
        Ok(Apply::Close {
            id,
            state: State::Retired,
            settlement: None,
            block: Some(block),
            at,
        })
    }

    /// The tracker's state; nothing else changes, `updatedAt` included.
    fn prepare_track(&self, record: &JsValue, mode: Mode) -> Result<Apply, Refusal> {
        let id = self.require_intent(record)?;
        require_id(record.get("run"), "run")?;
        require_held(self.intent(&id)?, mode)?;
        let (bracket, unread_since) = track_of(record)?;
        Ok(Apply::Track {
            id,
            bracket,
            unread_since,
        })
    }

    /// Applies a checked record (what the reference's `prepare*` returns),
    /// to the intent it names.
    fn apply_one(&mut self, apply: Apply) -> JsString {
        let (id, close) = match apply {
            Apply::Original(intent) => {
                let mut intent = *intent;
                self.sequence += 1;
                intent.sequence = self.sequence;
                // Sized afresh: the reference admits a copy of it.
                intent.sized.set(None);
                let id = intent.id.clone();
                self.by_id.insert(id.clone(), intent);
                return id;
            }
            Apply::Replacement { id, entry, at } => {
                if let Some(intent) = self.by_id.get_mut(&id) {
                    intent.hashes.push(entry);
                    intent.updated_at = at;
                }
                return id;
            }
            Apply::Handoff { id, handoff, at } => {
                if let Some(intent) = self.by_id.get_mut(&id) {
                    intent.handoffs.push(handoff);
                    intent.updated_at = at;
                }
                return id;
            }
            Apply::Outcome {
                id,
                handoff,
                outcome,
                at,
            } => {
                if let Some(intent) = self.by_id.get_mut(&id) {
                    if let Some(h) = intent.handoffs.iter_mut().find(|h| h.id == handoff) {
                        h.outcome = Some(outcome);
                    }
                    intent.updated_at = at;
                }
                return id;
            }
            Apply::Track {
                id,
                bracket,
                unread_since,
            } => {
                if let Some(intent) = self.by_id.get_mut(&id) {
                    intent.bracket = bracket;
                    intent.unread_since = unread_since;
                }
                return id;
            }
            Apply::Close {
                id,
                state,
                settlement,
                block,
                at,
            } => (id, (state, settlement, block, at)),
        };
        let (state, settlement, block, at) = close;
        if let Some(intent) = self.by_id.get_mut(&id) {
            intent.state = state;
            match state {
                State::Settled => intent.settlement = settlement,
                State::Voided => intent.voided_at = Some(at),
                _ => intent.retirement = Some((block, at)),
            }
            intent.close(at);
        }
        id
    }

    /// `recoverSigners`: the bytes a held intent keeps are signed by its
    /// sender, checked in the order the load met them.
    fn recover_signers(&self, unrecovered: &[(JsString, usize)]) -> Result<(), Refusal> {
        for (id, index) in unrecovered {
            let intent = self.intent(id)?;
            let Some(raw) = intent.hashes.get(*index).and_then(|e| e.raw.as_deref()) else {
                continue;
            };
            if intent.state == State::Held
                && signer_of(raw).as_deref() != Some(intent.sender.as_str())
            {
                return Err(invalid(format_args!(
                    "intent {id}'s bytes are not signed by its sender"
                )));
            }
        }
        Ok(())
    }

    /// `foldLoaded`: every handoff is an earlier run's now, folded into the
    /// summary; only the latest bytes are kept.
    fn fold_loaded(&mut self) {
        for intent in self.by_id.values_mut().filter(|i| i.state == State::Held) {
            intent.summary = intent.tally();
            intent.handoffs.clear();
            let last = intent.hashes.len().saturating_sub(1);
            for entry in &mut intent.hashes[..last] {
                entry.raw = None;
                entry.fields = None;
            }
        }
    }

    // --- Compaction --------------------------------------------------------

    fn snapshot_record(intent: &Intent, sizing: bool) -> JsValue {
        Self::snapshot_with(intent, sizing, None)
    }

    /// `snapshotRecord(intent, { sizing, extra })`: with `extra`, as if it
    /// were its latest hash.
    fn snapshot_with(intent: &Intent, sizing: bool, extra: Option<&Entry>) -> JsValue {
        let hashes: Vec<&Entry> = intent.hashes.iter().chain(extra).collect();
        let latest = hashes.last().copied();
        let (count, possibly_sent) = if sizing {
            (MAX_SAFE_INTEGER, false)
        } else {
            intent.folded()
        };
        let mut props = vec![
            ("type", text("held")),
            ("run", opt(intent.run.clone(), JsValue::String)),
            ("at", num(intent.created_at)),
            ("intent_id", JsValue::String(intent.id.clone())),
            ("chain_id", num(intent.chain_id)),
            ("sender", text(&intent.sender)),
            ("nonce", num(intent.nonce)),
            ("hash", opt(latest, |e| text(&e.hash))),
            ("raw", opt(latest.and_then(|e| e.raw.as_deref()), text)),
            ("fields", opt(latest.and_then(|e| e.fields.clone()), |f| f)),
            ("context", opt(intent.context.as_ref(), context_record)),
            (
                "hashes",
                JsValue::Array(
                    hashes
                        .iter()
                        .map(|e| {
                            object(vec![
                                ("hash", text(&e.hash)),
                                ("via", text(e.via())),
                                ("at", opt(e.at, num)),
                                ("run", opt(e.run.clone(), JsValue::String)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "handoffs",
                object(vec![
                    ("count", num(count)),
                    ("possibly_sent", JsValue::Bool(possibly_sent)),
                ]),
            ),
        ];
        let (bracket, unread_since) = if sizing {
            (
                Some((MAX_SAFE_INTEGER, LONGEST_HASH.to_owned())),
                Some(MAX_SAFE_INTEGER),
            )
        } else {
            (intent.bracket.clone(), intent.unread_since)
        };
        if let Some((number, hash)) = bracket {
            props.push((
                "bracket",
                object(vec![("number", num(number)), ("hash", text(&hash))]),
            ));
        }
        if let Some(since) = unread_since {
            props.push(("unread_since", num(since)));
        }
        object(props)
    }

    fn tombstone_record(intent: &Intent) -> JsValue {
        let mut props = vec![
            ("type", text("tombstone")),
            ("at", opt(intent.closed_at, num)),
            ("intent_id", JsValue::String(intent.id.clone())),
            ("chain_id", num(intent.chain_id)),
            ("sender", text(&intent.sender)),
            ("nonce", num(intent.nonce)),
            ("closed", text(intent.state.name())),
        ];
        if let Some(settlement) = intent
            .settlement
            .as_ref()
            .filter(|_| intent.state == State::Settled)
        {
            props.push(("label", text(settlement.label)));
        }
        if intent.state == State::Retired {
            props.push((
                "hashes",
                JsValue::Array(intent.hashes.iter().map(|e| text(&e.hash)).collect()),
            ));
        }
        object(props)
    }

    /// `compactedRecords`: the newest tombstones, then each held intent in
    /// the order it was created, with this run's open handoffs after it.
    pub fn compaction(&self) -> Vec<JsValue> {
        let mut records: Vec<JsValue> = self
            .kept_closed()
            .into_iter()
            .map(Self::tombstone_record)
            .collect();
        for intent in self.held_intents() {
            records.push(Self::snapshot_record(intent, false));
            records.extend(intent.open().map(|h| h.record.clone()));
        }
        records
    }

    /// After compaction's file is in place: closed intents past the kept
    /// tombstones are forgotten, and finished handoffs folded away.
    pub fn compacted(&mut self) {
        let kept: Vec<JsString> = self
            .kept_closed()
            .into_iter()
            .map(|i| i.id.clone())
            .collect();
        self.by_id
            .retain(|id, i| i.state == State::Held || kept.contains(id));
        for intent in self.by_id.values_mut().filter(|i| i.state == State::Held) {
            intent.summary = intent.folded();
            intent.handoffs.retain(|h| h.outcome.is_none());
        }
    }

    // --- Budget ------------------------------------------------------------

    /// `snapshotBytes`: a held intent's snapshot at its widest, cached
    /// until it has another hash; with `extra`, as if it had that one too.
    fn snapshot_bytes(intent: &Intent, extra: Option<&Entry>) -> usize {
        if extra.is_some() {
            return line_bytes(&Self::snapshot_with(intent, true, extra));
        }
        match intent.sized.get() {
            Some((hashes, bytes)) if hashes == intent.hashes.len() => bytes,
            _ => {
                let bytes = line_bytes(&Self::snapshot_record(intent, true));
                intent.sized.set(Some((intent.hashes.len(), bytes)));
                bytes
            }
        }
    }

    /// `intentBudget`: the held intent's widest snapshot, its terminal line,
    /// and its open handoffs with their outcomes, or one such pair. `extra`
    /// and `extra_open` count a hash and an open handoff (its line's bytes)
    /// it doesn't have yet.
    fn intent_budget(intent: &Intent, extra: Option<&Entry>, extra_open: usize) -> usize {
        let outcome = outcome_line_max();
        let open: usize = intent
            .open()
            .map(|h| line_bytes(&h.record) + outcome)
            .sum::<usize>()
            + if extra_open > 0 {
                extra_open + outcome
            } else {
                0
            };
        Self::snapshot_bytes(intent, extra)
            + terminal_line_max()
            + (handoff_line_max() + outcome).max(open)
    }

    /// `budget()`: what compaction would write at its widest, plus what is
    /// owed and each held intent's headroom.
    pub fn budget(&self) -> usize {
        let held: usize = self
            .held_intents()
            .map(|i| Self::intent_budget(i, None, 0))
            .sum();
        let tombstones: usize = self
            .kept_closed()
            .into_iter()
            .map(|i| line_bytes(&Self::tombstone_record(i)))
            .sum();
        held + tombstones
    }

    /// `owed()`: a terminal line for each held intent and an outcome for
    /// each open handoff.
    pub fn owed(&self) -> usize {
        self.held_intents()
            .map(|i| terminal_line_max() + i.open().count() * outcome_line_max())
            .sum()
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    // --- Views -------------------------------------------------------------

    /// `get(intentId)`.
    pub fn get(&self, intent_id: &str) -> Option<JsValue> {
        self.by_id.get(&JsString::from(intent_id)).map(view)
    }

    /// `byKey(key)`: the last held intent whose context has `key` (none:
    /// null).
    pub fn by_key(&self, key: Option<&JsString>) -> Option<JsValue> {
        self.held_intents()
            .filter(|i| i.context.as_ref().is_some_and(|c| c.key.as_ref() == key))
            .last()
            .map(view)
    }

    /// `held()`: by chain, sender and nonce.
    pub fn held(&self) -> Vec<JsValue> {
        let mut held: Vec<&Intent> = self.held_intents().collect();
        held.sort_by(|a, b| {
            a.chain_id
                .total_cmp(&b.chain_id)
                .then_with(|| a.sender.cmp(&b.sender))
                .then_with(|| a.nonce.total_cmp(&b.nonce))
        });
        held.into_iter().map(view).collect()
    }

    /// `list()`: every intent known, in the order the load met them.
    pub fn list(&self) -> Vec<JsValue> {
        self.in_order().into_iter().map(view).collect()
    }

    /// `heldNonces(chainId, sender)`, ascending.
    pub fn held_nonces(&self, chain_id: f64, sender: &str) -> Vec<f64> {
        let sender = sender.to_ascii_lowercase();
        let mut nonces: Vec<f64> = self.held_of(chain_id, &sender).map(|i| i.nonce).collect();
        nonces.sort_by(f64::total_cmp);
        nonces
    }

    /// `voidRefusal(intentId)` for a void of `run` (live): none for an
    /// unknown intent (`INTENT_UNKNOWN`), else the reason or none.
    pub fn void_refusal(&self, intent_id: &str, run: &str) -> Option<Option<String>> {
        let intent = self.by_id.get(&JsString::from(intent_id))?;
        Some(self.refusal(intent, &JsString::from(run), true))
    }
}

fn context_record(c: &Context) -> JsValue {
    object(vec![
        ("kind", text(&c.kind)),
        ("origin", opt(c.origin.clone(), JsValue::String)),
        ("key", opt(c.key.clone(), JsValue::String)),
        ("wallet_index", opt(c.wallet_index, num)),
    ])
}

fn camel_fields(fields: &JsValue) -> JsValue {
    let f = |key| fields.get(key).cloned().unwrap_or(JsValue::Undefined);
    object(vec![
        ("type", f("type")),
        ("to", f("to")),
        ("value", f("value")),
        ("data", f("data")),
        ("gasLimit", f("gas_limit")),
        ("maxFeePerGas", f("max_fee_per_gas")),
        ("maxPriorityFeePerGas", f("max_priority_fee_per_gas")),
        ("gasPrice", f("gas_price")),
    ])
}

/// `view(intent)`: a copy for callers, in camelCase.
fn view(intent: &Intent) -> JsValue {
    let latest = intent.hashes.last();
    let (count, possibly_sent) = intent.tally();
    object(vec![
        ("intentId", JsValue::String(intent.id.clone())),
        ("chainId", num(intent.chain_id)),
        ("sender", text(&intent.sender)),
        ("nonce", num(intent.nonce)),
        ("state", text(intent.state.name())),
        ("recovered", JsValue::Bool(intent.recovered)),
        (
            "context",
            opt(intent.context.as_ref(), |c| {
                object(vec![
                    ("kind", text(&c.kind)),
                    ("origin", opt(c.origin.clone(), JsValue::String)),
                    ("key", opt(c.key.clone(), JsValue::String)),
                    ("walletIndex", opt(c.wallet_index, num)),
                ])
            }),
        ),
        ("hash", opt(latest, |e| text(&e.hash))),
        ("raw", opt(latest.and_then(|e| e.raw.as_deref()), text)),
        (
            "fields",
            opt(latest.and_then(|e| e.fields.as_ref()), camel_fields),
        ),
        (
            "hashes",
            JsValue::Array(
                intent
                    .hashes
                    .iter()
                    .map(|e| {
                        object(vec![
                            ("hash", text(&e.hash)),
                            ("raw", opt(e.raw.as_deref(), text)),
                            ("via", text(e.via())),
                            ("at", opt(e.at, num)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "handoffs",
            JsValue::Array(
                intent
                    .handoffs
                    .iter()
                    .map(|h| {
                        object(vec![
                            ("handoffId", JsValue::String(h.id.clone())),
                            ("hash", text(&h.hash)),
                            ("at", num(h.at)),
                            (
                                "outcome",
                                opt(h.outcome.as_ref(), |o| {
                                    object(vec![
                                        ("outcome", text(o.outcome)),
                                        ("source", opt(o.source.clone(), JsValue::String)),
                                        (
                                            "reasonClass",
                                            opt(o.reason_class.clone(), JsValue::String),
                                        ),
                                        ("at", num(o.at)),
                                    ])
                                }),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("handoffCount", num(count)),
        ("possiblySent", JsValue::Bool(possibly_sent)),
        (
            "bracket",
            opt(intent.bracket.as_ref(), |(number, hash)| {
                object(vec![("number", num(*number)), ("hash", text(hash))])
            }),
        ),
        ("unreadSince", opt(intent.unread_since, num)),
        (
            "settlement",
            opt(intent.settlement.as_ref(), |s| {
                object(vec![
                    ("label", text(s.label)),
                    ("hash", opt(s.hash.as_deref(), text)),
                    ("block", opt(s.block, num)),
                    ("at", num(s.at)),
                ])
            }),
        ),
        ("voidedAt", opt(intent.voided_at, num)),
        (
            "retirement",
            opt(intent.retirement, |(block, at)| {
                object(vec![("block", opt(block, num)), ("at", num(at))])
            }),
        ),
        ("createdAt", num(intent.created_at)),
        ("updatedAt", num(intent.updated_at)),
    ])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn record(text: &str) -> JsValue {
        fc_json::parse(text).unwrap()
    }

    #[test]
    fn a_type_that_cannot_be_a_key_is_javascripts_type_error() {
        let r = record(r#"{"type":{"toString":1},"at":1}"#);
        let e = Intents::load(&[r], LIMITS).err().unwrap();
        assert_eq!(e.0, "Cannot convert object to primitive value");
        let r = record(r#"{"at":1}"#);
        let e = Intents::load(&[r], LIMITS).err().unwrap();
        assert_eq!(e.0, "Invalid wallet intent record: unknown record type");
    }

    #[test]
    fn no_tombstone_limit_keeps_them_all_as_slice_minus_zero_does() {
        let tomb = |id: &str, at: u32| {
            record(&format!(
                r#"{{"type":"tombstone","at":{at},"intent_id":"{id}","chain_id":1,"sender":"0x{}","nonce":0,"closed":"voided"}}"#,
                "ab".repeat(20)
            ))
        };
        let records = [
            tomb("aaaaaaaa", 2),
            tomb("bbbbbbbb", 1),
            tomb("cccccccc", 3),
        ];
        let all = Intents::load(
            &records,
            Limits {
                tombstones: 0,
                ..LIMITS
            },
        )
        .unwrap();
        assert_eq!(all.intents.compaction().len(), 3);
        let mut two = Intents::load(
            &records,
            Limits {
                tombstones: 2,
                ..LIMITS
            },
        )
        .unwrap();
        let kept: Vec<String> = two
            .intents
            .compaction()
            .iter()
            .map(|r| r.get("intent_id").unwrap().as_str().unwrap().to_owned())
            .collect();
        assert_eq!(kept, ["aaaaaaaa", "cccccccc"]);
        assert!(two.compact);
        two.intents.compacted();
        assert_eq!(two.intents.list().len(), 2);
        assert_eq!(two.intents.get("bbbbbbbb"), None);
    }
}
