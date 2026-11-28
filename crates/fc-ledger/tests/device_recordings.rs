//! LDG-3's device recordings replayed against the core (design 0016, LDG-3;
//! the LDG-3 plan's C1). Each case a Ledger answered goes through the
//! core's own machine, sans-I/O as ledger_vectors.rs drives it, with the
//! recorded answers fed in: every APDU the core emits is the recorded one
//! byte for byte (and waits for the user exactly where the recorded
//! `deadline_ms` says), its end is the recorded outcome, and every
//! signature recovers to the test account over the digest the core
//! computed.
//!
//! **The files** are freedom-browser's `scripts/ledger-record.js`'s, one
//! per device, exactly as it writes them; its `formats` says the form, and
//! this test holds its own copy ([`FORMATS`]) and reads every file
//! strictly against it: an unknown member, a missing one, a model the
//! recorder doesn't name or another `formats` fails.
//! - `vectors/ledger-devices/ledger-devices-<model>.json`: the user's
//!   recordings from the device session (the plan's §5), copied in under
//!   the names the recorder suggests, one per model. Until the session the
//!   directory is missing or empty and [`device_recordings_replay`]
//!   replays nothing. **When the recordings land** it replays every file
//!   there, each of which must be a real recording (no `meta.synthetic`,
//!   run under Electron, a firmware version that isn't `synthetic`) of
//!   the whole session: `meta.complete`, and every step the recorder plays
//!   for its model ([`FIELD_STEPS`], or a Nano S's [`HASH_ONLY_STEPS`])
//!   done as it asks. CI then holds the core to them; the synthetic files
//!   stay, as the damage tests' material.
//! - `tests/data/ledger-devices-synthetic/`: the same recorder run against
//!   the fake node-hid and a scripted Ethereum app
//!   (`tests/gen/synthetic-recordings.js`), `meta.synthetic` set and the
//!   firmware `synthetic`: not device evidence. Replayed always, so the
//!   replay is exercised before the session.
//!
//! **What is replayed:** the cases of `stream: "core"`, main's own stream,
//! which the joint contract makes the core's. `hash_only: "shown"` on the
//! `6D00` to the operation's first `E0 1A` is main's word that the warning
//! is on screen, and the core takes the hash-only branch; `cancelled:
//! true` is the parent's cancel: the core sent that APDU and is waiting
//! when the parent ends, so it sends nothing more. A `stream: "reference"`
//! case holds the JS reference's APDUs for F-2's names, which the core
//! refuses before any APDU (deviation `name-ascii`): device evidence only,
//! read as strictly and not replayed. Its APDUs are ledger.json's reference
//! ones for a request the core refuses; it stops short of them only where
//! the device ended it with a status other than `9000` or a failure, and a
//! signature the device gave recovers to the test account over
//! `expected_hash`.
//!
//! The timings (R2, R3) are read and recomputed, never judged: an answer
//! later than the core's `deadline_ms` is counted and printed for C2/C3.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use common::{account_at, grammar, hex, ledger, other_key};
use fc_evm::{
    Transaction, U256, checksum_address, decode_signed, eip191_digest, parse_address, parse_bytes,
    recover_address, sign_digest, typed_data_parse,
};
use fc_ledger::{
    Account, Cause, Failed, LedgerCode, LedgerPath, Operation, Reply, Scheme, Signed, Step,
};
use serde_json::{Map, Value, json};

/// The recorder's models (`MODELS` in scripts/ledger-record.js).
const MODELS: [(&str, &str); 5] = [
    ("nanoSP", "Nano S Plus"),
    ("nanoX", "Nano X"),
    ("stax", "Stax"),
    ("flex", "Flex"),
    ("nanoS", "Nano S"),
];
/// One step of the device session, as scripts/ledger-record.js plays it
/// (`DISCOVERY`, `FIELD_STEPS`, `HASH_ONLY_STEPS`): its id, the ledger.json
/// case it plays (`from`, ledger-record-cases.json's), its family and its
/// hands.
type SessionStep = (&'static str, &'static str, &'static str, &'static str);
/// The check of the first account, recorded before any step.
const DISCOVERY: SessionStep = ("discovery", "discovery-live-0-1", "discovery", "none");
/// The steps for a device that shows typed data's fields.
const FIELD_STEPS: [SessionStep; 19] = [
    (
        "tx-type0",
        "tx-type0-chain-1-parity-0",
        "transaction",
        "approve",
    ),
    (
        "tx-type2",
        "tx-type2-chain-1-parity-0",
        "transaction",
        "approve",
    ),
    ("message", "msg-steps", "message", "approve"),
    ("typed-mail", "typed-mail", "typed-data", "approve"),
    ("typed-safe-tx", "typed-safe-tx", "typed-data", "approve"),
    (
        "typed-eip3009",
        "typed-eip3009-transfer-with-authorization",
        "typed-data",
        "approve",
    ),
    (
        "name-field-ascii-253",
        "name-field-ascii-253",
        "name-length",
        "approve",
    ),
    (
        "name-primary-type-ascii-255",
        "name-primary-type-ascii-255",
        "name-length",
        "approve",
    ),
    (
        "name-field-e-acute-252",
        "name-field-e-acute-252",
        "name-length",
        "any",
    ),
    (
        "name-field-e-acute-253",
        "name-field-e-acute-253",
        "name-length",
        "any",
    ),
    (
        "name-field-emoji-252",
        "name-field-emoji-252",
        "name-length",
        "any",
    ),
    (
        "name-field-emoji-253",
        "name-field-emoji-253",
        "name-length",
        "any",
    ),
    ("add", "add-live-0", "add", "approve"),
    ("reject", "msg-live-125", "message", "reject"),
    (
        "contract-call-blind-off",
        "tx-steps",
        "transaction",
        "refuse",
    ),
    (
        "contract-call-blind-on",
        "tx-steps",
        "transaction",
        "approve",
    ),
    ("unplug", "msg-live-126", "message", "unplug"),
    ("cancel-old", "msg-live-275", "message", "leave"),
    ("cancel-new", "msg-live-1", "message", "reject-old"),
];
/// A Nano S's steps: the hash-only ones alone.
const HASH_ONLY_STEPS: [SessionStep; 2] = [
    (
        "typed-hash-only-mail",
        "typed-hash-only-mail",
        "hash-only",
        "approve",
    ),
    (
        "typed-hash-only-safe-tx",
        "typed-hash-only-safe-tx",
        "hash-only",
        "approve",
    ),
];

/// A model's whole session, discovery first.
fn session(model: &str) -> Vec<SessionStep> {
    let steps: &[SessionStep] = if model == "nanoS" {
        &HASH_ONLY_STEPS
    } else {
        &FIELD_STEPS
    };
    std::iter::once(DISCOVERY)
        .chain(steps.iter().copied())
        .collect()
}

/// The public test phrase's first account (keys.json's abandon-12).
const TEST_PATH: &str = "44'/60'/0'/0/0";
const TEST_ADDRESS: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
/// What the core sends as `deadline_ms`: an APDU that waits for the user,
/// and one that doesn't.
const USER_MS: u64 = 300_000;
const DEVICE_MS: u64 = 15_000;
/// The grammar's bound on APDUs per operation, as the recorder's timing
/// uses it.
const APDUS_PER_OPERATION: f64 = 2048.0;

/// The recorder's description of its own form (`FORMATS` in
/// scripts/ledger-record.js at freedom-browser 2210097b, PR 13), which
/// every file must carry unchanged.
const FORMATS: &str = r#"{
    "file": "vectors/ledger-devices.json's form (freedom-core design 0016, Vectors; LDG-3): one real Ledger's answers to Freedom's requests with the public test phrase on the device, recorded by freedom-browser's scripts/ledger-record.js, for the core's replay test (C1). One file per device.",
    "device": "{ model (nanoSP, nanoX, stax, flex or nanoS), name, firmware (as the user read it from the device or Ledger Live), app { name, version } and b001 (its B0 01 answer, hex), mnemonicId (keys.json's abandon-12), account { path, address }: the first account, which the recorder checked before it recorded anything }",
    "case": "{ id, attempt (from 1: a step the user tried again), from (the ledger.json case, at meta.vectors, whose operation, request and record these are), family, operation (the core's method), request (the core's wire form: ledger.accounts { scheme, start, count }; ledger.add { scheme, index, name }; sign.transaction { tx }; sign.message { message }; sign.typed_data { typed_data, expected_hash }), record { path, address } (a signature's account), stream, device (the file's model, firmware and app), hands, exchanges, outcome, then signer or address, hashes (the hash-only branch), after (the cancel case's new request: the old one's id and attempt), dropped (reports the HID host dropped: another channel's, such as an old request's late answer) }",
    "stream": "core: main's own stream for the request (core/ledger-grammar.js's Admission, with wallet/ledger/apdu-binding.js for typed data), the core's by the joint contract (0016, Main's typed-data binding), played APDU by APDU through the Admission as main's relay will, the hash-only APDU after a 6D00 to the first E0 1A. reference: ledger.json's APDUs for the case, the JS reference's, whose name length bytes count UTF-16 units (deviation name-ascii, F-2): the core never sends them; recorded to show what a device does with them.",
    "hands": "what the user was asked to do on the device: none (nothing shows), approve, reject, refuse (a contract call with blind signing off: the device should refuse it), unplug (at the prompt), leave (the cancel case's old request, left on screen until the recorder cancelled it), reject-old (the cancel case's new request, started at once: reject the old prompt, then approve this one), any (a reference stream: approve what shows, or dismiss an error).",
    "exchange": "{ apdu (hex), row (the grammar's row), deadline_ms (what the core sends: 300000 for the APDU that waits for the user, else 15000), at_ms (when it was sent, from the session's start), then answer (hex, the status word last), failed (not_found, busy, disconnected, unresponsive or timeout) or cancelled: true (the recorder let go of it, as main does on the core's cancel), ms (until the answer or the failure), held (an APDU that doesn't wait for the user, answered after meta.heldMs or more: R2), hash_only: 'shown' (the 6D00 the hash-only APDU follows) }. The recorder gives every APDU 5 minutes, so an answer held for the user is measured rather than cut off at 15 s; the cancel case's new request runs under the core's deadline_ms, as Freedom will.",
    "outcome": "{ status (the last answer's status word, hex) | failed | cancelled: true, as_asked: whether that is what the hands asked for }",
    "signer": "a signature answered 9000: the address its v, r and s recover to over the core's digest (a transaction's keccak256 of its unsigned serialization, a message's EIP-191 hash, typed data's expected_hash), or null. address: for ledger.accounts and ledger.add, the address the device answered. hashes: the hash-only warning's { domain, message } and match, the user's word that the device showed the same.",
    "timing": "R3: the time per APDU that doesn't wait for the user (held ones left out), overall and by CLA INS, and what the grammar's 2,048 APDUs would take at the median and at the 90th percentile.",
    "held": "R2: of the APDUs that don't wait for the user, in the steps the user approved, how many were answered after meta.heldMs or more, by CLA INS, and in which steps."
}"#;

type R<T> = Result<T, String>;

/// A real recording or a synthetic one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Synthetic,
    Device,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum End {
    Answer(Vec<u8>),
    Failed(Failed),
    Cancelled,
}

#[derive(Debug, Clone)]
struct Exchange {
    apdu: Vec<u8>,
    /// `deadline_ms` is 5 minutes: the device waits for the user.
    waits: bool,
    end: End,
    hash_only: bool,
    at_ms: f64,
    ms: f64,
    held: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Status(u16),
    Failed(Failed),
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream {
    Core,
    Reference,
}

#[derive(Debug, Clone)]
struct Case {
    id: String,
    attempt: u64,
    from: String,
    operation: String,
    request: Value,
    record: Option<Account>,
    stream: Stream,
    hands: String,
    exchanges: Vec<Exchange>,
    outcome: Outcome,
    /// `outcome.as_asked`, which is what the step's hands asked for.
    as_asked: bool,
    /// `signer` (a signature's) or `address` (`ledger.accounts`,
    /// `ledger.add`); `None` for null.
    answered: Option<[u8; 20]>,
    /// The hash-only warning's `{ domain, message }`, and the user's word
    /// that the device showed the same.
    hashes: Option<([u8; 32], [u8; 32], bool)>,
    after: Option<(String, u64)>,
}

#[derive(Debug)]
struct Recording {
    file: String,
    cases: Vec<Case>,
}

/// What one file's replay found.
#[derive(Debug, Default, PartialEq, Eq)]
struct Tally {
    file: String,
    core: usize,
    reference: usize,
    /// Each core case's end: `accounts`, `added`, `signed`, `hash-only`,
    /// `status <sw>`, `failed <reason>` or `cancelled`.
    ends: BTreeMap<String, usize>,
    /// Answers that came later than the core's `deadline_ms` (R2).
    late: usize,
}

// ---------------------------------------------------------------------------
// The vectors the recordings are read against

struct Vectors {
    /// ledger.json's cases by id.
    cases: BTreeMap<&'static str, &'static Value>,
    /// ledger-grammar.json's rows: each one's APDU headers.
    rows: BTreeMap<&'static str, BTreeSet<&'static str>>,
    /// ledger-grammar.json's honest streams by case.
    honest: BTreeMap<&'static str, Vec<&'static str>>,
}

fn vectors() -> &'static Vectors {
    static VECTORS: OnceLock<Vectors> = OnceLock::new();
    VECTORS.get_or_init(|| {
        let cases = ledger()["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| (c["id"].as_str().unwrap(), c))
            .collect();
        let rows = grammar()["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                let headers = row["apdus"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|a| a["header"].as_str().unwrap())
                    .collect();
                (row["row"].as_str().unwrap(), headers)
            })
            .collect();
        let honest = grammar()["honest"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                let apdus = h["apdus"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| a.as_str().unwrap())
                    .collect();
                (h["case"].as_str().unwrap(), apdus)
            })
            .collect();
        Vectors {
            cases,
            rows,
            honest,
        }
    })
}

fn test_address() -> [u8; 20] {
    parse_address(TEST_ADDRESS).unwrap()
}

/// The test phrase's address at a path.
fn test_address_at(path: &LedgerPath) -> [u8; 20] {
    account_at(&path.to_string()).address
}

// ---------------------------------------------------------------------------
// Reading strictly

/// An object of exactly `required` and some of `optional`.
fn members<'a>(
    value: &'a Value,
    at: &str,
    required: &[&str],
    optional: &[&str],
) -> R<&'a Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{at}: not an object"))?;
    if let Some(key) = object
        .keys()
        .find(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str()))
    {
        return Err(format!("{at}: an unknown member, {key}"));
    }
    if let Some(key) = required.iter().find(|k| !object.contains_key(**k)) {
        return Err(format!("{at}: no {key}"));
    }
    Ok(object)
}

fn field<'a>(object: &'a Map<String, Value>, key: &str, at: &str) -> R<&'a Value> {
    object.get(key).ok_or_else(|| format!("{at}: no {key}"))
}

fn text<'a>(object: &'a Map<String, Value>, key: &str, at: &str) -> R<&'a str> {
    field(object, key, at)?
        .as_str()
        .ok_or_else(|| format!("{at}: {key} isn't a string"))
}

fn uint(object: &Map<String, Value>, key: &str, at: &str) -> R<u64> {
    field(object, key, at)?
        .as_u64()
        .ok_or_else(|| format!("{at}: {key} isn't a whole number"))
}

/// A number of milliseconds: finite, at least 0.
fn millis(object: &Map<String, Value>, key: &str, at: &str) -> R<f64> {
    field(object, key, at)?
        .as_f64()
        .filter(|ms| ms.is_finite() && *ms >= 0.0)
        .ok_or_else(|| format!("{at}: {key} isn't a time"))
}

fn flag(object: &Map<String, Value>, key: &str, at: &str) -> R<bool> {
    field(object, key, at)?
        .as_bool()
        .ok_or_else(|| format!("{at}: {key} isn't true or false"))
}

/// Lower-case hex without `0x`, as the recorder writes bytes.
fn bytes(text: &str, at: &str) -> R<Vec<u8>> {
    let hex = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return Err(format!("{at}: not hex bytes"));
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some(hex(pair[0])? << 4 | hex(pair[1])?))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| format!("{at}: not lower-case hex"))
}

/// A 32-byte hash as `0x` and lower-case hex.
fn hash(text: &str, at: &str) -> R<[u8; 32]> {
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| format!("{at}: no 0x"))?;
    bytes(digits, at)?
        .try_into()
        .map_err(|_| format!("{at}: not 32 bytes"))
}

/// An EIP-55 address, as the recorder writes them.
fn address(value: &Value, at: &str) -> R<[u8; 20]> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{at}: not an address"))?;
    let address = parse_address(text).map_err(|e| format!("{at}: {e}"))?;
    if checksum_address(&address) != text {
        return Err(format!("{at}: {text} isn't EIP-55"));
    }
    Ok(address)
}

fn optional_address(value: &Value, at: &str) -> R<Option<[u8; 20]>> {
    match value {
        Value::Null => Ok(None),
        value => address(value, at).map(Some),
    }
}

/// Two values the same, numbers by value: the recorder writes a whole
/// number of milliseconds without a fraction.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same(x, y))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

/// A recording, read strictly.
fn parse(file: &str, value: &Value, kind: Kind) -> R<Recording> {
    let model = file
        .strip_prefix("ledger-devices-")
        .and_then(|m| m.strip_suffix(".json"))
        .filter(|m| MODELS.iter().any(|(id, _)| id == m))
        .ok_or_else(|| {
            format!("{file}: not ledger-devices-<model>.json for a model the recorder names")
        })?;
    let top = members(
        value,
        file,
        &["meta", "formats", "device", "cases", "timing", "held"],
        &[],
    )?;
    let held_ms = meta(file, &top["meta"], kind)?;
    let formats: Value = serde_json::from_str(FORMATS).unwrap();
    if top["formats"] != formats {
        return Err(format!("{file}: formats isn't the form this test reads"));
    }
    let device = device(file, model, &top["device"], kind)?;
    let list = top["cases"]
        .as_array()
        .filter(|list| !list.is_empty())
        .ok_or_else(|| format!("{file}: cases isn't a list of cases"))?;
    let session = session(model);
    let mut cases: Vec<Case> = Vec::new();
    for (k, value) in list.iter().enumerate() {
        let case = case(
            &format!("{file}: case {k}"),
            value,
            &device,
            &session,
            held_ms,
        )?;
        let at = format!("{file}: {} #{}", case.id, case.attempt);
        if cases
            .iter()
            .any(|c| c.id == case.id && c.attempt == case.attempt)
        {
            return Err(format!("{at}: twice"));
        }
        if let Some((id, attempt)) = &case.after
            && !cases
                .iter()
                .any(|c| &c.id == id && c.attempt == *attempt && c.outcome == Outcome::Cancelled)
        {
            return Err(format!("{at}: after names no cancelled case before it"));
        }
        cases.push(case);
    }
    // Nothing is recorded before the device's first account is the test
    // phrase's.
    let first = &cases[0];
    if first.id != "discovery"
        || first.operation != "ledger.accounts"
        || first.outcome != Outcome::Status(0x9000)
        || first.answered != Some(test_address())
    {
        return Err(format!(
            "{file}: the first case isn't discovery's check of the test account"
        ));
    }
    // The whole session its model's steps define: each step done as it
    // asks, at some attempt.
    for (id, ..) in &session {
        if !cases.iter().any(|c| c.id == *id && c.as_asked) {
            return Err(format!(
                "{file}: the session has no {id} done as its step asks"
            ));
        }
    }
    // One session clock, each APDU sent after the one before.
    let sent: Vec<f64> = cases
        .iter()
        .flat_map(|c| c.exchanges.iter().map(|e| e.at_ms))
        .collect();
    if sent.windows(2).any(|w| w[1] < w[0]) {
        return Err(format!("{file}: at_ms goes back"));
    }
    timing(file, &top["timing"], &cases)?;
    held(file, &top["held"], &cases, held_ms)?;
    Ok(Recording {
        file: file.to_owned(),
        cases,
    })
}

/// `meta`, and its `heldMs`.
fn meta(file: &str, value: &Value, kind: Kind) -> R<f64> {
    let at = format!("{file}: meta");
    let mut required = vec![
        "design",
        "recorder",
        "freedomBrowserCommit",
        "vectors",
        "recordedAt",
        "host",
        "heldMs",
        "complete",
    ];
    match kind {
        Kind::Synthetic => required.push("synthetic"),
        Kind::Device if value.get("synthetic").is_some() => {
            return Err(format!(
                "{at}: synthetic: not device evidence, among the device recordings"
            ));
        }
        Kind::Device => {}
    }
    let meta = members(value, &at, &required, &[])?;
    if text(meta, "design", &at)? != "0016, LDG-3" {
        return Err(format!("{at}: design"));
    }
    if text(meta, "recorder", &at)? != "freedom-browser scripts/ledger-record.js" {
        return Err(format!("{at}: recorder"));
    }
    match &meta["freedomBrowserCommit"] {
        Value::Null => {}
        Value::String(commit) if commit.len() == 40 && bytes(commit, &at).is_ok() => {}
        _ => return Err(format!("{at}: freedomBrowserCommit")),
    }
    // The ledger.json the recorder's cases are held to (its
    // ledger-record-cases.json `source`). Each case's request is also
    // checked against vectors/ledger.json as it is here.
    let source = json!({
        "repo": "solardev-xyz/freedom-core",
        "commit": "b4e0cef4f24f4e80aaa9df6568c7c9737ade9589",
        "release": "cored-v0.30.0",
        "file": "vectors/ledger.json",
    });
    if meta["vectors"] != source {
        return Err(format!("{at}: vectors isn't the recorder's source"));
    }
    let recorded = text(meta, "recordedAt", &at)?.as_bytes();
    if recorded.len() != 24 || recorded[10] != b'T' || recorded[23] != b'Z' {
        return Err(format!("{at}: recordedAt"));
    }
    let host = members(
        &meta["host"],
        &format!("{at}.host"),
        &["platform", "arch", "electron", "node"],
        &[],
    )?;
    for key in ["platform", "arch", "node"] {
        text(host, key, &at)?;
    }
    // The recorder runs only under Electron's Node; the synthetic files
    // come from plain Node.
    match (kind, &host["electron"]) {
        (Kind::Device, Value::String(_)) | (Kind::Synthetic, Value::Null) => {}
        _ => return Err(format!("{at}: host.electron")),
    }
    let held_ms = millis(meta, "heldMs", &at)?;
    if held_ms <= 0.0 {
        return Err(format!("{at}: heldMs"));
    }
    // The recorder writes the file after every step, `complete` once the
    // last is done.
    if !flag(meta, "complete", &at)? {
        return Err(format!("{at}: complete is false: an unfinished session"));
    }
    if kind == Kind::Synthetic && !text(meta, "synthetic", &at)?.starts_with("Not device evidence")
    {
        return Err(format!("{at}: a synthetic recording, unmarked"));
    }
    Ok(held_ms)
}

/// `device`, and what each case's `device` must be.
fn device(file: &str, model: &str, value: &Value, kind: Kind) -> R<Value> {
    let at = format!("{file}: device");
    let device = members(
        value,
        &at,
        &[
            "model",
            "name",
            "firmware",
            "app",
            "b001",
            "mnemonicId",
            "account",
        ],
        &[],
    )?;
    let named = text(device, "model", &at)?;
    if named != model {
        return Err(format!("{at}: model {named}, in {model}'s file"));
    }
    let name = MODELS.iter().find(|(id, _)| *id == model).unwrap().1;
    if text(device, "name", &at)? != name {
        return Err(format!("{at}: name isn't {model}'s, {name}"));
    }
    let firmware = text(device, "firmware", &at)?;
    let synthetic = firmware == "synthetic";
    if firmware.is_empty() || synthetic != (kind == Kind::Synthetic) {
        return Err(format!("{at}: firmware {firmware:?}"));
    }
    let app = members(
        &device["app"],
        &format!("{at}.app"),
        &["name", "version"],
        &[],
    )?;
    let (app_name, app_version) = (text(app, "name", &at)?, text(app, "version", &at)?);
    if app_name != "Ethereum" {
        return Err(format!("{at}: app {app_name}"));
    }
    let b001 = bytes(text(device, "b001", &at)?, &at)?;
    if app_of(&b001) != Some((app_name.as_bytes(), app_version.as_bytes())) {
        return Err(format!("{at}: b001 isn't app's answer"));
    }
    if text(device, "mnemonicId", &at)? != "abandon-12" {
        return Err(format!("{at}: mnemonicId"));
    }
    let account = members(
        &device["account"],
        &format!("{at}.account"),
        &["path", "address"],
        &[],
    )?;
    let first = account_at(TEST_PATH).address;
    if text(account, "path", &at)? != TEST_PATH
        || address(&account["address"], &at)? != first
        || first != test_address()
    {
        return Err(format!("{at}: account isn't the test phrase's first"));
    }
    Ok(json!({ "model": model, "firmware": firmware, "app": device["app"] }))
}

/// `B0 01`'s answer: format 1, the app's name and version, then its flags.
fn app_of(answer: &[u8]) -> Option<(&[u8], &[u8])> {
    let (body, status) = answer.split_at(answer.len().checked_sub(2)?);
    if status != [0x90, 0x00] || body.first() != Some(&1) {
        return None;
    }
    let n = usize::from(*body.get(1)?);
    let m = usize::from(*body.get(2 + n)?);
    Some((body.get(2..2 + n)?, body.get(3 + n..3 + n + m)?))
}

/// The request in the core's wire form: ledger.json's, with `ledger.add`
/// as `{ scheme, index, name }` (the plan's point 9).
fn wire_request(source: &Value) -> Value {
    let request = &source["request"];
    if source["operation"] != "ledger.add" {
        return request.clone();
    }
    let path = LedgerPath::parse(request["path"].as_str().unwrap()).unwrap();
    json!({
        "scheme": path.scheme().as_str(),
        "index": path.index(),
        "name": request["name"],
    })
}

fn case(at: &str, value: &Value, device: &Value, session: &[SessionStep], held_ms: f64) -> R<Case> {
    let operation = value
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{at}: no operation"))?;
    let signs = match operation {
        "ledger.accounts" | "ledger.add" => false,
        "sign.transaction" | "sign.message" | "sign.typed_data" => true,
        other => return Err(format!("{at}: operation {other}")),
    };
    let mut required = vec![
        "id",
        "attempt",
        "from",
        "family",
        "operation",
        "request",
        "stream",
        "device",
        "hands",
        "exchanges",
        "outcome",
        "dropped",
    ];
    let named: &[&str] = if signs {
        &["signer", "record"]
    } else {
        &["address"]
    };
    required.extend_from_slice(named);
    let c = members(value, at, &required, &["hashes", "after"])?;
    let id = text(c, "id", at)?;
    if id.is_empty() {
        return Err(format!("{at}: id"));
    }
    let at = &format!("{at} ({id})");
    let attempt = uint(c, "attempt", at)?;
    if attempt == 0 {
        return Err(format!("{at}: attempt 0"));
    }
    let from = text(c, "from", at)?;
    let source = *vectors()
        .cases
        .get(from)
        .ok_or_else(|| format!("{at}: from {from} isn't a case of vectors/ledger.json"))?;
    let step = session
        .iter()
        .find(|step| step.0 == id)
        .ok_or_else(|| format!("{at}: not a step of this model's session"))?;
    let hands = text(c, "hands", at)?;
    if (from, text(c, "family", at)?, hands) != (step.1, step.2, step.3) {
        return Err(format!("{at}: from, family or hands isn't the step's"));
    }
    if source["operation"] != operation {
        return Err(format!("{at}: operation isn't ledger.json {from}'s"));
    }
    if c["request"] != wire_request(source) {
        return Err(format!(
            "{at}: request isn't ledger.json {from}'s in the core's wire form"
        ));
    }
    let record = if signs {
        if source.get("record") != Some(&c["record"]) {
            return Err(format!("{at}: record isn't ledger.json {from}'s"));
        }
        let r = members(&c["record"], at, &["path", "address"], &[])?;
        let path = LedgerPath::parse(text(r, "path", at)?).map_err(|e| format!("{at}: {e}"))?;
        let address = address(&r["address"], at)?;
        if address != test_address_at(&path) {
            return Err(format!("{at}: record isn't the test phrase's account"));
        }
        Some(Account { path, address })
    } else {
        if source.get("record").is_some() {
            return Err(format!("{at}: no record, where ledger.json {from} has one"));
        }
        None
    };
    let stream = match text(c, "stream", at)? {
        "core" => Stream::Core,
        "reference" => Stream::Reference,
        other => return Err(format!("{at}: stream {other}")),
    };
    // The reference's APDUs are recorded only for F-2's names, which the
    // core refuses.
    if (stream == Stream::Reference) != (source["deviation"] == "name-ascii") {
        return Err(format!("{at}: stream {stream:?} for ledger.json {from}"));
    }
    if c["device"] != *device {
        return Err(format!("{at}: device isn't the file's"));
    }
    let list = c["exchanges"]
        .as_array()
        .filter(|l| !l.is_empty())
        .ok_or_else(|| format!("{at}: exchanges isn't a list of exchanges"))?;
    let mut exchanges = Vec::new();
    for (k, value) in list.iter().enumerate() {
        let e = exchange(&format!("{at}: exchange {k}"), value, held_ms)?;
        // Only the last exchange ends the case.
        let goes_on = matches!(&e.end, End::Answer(a) if a.ends_with(&[0x90, 0x00])) || e.hash_only;
        if k + 1 < list.len() && !goes_on {
            return Err(format!("{at}: exchange {k} ends the case, but more follow"));
        }
        exchanges.push(e);
    }
    if stream == Stream::Reference && exchanges.iter().any(|e| e.hash_only) {
        return Err(format!("{at}: hash_only in a reference stream"));
    }
    let (outcome, as_asked) = outcome(
        &format!("{at}: outcome"),
        &c["outcome"],
        exchanges.last().unwrap(),
    )?;
    // The recorder's own judgement (`asAsked`), recomputed: a reference
    // stream is whole when it carries every APDU of ledger.json's case.
    let whole = stream == Stream::Core
        || Some(exchanges.len()) == source["exchanges"].as_array().map(Vec::len);
    let asked = match hands {
        "none" | "approve" | "reject-old" => outcome == Outcome::Status(0x9000) && whole,
        "reject" => matches!(outcome, Outcome::Status(0x6985 | 0x5501)),
        "refuse" => matches!(outcome, Outcome::Status(status) if status != 0x9000),
        "unplug" => outcome == Outcome::Failed(Failed::Disconnected),
        "leave" => outcome == Outcome::Cancelled,
        _ => true,
    };
    if as_asked != asked {
        return Err(format!("{at}: as_asked isn't what the hands asked for"));
    }
    let answered = optional_address(&c[if signs { "signer" } else { "address" }], at)?;
    let hashes = match c.get("hashes") {
        None => None,
        Some(value) => {
            let h = members(
                value,
                &format!("{at}: hashes"),
                &["domain", "message", "match"],
                &[],
            )?;
            Some((
                hash(text(h, "domain", at)?, at)?,
                hash(text(h, "message", at)?, at)?,
                flag(h, "match", at)?,
            ))
        }
    };
    if hashes.is_some() != exchanges.iter().any(|e| e.hash_only) {
        return Err(format!(
            "{at}: hashes only and always with the hash-only branch"
        ));
    }
    let after = match c.get("after") {
        None => None,
        Some(value) => {
            let a = members(value, &format!("{at}: after"), &["id", "attempt"], &[])?;
            Some((text(a, "id", at)?.to_owned(), uint(a, "attempt", at)?))
        }
    };
    if after.is_some() != (hands == "reject-old") {
        return Err(format!(
            "{at}: after only and always on the cancel case's new request"
        ));
    }
    uint(c, "dropped", at)?;
    Ok(Case {
        id: id.to_owned(),
        attempt,
        from: from.to_owned(),
        operation: operation.to_owned(),
        request: c["request"].clone(),
        record,
        stream,
        hands: hands.to_owned(),
        exchanges,
        outcome,
        as_asked,
        answered,
        hashes,
        after,
    })
}

fn exchange(at: &str, value: &Value, held_ms: f64) -> R<Exchange> {
    let e = members(
        value,
        at,
        &["apdu", "row", "deadline_ms", "at_ms", "ms"],
        &["answer", "failed", "cancelled", "held", "hash_only"],
    )?;
    let apdu = bytes(text(e, "apdu", at)?, at)?;
    if !(5..=260).contains(&apdu.len()) || usize::from(apdu[4]) != apdu.len() - 5 {
        return Err(format!(
            "{at}: an APDU outside 5 to 260 bytes, or whose Lc isn't its data's length"
        ));
    }
    let row = text(e, "row", at)?;
    let headers = vectors()
        .rows
        .get(row)
        .ok_or_else(|| format!("{at}: row {row} isn't the grammar's"))?;
    if !headers.contains(hex(&apdu[..4]).as_str()) {
        return Err(format!(
            "{at}: {} isn't an APDU of row {row}",
            hex(&apdu[..4])
        ));
    }
    let waits = match uint(e, "deadline_ms", at)? {
        USER_MS => true,
        DEVICE_MS => false,
        other => return Err(format!("{at}: deadline_ms {other}")),
    };
    let at_ms = millis(e, "at_ms", at)?;
    let ms = millis(e, "ms", at)?;
    let ends: Vec<&str> = ["answer", "failed", "cancelled"]
        .into_iter()
        .filter(|k| e.contains_key(*k))
        .collect();
    let end = match ends.as_slice() {
        ["answer"] => {
            let answer = bytes(text(e, "answer", at)?, at)?;
            if !(2..=260).contains(&answer.len()) {
                return Err(format!("{at}: an answer outside 2 to 260 bytes"));
            }
            End::Answer(answer)
        }
        ["failed"] => End::Failed(
            Failed::parse(text(e, "failed", at)?).ok_or_else(|| format!("{at}: failed"))?,
        ),
        ["cancelled"] if e["cancelled"] == Value::Bool(true) => End::Cancelled,
        _ => {
            return Err(format!(
                "{at}: not one of answer, failed and cancelled: true"
            ));
        }
    };
    // Measured (R2) on every answered APDU that doesn't wait for the user.
    let measured = !waits && matches!(end, End::Answer(_));
    let held = match (measured, e.get("held")) {
        (true, Some(Value::Bool(held))) if *held == (ms >= held_ms) => Some(*held),
        (false, None) => None,
        _ => return Err(format!("{at}: held")),
    };
    let hash_only = match e.get("hash_only") {
        None => false,
        Some(Value::String(shown))
            if shown == "shown"
                && end == End::Answer(vec![0x6d, 0x00])
                && apdu[..4] == [0xe0, 0x1a, 0x00, 0x00] =>
        {
            true
        }
        Some(_) => return Err(format!("{at}: hash_only on another answer")),
    };
    Ok(Exchange {
        apdu,
        waits,
        end,
        hash_only,
        at_ms,
        ms,
        held,
    })
}

/// `outcome`, and its `as_asked`.
fn outcome(at: &str, value: &Value, last: &Exchange) -> R<(Outcome, bool)> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{at}: not an object"))?;
    let key = ["status", "failed", "cancelled"]
        .into_iter()
        .find(|k| object.contains_key(*k))
        .ok_or_else(|| format!("{at}: no status, failed or cancelled"))?;
    let o = members(value, at, &[key, "as_asked"], &[])?;
    let as_asked = flag(o, "as_asked", at)?;
    let outcome = match key {
        "status" => {
            let status = bytes(text(o, "status", at)?, at)?;
            let status: [u8; 2] = status
                .try_into()
                .map_err(|_| format!("{at}: status isn't a status word"))?;
            Outcome::Status(u16::from_be_bytes(status))
        }
        "failed" => Outcome::Failed(
            Failed::parse(text(o, "failed", at)?).ok_or_else(|| format!("{at}: failed"))?,
        ),
        _ if o["cancelled"] == Value::Bool(true) => Outcome::Cancelled,
        _ => return Err(format!("{at}: cancelled")),
    };
    let ended = match &last.end {
        End::Answer(a) => Outcome::Status(u16::from_be_bytes([a[a.len() - 2], a[a.len() - 1]])),
        End::Failed(failed) => Outcome::Failed(*failed),
        End::Cancelled => Outcome::Cancelled,
    };
    if outcome != ended {
        return Err(format!("{at}: not the last exchange's end"));
    }
    Ok((outcome, as_asked))
}

/// `stats` in scripts/ledger-record.js.
fn stats(values: &[f64]) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("apdus".into(), json!(values.len()));
    if values.is_empty() {
        return out;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let pick = |q: f64| sorted[((q * sorted.len() as f64).floor() as usize).min(sorted.len() - 1)];
    out.insert("median_ms".into(), json!(pick(0.5)));
    out.insert("p90_ms".into(), json!(pick(0.9)));
    out.insert("max_ms".into(), json!(sorted[sorted.len() - 1]));
    out
}

/// The exchanges `timing` and `held` count: answered, not waiting for the
/// user.
fn device_exchanges<'a>(cases: impl Iterator<Item = &'a Case>) -> Vec<&'a Exchange> {
    cases
        .flat_map(|c| &c.exchanges)
        .filter(|e| !e.waits && matches!(e.end, End::Answer(_)))
        .collect()
}

/// `timing` (R3), as the recorder computes it from the cases.
fn timing(file: &str, value: &Value, cases: &[Case]) -> R<()> {
    let quick: Vec<&Exchange> = device_exchanges(cases.iter())
        .into_iter()
        .filter(|e| e.held == Some(false))
        .collect();
    let mut by_ins: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for e in &quick {
        by_ins.entry(hex(&e.apdu[..2])).or_default().push(e.ms);
    }
    let all = stats(&quick.iter().map(|e| e.ms).collect::<Vec<_>>());
    let mut expected = all.clone();
    expected.insert(
        "by_ins".into(),
        Value::Object(
            by_ins
                .into_iter()
                .map(|(ins, ms)| (ins, Value::Object(stats(&ms))))
                .collect(),
        ),
    );
    expected.insert("bound".into(), json!(2048));
    let bound = match (all.get("median_ms"), all.get("p90_ms")) {
        (Some(median), Some(p90)) => {
            let at = |ms: &Value| (ms.as_f64().unwrap() * APDUS_PER_OPERATION / 1000.0).round();
            json!({ "median": at(median), "p90": at(p90) })
        }
        _ => Value::Null,
    };
    expected.insert("bound_s".into(), bound);
    if !same(value, &Value::Object(expected)) {
        return Err(format!("{file}: timing isn't the cases'"));
    }
    Ok(())
}

/// `held` (R2), as the recorder computes it from the approved cases.
fn held(file: &str, value: &Value, cases: &[Case], held_ms: f64) -> R<()> {
    let approved: Vec<&Case> = cases.iter().filter(|c| c.hands == "approve").collect();
    let rows = device_exchanges(approved.iter().copied());
    let mut by_ins: BTreeMap<String, (usize, usize, f64)> = BTreeMap::new();
    for e in &rows {
        let entry = by_ins.entry(hex(&e.apdu[..2])).or_insert((0, 0, 0.0));
        entry.0 += 1;
        entry.1 += usize::from(e.held == Some(true));
        entry.2 = entry.2.max(e.ms);
    }
    let mut steps: Vec<&str> = Vec::new();
    for c in &approved {
        if c.exchanges.iter().any(|e| e.held == Some(true)) && !steps.contains(&c.id.as_str()) {
            steps.push(&c.id);
        }
    }
    let expected = json!({
        "threshold_ms": held_ms,
        "apdus": rows.len(),
        "held": rows.iter().filter(|e| e.held == Some(true)).count(),
        "by_ins": by_ins
            .into_iter()
            .map(|(ins, (apdus, held, slowest))| {
                (ins, json!({ "apdus": apdus, "held": held, "slowest_ms": slowest }))
            })
            .collect::<Map<String, Value>>(),
        "steps": steps,
    });
    if !same(value, &expected) {
        return Err(format!("{file}: held isn't the cases'"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The replay

/// What a case's end is checked against: the core's own reading of its
/// request.
enum Expect {
    Accounts {
        scheme: Scheme,
        start: u64,
        count: u64,
    },
    Add(LedgerPath),
    Transaction {
        digest: [u8; 32],
        /// A legacy transaction's chain ID's first four bytes.
        legacy: Option<u64>,
    },
    Message([u8; 32]),
    Typed {
        hash: [u8; 32],
        domain: [u8; 32],
        message: [u8; 32],
    },
}

/// The chain ID's first four bytes, which the app keeps for a legacy `v`.
fn chain_prime(chain_id: &U256) -> u64 {
    chain_id
        .to_minimal_be()
        .iter()
        .take(4)
        .fold(0, |acc, byte| (acc << 8) | u64::from(*byte))
}

/// The core's operation for a case's request, read as the core's wire
/// readers read it (freedom-cored's ledger/methods.rs and signing.rs), with
/// the digest the core computes; or why the core refuses it.
fn build(case: &Case) -> R<(Operation, Expect)> {
    let request = &case.request;
    let at = "request";
    let refused = |e: &dyn std::fmt::Display| format!("refused: {e}");
    let record = || case.record.clone().ok_or("no record");
    match case.operation.as_str() {
        "ledger.accounts" => {
            let r = members(request, at, &["scheme", "start", "count"], &[])?;
            let scheme =
                Scheme::parse(text(r, "scheme", at)?).ok_or("a scheme the core doesn't read")?;
            let (start, count) = (uint(r, "start", at)?, uint(r, "count", at)?);
            // Discovery checks the records main lists: the recorder lists none.
            let operation = Operation::accounts(scheme, start, count)
                .and_then(|op| op.checking(Vec::new()))
                .map_err(|e| refused(&e))?;
            Ok((
                operation,
                Expect::Accounts {
                    scheme,
                    start,
                    count,
                },
            ))
        }
        "ledger.add" => {
            let r = members(request, at, &["scheme", "index"], &["name"])?;
            if r.get("name").is_some_and(|name| !name.is_string()) {
                return Err("name isn't a string".into());
            }
            let scheme =
                Scheme::parse(text(r, "scheme", at)?).ok_or("a scheme the core doesn't read")?;
            let path = LedgerPath::new(scheme, uint(r, "index", at)?).map_err(|e| refused(&e))?;
            Ok((Operation::add(path.clone()), Expect::Add(path)))
        }
        "sign.transaction" => {
            let r = members(request, at, &["tx"], &[])?;
            let tx = Transaction::from_json(&r["tx"]).map_err(|e| refused(&e))?;
            let digest = tx.prepare().map_err(|e| refused(&e))?.digest();
            let legacy = (tx.tx_type() == 0).then(|| chain_prime(tx.chain_id()));
            let operation = Operation::sign_transaction(record()?, &tx).map_err(|e| refused(&e))?;
            Ok((operation, Expect::Transaction { digest, legacy }))
        }
        "sign.message" => {
            let r = members(request, at, &["message"], &[])?;
            let message =
                parse_bytes(text(r, "message", at)?, "message").map_err(|e| refused(&e))?;
            let digest = eip191_digest(&message);
            let operation = Operation::sign_message(record()?, message).map_err(|e| refused(&e))?;
            Ok((operation, Expect::Message(digest)))
        }
        "sign.typed_data" => {
            let r = members(request, at, &["typed_data", "expected_hash"], &[])?;
            let expected: [u8; 32] = parse_bytes(text(r, "expected_hash", at)?, "expected_hash")
                .map_err(|e| refused(&e))?
                .try_into()
                .map_err(|_| "expected_hash isn't 32 bytes")?;
            let t = members(
                &r["typed_data"],
                "typed_data",
                &["domain", "types", "message"],
                &[],
            )?;
            let parsed = typed_data_parse(&t["domain"], &t["types"], &t["message"])
                .map_err(|e| refused(&e))?;
            if parsed.hash != expected {
                return Err("refused: the typed data doesn't hash to expected_hash".into());
            }
            let operation = Operation::sign_typed_data(
                record()?,
                &t["domain"],
                &t["types"],
                &t["message"],
                &parsed.hash,
            )
            .map_err(|e| refused(&e))?;
            Ok((
                operation,
                Expect::Typed {
                    hash: parsed.hash,
                    domain: parsed.domain_separator,
                    message: parsed.struct_hash,
                },
            ))
        }
        other => Err(format!("operation {other}")),
    }
}

fn describe(outcome: Outcome) -> String {
    match outcome {
        Outcome::Status(status) => format!("status {status:04x}"),
        Outcome::Failed(failed) => format!("failed {}", failed.as_str()),
        Outcome::Cancelled => "cancelled".into(),
    }
}

/// Replays one case; its end's name for the tally.
fn replay(case: &Case) -> R<String> {
    let at = format!("{} #{}", case.id, case.attempt);
    let built = build(case);
    if case.stream == Stream::Reference {
        return reference(case, &at, built.is_ok());
    }
    let (mut op, expect) = built.map_err(|e| format!("{at}: the core's request: {e}"))?;
    let mut step = op.start();
    for (k, ex) in case.exchanges.iter().enumerate() {
        let Step::Send(exchange) = step else {
            return Err(format!(
                "{at}: exchange {k}: the core had ended, so {} is an APDU it doesn't send",
                hex(&ex.apdu)
            ));
        };
        if exchange.apdu.as_bytes() != ex.apdu.as_slice() {
            return Err(format!(
                "{at}: exchange {k}: the core sends {}, the recording {}",
                hex(exchange.apdu.as_bytes()),
                hex(&ex.apdu)
            ));
        }
        if exchange.confirm != ex.waits {
            return Err(format!(
                "{at}: exchange {k}: deadline_ms isn't the core's for {}",
                hex(&ex.apdu)
            ));
        }
        step = match &ex.end {
            End::Answer(answer) => op.answer(Reply::Answer {
                answer,
                hash_only_shown: ex.hash_only,
            }),
            End::Failed(failed) => op.answer(Reply::Failed(*failed)),
            // The parent's cancel: the core is waiting for this APDU's
            // answer when its parent ends, and sends nothing more.
            End::Cancelled => {
                if case.answered.is_some() {
                    return Err(format!("{at}: a cancelled case with a signer"));
                }
                return Ok("cancelled".into());
            }
        };
    }
    let Step::Done(done) = step else {
        return Err(format!(
            "{at}: the core sends another APDU after the last recorded: the case is cut short"
        ));
    };
    match (case.outcome, done) {
        (Outcome::Status(0x9000), Ok(signed)) => signed_end(case, &at, &expect, signed),
        (Outcome::Status(status), Err(failure))
            if status != 0x9000
                && failure.code == LedgerCode::for_status(status)
                && failure.cause == Cause::Status(status) =>
        {
            unsigned_end(case, &at, Outcome::Status(status))
        }
        (Outcome::Failed(failed), Err(failure))
            if failure.code == failed.code() && failure.cause == Cause::Failed(failed) =>
        {
            unsigned_end(case, &at, Outcome::Failed(failed))
        }
        (outcome, Err(failure)) => Err(format!(
            "{at}: the core ends {failure} where the recording's outcome is {}",
            describe(outcome)
        )),
        (outcome, Ok(_)) => Err(format!(
            "{at}: the core succeeds where the recording's outcome is {}",
            describe(outcome)
        )),
    }
}

fn unsigned_end(case: &Case, at: &str, outcome: Outcome) -> R<String> {
    if case.answered.is_some() {
        return Err(format!(
            "{at}: a signer or an address for {}",
            describe(outcome)
        ));
    }
    Ok(describe(outcome))
}

/// The address a signature recovers to, or why none does.
fn recovered(digest: &[u8; 32], signature: &[u8; 65], at: &str) -> R<[u8; 20]> {
    recover_address(digest, signature).map_err(|e| format!("{at}: no signer recovers: {e}"))
}

/// A signature's signer: the record's account, the test phrase's, and the
/// case's `signer`.
fn check_signer(case: &Case, at: &str, signer: [u8; 20]) -> R<()> {
    let record = case
        .record
        .as_ref()
        .ok_or_else(|| format!("{at}: no record"))?;
    if signer != record.address {
        return Err(format!(
            "{at}: the signature recovers to {}, not the record's {}",
            checksum_address(&signer),
            checksum_address(&record.address)
        ));
    }
    if case.answered != Some(signer) {
        return Err(format!(
            "{at}: signer isn't {}, which the signature recovers to over the core's digest",
            checksum_address(&signer)
        ));
    }
    Ok(())
}

fn signed_end(case: &Case, at: &str, expect: &Expect, signed: Signed) -> R<String> {
    let End::Answer(last) = &case.exchanges.last().unwrap().end else {
        return Err(format!("{at}: no answer"));
    };
    match (expect, signed) {
        (
            Expect::Accounts {
                scheme,
                start,
                count,
            },
            Signed::Accounts(found),
        ) => {
            if found.accounts.len() as u64 != *count {
                return Err(format!("{at}: {} accounts", found.accounts.len()));
            }
            for (k, account) in found.accounts.iter().enumerate() {
                let path = LedgerPath::new(*scheme, start + k as u64).unwrap();
                if account.path != path || account.address != test_address_at(&path) {
                    return Err(format!("{at}: account {k} isn't the test phrase's"));
                }
            }
            if found.checks != Ok(Vec::new()) {
                return Err(format!("{at}: records checked that no one listed"));
            }
            if case.answered != found.accounts.last().map(|a| a.address) {
                return Err(format!("{at}: address isn't the device's last answer"));
            }
            Ok("accounts".into())
        }
        (Expect::Add(path), Signed::Added(account)) => {
            if account.path != *path || account.address != test_address_at(path) {
                return Err(format!("{at}: the added account isn't the test phrase's"));
            }
            if case.answered != Some(account.address) {
                return Err(format!("{at}: address isn't the device's answer"));
            }
            Ok("added".into())
        }
        (Expect::Transaction { digest, legacy }, Signed::Transaction(tx)) => {
            let decoded = decode_signed(&tx.raw).map_err(|e| format!("{at}: {e}"))?;
            if decoded.digest() != digest {
                return Err(format!(
                    "{at}: the signed transaction's digest isn't the core's"
                ));
            }
            // The device's r and s, and its v for the parity signed.
            if decoded.r()[..] != last[1..33] || decoded.s()[..] != last[33..65] {
                return Err(format!(
                    "{at}: the signed transaction's r and s aren't the device's"
                ));
            }
            let parity = decoded.y_parity();
            let v = match legacy {
                None => parity,
                Some(prime) => ((prime * 2 + 35 + u64::from(parity)) % 256) as u8,
            };
            if last[0] != v {
                return Err(format!("{at}: the device's v isn't the signed parity's"));
            }
            let mut signature = [0u8; 65];
            signature[..64].copy_from_slice(&last[1..65]);
            signature[64] = 27 + parity;
            check_signer(case, at, recovered(digest, &signature, at)?)?;
            Ok("signed".into())
        }
        (Expect::Message(digest), Signed::Signature(signature))
        | (Expect::Typed { hash: digest, .. }, Signed::Signature(signature)) => {
            // The core's r ‖ s ‖ v is the device's v ‖ r ‖ s.
            if signature[..64] != last[1..65] || signature[64] != last[0] {
                return Err(format!("{at}: the core's signature isn't the device's"));
            }
            check_signer(case, at, recovered(digest, &signature, at)?)?;
            if let (
                Expect::Typed {
                    domain, message, ..
                },
                Some((shown_domain, shown_message, matched)),
            ) = (expect, case.hashes)
            {
                // The warning's two hashes are the core's, which its
                // hash-only APDU carried and the device signed over.
                if (shown_domain, shown_message) != (*domain, *message) {
                    return Err(format!("{at}: hashes aren't the core's"));
                }
                if !matched {
                    return Err(format!(
                        "{at}: the user saw other hashes on the device (hashes.match false)"
                    ));
                }
                return Ok("hash-only".into());
            }
            Ok("signed".into())
        }
        (_, signed) => Err(format!("{at}: a result of another operation, {signed:?}")),
    }
}

/// A reference stream: read, never replayed. The core refuses its request
/// before any APDU, and its APDUs are ledger.json's reference ones, in
/// order. It stops short of them only where the device ended it, with a
/// status other than `9000` or a failure; one the device signed is whole,
/// its signature by the record's account (the test phrase's) over
/// `expected_hash`, and its `signer` that account.
fn reference(case: &Case, at: &str, core_signs: bool) -> R<String> {
    if core_signs {
        return Err(format!(
            "{at}: a reference stream for a request the core signs"
        ));
    }
    let source = vectors().cases[case.from.as_str()];
    let theirs: Vec<&str> = source["exchanges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["apdu"].as_str().unwrap())
        .collect();
    let ours: Vec<String> = case.exchanges.iter().map(|e| hex(&e.apdu)).collect();
    if ours.len() > theirs.len() || ours.iter().zip(&theirs).any(|(a, b)| a != b) {
        return Err(format!(
            "{at}: not ledger.json {}'s reference APDUs",
            case.from
        ));
    }
    let answer = match &case.exchanges.last().unwrap().end {
        End::Answer(answer) if answer.ends_with(&[0x90, 0x00]) => answer,
        // The device ended it: no signature.
        _ => {
            if case.answered.is_some() {
                return Err(format!("{at}: a signer without a signature"));
            }
            return Ok("reference".into());
        }
    };
    if ours.len() != theirs.len() {
        return Err(format!(
            "{at}: a reference stream cut short of its signature"
        ));
    }
    if answer.len() != 67 || !matches!(answer[0], 27 | 28) {
        return Err(format!("{at}: the last answer isn't a signature"));
    }
    let expected = hash(case.request["expected_hash"].as_str().unwrap(), at)?;
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&answer[1..65]);
    signature[64] = answer[0];
    // A high s, or a signature no key recovers, fails here too.
    check_signer(case, at, recovered(&expected, &signature, at)?)?;
    Ok("reference".into())
}

fn replay_recording(recording: &Recording) -> R<Tally> {
    let honest = &vectors().honest;
    let mut tally = Tally {
        file: recording.file.clone(),
        ..Tally::default()
    };
    for case in &recording.cases {
        let end = replay(case).map_err(|e| format!("{}: {e}", recording.file))?;
        if case.stream == Stream::Reference {
            tally.reference += 1;
        } else {
            tally.core += 1;
            *tally.ends.entry(end).or_default() += 1;
            // ledger-grammar.json's honest stream, as far as the case went,
            // where the device took the branch ledger.json's did.
            if let Some(stream) = honest.get(case.from.as_str()) {
                let ours: Vec<String> = case.exchanges.iter().map(|e| hex(&e.apdu)).collect();
                let ours: Vec<&str> = ours.iter().map(String::as_str).collect();
                if takes_hash_only(&ours) == takes_hash_only(stream) && !stream.starts_with(&ours) {
                    return Err(format!(
                        "{}: {} #{}: not ledger-grammar.json's honest stream",
                        recording.file, case.id, case.attempt
                    ));
                }
            }
        }
        tally.late += case
            .exchanges
            .iter()
            .filter(|e| {
                matches!(e.end, End::Answer(_))
                    && e.ms > if e.waits { USER_MS } else { DEVICE_MS } as f64
            })
            .count();
    }
    Ok(tally)
}

/// Whether a stream takes the hash-only branch.
fn takes_hash_only(apdus: &[&str]) -> bool {
    apdus.iter().any(|a| a.starts_with("e00c0000"))
}

/// One file read and replayed.
fn verdict(file: &str, value: &Value, kind: Kind) -> R<Tally> {
    replay_recording(&parse(file, value, kind)?)
}

/// Every file of a directory, by name.
fn read_dir(dir: &Path) -> R<Vec<(String, Value)>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "a file name that isn't UTF-8".to_owned())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_file() {
            return Err(format!("{name}: not a file"));
        }
        let text = std::fs::read_to_string(entry.path()).map_err(|e| format!("{name}: {e}"))?;
        let value = serde_json::from_str(&text).map_err(|e| format!("{name}: {e}"))?;
        files.push((name, value));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

/// The user's recordings: none while the directory is missing or empty.
fn device_files(dir: &Path) -> R<Vec<(String, Value)>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    read_dir(dir)
}

fn synthetic_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/ledger-devices-synthetic")
}

/// Where the user's recordings go (the plan's §5).
fn devices_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/ledger-devices")
}

fn report(tally: &Tally) {
    eprintln!(
        "{}: {} core cases replayed {:?}, {} reference cases read; {} answers after the core's deadline_ms (R2)",
        tally.file, tally.core, tally.ends, tally.reference, tally.late
    );
}

// ---------------------------------------------------------------------------
// The replays

#[test]
fn synthetic_recordings_replay() {
    let files = read_dir(&synthetic_dir()).unwrap();
    assert!(!files.is_empty(), "no synthetic recording");
    let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        ["ledger-devices-nanoS.json", "ledger-devices-nanoSP.json"]
    );
    let tallies: Vec<Tally> = files
        .iter()
        .map(|(name, value)| {
            verdict(name, value, Kind::Synthetic).unwrap_or_else(|e| panic!("{e}"))
        })
        .collect();
    tallies.iter().for_each(report);
    let ends = |pairs: &[(&str, usize)]| {
        pairs
            .iter()
            .map(|(end, n)| ((*end).to_owned(), *n))
            .collect::<BTreeMap<_, _>>()
    };
    // A Nano S: discovery and the two hash-only signatures.
    assert_eq!(tallies[0].core, 3);
    assert_eq!(tallies[0].reference, 0);
    assert_eq!(tallies[0].ends, ends(&[("accounts", 1), ("hash-only", 2)]));
    // A Nano S Plus: every field step of the session, and the four
    // reference streams of F-2's names.
    assert_eq!(tallies[1].core, 16);
    assert_eq!(tallies[1].reference, 4);
    assert_eq!(
        tallies[1].ends,
        ends(&[
            ("accounts", 1),
            ("added", 1),
            ("signed", 10),
            ("status 6985", 1),
            ("status 6a80", 1),
            ("failed disconnected", 1),
            ("cancelled", 1),
        ])
    );
}

/// The user's recordings, once they land in vectors/ledger-devices/. Before
/// the device session there are none, which isn't an error; from then on
/// every file there is replayed, and a synthetic one among them fails.
#[test]
fn device_recordings_replay() {
    let dir = devices_dir();
    let files = device_files(&dir).unwrap_or_else(|e| panic!("{e}"));
    if files.is_empty() {
        eprintln!(
            "{}: no device recordings yet (the LDG-3 device session); only the synthetic ones are replayed",
            dir.display()
        );
        return;
    }
    for (name, value) in &files {
        let tally = verdict(name, value, Kind::Device).unwrap_or_else(|e| panic!("{e}"));
        report(&tally);
    }
}

/// A missing and an empty directory both hold no recording yet.
#[test]
fn no_device_recordings_yet_is_a_missing_or_empty_directory() {
    let empty = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ledger-devices-empty-{}", std::process::id()));
    std::fs::create_dir_all(&empty).unwrap();
    assert!(device_files(&empty).unwrap().is_empty());
    std::fs::remove_dir(&empty).unwrap();
    assert!(device_files(&empty).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Damage: each makes the replay fail

fn fixture(model: &str) -> (String, Value) {
    let name = format!("ledger-devices-{model}.json");
    let text = std::fs::read_to_string(synthetic_dir().join(&name)).unwrap();
    (name, serde_json::from_str(&text).unwrap())
}

fn parsed(model: &str) -> Recording {
    let (name, value) = fixture(model);
    parse(&name, &value, Kind::Synthetic).unwrap()
}

fn case_mut<'a>(value: &'a mut Value, id: &str) -> &'a mut Value {
    value["cases"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|c| c["id"] == id)
        .unwrap()
}

fn fails(result: R<Tally>, words: &str) {
    match result {
        Ok(_) => panic!("replayed, where {words:?} should fail it"),
        Err(e) => assert!(e.contains(words), "{e:?} doesn't say {words:?}"),
    }
}

#[test]
fn a_flipped_apdu_byte_fails() {
    // Each data byte's flip at each exchange of each core case.
    let mut flips = 0;
    for model in ["nanoSP", "nanoS"] {
        for case in parsed(model)
            .cases
            .iter()
            .filter(|c| c.stream == Stream::Core)
        {
            for k in 0..case.exchanges.len() {
                let mut damaged = case.clone();
                let apdu = &mut damaged.exchanges[k].apdu;
                // Its last data byte; B0 01 has none, so its INS.
                let at = if apdu.len() > 5 { apdu.len() - 1 } else { 1 };
                apdu[at] ^= 0x01;
                let e = replay(&damaged).unwrap_err();
                assert!(e.contains(&format!("exchange {k}: the core sends")), "{e}");
                flips += 1;
            }
        }
    }
    assert_eq!(flips, 149);
    // And in the file.
    let (name, mut value) = fixture("nanoSP");
    let apdu = &mut case_mut(&mut value, "typed-mail")["exchanges"][7]["apdu"];
    let mut text = apdu.as_str().unwrap().to_owned();
    let flipped = if text.ends_with('0') { '1' } else { '0' };
    text.pop();
    text.push(flipped);
    *apdu = Value::String(text);
    fails(
        verdict(&name, &value, Kind::Synthetic),
        "exchange 7: the core sends",
    );
}

/// A signature by another key over the core's own digest: v ‖ r ‖ s.
fn other_signature(case: &Case) -> Vec<u8> {
    let (_, expect) = build(case).unwrap();
    let (digest, legacy) = match expect {
        Expect::Transaction { digest, legacy } => (digest, legacy),
        Expect::Message(digest) | Expect::Typed { hash: digest, .. } => (digest, None),
        _ => unreachable!(),
    };
    let signature = sign_digest(other_key().signing_key(), &digest).unwrap();
    let parity = signature[64] - 27;
    let v = match (case.operation.as_str(), legacy) {
        ("sign.transaction", None) => parity,
        ("sign.transaction", Some(prime)) => ((prime * 2 + 35 + u64::from(parity)) % 256) as u8,
        _ => 27 + parity,
    };
    let mut answer = vec![v];
    answer.extend_from_slice(&signature[..64]);
    answer.extend_from_slice(&[0x90, 0x00]);
    answer
}

#[test]
fn a_signature_from_another_key_fails() {
    let other = *other_key().address().as_bytes();
    let mut signed = 0;
    for model in ["nanoSP", "nanoS"] {
        for case in parsed(model).cases.iter().filter(|c| {
            c.stream == Stream::Core
                && c.operation.starts_with("sign.")
                && c.outcome == Outcome::Status(0x9000)
        }) {
            let mut damaged = case.clone();
            let answer = other_signature(case);
            damaged.exchanges.last_mut().unwrap().end = End::Answer(answer);
            damaged.answered = Some(other);
            let e = replay(&damaged).unwrap_err();
            assert!(e.contains("LEDGER_BAD_SIGNATURE"), "{e}");
            signed += 1;
        }
    }
    assert_eq!(signed, 12);
    // And in the file, its signer the other key's.
    let (name, mut value) = fixture("nanoSP");
    let case = parsed("nanoSP")
        .cases
        .into_iter()
        .find(|c| c.id == "message")
        .unwrap();
    let kase = case_mut(&mut value, "message");
    let last = kase["exchanges"].as_array().unwrap().len() - 1;
    kase["exchanges"][last]["answer"] = Value::String(hex(&other_signature(&case)));
    kase["signer"] = Value::String(checksum_address(&other));
    fails(
        verdict(&name, &value, Kind::Synthetic),
        "LEDGER_BAD_SIGNATURE",
    );
}

#[test]
fn a_recorded_apdu_the_core_doesnt_send_fails() {
    let recording = parsed("nanoSP");
    let mail = recording
        .cases
        .iter()
        .find(|c| c.id == "typed-mail")
        .unwrap();
    // A piece sent twice.
    let mut damaged = mail.clone();
    damaged.exchanges.insert(4, mail.exchanges[3].clone());
    let e = replay(&damaged).unwrap_err();
    assert!(e.contains("exchange 4: the core sends"), "{e}");
    // An APDU after the core's end: B0 01 again once it signed.
    let mut damaged = mail.clone();
    damaged.exchanges.push(mail.exchanges[1].clone());
    let e = replay(&damaged).unwrap_err();
    assert!(e.contains("the core had ended"), "{e}");
    // An APDU the core never sends for a message: the device's display.
    let message = recording.cases.iter().find(|c| c.id == "message").unwrap();
    let mut damaged = message.clone();
    damaged.exchanges[0].apdu[2] = 0x01;
    let e = replay(&damaged).unwrap_err();
    assert!(e.contains("exchange 0: the core sends"), "{e}");
    // And in the file: the signing APDU again once the core signed.
    let (name, mut value) = fixture("nanoSP");
    let exchanges = case_mut(&mut value, "typed-mail")["exchanges"]
        .as_array_mut()
        .unwrap();
    exchanges.push(exchanges.last().unwrap().clone());
    fails(
        verdict(&name, &value, Kind::Synthetic),
        "the core had ended",
    );
}

#[test]
fn a_truncated_case_fails() {
    let mut cut = 0;
    for model in ["nanoSP", "nanoS"] {
        for case in parsed(model)
            .cases
            .iter()
            .filter(|c| c.stream == Stream::Core && c.exchanges.len() > 1)
        {
            let mut damaged = case.clone();
            damaged.exchanges.pop();
            let e = replay(&damaged).unwrap_err();
            assert!(e.contains("cut short"), "{e}");
            cut += 1;
        }
    }
    assert_eq!(cut, 16);
    // And in the file: the Mail without its signature, its last answer a 9000.
    let (name, mut value) = fixture("nanoSP");
    let mail = case_mut(&mut value, "typed-mail");
    mail["exchanges"].as_array_mut().unwrap().pop();
    mail["signer"] = Value::Null;
    fails(verdict(&name, &value, Kind::Synthetic), "cut short");
    // A file cut off mid-way isn't JSON.
    let text = std::fs::read_to_string(synthetic_dir().join(&name)).unwrap();
    assert!(serde_json::from_str::<Value>(&text[..text.len() / 2]).is_err());
}

#[test]
fn every_file_is_read_strictly() {
    let (name, value) = fixture("nanoSP");
    verdict(&name, &value, Kind::Synthetic).unwrap();
    let message = value["cases"]
        .as_array()
        .unwrap()
        .iter()
        .position(|c| c["id"] == "message")
        .unwrap();
    let case = format!("/cases/{message}");
    let exchange = |k: usize| format!("{case}/exchanges/{k}");
    let read = |damage: &dyn Fn(&mut Value), words: &str| {
        let mut damaged = value.clone();
        damage(&mut damaged);
        fails(verdict(&name, &damaged, Kind::Synthetic), words);
    };
    // An unknown member at each level.
    for (at, key, words) in [
        ("", "extra", "an unknown member, extra"),
        ("/meta", "extra", "an unknown member, extra"),
        ("/device", "serial", "an unknown member, serial"),
        (&case, "note", "an unknown member, note"),
        (&exchange(0), "note", "an unknown member, note"),
        (
            &format!("{case}/outcome"),
            "note",
            "an unknown member, note",
        ),
        (&exchange(1), "hash_only", "hash_only on another answer"),
    ] {
        read(
            &|v| {
                let object = v.pointer_mut(at).unwrap().as_object_mut().unwrap();
                object.insert(key.into(), json!("shown"));
            },
            words,
        );
    }
    // A member left out at each level.
    for (at, key) in [
        ("", "held"),
        ("/meta", "heldMs"),
        ("/meta", "synthetic"),
        ("/device", "b001"),
        (&case, "dropped"),
        (&case, "signer"),
        (&exchange(1), "row"),
    ] {
        read(
            &|v| {
                v.pointer_mut(at)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(key);
            },
            &format!("no {key}"),
        );
    }
    // A member with another value.
    for (at, changed, words) in [
        ("/device/model", json!("nanoZ"), "model nanoZ"),
        ("/device/name", json!("Nano X"), "name isn't"),
        ("/formats/hands", json!("approve"), "formats"),
        (
            &format!("{case}/device/firmware"),
            json!("2.4.1"),
            "device isn't the file's",
        ),
        (
            &format!("{case}/request/message"),
            json!("0x00"),
            "request isn't ledger.json",
        ),
        (
            &format!("{}/row", exchange(1)),
            json!("ledger.add"),
            "isn't an APDU of row",
        ),
        (&format!("{}/held", exchange(1)), json!(true), "held"),
        ("/timing/apdus", json!(1), "timing isn't the cases'"),
    ] {
        read(&|v| *v.pointer_mut(at).unwrap() = changed.clone(), words);
    }
    // Another model's file name.
    fails(
        verdict("ledger-devices-nanoX.json", &value, Kind::Synthetic),
        "model nanoSP, in nanoX's file",
    );
    fails(
        verdict("ledger-devices-nanoZ.json", &value, Kind::Synthetic),
        "a model the recorder names",
    );
    // A synthetic recording among the device recordings.
    fails(verdict(&name, &value, Kind::Device), "synthetic");
}

/// The synthetic Nano S Plus as the device session writes a file: no
/// synthetic mark, run under Electron, the firmware the user read. It is
/// read as device evidence and replayed; each synthetic mark fails it.
#[test]
fn the_device_form_is_read_and_replayed() {
    let (name, value) = device_form("nanoSP");
    let tally = verdict(&name, &value, Kind::Device).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((tally.core, tally.reference), (16, 4));
    let mut damaged = value.clone();
    set_firmware(&mut damaged, "synthetic");
    fails(verdict(&name, &damaged, Kind::Device), "firmware");
    let mut damaged = value.clone();
    damaged["meta"]["host"]["electron"] = Value::Null;
    fails(verdict(&name, &damaged, Kind::Device), "host.electron");
    // And the device form isn't a synthetic recording.
    fails(verdict(&name, &value, Kind::Synthetic), "no synthetic");
}

fn set_firmware(value: &mut Value, firmware: &str) {
    value["device"]["firmware"] = json!(firmware);
    for case in value["cases"].as_array_mut().unwrap() {
        case["device"]["firmware"] = json!(firmware);
    }
}

/// A synthetic recording as the device session writes a file: no synthetic
/// mark, run under Electron, the firmware the user read.
fn device_form(model: &str) -> (String, Value) {
    let (name, mut value) = fixture(model);
    value["meta"].as_object_mut().unwrap().remove("synthetic");
    value["meta"]["host"]["electron"] = json!("39.2.7");
    set_firmware(&mut value, "1.3.0");
    (name, value)
}

fn remove_case(value: &mut Value, id: &str) {
    value["cases"]
        .as_array_mut()
        .unwrap()
        .retain(|c| c["id"] != id);
}

/// A device file holds the whole session its model's steps define.
#[test]
fn a_device_file_holds_the_whole_session() {
    for model in ["nanoSP", "nanoS"] {
        let (name, value) = device_form(model);
        verdict(&name, &value, Kind::Device).unwrap_or_else(|e| panic!("{e}"));
        // An unfinished session, as the recorder writes it after each step.
        let mut damaged = value.clone();
        damaged["meta"]["complete"] = json!(false);
        fails(
            verdict(&name, &damaged, Kind::Device),
            "complete is false: an unfinished session",
        );
        // Discovery alone, marked complete.
        let mut damaged = value.clone();
        damaged["cases"].as_array_mut().unwrap().truncate(1);
        let first = if model == "nanoS" {
            "typed-hash-only-mail"
        } else {
            "tx-type0"
        };
        fails(
            verdict(&name, &damaged, Kind::Device),
            &format!("the session has no {first} done as its step asks"),
        );
    }
    // A complete-looking file without one of its steps: each step in turn.
    for (model, steps) in [
        ("nanoSP", &FIELD_STEPS[..]),
        ("nanoS", &HASH_ONLY_STEPS[..]),
    ] {
        let (name, value) = device_form(model);
        for (id, ..) in steps {
            let mut damaged = value.clone();
            remove_case(&mut damaged, id);
            // The cancel case's new request names the old one.
            let words = if *id == "cancel-old" {
                "after names no cancelled case before it".to_owned()
            } else {
                format!("the session has no {id} done as its step asks")
            };
            fails(verdict(&name, &damaged, Kind::Device), &words);
        }
    }
    let (name, value) = device_form("nanoSP");
    // The rejection, answered otherwise: it doesn't count.
    let mut damaged = value.clone();
    let reject = case_mut(&mut damaged, "reject");
    let last = reject["exchanges"].as_array().unwrap().len() - 1;
    reject["exchanges"][last]["answer"] = json!("6a80");
    reject["outcome"] = json!({ "status": "6a80", "as_asked": false });
    fails(
        verdict(&name, &damaged, Kind::Device),
        "the session has no reject done as its step asks",
    );
    // as_asked that isn't what the hands asked for.
    let mut damaged = value.clone();
    case_mut(&mut damaged, "unplug")["outcome"]["as_asked"] = json!(false);
    fails(
        verdict(&name, &damaged, Kind::Device),
        "as_asked isn't what the hands asked for",
    );
    // A case that isn't a step of its model's session.
    let mut damaged = value.clone();
    case_mut(&mut damaged, "typed-mail")["id"] = json!("typed-mail-2");
    fails(
        verdict(&name, &damaged, Kind::Device),
        "not a step of this model's session",
    );
    let (nano_s, mut damaged) = device_form("nanoS");
    let message = fixture("nanoSP").1["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "message")
        .unwrap()
        .clone();
    damaged["cases"].as_array_mut().unwrap().push(message);
    fails(
        verdict(&nano_s, &damaged, Kind::Device),
        "not a step of this model's session",
    );
    // A step that plays another case.
    let mut damaged = value.clone();
    case_mut(&mut damaged, "message")["from"] = json!("msg-live-1");
    fails(
        verdict(&name, &damaged, Kind::Device),
        "from, family or hands isn't the step's",
    );
}

/// The device's answer `v ‖ r ‖ s ‖ 9000` for a signature `r ‖ s ‖ v`.
fn signature_answer(signature: &[u8; 65]) -> Vec<u8> {
    let mut answer = vec![signature[64]];
    answer.extend_from_slice(&signature[..64]);
    answer.extend_from_slice(&[0x90, 0x00]);
    answer
}

fn reference_case() -> Case {
    parsed("nanoSP")
        .cases
        .into_iter()
        .find(|c| c.id == "name-field-e-acute-252")
        .unwrap()
}

/// A reference stream's signature is the test account's over
/// `expected_hash`.
#[test]
fn a_reference_signature_is_the_test_accounts() {
    let case = reference_case();
    assert_eq!(replay(&case).unwrap(), "reference");
    let expected = hash(case.request["expected_hash"].as_str().unwrap(), "").unwrap();
    let End::Answer(good) = case.exchanges.last().unwrap().end.clone() else {
        unreachable!()
    };
    let with_last = |answer: Vec<u8>, answered: Option<[u8; 20]>| {
        let mut damaged = case.clone();
        damaged.exchanges.last_mut().unwrap().end = End::Answer(answer);
        damaged.answered = answered;
        replay(&damaged)
    };
    let refused = |result: R<String>, words: &str| match result {
        Ok(_) => panic!("read, where {words:?} should fail it"),
        Err(e) => assert!(e.contains(words), "{e:?} doesn't say {words:?}"),
    };
    // Another key's, its signer that key's.
    let other = other_key();
    let signature = sign_digest(other.signing_key(), &expected).unwrap();
    refused(
        with_last(
            signature_answer(&signature),
            Some(*other.address().as_bytes()),
        ),
        "not the record's",
    );
    // The same signature with s in the high half, the parity flipped: no
    // signer recovers.
    let s = U256::from_be_slice(&good[33..65]).unwrap();
    let mut high = good.clone();
    high[33..65].copy_from_slice(&common::order().checked_sub(&s).unwrap().to_be_bytes());
    high[0] = 27 + 28 - high[0];
    refused(with_last(high, None), "no signer recovers");
    // r zero.
    let mut zero = good.clone();
    zero[1..33].fill(0);
    refused(with_last(zero, None), "no signer recovers");
    // The test account's signature with no signer.
    refused(with_last(good.clone(), None), "signer isn't");
    // A 9000 that isn't a signature.
    refused(
        with_last(vec![0x90, 0x00], Some(test_address())),
        "the last answer isn't a signature",
    );
}

/// A reference stream is whole unless the device ended it.
#[test]
fn a_reference_stream_ends_whole_or_where_the_device_ended_it() {
    let case = reference_case();
    let cut = |n: usize, end: End| {
        let mut damaged = case.clone();
        damaged.exchanges.truncate(n);
        damaged.exchanges.last_mut().unwrap().end = end;
        damaged.answered = None;
        replay(&damaged)
    };
    // Cut after its successful app probe, with no signature.
    let End::Answer(probe) = case.exchanges[1].end.clone() else {
        unreachable!()
    };
    let e = cut(2, End::Answer(probe)).unwrap_err();
    assert!(e.contains("cut short of its signature"), "{e}");
    // Ended by the device: refused mid-way, unplugged, or rejected at the
    // signature.
    assert_eq!(cut(3, End::Answer(vec![0x6a, 0x80])).unwrap(), "reference");
    assert_eq!(
        cut(3, End::Failed(Failed::Disconnected)).unwrap(),
        "reference"
    );
    let whole = case.exchanges.len();
    assert_eq!(
        cut(whole, End::Answer(vec![0x69, 0x85])).unwrap(),
        "reference"
    );
    // A signer where the device ended it.
    let mut damaged = case.clone();
    damaged.exchanges.truncate(3);
    damaged.exchanges[2].end = End::Answer(vec![0x6a, 0x80]);
    let e = replay(&damaged).unwrap_err();
    assert!(e.contains("a signer without a signature"), "{e}");
}
