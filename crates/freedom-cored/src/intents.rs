//! The wallet's intent records, `wallet-intents.jsonl` at the Freedom root
//! (the hello's `grant_root`, where main's `getFreedomDataPath` puts it),
//! through `fc-store`'s JSON Lines journal and `fc-wallet-state`'s intent
//! rules (design 0013, "The intent journal"; PRF-5e-3).
//!
//! - **Methods,** main's alone: one per `intent-store.js` write
//!   (`intents.commit`, `.handoff`, `.outcome`, `.settle`, `.void`,
//!   `.retire`, `.track`, `.withdraw_origin`, `.compact`) and read (`.get`,
//!   `.by_key`, `.held`, `.list`, `.held_nonces`, `.usage`,
//!   `.void_refusal`). Members are snake_case; an answer holds the
//!   reference's return value as it is (its views' keys included).
//! - **Main's run:** every write that appends a line carries `run`, main's
//!   `RUN_ID`, and the core writes it on the line. `void` and `retire`
//!   carry `lock`, main's word that it holds the account's reservation lock
//!   (until APR-6). No events: main tells its own listeners.
//! - **One writer:** until `core.hello` names `intents` in `store_moved`,
//!   main writes the file. The reads are served from it, read at each
//!   request as a fresh load would see it (an unreadable or damaged file
//!   reads as empty and stays where it is, and nothing is compacted), and
//!   every write answers `not_moved` (`data.store`) whatever its members,
//!   with nothing written, renamed or removed.
//! - **Once moved** the core holds the records, loaded at the first
//!   request: the file read and replayed, a damaged one moved aside as
//!   `<file>.corrupt-<ms>` (the store starts empty), and the file compacted
//!   when it differs from what compaction writes (a failure only logged).
//!   A load that can't read the file is `storage` (`INTENT_STORE_UNAVAILABLE`)
//!   and is tried again by the next request.
//! - **A write** is checked by the pure functions, admitted against the
//!   budget (compacting first when it must), appended and synced, and only
//!   then applied. A failed append or admission compaction is `storage`
//!   with `data.code` `INTENT_WRITE_FAILED`, the records unchanged. A
//!   void's compaction afterwards only logs a failure. `withdraw_origin`
//!   puts the origin back when its compaction fails.
//! - **Members are checked before the rules:** each has the JSON type main
//!   passes, or the request is `invalid_argument` ("Invalid parameters").
//!   So the reference's own `TypeError`s (an intent id or a hash whose
//!   `String()` throws, settle's `hashes` that isn't an array), which carry
//!   no code, never reach the wire.
//! - **Refusals** are the reference's: `invalid_argument` with its message,
//!   and its `INTENT_*` code as `data.code`.

use std::path::PathBuf;

use fc_json::{JsString, JsValue};
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_store::journal::{self, Journal};
use fc_wallet_state::intents::{Damaged, Intents, LIMITS, Limits, Refusal, Room, Write};
use serde_json::json;
use serde_json::value::RawValue;

use crate::testhooks::GrantWrite;

/// The methods, all main's (fc-protocol's table).
pub const METHODS: &[&str] = &[
    "intents.commit",
    "intents.handoff",
    "intents.outcome",
    "intents.settle",
    "intents.void",
    "intents.retire",
    "intents.track",
    "intents.withdraw_origin",
    "intents.compact",
    "intents.get",
    "intents.by_key",
    "intents.held",
    "intents.list",
    "intents.held_nonces",
    "intents.usage",
    "intents.void_refusal",
];

/// Its name in `store_moved`, `not_moved`'s `data.store`, a storage
/// error's, and the write hooks' (`intents:<step>`).
pub const STORE: &str = "intents";

/// The file, at the Freedom root.
pub const FILE_NAME: &str = "wallet-intents.jsonl";

/// The methods served before the store is named.
const READS: &[&str] = &[
    "intents.get",
    "intents.by_key",
    "intents.held",
    "intents.list",
    "intents.held_nonces",
    "intents.usage",
    "intents.void_refusal",
];

/// A member's JSON type, as main passes it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ty {
    Str,
    Num,
    Bool,
    Obj,
    StrOrNull,
    NumOrNull,
    ObjOrNull,
    /// An array of strings.
    Strs,
    /// An array of strings, or null.
    StrsOrNull,
}

impl Ty {
    fn admits(self, value: &JsValue) -> bool {
        let strings = |v: &JsValue| {
            v.as_array()
                .is_some_and(|items| items.iter().all(|h| matches!(h, JsValue::String(_))))
        };
        match (self, value) {
            (Ty::Str | Ty::StrOrNull, JsValue::String(_))
            | (Ty::Num | Ty::NumOrNull, JsValue::Number(_))
            | (Ty::Bool, JsValue::Bool(_))
            | (Ty::Obj | Ty::ObjOrNull, JsValue::Object(_)) => true,
            (Ty::StrOrNull | Ty::NumOrNull | Ty::ObjOrNull | Ty::StrsOrNull, JsValue::Null) => true,
            (Ty::Strs | Ty::StrsOrNull, v) => strings(v),
            _ => false,
        }
    }
}

/// A member: its wire name, the reference's argument name it becomes (none
/// for `run` and `lock`, which aren't the reference's arguments), its type,
/// and whether main always passes it.
struct Member(&'static str, Option<&'static str>, Ty, bool);

const RUN: Member = Member("run", None, Ty::Str, true);
const LOCK: Member = Member("lock", None, Ty::Bool, true);
const ID: Member = Member("intent_id", Some("intentId"), Ty::Str, true);

/// Each method's members.
fn members(method: &str) -> Option<&'static [Member]> {
    Some(match method {
        "intents.commit" => &[
            RUN,
            Member("intent_id", Some("intentId"), Ty::Str, false),
            Member("chain_id", Some("chainId"), Ty::Num, true),
            Member("sender", Some("sender"), Ty::Str, true),
            Member("nonce", Some("nonce"), Ty::Num, true),
            Member("hash", Some("hash"), Ty::Str, true),
            Member("raw", Some("raw"), Ty::Str, true),
            Member("via", Some("via"), Ty::Str, true),
            Member("context", Some("context"), Ty::Obj, false),
        ],
        "intents.handoff" => &[RUN, ID, Member("hash", Some("hash"), Ty::StrOrNull, false)],
        "intents.outcome" => &[
            RUN,
            ID,
            Member("handoff_id", Some("handoffId"), Ty::Str, true),
            Member("outcome", Some("outcome"), Ty::Str, true),
            Member("source", Some("source"), Ty::StrOrNull, false),
            Member("reason_class", Some("reasonClass"), Ty::StrOrNull, false),
        ],
        "intents.settle" => &[
            RUN,
            ID,
            Member("label", Some("label"), Ty::Str, true),
            Member("hash", Some("hash"), Ty::StrOrNull, false),
            Member("block", Some("block"), Ty::Num, true),
            Member("hashes", Some("hashes"), Ty::StrsOrNull, false),
        ],
        "intents.void" => &[RUN, ID, LOCK],
        "intents.retire" => &[
            RUN,
            ID,
            Member("block", Some("block"), Ty::Num, true),
            Member("hashes", Some("hashes"), Ty::Strs, true),
            LOCK,
        ],
        "intents.track" => &[
            RUN,
            ID,
            Member("bracket", Some("bracket"), Ty::ObjOrNull, false),
            Member("unread_since", Some("unreadSince"), Ty::NumOrNull, false),
        ],
        "intents.withdraw_origin" | "intents.get" => &[ID],
        "intents.by_key" => &[Member("key", Some("key"), Ty::StrOrNull, true)],
        "intents.held_nonces" => &[
            Member("chain_id", Some("chainId"), Ty::Num, true),
            Member("sender", Some("sender"), Ty::Str, true),
        ],
        "intents.void_refusal" => &[ID, RUN],
        "intents.compact" | "intents.held" | "intents.list" | "intents.usage" => &[],
        _ => return None,
    })
}

/// A request's members, checked: the reference's argument object, main's
/// run and its lock flag.
struct Params {
    args: JsValue,
    run: JsString,
    lock: bool,
}

impl Params {
    fn id(&self) -> &str {
        self.args
            .get("intentId")
            .and_then(JsValue::as_str)
            .unwrap_or_default()
    }
}

/// The run's form, the reference's `ID_PATTERN`: 8 to 64 of
/// `[A-Za-z0-9_-]`.
fn is_run(run: &str) -> bool {
    (8..=64).contains(&run.len())
        && run
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn params(method: &str, raw: Option<&str>) -> Result<Params, ErrorBody> {
    let spec = members(method).ok_or_else(crate::vault::internal)?;
    let value = fc_json::parse(raw.unwrap_or("{}")).map_err(|_| invalid())?;
    let JsValue::Object(props) = &value else {
        return Err(invalid());
    };
    let mut args = Vec::new();
    let mut run = None;
    let mut lock = false;
    for (key, value) in props {
        let member = spec.iter().find(|m| key == m.0).ok_or_else(invalid)?;
        if !member.2.admits(value) {
            return Err(invalid());
        }
        match (member.0, member.1) {
            ("run", _) => match value.as_str() {
                Some(r) if is_run(r) => run = value.as_js_string().cloned(),
                _ => return Err(invalid()),
            },
            ("lock", _) => lock = matches!(value, JsValue::Bool(true)),
            (_, Some(js)) => args.push((JsString::from(js), value.clone())),
            _ => return Err(invalid()),
        }
    }
    if spec
        .iter()
        .any(|m| m.3 && !props.iter().any(|(k, _)| k == m.0))
    {
        return Err(invalid());
    }
    Ok(Params {
        args: JsValue::Object(args),
        run: run.unwrap_or_else(|| JsString::from("")),
        lock,
    })
}

fn invalid() -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters")
}

fn not_moved() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::NotMoved,
        "main still writes the wallet's intent records (intents isn't in store_moved)",
    )
    .with_data(json!({ "store": STORE }))
}

/// The reference's refusal: its message, and its code. A refusal without
/// one (JavaScript's own `TypeError`) can't follow the members' check; if
/// one did, it is the members' error.
fn refused(refusal: Refusal) -> ErrorBody {
    if refusal.code.is_empty() {
        return invalid();
    }
    ErrorBody::new(ErrorCode::InvalidArgument, refusal.message)
        .with_data(json!({ "code": refusal.code }))
}

fn kind_of(error: &journal::Error) -> String {
    match error {
        journal::Error::Io(e) => crate::secrets::io_kind(e).to_owned(),
        other => other.code(),
    }
}

/// `INTENT_WRITE_FAILED`: an append, or the compaction before it, failed.
fn write_failed(error: &journal::Error) -> ErrorBody {
    crate::log::error(
        "a wallet intent record could not be written",
        json!({ "kind": kind_of(error) }),
    );
    ErrorBody::new(
        ErrorCode::Storage,
        "Could not save the wallet's payment record.",
    )
    .with_data(json!({ "code": "INTENT_WRITE_FAILED", "store": STORE, "kind": kind_of(error) }))
}

/// `INTENT_STORE_UNAVAILABLE`: the load couldn't read the file, or set a
/// damaged one aside.
fn unavailable(error: &journal::Error) -> ErrorBody {
    crate::log::error(
        "the wallet intent records could not be loaded",
        json!({ "kind": kind_of(error) }),
    );
    ErrorBody::new(
        ErrorCode::Storage,
        "The wallet's payment records could not be read.",
    )
    .with_data(
        json!({ "code": "INTENT_STORE_UNAVAILABLE", "store": STORE, "kind": kind_of(error) }),
    )
}

/// A compaction asked for (`compact`, `withdraw_origin`) failed: the
/// reference throws the journal's own error.
fn storage(error: &journal::Error) -> ErrorBody {
    crate::log::error(
        "the wallet intent records could not be compacted",
        json!({ "kind": kind_of(error) }),
    );
    ErrorBody::new(ErrorCode::Storage, "Storage error")
        .with_data(json!({ "store": STORE, "kind": kind_of(error) }))
}

/// The records once moved: the journal and the state its lines give.
struct Live {
    journal: Journal,
    state: Intents,
}

impl Live {
    /// `compactNow`: the file rewritten from the state, which then folds.
    fn compact(&mut self) -> Result<(), journal::Error> {
        self.journal
            .compact(&self.state.compaction(), &GrantWrite(STORE))?;
        self.state.compacted();
        Ok(())
    }

    /// `compactQuietly`: a failure only logged.
    fn compact_quietly(&mut self, why: &str) {
        if let Err(e) = self.compact() {
            crate::log::warn(
                "a wallet intent compaction failed",
                json!({ "when": why, "kind": kind_of(&e) }),
            );
        }
    }
}

/// `wallet-intents.jsonl`, and who writes it.
#[derive(Default)]
pub struct IntentStore {
    root: Option<PathBuf>,
    moved: bool,
    live: Option<Live>,
}

/// A view, `null` when there is none.
fn shown(value: Option<JsValue>) -> String {
    value.map_or_else(|| "null".to_owned(), |v| v.stringify())
}

fn texts(values: Vec<JsValue>) -> String {
    JsValue::Array(values).stringify()
}

impl IntentStore {
    pub fn new() -> Self {
        IntentStore::default()
    }

    /// The hello's `grant_root`, and whether `store_moved` names `intents`.
    pub fn configure(&mut self, root: PathBuf, moved: bool) {
        self.root = Some(root);
        self.moved = moved;
        self.live = None;
    }

    /// A request: its result's JSON text, or its error. `wall_ms` is the
    /// time a line records (`Date.now()`).
    pub fn request(
        &mut self,
        method: &str,
        raw: Option<&str>,
        wall_ms: u64,
    ) -> Result<Box<RawValue>, ErrorBody> {
        if !self.moved && !READS.contains(&method) {
            return Err(not_moved());
        }
        let p = params(method, raw)?;
        let text = if self.moved {
            let live = self.live(wall_ms)?;
            if READS.contains(&method) {
                read(&live.state, live.journal.size(), method, &p)?
            } else {
                write(live, method, &p, wall_ms as f64)?
            }
        } else {
            let (state, size) = self.read_only()?;
            read(&state, size, method, &p)?
        };
        RawValue::from_string(text).map_err(|_| crate::vault::internal())
    }

    fn path(&self) -> Option<PathBuf> {
        self.root.as_ref().map(|root| root.join(FILE_NAME))
    }

    /// The records as main's file gives them, before the store is moved,
    /// and the file's size: what a load would hold, compaction's fold
    /// included, with nothing written. Unreadable or damaged: empty.
    fn read_only(&self) -> Result<(Intents, u64), ErrorBody> {
        let limits = crate::testhooks::intent_limits(LIMITS);
        let read = self
            .path()
            .and_then(|path| journal::read(&path, limits.read_bytes).ok())
            .filter(|read| read.parsed.corrupt.is_empty());
        let size = read.as_ref().map_or(0, |read| read.size);
        match read.and_then(|read| Intents::load(&read.parsed.records, limits).ok()) {
            Some(mut loaded) => {
                if loaded.compact {
                    loaded.intents.compacted();
                }
                Ok((loaded.intents, size))
            }
            None => Ok((empty(limits)?, 0)),
        }
    }

    /// `load()` once moved: the records, read at the first request.
    fn live(&mut self, wall_ms: u64) -> Result<&mut Live, ErrorBody> {
        if self.live.is_none() {
            let root = self.root.clone().ok_or_else(crate::vault::internal)?;
            self.live = Some(load(root, wall_ms)?);
        }
        self.live.as_mut().ok_or_else(crate::vault::internal)
    }
}

/// No records (an empty file breaks no rule).
fn empty(limits: Limits) -> Result<Intents, ErrorBody> {
    Intents::load(&[], limits)
        .map(|loaded| loaded.intents)
        .map_err(|_| crate::vault::internal())
}

/// `doLoad`: the file read and replayed; a damaged one moved aside, the
/// store empty; the file compacted when it differs from what compaction
/// writes.
fn load(root: PathBuf, wall_ms: u64) -> Result<Live, ErrorBody> {
    let limits = crate::testhooks::intent_limits(LIMITS);
    let mut journal = Journal::new(&root, FILE_NAME, limits.read_bytes);
    let (damage, loaded) = match journal.open_hooked(&GrantWrite(STORE)) {
        Err(journal::Error::TooLarge) => (Some("the file is too large".to_owned()), None),
        Err(journal::Error::NotAFile) => (Some("not a regular file".to_owned()), None),
        Err(e) => return Err(unavailable(&e)),
        Ok(read) => match read.parsed.corrupt.first() {
            Some(first) => (
                Some(format!(
                    "{} damaged line(s), the first at line {}",
                    read.parsed.corrupt.len(),
                    first.line
                )),
                None,
            ),
            None => {
                if read.parsed.torn_tail > 0 {
                    crate::log::warn(
                        "dropped an unfinished last wallet intent line",
                        json!({ "bytes": read.parsed.torn_tail }),
                    );
                }
                match Intents::load(&read.parsed.records, limits) {
                    Ok(loaded) => (None, Some(loaded)),
                    Err(Damaged(reason)) => (Some(reason), None),
                }
            }
        },
    };
    let Some(loaded) = loaded else {
        // `quarantine(reason)`.
        let reason = damage.unwrap_or_default();
        let moved = journal
            .move_aside(&format!("corrupt-{wall_ms}"))
            .map_err(|e| unavailable(&e))?;
        crate::log::error(
            "wallet intent records were damaged: moved aside, starting empty",
            json!({
                "reason": reason,
                "moved_to": moved.as_ref().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()),
            }),
        );
        return Ok(Live {
            journal,
            state: empty(limits)?,
        });
    };
    let mut live = Live {
        journal,
        state: loaded.intents,
    };
    if loaded.compact {
        live.compact_quietly("at startup");
    }
    Ok(live)
}

/// A read's answer.
fn read(state: &Intents, file: u64, method: &str, p: &Params) -> Result<String, ErrorBody> {
    let arg = |key: &str| p.args.get(key);
    Ok(match method {
        "intents.get" => format!(r#"{{"intent":{}}}"#, shown(state.get(p.id()))),
        "intents.by_key" => format!(
            r#"{{"intent":{}}}"#,
            shown(state.by_key(arg("key").and_then(JsValue::as_js_string)))
        ),
        "intents.held" => format!(r#"{{"intents":{}}}"#, texts(state.held())),
        "intents.list" => format!(r#"{{"intents":{}}}"#, texts(state.list())),
        "intents.held_nonces" => {
            let chain_id = match arg("chainId") {
                Some(JsValue::Number(n)) => *n,
                _ => return Err(invalid()),
            };
            let sender = arg("sender").and_then(JsValue::as_str).unwrap_or_default();
            let nonces = state
                .held_nonces(chain_id, sender)
                .into_iter()
                .map(JsValue::Number)
                .collect();
            format!(r#"{{"nonces":{}}}"#, texts(nonces))
        }
        "intents.usage" => {
            let usage = JsValue::Object(vec![
                ("file".into(), JsValue::Number(file as f64)),
                ("owed".into(), JsValue::Number(state.owed() as f64)),
                ("budget".into(), JsValue::Number(state.budget() as f64)),
                (
                    "limit".into(),
                    JsValue::Number(state.limits().journal_bytes as f64),
                ),
            ]);
            format!(r#"{{"usage":{}}}"#, usage.stringify())
        }
        "intents.void_refusal" => match state.void_refusal(p.id(), p.run.as_ref()) {
            Some(refusal) => format!(r#"{{"refusal":{}}}"#, shown(refusal.map(JsValue::string))),
            None => {
                return Err(refused(Refusal {
                    code: "INTENT_UNKNOWN",
                    message: format!("Unknown wallet intent {}", p.id()),
                }));
            }
        },
        _ => return Err(crate::vault::internal()),
    })
}

/// `crypto.randomUUID()`, or a test's (`FREEDOM_CORED_TEST_INTENT_IDS`).
fn new_id() -> Result<JsString, ErrorBody> {
    if let Some(id) = crate::testhooks::intent_id() {
        return Ok(JsString::from(id.as_str()));
    }
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| crate::vault::internal())?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex = fc_evm::to_hex(&b);
    let hex = hex.trim_start_matches("0x");
    let id = format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    );
    Ok(JsString::from(id.as_str()))
}

/// `write(record, lock, { admitted })`: checked, admitted (compacting first
/// if it must), appended and synced, then applied. The answer's JSON text.
fn write(live: &mut Live, method: &str, p: &Params, at: f64) -> Result<String, ErrorBody> {
    let state = &live.state;
    let (run, args) = (&p.run, &p.args);
    let checked: Write = match method {
        "intents.commit" => state.commit(run, at, &new_id()?, args),
        "intents.handoff" => state.handoff(run, at, &new_id()?, args),
        "intents.outcome" => match state.outcome(run, at, args).map_err(refused)? {
            Some(write) => Ok(write),
            // No longer owed: nothing written, the intent as it is.
            None => return Ok(format!(r#"{{"intent":{}}}"#, shown(state.get(p.id())))),
        },
        "intents.settle" => state.settle(run, at, args),
        "intents.void" => state.void(run, at, args, p.lock),
        "intents.retire" => state.retire(run, at, args, p.lock),
        "intents.track" => state.track(run, at, args),
        "intents.withdraw_origin" => {
            let withdrawn = match live.state.withdraw_origin(p.id()) {
                None => false,
                Some(taken) => match live.compact() {
                    Ok(()) => true,
                    Err(e) => {
                        live.state.restore_origin(taken);
                        return Err(storage(&e));
                    }
                },
            };
            return Ok(format!(r#"{{"withdrawn":{withdrawn}}}"#));
        }
        "intents.compact" => {
            live.compact().map_err(|e| storage(&e))?;
            return Ok("{}".to_owned());
        }
        _ => return Err(crate::vault::internal()),
    }
    .map_err(refused)?;
    // `admit`: owed lines always fit.
    if live
        .state
        .room(&checked, live.journal.size(), false)
        .map_err(refused)?
        == Room::Compact
    {
        live.compact().map_err(|e| write_failed(&e))?;
        live.state
            .room(&checked, live.journal.size(), true)
            .map_err(refused)?;
    }
    live.journal
        .append(checked.record(), &GrantWrite(STORE))
        .map_err(|e| write_failed(&e))?;
    let record = checked.record().clone();
    let view = live.state.apply(checked);
    match method {
        "intents.handoff" => {
            let hash = record
                .get("hash")
                .and_then(JsValue::as_str)
                .unwrap_or_default();
            let handoff = JsValue::Object(vec![
                (
                    "handoffId".into(),
                    record.get("handoff_id").cloned().unwrap_or(JsValue::Null),
                ),
                ("hash".into(), JsValue::string(hash)),
                (
                    "raw".into(),
                    live.state
                        .signed(p.id(), hash)
                        .map_or(JsValue::Null, JsValue::string),
                ),
            ]);
            Ok(format!(r#"{{"handoff":{}}}"#, handoff.stringify()))
        }
        "intents.void" => {
            live.compact_quietly("after a void");
            Ok(format!(r#"{{"intent":{}}}"#, shown(view)))
        }
        _ => Ok(format!(r#"{{"intent":{}}}"#, shown(view))),
    }
}
