//! Main's own Swarm methods that call the node (design 0015, "Methods main
//! calls"): `swarm.publish`, `swarm.feed`, `swarm.stamps` and
//! `swarm.upload_status`, each a **shell parent** ([`Shell`]): no page, no
//! grant, no live facts, no readiness check (their grammar rows have none).
//! The asks, the strict reading of main's answers and the history row's
//! last write after an early end are the framework's, as for
//! `swarm.request` ([`super::Request`]).
//!
//! **The rows** (SWM-4's D5): `swarm.publish` is main's (`shell`) with no
//! total deadline, only the idle bounds of D13 ([`Deadline::Idle`]);
//! `swarm.feed` is main's with the `swarm` deadline; `swarm.stamps` and
//! `swarm.upload_status` are the chrome's and main's with the `swarm`
//! deadline ([`ShellMethod`]). All four take a place in the admission gate
//! ([`super::RUNNING_REQUESTS`], [`super::WAITING_REQUESTS`]), and beyond it
//! are the protocol error `busy` (design 0015, "Budgets").
//!
//! **What the driver needs to know** (D13, for a request with no total
//! deadline): a memory reservation waits at most [`MEMORY_WAIT_MS`], then
//! the request ends [`Shell::busy`]; each ask of main has its own bound
//! ([`ask_bound`]): 60 s without progress for a part, a streamed reply and
//! a streamed body, 300 s in all for a whole node reply. Past it the
//! driver calls [`Shell::expire`]: the ask is cancelled, the method reads
//! it as `failed: error`, and the request ends, releasing its place. The
//! ask keeps its charge until main's terminal answer is read and dropped.
//!
//! **Params** come as main's JSON ([`ShellCall::parse`]), read strictly:
//! an unknown member, a value of another type or outside its bounds is
//! [`Invalid`], which the driver answers `invalid_argument`.
//!
//! **Answers** ([`ShellOutcome`]): the result as the reference's service
//! gives it; or the error the service throws, its message and the fields
//! its callers read (`code`, `status`, `capacity`: [`ShellError`]);
//! `cancelled`; the protocol error `busy`; or main broke the protocol,
//! which ends the connection (D5).

use std::collections::BTreeSet;

use fc_json::{JsString, JsValue};

use super::node::{Failed, transport_text};
use super::{After, AskId, Asks, Cx, Effect, Event, Kind, Need, Protocol, Reply, World};
use crate::ReplyError;
use crate::errors::{self, NodeError, ServiceError, Site};
use crate::methods::{shell_feed, shell_publish, shell_stamps, shell_status};
use crate::stamps::{BatchId, Capacity, JsError, PostageError};
use crate::value::{INLINE_BYTES, Source, Value, decode_base64};

/// The `swarm` deadline kind's most (D5): 300 s, or the caller's shorter
/// `deadline_ms`.
pub const SWARM_DEADLINE_MS: u64 = 300_000;
/// D13: the most a request with no total deadline waits for memory.
pub const MEMORY_WAIT_MS: u64 = 60_000;
/// D13: an ask of main under such a request makes no progress (an answer,
/// a head, a frame or credit) for this long.
pub const IDLE_MS: u64 = 60_000;
/// D13: a whole node reply under such a request comes within this long.
pub const WHOLE_REPLY_MS: u64 = 300_000;

/// `swarm.feed`'s refusal code when the vault's Bee wallet is no longer
/// the owner main named (core PR K2), before any node call: as the feed
/// store's `identity_taken` refuses what a prompt showed once another
/// identity took it.
pub const OWNER_CHANGED: &str = "owner_changed";
/// Its message.
pub const OWNER_CHANGED_MESSAGE: &str =
    "The Bee wallet this feed request names is no longer the vault's";

/// `swarm.publish`'s code when its history row's insert, or the
/// `history-bound` trim right after it, failed, before any node call: where
/// the reference's `addEntry` throws before the IPC handler's `try`, so the
/// invoke rejects. The text stays the history store's.
pub const HISTORY_INSERT: &str = "history_insert";
/// `swarm.publish`'s code when a later write of its history row failed (the
/// `completed` update, or a failure's own `failed` update), after the
/// core's one retry (`history-retry`). The text stays the write's.
pub const HISTORY_UPDATE: &str = "history_update";

/// The largest safe integer.
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// Main's own node methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellMethod {
    Publish,
    Feed,
    Stamps,
    UploadStatus,
}

/// Who may call a method (D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Callers {
    Shell,
    ChromeAndShell,
}

/// A method's deadline kind (D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deadline {
    /// No total deadline (a picked file may be large): only D13's bounds.
    Idle,
    /// 300 s, or the caller's shorter `deadline_ms`.
    Swarm,
}

impl Deadline {
    /// The request's total deadline from the caller's `deadline_ms`.
    pub fn total_ms(self, asked: Option<u64>) -> Option<u64> {
        match self {
            Deadline::Idle => None,
            Deadline::Swarm => {
                Some(asked.map_or(SWARM_DEADLINE_MS, |ms| ms.min(SWARM_DEADLINE_MS)))
            }
        }
    }

    /// How long a memory reservation may wait before the request ends
    /// `busy`: D13's 60 s with no total deadline, else until the deadline.
    pub fn memory_wait_ms(self, asked: Option<u64>) -> Option<u64> {
        match self {
            Deadline::Idle => Some(MEMORY_WAIT_MS),
            Deadline::Swarm => self.total_ms(asked),
        }
    }
}

impl ShellMethod {
    pub const ALL: [ShellMethod; 4] = [
        ShellMethod::Publish,
        ShellMethod::Feed,
        ShellMethod::Stamps,
        ShellMethod::UploadStatus,
    ];

    /// The method's name on the wire.
    pub fn name(self) -> &'static str {
        match self {
            ShellMethod::Publish => "swarm.publish",
            ShellMethod::Feed => "swarm.feed",
            ShellMethod::Stamps => "swarm.stamps",
            ShellMethod::UploadStatus => "swarm.upload_status",
        }
    }

    pub fn from_name(name: &str) -> Option<ShellMethod> {
        ShellMethod::ALL.into_iter().find(|m| m.name() == name)
    }

    pub fn callers(self) -> Callers {
        match self {
            ShellMethod::Publish | ShellMethod::Feed => Callers::Shell,
            ShellMethod::Stamps | ShellMethod::UploadStatus => Callers::ChromeAndShell,
        }
    }

    pub fn deadline(self) -> Deadline {
        match self {
            ShellMethod::Publish => Deadline::Idle,
            _ => Deadline::Swarm,
        }
    }

    /// Whether the method takes a place in the admission gate: every parent
    /// that asks main, the node or the vault does (design 0015, "Budgets"),
    /// and each of these four asks the node.
    pub fn gated(self) -> bool {
        true
    }
}

/// An ask's own bound (D13), which the driver enforces with
/// [`Shell::expire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskBound {
    /// The request's total deadline bounds it.
    Deadline,
    /// No progress for this many milliseconds: for a part, its head and
    /// frames; for a streamed reply, its head and frames.
    Idle(u64),
    /// In all, from the ask.
    Total(u64),
    /// A whole call whose body streams (`swarm.body`): `idle` without
    /// progress (main's `swarm.body`, its credit) until the core sends the
    /// body's terminal, then `total` for the reply from that terminal on.
    BodyThenReply { idle: u64, total: u64 },
    /// Not an ask of main (a store write, the upload's turn, the vault, a
    /// topic's turn): no bound of its own. The request's deadline, where it
    /// has one, still ends it; an upload's turn waits only on uploads that
    /// are bound themselves.
    None,
}

/// What bounds `need` under a parent of `deadline`'s kind (D13): with no
/// total deadline, 60 s without progress for each ask of main, and 300 s
/// for a whole node reply, which shows the core no progress while main
/// reads it.
pub fn ask_bound(deadline: Deadline, need: &Need) -> AskBound {
    let main = matches!(need, Need::Ready(_) | Need::Node(_) | Need::Part(_));
    match deadline {
        Deadline::Swarm if main => AskBound::Deadline,
        Deadline::Swarm => AskBound::None,
        Deadline::Idle => match need {
            Need::Ready(_) | Need::Part(_) => AskBound::Idle(IDLE_MS),
            Need::Node(call) if call.stream() => AskBound::Idle(IDLE_MS),
            Need::Node(call) if matches!(call.body, Some(super::Body::Stream { .. })) => {
                AskBound::BodyThenReply {
                    idle: IDLE_MS,
                    total: WHOLE_REPLY_MS,
                }
            }
            Need::Node(_) => AskBound::Total(WHOLE_REPLY_MS),
            _ => AskBound::None,
        },
    }
}

// ---------------------------------------------------------------------------
// The answers.

/// The error a reference service throws, as its callers read it: its
/// message, and `code` (a batch choice's), `status` (a node's error
/// answer's) and `capacity` (`selectBestBatch`'s refusal) where it has
/// them.
#[derive(Debug, Clone, PartialEq)]
pub struct ShellError {
    pub message: JsString,
    pub code: Option<&'static str>,
    pub status: Option<u16>,
    pub capacity: Option<Capacity>,
}

impl ShellError {
    /// A plain `Error(message)`.
    pub fn new(message: impl Into<JsString>) -> ShellError {
        ShellError {
            message: message.into(),
            code: None,
            status: None,
            capacity: None,
        }
    }

    /// A node's error answer (bee-js's `BeeResponseError`, the SOC
    /// uploader's `Error`), with its status where the site's error has one.
    pub(crate) fn node(err: &NodeError) -> ShellError {
        ShellError {
            status: err.status,
            ..ShellError::new(err.message.clone())
        }
    }

    pub(crate) fn service(err: &ServiceError) -> ShellError {
        ShellError {
            code: err.code,
            ..ShellError::new(err.message.clone())
        }
    }

    /// `selectBestBatch`'s refusal under `requireCapacity`.
    pub(crate) fn postage(err: &PostageError) -> ShellError {
        ShellError {
            code: Some(err.code.code()),
            capacity: Some(err.capacity),
            ..ShellError::new(err.code.message())
        }
    }

    /// What bee-js threw reading a reply (zod's, `mapPostageBatch`'s).
    pub(crate) fn js(err: &JsError) -> ShellError {
        ShellError::new(err.message.clone())
    }

    /// A history write's failure, `message` the store's text, with its
    /// code ([`HISTORY_INSERT`] or [`HISTORY_UPDATE`]).
    pub(crate) fn history(message: impl Into<JsString>, code: &'static str) -> ShellError {
        ShellError {
            code: Some(code),
            ..ShellError::new(message)
        }
    }

    /// `swarm.feed`'s refusal when the vault's Bee wallet isn't the owner
    /// main named (K2): [`OWNER_CHANGED_MESSAGE`], code [`OWNER_CHANGED`].
    pub(crate) fn owner_changed() -> ShellError {
        ShellError {
            code: Some(OWNER_CHANGED),
            ..ShellError::new(OWNER_CHANGED_MESSAGE)
        }
    }

    /// `{ message, code?, status?, capacity? }`.
    pub fn to_value(&self) -> Value {
        let mut members = vec![(
            JsString::from("message"),
            Value::String(self.message.clone()),
        )];
        if let Some(code) = self.code {
            members.push((JsString::from("code"), Value::str(code)));
        }
        if let Some(status) = self.status {
            members.push((JsString::from("status"), Value::int(u64::from(status))));
        }
        if let Some(c) = self.capacity {
            members.push((
                JsString::from("capacity"),
                Value::object([
                    ("uploadBytes", Value::Number(c.upload_bytes)),
                    ("requiredBytes", Value::Number(c.required_bytes)),
                    (
                        "largestRemainingBytes",
                        Value::Number(c.largest_remaining_bytes),
                    ),
                ]),
            ));
        }
        Value::Object(members)
    }
}

/// How a shell parent ended.
#[derive(Debug, Clone, PartialEq)]
pub enum ShellOutcome {
    /// The service's result.
    Result(Value),
    /// What the service threw.
    Error(ShellError),
    /// Cancelled by main or past its deadline.
    Cancelled,
    /// The protocol error `busy`: the gate, the memory wait, or main's
    /// Swarm I/O pool (`failed: busy`).
    Busy,
    /// Main broke the protocol: the connection ends (D5).
    Protocol(Protocol),
}

/// A plain error.
pub(crate) fn error(message: impl Into<JsString>) -> ShellOutcome {
    ShellOutcome::Error(ShellError::new(message))
}

/// -32603 `Internal error`'s text: what only a core or main bug reaches
/// (an answer of the wrong kind, a call main's grammar refused).
pub(crate) fn internal() -> ShellOutcome {
    error("Internal error")
}

/// A node call that failed before any reply: main's pool full is `busy`;
/// past its cap, `Swarm node reply too large` (`reply-bounds`); else its
/// class's text (`transport-error-text`), `stopped` the reference's `Swarm
/// node is not ready`.
pub(crate) fn failed(failed: Failed) -> ShellOutcome {
    match failed {
        Failed::Busy => ShellOutcome::Busy,
        Failed::TooLarge => error(errors::REPLY_TOO_LARGE_MESSAGE),
        class => error(transport_text(class)),
    }
}

/// A JSON reply the typed reader refused.
pub(crate) fn reply_error(err: ReplyError) -> ShellOutcome {
    match err {
        ReplyError::TooLarge => error(errors::REPLY_TOO_LARGE_MESSAGE),
        ReplyError::TooDeep => error(transport_text(Failed::Error)),
        ReplyError::Syntax(_) => error(errors::REPLY_SYNTAX_MESSAGE),
    }
}

/// A node's error answer at `site`, from at most 8 KiB of its body.
pub(crate) fn error_reply(reply: &Reply, site: Site) -> ShellOutcome {
    match reply.error(site) {
        Ok(err) => ShellOutcome::Error(ShellError::node(&err)),
        Err(class) => failed(class),
    }
}

/// A node call's whole answer: its reply, or the end it gives the method
/// (a failure before any reply, main's grammar refusal, a wrong kind).
pub(crate) fn whole_reply(event: Event) -> Result<Reply, ShellOutcome> {
    match event {
        Event::Reply(reply) => Ok(reply),
        Event::Failed(class) => Err(failed(class)),
        _ => Err(internal()),
    }
}

// ---------------------------------------------------------------------------
// The params.

/// Why main's params aren't read: the member and what is wrong with it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Invalid(pub String);

fn invalid(at: &str, why: &str) -> Invalid {
    Invalid(format!("{at}: {why}"))
}

/// One call of a shell method, its params read.
#[derive(Debug, Clone, PartialEq)]
pub enum ShellCall {
    Publish(PublishCall),
    Feed(FeedCall),
    /// `{ id? }`.
    Stamps {
        id: Option<BatchId>,
    },
    /// `{ tag_uid }`.
    UploadStatus {
        tag_uid: u64,
    },
}

/// `swarm.publish`'s `kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishKind {
    /// publish-service.js's `publishData`: one part, its bytes.
    Data,
    /// `publishFile`: one part, a picked file main streams.
    File,
    /// `publishCollection` and `publishDirectory`: the parts as a tar.
    Collection,
}

/// A payload part: its path in a collection, its length, and its bytes
/// (inline, or a part main streams with `shell.swarm_part`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartSpec {
    pub path: Option<JsString>,
    pub bytes: u64,
    pub source: Source,
}

/// The history row's kind (publish-service.js's IPC handlers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryKind {
    Data,
    File,
    Directory,
}

impl HistoryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            HistoryKind::Data => "data",
            HistoryKind::File => "file",
            HistoryKind::Directory => "directory",
        }
    }
}

/// `history`: the row a `freedom://publish` upload keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub kind: HistoryKind,
    pub name: JsString,
}

/// `swarm.publish`'s params: `{ kind, parts, name?, content_type?,
/// index_document?, encrypt?, batch?, pin, deferred, history? }`.
#[derive(Debug, Clone, PartialEq)]
pub struct PublishCall {
    pub kind: PublishKind,
    pub parts: Vec<PartSpec>,
    pub name: Option<JsString>,
    pub content_type: Option<JsString>,
    pub index_document: Option<JsString>,
    pub encrypt: bool,
    pub batch: Option<BatchId>,
    /// `swarm-deferred-upload`. (`pin` is always `true`: the forms admit no
    /// other value.)
    pub deferred: bool,
    pub history: Option<HistoryEntry>,
}

/// `swarm.feed`'s `op`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedOp {
    Create,
    /// `reference` (32 bytes, or 64 for an encrypted one), and the least
    /// index to write at.
    Update {
        reference: Vec<u8>,
        min_index: u64,
    },
    /// feed-service.js's `readFeedState(owner, topic)`, which the agent's
    /// publication controller calls after `updateFeed`: whether the feed
    /// has an update, and its latest index. The owner is the Bee wallet's,
    /// as every caller's is.
    Read,
}

/// `swarm.feed`'s params: `{ op, key: { kind: "bee_wallet" }, owner,
/// topic, reference?, min_index?, batch? }`; a read takes only `op`,
/// `key`, `owner` and `topic`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedCall {
    pub op: FeedOp,
    /// The Bee wallet's owner main showed (core PR K2), which the vault's
    /// must still be: compared with the owner the vault answers before any
    /// node call, and every signature the operation gets checked against
    /// it before its upload.
    pub owner: [u8; 20],
    /// The feed's topic, `Topic.fromString(…)`'s 32 bytes, which main
    /// computes.
    pub topic: [u8; 32],
    pub batch: Option<BatchId>,
}

/// Main's params as an object of known members.
struct Members<'v> {
    at: &'static str,
    members: &'v [(JsString, JsValue)],
}

impl<'v> Members<'v> {
    fn of(value: &'v JsValue, at: &'static str, known: &[&str]) -> Result<Self, Invalid> {
        let JsValue::Object(members) = value else {
            return Err(invalid(at, "not an object"));
        };
        if let Some((key, _)) = members
            .iter()
            .find(|(k, _)| !known.iter().any(|n| *k == *n))
        {
            return Err(Invalid(format!("{at}: an unknown member {}", key.as_str())));
        }
        Ok(Members { at, members })
    }

    fn get(&self, key: &str) -> Option<&'v JsValue> {
        self.members.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    fn need(&self, key: &str) -> Result<&'v JsValue, Invalid> {
        self.get(key)
            .ok_or_else(|| Invalid(format!("{}.{key}: missing", self.at)))
    }

    fn bad(&self, key: &str, why: &str) -> Invalid {
        Invalid(format!("{}.{key}: {why}", self.at))
    }

    fn string(&self, key: &str) -> Result<Option<&'v JsString>, Invalid> {
        match self.get(key) {
            None => Ok(None),
            Some(JsValue::String(s)) => Ok(Some(s)),
            Some(_) => Err(self.bad(key, "not a string")),
        }
    }

    fn boolean(&self, key: &str) -> Result<Option<bool>, Invalid> {
        match self.get(key) {
            None => Ok(None),
            Some(JsValue::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(self.bad(key, "not a boolean")),
        }
    }

    fn safe_integer(&self, key: &str) -> Result<Option<u64>, Invalid> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => safe_integer(v)
                .map(Some)
                .ok_or_else(|| self.bad(key, "not a safe non-negative integer")),
        }
    }

    fn batch(&self, key: &str) -> Result<Option<BatchId>, Invalid> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => hex_bytes::<32>(v)
                .map(|b| Some(BatchId(b)))
                .ok_or_else(|| self.bad(key, "not 64 hex digits")),
        }
    }
}

/// Keys met so far, each once: a set, so `n` keys cost `O(n log n)`
/// comparisons, and a part table as large as main's frame holds is read
/// in time the swarm thread can spare (it runs before any bound applies).
struct Seen<K>(BTreeSet<K>);

impl<K: Ord> Seen<K> {
    fn new() -> Self {
        Seen(BTreeSet::new())
    }

    /// Whether `key` is met for the first time.
    fn first(&mut self, key: K) -> bool {
        self.0.insert(key)
    }
}

/// A safe non-negative integer.
fn safe_integer(value: &JsValue) -> Option<u64> {
    match value {
        JsValue::Number(n) if n.is_finite() && n.trunc() == *n && (0.0..=MAX_SAFE).contains(n) =>
        {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "a safe non-negative integer"
            )]
            Some(*n as u64)
        }
        _ => None,
    }
}

/// `N` bytes from `2N` hex digits, either case (bound values are
/// lowercased, design 0015, `shell.swarm_api`).
fn hex_bytes<const N: usize>(value: &JsValue) -> Option<[u8; N]> {
    let JsValue::String(s) = value else {
        return None;
    };
    if !s.is_well_formed() || s.len() != 2 * N || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    crate::chunks::unhex::<N>(&s.as_str().to_ascii_lowercase())
}

/// An owner as design 0015 writes `<o>` and `shell.swarm_api`'s
/// `feed.owner`: 40 hex digits, lowercase, with no `0x`.
fn owner_hex(value: &JsValue) -> Option<[u8; 20]> {
    let JsValue::String(s) = value else {
        return None;
    };
    if !s.is_well_formed()
        || s.len() != 40
        || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    crate::chunks::unhex::<20>(s.as_str())
}

/// A header value as main sends it (design 0015, `shell.swarm_api`: byte
/// strings): tab, U+0020 to U+007E, and U+0080 to U+00FF, each one byte.
fn header_safe(s: &JsString) -> bool {
    s.units()
        .all(|u| u == 0x09 || (0x20..=0x7e).contains(&u) || (0x80..=0xff).contains(&u))
}

impl ShellCall {
    /// The method this call is of.
    pub fn method(&self) -> ShellMethod {
        match self {
            ShellCall::Publish(_) => ShellMethod::Publish,
            ShellCall::Feed(_) => ShellMethod::Feed,
            ShellCall::Stamps { .. } => ShellMethod::Stamps,
            ShellCall::UploadStatus { .. } => ShellMethod::UploadStatus,
        }
    }

    /// Main's params for `method`, read strictly.
    pub fn parse(method: ShellMethod, params: &JsValue) -> Result<ShellCall, Invalid> {
        match method {
            ShellMethod::Publish => parse_publish(params).map(ShellCall::Publish),
            ShellMethod::Feed => parse_feed(params).map(ShellCall::Feed),
            ShellMethod::Stamps => {
                let m = Members::of(params, "params", &["id"])?;
                Ok(ShellCall::Stamps { id: m.batch("id")? })
            }
            ShellMethod::UploadStatus => {
                let m = Members::of(params, "params", &["tag_uid"])?;
                // `<uid>`: 1 to 2^53 - 1.
                match safe_integer(m.need("tag_uid")?) {
                    Some(tag_uid) if tag_uid > 0 => Ok(ShellCall::UploadStatus { tag_uid }),
                    _ => Err(m.bad("tag_uid", "not a positive safe integer")),
                }
            }
        }
    }
}

fn parse_publish(params: &JsValue) -> Result<PublishCall, Invalid> {
    let m = Members::of(
        params,
        "params",
        &[
            "kind",
            "parts",
            "name",
            "content_type",
            "index_document",
            "encrypt",
            "batch",
            "pin",
            "deferred",
            "history",
        ],
    )?;
    let kind = match m.need("kind")? {
        JsValue::String(s) if *s == "data" => PublishKind::Data,
        JsValue::String(s) if *s == "file" => PublishKind::File,
        JsValue::String(s) if *s == "collection" => PublishKind::Collection,
        _ => return Err(m.bad("kind", "not data, file or collection")),
    };
    let collection = kind == PublishKind::Collection;
    let JsValue::Array(items) = m.need("parts")? else {
        return Err(m.bad("parts", "not an array"));
    };
    if !collection && items.len() != 1 {
        return Err(m.bad("parts", "one part for data or a file"));
    }
    let mut parts = Vec::with_capacity(items.len());
    let mut named = Seen::new();
    for item in items {
        let part = parse_part(item, collection)?;
        if let Source::Part(k) = part.source
            && !named.first(k)
        {
            return Err(invalid("params.parts", "a part named twice"));
        }
        parts.push(part);
    }
    let name = m.string("name")?.cloned();
    if kind == PublishKind::File && name.as_ref().is_none_or(|n| n.is_empty()) {
        // publishFile's `options.name || path.basename(filePath)`: main
        // names a picked file.
        return Err(m.bad("name", "a file's name is required"));
    }
    if collection && name.is_some() {
        return Err(m.bad("name", "a collection has none"));
    }
    let content_type = m.string("content_type")?.cloned();
    if let Some(ct) = &content_type {
        if collection {
            return Err(m.bad("content_type", "a collection has none"));
        }
        if !header_safe(ct) {
            return Err(m.bad("content_type", "not a header value"));
        }
    }
    let index_document = m.string("index_document")?.cloned();
    if let Some(index) = &index_document {
        if !collection {
            return Err(m.bad("index_document", "only a collection has one"));
        }
        if index.is_empty() || !header_safe(index) {
            return Err(m.bad("index_document", "not a header value"));
        }
    }
    let encrypt = m.boolean("encrypt")?.unwrap_or(false);
    let batch = m.batch("batch")?;
    match m.boolean("pin")? {
        Some(true) => {}
        // The forms admit only `swarm-pin: true`, and every reference
        // caller pins.
        Some(false) => return Err(m.bad("pin", "only true")),
        None => return Err(m.bad("pin", "missing")),
    }
    let deferred = m
        .boolean("deferred")?
        .ok_or_else(|| m.bad("deferred", "missing"))?;
    if collection && !deferred {
        // `bzz_tar` admits only `swarm-deferred-upload: true`.
        return Err(m.bad("deferred", "a collection defers"));
    }
    let history = match m.get("history") {
        None => None,
        Some(value) => {
            let h = Members::of(value, "params.history", &["type", "name"])?;
            let kind = match h.need("type")? {
                JsValue::String(s) if *s == "data" => HistoryKind::Data,
                JsValue::String(s) if *s == "file" => HistoryKind::File,
                JsValue::String(s) if *s == "directory" => HistoryKind::Directory,
                _ => return Err(h.bad("type", "not data, file or directory")),
            };
            let JsValue::String(name) = h.need("name")? else {
                return Err(h.bad("name", "not a string"));
            };
            Some(HistoryEntry {
                kind,
                name: name.clone(),
            })
        }
    };
    Ok(PublishCall {
        kind,
        parts,
        name,
        content_type,
        index_document,
        encrypt,
        batch,
        deferred,
        history,
    })
}

/// A part: `{ path?, bytes, base64 }` (at most 64 KiB) or `{ path?, bytes,
/// part }`; a collection's parts have a path, data and a file's don't.
fn parse_part(value: &JsValue, collection: bool) -> Result<PartSpec, Invalid> {
    let m = Members::of(
        value,
        "params.parts[]",
        &["path", "bytes", "base64", "part"],
    )?;
    let path = m.string("path")?.cloned();
    match (&path, collection) {
        (Some(p), true) if !p.is_empty() => {}
        // bee-js's `assertCollection` refuses a falsy path.
        (_, true) => return Err(m.bad("path", "a collection's part needs one")),
        (None, false) => {}
        (Some(_), false) => return Err(m.bad("path", "only a collection's parts have one")),
    }
    let bytes = m
        .safe_integer("bytes")?
        .ok_or_else(|| m.bad("bytes", "missing"))?;
    if collection && bytes > fc_swarm::tar::MAX_OCTAL_FIELD {
        // A tar entry's size field holds 11 octal digits.
        return Err(m.bad("bytes", "past a tar entry's size field"));
    }
    let source = match (m.get("base64"), m.get("part")) {
        (Some(JsValue::String(text)), None) => {
            let data = decode_base64(text.as_str())
                .filter(|d| d.len() as u64 == bytes && d.len() <= INLINE_BYTES)
                .ok_or_else(|| m.bad("base64", "not base64 of its bytes, at most 64 KiB"))?;
            Source::Inline(data)
        }
        (None, Some(k)) => {
            let k = safe_integer(k)
                .and_then(|k| u32::try_from(k).ok())
                .ok_or_else(|| m.bad("part", "not a part number"))?;
            Source::Part(k)
        }
        _ => return Err(m.bad("base64", "exactly one of base64 and part")),
    };
    Ok(PartSpec {
        path,
        bytes,
        source,
    })
}

fn parse_feed(params: &JsValue) -> Result<FeedCall, Invalid> {
    let m = Members::of(
        params,
        "params",
        &[
            "op",
            "key",
            "owner",
            "topic",
            "reference",
            "min_index",
            "batch",
        ],
    )?;
    let (update, read) = match m.need("op")? {
        JsValue::String(s) if *s == "create" => (false, false),
        JsValue::String(s) if *s == "update" => (true, false),
        JsValue::String(s) if *s == "read" => (false, true),
        _ => return Err(m.bad("op", "not create, update or read")),
    };
    // SW-1: main's own feeds take only the Bee wallet key.
    let key = Members::of(m.need("key")?, "params.key", &["kind"])?;
    match key.need("kind")? {
        JsValue::String(s) if *s == "bee_wallet" => {}
        _ => return Err(key.bad("kind", "only bee_wallet")),
    }
    // The owner main showed, in `<o>`'s form (K2).
    let owner =
        owner_hex(m.need("owner")?).ok_or_else(|| m.bad("owner", "not 40 lowercase hex"))?;
    let topic = hex_bytes::<32>(m.need("topic")?).ok_or_else(|| m.bad("topic", "not 64 hex"))?;
    let batch = m.batch("batch")?;
    if read && batch.is_some() {
        return Err(m.bad("batch", "a read writes nothing"));
    }
    let op = if update {
        let reference = match m.need("reference")? {
            v @ JsValue::String(s) if s.len() == 64 => hex_bytes::<32>(v).map(|b| b.to_vec()),
            v @ JsValue::String(s) if s.len() == 128 => hex_bytes::<64>(v).map(|b| b.to_vec()),
            _ => None,
        }
        .ok_or_else(|| m.bad("reference", "not 64 or 128 hex"))?;
        let min_index = m.safe_integer("min_index")?.unwrap_or(0);
        FeedOp::Update {
            reference,
            min_index,
        }
    } else {
        if m.get("reference").is_some() {
            return Err(m.bad("reference", "only an update has one"));
        }
        if m.get("min_index").is_some() {
            return Err(m.bad("min_index", "only an update has one"));
        }
        if read { FeedOp::Read } else { FeedOp::Create }
    };
    Ok(FeedCall {
        op,
        owner,
        topic,
        batch,
    })
}

// ---------------------------------------------------------------------------
// The request.

/// A method's step.
pub(crate) enum ShellStep {
    Wait,
    Done(ShellOutcome),
}

/// The method, running.
enum Running {
    Publish(Box<shell_publish::ShellPublish>),
    Feed(Box<shell_feed::ShellFeed>),
    Stamps(shell_stamps::ShellStamps),
    Status(shell_status::ShellStatus),
}

impl Running {
    fn on<W: World>(&mut self, cx: &mut Cx<'_, W>, id: AskId, event: Event) -> ShellStep {
        match self {
            Running::Publish(m) => m.on(cx, id, event),
            Running::Feed(m) => m.on(cx, id, event),
            Running::Stamps(m) => m.on(id, event),
            Running::Status(m) => m.on(id, event),
        }
    }
}

/// One shell parent: `swarm.publish`, `swarm.feed`, `swarm.stamps` or
/// `swarm.upload_status`, moved as a `swarm.request` is: its effects taken
/// and done, each answer handed back, until its outcome.
pub struct Shell {
    method: ShellMethod,
    running: Option<Running>,
    asks: Asks,
    outcome: Option<ShellOutcome>,
    /// After the outcome, what a publish's history row still waits for.
    after: Option<After>,
    /// No page: the key a [`Cx`] reads is empty, and nothing reads it.
    origin: JsString,
}

impl Shell {
    /// Starts the call: the method's first asks.
    pub fn start<W: World>(call: ShellCall, world: &mut W) -> Shell {
        let mut shell = Shell {
            method: call.method(),
            running: None,
            asks: Asks::default(),
            outcome: None,
            after: None,
            origin: JsString::default(),
        };
        let mut cx = Cx {
            world,
            origin: &shell.origin,
            asks: &mut shell.asks,
        };
        let started = match call {
            ShellCall::Publish(call) => shell_publish::ShellPublish::start(&mut cx, call)
                .map(|m| Running::Publish(Box::new(m))),
            ShellCall::Feed(call) => Ok(Running::Feed(Box::new(shell_feed::ShellFeed::start(
                &mut cx, call,
            )))),
            ShellCall::Stamps { id } => Ok(Running::Stamps(shell_stamps::ShellStamps::start(
                &mut cx, id,
            ))),
            ShellCall::UploadStatus { tag_uid } => Ok(Running::Status(
                shell_status::ShellStatus::start(&mut cx, tag_uid),
            )),
        };
        match started {
            Ok(running) => shell.running = Some(running),
            Err(outcome) => shell.finish(outcome),
        }
        shell
    }

    /// Hands the request main's answer (or a part of it) to ask `id`.
    pub fn answer<W: World>(&mut self, world: &mut W, id: AskId, event: Event) {
        if self.outcome.is_some() {
            // Taken and dropped, as for `swarm.request`: an ask stays open
            // until its own terminal answer; a body main asks for now still
            // gets its terminal; a history row waiting for a write moves on.
            let admitted = self.asks.admit(id, &event);
            if admitted.is_ok() {
                self.asks.terminate_body(id, &event);
                After::answer(&mut self.asks, &mut self.after, id, event);
            }
            return;
        }
        let cancelled = match self.asks.admit(id, &event) {
            Ok(cancelled) => cancelled,
            Err(protocol) => return self.finish(ShellOutcome::Protocol(protocol)),
        };
        if cancelled {
            self.asks.terminate_body(id, &event);
            return;
        }
        self.step(world, id, event);
    }

    fn step<W: World>(&mut self, world: &mut W, id: AskId, event: Event) {
        let Some(running) = self.running.as_mut() else {
            return self.finish(ShellOutcome::Protocol(Protocol::UnknownAsk));
        };
        let mut cx = Cx {
            world,
            origin: &self.origin,
            asks: &mut self.asks,
        };
        if let ShellStep::Done(outcome) = running.on(&mut cx, id, event) {
            self.finish(outcome);
        }
    }

    /// D13: ask `id` of main went past its own bound ([`ask_bound`]). It is
    /// cancelled, and the method reads it as `failed: error`; the request
    /// ends, its history row `failed` with that failure's text. Main's
    /// terminal answer, when it comes, is taken and dropped. Nothing for
    /// an ask that isn't main's, already answered, or already cancelled.
    pub fn expire<W: World>(&mut self, world: &mut W, id: AskId) {
        if self.outcome.is_some() {
            return;
        }
        let expirable = self.asks.open.get(&id).is_some_and(|open| {
            !open.cancelled
                && matches!(
                    open.kind,
                    Kind::Ready | Kind::Whole { .. } | Kind::Stream { .. } | Kind::Part { .. }
                )
        });
        if !expirable {
            return;
        }
        self.asks.cancel(id);
        self.step(world, id, Event::Failed(Failed::Error));
    }

    /// Main cancelled the request, or its deadline passed.
    pub fn cancel(&mut self) {
        if self.outcome.is_none() {
            self.finish(ShellOutcome::Cancelled);
        }
    }

    /// A memory reservation that waited past its bound
    /// ([`Deadline::memory_wait_ms`]): the protocol error `busy`.
    pub fn busy(&mut self) {
        if self.outcome.is_none() {
            self.finish(ShellOutcome::Busy);
        }
    }

    fn finish(&mut self, outcome: ShellOutcome) {
        let mut running = self.running.take();
        if let Some(Running::Publish(m)) = running.as_mut()
            && let Some(terminal) = m.end(&outcome)
        {
            self.asks.effects.push(terminal);
        }
        self.asks.cancel_all();
        let closing = match &running {
            Some(Running::Publish(m)) => m.closing(&outcome),
            _ => None,
        };
        After::of(&mut self.asks, &mut self.after, closing);
        self.outcome = Some(outcome);
    }

    /// The effects since the last call, in order.
    pub fn take_effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.asks.effects)
    }

    /// How the request ended, once it has.
    pub fn outcome(&self) -> Option<&ShellOutcome> {
        self.outcome.as_ref()
    }

    /// Asks not yet answered, cancelled ones included.
    pub fn open_asks(&self) -> usize {
        self.asks.open.len()
    }

    pub fn method(&self) -> ShellMethod {
        self.method
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn parse(method: ShellMethod, text: &str) -> Result<ShellCall, Invalid> {
        ShellCall::parse(method, &fc_json::parse(text).unwrap())
    }

    #[test]
    fn rows_as_d5_gives_them() {
        assert_eq!(
            ShellMethod::ALL.map(|m| (m.name(), m.callers(), m.deadline())),
            [
                ("swarm.publish", Callers::Shell, Deadline::Idle),
                ("swarm.feed", Callers::Shell, Deadline::Swarm),
                ("swarm.stamps", Callers::ChromeAndShell, Deadline::Swarm),
                (
                    "swarm.upload_status",
                    Callers::ChromeAndShell,
                    Deadline::Swarm
                ),
            ]
        );
        assert!(ShellMethod::ALL.iter().all(|m| m.gated()));
        assert_eq!(
            ShellMethod::from_name("swarm.feed"),
            Some(ShellMethod::Feed)
        );
        assert_eq!(ShellMethod::from_name("swarm.request"), None);
        assert_eq!(Deadline::Swarm.total_ms(None), Some(300_000));
        assert_eq!(Deadline::Swarm.total_ms(Some(10_000)), Some(10_000));
        assert_eq!(Deadline::Swarm.total_ms(Some(900_000)), Some(300_000));
        assert_eq!(Deadline::Idle.total_ms(Some(10_000)), None);
        assert_eq!(Deadline::Idle.memory_wait_ms(None), Some(60_000));
        assert_eq!(Deadline::Swarm.memory_wait_ms(Some(10_000)), Some(10_000));
    }

    #[test]
    fn bounds_as_d13_gives_them() {
        use crate::machine::node::{Body, Form, NodeCall};
        let upload = |body| {
            Need::Node(NodeCall::upload(
                Form::BzzTar,
                "/bzz",
                Vec::new(),
                Vec::new(),
                body,
            ))
        };
        let idle = Deadline::Idle;
        assert_eq!(
            ask_bound(idle, &Need::Node(NodeCall::stamps())),
            AskBound::Total(300_000)
        );
        assert_eq!(
            ask_bound(idle, &upload(Body::Stream { bytes: 9 })),
            AskBound::BodyThenReply {
                idle: 60_000,
                total: 300_000
            }
        );
        assert_eq!(
            ask_bound(idle, &upload(Body::Base64(vec![1]))),
            AskBound::Total(300_000)
        );
        assert_eq!(ask_bound(idle, &Need::Part(0)), AskBound::Idle(60_000));
        assert_eq!(
            ask_bound(
                idle,
                &Need::Node(NodeCall::feed_latest(&[0; 20], &[0; 32], 9))
            ),
            AskBound::Idle(60_000)
        );
        assert_eq!(ask_bound(idle, &Need::Upload), AskBound::None);
        assert_eq!(
            ask_bound(Deadline::Swarm, &Need::Node(NodeCall::stamps())),
            AskBound::Deadline
        );
        assert_eq!(ask_bound(Deadline::Swarm, &Need::Upload), AskBound::None);
    }

    #[test]
    fn params_are_read_strictly() {
        let ok = parse(
            ShellMethod::Publish,
            r#"{"kind":"data","parts":[{"bytes":5,"base64":"aGVsbG8="}],"pin":true,"deferred":false}"#,
        )
        .unwrap();
        let ShellCall::Publish(call) = ok else {
            panic!("a publish")
        };
        assert_eq!(call.parts[0].source, Source::Inline(b"hello".to_vec()));
        for (method, text, why) in [
            (
                ShellMethod::Publish,
                r#"{"kind":"data","parts":[{"bytes":5,"base64":"aGVsbG8="}],"pin":true,"deferred":false,"extra":1}"#,
                "params: an unknown member extra",
            ),
            (
                ShellMethod::Publish,
                r#"{"kind":"data","parts":[{"bytes":4,"base64":"aGVsbG8="}],"pin":true,"deferred":false}"#,
                "params.parts[].base64: not base64 of its bytes, at most 64 KiB",
            ),
            (
                ShellMethod::Publish,
                r#"{"kind":"data","parts":[{"bytes":5,"part":0}],"pin":false,"deferred":false}"#,
                "params.pin: only true",
            ),
            (
                ShellMethod::Publish,
                r#"{"kind":"data","parts":[{"bytes":5,"part":0}],"pin":true}"#,
                "params.deferred: missing",
            ),
            (
                ShellMethod::Publish,
                r#"{"kind":"file","parts":[{"bytes":5,"part":0}],"pin":true,"deferred":true}"#,
                "params.name: a file's name is required",
            ),
            (
                ShellMethod::Publish,
                r#"{"kind":"collection","parts":[{"bytes":5,"part":0}],"pin":true,"deferred":true}"#,
                "params.parts[].path: a collection's part needs one",
            ),
            (
                ShellMethod::Publish,
                r#"{"kind":"collection","parts":[{"path":"a","bytes":5,"part":0}],"pin":true,"deferred":false}"#,
                "params.deferred: a collection defers",
            ),
            (
                ShellMethod::Publish,
                r#"{"kind":"collection","parts":[{"path":"a","bytes":5,"part":0},{"path":"b","bytes":1,"part":0}],"pin":true,"deferred":true}"#,
                "params.parts: a part named twice",
            ),
            (
                ShellMethod::Publish,
                r#"{"kind":"data","parts":[{"bytes":5,"part":0}],"content_type":"テキスト","pin":true,"deferred":false}"#,
                "params.content_type: not a header value",
            ),
            (
                ShellMethod::Publish,
                r#"{"kind":"data","parts":[],"pin":true,"deferred":false}"#,
                "params.parts: one part for data or a file",
            ),
            (
                ShellMethod::Feed,
                r#"{"op":"create","key":{"kind":"publisher"},"topic":"00"}"#,
                "params.key.kind: only bee_wallet",
            ),
            (
                ShellMethod::Feed,
                r#"{"op":"update","key":{"kind":"bee_wallet"},"owner":"1111111111111111111111111111111111111111","topic":"00"}"#,
                "params.topic: not 64 hex",
            ),
            // K2: the owner main showed, in `<o>`'s form only.
            (
                ShellMethod::Feed,
                r#"{"op":"read","key":{"kind":"bee_wallet"},"topic":"00"}"#,
                "params.owner: missing",
            ),
            (
                ShellMethod::Feed,
                r#"{"op":"read","key":{"kind":"bee_wallet"},"owner":"0x1111111111111111111111111111111111111111","topic":"00"}"#,
                "params.owner: not 40 lowercase hex",
            ),
            (
                ShellMethod::Feed,
                r#"{"op":"read","key":{"kind":"bee_wallet"},"owner":"6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0","topic":"00"}"#,
                "params.owner: not 40 lowercase hex",
            ),
            (
                ShellMethod::Feed,
                r#"{"op":"read","key":{"kind":"bee_wallet"},"owner":"111111111111111111111111111111111111111","topic":"00"}"#,
                "params.owner: not 40 lowercase hex",
            ),
            (
                ShellMethod::Feed,
                r#"{"op":"read","key":{"kind":"bee_wallet"},"owner":null,"topic":"00"}"#,
                "params.owner: not 40 lowercase hex",
            ),
            (
                ShellMethod::Stamps,
                r#"{"id":"0xab"}"#,
                "params.id: not 64 hex digits",
            ),
            (
                ShellMethod::UploadStatus,
                r#"{"tag_uid":0}"#,
                "params.tag_uid: not a positive safe integer",
            ),
            (
                ShellMethod::UploadStatus,
                r#"{"tag_uid":9007199254740992}"#,
                "params.tag_uid: not a positive safe integer",
            ),
            (ShellMethod::UploadStatus, "[]", "params: not an object"),
        ] {
            assert_eq!(parse(method, text).unwrap_err().0, why, "{text}");
        }
        let topic = "AB".repeat(32);
        let call = parse(
            ShellMethod::Feed,
            &format!(
                r#"{{"op":"update","key":{{"kind":"bee_wallet"}},"owner":"{}","topic":"{topic}","reference":"{}"}}"#,
                "e0".repeat(20),
                "cd".repeat(64)
            ),
        )
        .unwrap();
        assert_eq!(
            call,
            ShellCall::Feed(FeedCall {
                op: FeedOp::Update {
                    reference: vec![0xcd; 64],
                    min_index: 0
                },
                owner: [0xe0; 20],
                topic: [0xab; 32],
                batch: None,
            })
        );
    }

    /// A key that counts the comparisons made of it.
    #[derive(Debug)]
    struct Counted<'c>(u32, &'c std::cell::Cell<u64>);

    impl PartialEq for Counted<'_> {
        fn eq(&self, other: &Self) -> bool {
            self.cmp(other).is_eq()
        }
    }
    impl Eq for Counted<'_> {}
    impl PartialOrd for Counted<'_> {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for Counted<'_> {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.1.set(self.1.get() + 1);
            self.0.cmp(&other.0)
        }
    }

    /// The part table's check makes `O(n log n)` comparisons: 100,000
    /// parts in a scrambled order cost a few dozen comparisons each, where
    /// a scan of every earlier part would cost tens of thousands.
    #[test]
    fn a_large_part_table_is_checked_in_n_log_n() {
        let n: u32 = 100_000;
        let compared = std::cell::Cell::new(0u64);
        let mut seen = Seen::new();
        for i in 0..n {
            // Scrambled, and distinct: reversing the bits is a bijection.
            assert!(seen.first(Counted(i.reverse_bits(), &compared)));
        }
        assert!(!seen.first(Counted(7u32.reverse_bits(), &compared)));
        let bound = 16 * u64::from(n) * u64::from(n.ilog2() + 1);
        assert!(
            compared.get() <= bound,
            "{} comparisons for {n} parts, past {bound}",
            compared.get()
        );
        // The whole params, through the parser: a collection of 100,000
        // streamed parts is read, and a part named twice at its end is
        // refused.
        let items: Vec<String> = (0..n)
            .map(|k| format!(r#"{{"path":"f/{k}","bytes":1,"part":{k}}}"#))
            .collect();
        let params = |extra: &str| {
            format!(
                r#"{{"kind":"collection","parts":[{}{extra}],"pin":true,"deferred":true}}"#,
                items.join(",")
            )
        };
        let ShellCall::Publish(call) = parse(ShellMethod::Publish, &params("")).unwrap() else {
            panic!("a publish")
        };
        assert_eq!(call.parts.len(), n as usize);
        assert_eq!(
            parse(
                ShellMethod::Publish,
                &params(r#",{"path":"g","bytes":1,"part":99999}"#)
            )
            .unwrap_err()
            .0,
            "params.parts: a part named twice"
        );
    }

    #[test]
    fn errors_carry_what_their_callers_read() {
        let err = ShellError::postage(&PostageError {
            code: crate::stamps::PostageCode::CapacityInsufficient,
            capacity: Capacity {
                upload_bytes: 4096.0,
                required_bytes: 6144.0,
                largest_remaining_bytes: 10.0,
            },
        });
        assert_eq!(
            err.to_value(),
            Value::object([
                (
                    "message",
                    Value::str(
                        "No postage batch has enough capacity for this upload. Select or purchase a suitable batch."
                    )
                ),
                ("code", Value::str("POSTAGE_CAPACITY_INSUFFICIENT")),
                (
                    "capacity",
                    Value::object([
                        ("uploadBytes", Value::Number(4096.0)),
                        ("requiredBytes", Value::Number(6144.0)),
                        ("largestRemainingBytes", Value::Number(10.0)),
                    ])
                ),
            ])
        );
        assert_eq!(failed(Failed::Busy), ShellOutcome::Busy);
        assert_eq!(failed(Failed::Stopped), error("Swarm node is not ready"));
    }
}
