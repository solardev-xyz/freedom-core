//! The method machines' framework (design 0015, "In the core" >
//! "Crates"): sans-I/O, each machine asks for what it needs and is handed
//! the answer.
//!
//! **One [`Request`] per `swarm.request`.** The swarm thread starts it with
//! the call main sent ([`Call`]: the method, the typed params, the page's
//! attested key, the approval) and then only moves it: it takes the
//! request's [`Effect`]s, does each, and hands back each answer with
//! [`Request::answer`], until [`Request::outcome`] is set. Main's cancel
//! and the request's deadline are [`Request::cancel`] (deviation
//! `deadlines`); a memory reservation still waiting at the deadline is
//! [`Request::busy`].
//!
//! **What a machine needs comes two ways:**
//! - **Asks** ([`Need`]), answered later, each with an [`AskId`]: a
//!   readiness check (`shell.swarm_ready`), a node call (`shell.swarm_api`,
//!   with what it costs the swarm thread's memory, which the thread
//!   reserves before the call goes), work for the hashing pool, a payload
//!   part (`shell.swarm_part`), a streaming upload's turn, a store write
//!   (0013's durable write, or the history's statements), and, for the
//!   pieces to come, a signature (the vault, with SW-1's hold) and a GSOC
//!   search (the mining lane). A node call whose body streams is answered
//!   with main's `swarm.body` and its credit too, and the request writes
//!   that body ([`Effect::Body`]).
//! - **A request that ends without its machine** (a cancel, its deadline,
//!   `busy`, a protocol error) still makes the one write its method needs
//!   then: an upload's history row ends `failed`.
//! - **The world** ([`World`]), read synchronously on the swarm thread
//!   between two answers: the clock, the Swarm grants (0012) and the feed
//!   store (part 2's [`Reads`]), and the read budgets every request
//!   shares. A check and the charge that follows it are one step, as
//!   in the reference.
//!
//! **Answers are read strictly** (design 0015, "Requests the core makes"):
//! an answer of the wrong kind for its ask, a stream's data before its
//! head or past its credit, a frame outside 1 to 65,536 bytes, a reply
//! past its cap or outside the header bounds ends the request with a
//! protocol error ([`Outcome::Protocol`]). An answer to an ask the machine
//! cancelled is taken and dropped, as is any answer after the outcome.

use std::collections::BTreeMap;

use fc_json::JsString;

pub mod keeper;
pub mod node;
pub mod page;
pub(crate) mod params;

pub use node::{
    Abort, Body, BodyAbort, BodyOut, CHUNK_REPLY_CAP, Failed, FeedRef, Form, Head, JSON_REPLY_CAP,
    MAX_FRAME, NodeCall, Reply, Rule, TreeRef, stream_charge, whole_charge,
};
pub use page::Failure;

use crate::budgets::{self, ReadBudgets};
use crate::errors::INVALID_PARAMS;
use crate::methods;
use crate::stores::feeds::FeedChange;
use crate::stores::history::Statement;
pub use crate::stores::manifests::Capability;
pub use crate::stores::manifests::Reads;
use crate::stores::manifests::Save;
use crate::stores::origin::normalize_origin;
use crate::value::Value;

/// `KNOWN_METHODS` (swarm-provider-ipc.js).
pub const KNOWN_METHODS: [&str; 21] = [
    "swarm_requestAccess",
    "swarm_getCapabilities",
    "swarm_publishData",
    "swarm_publishFiles",
    "swarm_getUploadStatus",
    "swarm_createFeed",
    "swarm_updateFeed",
    "swarm_writeFeedEntry",
    "swarm_readFeedEntry",
    "swarm_listFeeds",
    "swarm_publishChunk",
    "swarm_readChunk",
    "swarm_readData",
    "swarm_writeSingleOwnerChunk",
    "swarm_readSingleOwnerChunk",
    "swarm_getSigningIdentity",
    "swarm_getMessagingIdentity",
    "swarm_subscribe",
    "swarm_unsubscribe",
    "swarm_sendPss",
    "swarm_sendGsoc",
];

pub use methods::upload_status::TagOwners;

/// What the swarm thread holds that every request reads.
pub trait World: Reads {
    /// The clock: `Date.now()`, in milliseconds.
    fn now(&self) -> u64;
    /// The read budgets (`READ_BUDGETS`' buckets), one for every request.
    fn budgets(&mut self) -> &mut ReadBudgets;
    /// Whether the document that sent the request under `key` still holds
    /// it: 0012's `transport_key` check, which the core makes again before
    /// each effect (design 0015, "Methods main calls": name checks), as
    /// page-swarm.js's `nameHolds` and `holdsKey` do.
    fn key_holds(&self, key: &JsString) -> bool;
    /// Whether the agent holds that document's tab now (0012's `agent`,
    /// read live): a request a site's rule approved reads it again before
    /// its effect (design 0015, "What moves into the core": the rules).
    fn agent(&self, key: &JsString) -> bool;
    /// Which site owns each upload's tag (`tagOwnership`, session-scoped).
    fn tags(&mut self) -> &mut TagOwners;
}

/// What a streaming upload's turn reserves in the swarm thread's memory:
/// one incoming and one outgoing window, the chunker's state and a tar
/// header (design 0015, "Bounds": about 300 KiB).
pub const UPLOAD_CHARGE: usize = 300 * 1024;

/// How many uploads stream at once (design 0015, "Bounds"); the rest wait
/// for a turn ([`Need::Upload`]).
pub const STREAMING_UPLOADS: usize = 4;

/// How main approved a request (`approval`): its prompt, or a standing
/// rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    User,
    Auto,
}

/// `swarm.request`, as the machines read it.
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    /// The method, as main sent it.
    pub method: Value,
    /// The params, in the typed form.
    pub params: Value,
    /// The page's attested key (0011); empty for a document with none.
    pub key: JsString,
    pub approval: Option<Approval>,
}

/// An ask's number within its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AskId(pub u64);

/// What a machine asks for.
#[derive(Debug, Clone, PartialEq)]
pub struct Ask {
    pub id: AskId,
    pub need: Need,
    /// What the answer may hold in the swarm thread's memory, reserved
    /// before the ask goes (design 0015, "The swarm thread's memory"); 0
    /// for an ask that brings no bytes in.
    pub charge: usize,
}

/// `shell.swarm_ready`'s checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadyCheck {
    /// `getPublishReadiness()`.
    Publish,
    /// The 5 s `GET /node` probe.
    Reachable,
    /// The probe after the proxy check (question 4).
    Subscribe,
}

impl ReadyCheck {
    pub fn as_str(self) -> &'static str {
        match self {
            ReadyCheck::Publish => "publish",
            ReadyCheck::Reachable => "reachable",
            ReadyCheck::Subscribe => "subscribe",
        }
    }
}

/// Every kind of ask the 21 methods make.
#[derive(Debug, Clone, PartialEq)]
pub enum Need {
    /// `shell.swarm_ready { check }`, once, before any node call.
    Ready(ReadyCheck),
    /// `shell.swarm_api`.
    Node(NodeCall),
    /// Work for 0009's hashing pool: [`Job::run`] there, and hand back its
    /// [`JobDone`].
    Hash(Job),
    /// `shell.swarm_part { part }`: one payload part of the request's own
    /// params, streamed: [`Event::PartHead`], then its bytes within the
    /// credit the machine gives. Its bytes are held under the upload's
    /// turn ([`Need::Upload`]), so the ask's charge is 0.
    Part(u32),
    /// A turn among the [`STREAMING_UPLOADS`] uploads that stream at once,
    /// with [`UPLOAD_CHARGE`] reserved: [`Event::Turn`] once one is free.
    /// The turn is the request's until it ends.
    Upload,
    /// A signature from the vault (the Feeds and SOCs piece).
    Sign(SignSoc),
    /// A durable write of a store (0013), or the history's statements.
    Write(StoreWrite),
    /// A GSOC signer search on the mining lane (the Messaging piece).
    Mine(MineJob),
    /// The vault: a signing key's owner address (swarm-signer.js's
    /// `resolveSwarmSigner`), which needs the unlocked vault. Answered
    /// [`Event::Owner`].
    Owner(SignKey),
    /// Writes to one topic go one at a time (feed-service.js's
    /// `withWriteLock`): answered [`Event::Locked`] once no other request
    /// holds `topic`, which this request then holds until it ends.
    Lock([u8; 32]),
}

/// What the vault signs: a SOC over `span ‖ payload` with `identifier`,
/// under `key`. `hold` is SW-1's: from this ask until its answer, the
/// swarm thread defers every store change that could change the re-check
/// the machine just made for that key (design 0015, "SW-1 in the core").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignSoc {
    pub key: SignKey,
    pub identifier: [u8; 32],
    pub span: u64,
    pub payload: Vec<u8>,
    pub hold: Option<JsString>,
    /// What the SOC is, the authorization's `soc` (0012, "A page's SOC").
    pub kind: SocKind,
}

/// A page's SOC: a feed write's update, or a raw single-owner chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocKind {
    Feed,
    Raw,
}

impl SocKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SocKind::Feed => "feed",
            SocKind::Raw => "raw",
        }
    }
}

/// A signing key reference (design 0002): never key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignKey {
    BeeWallet,
    Publisher(u32),
}

/// A store write. A write can't be called back: once asked it is made,
/// and its answer is dropped if the machine no longer waits for it.
#[derive(Debug, Clone, PartialEq)]
pub enum StoreWrite {
    /// A change to `swarm-feeds.json`, made through SW-1's keeper
    /// ([`keeper::Keeper::change`]) and written durably before it is
    /// answered.
    Feeds(FeedChange),
    /// `publish-history.sqlite`'s statements, in order.
    History(Vec<Statement>),
    /// One `INSERT` into `publish-history.sqlite`, answered with the new
    /// row's rowid ([`Event::Inserted`]).
    HistoryInsert(Statement),
    /// `swarm-manifest-grants.json`.
    Manifests(Save),
}

/// A GSOC search (`gsoc::Miner`): the first signer whose SOC address
/// shares `proximity` leading bits with `target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MineJob {
    pub target: [u8; 32],
    pub identifier: [u8; 32],
    pub proximity: u8,
}

/// What the request asks of the swarm thread, in order.
#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    Ask(Ask),
    /// The machine no longer waits for this ask: send `cancel`. Its
    /// terminal answer still comes, and is taken.
    Cancel(AskId),
    /// Credit for a stream the machine took bytes of.
    Credit {
        id: AskId,
        bytes: usize,
    },
    /// The next part of a node call's streamed body (`swarm.body`'s answer
    /// to main, for call `id`): its head once main asked for it
    /// ([`Event::BodyOpen`]), then its bytes within main's window, then
    /// one terminal. A cancel of the call also ends its body `cancelled`.
    Body {
        id: AskId,
        out: BodyOut,
    },
}

/// Main's answer to an ask, or a part of it.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// `shell.swarm_ready`'s `{ ok: true }` or `{ ok: false, reason }`.
    Ready(Result<(), JsString>),
    /// A whole reply; for a streamed form, an error status (answered
    /// whole, its body at most 8 KiB).
    Reply(Reply),
    /// A streamed reply's head (a 2xx).
    Head(Head),
    /// The next bytes of a stream: a part's or a reply's.
    Data(Vec<u8>),
    End,
    Abort(Abort),
    /// `{ failed }`, before any reply.
    Failed(Failed),
    /// `invalid_argument` with its rule: main's grammar refused the call.
    Refused(Rule),
    /// The hashing pool's result.
    Hashed(JobDone),
    /// A part's head: its length.
    PartHead(u64),
    /// The vault's signature and the key's owner, or its refusal.
    Signed(Result<Signed, JsString>),
    /// The store write's outcome: its failure's text.
    Written(Result<(), JsString>),
    /// A history insert's rowid, or its failure's text.
    Inserted(Result<i64, JsString>),
    /// The upload's turn.
    Turn,
    /// Main's `swarm.body { for }` for a call whose body streams: the core
    /// sends the head, then the bytes within a window of
    /// [`node::WINDOW`], which [`Event::BodyCredit`] extends.
    BodyOpen,
    /// Main's credit on a streamed body.
    BodyCredit(usize),
    /// The mining lane's answer.
    Mined(Mined),
    /// The vault's answer to [`Need::Owner`]: the owner, `None` while the
    /// vault is locked, or the vault's failure.
    Owner(Result<Option<[u8; 20]>, JsString>),
    /// The topic is this request's ([`Need::Lock`]).
    Locked,
}

/// A SOC signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signed {
    pub signature: [u8; 65],
    pub owner: [u8; 20],
}

/// What a GSOC search found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mined {
    /// The signer's index from bee-js's first key.
    Found(u32),
    /// No signer within the search's cap (`gsoc_mining_failed`).
    Exhausted,
    /// The job's 15 s passed (`gsoc_mining_timeout`).
    Timeout,
}

pub use methods::read_data::{Job, JobDone};

/// How a request ended.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// `{ result }`.
    Result(Value),
    /// `{ error }`.
    Error(Failure),
    /// Cancelled by main or past its deadline: answered `cancelled`, with
    /// nothing more asked.
    Cancelled,
    /// Main broke the protocol: answered -32603 `Internal error`.
    Protocol(Protocol),
}

/// How main broke the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Protocol {
    #[error("an answer to no open ask")]
    UnknownAsk,
    #[error("an answer of another kind than its ask")]
    WrongKind,
    #[error("a reply past its cap or outside the header bounds")]
    Bounds,
    #[error("a stream's second head")]
    SecondHead,
    #[error("stream data before the head")]
    BeforeHead,
    #[error("an empty data frame, or one past 65,536 bytes")]
    Frame,
    #[error("stream data past the credit given")]
    BeyondCredit,
    #[error("stream data past max_bytes")]
    PastMax,
    #[error("a part that isn't the length its params gave")]
    PartLength,
}

/// A method the later piece brings (Messaging): the machines so far
/// answer Access, the Reads, the Publish group, and the feed and SOC
/// writes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0} has no machine yet")]
pub struct NotBuilt(pub String);

pub(crate) enum Step {
    Wait,
    Done(Outcome),
}

/// A whole call's streamed body, as main has asked for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyState {
    /// The call's body is inline, or absent.
    None,
    /// It streams, and main hasn't asked for it yet.
    Waiting,
    Open,
}

/// What an open ask expects.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Ready,
    Whole {
        max: usize,
        body: BodyState,
    },
    Stream {
        max: u64,
        head: bool,
        received: u64,
        window: u64,
    },
    Hash,
    Part {
        head: bool,
        received: u64,
        window: u64,
    },
    Sign,
    Write,
    Insert,
    Turn,
    Mine,
    Owner,
    Lock,
}

#[derive(Debug)]
struct Open {
    kind: Kind,
    cancelled: bool,
}

#[derive(Debug, Default)]
pub(crate) struct Asks {
    next: u64,
    open: BTreeMap<AskId, Open>,
    effects: Vec<Effect>,
}

impl Asks {
    fn push(&mut self, need: Need, charge: usize) -> AskId {
        self.next += 1;
        let id = AskId(self.next);
        let kind = match &need {
            Need::Ready(_) => Kind::Ready,
            Need::Node(call) if call.stream() => Kind::Stream {
                max: call.max_bytes as u64,
                head: false,
                received: 0,
                window: node::WINDOW,
            },
            Need::Node(call) => Kind::Whole {
                max: call.max_bytes,
                body: match call.body {
                    Some(Body::Stream { .. }) => BodyState::Waiting,
                    _ => BodyState::None,
                },
            },
            Need::Hash(_) => Kind::Hash,
            Need::Part(_) => Kind::Part {
                head: false,
                received: 0,
                window: node::WINDOW,
            },
            Need::Sign(_) => Kind::Sign,
            Need::Write(StoreWrite::HistoryInsert(_)) => Kind::Insert,
            Need::Write(_) => Kind::Write,
            Need::Upload => Kind::Turn,
            Need::Mine(_) => Kind::Mine,
            Need::Owner(_) => Kind::Owner,
            Need::Lock(_) => Kind::Lock,
        };
        self.open.insert(
            id,
            Open {
                kind,
                cancelled: false,
            },
        );
        self.effects.push(Effect::Ask(Ask { id, need, charge }));
        id
    }

    fn cancel(&mut self, id: AskId) {
        if let Some(open) = self.open.get_mut(&id)
            && !open.cancelled
        {
            open.cancelled = true;
            // Work on the hashing pool and a store write can't be called
            // back; the answer is dropped when it comes.
            if !matches!(open.kind, Kind::Hash | Kind::Write | Kind::Insert) {
                self.effects.push(Effect::Cancel(id));
            }
        }
    }

    fn cancel_all(&mut self) {
        let ids: Vec<AskId> = self.open.keys().copied().collect();
        for id in ids {
            self.cancel(id);
        }
    }

    /// Checks `event` against its ask, and closes the ask on its terminal
    /// answer: whether the machine had cancelled it, or how the answer
    /// breaks the protocol.
    fn admit(&mut self, id: AskId, event: &Event) -> Result<bool, Protocol> {
        let open = self.open.get_mut(&id).ok_or(Protocol::UnknownAsk)?;
        let terminal = match (&mut open.kind, event) {
            (_, Event::Refused(_)) => true,
            (Kind::Ready, Event::Ready(_)) => true,
            (Kind::Whole { body, .. }, Event::BodyOpen) => {
                if *body != BodyState::Waiting {
                    return Err(Protocol::WrongKind);
                }
                *body = BodyState::Open;
                false
            }
            (Kind::Whole { body, .. }, Event::BodyCredit(bytes)) => {
                if *body != BodyState::Open {
                    return Err(Protocol::WrongKind);
                }
                if *bytes == 0 {
                    return Err(Protocol::Frame);
                }
                false
            }
            (Kind::Whole { max, .. }, Event::Reply(reply)) => {
                let cap = if reply.ok() { *max } else { node::ERROR_BODY };
                if !node::reply_in_bounds(reply.status, &reply.status_text, &reply.headers)
                    || reply.body.len() > cap
                {
                    return Err(Protocol::Bounds);
                }
                true
            }
            (Kind::Whole { .. }, Event::Failed(_)) => true,
            (Kind::Stream { head: false, .. }, Event::Reply(reply)) => {
                if reply.ok()
                    || !node::reply_in_bounds(reply.status, &reply.status_text, &reply.headers)
                    || reply.body.len() > node::ERROR_BODY
                {
                    return Err(Protocol::Bounds);
                }
                true
            }
            (Kind::Stream { head: false, .. }, Event::Failed(_)) => true,
            (Kind::Stream { head, .. }, Event::Head(h)) => {
                if *head {
                    return Err(Protocol::SecondHead);
                }
                if !(200..300).contains(&h.status)
                    || !node::reply_in_bounds(h.status, &h.status_text, &h.headers)
                {
                    return Err(Protocol::Bounds);
                }
                *head = true;
                false
            }
            (
                Kind::Stream {
                    max,
                    head,
                    received,
                    window,
                },
                Event::Data(bytes),
            ) => {
                if !*head {
                    return Err(Protocol::BeforeHead);
                }
                frame(bytes.len(), received, *window)?;
                if *received > *max {
                    return Err(Protocol::PastMax);
                }
                false
            }
            (
                Kind::Part {
                    head,
                    received,
                    window,
                },
                Event::Data(bytes),
            ) => {
                if !*head {
                    return Err(Protocol::BeforeHead);
                }
                frame(bytes.len(), received, *window)?;
                false
            }
            (Kind::Stream { head, .. } | Kind::Part { head, .. }, Event::End | Event::Abort(_)) => {
                if !*head {
                    return Err(Protocol::BeforeHead);
                }
                true
            }
            (Kind::Part { head, .. }, Event::PartHead(_)) => {
                if *head {
                    return Err(Protocol::SecondHead);
                }
                *head = true;
                false
            }
            (Kind::Part { head: false, .. }, Event::Failed(_)) => true,
            (Kind::Hash, Event::Hashed(_))
            | (Kind::Sign, Event::Signed(_))
            | (Kind::Write, Event::Written(_))
            | (Kind::Insert, Event::Inserted(_))
            | (Kind::Turn, Event::Turn)
            | (Kind::Mine, Event::Mined(_))
            | (Kind::Owner, Event::Owner(_))
            | (Kind::Lock, Event::Locked) => true,
            _ => return Err(Protocol::WrongKind),
        };
        let cancelled = open.cancelled;
        if terminal {
            self.open.remove(&id);
        }
        Ok(cancelled)
    }

    fn credit(&mut self, id: AskId, bytes: usize) {
        if bytes == 0 {
            return;
        }
        if let Some(open) = self.open.get_mut(&id)
            && let Kind::Stream { window, .. } | Kind::Part { window, .. } = &mut open.kind
        {
            *window += bytes as u64;
            self.effects.push(Effect::Credit { id, bytes });
        }
    }
}

fn frame(len: usize, received: &mut u64, window: u64) -> Result<(), Protocol> {
    if len == 0 || len > node::MAX_FRAME {
        return Err(Protocol::Frame);
    }
    *received += len as u64;
    if *received > window {
        return Err(Protocol::BeyondCredit);
    }
    Ok(())
}

/// What a machine reaches while it handles one answer.
pub(crate) struct Cx<'a, W> {
    pub world: &'a mut W,
    /// `normalizeOrigin(key)`: the key the request reads and charges under.
    pub origin: &'a JsString,
    asks: &'a mut Asks,
}

impl<W: World> Cx<'_, W> {
    /// `getPermission(origin)`: the site has the connection grant.
    pub fn connected(&self) -> bool {
        self.world.connected(self.origin)
    }

    /// `getReadBudget(origin).maxBytes`.
    pub fn max_bytes(&self) -> u64 {
        budgets::budget(self.connected()).max_bytes
    }

    /// `consumePermissionFreeReadBudget(origin, { requests, bytes })`.
    pub fn consume(&mut self, requests: u64, bytes: u64) -> Result<(), Failure> {
        let connected = self.connected();
        let now = self.world.now();
        self.world
            .budgets()
            .consume(self.origin, connected, now, requests, bytes)
    }

    /// `reservePermissionFreeReadBytes(origin, bytes)`.
    pub fn reserve(&mut self, bytes: u64) -> Result<(), Failure> {
        let connected = self.connected();
        let now = self.world.now();
        self.world
            .budgets()
            .reserve(self.origin, connected, now, bytes)
    }

    /// What is left of the site's bytes in this window.
    pub fn room(&mut self) -> u64 {
        let connected = self.connected();
        let now = self.world.now();
        self.world.budgets().room(self.origin, connected, now)
    }

    pub fn ready(&mut self, check: ReadyCheck) -> AskId {
        self.asks.push(Need::Ready(check), 0)
    }

    /// A whole node call, charged its form's cap.
    pub fn whole(&mut self, call: NodeCall) -> AskId {
        let charge = whole_charge(call.form);
        self.asks.push(Need::Node(call), charge)
    }

    /// A streamed read for the page that may hold `holds` bytes.
    pub fn stream(&mut self, call: NodeCall, holds: u64) -> AskId {
        let charge = stream_charge(usize::try_from(holds).unwrap_or(usize::MAX));
        self.asks.push(Need::Node(call), charge)
    }

    /// Work for the hashing pool. Its bytes are already held under the
    /// charge of the call that brought them.
    pub fn hash(&mut self, job: Job) -> AskId {
        self.asks.push(Need::Hash(job), 0)
    }

    pub fn credit(&mut self, id: AskId, bytes: usize) {
        self.asks.credit(id, bytes);
    }

    /// A payload part of the request's own params.
    pub fn part(&mut self, part: u32) -> AskId {
        self.asks.push(Need::Part(part), 0)
    }

    /// A streaming upload's turn, with its memory.
    pub fn turn(&mut self) -> AskId {
        self.asks.push(Need::Upload, UPLOAD_CHARGE)
    }

    /// A store write.
    pub fn write(&mut self, write: StoreWrite) -> AskId {
        self.asks.push(Need::Write(write), 0)
    }

    /// The next part of call `id`'s streamed body.
    pub fn body(&mut self, id: AskId, out: BodyOut) {
        self.asks.effects.push(Effect::Body { id, out });
    }

    /// The machine no longer waits for ask `id`.
    pub fn cancel(&mut self, id: AskId) {
        self.asks.cancel(id);
    }

    /// `getAutoApprove(origin, capability)`: the site's standing rule.
    pub fn auto_approve(&self, capability: Capability) -> bool {
        self.world.auto_approve(self.origin, capability)
    }

    /// The document still holds the request's key (0012's
    /// `transport_key`).
    pub fn key_holds(&self) -> bool {
        self.world.key_holds(self.origin)
    }

    /// The agent holds the document's tab (0012's `agent`).
    pub fn agent(&self) -> bool {
        self.world.agent(self.origin)
    }

    /// The vault: a key's owner.
    pub fn owner(&mut self, key: SignKey) -> AskId {
        self.asks.push(Need::Owner(key), 0)
    }

    /// The topic's turn among the writes to it.
    pub fn lock(&mut self, topic: [u8; 32]) -> AskId {
        self.asks.push(Need::Lock(topic), 0)
    }

    /// A signature from the vault.
    pub fn sign(&mut self, soc: SignSoc) -> AskId {
        self.asks.push(Need::Sign(soc), 0)
    }
}

/// The request's method, running.
enum Running {
    Capabilities(methods::access::Capabilities),
    ReadChunk(methods::chunk_reads::ReadChunk),
    ReadSoc(methods::chunk_reads::ReadSoc),
    ReadData(methods::read_data::ReadData),
    ReadFeed(methods::feed_read::ReadFeed),
    Publish(Box<methods::publish::Publish>),
    UploadStatus(methods::upload_status::UploadStatus),
    Signing(methods::signing::Signing),
    CreateFeed(methods::create_feed::CreateFeed),
    FeedWrite(Box<methods::feed_write::FeedWrite>),
    SocWrite(methods::soc_write::SocWrite),
}

impl Running {
    /// What a method still writes when the request ends without its
    /// machine (a cancel, the deadline, `busy`, a protocol error): an
    /// upload's history row ends `failed` (design 0015, "Deadlines and
    /// cancel").
    fn closing(&self, outcome: &Outcome) -> Option<StoreWrite> {
        match self {
            Running::Publish(m) => m.closing(outcome),
            Running::CreateFeed(m) => m.closing(outcome),
            Running::FeedWrite(m) => m.closing(outcome),
            Running::SocWrite(m) => m.closing(outcome),
            _ => None,
        }
    }
}

/// One `swarm.request`.
pub struct Request {
    origin: JsString,
    running: Option<Running>,
    asks: Asks,
    outcome: Option<Outcome>,
}

impl Request {
    /// Starts the request: `executeSwarmMethod`'s checks of the method,
    /// then the method's machine, which validates its params in today's
    /// order and makes its first asks.
    pub fn start<W: World>(call: &Call, world: &mut W) -> Result<Request, NotBuilt> {
        let mut request = Request {
            origin: JsString::from(normalize_origin(call.key.as_str())),
            running: None,
            asks: Asks::default(),
            outcome: None,
        };
        let method = match &call.method {
            Value::String(s) if !s.is_empty() => s.clone(),
            _ => {
                request.outcome = Some(Outcome::Error(Failure::bare(
                    INVALID_PARAMS,
                    "Method is required",
                )));
                return Ok(request);
            }
        };
        if !KNOWN_METHODS.iter().any(|m| method == *m) {
            request.outcome = Some(Outcome::Error(Failure::bare(
                page::UNSUPPORTED_METHOD,
                crate::js::concat(&[&JsString::from("Unknown method: "), &method]),
            )));
            return Ok(request);
        }
        let origin = request.origin.clone();
        let mut cx = Cx {
            world,
            origin: &origin,
            asks: &mut request.asks,
        };
        let params = &call.params;
        use methods::{access, chunk_reads, feed_read, publish, read_data, upload_status};
        use methods::{create_feed, feed_write, signing, soc_write};
        let started = match method.as_str() {
            "swarm_requestAccess" => Err(access::request_access(&mut cx)),
            "swarm_getCapabilities" => {
                access::Capabilities::start(&mut cx).map(Running::Capabilities)
            }
            "swarm_listFeeds" => Err(access::list_feeds(&mut cx)),
            "swarm_readChunk" => {
                chunk_reads::ReadChunk::start(&mut cx, params).map(Running::ReadChunk)
            }
            "swarm_readSingleOwnerChunk" => {
                chunk_reads::ReadSoc::start(&mut cx, params).map(Running::ReadSoc)
            }
            "swarm_readData" => read_data::ReadData::start(&mut cx, params).map(Running::ReadData),
            "swarm_readFeedEntry" => {
                feed_read::ReadFeed::start(&mut cx, params).map(Running::ReadFeed)
            }
            "swarm_publishData" | "swarm_publishFiles" | "swarm_publishChunk" => {
                publish::Publish::start(&mut cx, method.as_str(), params, call.approval)
                    .map(|m| Running::Publish(Box::new(m)))
            }
            "swarm_getUploadStatus" => {
                upload_status::UploadStatus::start(&mut cx, params).map(Running::UploadStatus)
            }
            "swarm_getSigningIdentity" => {
                signing::Signing::start(&mut cx, call.approval).map(Running::Signing)
            }
            "swarm_createFeed" => create_feed::CreateFeed::start(&mut cx, params, call.approval)
                .map(Running::CreateFeed),
            "swarm_updateFeed" => feed_write::FeedWrite::update(&mut cx, params, call.approval)
                .map(|m| Running::FeedWrite(Box::new(m))),
            "swarm_writeFeedEntry" => feed_write::FeedWrite::entry(&mut cx, params, call.approval)
                .map(|m| Running::FeedWrite(Box::new(m))),
            "swarm_writeSingleOwnerChunk" => {
                soc_write::SocWrite::start(&mut cx, params, call.approval).map(Running::SocWrite)
            }
            other => return Err(NotBuilt(other.to_owned())),
        };
        match started {
            Ok(running) => request.running = Some(running),
            Err(outcome) => request.finish(outcome),
        }
        Ok(request)
    }

    /// Hands the request main's answer (or a part of it) to ask `id`.
    pub fn answer<W: World>(&mut self, world: &mut W, id: AskId, event: Event) {
        if self.outcome.is_some() {
            // Taken and dropped: the request has its answer.
            self.asks.open.remove(&id);
            return;
        }
        let cancelled = match self.asks.admit(id, &event) {
            Ok(admitted) => admitted,
            Err(protocol) => return self.finish(Outcome::Protocol(protocol)),
        };
        if cancelled {
            return;
        }
        let Some(running) = self.running.as_mut() else {
            return self.finish(Outcome::Protocol(Protocol::UnknownAsk));
        };
        let mut cx = Cx {
            world,
            origin: &self.origin,
            asks: &mut self.asks,
        };
        let step = match running {
            Running::Capabilities(m) => m.on(&mut cx, id, event),
            Running::ReadChunk(m) => m.on(&mut cx, id, event),
            Running::ReadSoc(m) => m.on(&mut cx, id, event),
            Running::ReadData(m) => m.on(&mut cx, id, event),
            Running::ReadFeed(m) => m.on(&mut cx, id, event),
            Running::Publish(m) => m.on(&mut cx, id, event),
            Running::UploadStatus(m) => m.on(&mut cx, id, event),
            Running::Signing(m) => m.on(&mut cx, id, event),
            Running::CreateFeed(m) => m.on(&mut cx, id, event),
            Running::FeedWrite(m) => m.on(&mut cx, id, event),
            Running::SocWrite(m) => m.on(&mut cx, id, event),
        };
        if let Step::Done(outcome) = step {
            self.finish(outcome);
        }
    }

    /// Main cancelled the request, or its deadline passed: every open ask
    /// is cancelled and the request answers `cancelled`.
    pub fn cancel(&mut self) {
        if self.outcome.is_none() {
            self.finish(Outcome::Cancelled);
        }
    }

    /// A reservation that waited until the request's deadline: the request
    /// ends 4900 `busy` (deviation `busy`).
    pub fn busy(&mut self) {
        if self.outcome.is_none() {
            self.finish(Outcome::Error(Failure::busy()));
        }
    }

    fn finish(&mut self, outcome: Outcome) {
        self.asks.cancel_all();
        if let Some(write) = self.running.take().and_then(|m| m.closing(&outcome)) {
            // The one ask after the outcome: a write isn't called back, and
            // its answer is dropped.
            self.asks.push(Need::Write(write), 0);
        }
        self.outcome = Some(outcome);
    }

    /// The effects since the last call, in order.
    pub fn take_effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.asks.effects)
    }

    /// How the request ended, once it has.
    pub fn outcome(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }

    /// Asks not yet answered, cancelled ones included.
    pub fn open_asks(&self) -> usize {
        self.asks.open.len()
    }

    /// The key the request reads and charges under.
    pub fn origin(&self) -> &JsString {
        &self.origin
    }
}

/// A step's outcome from a page error.
pub(crate) fn fail(failure: Failure) -> Step {
    Step::Done(Outcome::Error(failure))
}

/// A step's outcome from a result.
pub(crate) fn done(value: Value) -> Step {
    Step::Done(Outcome::Result(value))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::stores::feeds::FeedStore;
    use crate::stores::manifests::Capability;

    struct Plain {
        budgets: ReadBudgets,
        feeds: FeedStore,
        tags: TagOwners,
    }

    impl Reads for Plain {
        fn connected(&self, _key: &JsString) -> bool {
            true
        }
        fn messaging(&self, _key: &JsString) -> bool {
            false
        }
        fn auto_approve(&self, _key: &JsString, _capability: Capability) -> bool {
            false
        }
        fn feeds(&self) -> &FeedStore {
            &self.feeds
        }
    }

    impl World for Plain {
        fn now(&self) -> u64 {
            1000
        }
        fn budgets(&mut self) -> &mut ReadBudgets {
            &mut self.budgets
        }
        fn key_holds(&self, _key: &JsString) -> bool {
            true
        }
        fn agent(&self, _key: &JsString) -> bool {
            false
        }
        fn tags(&mut self) -> &mut TagOwners {
            &mut self.tags
        }
    }

    fn world() -> Plain {
        Plain {
            budgets: ReadBudgets::new(),
            feeds: FeedStore::empty(),
            tags: TagOwners::new(),
        }
    }

    fn call(method: &str, params: Value) -> Call {
        Call {
            method: Value::str(method),
            params,
            key: JsString::from("https://a.example"),
            approval: None,
        }
    }

    /// `readFeedEntry` of the latest entry, past its readiness check: the
    /// request and its `feed_latest` ask.
    fn latest(w: &mut Plain) -> (Request, AskId) {
        let params = Value::object([
            ("topic", Value::str(&"ab".repeat(32))),
            ("owner", Value::str(&"cd".repeat(20))),
        ]);
        let mut r = Request::start(&call("swarm_readFeedEntry", params), w).unwrap();
        let Some(Effect::Ask(ready)) = r.take_effects().pop() else {
            panic!("the ready check")
        };
        assert_eq!(ready.need, Need::Ready(ReadyCheck::Reachable));
        r.answer(w, ready.id, Event::Ready(Ok(())));
        let Some(Effect::Ask(ask)) = r.take_effects().pop() else {
            panic!("the stream")
        };
        let Need::Node(node) = &ask.need else {
            panic!("a node call")
        };
        assert_eq!(node.form, Form::FeedLatest);
        assert_eq!(node.max_bytes, 5 * 1024 * 1024);
        assert_eq!(ask.charge, stream_charge(5 * 1024 * 1024));
        (r, ask.id)
    }

    fn head() -> Event {
        Event::Head(Head {
            status: 200,
            status_text: "OK".into(),
            headers: vec![
                ("swarm-feed-index".into(), "0000000000000001".into()),
                ("swarm-feed-index-next".into(), "0000000000000002".into()),
            ],
        })
    }

    #[test]
    fn answers_are_read_strictly() {
        let mut w = world();
        let (mut r, id) = latest(&mut w);
        r.answer(&mut w, AskId(99), Event::End);
        assert_eq!(r.outcome(), Some(&Outcome::Protocol(Protocol::UnknownAsk)));

        let (mut r, id2) = latest(&mut w);
        assert_eq!(id, id2);
        r.answer(&mut w, id, Event::Data(vec![1]));
        assert_eq!(r.outcome(), Some(&Outcome::Protocol(Protocol::BeforeHead)));

        let (mut r, _) = latest(&mut w);
        r.answer(&mut w, id, head());
        r.answer(&mut w, id, Event::Data(vec![0; MAX_FRAME + 1]));
        assert_eq!(r.outcome(), Some(&Outcome::Protocol(Protocol::Frame)));

        let (mut r, _) = latest(&mut w);
        r.answer(&mut w, id, Event::Ready(Ok(())));
        assert_eq!(r.outcome(), Some(&Outcome::Protocol(Protocol::WrongKind)));
    }

    #[test]
    fn credit_follows_what_the_machine_takes() {
        let mut w = world();
        let (mut r, id) = latest(&mut w);
        r.answer(&mut w, id, head());
        // Past the first window (two frames): each frame credited back as
        // the machine takes it.
        for _ in 0..3 {
            r.answer(&mut w, id, Event::Data(vec![7; MAX_FRAME]));
            assert_eq!(
                r.take_effects(),
                vec![Effect::Credit {
                    id,
                    bytes: MAX_FRAME
                }]
            );
        }
        r.answer(&mut w, id, Event::End);
        let Some(Outcome::Result(value)) = r.outcome() else {
            panic!("{:?}", r.outcome())
        };
        assert_eq!(value.get("index"), &Value::int(1));
        assert_eq!(value.get("nextIndex"), &Value::int(2));
    }

    #[test]
    fn a_cancel_ends_it_and_drops_what_comes_after() {
        let mut w = world();
        let (mut r, id) = latest(&mut w);
        r.cancel();
        assert_eq!(r.take_effects(), vec![Effect::Cancel(id)]);
        assert_eq!(r.outcome(), Some(&Outcome::Cancelled));
        r.answer(&mut w, id, head());
        r.answer(&mut w, id, Event::End);
        assert_eq!(r.outcome(), Some(&Outcome::Cancelled));
        assert!(r.take_effects().is_empty());
        r.busy();
        assert_eq!(r.outcome(), Some(&Outcome::Cancelled));

        let (mut r, _) = latest(&mut w);
        r.busy();
        assert_eq!(r.outcome(), Some(&Outcome::Error(Failure::busy())));
    }

    #[test]
    fn a_refused_call_is_an_internal_error() {
        let mut w = world();
        let (mut r, id) = latest(&mut w);
        r.answer(&mut w, id, Event::Refused(Rule::Value));
        assert_eq!(
            r.outcome(),
            Some(&Outcome::Error(Failure::internal_error()))
        );
    }

    #[test]
    fn the_method_comes_first() {
        let mut w = world();
        let r = Request::start(&call("", Value::Undefined), &mut w).unwrap();
        assert_eq!(
            r.outcome(),
            Some(&Outcome::Error(Failure::bare(-32602, "Method is required")))
        );
        let r = Request::start(&call("toString", Value::Undefined), &mut w).unwrap();
        assert_eq!(
            r.outcome(),
            Some(&Outcome::Error(Failure::bare(
                4200,
                "Unknown method: toString"
            )))
        );
        assert_eq!(
            Request::start(&call("swarm_sendPss", Value::Undefined), &mut w).err(),
            Some(NotBuilt("swarm_sendPss".into()))
        );
    }
}
