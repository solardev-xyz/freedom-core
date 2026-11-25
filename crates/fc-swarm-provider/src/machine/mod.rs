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
//!   reserves before the call goes), work for the hashing pool, and, for the
//!   pieces to come, a payload part (`shell.swarm_part`), a signature (the
//!   vault, with SW-1's hold), a store write (0013's durable write) and a
//!   GSOC search (the mining lane).
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

pub mod node;
pub mod page;
pub(crate) mod params;

pub use node::{
    Abort, Body, CHUNK_REPLY_CAP, Failed, FeedRef, Form, Head, NodeCall, Reply, Rule, TreeRef,
    stream_charge, whole_charge,
};
pub use page::Failure;

use crate::budgets::{self, ReadBudgets};
use crate::errors::INVALID_PARAMS;
use crate::methods;
use crate::stores::history::Statement;
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

/// What the swarm thread holds that every request reads.
pub trait World: Reads {
    /// The clock: `Date.now()`, in milliseconds.
    fn now(&self) -> u64;
    /// The read budgets (`READ_BUDGETS`' buckets), one for every request.
    fn budgets(&mut self) -> &mut ReadBudgets;
}

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
    /// params, streamed (the Publish and write pieces).
    Part(u32),
    /// A signature from the vault (the Feeds and SOCs piece).
    Sign(SignSoc),
    /// A durable write of a store (0013), or the history's statements.
    Write(StoreWrite),
    /// A GSOC signer search on the mining lane (the Messaging piece).
    Mine(MineJob),
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
}

/// A signing key reference (design 0002): never key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignKey {
    BeeWallet,
    Publisher(u32),
}

/// A store write.
#[derive(Debug, Clone, PartialEq)]
pub enum StoreWrite {
    /// `swarm-feeds.json`'s text.
    Feeds(String),
    /// `publish-history.sqlite`'s statements, in order.
    History(Vec<Statement>),
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
    /// The mining lane's answer.
    Mined(Mined),
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
}

/// A method the later pieces bring (the Publish group, feed and SOC
/// writes, Messaging): this part's machines answer only the Access and
/// Reads methods.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0} has no machine yet")]
pub struct NotBuilt(pub String);

pub(crate) enum Step {
    Wait,
    Done(Outcome),
}

/// What an open ask expects.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Ready,
    Whole {
        max: usize,
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
    Mine,
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
            },
            Need::Hash(_) => Kind::Hash,
            Need::Part(_) => Kind::Part {
                head: false,
                received: 0,
                window: node::WINDOW,
            },
            Need::Sign(_) => Kind::Sign,
            Need::Write(_) => Kind::Write,
            Need::Mine(_) => Kind::Mine,
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
            // Work on the hashing pool can't be called back; its result is
            // dropped when it comes.
            if open.kind != Kind::Hash {
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
            (Kind::Whole { max }, Event::Reply(reply)) => {
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
            | (Kind::Mine, Event::Mined(_)) => true,
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
}

/// The request's method, running.
enum Running {
    Capabilities(methods::access::Capabilities),
    ReadChunk(methods::chunk_reads::ReadChunk),
    ReadSoc(methods::chunk_reads::ReadSoc),
    ReadData(methods::read_data::ReadData),
    ReadFeed(methods::feed_read::ReadFeed),
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
        use methods::{access, chunk_reads, feed_read, read_data};
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
        self.running = None;
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
