//! The swarm thread's engine (design 0015, "In the core"; SWM-4): each
//! `swarm.request`'s method machine ([`Request`]), what it asks of main and
//! of the thread, and the bounds they share. It does no I/O: the thread
//! hands it main's messages and the naming verdicts, and it acts through an
//! [`Io`], which the tests fake.
//!
//! - **At the door** (D2, D3, D5): a request needs the Swarm grants moved
//!   (`not_moved`, `data.store: "swarm"`, otherwise); its params are read
//!   strictly (`invalid_argument`); a method that touches the stores
//!   answers `not_moved` (`data.store: "swarm_stores"`) until `core.hello`
//!   names `swarm_stores` in `store_moved` ([`Shared::stores_moved`]), and
//!   `swarm_unsubscribe` is `invalid_argument` (main answers it itself)
//!   ([`Door`]).
//! - **Admission** (design 0015, "Budgets"): at most
//!   [`RUNNING_REQUESTS`] run, at most [`WAITING_REQUESTS`] wait in order,
//!   and past that a request is `busy` at once: 4900 inside `{
//!   error_typed }` for the page (D5). An admitted request reserves its
//!   base ([`REQUEST_CHARGE`]) before its machine starts.
//! - **The deadline** (D5's `swarm` kind): 300 s from arrival, or the
//!   page's shorter `deadline_ms`. At it a request that waits for a place,
//!   for its base or for a charge ends `busy`; a running one is cancelled
//!   ([`Request::cancel`], answered `cancelled`: deviation `deadlines`).
//! - **Memory** ([`memory`]): every ask's charge is reserved, first in,
//!   first out, before the ask goes. A whole call's charge is freed once
//!   the step that consumes its reply has ended; a cancelled call's only
//!   once main's terminal answer has been read and dropped (D13: the ask
//!   keeps its charge and its slot among main's 256 until then, and the
//!   transport ends the connection if main doesn't answer within 60 s of
//!   the cancel); a request's base at its end, once its answer has been
//!   written ([`Engine::written`], the reply hold's guard).
//! - **Node calls:** at most [`API_CALLS`] `shell.swarm_api` are
//!   outstanding at once, a cancelled one included until main's answer;
//!   the rest wait in order. Every ask of main goes through the core's one
//!   gate in the order it became ready ([`Io::send`]).
//! - **The live facts** (D1): a naming check when the page's
//!   `PageContext.transport_key` binds its key ([`Io::name_check`]), then
//!   `approval.recheck` to main, assembled into [`Event::Live`]. A name
//!   that no longer serves the key answers at once, with no recheck: every
//!   guard reads the name first.
//! - **A topic's writes** go one at a time, in order ([`Locks`]), and at
//!   most [`STREAMING_UPLOADS`] uploads stream at once ([`Turns`]), each
//!   held until its request's answer.
//! - **A subscription's close** (D16) is never cancelled and carries its
//!   own bound: unanswered [`CLOSE_BOUND_MS`] after it was asked, it ends
//!   the connection ([`Fault`]).
//! - **Streams** (design 0015, "Streams"; the [`streams`] module): a
//!   streamed node reply (`bytes`, `feed_latest`) and a part
//!   (`shell.swarm_part`) each take one of the [`SWARM_STREAMS`] incoming
//!   streams' slots (D4: 4 MiB of 128 KiB windows) before they go, and hold
//!   it until main's terminal for the stream; a node reply's also holds its
//!   call's slot. A `swarm.body` main asks for one of the thread's calls
//!   whose body streams is answered from its machine's [`Effect::Body`],
//!   within main's credit; its route closes once main has answered the
//!   call, or cancelled the body, and a credit for it after that is a
//!   protocol error (D4). An upload's part and body that make no
//!   progress for [`IDLE_MS`] end the upload (D13), and a stream the
//!   thread cancelled that main hasn't ended [`IDLE_MS`] later ends the
//!   connection.
//! - **Hashing** (D9): `readData`'s leaf checks go to the thread's own
//!   pool ([`Io::hash`]); the request stays until each result is back.
//! - **The stores** (design 0015, "The stores"; [`super::stores`]): every
//!   write is made at its ask, synchronously and in the order asked, and
//!   answered in that order ("SWM-4 must apply feed-store writes in
//!   order"). A feed store change goes through SW-1's keeper
//!   ([`Shared::keeper`]), which keeps it in memory only once its durable
//!   write ([`Io::write_feeds`]) succeeded; the history's statements and
//!   the manifest store's saves go to the files ([`Io::history`],
//!   [`Io::history_insert`], [`Io::save_manifests`]).
//! - **The vault** (D15; [`VaultAsk`]): a key's owner and a SOC's
//!   signature are asked of the event loop, which holds the vault
//!   ([`Io::vault`]), and answered to [`Engine::vaulted`]. A raw SOC's
//!   signature holds its site's key in the keeper (SW-1's hold,
//!   [`SignSoc::hold`]) from its ask until the vault answers, or the
//!   machine cancels the ask (its request's cancel or deadline): the
//!   changes the hold defers apply then, in order, before the machine takes
//!   the signature, and their callers are answered. A late signature is
//!   dropped. The sign ask carries D15's inputs: the page's key, its
//!   custody as main last reported it (the latest live facts, else its
//!   `PageContext`), how main approved the request, and the site's feed
//!   grant in the keeper's store.
//! - **What this step leaves for later:** the mining lane (PR 8: until it
//!   comes every GSOC search is answered [`Mined::Off`], mining off) and
//!   main's own methods (PR 9).
//!
//! [`memory`]: super::memory
//! [`CLOSE_BOUND_MS`]: fc_swarm_provider::machine::CLOSE_BOUND_MS
//! [`SWARM_STREAMS`]: crate::transport::SWARM_STREAMS

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use fc_approval::stores::{SwarmFlag, SwarmStore};
use fc_eip1193::names::{Binding, Document};
use fc_json::JsString;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::message::PageContext;
use fc_protocol::stream::Codes;
use fc_swarm_provider::budgets::ReadBudgets;
use fc_swarm_provider::machine::keeper::{ChangeAnswer, ChangeError, HoldId, Keeper, Ran, Ticket};
use fc_swarm_provider::machine::node::{ERROR_BODY, b64};
use fc_swarm_provider::machine::shell::Deadline;
use fc_swarm_provider::machine::{
    Approval, AskId, Body, BodyOut, Call, Capability, Effect, Event, Failed, Failure, Job,
    KNOWN_METHODS, Live, Mined, Need, NotBuilt, Outcome, Protocol, REQUEST_CHARGE,
    RUNNING_REQUESTS, Reads, Request, STREAMING_UPLOADS, SignKey, SignSoc, StoreWrite, TagOwners,
    WAITING_REQUESTS, World,
};
use fc_swarm_provider::stores::feeds::{FeedChange, FeedStore};
use fc_swarm_provider::stores::history::Statement;
use fc_swarm_provider::stores::manifests::{ManifestStore, Save};
use fc_swarm_provider::value::Value;

use super::memory::{self, Pool};
use super::stream;
use super::wire::{self, Params, Refusal};
use crate::eip1193::Bindings;
use crate::transport::{SWARM_STREAMS, StreamKey};

mod streams;

/// Milliseconds on the thread's monotonic clock.
pub type Ms = u64;

/// Outstanding `shell.swarm_api` calls at most (design 0015, "Budgets").
pub const API_CALLS: usize = 64;

/// An upload's idle bound (design 0015, "Bounds"; D13): a part and its
/// `swarm.body` with no bytes and no credit from main for this long end the
/// upload, beside main's own idle bound; and a stream the thread cancelled
/// that main hasn't ended this long after ends the connection.
pub const IDLE_MS: Ms = 60_000;

/// The bit that marks the swarm thread's name checks' tags: the event loop
/// routes their verdicts here (a page's EIP-1193 checks are tagged with
/// their request's id, below 2^53).
pub const NAME_TAG: u64 = 1 << 62;

/// The room a small answer of main's takes, serialized: a readiness
/// answer, a recheck, a subscription's id or its failure, a close.
const SMALL_REPLY: usize = 16 * 1024;

/// What a whole reply's serialized form takes beside its body's base64:
/// the reply's room in the swarm thread's memory (design 0015, "The swarm
/// thread's memory").
const ENVELOPE: usize = 16 * 1024;

/// The live facts when the page's name no longer serves its key: every
/// guard reads the name first, so the rest isn't asked.
const MOVED: Live = Live {
    name: false,
    live: false,
    agent: false,
};

/// The engine's bounds; the tests use smaller ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub running: usize,
    pub waiting: usize,
    pub api: usize,
    pub memory: usize,
    pub uploads: usize,
    /// Incoming streams at once: parts and streamed node replies (D4).
    pub streams: usize,
    /// The idle bound ([`IDLE_MS`]).
    pub idle_ms: Ms,
}

impl Default for Bounds {
    fn default() -> Self {
        Bounds {
            running: RUNNING_REQUESTS,
            waiting: WAITING_REQUESTS,
            api: API_CALLS,
            memory: memory::POOL,
            uploads: STREAMING_UPLOADS,
            streams: SWARM_STREAMS,
            idle_ms: IDLE_MS,
        }
    }
}

/// Main broke the protocol: a fixed category, never input text. The
/// thread ends the connection (D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault(pub &'static str);

/// A request of the core's to main, for the gate.
pub struct Outgoing {
    pub method: &'static str,
    pub params: Vec<u8>,
    /// The most main's reply may take, serialized (D4).
    pub reply_bound: usize,
    /// The codes main may end the stream its reply opens with, for a
    /// request whose reply may open one (a part, a streamed node reply):
    /// its stream is routed to the thread and registered in its duplex
    /// before the writer has the request.
    pub opens: Option<Codes>,
}

/// What became of an [`Outgoing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    /// Handed to the writer as this request of the core's.
    Id(u64),
    /// Main holds as many of the core's requests as it takes, or the
    /// thread's share of the writer is full: [`Engine::room`] tries again.
    Wait,
    /// It can't go: over one frame, or the core is exiting.
    Refused,
}

/// `swarm.request`'s answer.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    /// The result member's JSON: `{ result_typed }` or `{ error_typed }`.
    Result(String),
    /// A protocol error: `cancelled`, `not_moved`, `invalid_argument`.
    Error(ErrorBody),
}

/// The engine's I/O.
pub trait Io {
    /// One of the core's requests to main, through the core's one gate.
    fn send(&mut self, outgoing: Outgoing) -> Sent;
    /// `cancel` for the core's request `core`, whose answer main must give
    /// within 60 s (D13).
    fn cancel(&mut self, core: u64);
    /// A page's name check (D1): its verdict comes to [`Engine::named`]
    /// under `tag`.
    fn name_check(&mut self, tag: u64, binding: Binding, deadline_ms: u64);
    /// The check under `tag` is no longer wanted.
    fn name_cancel(&mut self, tag: u64);
    /// `swarm.request` `id`'s answer: [`Engine::written`] is told `id` once
    /// the writer has written it.
    fn answer(&mut self, id: u64, answer: Answer);
    /// `Date.now()`, for the machines (D14).
    fn wall_ms(&self) -> u64;
    /// Main's reply to request `core`, sent with [`Outgoing::opens`], has
    /// come: `head` when it opens the stream, with the exact length its
    /// head gave it (a part's). True to hand it on; false when the thread
    /// had cancelled the request (its stream, if it opened one, is dropped
    /// as it comes, until its terminal). A reply the duplex refuses is
    /// main breaking the protocol.
    fn replied(&mut self, core: u64, head: Option<Option<u64>>) -> Result<bool, Fault>;
    /// The machine let go of `bytes` of request `core`'s stream: its credit.
    fn credit(&mut self, core: u64, bytes: usize);
    /// The next part of the core's answer to main's `swarm.body` `body`.
    fn body(&mut self, body: u64, out: BodyOut);
    /// `swarm.body` `body` refused: its one answer.
    fn body_refuse(&mut self, body: u64, error: ErrorBody);
    /// No frame of stream `key` can come any more: its route goes (D4). A
    /// body's is closed: main's credit for it after this is main breaking
    /// the protocol, which the event loop refuses.
    fn forget(&mut self, key: StreamKey);
    /// Work for the thread's hashing pool (D9): its result comes to
    /// [`Engine::hashed`] for request `id`'s ask `ask`.
    fn hash(&mut self, id: u64, ask: AskId, job: Job);
    /// `swarm-feeds.json`'s durable write of `text` (0013), which the
    /// keeper makes before it keeps a change: `Err` with the text a caller
    /// reads.
    fn write_feeds(&mut self, text: &str) -> Result<(), JsString>;
    /// `swarm-manifest-grants.json`'s save.
    fn save_manifests(&mut self, save: &Save) -> Result<(), JsString>;
    /// `publish-history.sqlite`'s statements, in order.
    fn history(&mut self, statements: &[Statement]) -> Result<(), JsString>;
    /// One `INSERT` into `publish-history.sqlite`: the new row's rowid.
    fn history_insert(&mut self, statement: &Statement) -> Result<i64, JsString>;
    /// An ask of the vault, which the event loop holds: its answer comes
    /// to [`Engine::vaulted`] under `tag`.
    fn vault(&mut self, tag: u64, ask: VaultAsk);
}

/// What the swarm thread asks of the vault (design 0015, "SW-1 in the
/// core", D15), through the event loop.
#[derive(Debug, Clone, PartialEq)]
pub enum VaultAsk {
    /// [`Need::Owner`]: the key's owner, answered [`Event::Owner`] (`None`
    /// while the vault is locked).
    Owner(SignKey),
    /// [`Need::Sign`]: the SOC's signature and its key's owner, answered
    /// [`Event::Signed`], once 0012's page-SOC decision, run again over
    /// the grants as they stand, covers it (D15).
    Sign(Box<SignAsk>),
}

/// A SOC to sign, with D15's inputs.
#[derive(Debug, Clone, PartialEq)]
pub struct SignAsk {
    pub soc: SignSoc,
    /// `PageContext.origin`: the site's key.
    pub key: String,
    /// The page's custody as main last reported it: the request's latest
    /// live facts, else its `PageContext.agent`.
    pub agent: Option<bool>,
    /// How main approved the request (a method that signs always carries
    /// one; none reads as the user's).
    pub approval: Approval,
    /// The site holds its feed grant in the keeper's store as the
    /// signature is asked (`hasFeedGrant`).
    pub feed_grant: bool,
}

/// What the swarm thread holds that every request reads (design 0015, "In
/// the core"): the Swarm grants, shared with the event loop (D2), the
/// ended name bindings, shared with it too (D1), the feed store in SW-1's
/// keeper and the manifest store (D3: the core's once `swarm_stores` is in
/// `store_moved`), the read budgets and the tags' owners.
pub struct Shared {
    pub grants: Arc<Mutex<SwarmStore>>,
    /// The documents whose name binding has ended, shared with the event
    /// loop's page requests (D1): one record for every method family.
    pub bindings: Bindings,
    /// The feed store and SW-1's holds: every change goes through it.
    pub keeper: Keeper,
    pub manifests: ManifestStore,
    /// `core.hello` named `swarm_stores` in `store_moved` (D3): the stores
    /// are loaded, and the methods that touch them pass the door.
    pub stores_moved: bool,
    pub budgets: ReadBudgets,
    pub tags: TagOwners,
}

impl Shared {
    /// The stores not moved: the feed store empty, the manifest store not
    /// loaded.
    pub fn new(grants: Arc<Mutex<SwarmStore>>, bindings: Bindings) -> Self {
        Shared {
            grants,
            bindings,
            keeper: Keeper::new(FeedStore::empty()),
            manifests: ManifestStore::new(),
            stores_moved: false,
            budgets: ReadBudgets::new(),
            tags: TagOwners::new(),
        }
    }
}

/// One step's world: the grants locked for the step, so a check and the
/// charge that follows it read one store.
struct StepWorld<'a> {
    grants: MutexGuard<'a, SwarmStore>,
    feeds: &'a FeedStore,
    budgets: &'a mut ReadBudgets,
    tags: &'a mut TagOwners,
    now: u64,
}

impl<'a> StepWorld<'a> {
    fn new(shared: &'a mut Shared, now: u64) -> Self {
        StepWorld {
            grants: shared
                .grants
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            feeds: shared.keeper.store(),
            budgets: &mut shared.budgets,
            tags: &mut shared.tags,
            now,
        }
    }
}

fn flag(capability: Capability) -> SwarmFlag {
    match capability {
        Capability::Publish => SwarmFlag::Publish,
        Capability::Feeds => SwarmFlag::Feeds,
        Capability::Signing => SwarmFlag::Signing,
        Capability::Messaging => SwarmFlag::Messaging,
    }
}

impl Reads for StepWorld<'_> {
    fn connected(&self, key: &JsString) -> bool {
        self.grants.entry(key.as_str()).is_some()
    }
    fn messaging(&self, key: &JsString) -> bool {
        self.grants.has_messaging(key.as_str())
    }
    fn auto_approve(&self, key: &JsString, capability: Capability) -> bool {
        self.grants.flag(key.as_str(), flag(capability))
    }
    fn feeds(&self) -> &FeedStore {
        self.feeds
    }
}

impl World for StepWorld<'_> {
    fn now(&self) -> u64 {
        self.now
    }
    fn budgets(&mut self) -> &mut ReadBudgets {
        self.budgets
    }
    fn tags(&mut self) -> &mut TagOwners {
        self.tags
    }
}

/// The methods that read or write the stores (D3): `not_moved` until main
/// hands them over. `readFeedEntry` reads a feed by its name from the feed
/// store.
pub const STORE_METHODS: [&str; 10] = [
    "swarm_listFeeds",
    "swarm_readFeedEntry",
    "swarm_publishData",
    "swarm_publishFiles",
    "swarm_publishChunk",
    "swarm_createFeed",
    "swarm_updateFeed",
    "swarm_writeFeedEntry",
    "swarm_writeSingleOwnerChunk",
    "swarm_getSigningIdentity",
];

/// What the door makes of a request's method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Door {
    /// Its machine runs: the method is served, or it isn't one (the
    /// machine answers that itself, as `executeSwarmMethod` does).
    Run,
    /// It touches the stores, which haven't moved (D3).
    NotMoved,
    /// `swarm_unsubscribe`, which main answers itself (D5).
    Unsubscribe,
}

impl Door {
    pub fn of(method: &Value) -> Door {
        let Value::String(name) = method else {
            return Door::Run;
        };
        if !name.is_well_formed() || !KNOWN_METHODS.contains(&name.as_str()) {
            return Door::Run;
        }
        let name = name.as_str();
        if name == "swarm_unsubscribe" {
            Door::Unsubscribe
        } else if STORE_METHODS.contains(&name) {
            Door::NotMoved
        } else {
            Door::Run
        }
    }
}

/// Who waits for memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Waiter {
    /// A request's base.
    Base(u64),
    /// An ask's charge.
    Ask(u64, AskId),
}

/// Where an ask stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Waiting for its charge.
    Memory,
    /// Its charge held, waiting for one of the node calls' slots.
    Slot,
    /// Waiting for the gate.
    Outbox,
    /// Sent to main as the core's request.
    Sent(u64),
    /// A naming check under this tag.
    Naming(u64),
    /// Waiting for a topic's turn.
    Lock([u8; 32]),
    /// Its charge held, waiting for an upload's turn.
    Turn,
    /// Its charge (and a node reply's call slot) held, waiting for one of
    /// the incoming streams' slots.
    Streams,
    /// Main's head for the core's request `core` came: its stream is open
    /// (or, cancelled, retiring until main's terminal).
    Open(u64),
    /// Asked of the vault under this tag.
    Vault(u64),
}

/// An ask the engine holds, until its terminal answer has been handed back
/// (or dropped, for one cancelled).
struct Ask {
    need: Need,
    charge: usize,
    /// What it holds of the pool.
    held: usize,
    /// It holds one of the node calls' slots.
    api: bool,
    stage: Stage,
    cancelled: bool,
    /// It holds one of the incoming streams' slots.
    stream: bool,
    /// The machine holds it no more: the engine gave it its terminal (the
    /// idle bound), and main's answer is dropped when it comes.
    closed: bool,
    /// A call whose body streams: its body has had its terminal.
    body_ended: bool,
    /// A raw SOC's signature: SW-1's hold on its site's key, until the
    /// vault answers or the ask is cancelled.
    hold: Option<HoldId>,
}

enum Phase {
    /// Waiting for a place.
    Waiting(Params),
    /// Placed, waiting for its base.
    Base(Params),
    Running(Box<Request>),
    /// Answered without its machine.
    Done,
}

struct Slot {
    phase: Phase,
    page: PageContext,
    /// How main approved it.
    approval: Option<Approval>,
    /// Its page's custody as main last reported it (D15's input): its
    /// latest live facts, else its `PageContext`.
    agent: Option<bool>,
    /// The `PageContext` as JSON, for `approval.recheck`.
    page_json: String,
    /// The page's name binding (D1), when its transport key binds its key,
    /// and the document it binds.
    binding: Option<(Binding, Document)>,
    deadline: Ms,
    asks: BTreeMap<AskId, Ask>,
    /// It holds a place among the running.
    placed: bool,
    /// Its base, once reserved.
    base: usize,
    /// What its upload's turn holds, until its answer.
    turn: usize,
    answered: bool,
    written: bool,
    /// When its upload's streams, idle since, end (D13): while a part or a
    /// call whose body streams is out.
    idle: Option<Ms>,
    /// Its jobs on the hashing pool, not yet back.
    hashing: usize,
    /// Its streamed reads' charges, whose bytes are its result's (or on
    /// the hashing pool): they go once it has ended, nothing of it is
    /// open, and its answer has been written.
    kept: usize,
}

/// One write to a topic at a time (feed-service.js's `withWriteLock`):
/// each topic's holder and the requests waiting for it, in order.
#[derive(Debug)]
pub struct Locks<T> {
    topics: BTreeMap<[u8; 32], (u64, VecDeque<T>)>,
}

impl<T> Default for Locks<T> {
    fn default() -> Self {
        Locks {
            topics: BTreeMap::new(),
        }
    }
}

impl<T: Copy> Locks<T> {
    /// Request `holder` asks for `topic`: true when it is its at once; or
    /// `waiter` waits.
    pub fn take(&mut self, topic: [u8; 32], holder: u64, waiter: T) -> bool {
        match self.topics.get_mut(&topic) {
            None => {
                self.topics.insert(topic, (holder, VecDeque::new()));
                true
            }
            Some((held, _)) if *held == holder => true,
            Some((_, queue)) => {
                queue.push_back(waiter);
                false
            }
        }
    }

    /// `holder` ends: its topic goes to the first waiter still wanting it
    /// (`next` names its request, or `None` for one that went), and that
    /// waiter is returned.
    pub fn release(
        &mut self,
        topic: [u8; 32],
        holder: u64,
        mut next: impl FnMut(&T) -> Option<u64>,
    ) -> Option<T> {
        let (held, queue) = self.topics.get_mut(&topic)?;
        if *held != holder {
            return None;
        }
        while let Some(waiter) = queue.pop_front() {
            if let Some(request) = next(&waiter) {
                *held = request;
                return Some(waiter);
            }
        }
        self.topics.remove(&topic);
        None
    }

    /// Topics held.
    #[cfg(test)]
    pub fn held(&self) -> usize {
        self.topics.len()
    }
}

/// The engine. See the module documentation.
pub struct Engine {
    bounds: Bounds,
    /// The Swarm grants are the core's (`grant_moved: swarm`, D2).
    grants_moved: bool,
    shared: Shared,
    slots: BTreeMap<u64, Slot>,
    /// Requests waiting for a place, in order.
    admission: VecDeque<u64>,
    running: usize,
    memory: Pool<Waiter>,
    /// `shell.swarm_api` calls outstanding, cancelled ones included.
    api_open: usize,
    /// Node calls with their charge, waiting for a slot.
    api_queue: VecDeque<(u64, AskId)>,
    /// Asks waiting for the gate, in order.
    outbox: VecDeque<(u64, AskId)>,
    /// The gate or the writer had no room: nothing goes until
    /// [`Engine::room`].
    blocked: bool,
    /// The core's requests to main, by ID.
    sent: BTreeMap<u64, (u64, AskId)>,
    /// Name checks, by tag.
    names: BTreeMap<u64, (u64, AskId)>,
    next_tag: u64,
    locks: Locks<(u64, AskId)>,
    turns: usize,
    turn_queue: VecDeque<(u64, AskId)>,
    /// Each subscription close's bound (D16).
    closes: BTreeMap<(u64, AskId), Ms>,
    /// Bases of requests that ended before their answer was written.
    unwritten: BTreeMap<u64, usize>,
    /// Requests whose base was granted from the queue, to start.
    granted: VecDeque<u64>,
    /// Answers the engine gives itself (a topic's turn, an upload's, a
    /// name that moved), handed back in order.
    ready: VecDeque<(u64, AskId, Event)>,
    /// Requests the engine cancels (an ask it can't serve).
    cancels: VecDeque<u64>,
    /// Incoming streams' slots taken, cancelled ones included until main's
    /// terminal.
    streams_open: usize,
    /// Asks waiting for one, in order.
    stream_queue: VecDeque<(u64, AskId)>,
    /// The core's requests whose stream is open (or retiring), by ID.
    open: BTreeMap<u64, (u64, AskId)>,
    /// Streams the thread cancelled, and when main's terminal for each is
    /// overdue.
    retiring: BTreeMap<u64, Ms>,
    /// Main's `swarm.body` requests, by ID, and the call each is the body
    /// of, until main has answered the call or cancelled the body: at most
    /// one per upload's turn, and those whose call main hasn't answered.
    bodies: BTreeMap<u64, (u64, AskId)>,
    /// Each call whose body main asked for, and that `swarm.body`, until
    /// the body has had its terminal.
    body_of: BTreeMap<(u64, AskId), u64>,
    /// The bodies whose routes the thread closed last (D4), as the event
    /// loop remembers them: a credit for one that was routed here before
    /// its route closed is refused here too.
    closed_bodies: VecDeque<u64>,
    /// Vault asks out, by tag.
    vaults: BTreeMap<u64, (u64, AskId)>,
    next_vault: u64,
    next_hold: u64,
    next_ticket: u64,
    /// Feed store changes a hold defers, and whom to answer.
    tickets: BTreeMap<Ticket, Asker>,
}

/// Who waits for a feed store change a hold deferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asker {
    /// A request's write.
    Ask(u64, AskId),
    /// `test.swarm_feed_change` `id` (D11).
    #[cfg(any(test, feature = "testhooks"))]
    Test(u64),
}

impl Engine {
    pub fn new(bounds: Bounds, shared: Shared, grants_moved: bool) -> Self {
        Engine {
            bounds,
            grants_moved,
            shared,
            slots: BTreeMap::new(),
            admission: VecDeque::new(),
            running: 0,
            memory: Pool::new(bounds.memory),
            api_open: 0,
            api_queue: VecDeque::new(),
            outbox: VecDeque::new(),
            blocked: false,
            sent: BTreeMap::new(),
            names: BTreeMap::new(),
            next_tag: 0,
            locks: Locks::default(),
            turns: 0,
            turn_queue: VecDeque::new(),
            closes: BTreeMap::new(),
            unwritten: BTreeMap::new(),
            granted: VecDeque::new(),
            ready: VecDeque::new(),
            cancels: VecDeque::new(),
            streams_open: 0,
            stream_queue: VecDeque::new(),
            open: BTreeMap::new(),
            retiring: BTreeMap::new(),
            bodies: BTreeMap::new(),
            body_of: BTreeMap::new(),
            closed_bodies: VecDeque::new(),
            vaults: BTreeMap::new(),
            next_vault: 0,
            next_hold: 0,
            next_ticket: 0,
            tickets: BTreeMap::new(),
        }
    }

    /// The world every request reads, for the test hooks (D11).
    #[cfg(any(test, feature = "testhooks"))]
    pub fn shared_mut(&mut self) -> &mut Shared {
        &mut self.shared
    }

    /// What the pool holds.
    #[cfg(any(test, feature = "testhooks"))]
    pub fn memory_used(&self) -> usize {
        self.memory.used()
    }

    /// Requests held (running, waiting, or ended with asks still open).
    #[cfg(any(test, feature = "testhooks"))]
    pub fn requests(&self) -> usize {
        self.slots.len()
    }

    /// Main's `swarm.request` `id` from page `page`, its params read (or
    /// why not).
    pub fn request(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        id: u64,
        params: Result<Params, &'static str>,
        page: Option<PageContext>,
    ) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        if !self.grants_moved {
            io.answer(
                id,
                Answer::Error(
                    ErrorBody::new(
                        ErrorCode::NotMoved,
                        "main still writes the Swarm grants (they aren't in grant_moved)",
                    )
                    .with_data(serde_json::json!({ "store": "swarm" })),
                ),
            );
            return Ok(());
        }
        let (params, page) = match (params, page) {
            (Ok(params), Some(page)) => (params, page),
            (Err(message), _) => {
                io.answer(
                    id,
                    Answer::Error(ErrorBody::new(ErrorCode::InvalidArgument, message)),
                );
                return Ok(());
            }
            (Ok(_), None) => {
                io.answer(
                    id,
                    Answer::Error(ErrorBody::new(
                        ErrorCode::InvalidArgument,
                        "swarm.request needs its page",
                    )),
                );
                return Ok(());
            }
        };
        match Door::of(&params.method) {
            Door::Run => {}
            Door::NotMoved if self.shared.stores_moved => {}
            Door::NotMoved => {
                io.answer(
                    id,
                    Answer::Error(
                        ErrorBody::new(
                            ErrorCode::NotMoved,
                            "main still writes the Swarm stores (they aren't in store_moved)",
                        )
                        .with_data(serde_json::json!({ "store": "swarm_stores" })),
                    ),
                );
                return Ok(());
            }
            Door::Unsubscribe => {
                io.answer(
                    id,
                    Answer::Error(ErrorBody::new(
                        ErrorCode::InvalidArgument,
                        "swarm_unsubscribe is main's own",
                    )),
                );
                return Ok(());
            }
        }
        if self.running >= self.bounds.running && self.admission.len() >= self.bounds.waiting {
            io.answer(id, Answer::Result(wire::error_typed(&Failure::busy())));
            return Ok(());
        }
        let total = Deadline::Swarm
            .total_ms(params.deadline_ms)
            .unwrap_or(fc_swarm_provider::machine::shell::SWARM_DEADLINE_MS);
        let binding = Binding::of(&page.origin, page.transport_key.as_deref()).map(|binding| {
            let document = Document::new(
                &page.origin,
                page.transport_key.as_deref().unwrap_or(""),
                page.frame,
                page.navigation,
            );
            (binding, document)
        });
        let page_json = serde_json::to_string(&page).unwrap_or_else(|_| "{}".to_owned());
        let approval = params.approval;
        let agent = page.agent;
        self.slots.insert(
            id,
            Slot {
                phase: Phase::Waiting(params),
                page,
                approval,
                agent,
                page_json,
                binding,
                deadline: now.saturating_add(total),
                asks: BTreeMap::new(),
                placed: false,
                base: 0,
                turn: 0,
                answered: false,
                written: false,
                idle: None,
                hashing: 0,
                kept: 0,
            },
        );
        self.admission.push_back(id);
        self.drive(io, now)
    }

    /// Main cancelled `swarm.request` `id`. One the thread doesn't hold, or
    /// has answered, changes nothing.
    pub fn cancel(&mut self, io: &mut impl Io, now: Ms, id: u64) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        let Some(slot) = self.slots.get_mut(&id) else {
            return Ok(());
        };
        if slot.answered {
            return Ok(());
        }
        match &mut slot.phase {
            Phase::Running(request) => {
                request.cancel();
                self.settle(io, now, id)?;
            }
            Phase::Waiting(_) | Phase::Base(_) | Phase::Done => {
                self.end_unstarted(io, id, cancelled());
            }
        }
        self.drive(io, now)
    }

    /// Main's terminal answer to the core's request `core`: the text of its
    /// `result` (`Ok`) or its `error` (`Err`).
    pub fn response(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        core: u64,
        outcome: Result<&str, &str>,
    ) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        let Some((id, ask_id)) = self.sent.remove(&core) else {
            return Err(Fault("swarm_unsolicited"));
        };
        let slot = self.slots.get_mut(&id).ok_or(Fault("swarm_unsolicited"))?;
        let ask = slot.asks.get(&ask_id).ok_or(Fault("swarm_unsolicited"))?;
        let ended = slot
            .binding
            .as_ref()
            .is_some_and(|(_, document)| self.shared.bindings.has(document));
        let event = match outcome {
            Ok(text) => Some(decode(&ask.need, text).ok_or(Fault("swarm_reply"))?),
            Err(text) => match (wire::refusal(text), &ask.need) {
                (Some(Refusal::Cancelled), _) if ask.cancelled => None,
                (Some(Refusal::Rule(rule)), Need::Node(_) | Need::Part(_)) => {
                    Some(Event::Refused(rule))
                }
                // Main refused the recheck itself: as 0012's APR-5 reads a
                // recheck that isn't one, the effect doesn't go. Here the
                // document isn't confirmed under its key.
                (_, Need::Live) if wire::is_error(text) => Some(Event::Live(Live {
                    name: true,
                    live: false,
                    agent: false,
                })),
                _ => return Err(Fault("swarm_reply")),
            },
        };
        // Main's recheck answers for the document; its binding is read
        // again as the answer comes: another check may have ended it while
        // the recheck was out.
        let event = match event {
            Some(Event::Live(live)) if ended => Some(Event::Live(Live {
                name: false,
                ..live
            })),
            other => other,
        };
        // A part's or a node reply's head opens its stream, which keeps
        // the ask, its charge and its slots until main's terminal.
        let head = match &event {
            Some(Event::Head(_)) => Some(None),
            Some(Event::PartHead(bytes)) => Some(Some(*bytes)),
            _ => None,
        };
        let opens = ask.opens().is_some();
        let closed = ask.closed;
        let deliver = if opens { io.replied(core, head)? } else { true };
        if head.is_some() {
            self.opened(now, id, ask_id, core, deliver);
            if let Some(event) = event.filter(|_| deliver && !closed) {
                self.progress(now, id, ask_id);
                self.deliver(io, now, id, ask_id, event)?;
            }
            self.settle(io, now, id)?;
            return self.drive(io, now);
        }
        let Some(ask) = self.take_ask(id, ask_id) else {
            return Err(Fault("swarm_unsolicited"));
        };
        if opens {
            io.forget(StreamKey::Piece(core));
        }
        // Main has answered the call: no credit for its body can follow
        // (D4), so the body's route goes.
        self.answered_call(io, id, ask_id);
        if let Some(event) = event.filter(|_| deliver && !closed) {
            self.deliver(io, now, id, ask_id, event)?;
        }
        // The step that consumed the reply has ended: its charge goes.
        self.release(ask.held);
        self.settle(io, now, id)?;
        self.drive(io, now)
    }

    /// The naming thread's verdict on the check under `tag` (D1).
    pub fn named(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        tag: u64,
        verdict: crate::eip1193::Verdict,
    ) -> Result<(), Fault> {
        use crate::eip1193::Verdict;
        // At or after its request's deadline, a verdict is the deadline's:
        // the request ends there, and its check, withdrawn, ends no binding.
        self.deadlines(io, now)?;
        let Some((id, ask_id)) = self.names.remove(&tag) else {
            return Ok(());
        };
        let Some(slot) = self.slots.get_mut(&id) else {
            return Ok(());
        };
        let Some(ask) = slot.asks.get_mut(&ask_id) else {
            return Ok(());
        };
        let document = slot.binding.as_ref().map(|(_, document)| document);
        match verdict {
            // Main's recheck next, unless another check, of any family,
            // ended the binding while this one's answer waited: a lookup
            // that holds can't revive it.
            Verdict::Holds if !document.is_some_and(|d| self.shared.bindings.has(d)) => {
                ask.stage = Stage::Outbox;
                self.outbox.push_back((id, ask_id));
            }
            // The name no longer serves the key: the binding ends for the
            // document, for every later check of either family. Every guard
            // reads the name first: no recheck to make.
            Verdict::Holds | Verdict::Fails => {
                if verdict == Verdict::Fails
                    && let Some(document) = document
                {
                    self.shared.bindings.end(document);
                }
                slot.asks.remove(&ask_id);
                self.ready.push_back((id, ask_id, Event::Live(MOVED)));
            }
            // The request's time ran out on naming's clock: its deadline,
            // which ends no binding.
            Verdict::Deadline => {
                slot.asks.remove(&ask_id);
                if let Phase::Running(request) = &mut slot.phase {
                    request.cancel();
                }
                self.settle(io, now, id)?;
            }
        }
        self.drive(io, now)
    }

    /// The vault's answer to the ask under `tag`: an owner
    /// ([`Event::Owner`]) or a signature ([`Event::Signed`]). One for an ask
    /// the machine cancelled, or whose request ended, is dropped: a late
    /// signature signs nothing that goes out. A signature's hold ends first,
    /// so every change it deferred lands before the machine's next step
    /// reads the store (design 0015, "The change waits").
    pub fn vaulted(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        tag: u64,
        event: Event,
    ) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        let Some((id, ask_id)) = self.vaults.remove(&tag) else {
            return Ok(());
        };
        let hold = self
            .slots
            .get_mut(&id)
            .and_then(|slot| slot.asks.remove(&ask_id))
            .and_then(|ask| ask.hold);
        if let Some(hold) = hold {
            self.release_hold(io, hold);
        }
        self.drive(io, now)?;
        self.deliver(io, now, id, ask_id, event)?;
        self.settle(io, now, id)?;
        self.drive(io, now)
    }

    /// SW-1's hold `hold` ends: the changes it deferred, which no other
    /// hold blocks, apply in their order, and each caller is answered.
    fn release_hold(&mut self, io: &mut impl Io, hold: HoldId) {
        let wall = io.wall_ms();
        let mut durable = |text: &str| io.write_feeds(text);
        let answers = self.shared.keeper.release(hold, wall, &mut durable);
        for (ticket, result) in answers {
            match self.tickets.remove(&ticket) {
                Some(Asker::Ask(id, ask_id)) => {
                    self.ready
                        .push_back((id, ask_id, Event::Written(written(result))));
                }
                #[cfg(any(test, feature = "testhooks"))]
                Some(Asker::Test(id)) => io.answer(id, changed(result)),
                None => {}
            }
        }
    }

    /// `test.swarm_feed_change` `id` (D11): a change to the feed store
    /// through SW-1's keeper, as `swarm.identities` will make one (PR 9),
    /// answered once made, or once the hold that defers it ends.
    #[cfg(any(test, feature = "testhooks"))]
    pub fn feed_change(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        id: u64,
        change: FeedChange,
    ) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        self.next_ticket += 1;
        let ticket = Ticket(self.next_ticket);
        let wall = io.wall_ms();
        let mut durable = |text: &str| io.write_feeds(text);
        match self
            .shared
            .keeper
            .change(ticket, change, wall, &mut durable)
        {
            Ran::Applied(result) => io.answer(id, changed(result)),
            Ran::Deferred => {
                self.tickets.insert(ticket, Asker::Test(id));
            }
        }
        self.drive(io, now)
    }

    /// The gate or the thread's share of the writer has room again.
    pub fn room(&mut self, io: &mut impl Io, now: Ms) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        self.blocked = false;
        self.drive(io, now)
    }

    /// `swarm.request` `id`'s answer has been written (or dropped at the
    /// end): its base goes once its request has ended.
    pub fn written(&mut self, io: &mut impl Io, now: Ms, id: u64) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        if let Some(slot) = self.slots.get_mut(&id) {
            slot.written = true;
            // Answered and written: its base goes, though a cancelled ask
            // of its own still waits for main's terminal answer, holding its
            // own charge and its slot (D13).
            if slot.answered {
                let base = std::mem::take(&mut slot.base);
                self.release(base);
            }
        } else if let Some(base) = self.unwritten.remove(&id) {
            self.release(base);
        }
        self.drive(io, now)
    }

    /// The deadlines due at `now`, and the closes' bounds.
    pub fn tick(&mut self, io: &mut impl Io, now: Ms) -> Result<(), Fault> {
        if self.closes.values().any(|due| *due <= now) {
            return Err(Fault("swarm_close_unanswered"));
        }
        // A stream the thread cancelled that main hasn't ended within the
        // idle bound: main broke the protocol (D13's rule for a cancelled
        // ask, for the stream's own terminal).
        if self.retiring.values().any(|due| *due <= now) {
            return Err(Fault("swarm_stream_unterminated"));
        }
        self.deadlines(io, now)?;
        // Uploads whose streams have been idle for the bound (D13), once
        // the requests past their deadline have ended at it.
        let idle: Vec<u64> = self
            .slots
            .iter()
            .filter(|(_, slot)| slot.idle.is_some_and(|due| due <= now))
            .map(|(id, _)| *id)
            .collect();
        for id in idle {
            self.stall(io, now, id)?;
        }
        self.drive(io, now)
    }

    /// The requests whose deadline has come by `now` end at it, before
    /// anything else is handled at `now`: an answer that comes at or after
    /// a request's deadline (a naming verdict, main's recheck, a node's
    /// reply) finds it cancelled, as the thread's own tick would have left
    /// it had it turned first. So a name check that fails then ends no
    /// binding: a deadline ends nothing.
    fn deadlines(&mut self, io: &mut impl Io, now: Ms) -> Result<(), Fault> {
        let due: Vec<u64> = self
            .slots
            .iter()
            .filter(|(_, slot)| !slot.answered && slot.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        let ended = !due.is_empty();
        for id in due {
            let Some(slot) = self.slots.get_mut(&id) else {
                continue;
            };
            match &mut slot.phase {
                Phase::Running(request) => {
                    // A charge still waiting is `busy`; anything else the
                    // page's timer, `cancelled` (deviation `deadlines`).
                    if slot.asks.values().any(|ask| ask.stage == Stage::Memory) {
                        request.busy();
                    } else {
                        request.cancel();
                    }
                    self.settle(io, now, id)?;
                }
                Phase::Waiting(_) | Phase::Base(_) | Phase::Done => {
                    self.end_unstarted(io, id, Answer::Result(wire::error_typed(&Failure::busy())));
                }
            }
        }
        if ended {
            self.drive(io, now)?;
        }
        Ok(())
    }

    /// When the next deadline or close bound falls due.
    pub fn next_due(&self) -> Option<Ms> {
        let deadlines = self
            .slots
            .values()
            .filter(|slot| !slot.answered)
            .map(|slot| slot.deadline);
        let idle = self.slots.values().filter_map(|slot| slot.idle);
        deadlines
            .chain(idle)
            .chain(self.closes.values().copied())
            .chain(self.retiring.values().copied())
            .min()
    }

    // -----------------------------------------------------------------------
    // Moving requests on.

    /// Does what waits until nothing more can move: reservations granted,
    /// answers the engine gave, node calls given a slot, asks sent, places
    /// filled.
    fn drive(&mut self, io: &mut impl Io, now: Ms) -> Result<(), Fault> {
        loop {
            if let Some(id) = self.cancels.pop_front() {
                if let Some(Slot {
                    phase: Phase::Running(request),
                    ..
                }) = self.slots.get_mut(&id)
                {
                    request.cancel();
                    self.settle(io, now, id)?;
                }
                continue;
            }
            if let Some(id) = self.granted.pop_front() {
                if let Some(slot) = self.slots.get_mut(&id)
                    && let Phase::Base(params) = std::mem::replace(&mut slot.phase, Phase::Done)
                {
                    self.start(io, now, id, params)?;
                }
                continue;
            }
            if let Some((id, ask, event)) = self.ready.pop_front() {
                self.deliver(io, now, id, ask, event)?;
                self.settle(io, now, id)?;
                continue;
            }
            if self.pump_api()
                || self.pump_streams()
                || self.pump_outbox(io, now)?
                || self.pump_admission(io, now)?
            {
                continue;
            }
            return Ok(());
        }
    }

    fn release(&mut self, amount: usize) {
        if amount > 0 {
            let granted = self.memory.release(amount);
            self.grant(granted);
        }
    }

    /// Reservations granted from the queue: each now holds its charge,
    /// whatever happens to it next. A base's request starts from the loop;
    /// an ask moves on at once.
    fn grant(&mut self, granted: Vec<Waiter>) {
        for waiter in granted {
            match waiter {
                Waiter::Base(id) => match self.slots.get_mut(&id) {
                    Some(slot) => {
                        slot.base = REQUEST_CHARGE;
                        self.granted.push_back(id);
                    }
                    None => self.release(REQUEST_CHARGE),
                },
                Waiter::Ask(id, ask_id) => self.charged(id, ask_id),
            }
        }
    }

    /// An ask's charge is reserved: it holds it, and goes on to its slot or
    /// its upload's turn.
    fn charged(&mut self, id: u64, ask_id: AskId) {
        let ask = self
            .slots
            .get_mut(&id)
            .and_then(|slot| slot.asks.get_mut(&ask_id))
            .filter(|ask| ask.stage == Stage::Memory);
        let Some(ask) = ask else {
            // Never: a withdrawn reservation isn't granted.
            return;
        };
        ask.held = ask.charge;
        if matches!(ask.need, Need::Upload) {
            self.take_turn(id, ask_id);
        } else {
            ask.stage = Stage::Slot;
            self.api_queue.push_back((id, ask_id));
        }
    }

    /// A request that never started ends with `answer`.
    fn end_unstarted(&mut self, io: &mut impl Io, id: u64, answer: Answer) {
        let Some(slot) = self.slots.get_mut(&id) else {
            return;
        };
        let withdraw = matches!(slot.phase, Phase::Base(_)) && slot.base == 0;
        slot.phase = Phase::Done;
        slot.answered = true;
        if slot.placed {
            slot.placed = false;
            self.running = self.running.saturating_sub(1);
        }
        io.answer(id, answer);
        self.admission.retain(|waiting| *waiting != id);
        if withdraw {
            let granted = self.memory.withdraw(Waiter::Base(id));
            self.grant(granted);
        }
        self.retire(io, id);
    }

    fn pump_admission(&mut self, io: &mut impl Io, now: Ms) -> Result<bool, Fault> {
        if self.running >= self.bounds.running {
            return Ok(false);
        }
        let Some(id) = self.admission.pop_front() else {
            return Ok(false);
        };
        let Some(slot) = self.slots.get_mut(&id) else {
            return Ok(true);
        };
        let Phase::Waiting(params) = std::mem::replace(&mut slot.phase, Phase::Done) else {
            return Ok(true);
        };
        slot.placed = true;
        self.running += 1;
        if self.memory.reserve(Waiter::Base(id), REQUEST_CHARGE) {
            slot.base = REQUEST_CHARGE;
            self.start(io, now, id, params)?;
        } else {
            slot.phase = Phase::Base(params);
        }
        Ok(true)
    }

    /// Starts the request's machine, its base reserved.
    fn start(&mut self, io: &mut impl Io, now: Ms, id: u64, params: Params) -> Result<(), Fault> {
        let Some(slot) = self.slots.get_mut(&id) else {
            return Ok(());
        };
        let call = Call {
            method: params.method,
            params: params.params,
            key: JsString::from(slot.page.origin.as_str()),
            approval: params.approval,
        };
        let mut world = StepWorld::new(&mut self.shared, io.wall_ms());
        let started = Request::start(&call, &mut world);
        drop(world);
        match started {
            Ok(request) => {
                slot.phase = Phase::Running(Box::new(request));
                self.settle(io, now, id)
            }
            Err(NotBuilt(_)) => {
                self.end_unstarted(
                    io,
                    id,
                    Answer::Error(ErrorBody::new(
                        ErrorCode::InvalidArgument,
                        "swarm_unsubscribe is main's own",
                    )),
                );
                Ok(())
            }
        }
    }

    /// Hands the request an answer to its ask.
    fn deliver(
        &mut self,
        io: &mut impl Io,
        _now: Ms,
        id: u64,
        ask: AskId,
        event: Event,
    ) -> Result<(), Fault> {
        let Some(Slot {
            phase: Phase::Running(request),
            agent,
            ..
        }) = self.slots.get_mut(&id)
        else {
            return Ok(());
        };
        // The custody main reports for a document whose name still binds
        // it: D15's input for a signature that follows.
        if let Event::Live(live) = &event
            && live.name
        {
            *agent = Some(live.agent);
        }
        let mut world = StepWorld::new(&mut self.shared, io.wall_ms());
        request.answer(&mut world, ask, event);
        Ok(())
    }

    /// Takes the request's effects until it has none, then answers it once
    /// it has its outcome, and retires it once nothing of it is open.
    fn settle(&mut self, io: &mut impl Io, now: Ms, id: u64) -> Result<(), Fault> {
        loop {
            let effects = match self.slots.get_mut(&id) {
                Some(Slot {
                    phase: Phase::Running(request),
                    ..
                }) => request.take_effects(),
                _ => return Ok(()),
            };
            if effects.is_empty() {
                break;
            }
            for effect in effects {
                self.effect(io, now, id, effect);
            }
        }
        let Some(slot) = self.slots.get_mut(&id) else {
            return Ok(());
        };
        let Phase::Running(request) = &slot.phase else {
            return Ok(());
        };
        if !slot.answered
            && let Some(outcome) = request.outcome()
        {
            let answer = match outcome {
                Outcome::Result(value) => Answer::Result(wire::result_typed(value)),
                Outcome::Error(failure) => Answer::Result(wire::error_typed(failure)),
                Outcome::Cancelled => cancelled(),
                Outcome::Protocol(protocol) => return Err(Fault(category(*protocol))),
            };
            slot.answered = true;
            io.answer(id, answer);
            // Its place, its topics and its upload's turn go with its
            // answer; what it still has open keeps its own charges.
            if slot.placed {
                slot.placed = false;
                self.running = self.running.saturating_sub(1);
            }
            self.end_holdings(io, id);
        }
        if self.slots.get(&id).is_some_and(|slot| {
            slot.answered
                && slot.asks.is_empty()
                && slot.hashing == 0
                && matches!(slot.phase, Phase::Running(_))
        }) {
            self.retire(io, id);
            return Ok(());
        }
        self.watch(now, id);
        Ok(())
    }

    /// The request has ended and nothing of it is open: it goes, and the
    /// base it still holds, if any, once its answer has been written.
    fn retire(&mut self, io: &mut impl Io, id: u64) {
        let Some(slot) = self.slots.remove(&id) else {
            return;
        };
        self.forget_bodies(io, id);
        let held = slot.base.saturating_add(slot.kept);
        if held == 0 {
            return;
        }
        if slot.written {
            self.release(held);
        } else {
            self.unwritten.insert(id, held);
        }
    }

    fn effect(&mut self, io: &mut impl Io, now: Ms, id: u64, effect: Effect) {
        match effect {
            Effect::Ask(ask) => self.ask(io, now, id, ask.id, ask.need, ask.charge),
            Effect::Cancel(ask) => self.cancel_ask(io, now, id, ask),
            Effect::Credit { id: ask, bytes } => self.credit(io, id, ask, bytes),
            Effect::Body { id: ask, out } => self.body_out(io, id, ask, out),
        }
    }

    fn ask(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        id: u64,
        ask_id: AskId,
        need: Need,
        charge: usize,
    ) {
        let Some(slot) = self.slots.get_mut(&id) else {
            return;
        };
        let mut hold = None;
        let need = match need {
            // The thread's own pool (D9): the request stays until it's back.
            Need::Hash(job) => {
                slot.hashing += 1;
                io.hash(id, ask_id, job);
                return;
            }
            // Made now, synchronously, and answered in the order asked: a
            // write finishes before the thread takes the next store change.
            Need::Write(write) => {
                let event = match write {
                    StoreWrite::Feeds(change) => {
                        self.next_ticket += 1;
                        let ticket = Ticket(self.next_ticket);
                        let wall = io.wall_ms();
                        let mut durable = |text: &str| io.write_feeds(text);
                        match self
                            .shared
                            .keeper
                            .change(ticket, change, wall, &mut durable)
                        {
                            Ran::Applied(result) => Event::Written(written(result)),
                            // Answered as the hold that defers it ends.
                            Ran::Deferred => {
                                self.tickets.insert(ticket, Asker::Ask(id, ask_id));
                                return;
                            }
                        }
                    }
                    StoreWrite::History(statements) => Event::Written(io.history(&statements)),
                    StoreWrite::HistoryInsert(statement) => {
                        Event::Inserted(io.history_insert(&statement))
                    }
                    StoreWrite::Manifests(save) => Event::Written(io.save_manifests(&save)),
                };
                self.ready.push_back((id, ask_id, event));
                return;
            }
            need => need,
        };
        let stage = match &need {
            Need::Ready(_) | Need::Subscribe(_) => Stage::Outbox,
            Need::Unsubscribe {
                answer_within_ms, ..
            } => {
                self.closes
                    .insert((id, ask_id), now.saturating_add(*answer_within_ms));
                Stage::Outbox
            }
            Need::Node(_) | Need::Upload => Stage::Memory,
            // A part's bytes are held under its upload's turn: it needs only
            // a stream's slot.
            Need::Part(_) => Stage::Streams,
            Need::Hash(_) => return,
            Need::Live => match slot.binding.clone() {
                // A binding already ended, by any family's check, or a
                // transport key that isn't `ipns://<key>`: the name fails,
                // with nothing resolved.
                Some((binding, document))
                    if !binding.resolvable() || self.shared.bindings.has(&document) =>
                {
                    self.ready.push_back((id, ask_id, Event::Live(MOVED)));
                    return;
                }
                Some((binding, _)) => {
                    self.next_tag += 1;
                    let tag = NAME_TAG | self.next_tag;
                    io.name_check(tag, binding, slot.deadline.saturating_sub(now));
                    self.names.insert(tag, (id, ask_id));
                    Stage::Naming(tag)
                }
                None => Stage::Outbox,
            },
            Need::Lock(topic) => {
                let topic = *topic;
                if self.locks.take(topic, id, (id, ask_id)) {
                    self.ready.push_back((id, ask_id, Event::Locked));
                    return;
                }
                Stage::Lock(topic)
            }
            // No mining lane before SWM-4 PR 8: mining is off.
            Need::Mine(_) => {
                self.ready.push_back((id, ask_id, Event::Mined(Mined::Off)));
                return;
            }
            Need::Owner(key) => {
                self.next_vault += 1;
                let tag = self.next_vault;
                io.vault(tag, VaultAsk::Owner(*key));
                self.vaults.insert(tag, (id, ask_id));
                Stage::Vault(tag)
            }
            // SW-1's hold from this ask until the vault answers (design
            // 0015, "SW-1 in the core"), and D15's inputs with the SOC.
            Need::Sign(soc) => {
                let key = JsString::from(slot.page.origin.as_str());
                if let Some(held) = &soc.hold {
                    self.next_hold += 1;
                    hold = Some(HoldId(self.next_hold));
                    self.shared
                        .keeper
                        .hold(HoldId(self.next_hold), held.clone());
                }
                let ask = SignAsk {
                    soc: soc.clone(),
                    key: slot.page.origin.clone(),
                    agent: slot.agent,
                    approval: slot.approval.unwrap_or(Approval::User),
                    feed_grant: self.shared.keeper.store().has_feed_grant(&key),
                };
                self.next_vault += 1;
                let tag = self.next_vault;
                io.vault(tag, VaultAsk::Sign(Box::new(ask)));
                self.vaults.insert(tag, (id, ask_id));
                Stage::Vault(tag)
            }
            Need::Write(_) => return,
        };
        slot.asks.insert(
            ask_id,
            Ask {
                need,
                charge,
                held: 0,
                api: false,
                stage,
                cancelled: false,
                stream: false,
                closed: false,
                body_ended: false,
                hold,
            },
        );
        if stage == Stage::Outbox {
            self.outbox.push_back((id, ask_id));
        } else if stage == Stage::Streams {
            self.stream_queue.push_back((id, ask_id));
        } else if stage == Stage::Memory && self.memory.reserve(Waiter::Ask(id, ask_id), charge) {
            self.charged(id, ask_id);
        }
    }

    fn take_turn(&mut self, id: u64, ask_id: AskId) {
        let Some(slot) = self.slots.get_mut(&id) else {
            return;
        };
        let Some(ask) = slot.asks.get_mut(&ask_id) else {
            return;
        };
        if self.turns < self.bounds.uploads {
            self.turns += 1;
            slot.turn += ask.held;
            slot.asks.remove(&ask_id);
            self.ready.push_back((id, ask_id, Event::Turn));
        } else {
            ask.stage = Stage::Turn;
            self.turn_queue.push_back((id, ask_id));
        }
    }

    fn next_turn(&mut self) {
        while let Some((id, ask_id)) = self.turn_queue.pop_front() {
            let waiting = self
                .slots
                .get(&id)
                .and_then(|slot| slot.asks.get(&ask_id))
                .is_some_and(|ask| ask.stage == Stage::Turn);
            if waiting {
                self.take_turn(id, ask_id);
                return;
            }
        }
    }

    /// The request's answer has gone: its upload's turn and its topics go
    /// to the next in line.
    fn end_holdings(&mut self, io: &mut impl Io, id: u64) {
        // A hold its request still has (never: the machine waits for the
        // signature, or cancels it, before it ends) goes with its answer.
        let holds: Vec<HoldId> = self
            .slots
            .get_mut(&id)
            .map(|slot| {
                slot.asks
                    .values_mut()
                    .filter_map(|ask| ask.hold.take())
                    .collect()
            })
            .unwrap_or_default();
        for hold in holds {
            self.release_hold(io, hold);
        }
        let turn = self
            .slots
            .get_mut(&id)
            .map_or(0, |slot| std::mem::take(&mut slot.turn));
        if turn > 0 {
            self.turns = self.turns.saturating_sub(1);
            self.release(turn);
            self.next_turn();
        }
        self.release_locks(id);
    }

    fn release_locks(&mut self, id: u64) {
        let held: Vec<[u8; 32]> = self
            .locks
            .topics
            .iter()
            .filter(|(_, (holder, _))| *holder == id)
            .map(|(topic, _)| *topic)
            .collect();
        for topic in held {
            let slots = &self.slots;
            let next = self.locks.release(topic, id, |(waiter, ask_id)| {
                slots
                    .get(waiter)
                    .and_then(|slot| slot.asks.get(ask_id))
                    .filter(|ask| ask.stage == Stage::Lock(topic))
                    .map(|_| *waiter)
            });
            if let Some((waiter, ask_id)) = next {
                if let Some(slot) = self.slots.get_mut(&waiter) {
                    slot.asks.remove(&ask_id);
                }
                self.ready.push_back((waiter, ask_id, Event::Locked));
            }
        }
    }

    /// The machine no longer waits for an ask: withdrawn where it waits,
    /// cancelled at main where it went. A cancelled call keeps its charge
    /// and its slot until main's answer (D13).
    fn cancel_ask(&mut self, io: &mut impl Io, now: Ms, id: u64, ask_id: AskId) {
        let Some(slot) = self.slots.get_mut(&id) else {
            return;
        };
        let Some(ask) = slot.asks.get_mut(&ask_id) else {
            return;
        };
        match ask.stage {
            Stage::Sent(core) => {
                if !ask.cancelled {
                    ask.cancelled = true;
                    io.cancel(core);
                }
                return;
            }
            // Its stream retires: its frames are dropped as they come, and
            // its slots and charge stay until main's terminal, which must
            // come within the idle bound.
            Stage::Open(core) => {
                if !ask.cancelled {
                    ask.cancelled = true;
                    io.cancel(core);
                    self.retiring
                        .insert(core, now.saturating_add(self.bounds.idle_ms));
                }
                return;
            }
            Stage::Naming(tag) => {
                io.name_cancel(tag);
                self.names.remove(&tag);
            }
            // The vault's answer is dropped when it comes; a signature's
            // hold ends now, and what it deferred applies.
            Stage::Vault(tag) => {
                self.vaults.remove(&tag);
                if let Some(hold) = ask.hold.take() {
                    self.release_hold(io, hold);
                }
            }
            Stage::Memory => {
                let granted = self.memory.withdraw(Waiter::Ask(id, ask_id));
                slot.asks.remove(&ask_id);
                self.grant(granted);
                return;
            }
            Stage::Slot | Stage::Outbox | Stage::Lock(_) | Stage::Turn | Stage::Streams => {}
        }
        if let Some(ask) = self.take_ask(id, ask_id) {
            self.release(ask.held);
        }
    }

    /// Node calls with their charge take free slots, in order.
    fn pump_api(&mut self) -> bool {
        let mut moved = false;
        while self.api_open < self.bounds.api {
            let Some((id, ask_id)) = self.api_queue.pop_front() else {
                break;
            };
            let Some(ask) = self
                .slots
                .get_mut(&id)
                .and_then(|slot| slot.asks.get_mut(&ask_id))
                .filter(|ask| ask.stage == Stage::Slot)
            else {
                continue;
            };
            self.api_open += 1;
            ask.api = true;
            // A node reply that streams needs a stream's slot too (D4).
            if ask.opens().is_some() {
                ask.stage = Stage::Streams;
                self.stream_queue.push_back((id, ask_id));
            } else {
                ask.stage = Stage::Outbox;
                self.outbox.push_back((id, ask_id));
            }
            moved = true;
        }
        moved
    }

    /// Sends the first ask that waits for the gate, if the gate takes it.
    fn pump_outbox(&mut self, io: &mut impl Io, now: Ms) -> Result<bool, Fault> {
        if self.blocked {
            return Ok(false);
        }
        let Some((id, ask_id)) = self.outbox.pop_front() else {
            return Ok(false);
        };
        let Some(slot) = self.slots.get_mut(&id) else {
            return Ok(true);
        };
        let Some(ask) = slot
            .asks
            .get_mut(&ask_id)
            .filter(|ask| ask.stage == Stage::Outbox)
        else {
            return Ok(true);
        };
        let outgoing = match &ask.need {
            Need::Ready(check) => Outgoing {
                method: "shell.swarm_ready",
                params: wire::ready_params(id, *check),
                reply_bound: SMALL_REPLY,
                opens: None,
            },
            // A streamed reply's head, or an error status's whole body:
            // the reply's bound is the larger, the error body's.
            Need::Node(call) => Outgoing {
                method: "shell.swarm_api",
                params: wire::api_params(id, call),
                reply_bound: b64(call.max_bytes.max(ERROR_BODY)).saturating_add(ENVELOPE),
                opens: ask.opens(),
            },
            Need::Part(part) => Outgoing {
                method: "shell.swarm_part",
                params: stream::part_params(id, *part),
                reply_bound: SMALL_REPLY,
                opens: ask.opens(),
            },
            Need::Subscribe(subscription) => Outgoing {
                method: "shell.swarm_subscribe",
                params: wire::subscribe_params(id, subscription),
                reply_bound: SMALL_REPLY,
                opens: None,
            },
            Need::Unsubscribe {
                id: subscription, ..
            } => Outgoing {
                method: "shell.swarm_unsubscribe",
                params: wire::unsubscribe_params(subscription),
                reply_bound: SMALL_REPLY,
                opens: None,
            },
            Need::Live => Outgoing {
                method: "approval.recheck",
                params: wire::recheck_params(id, &slot.page_json),
                reply_bound: SMALL_REPLY,
                opens: None,
            },
            _ => return Ok(true),
        };
        match io.send(outgoing) {
            Sent::Id(core) => {
                ask.stage = Stage::Sent(core);
                let watched = ask.watched();
                self.sent.insert(core, (id, ask_id));
                // An upload's stream is out: its idle bound runs (D13).
                if watched {
                    self.progress(now, id, ask_id);
                }
            }
            Sent::Wait => {
                self.outbox.push_front((id, ask_id));
                self.blocked = true;
                return Ok(false);
            }
            // Over one frame, or the core is exiting: a node call fails as
            // a dial would; anything else ends its request.
            Sent::Refused => {
                let node = matches!(ask.need, Need::Node(_));
                let held = self.take_ask(id, ask_id).map_or(0, |ask| ask.held);
                if node {
                    self.deliver(io, now, id, ask_id, Event::Failed(Failed::Error))?;
                } else {
                    self.cancels.push_back(id);
                }
                self.release(held);
                self.settle(io, now, id)?;
            }
        }
        Ok(true)
    }

    /// Topics held, for the tests.
    #[cfg(test)]
    fn topics_held(&self) -> usize {
        self.locks.held()
    }
}

/// A feed store change's answer, as a machine's write reads it.
fn written(result: Result<ChangeAnswer, ChangeError>) -> Result<(), JsString> {
    result.map(drop).map_err(|e| e.message())
}

/// `test.swarm_feed_change`'s answer: `{ value }`, the change's own (`null`
/// for `undefined`), or `{ error }`, the text its caller reads.
#[cfg(any(test, feature = "testhooks"))]
fn changed(result: Result<ChangeAnswer, ChangeError>) -> Answer {
    let json = match result {
        Ok(answer) => {
            let value = match answer.value {
                fc_json::JsValue::Undefined => "null".to_owned(),
                value => value.stringify(),
            };
            format!(r#"{{"value":{value}}}"#)
        }
        Err(e) => serde_json::json!({ "error": e.message().as_str() }).to_string(),
    };
    Answer::Result(json)
}

/// 0001's `cancelled`.
fn cancelled() -> Answer {
    Answer::Error(ErrorBody::new(ErrorCode::Cancelled, "Cancelled"))
}

/// A machine's protocol outcome's category (D5: it ends the connection).
fn category(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::UnknownAsk => "swarm_unknown_ask",
        Protocol::WrongKind => "swarm_wrong_kind",
        Protocol::Bounds => "swarm_reply_bounds",
        Protocol::SecondHead => "swarm_second_head",
        Protocol::BeforeHead => "swarm_before_head",
        Protocol::Frame => "swarm_frame",
        Protocol::BeyondCredit => "swarm_beyond_credit",
        Protocol::PastMax => "swarm_past_max",
        Protocol::PartLength => "swarm_part_length",
    }
}

/// Main's result for an ask, as the machine's event: `None` when it isn't
/// the ask's form.
fn decode(need: &Need, text: &str) -> Option<Event> {
    match need {
        Need::Ready(_) => wire::ready_reply(text).map(Event::Ready),
        Need::Node(call) => wire::api_reply(text, call.stream()),
        Need::Part(_) => stream::part_head(text).map(Event::PartHead),
        Need::Subscribe(_) => wire::subscribe_reply(text).map(Event::Opened),
        Need::Unsubscribe { .. } => wire::unsubscribe_reply(text).then_some(Event::Closed),
        Need::Live => fc_eip1193::Recheck::parse(text).ok().map(|recheck| {
            Event::Live(Live {
                name: true,
                live: recheck.live,
                agent: recheck.agent,
            })
        }),
        _ => None,
    }
}

/// The asks a request holds, by stage, for the tests.
#[cfg(test)]
fn stages(engine: &Engine, id: u64) -> std::collections::BTreeSet<String> {
    engine
        .slots
        .get(&id)
        .map(|slot| {
            slot.asks
                .values()
                .map(|ask| format!("{:?}", ask.stage))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
