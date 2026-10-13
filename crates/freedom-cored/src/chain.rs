//! The chain thread (design 0005): fc-chain's machine on its own thread, as
//! the naming thread runs fc-naming's. The event loop forwards `chain.*`
//! requests, cancels and main's responses to `shell.*` here; this thread
//! writes its own replies, cancels and requests to the writer.
//!
//! - **Admission and limits** are the machine's: 64 running and 256 waiting
//!   requests, and the memory budgets.
//! - **Its own share of the writer,** in two parts. The thread never blocks
//!   on the writer: past a part's share, its frames wait here.
//!   - **Bulk:** replies over [`SMALL_REPLY`], whole or fragmented, within
//!     one message cap ([`transport::MAX_QUEUED_CHAIN_BYTES`]), in order.
//!   - **Control:** cancels, small replies and requests to main, within
//!     their own share ([`transport::MAX_QUEUED_CHAIN_CONTROL_BYTES`]), in
//!     order. A bulk reply waiting for main's credit never holds them up
//!     (0001's reserved control capacity; PR #57 review, 57-M3), so a
//!     cancel and its small reply go at once.
//!
//!   What waits, and what the writer still holds, is the machine's
//!   backlog: it counts in the chain total until written, and new requests
//!   are `busy` while that total is full (design 0005, Frames).
//! - **Requests to main** go through the core's one gate ([`Requests`]):
//!   IDs from the counter naming uses too, main's limit of 256 outstanding
//!   requests across both threads, and main's responses routed back here.
//!   Until they go, they wait here, first in, first out.
//! - **Replies** take design 0005's wire forms ([`reply_message`]). One over
//!   one frame goes fragmented to a main that offered fragments; otherwise,
//!   or over the message cap, the request fails with `too_large`.

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Range;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use base64::Engine as _;
use fc_chain::machine::{
    Answer, Bounds, BroadcastOutcome, Call, ChainConfig, ChainError, ColibriClass, ColibriReply,
    Effect, Emitted, Machine, Ms, MyotisClass, MyotisReply, Origin, Prop, Protocol, Prover,
    QuorumConfig, ReadOptions, Reply as Done, Request, Reservation, RpcEndpoint, Success,
    Transport, VerifiedOp,
};
use fc_chain::{JsString, MyotisOperation, READ_METHODS, SINGLE_NODE_METHODS};
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::frame::MAX_MESSAGE;
use fc_protocol::message::MAX_ID;
use serde::Deserialize;
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use crate::log;
use crate::requests::{self, Dispatch, Owner, Requests, Start};
use crate::serve::Event;
use crate::transport::{self, Allowance, Credit, Link, Out, Reply};

/// The methods the chain thread answers.
pub const METHODS: &[&str] = &[
    "chain.configure",
    "chain.availability",
    "chain.request",
    "chain.fee_quote",
    "chain.broadcast",
];

pub fn handles(method: &str) -> bool {
    METHODS.contains(&method)
}

/// What the event loop forwards.
pub enum In {
    Request {
        id: u64,
        method: &'static str,
        params: Option<Box<RawValue>>,
    },
    Cancel {
        id: u64,
    },
    /// Main's terminal reply to one of this thread's `shell.*` requests.
    Response {
        id: u64,
        reply: Shell,
    },
    /// The writer has room again, or main a free slot, for what waits here.
    Drained,
}

/// Main's terminal reply to one of the chain thread's requests, as the
/// event loop hands it over.
pub enum Shell {
    /// The response message as it was read, moved here rather than copied,
    /// and where its `error` lies in it.
    Failed {
        message: Zeroizing<Vec<u8>>,
        error: Range<usize>,
    },
    /// The response message as it was read, and where its `result` lies in
    /// it.
    Result {
        message: Zeroizing<Vec<u8>>,
        result: Range<usize>,
    },
}

/// A message, with the reader's credit for the frame it came in: the
/// reader counts it until this thread has handled it. A reassembled
/// response's credit returns main's bulk credit once dropped.
type Mail = (In, Option<Credit>);

/// The event loop's side of the chain thread. The wake-ups hold only weak
/// references, so dropping this ends the thread.
pub struct Handle {
    tx: Arc<Sender<Mail>>,
}

impl Handle {
    /// False once the thread has gone.
    pub fn send(&self, message: In, credit: Option<Credit>) -> bool {
        self.tx.send((message, credit)).is_ok()
    }
}

/// What wakes the thread to send what waits: room in its share of the
/// writer, or a free slot at main.
fn waker(tx: &Arc<Sender<Mail>>) -> impl Fn() + Send + 'static {
    let wake: Weak<Sender<Mail>> = Arc::downgrade(tx);
    move || {
        if let Some(tx) = wake.upgrade() {
            let _ = tx.send((In::Drained, None));
        }
    }
}

/// Starts the chain thread. It writes to `out`, fragments replies for a
/// main that offered fragments (`link`), sends its `shell.*` requests
/// through `requests`, and reports a protocol error from main, or its own
/// end, to the event loop.
pub fn spawn(
    out: Sender<Out>,
    events: Sender<Event>,
    link: Arc<Link>,
    requests: Arc<Requests>,
) -> std::io::Result<Handle> {
    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(tx);
    // Chain's share of the writer: one message cap for bulk replies (design
    // 0005, Frames), and a share of its own for control frames.
    let allowance = Allowance::new(usize::MAX, transport::MAX_QUEUED_CHAIN_BYTES);
    allowance.on_room(waker(&tx));
    let control = Allowance::new(usize::MAX, transport::MAX_QUEUED_CHAIN_CONTROL_BYTES);
    control.on_room(waker(&tx));
    requests.on_room(Owner::Chain, waker(&tx));
    std::thread::Builder::new()
        .name("chain".into())
        .spawn(move || {
            let _notice = transport::DeathNotice::new(events.clone(), "chain");
            // The thread's monotonic clock, in milliseconds from its start.
            let started = Instant::now();
            let clock = move || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let chain = Chain::new(
                Machine::new(0, crate::testhooks::chain_bounds(Bounds::default())),
                out,
                link,
                Shares {
                    bulk: allowance,
                    control,
                },
                requests,
                Box::new(clock),
            );
            let event = match run(&rx, chain) {
                Stop::Protocol(category) => Event::ProtocolError(category),
                Stop::Writer => Event::WriterFailed,
                // The event loop has gone: nothing to report to.
                Stop::Gone => return,
            };
            let _ = events.send(event);
        })?;
    Ok(Handle { tx })
}

/// Why the chain thread stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// Main broke the protocol (a fixed category, never input text).
    Protocol(&'static str),
    /// The writer is gone or main stopped reading.
    Writer,
    /// The event loop has gone.
    Gone,
}

type Flow = Result<(), Stop>;

/// The thread's loop, until it has to stop.
fn run(rx: &Receiver<Mail>, mut chain: Chain) -> Stop {
    loop {
        if let Err(stop) = chain.flush() {
            return stop;
        }
        let due = match (chain.machine.next_due(), chain.next_expiry()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let wait = due.map_or(Duration::from_secs(3600), |at| {
            Duration::from_millis(at.saturating_sub(chain.clock.now()))
        });
        let flow = match rx.recv_timeout(wait) {
            // The frame's credit goes once its message is handled. The
            // machine is brought to the clock before the message, and again
            // after it, before anything is dispatched: handling it can take
            // a while (R3-M1).
            Ok((message, _credit)) => chain
                .flush()
                .and_then(|()| chain.handle(message))
                .and_then(|()| chain.flush()),
            Err(RecvTimeoutError::Timeout) => Ok(()),
            // The event loop has gone (shutdown or EOF): the replies and
            // cancels still waiting go to the writer, which the loop gives
            // its bounded drain. Queued requests are dropped unsent.
            Err(RecvTimeoutError::Disconnected) => {
                chain.drain();
                Err(Stop::Gone)
            }
        };
        if let Err(stop) = flow {
            return stop;
        }
    }
}

/// What a `shell.*` request is, to read main's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Rpc,
    Blockscout,
    MyotisRead,
    MyotisBroadcast,
    Colibri,
}

struct Outgoing {
    /// The machine's request id; `None` once the machine cancelled it (its
    /// one terminal reply is still due, and dropped).
    io: Option<u64>,
    kind: Kind,
}

/// One of the machine's requests waiting to go to main.
struct Queued {
    io: u64,
    request: Request,
    /// The generation of the chain request that made it.
    generation: u64,
    /// The machine's id of that chain request: once it has replied, the
    /// request never goes (57-M2).
    owner: Option<u64>,
    /// An exchange's own deadline (Direct's, Blockscout's, Colibri's): the
    /// machine's own timer for it ends then. `None` for a Myotis
    /// operation, which main runs whole while its request runs.
    own: Option<Ms>,
    /// The latest it may start for itself: its own deadline, or for a
    /// transaction sent (a broadcast's attempt, Direct or Myotis) its
    /// broadcast's attempt cutoff, 10 s before the deadline, if earlier
    /// (design 0005, Deadlines).
    until: Option<Ms>,
    /// Its chain request's deadline. The machine's own timer for that ends
    /// the request, and the request's waiting I/O retires.
    deadline: Option<Ms>,
    /// Whether it sends a transaction ([`Request::sends_transaction`]).
    sends: bool,
}

impl Queued {
    /// When it expires here, unsent, if it is still waiting: at `until`,
    /// before any timer due at the same instant (the machine's own for its
    /// exchange), only when that is earlier than its chain request's
    /// deadline. From that deadline on, the machine's own timer for the
    /// request goes first: a read or a fee quote ends with `deadline`, and
    /// this retires unread (PR #57 daemon review, round 5). A transaction's
    /// attempt expires at its cutoff all the same, so one that never went
    /// counts as not sent in its broadcast's outcome.
    fn expiry(&self) -> Option<Ms> {
        let until = self.until?;
        let first = self.sends || self.deadline.is_none_or(|deadline| until < deadline);
        first.then_some(until)
    }

    /// Whether it may still start at `now` ([`Requests::send`]): not at or
    /// after its own deadline, its broadcast's attempt cutoff or its chain
    /// request's deadline, whichever comes first. Its `deadline_ms` is
    /// what is left of the earlier of its own deadline and its request's.
    fn start(&self, now: Ms) -> Start {
        if earliest(self.until, self.deadline).is_some_and(|latest| latest <= now) {
            return Start::Late;
        }
        match earliest(self.own, self.deadline) {
            Some(end) => Start::Within(end.saturating_sub(now)),
            None => Start::Anytime,
        }
    }
}

/// The earlier of two times, either of which may not be set.
fn earliest(a: Option<Ms>, b: Option<Ms>) -> Option<Ms> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// A request from main the machine is running.
struct Caller {
    /// Main's request ID.
    id: u64,
    /// For the outcome's log line: never an origin, address or message.
    chain_id: u64,
    method: &'static str,
    /// Its deadline, as the machine counts it: its I/O never starts at or
    /// after it.
    deadline: Ms,
    /// A broadcast's attempt cutoff: no attempt starts at or after it.
    cutoff: Option<Ms>,
}

/// The thread's monotonic clock, in milliseconds. A reading is never
/// earlier than the one before it, whatever the source does: a request
/// found past its latest start is past it at every later reading.
struct Clock {
    source: Box<dyn Fn() -> Ms>,
    latest: Cell<Ms>,
}

impl Clock {
    fn new(source: Box<dyn Fn() -> Ms>) -> Self {
        Self {
            source,
            latest: Cell::new(0),
        }
    }

    fn now(&self) -> Ms {
        let now = (self.source)().max(self.latest.get());
        self.latest.set(now);
        now
    }
}

struct Chain {
    /// Read whenever the machine is brought to now, and again as each
    /// request takes its slot at main, so nothing is dispatched against a
    /// time that has passed.
    clock: Clock,
    machine: Machine,
    out: Sender<Out>,
    /// Whether main takes fragments.
    link: Arc<Link>,
    /// Bulk replies' share of the writer.
    allowance: Arc<Allowance>,
    /// Control frames' share of the writer.
    control_allowance: Arc<Allowance>,
    /// The core's requests to main, chain's and naming's: one ID counter,
    /// main's limit of outstanding requests, and the gate closed at
    /// shutdown.
    requests: Arc<Requests>,
    /// Cancels and small replies waiting for room in the writer, in order.
    control: VecDeque<Zeroizing<Vec<u8>>>,
    /// Bulk replies waiting for room in the writer, in order.
    bulk: VecDeque<Reply>,
    /// The machine's requests waiting for a slot at main or room in the
    /// writer, first in, first out.
    queued: VecDeque<Queued>,
    /// Main's requests, by the machine's id for them.
    callers: BTreeMap<u64, Caller>,
    /// The machine's ids, by main's request ID: what a `cancel` names.
    by_main: BTreeMap<u64, u64>,
    /// This thread's `shell.*` requests, by their message ID.
    outgoing: BTreeMap<u64, Outgoing>,
    /// Message IDs by the machine's request id.
    by_io: BTreeMap<u64, u64>,
    /// Runs as each reply is queued: a test's way to act while this thread
    /// serializes one (PR #57 review, round 4).
    #[cfg(test)]
    on_reply: Option<Box<dyn FnMut()>>,
    /// Runs as each request's frame is made: a test's way to act while
    /// this thread makes one (round 5).
    #[cfg(test)]
    on_frame: Option<Box<dyn FnMut()>>,
}

/// The chain thread's two shares of the writer.
struct Shares {
    bulk: Arc<Allowance>,
    control: Arc<Allowance>,
}

/// A reply this size or under (its payload) is a control frame: it never
/// waits behind a bulk reply. Main's pool exempts replies under 64 KiB
/// (design 0005, Main's pool).
const SMALL_REPLY: usize = 64 * 1024;

impl Chain {
    fn new(
        machine: Machine,
        out: Sender<Out>,
        link: Arc<Link>,
        shares: Shares,
        requests: Arc<Requests>,
        clock: Box<dyn Fn() -> Ms>,
    ) -> Self {
        Self {
            clock: Clock::new(clock),
            machine,
            out,
            link,
            allowance: shares.bulk,
            control_allowance: shares.control,
            requests,
            control: VecDeque::new(),
            bulk: VecDeque::new(),
            queued: VecDeque::new(),
            callers: BTreeMap::new(),
            by_main: BTreeMap::new(),
            outgoing: BTreeMap::new(),
            by_io: BTreeMap::new(),
            #[cfg(test)]
            on_reply: None,
            #[cfg(test)]
            on_frame: None,
        }
    }

    /// Polls the machine, with what waits to be written counted in the
    /// chain total (`memory-budgets`).
    fn poll(&mut self) {
        let backlog = self.backlog();
        self.machine.set_output_backlog(backlog);
        self.machine.poll();
    }

    /// Brings the machine to the clock's now ([`Chain::advance`]), then
    /// sends what waits ([`Chain::deliver`]).
    fn flush(&mut self) -> Flow {
        self.advance()?;
        self.poll();
        self.deliver()
    }

    /// Brings the machine to the clock's now. Every timer and every queued
    /// request's expiry due by now is processed, in time order, the machine
    /// polled after each as the executor requires, its I/O queued and its
    /// replies taken; a request whose time runs out while it waits here
    /// completes as not sent before a timer due at the same instant fires
    /// (the machine's own for that exchange): none of it reached main
    /// (design 0005, Attempts). The clock is read again after each, since
    /// processing one (a reply serialized) takes time, until a reading finds
    /// nothing due: no work at all lies between that reading and the
    /// return.
    fn advance(&mut self) -> Flow {
        loop {
            let now = self.clock.now();
            let expiry = self.next_expiry().filter(|at| *at <= now);
            let timer = self.machine.next_due().filter(|at| *at <= now);
            match (expiry, timer) {
                (Some(at), timer) if timer.is_none_or(|due| at <= due) => {
                    // The clock up to just before it: nothing is due on the
                    // way.
                    self.machine.fire_next(at.saturating_sub(1));
                    self.expire(at);
                }
                (_, Some(_)) => {
                    self.machine.fire_next(now);
                }
                _ => {
                    // Nothing is due: the machine's clock moves to now.
                    self.machine.fire_next(now);
                    return Ok(());
                }
            }
            self.poll();
            while self.settle()? {
                self.poll();
            }
        }
    }

    /// When the first request waiting here runs out of time.
    fn next_expiry(&self) -> Option<Ms> {
        self.queued.iter().filter_map(Queued::expiry).min()
    }

    /// Completes the requests waiting here whose time ran out by `at`:
    /// unsent.
    fn expire(&mut self, at: Ms) {
        let mut i = 0;
        while i < self.queued.len() {
            if self.queued[i].expiry().is_some_and(|until| until <= at)
                && let Some(queued) = self.queued.remove(i)
            {
                self.machine
                    .complete(queued.io, unsent(kind_of(&queued.request)));
                continue;
            }
            i += 1;
        }
    }

    fn handle(&mut self, message: In) -> Flow {
        match message {
            In::Request { id, method, params } => {
                self.request(id, method, params.as_deref().map(RawValue::get))
            }
            In::Cancel { id } => {
                // Main's cancel for a request that has replied changes
                // nothing.
                if let Some(&call) = self.by_main.get(&id) {
                    self.machine.cancel(call);
                    self.poll();
                }
                Ok(())
            }
            In::Response { id, reply } => self.response(id, reply),
            In::Drained => self.pump(),
        }
    }

    fn request(&mut self, id: u64, method: &str, params: Option<&str>) -> Flow {
        let params = params.unwrap_or("{}");
        // Admission judges the total with what waits to be written.
        let backlog = self.backlog();
        self.machine.set_output_backlog(backlog);
        let invalid = || ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters");
        match method {
            "chain.configure" => {
                let Some(chains) = configure_params(params) else {
                    return self.error(id, invalid());
                };
                let generations = self.machine.configure(&chains);
                // The requests the change ended reply first: once main has
                // the new generations, nothing of the old ones is to come.
                self.take_replies()?;
                let mut map = Object::new();
                for (chain_id, generation) in generations {
                    map = map.number(&chain_id.to_string(), generation);
                }
                let result = Object::new()
                    .raw("generations", &map.finish_text())
                    .finish();
                self.result(id, result)
            }
            "chain.availability" => {
                let Some(params) = parse::<AvailabilityParams>(params) else {
                    return self.error(id, invalid());
                };
                if !params.valid() {
                    return self.error(id, invalid());
                }
                self.machine.availability(params.chain_id, params.ready);
                self.result(id, b"{}".to_vec())
            }
            "chain.request" | "chain.fee_quote" | "chain.broadcast" => {
                let Some((call, deadline_ms)) = call_params(method, params) else {
                    return self.error(id, invalid());
                };
                let bounds = self.machine.bounds();
                // Its deadline, from its arrival, as the machine counts it,
                // and when a broadcast's attempts stop (design 0005,
                // Deadlines).
                let deadline = self
                    .machine
                    .now()
                    .saturating_add(deadline_ms.min(bounds.deadline_ms));
                let cutoff = matches!(call, Call::Broadcast { .. })
                    .then(|| deadline.saturating_sub(bounds.reconcile_ms));
                let caller = Caller {
                    id,
                    chain_id: call_chain(&call),
                    method: label(&call),
                    deadline,
                    cutoff,
                };
                let call = self.machine.submit(call, Some(deadline_ms));
                self.callers.insert(call, caller);
                self.by_main.insert(id, call);
                // It starts now: its first I/O goes with this flush.
                self.poll();
                Ok(())
            }
            _ => self.error(
                id,
                ErrorBody::new(ErrorCode::UnknownMethod, "Unknown method"),
            ),
        }
    }

    /// Main's reply to a `shell.*` request, which the event loop routed
    /// here, its message moved rather than copied.
    ///
    /// - **Charged first:** when a running request still reads it, the
    ///   message is reserved against that request before any of it is
    ///   parsed, with the pass's own scratch, a byte a level of nesting
    ///   (57-M4; round 3, R3-M2).
    /// - **Checked in place:** it must be one of its request's shapes, or
    ///   it is a protocol error, even when nobody waits for it any more.
    ///   The check unescapes and copies nothing ([`RawObject`]); only a
    ///   reply nobody reads that nests past [`UNRESERVED_NESTING`] goes
    ///   unchecked, since even its scratch would be unreserved.
    /// - **Read for good** with every allocation reserved first. A
    ///   reservation refused ends that request with `budget` (a broadcast
    ///   through its outcome table) and the reply completes unread, so a
    ///   verifier's slot is still freed; so does one whose request has
    ///   ended. One for a request the machine cancelled is dropped.
    fn response(&mut self, id: u64, reply: Shell) -> Flow {
        let Some(outgoing) = self.outgoing.remove(&id) else {
            return Err(Stop::Protocol("unsolicited_response"));
        };
        let malformed = Stop::Protocol("malformed_shell_reply");
        // An error is a reply like a result (round 2, daemon review).
        let (message, span, failed) = match reply {
            Shell::Failed { message, error } => (message, error, true),
            Shell::Result { message, result } => (message, result, false),
        };
        let Some(text) = message
            .get(span)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
        else {
            return Err(malformed);
        };
        let nested = nesting(text);
        let held = match outgoing.io {
            Some(io) if self.machine.wants(io) => Some(
                self.machine
                    .reserve_reply(io, message.capacity().saturating_add(2 * nested)),
            ),
            _ => None,
        };
        let reserved = matches!(held, Some(Ok(_)));
        if !reserved && nested > UNRESERVED_NESTING {
            // Unread whatever its shape; a verifier's slot is still freed.
            if let Some(io) = outgoing.io {
                self.by_io.remove(&io);
                self.machine.complete_unread(io);
                self.poll();
            }
            return Ok(());
        }
        let shape = if failed {
            Shape::failed(text)
        } else {
            Shape::parse(outgoing.kind, text)
        }
        .ok_or(malformed)?;
        let Some(io) = outgoing.io else {
            return Ok(());
        };
        self.by_io.remove(&io);
        // Nobody reads a reply whose request has ended: it completes
        // unread, as one past the budget does.
        let read = match held {
            Some(Ok(held)) => shape.read(&self.machine, io).map(|read| (read, held)),
            Some(Err(_)) | None => Err(Unread::Over),
        };
        // The message goes before its charge does.
        drop(message);
        match read {
            Ok(((answer, reservation), held)) => {
                drop(held);
                self.machine.complete_reserved(io, answer, reservation);
            }
            Err(Unread::Malformed) => return Err(malformed),
            Err(Unread::Over) => {
                self.machine.complete_unread(io);
            }
        }
        self.poll();
        Ok(())
    }

    /// Queues the machine's requests and cancels, retires what is no
    /// longer wanted, and takes its replies, dispatching nothing. True when
    /// a request completed here, to settle at the next poll.
    fn settle(&mut self) -> Result<bool, Stop> {
        self.effects()?;
        let mut settled = self.retire();
        self.take_replies()?;
        settled |= self.retire();
        Ok(settled)
    }

    /// Sends the machine's requests, cancels and replies, each dispatch
    /// against the clock's now ([`Chain::dispatch`]). A request that
    /// completes here (expired, too large to send, or retired) settles at
    /// the next poll, so this polls and goes round again.
    fn deliver(&mut self) -> Flow {
        loop {
            let mut settled = self.settle()?;
            settled |= self.dispatch()?;
            settled |= self.settle()?;
            if !settled {
                return Ok(());
            }
            self.poll();
        }
    }

    /// Retires the queued requests of chain requests that have ended
    /// (cancelled, ended by their deadline, a configuration change or
    /// their budget, or finished): they never go to main. Whether one has
    /// ended is the machine's to say, whether or not its reply has been
    /// taken yet (round 2, R2-M2). A verifier operation's request is held
    /// by the machine until main's terminal reply, so one that never went
    /// completes here unread, freeing its slot (57-M2). True when any did.
    fn retire(&mut self) -> bool {
        let mut retired = false;
        let mut i = 0;
        while i < self.queued.len() {
            let ended = self.queued[i]
                .owner
                .is_some_and(|owner| !self.machine.runs(owner));
            if ended && let Some(queued) = self.queued.remove(i) {
                self.machine.complete_unread(queued.io);
                retired = true;
                continue;
            }
            i += 1;
        }
        retired
    }

    fn effects(&mut self) -> Flow {
        for Emitted {
            effect,
            generation,
            request: owner,
        } in self.machine.take_effects()
        {
            match effect {
                Effect::Request {
                    id: io,
                    at,
                    request,
                    ..
                } => {
                    let caller = owner.and_then(|owner| self.callers.get(&owner));
                    let own = match &request {
                        Request::Rpc { deadline_ms, .. }
                        | Request::Blockscout { deadline_ms, .. }
                        | Request::Verified(VerifiedOp::Colibri { deadline_ms, .. }) => {
                            Some(at.saturating_add(*deadline_ms))
                        }
                        Request::Verified(
                            VerifiedOp::MyotisBroadcast { .. } | VerifiedOp::MyotisRead { .. },
                        ) => None,
                    };
                    // A transaction is sent only before its broadcast's
                    // attempt cutoff; reconciliation reads run on to the
                    // deadline.
                    let sends = request.sends_transaction();
                    let cutoff = if sends {
                        caller.and_then(|caller| caller.cutoff)
                    } else {
                        None
                    };
                    let deadline = caller.map(|caller| caller.deadline);
                    self.queued.push_back(Queued {
                        io,
                        request,
                        generation: generation.unwrap_or(0),
                        owner,
                        own,
                        until: earliest(own, cutoff),
                        deadline,
                        sends,
                    });
                }
                Effect::Cancel { id: io, .. } => {
                    // Not yet sent: it never is.
                    if let Some(at) = self.queued.iter().position(|q| q.io == io) {
                        self.queued.remove(at);
                        continue;
                    }
                    let Some(id) = self.by_io.remove(&io) else {
                        continue;
                    };
                    if let Some(outgoing) = self.outgoing.get_mut(&id) {
                        outgoing.io = None;
                    }
                    let cancel = format!(r#"{{"type":"cancel","id":{id}}}"#);
                    let frame = transport::frame(cancel.as_bytes())
                        .ok_or(Stop::Protocol("oversized_message"))?;
                    self.control.push_back(frame);
                }
            }
        }
        self.pump()
    }

    /// Sends queued requests, first in, first out, while no control frame
    /// waits, a slot at main is free and the control share has room; the
    /// gate and the allowance wake the thread when one is. A request leaves the
    /// queue only when it is sent or settled here, so until then a cancel
    /// removes it. True when one settled here.
    ///
    /// No request goes against a time that has passed (PR #57 review,
    /// rounds 3 to 5, R3-M1): the machine is first brought to the clock's
    /// now ([`Chain::advance`]), whatever this thread did before (a reply
    /// serialized), so what came due meanwhile, a queued request's expiry
    /// or a timer, is processed first. Then each request's frame is made,
    /// and only then, as it takes its slot under the gate's lock, is its
    /// time read again: past its latest start (its own deadline, its chain
    /// request's, or for a transaction its broadcast's attempt cutoff), it
    /// never goes; otherwise its `deadline_ms` is what is left at that
    /// reading ([`Requests::send`], [`Queued::start`]).
    fn dispatch(&mut self) -> Result<bool, Stop> {
        self.advance()?;
        let mut settled = false;
        while self.control.is_empty() {
            let Some(queued) = self.queued.front() else {
                break;
            };
            let io = queued.io;
            let kind = kind_of(&queued.request);
            let clock = &self.clock;
            #[cfg(test)]
            let on_frame = &mut self.on_frame;
            let sent = self.requests.send(
                Owner::Chain,
                &self.control_allowance,
                &self.out,
                || {
                    let (method, (params, deadline)) =
                        shell_params(&queued.request, queued.generation);
                    let frame = requests::request_frame(method, &params, deadline);
                    #[cfg(test)]
                    if let Some(on_frame) = on_frame.as_mut() {
                        on_frame();
                    }
                    frame
                },
                || queued.start(clock.now()),
            );
            match sent {
                Dispatch::Sent(id) => {
                    self.queued.pop_front();
                    self.outgoing.insert(id, Outgoing { io: Some(io), kind });
                    self.by_io.insert(io, id);
                }
                // Over one frame: never sent (deviation `request-size`).
                Dispatch::TooLarge => {
                    self.queued.pop_front();
                    self.machine.complete(io, too_large(kind));
                    settled = true;
                }
                // Its time ran out since the machine was brought to now:
                // brought there again, it expires in time order, unsent, or
                // its chain request's deadline ends the request and it
                // retires. The clock never goes back, so one is due there.
                Dispatch::Late => {
                    self.advance()?;
                    // The machine counts that deadline as this thread does;
                    // were it ever later, the request goes unsent all the
                    // same.
                    if self.queued.front().is_some_and(|q| q.io == io) {
                        self.queued.pop_front();
                        self.machine.complete(io, unsent(kind));
                    }
                    settled = true;
                }
                // The core is exiting, main holds all it takes, or the
                // writer share is full: it waits.
                Dispatch::Closed | Dispatch::Full | Dispatch::NoRoom => break,
                Dispatch::WriterGone => return Err(Stop::Writer),
            }
        }
        Ok(settled)
    }

    /// The machine's replies, each in its wire form, queued for the writer.
    fn take_replies(&mut self) -> Flow {
        for done in self.machine.take_replies() {
            let Some(caller) = self.callers.remove(&done.id) else {
                continue;
            };
            self.by_main.remove(&caller.id);
            log_outcome(&caller, &done);
            let (generation, outcome) = (done.generation, done.outcome);
            let message = reply_message(caller.id, &done);
            let payload = if message.len() <= MAX_MESSAGE {
                message.write()
            } else {
                too_large_payload(caller.id, generation, outcome)
            };
            drop(message);
            drop(done);
            // Over one frame for a main that didn't offer fragments (or over
            // the cap): `too_large` in its place.
            let reply = match Reply::new(&self.link, caller.id, payload) {
                Some(reply) => reply,
                None => Reply::Whole(
                    transport::frame(&too_large_payload(caller.id, generation, outcome))
                        .ok_or(Stop::Protocol("oversized_message"))?,
                ),
            };
            match reply {
                Reply::Whole(frame) if frame.len() <= SMALL_REPLY + 5 => {
                    self.control.push_back(frame);
                }
                reply => self.bulk.push_back(reply),
            }
            #[cfg(test)]
            if let Some(on_reply) = self.on_reply.as_mut() {
                on_reply();
            }
        }
        self.pump()
    }

    fn result(&mut self, id: u64, result: Vec<u8>) -> Flow {
        let mut payload = Zeroizing::new(Vec::with_capacity(result.len() + 48));
        payload.extend_from_slice(br#"{"type":"response","id":"#);
        payload.extend_from_slice(id.to_string().as_bytes());
        payload.extend_from_slice(br#","result":"#);
        payload.extend_from_slice(&result);
        payload.push(b'}');
        self.send(&payload)
    }

    fn error(&mut self, id: u64, error: ErrorBody) -> Flow {
        let mut payload = Zeroizing::new(Vec::with_capacity(128));
        fc_protocol::message::write_error(&mut *payload, id, &error)
            .map_err(|_| Stop::Protocol("unwritable_result"))?;
        self.send(&payload)
    }

    /// Queues a small reply behind the control frames that wait.
    fn send(&mut self, payload: &[u8]) -> Flow {
        let frame = transport::frame(payload).ok_or(Stop::Protocol("oversized_message"))?;
        self.control.push_back(frame);
        self.pump()
    }

    /// What chain has made and not yet written: the frames the writer
    /// holds, the replies and cancels waiting here, and the requests that
    /// wait to go (design 0005, Bounds: they left their request's charge).
    fn backlog(&self) -> usize {
        self.allowance.held_bytes()
            + self.control_allowance.held_bytes()
            + self.control.iter().map(|f| f.len()).sum::<usize>()
            + self.bulk.iter().map(Reply::len).sum::<usize>()
            + self
                .queued
                .iter()
                .map(|q| request_bytes(&q.request))
                .sum::<usize>()
    }

    /// Hands every waiting frame to the writer, past the allowances: at
    /// shutdown, where the writer's drain is bounded by time instead.
    fn drain(&mut self) {
        for frame in self.control.drain(..) {
            let hold = self.control_allowance.force(frame.len());
            let _ = self.out.send(Out::Frame { frame, hold });
        }
        for reply in self.bulk.drain(..) {
            let hold = self.allowance.force(reply.len());
            let _ = self.out.send(reply.into_out(hold));
        }
    }

    /// Hands waiting frames to the writer while their share has room, the
    /// control frames first and apart from the bulk replies; the rest wait
    /// for [`In::Drained`].
    fn pump(&mut self) -> Flow {
        while let Some(frame) = self.control.front() {
            let Some(hold) = self.control_allowance.take(frame.len()) else {
                break;
            };
            let Some(frame) = self.control.pop_front() else {
                break;
            };
            self.out
                .send(Out::Frame { frame, hold })
                .map_err(|_| Stop::Writer)?;
        }
        while let Some(reply) = self.bulk.front() {
            let Some(hold) = self.allowance.take(reply.len()) else {
                return Ok(());
            };
            let Some(reply) = self.bulk.pop_front() else {
                return Ok(());
            };
            self.out
                .send(reply.into_out(hold))
                .map_err(|_| Stop::Writer)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The core's requests to main (design 0005, Requests the core makes).

/// A `shell.*` request's method, and its params with the generation it
/// runs under. Where the design has a `deadline_ms`, the params have a slot
/// for it, written as the request takes its slot at main
/// ([`requests::RequestFrame`]), and where it starts comes with them.
fn shell_params(request: &Request, generation: u64) -> (&'static str, (Vec<u8>, Option<usize>)) {
    match request {
        Request::Rpc {
            endpoint,
            body,
            max_bytes,
            ..
        } => (
            "shell.rpc",
            Object::new()
                .string("endpoint", endpoint)
                .string("body", body)
                .string("policy", "plain")
                .number("max_bytes", *max_bytes as u64)
                .number("generation", generation)
                .deadline_slot()
                .finish_params(),
        ),
        Request::Blockscout {
            endpoint,
            query,
            max_bytes,
            ..
        } => (
            "shell.blockscout",
            Object::new()
                .string("endpoint", endpoint)
                .string("query", query)
                .number("max_bytes", *max_bytes as u64)
                .number("generation", generation)
                .deadline_slot()
                .finish_params(),
        ),
        Request::Verified(VerifiedOp::MyotisRead {
            chain_id,
            operation,
        }) => {
            let name = match operation {
                MyotisOperation::Account { .. } => "account",
                MyotisOperation::Code { .. } => "code",
                MyotisOperation::Storage { .. } => "storage",
                MyotisOperation::CallTx { .. } => "call_tx",
                MyotisOperation::EstimateTx { .. } => "estimate_tx",
                MyotisOperation::Fee => "fee",
            };
            let op = Object::new()
                .string("myotis", name)
                .number("chain_id", *chain_id);
            // The caller's arguments as JSON; `undefined` ones are left out.
            let op = match operation {
                MyotisOperation::Account { address } | MyotisOperation::Code { address } => {
                    op.raw_opt("address", address.as_deref())
                }
                MyotisOperation::Storage { address, slot } => op
                    .raw_opt("address", address.as_deref())
                    .raw_opt("slot", slot.as_deref()),
                MyotisOperation::CallTx { tx } | MyotisOperation::EstimateTx { tx } => {
                    op.raw("tx", tx)
                }
                MyotisOperation::Fee => op,
            };
            (
                "shell.verified",
                op.number("generation", generation).finish_params(),
            )
        }
        Request::Verified(VerifiedOp::MyotisBroadcast { chain_id, raw }) => (
            "shell.verified",
            Object::new()
                .string("myotis", "broadcast")
                .number("chain_id", *chain_id)
                .string("raw", raw)
                .number("generation", generation)
                .finish_params(),
        ),
        Request::Verified(VerifiedOp::Colibri {
            chain_id,
            method,
            params,
            ..
        }) => (
            "shell.verified",
            Object::new()
                .string("colibri", "request")
                .number("chain_id", *chain_id)
                .string("method", method)
                .raw("params", params)
                .deadline_slot()
                .number("generation", generation)
                .finish_params(),
        ),
    }
}

fn kind_of(request: &Request) -> Kind {
    match request {
        Request::Rpc { .. } => Kind::Rpc,
        Request::Blockscout { .. } => Kind::Blockscout,
        Request::Verified(VerifiedOp::MyotisRead { .. }) => Kind::MyotisRead,
        Request::Verified(VerifiedOp::MyotisBroadcast { .. }) => Kind::MyotisBroadcast,
        Request::Verified(VerifiedOp::Colibri { .. }) => Kind::Colibri,
    }
}

/// What a request waiting here holds.
fn request_bytes(request: &Request) -> usize {
    match request {
        Request::Rpc { endpoint, body, .. } => endpoint.len() + body.len(),
        Request::Blockscout {
            endpoint, query, ..
        } => endpoint.len() + query.len(),
        Request::Verified(VerifiedOp::MyotisRead { operation, .. }) => match operation {
            MyotisOperation::Account { address } | MyotisOperation::Code { address } => {
                address.as_ref().map_or(0, String::len)
            }
            MyotisOperation::Storage { address, slot } => {
                address.as_ref().map_or(0, String::len) + slot.as_ref().map_or(0, String::len)
            }
            MyotisOperation::CallTx { tx } | MyotisOperation::EstimateTx { tx } => tx.len(),
            MyotisOperation::Fee => 0,
        },
        Request::Verified(VerifiedOp::MyotisBroadcast { raw, .. }) => raw.len(),
        Request::Verified(VerifiedOp::Colibri { method, params, .. }) => {
            method.len() + params.len()
        }
    }
}

/// The answer for a request that never went to main because its time ran
/// out first: nothing of it was sent (design 0005, Attempts: an attempt
/// the core never sent to main is not sent). A verifier operation still
/// completes, so its slot is freed.
fn unsent(kind: Kind) -> Answer {
    match kind {
        Kind::Rpc | Kind::Blockscout => Answer::NotSent,
        Kind::MyotisRead => Answer::Myotis(MyotisReply::Failure(MyotisClass::Error)),
        Kind::MyotisBroadcast => Answer::Myotis(MyotisReply::NotSent),
        Kind::Colibri => Answer::Colibri(ColibriReply::Failure(ColibriClass::Error)),
    }
}

/// The answer for a request over one frame, which never goes: an exchange
/// or a broadcast is not sent; a verifier read fails `too_large`, as a
/// reply over the cap does (design 0005, Verified operations).
fn too_large(kind: Kind) -> Answer {
    match kind {
        Kind::Rpc | Kind::Blockscout => Answer::NotSent,
        Kind::MyotisRead => Answer::Myotis(MyotisReply::Failure(MyotisClass::TooLarge)),
        Kind::MyotisBroadcast => Answer::Myotis(MyotisReply::NotSent),
        Kind::Colibri => Answer::Colibri(ColibriReply::Failure(ColibriClass::TooLarge)),
    }
}

/// Myotis's failure classes, chain data's own closed set (design 0005,
/// Myotis read outcomes).
const MYOTIS_CLASSES: &[(&str, MyotisClass)] = &[
    ("not_running", MyotisClass::NotRunning),
    ("not_ready", MyotisClass::NotReady),
    ("state_changed", MyotisClass::StateChanged),
    ("queue_full", MyotisClass::QueueFull),
    ("queue_deadline", MyotisClass::QueueDeadline),
    ("caller_deadline", MyotisClass::CallerDeadline),
    ("too_large", MyotisClass::TooLarge),
    ("busy", MyotisClass::Busy),
    ("error", MyotisClass::Error),
];

fn myotis_class(class: &str) -> Option<MyotisClass> {
    MYOTIS_CLASSES
        .iter()
        .find(|(name, _)| *name == class)
        .map(|(_, class)| *class)
}

/// Colibri's classes: the chain set and its own `capacity`. What the
/// machine doesn't tell apart is `error`.
fn colibri_class(class: &str) -> Option<ColibriClass> {
    match class {
        "capacity" => Some(ColibriClass::Capacity),
        "too_large" => Some(ColibriClass::TooLarge),
        "busy" => Some(ColibriClass::Busy),
        other => myotis_class(other).map(|_| ColibriClass::Error),
    }
}

/// A JSON object's members, read in place: each name and value is its
/// raw JSON, so nothing is unescaped and serde_json takes no scratch for a
/// string (PR #57 review, round 3, R3-M2). A member is present whatever its
/// value, `null` included (R2-M1). A name with an escape (JSON.stringify
/// writes none for the names here), a member given twice, or more than `N`
/// members is refused as it is read, before anything is allocated: the
/// members sit in a fixed array.
struct RawObject<'a, const N: usize> {
    len: usize,
    items: [(&'a str, Option<&'a RawValue>); N],
}

impl<'a, const N: usize> RawObject<'a, N> {
    /// `text` as such an object; `None` for anything else.
    fn parse(text: &'a str) -> Option<Self> {
        serde_json::from_str::<Self>(text).ok()
    }

    fn iter(&self) -> impl Iterator<Item = (&'a str, &'a RawValue)> + '_ {
        self.items[..self.len]
            .iter()
            .filter_map(|(name, value)| value.map(|value| (*name, value)))
    }

    fn get(&self, name: &str) -> Option<&'a RawValue> {
        self.iter()
            .find(|(n, _)| *n == name)
            .map(|(_, value)| value)
    }

    /// Whether its members are exactly `names`.
    fn are(&self, names: &[&str]) -> bool {
        self.len == names.len() && names.iter().all(|name| self.get(name).is_some())
    }

    /// Whether it has `required`, and no member outside `allowed`.
    fn within(&self, required: &str, allowed: &[&str]) -> bool {
        self.get(required).is_some() && self.iter().all(|(name, _)| allowed.contains(&name))
    }
}

impl<'de, const N: usize> Deserialize<'de> for RawObject<'de, N> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visit<const N: usize>;

        impl<'de, const N: usize> serde::de::Visitor<'de> for Visit<N> {
            type Value = RawObject<'de, N>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a JSON object of at most {N} members")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<RawObject<'de, N>, A::Error> {
                use serde::de::Error as _;
                let mut object = RawObject {
                    len: 0,
                    items: [("", None); N],
                };
                while let Some(name) = map.next_key::<&'de RawValue>()? {
                    let name = plain(name).ok_or_else(|| A::Error::custom("an escaped name"))?;
                    if object.get(name).is_some() {
                        return Err(A::Error::custom("a member given twice"));
                    }
                    let Some(slot) = object.items.get_mut(object.len) else {
                        return Err(A::Error::custom("too many members"));
                    };
                    *slot = (name, Some(map.next_value::<&'de RawValue>()?));
                    object.len += 1;
                }
                Ok(object)
            }
        }

        d.deserialize_map(Visit::<N>)
    }
}

/// A JSON string with no escape, as its text; `None` for anything else.
/// Codes, classes, names and base64 bodies need no escape, and
/// JSON.stringify writes them with none.
fn plain(raw: &RawValue) -> Option<&str> {
    let text = raw.get().strip_prefix('"')?.strip_suffix('"')?;
    (!text.contains('\\')).then_some(text)
}

/// How deep `text`'s arrays and objects nest: what serde_json's pass over a
/// raw value keeps on its scratch stack, a byte a level. Counted in place.
fn nesting(text: &str) -> usize {
    let (mut depth, mut deepest) = (0usize, 0usize);
    let (mut string, mut escaped) = (false, false);
    for byte in text.bytes() {
        if string {
            match byte {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => string = true,
            b'[' | b'{' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

/// Past this nesting, a reply nobody reads (or whose reading crossed its
/// budget) isn't parsed at all: its scratch would be unreserved. It is
/// dropped unread, as it would be after the parse.
const UNRESERVED_NESTING: usize = 512;

/// A present member stays `Some`, even when its value is `null`.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<&'de RawValue>, D::Error> {
    <&'de RawValue>::deserialize(d).map(Some)
}

/// A member that must be present and may be `null`: serde would otherwise
/// take a missing `Option` member for `null`.
fn nullable<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

/// `T` read from a JSON object only. Serde's derived structs also take a
/// positional array, which no shape here has: `[true]` must never pass for
/// `{ "not_sent": true }` (PR #57 review, 57-M1).
struct ObjectOf<T>(T);

impl<T> ObjectOf<T> {
    fn into_inner(self) -> T {
        self.0
    }
}

impl<T> std::ops::Deref for ObjectOf<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for ObjectOf<T> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Only<T>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Only<T> {
            type Value = T;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
            }
        }

        d.deserialize_map(Only(std::marker::PhantomData))
            .map(ObjectOf)
    }
}

/// The most headers a Blockscout page's reply carries. The core reads
/// three ([`BLOCKSCOUT_HEADERS`]), so main sends those it has; a few more
/// are tolerated, any more is a malformed reply (design 0005, Requests the
/// core makes; PR #57 review, round 2, R2-M3).
const MAX_BLOCKSCOUT_HEADERS: usize = 8;

/// The headers the core reads from a Blockscout page, by name, as
/// `Headers#get` does (ASCII case ignored): the size check and the
/// cooldown (design 0005, Logs).
const BLOCKSCOUT_HEADERS: [&str; 3] = ["content-length", "x-ratelimit-reset", "retry-after"];

/// A page's headers, checked in place: an object of at most
/// [`MAX_BLOCKSCOUT_HEADERS`] strings, none unescaped.
fn headers_of(raw: &RawValue) -> Option<RawObject<'_, MAX_BLOCKSCOUT_HEADERS>> {
    let headers = RawObject::<MAX_BLOCKSCOUT_HEADERS>::parse(raw.get())?;
    let strings = headers.iter().all(|(_, value)| is_string(value));
    strings.then_some(headers)
}

/// The headers the core reads, unescaped into a vector of
/// [`MAX_BLOCKSCOUT_HEADERS`] places: the caller has reserved room for
/// those places and for every string the object holds. Only these three
/// are unescaped; `None` when one is no valid string.
fn kept_headers(raw: &RawValue) -> Option<Vec<(String, String)>> {
    let headers = headers_of(raw)?;
    let mut kept = Vec::with_capacity(MAX_BLOCKSCOUT_HEADERS);
    for (name, value) in headers.iter() {
        if BLOCKSCOUT_HEADERS
            .iter()
            .any(|known| known.eq_ignore_ascii_case(name))
        {
            kept.push((name.to_owned(), decode_string(value.get())?));
        }
    }
    Some(kept)
}

/// A transport failure: one of the closed set, with no text and no data
/// (design 0004, Transport errors); `None` for anything else, which is
/// malformed. Only `not_sent` proves nothing was sent, so every failure may
/// have followed a send.
fn transport_failure(code: &str) -> Option<Transport> {
    Some(match code {
        "timeout" | "deadline" => Transport::Timeout,
        "network" | "cancelled" | "stale_generation" => Transport::Network,
        "refused" => Transport::Refused,
        "too_large" => Transport::TooLarge,
        "busy" => Transport::Busy,
        _ => return None,
    })
}

/// Main's reply, read in place: borrowed from its message, with nothing
/// allocated, every structural boundary a JSON object (57-M1) and every
/// shape's members exact, a `null` member included (R2-M1). Reading it for
/// good ([`Shape::read`]) reserves each allocation first (57-M4).
#[derive(Debug)]
enum Shape<'a> {
    /// A transport failure.
    Failed(Transport),
    /// `{ "not_sent": true }`; for a Myotis broadcast, its own form.
    NotSent {
        broadcast: bool,
    },
    Http {
        status: u16,
        body: &'a str,
    },
    Page {
        status: u16,
        headers: &'a RawValue,
        body: &'a str,
    },
    Read {
        payload: &'a RawValue,
        before: Option<&'a RawValue>,
        after: Option<&'a RawValue>,
    },
    MyotisFailure(MyotisClass),
    Sent(&'a RawValue),
    /// The reason, a JSON string.
    Rejected(&'a RawValue),
    Uncertain,
    ColibriResult(&'a RawValue),
    /// `{ undefined_keys: ["result"] }`: Colibri's result was `undefined`.
    ColibriUndefined,
    /// The data, a JSON string, and whether main also classed the error a
    /// capacity failure.
    Revert {
        data: &'a RawValue,
        capacity: bool,
    },
    ColibriFailure(ColibriClass),
}

/// Why a reply was not read for good.
#[derive(Debug, PartialEq, Eq)]
enum Unread {
    /// Reading it would cross its request's budget: the request is over.
    Over,
    /// Main's reply is malformed after all (its base64, a string's escapes).
    Malformed,
}

/// Whether a raw value is a JSON string.
fn is_string(raw: &RawValue) -> bool {
    raw.get().starts_with('"')
}

/// A raw value's text, or `None` for `null`.
fn unless_null(raw: Option<&RawValue>) -> Option<&RawValue> {
    raw.filter(|raw| raw.get() != "null")
}

impl<'a> Shape<'a> {
    /// Main's `error`, as a transport failure: a code of the closed set, a
    /// string message, no other member; `None` when it is malformed.
    fn failed(text: &'a str) -> Option<Self> {
        let error = RawObject::<2>::parse(text)?;
        if !error.are(&["code", "message"]) || !is_string(error.get("message")?) {
            return None;
        }
        transport_failure(plain(error.get("code")?)?).map(Shape::Failed)
    }

    /// Main's terminal reply to a request of `kind`; `None` when it is
    /// malformed. Read in place: nothing is unescaped or copied.
    fn parse(kind: Kind, text: &'a str) -> Option<Self> {
        let reply = RawObject::<3>::parse(text)?;
        if reply.get("not_sent").is_some() {
            // `{ "not_sent": true }`, alone; only `true` says it.
            let alone = reply.are(&["not_sent"]) && reply.get("not_sent")?.get() == "true";
            return alone.then_some(Shape::NotSent {
                broadcast: kind == Kind::MyotisBroadcast,
            });
        }
        let status = |raw: &RawValue| serde_json::from_str::<u16>(raw.get()).ok();
        match kind {
            Kind::Rpc => {
                if !reply.are(&["status", "body"]) {
                    return None;
                }
                Some(Shape::Http {
                    status: status(reply.get("status")?)?,
                    body: plain(reply.get("body")?)?,
                })
            }
            Kind::Blockscout => {
                if !reply.are(&["status", "headers", "body"]) {
                    return None;
                }
                let headers = reply.get("headers")?;
                headers_of(headers)?;
                Some(Shape::Page {
                    status: status(reply.get("status")?)?,
                    headers,
                    body: plain(reply.get("body")?)?,
                })
            }
            Kind::MyotisRead | Kind::MyotisBroadcast | Kind::Colibri => {
                Self::verified(kind, &reply)
            }
        }
    }

    /// A verified operation's reply, which must be exactly one of its
    /// operation's shapes (design 0005, Verified operations): a failure
    /// stands alone and carries only its class, and a member that belongs
    /// to another shape is malformed whatever its value, `null` included.
    /// Only a Myotis read's `block_before` and `block_after` may be `null`
    /// or absent.
    fn verified(kind: Kind, members: &RawObject<'a, 3>) -> Option<Self> {
        let class = || plain(members.get("failure")?);
        // `{ <name>: <a JSON string> }`, in place.
        let wrapped = |member: &str, name: &str| {
            let object = RawObject::<1>::parse(members.get(member)?.get())?;
            let value = object.get(name)?;
            (object.are(&[name]) && is_string(value)).then_some(value)
        };
        match kind {
            Kind::MyotisRead => {
                if members.are(&["failure"]) {
                    return myotis_class(class()?).map(Shape::MyotisFailure);
                }
                if !members.within("payload", &["payload", "block_before", "block_after"]) {
                    return None;
                }
                Some(Shape::Read {
                    payload: members.get("payload")?,
                    before: unless_null(members.get("block_before")),
                    after: unless_null(members.get("block_after")),
                })
            }
            Kind::MyotisBroadcast => {
                if members.are(&["failure"]) {
                    myotis_class(class()?).map(Shape::MyotisFailure)
                } else if members.are(&["hash"]) {
                    members.get("hash").map(Shape::Sent)
                } else if members.are(&["rejected"]) {
                    wrapped("rejected", "reason").map(Shape::Rejected)
                } else if members.are(&["uncertain"]) {
                    (members.get("uncertain")?.get() == "true").then_some(Shape::Uncertain)
                } else {
                    None
                }
            }
            Kind::Colibri => {
                if members.are(&["failure"]) {
                    colibri_class(class()?).map(Shape::ColibriFailure)
                } else if members.are(&["result"]) {
                    members.get("result").map(Shape::ColibriResult)
                } else if members.are(&["undefined_keys"]) {
                    // Exactly `["result"]`: nothing else is ever undefined.
                    let (key,) =
                        serde_json::from_str::<(&RawValue,)>(members.get("undefined_keys")?.get())
                            .ok()?;
                    (plain(key)? == "result").then_some(Shape::ColibriUndefined)
                } else if members.are(&["revert"]) {
                    wrapped("revert", "data").map(|data| Shape::Revert {
                        data,
                        capacity: false,
                    })
                } else if members.are(&["revert", "capacity"]) {
                    // `capacity` is sent only when it is `true`.
                    if members.get("capacity")?.get() != "true" {
                        return None;
                    }
                    wrapped("revert", "data").map(|data| Shape::Revert {
                        data,
                        capacity: true,
                    })
                } else {
                    None
                }
            }
            Kind::Rpc | Kind::Blockscout => None,
        }
    }

    /// The machine's answer, each allocation reserved first against the
    /// request that made I/O request `io`, with the reservation that covers
    /// it (57-M4).
    fn read(self, machine: &Machine, io: u64) -> Result<(Answer, Reservation), Unread> {
        let reserve = |bytes: usize| machine.reserve_reply(io, bytes).map_err(|_| Unread::Over);
        let copy = |raw: &RawValue| raw.get().to_owned();
        Ok(match self {
            Shape::Failed(transport) => (Answer::Failed(transport), reserve(0)?),
            Shape::NotSent { broadcast } => {
                let answer = if broadcast {
                    Answer::Myotis(MyotisReply::NotSent)
                } else {
                    Answer::NotSent
                };
                (answer, reserve(0)?)
            }
            Shape::Http { status, body } => {
                let mut reservation = reserve(0)?;
                let body = decode_base64(body, &mut reservation)?;
                (Answer::Rpc { status, body }, reservation)
            }
            Shape::Page {
                status,
                headers,
                body,
            } => {
                // The vector's places, and every string the object holds,
                // each at most its JSON text, all of them at once while the
                // object is read (R2-M3).
                let places = MAX_BLOCKSCOUT_HEADERS * std::mem::size_of::<(String, String)>();
                let mut reservation = reserve(places.saturating_add(headers.get().len()))?;
                let headers = kept_headers(headers).ok_or(Unread::Malformed)?;
                let body = decode_base64(body, &mut reservation)?;
                (
                    Answer::Blockscout {
                        status,
                        headers,
                        body,
                    },
                    reservation,
                )
            }
            Shape::Read {
                payload,
                before,
                after,
            } => {
                let len = |raw: Option<&RawValue>| raw.map_or(0, |r| r.get().len());
                let reservation = reserve(payload.get().len() + len(before) + len(after))?;
                (
                    Answer::Myotis(MyotisReply::Read {
                        payload: copy(payload),
                        block_before: before.map(copy),
                        block_after: after.map(copy),
                    }),
                    reservation,
                )
            }
            Shape::MyotisFailure(class) => {
                (Answer::Myotis(MyotisReply::Failure(class)), reserve(0)?)
            }
            Shape::Sent(hash) => {
                let reservation = reserve(hash.get().len())?;
                (
                    Answer::Myotis(MyotisReply::Sent { hash: copy(hash) }),
                    reservation,
                )
            }
            Shape::Rejected(reason) => {
                let reservation = reserve(reason.get().len())?;
                let reason = decode_string(reason.get()).ok_or(Unread::Malformed)?;
                (
                    Answer::Myotis(MyotisReply::Rejected { reason }),
                    reservation,
                )
            }
            Shape::Uncertain => (Answer::Myotis(MyotisReply::Uncertain), reserve(0)?),
            Shape::ColibriResult(result) => {
                let reservation = reserve(result.get().len())?;
                (
                    Answer::Colibri(ColibriReply::Result(copy(result))),
                    reservation,
                )
            }
            Shape::ColibriUndefined => (Answer::Colibri(ColibriReply::Undefined), reserve(0)?),
            Shape::Revert { data, capacity } => {
                let reservation = reserve(data.get().len())?;
                let data = decode_string(data.get()).ok_or(Unread::Malformed)?;
                (
                    Answer::Colibri(ColibriReply::Revert { data, capacity }),
                    reservation,
                )
            }
            Shape::ColibriFailure(class) => {
                (Answer::Colibri(ColibriReply::Failure(class)), reserve(0)?)
            }
        })
    }
}

/// A base64 body, decoded into a buffer whose room `reservation` grows to
/// cover before it is allocated.
fn decode_base64(body: &str, reservation: &mut Reservation) -> Result<Vec<u8>, Unread> {
    let room = base64::decoded_len_estimate(body.len());
    let held = reservation.bytes();
    reservation
        .settle(held.saturating_add(room))
        .map_err(|_| Unread::Over)?;
    let mut decoded = vec![0u8; room];
    let len = base64::engine::general_purpose::STANDARD
        .decode_slice(body.as_bytes(), &mut decoded)
        .map_err(|_| Unread::Malformed)?;
    decoded.truncate(len);
    Ok(decoded)
}

/// The text of the JSON string `raw`, each lone surrogate replaced by
/// U+FFFD, decoded in one pass into a buffer of the JSON's length (its
/// bound: no escape decodes longer than it is written); `None` for anything
/// but a string.
fn decode_string(raw: &str) -> Option<String> {
    let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(inner.len());
    let bytes = inner.as_bytes();
    let hex4 = |at: usize| -> Option<u32> {
        let digits = inner.get(at..at + 4)?;
        if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u32::from_str_radix(digits, 16).ok()
    };
    let (mut i, mut start) = (0, 0);
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                out.push_str(inner.get(start..i)?);
                let escape = *bytes.get(i + 1)?;
                i += 2;
                match escape {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let unit = hex4(i)?;
                        i += 4;
                        let pair = (0xD800..0xDC00).contains(&unit)
                            && inner.get(i..i + 2) == Some("\\u")
                            && hex4(i + 2).is_some_and(|t| (0xDC00..0xE000).contains(&t));
                        let c = if pair {
                            let trail = hex4(i + 2)?;
                            i += 6;
                            char::from_u32(0x10000 + ((unit - 0xD800) << 10) + (trail - 0xDC00))
                        } else {
                            char::from_u32(unit)
                        };
                        // A lone surrogate is no char.
                        out.push(c.unwrap_or('\u{fffd}'));
                    }
                    _ => return None,
                }
                start = i;
            }
            b'"' | 0..=0x1f => return None,
            _ => i += 1,
        }
    }
    out.push_str(inner.get(start..)?);
    Some(out)
}

// ---------------------------------------------------------------------------
// Main's requests (design 0005, Methods main calls).

/// The largest chain ID: JavaScript represents it exactly.
const MAX_CHAIN_ID: u64 = MAX_ID;

/// At most this many RPC endpoints per chain (design 0005, Configuration;
/// as 0004, the core refuses a longer list).
const MAX_RPC_ENDPOINTS: usize = 64;

/// Params from a JSON object: never an array serde would also take for a
/// struct, at any depth (every nested shape is an [`ObjectOf`]).
fn parse<'a, T: Deserialize<'a>>(params: &'a str) -> Option<T> {
    serde_json::from_str::<ObjectOf<T>>(params)
        .ok()
        .map(ObjectOf::into_inner)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigureParams<'a> {
    #[serde(borrow)]
    chains: Vec<ObjectOf<ChainParam<'a>>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainParam<'a> {
    chain_id: u64,
    display_name: String,
    read_order: Vec<String>,
    broadcast_order: Vec<String>,
    /// `network.quorum` as the registry merges it, raw: the machine applies
    /// today's coercions, defaults and clamps, and the core's bounds.
    #[serde(borrow, default)]
    quorum: Option<ObjectOf<QuorumParam<'a>>>,
    rpc: Vec<ObjectOf<RpcParam>>,
    /// Present, `null` when the chain has none (design 0005,
    /// Configuration).
    #[serde(deserialize_with = "nullable")]
    prover: Option<ObjectOf<ProverParam>>,
    myotis: bool,
    #[serde(deserialize_with = "nullable")]
    blockscout: Option<ObjectOf<BlockscoutParam>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuorumParam<'a> {
    #[serde(borrow, default, deserialize_with = "present")]
    k: Option<&'a RawValue>,
    #[serde(borrow, default, deserialize_with = "present")]
    m: Option<&'a RawValue>,
    #[serde(borrow, default, deserialize_with = "present")]
    timeout_ms: Option<&'a RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcParam {
    endpoint: String,
    user_configured: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProverParam {
    endpoint: String,
    zk: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockscoutParam {
    endpoint: String,
}

/// `chain.configure`'s snapshot as the machine takes it; `None` when it is
/// invalid: a chain ID JavaScript can't represent, one given twice, or more
/// than 64 endpoints. Orders keep unknown and repeated names, which the
/// machine drops (deviation `order-validation`); quorum values stay raw.
fn configure_params(params: &str) -> Option<Vec<ChainConfig>> {
    let snapshot: ConfigureParams = parse(params)?;
    let mut seen = BTreeSet::new();
    let mut chains = Vec::with_capacity(snapshot.chains.len());
    for chain in snapshot.chains {
        let chain = chain.into_inner();
        if chain.chain_id > MAX_CHAIN_ID
            || !seen.insert(chain.chain_id)
            || chain.rpc.len() > MAX_RPC_ENDPOINTS
        {
            return None;
        }
        let raw = |value: Option<&RawValue>| value.map(|v| v.get().to_owned());
        let quorum = chain
            .quorum
            .map_or_else(QuorumConfig::default, |q| QuorumConfig {
                k: raw(q.k),
                m: raw(q.m),
                timeout_ms: raw(q.timeout_ms),
            });
        chains.push(ChainConfig {
            chain_id: chain.chain_id,
            display_name: chain.display_name,
            read_order: chain.read_order,
            broadcast_order: chain.broadcast_order,
            quorum,
            rpc: chain
                .rpc
                .into_iter()
                .map(|e| {
                    let e = e.into_inner();
                    RpcEndpoint {
                        endpoint: e.endpoint,
                        user_configured: e.user_configured,
                    }
                })
                .collect(),
            prover: chain.prover.map(|p| {
                let p = p.into_inner();
                Prover {
                    endpoint: p.endpoint,
                    zk: p.zk,
                }
            }),
            myotis: chain.myotis,
            blockscout: chain.blockscout.map(|b| b.into_inner().endpoint),
        });
    }
    Some(chains)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AvailabilityParams {
    chain_id: u64,
    ready: bool,
}

impl AvailabilityParams {
    fn valid(&self) -> bool {
        self.chain_id <= MAX_CHAIN_ID
    }
}

/// A read's profile: the Ant bridge's options become one named profile.
#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum Profile {
    Default,
    AntScan,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestParams<'a> {
    chain_id: u64,
    method: String,
    /// The caller's JSON as main serializes it, kept as text so the core
    /// reads it in JavaScript's property order.
    #[serde(borrow)]
    params: &'a RawValue,
    include_trust: bool,
    /// The routing context: it stays in memory and is never logged.
    #[serde(default)]
    origin: Option<String>,
    background: bool,
    profile: Profile,
    deadline_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FeeQuoteParams {
    chain_id: u64,
    deadline_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BroadcastParams {
    chain_id: u64,
    raw: String,
    deadline_ms: u64,
}

/// A request's call and what is left of its caller's deadline; `None` when
/// its params are invalid. `deadline_ms` is at most 120 s (design 0005,
/// Methods main calls); main never sends more.
fn call_params(method: &str, params: &str) -> Option<(Call, Ms)> {
    let deadline = Bounds::default().deadline_ms;
    let valid = |chain_id: u64, deadline_ms: u64| {
        (chain_id <= MAX_CHAIN_ID && deadline_ms <= deadline).then_some(deadline_ms)
    };
    match method {
        "chain.request" => {
            let p: RequestParams = parse(params)?;
            let deadline_ms = valid(p.chain_id, p.deadline_ms)?;
            let mut options = match p.profile {
                Profile::Default => ReadOptions::default(),
                Profile::AntScan => ReadOptions::ant_scan(),
            };
            options.include_trust |= p.include_trust;
            options.background |= p.background;
            options.origin = p.origin;
            Some((
                Call::Read {
                    chain_id: p.chain_id,
                    method: p.method,
                    params: p.params.get().to_owned(),
                    options,
                },
                deadline_ms,
            ))
        }
        "chain.fee_quote" => {
            let p: FeeQuoteParams = parse(params)?;
            let deadline_ms = valid(p.chain_id, p.deadline_ms)?;
            Some((
                Call::FeeQuote {
                    chain_id: p.chain_id,
                },
                deadline_ms,
            ))
        }
        "chain.broadcast" => {
            let p: BroadcastParams = parse(params)?;
            let deadline_ms = valid(p.chain_id, p.deadline_ms)?;
            Some((
                Call::Broadcast {
                    chain_id: p.chain_id,
                    raw: p.raw,
                },
                deadline_ms,
            ))
        }
        _ => None,
    }
}

fn call_chain(call: &Call) -> u64 {
    match call {
        Call::Read { chain_id, .. }
        | Call::FeeQuote { chain_id }
        | Call::Broadcast { chain_id, .. } => *chain_id,
    }
}

/// A call's name for the log: a known read method, never a caller's text.
fn label(call: &Call) -> &'static str {
    match call {
        Call::Read { method, .. } => READ_METHODS
            .iter()
            .chain(SINGLE_NODE_METHODS.iter())
            .find(|known| **known == method.as_str())
            .copied()
            .unwrap_or("unsupported"),
        Call::FeeQuote { .. } => "fee_quote",
        Call::Broadcast { .. } => "broadcast",
    }
}

/// The sources a result can name, for the log.
const SOURCES: &[&str] = &[
    "myotis",
    "colibri",
    "quorum",
    "direct",
    "blockscout",
    "reconcile",
];

/// Logs a request's outcome by chain, method and source only (design 0005,
/// Errors and text): never an origin, an address or a message.
fn log_outcome(caller: &Caller, done: &Done) {
    let source = match &done.result {
        Ok(Success::Read { source, .. } | Success::Broadcast { source, .. }) => Some(*source),
        Ok(Success::FeeQuote(quote)) => {
            let named = match quote {
                fc_chain::FeeQuote::Legacy { source, .. }
                | fc_chain::FeeQuote::Eip1559 { source, .. } => source.as_str(),
            };
            SOURCES.iter().find(|known| **known == named).copied()
        }
        Err(_) => None,
    };
    let outcome = match &done.result {
        Ok(Success::Broadcast { outcome, .. }) => outcome.as_str(),
        Ok(_) => "ok",
        Err(ChainError::Thrown(_)) => done.outcome.map_or("chain_error", BroadcastOutcome::as_str),
        Err(ChainError::Protocol(code)) => code.as_str(),
    };
    log::info(
        "chain request",
        serde_json::json!({
            "chain": caller.chain_id,
            "method": caller.method,
            "source": source,
            "outcome": outcome,
        }),
    );
}

// ---------------------------------------------------------------------------
// Replies (design 0005, Replies, Errors and text).

/// A JSON object written member by member: raw JSON embedded as it is,
/// strings escaped. Keys are the core's own names.
struct Object {
    json: Vec<u8>,
    /// Where its `deadline_ms` slot starts, when it has one.
    deadline: Option<usize>,
}

impl Object {
    fn new() -> Self {
        Self {
            json: vec![b'{'],
            deadline: None,
        }
    }

    fn key(&mut self, key: &str) {
        if self.json.len() > 1 {
            self.json.push(b',');
        }
        quote_into(&mut self.json, key);
        self.json.push(b':');
    }

    fn raw(mut self, key: &str, json: &str) -> Self {
        self.key(key);
        self.json.extend_from_slice(json.as_bytes());
        self
    }

    fn raw_opt(self, key: &str, json: Option<&str>) -> Self {
        match json {
            Some(json) => self.raw(key, json),
            None => self,
        }
    }

    fn string(mut self, key: &str, value: &str) -> Self {
        self.key(key);
        quote_into(&mut self.json, value);
        self
    }

    fn number(mut self, key: &str, value: u64) -> Self {
        self.key(key);
        self.json.extend_from_slice(value.to_string().as_bytes());
        self
    }

    /// A request's `deadline_ms`, as a slot written as it takes its slot
    /// at main.
    fn deadline_slot(mut self) -> Self {
        self.key("deadline_ms");
        self.deadline = Some(requests::slot_into(&mut self.json));
        self
    }

    fn finish(mut self) -> Vec<u8> {
        self.json.push(b'}');
        self.json
    }

    /// A request's params, and where their `deadline_ms` slot starts.
    fn finish_params(self) -> (Vec<u8>, Option<usize>) {
        let deadline = self.deadline;
        (self.finish(), deadline)
    }

    fn finish_text(self) -> String {
        String::from_utf8_lossy(&self.finish()).into_owned()
    }
}

/// `text` as a JSON string.
fn quote_into(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    for &byte in text.as_bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            0..=0x1f => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(HEX[usize::from(byte >> 4)]);
                out.push(HEX[usize::from(byte & 0xf)]);
            }
            _ => out.push(byte),
        }
    }
    out.push(b'"');
}

/// One part of a message being written.
enum Part<'a> {
    Bytes(Cow<'a, [u8]>),
    /// A JavaScript string, written as `JSON.stringify` writes it.
    Js(&'a JsString),
}

/// A message as the parts it is written from: its size is known before
/// any of it is written (design 0005, Bounds: the message cap is checked
/// on the serialized size, measured without writing it).
#[derive(Default)]
struct Message<'a> {
    parts: Vec<Part<'a>>,
}

impl<'a> Message<'a> {
    fn text(&mut self, text: &'a str) -> &mut Self {
        self.parts.push(Part::Bytes(Cow::Borrowed(text.as_bytes())));
        self
    }

    fn owned(&mut self, text: String) -> &mut Self {
        self.parts.push(Part::Bytes(Cow::Owned(text.into_bytes())));
        self
    }

    fn string(&mut self, text: &str) -> &mut Self {
        let mut quoted = Vec::with_capacity(text.len() + 2);
        quote_into(&mut quoted, text);
        self.parts.push(Part::Bytes(Cow::Owned(quoted)));
        self
    }

    fn js(&mut self, text: &'a JsString) -> &mut Self {
        self.parts.push(Part::Js(text));
        self
    }

    fn len(&self) -> usize {
        self.parts
            .iter()
            .map(|part| match part {
                Part::Bytes(bytes) => bytes.len(),
                Part::Js(text) => text.json_len(),
            })
            .sum()
    }

    fn write(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(self.len()));
        for part in &self.parts {
            match part {
                Part::Bytes(bytes) => out.extend_from_slice(bytes),
                Part::Js(text) => out.extend_from_slice(text.to_json().as_bytes()),
            }
        }
        out
    }
}

/// The text 0001's codes carry; main keys on the code.
fn protocol_text(code: Protocol) -> &'static str {
    match code {
        Protocol::Deadline => "The chain request's deadline passed",
        Protocol::Cancelled => "Cancelled",
        Protocol::Busy => "Too many chain requests",
        Protocol::Budget => "The chain request ran out of memory budget",
        Protocol::TooLarge => "Response too large",
        Protocol::Reconfigured => "The chain's configuration changed",
    }
}

/// `data` of an error: a broadcast failure's outcome, then the generation.
fn tail(message: &mut Message<'_>, outcome: Option<BroadcastOutcome>, generation: u64) {
    if let Some(outcome) = outcome {
        message.text(r#","outcome":"#).string(outcome.as_str());
    }
    message.owned(format!(r#","generation":{generation}}}}}}}"#));
}

/// A request's reply in its wire form (design 0005, Replies, Errors and
/// text), with `generation` on every result and error:
///
/// - `chain.request`: `{ result, source, verified, trust?, undefined_keys,
///   generation }`, `result` embedded as the answer's raw JSON. A missing
///   `result` (JavaScript's `undefined`) is left out and named in
///   `undefined_keys`; main restores it first in key order.
/// - `chain.fee_quote`: today's quote, keys in the router's order, then
///   `generation`.
/// - `chain.broadcast`: `{ hash, source, outcome, generation }`.
/// - Today's thrown error: `chain_error`, whose `data` is `{ kind,
///   constructor, message, props, undefined_keys, outcome?, generation }`.
///   `kind` is `node` for a JSON-RPC error the core parsed out of an answer,
///   `core` for its own texts. `props` are the error's own enumerable
///   properties in order (`code`, `data`, …), raw; one whose value is
///   `undefined` is `null` there and named in `undefined_keys`.
/// - 0001's codes (`deadline`, `cancelled`, `busy`, `budget`, `too_large`,
///   `reconfigured`): `data` is `{ outcome?, generation }`.
///
/// A broadcast failure's `outcome` is `rejected` or `not_sent`.
fn reply_message(id: u64, done: &Done) -> Message<'_> {
    let mut message = Message::default();
    message.owned(format!(r#"{{"type":"response","id":{id},"#));
    let generation = done.generation;
    match &done.result {
        Ok(Success::Read {
            result,
            source,
            verified,
            trust,
        }) => {
            message.text(r#""result":{"#);
            if let Some(result) = result {
                message.text(r#""result":"#).text(result).text(",");
            }
            message
                .text(r#""source":"#)
                .string(source)
                .text(if *verified {
                    r#","verified":true"#
                } else {
                    r#","verified":false"#
                });
            if let Some(trust) = trust {
                message.text(r#","trust":"#).text(trust);
            }
            message
                .text(if result.is_some() {
                    r#","undefined_keys":[]"#
                } else {
                    r#","undefined_keys":["result"]"#
                })
                .owned(format!(r#","generation":{generation}}}}}"#));
        }
        Ok(Success::FeeQuote(quote)) => {
            let mut json = quote.to_json();
            // Today's object, then the generation.
            json.pop();
            message
                .text(r#""result":"#)
                .owned(json)
                .owned(format!(r#","generation":{generation}}}}}"#));
        }
        Ok(Success::Broadcast {
            hash,
            source,
            outcome,
        }) => {
            message.text(r#""result":{"hash":"#);
            match hash {
                Some(hash) => message.string(hash),
                None => message.text("null"),
            };
            message
                .text(r#","source":"#)
                .string(source)
                .text(r#","outcome":"#)
                .string(outcome.as_str())
                .owned(format!(r#","generation":{generation}}}}}"#));
        }
        Err(ChainError::Thrown(thrown)) => {
            message
                .text(r#""error":{"code":"chain_error","message":"Chain request failed","data":{"kind":"#)
                .text(match thrown.origin {
                    Origin::Node => r#""node""#,
                    Origin::Core => r#""core""#,
                })
                .text(r#","constructor":"#)
                .string(thrown.class.constructor())
                .text(r#","message":"#)
                .js(&thrown.message)
                .text(r#","props":{"#);
            let mut undefined = Vec::new();
            for (i, (key, value)) in thrown.props.iter().enumerate() {
                if i > 0 {
                    message.text(",");
                }
                message.string(key).text(":");
                match value {
                    Prop::Json(json) => message.text(json),
                    Prop::Undefined => {
                        undefined.push(*key);
                        message.text("null")
                    }
                };
            }
            message.text(r#"},"undefined_keys":["#);
            for (i, key) in undefined.into_iter().enumerate() {
                if i > 0 {
                    message.text(",");
                }
                message.string(key);
            }
            message.text("]");
            tail(&mut message, done.outcome, generation);
        }
        Err(ChainError::Protocol(code)) => {
            message
                .text(r#""error":{"code":"#)
                .string(code.as_str())
                .text(r#","message":"#)
                .string(protocol_text(*code))
                .text(r#","data":{"#);
            // `data` opens with the outcome, if any, without a comma.
            match done.outcome {
                Some(outcome) => {
                    message.text(r#""outcome":"#).string(outcome.as_str());
                    message.owned(format!(r#","generation":{generation}}}}}}}"#));
                }
                None => {
                    message.owned(format!(r#""generation":{generation}}}}}}}"#));
                }
            }
        }
    }
    message
}

/// `too_large` in place of a reply that can't go out.
fn too_large_payload(
    id: u64,
    generation: u64,
    outcome: Option<BroadcastOutcome>,
) -> Zeroizing<Vec<u8>> {
    let done = Done {
        id,
        result: Err(ChainError::Protocol(Protocol::TooLarge)),
        outcome,
        settled: 0,
        generation,
    };
    reply_message(id, &done).write()
}

#[cfg(test)]
mod tests;
