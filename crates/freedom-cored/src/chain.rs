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
use crate::requests::{self, Dispatch, Owner, Requests};
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
    /// A transport failure.
    Failed(ErrorBody),
    /// The response message as it was read, moved here rather than copied,
    /// and where its `result` lies in it.
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
            let chain = Chain::new(
                Machine::new(0, crate::testhooks::chain_bounds(Bounds::default())),
                out,
                link,
                Shares {
                    bulk: allowance,
                    control,
                },
                requests,
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
    let started = Instant::now();
    let now = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    loop {
        if let Err(stop) = chain.advance(now()) {
            return stop;
        }
        let due = match (chain.machine.next_due(), chain.next_expiry()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let wait = due.map_or(Duration::from_secs(3600), |at| {
            Duration::from_millis(at.saturating_sub(now()))
        });
        let flow = match rx.recv_timeout(wait) {
            // The frame's credit goes once its message is handled.
            Ok((message, _credit)) => chain
                .advance(now())
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
    /// The latest it may start: past it, it completes here unsent. An
    /// exchange's own time (what is left of it goes as `deadline_ms`); a
    /// Myotis broadcast's attempt cutoff, 10 s before its request's
    /// deadline (design 0005, Deadlines). `None` for a Myotis read, which
    /// main runs whole while its request runs.
    until: Option<Ms>,
}

/// A request from main the machine is running.
struct Caller {
    /// Main's request ID.
    id: u64,
    /// For the outcome's log line: never an origin, address or message.
    chain_id: u64,
    method: &'static str,
    /// A broadcast's attempt cutoff: no attempt starts at or after it.
    cutoff: Option<Ms>,
}

struct Chain {
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
    ) -> Self {
        Self {
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
        }
    }

    /// Polls the machine, with what waits to be written counted in the
    /// chain total (`memory-budgets`).
    fn poll(&mut self) {
        let backlog = self.backlog();
        self.machine.set_output_backlog(backlog);
        self.machine.poll();
    }

    /// Fires the timers due by `now`, polling after each as the executor
    /// requires, then moves the clock to `now`. A request whose time runs
    /// out while it waits here completes as not sent before a timer due at
    /// the same instant fires (the machine's own for that exchange): none
    /// of it reached main (design 0005, Attempts).
    fn advance(&mut self, now: u64) -> Flow {
        loop {
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
                _ => break,
            }
            self.poll();
            self.flush()?;
        }
        self.machine.fire_next(now);
        self.poll();
        self.flush()
    }

    /// When the first request waiting here runs out of time.
    fn next_expiry(&self) -> Option<Ms> {
        self.queued.iter().filter_map(|q| q.until).min()
    }

    /// Completes the requests waiting here whose time ran out by `at`:
    /// unsent.
    fn expire(&mut self, at: Ms) {
        let mut i = 0;
        while i < self.queued.len() {
            if self.queued[i].until.is_some_and(|until| until <= at)
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
                // When its attempts stop (design 0005, Deadlines), from its
                // arrival as the machine counts its deadline.
                let cutoff = matches!(call, Call::Broadcast { .. }).then(|| {
                    self.machine
                        .now()
                        .saturating_add(deadline_ms.min(bounds.deadline_ms))
                        .saturating_sub(bounds.reconcile_ms)
                });
                let caller = Caller {
                    id,
                    chain_id: call_chain(&call),
                    method: label(&call),
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
    /// here. It must be one of its request's shapes, or it is a protocol
    /// error, even when nobody waits for it any more. One for a request the
    /// machine cancelled is then dropped, and one whose chain request has
    /// ended completes unread. Otherwise it is read for good with every
    /// allocation reserved first against the request that asked, the
    /// message itself included (57-M4); a reservation refused ends that
    /// request with `budget` (a broadcast through its outcome table) and
    /// the reply completes unread, so a verifier's slot is still freed.
    fn response(&mut self, id: u64, reply: Shell) -> Flow {
        let Some(outgoing) = self.outgoing.remove(&id) else {
            return Err(Stop::Protocol("unsolicited_response"));
        };
        let malformed = Stop::Protocol("malformed_shell_reply");
        let (message, result) = match reply {
            Shell::Failed(error) => {
                let failure = transport_failure(&error).ok_or(malformed)?;
                if let Some(io) = outgoing.io {
                    self.by_io.remove(&io);
                    self.machine.complete(io, Answer::Failed(failure));
                    self.poll();
                }
                return Ok(());
            }
            Shell::Result { message, result } => (message, result),
        };
        let Some(text) = message
            .get(result)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
        else {
            return Err(malformed);
        };
        let shape = Shape::parse(outgoing.kind, text).ok_or(malformed)?;
        let Some(io) = outgoing.io else {
            return Ok(());
        };
        self.by_io.remove(&io);
        // Nobody reads a reply whose request has ended: it completes
        // unread, as one past the budget does.
        let read = if self.machine.wants(io) {
            match self.machine.reserve_reply(io, message.capacity()) {
                Ok(held) => shape.read(&self.machine, io).map(|read| (read, held)),
                Err(_) => Err(Unread::Over),
            }
        } else {
            Err(Unread::Over)
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

    /// Sends the machine's requests, cancels and replies. A request that
    /// completes here (expired, or too large to send) settles at the next
    /// poll, so this polls and goes round again.
    fn flush(&mut self) -> Flow {
        loop {
            self.effects()?;
            let mut settled = self.retire();
            settled |= self.dispatch()?;
            self.take_replies()?;
            settled |= self.retire();
            if !settled {
                return Ok(());
            }
            self.poll();
        }
    }

    /// Retires the queued requests of chain requests that have replied
    /// (cancelled, ended by their deadline, a configuration change or
    /// their budget, or finished): they never go to main. A verifier
    /// operation's request is held by the machine until main's terminal
    /// reply, so one that never went completes here unread, freeing its
    /// slot (57-M2). True when any did.
    fn retire(&mut self) -> bool {
        let mut retired = false;
        let mut i = 0;
        while i < self.queued.len() {
            let ended = self.queued[i]
                .owner
                .is_some_and(|owner| !self.callers.contains_key(&owner));
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
                    let until = match &request {
                        Request::Rpc { deadline_ms, .. }
                        | Request::Blockscout { deadline_ms, .. }
                        | Request::Verified(VerifiedOp::Colibri { deadline_ms, .. }) => {
                            Some(at.saturating_add(*deadline_ms))
                        }
                        Request::Verified(VerifiedOp::MyotisBroadcast { .. }) => owner
                            .and_then(|owner| self.callers.get(&owner))
                            .and_then(|caller| caller.cutoff),
                        Request::Verified(VerifiedOp::MyotisRead { .. }) => None,
                    };
                    self.queued.push_back(Queued {
                        io,
                        request,
                        generation: generation.unwrap_or(0),
                        owner,
                        until,
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
    /// removes it, and its deadline is what is left when it goes. True when
    /// one settled here.
    fn dispatch(&mut self) -> Result<bool, Stop> {
        let mut settled = false;
        while self.control.is_empty() {
            let Some(queued) = self.queued.front() else {
                break;
            };
            let io = queued.io;
            let left = queued
                .until
                .map(|until| until.saturating_sub(self.machine.now()));
            // Its time ran out while it waited: it completes here, unsent.
            if left == Some(0) {
                let kind = kind_of(&queued.request);
                self.queued.pop_front();
                self.machine.complete(io, unsent(kind));
                settled = true;
                continue;
            }
            let (method, kind, params) =
                shell_request(&queued.request, queued.generation, left.unwrap_or(0));
            let sent = self
                .requests
                .send(Owner::Chain, &self.control_allowance, &self.out, |id| {
                    requests::request_frame(id, method, &params)
                });
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

/// A `shell.*` request: its method, how to read the answer, and its params
/// with the generation it runs under. `left` is what is left of its time,
/// sent as `deadline_ms` where the design has one.
fn shell_request(request: &Request, generation: u64, left: Ms) -> (&'static str, Kind, Vec<u8>) {
    let kind = kind_of(request);
    let (method, params) = shell_params(request, generation, left);
    (method, kind, params)
}

/// A `shell.*` request's method and params.
fn shell_params(request: &Request, generation: u64, left: Ms) -> (&'static str, Vec<u8>) {
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
                .number("deadline_ms", left)
                .finish(),
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
                .number("deadline_ms", left)
                .finish(),
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
                op.number("generation", generation).finish(),
            )
        }
        Request::Verified(VerifiedOp::MyotisBroadcast { chain_id, raw }) => (
            "shell.verified",
            Object::new()
                .string("myotis", "broadcast")
                .number("chain_id", *chain_id)
                .string("raw", raw)
                .number("generation", generation)
                .finish(),
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
                .number("deadline_ms", left)
                .number("generation", generation)
                .finish(),
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

/// Every member main's verified replies can have (design 0005, Verified
/// operations), borrowed from the reply; which may appear together depends
/// on the operation.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct VerifiedReply<'a> {
    #[serde(borrow, default, deserialize_with = "present")]
    payload: Option<&'a RawValue>,
    /// `null` or absent when the status had none.
    #[serde(borrow, default)]
    block_before: Option<&'a RawValue>,
    #[serde(borrow, default)]
    block_after: Option<&'a RawValue>,
    /// A class: one of the closed set's names, which need no escapes.
    #[serde(borrow, default)]
    failure: Option<&'a str>,
    #[serde(borrow, default, deserialize_with = "present")]
    hash: Option<&'a RawValue>,
    #[serde(borrow, default)]
    rejected: Option<ObjectOf<Rejected<'a>>>,
    #[serde(default)]
    uncertain: Option<bool>,
    #[serde(default)]
    not_sent: Option<bool>,
    #[serde(borrow, default, deserialize_with = "present")]
    result: Option<&'a RawValue>,
    #[serde(borrow, default)]
    revert: Option<ObjectOf<Revert<'a>>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rejected<'a> {
    #[serde(borrow)]
    reason: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revert<'a> {
    #[serde(borrow)]
    data: &'a RawValue,
}

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

/// A Blockscout page's headers, checked in place: an object of strings.
/// Nothing is kept; they are read for good once their room is reserved.
struct Headers;

impl<'de> Deserialize<'de> for Headers {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Text;

        impl<'de> Deserialize<'de> for Text {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct Any;

                impl serde::de::Visitor<'_> for Any {
                    type Value = Text;

                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.write_str("a string")
                    }

                    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Text, E> {
                        Ok(Text)
                    }
                }

                d.deserialize_str(Any)
            }
        }

        struct Map;

        impl<'de> serde::de::Visitor<'de> for Map {
            type Value = Headers;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object of strings")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Headers, A::Error> {
                while map.next_entry::<Text, Text>()?.is_some() {}
                Ok(Headers)
            }
        }

        d.deserialize_map(Map)
    }
}

/// `{ "not_sent": true }`: main performed nothing (design 0005, Requests
/// the core makes).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotSent {
    not_sent: bool,
}

/// A transport failure: one of the closed set, with no text and no data
/// (design 0004, Transport errors); `None` for anything else, which is
/// malformed. Only `not_sent` proves nothing was sent, so every failure may
/// have followed a send.
fn transport_failure(error: &ErrorBody) -> Option<Transport> {
    if error.data.is_some() {
        return None;
    }
    Some(match error.code {
        ErrorCode::Timeout | ErrorCode::Deadline => Transport::Timeout,
        ErrorCode::Network | ErrorCode::Cancelled | ErrorCode::StaleGeneration => {
            Transport::Network
        }
        ErrorCode::Refused => Transport::Refused,
        ErrorCode::TooLarge => Transport::TooLarge,
        ErrorCode::Busy => Transport::Busy,
        _ => return None,
    })
}

/// Main's reply, read in place: borrowed from its message, with nothing
/// allocated, every structural boundary a JSON object (57-M1). Reading it
/// for good ([`Shape::read`]) reserves each allocation first (57-M4).
#[derive(Debug)]
enum Shape<'a> {
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
    /// The data, a JSON string.
    Revert(&'a RawValue),
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

impl<'a> Shape<'a> {
    /// Main's terminal reply to a request of `kind`; `None` when it is
    /// malformed.
    fn parse(kind: Kind, text: &'a str) -> Option<Self> {
        if let Ok(not_sent) = serde_json::from_str::<ObjectOf<NotSent>>(text) {
            // Only `true` says it.
            return not_sent.not_sent.then_some(Shape::NotSent {
                broadcast: kind == Kind::MyotisBroadcast,
            });
        }
        match kind {
            Kind::Rpc => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Http<'a> {
                    status: u16,
                    /// Base64, which JSON never escapes.
                    #[serde(borrow)]
                    body: &'a str,
                }
                let http = serde_json::from_str::<ObjectOf<Http>>(text)
                    .ok()?
                    .into_inner();
                Some(Shape::Http {
                    status: http.status,
                    body: http.body,
                })
            }
            Kind::Blockscout => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Page<'a> {
                    status: u16,
                    #[serde(borrow)]
                    headers: &'a RawValue,
                    #[serde(borrow)]
                    body: &'a str,
                }
                let page = serde_json::from_str::<ObjectOf<Page>>(text)
                    .ok()?
                    .into_inner();
                serde_json::from_str::<Headers>(page.headers.get()).ok()?;
                Some(Shape::Page {
                    status: page.status,
                    headers: page.headers,
                    body: page.body,
                })
            }
            Kind::MyotisRead | Kind::MyotisBroadcast | Kind::Colibri => {
                let reply = serde_json::from_str::<ObjectOf<VerifiedReply>>(text)
                    .ok()?
                    .into_inner();
                Self::verified(kind, reply)
            }
        }
    }

    /// A verified operation's reply, which must be one of its operation's
    /// shapes: a failure stands alone and carries only its class.
    fn verified(kind: Kind, reply: VerifiedReply<'a>) -> Option<Self> {
        let VerifiedReply {
            payload,
            block_before,
            block_after,
            failure,
            hash,
            rejected,
            uncertain,
            not_sent,
            result,
            revert,
        } = reply;
        // Members that belong to no shape of the operation.
        let read_members = payload.is_some() || block_before.is_some() || block_after.is_some();
        let broadcast_members = hash.is_some() || rejected.is_some() || uncertain.is_some();
        let colibri_members = result.is_some() || revert.is_some();
        if not_sent.is_some() {
            return None;
        }
        let shapes = usize::from(failure.is_some())
            + usize::from(payload.is_some())
            + usize::from(hash.is_some())
            + usize::from(rejected.is_some())
            + usize::from(uncertain.is_some())
            + usize::from(result.is_some())
            + usize::from(revert.is_some());
        if shapes != 1 {
            return None;
        }
        match kind {
            Kind::MyotisRead => {
                if broadcast_members || colibri_members {
                    return None;
                }
                if let Some(class) = failure {
                    return (!read_members)
                        .then(|| myotis_class(class))
                        .flatten()
                        .map(Shape::MyotisFailure);
                }
                Some(Shape::Read {
                    payload: payload?,
                    before: block_before,
                    after: block_after,
                })
            }
            Kind::MyotisBroadcast => {
                if read_members || colibri_members {
                    return None;
                }
                if let Some(class) = failure {
                    return myotis_class(class).map(Shape::MyotisFailure);
                }
                if let Some(hash) = hash {
                    return Some(Shape::Sent(hash));
                }
                if let Some(rejected) = rejected {
                    let reason = rejected.into_inner().reason;
                    return is_string(reason).then_some(Shape::Rejected(reason));
                }
                (uncertain == Some(true)).then_some(Shape::Uncertain)
            }
            Kind::Colibri => {
                if read_members || broadcast_members {
                    return None;
                }
                if let Some(class) = failure {
                    return colibri_class(class).map(Shape::ColibriFailure);
                }
                if let Some(result) = result {
                    return Some(Shape::ColibriResult(result));
                }
                let data = revert?.into_inner().data;
                is_string(data).then_some(Shape::Revert(data))
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
                // Each name and value is at most its JSON text.
                let mut reservation = reserve(headers.get().len())?;
                let headers: BTreeMap<String, String> =
                    serde_json::from_str(headers.get()).map_err(|_| Unread::Malformed)?;
                let body = decode_base64(body, &mut reservation)?;
                (
                    Answer::Blockscout {
                        status,
                        headers: headers.into_iter().collect(),
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
            Shape::Revert(data) => {
                let reservation = reserve(data.get().len())?;
                let data = decode_string(data.get()).ok_or(Unread::Malformed)?;
                (Answer::Colibri(ColibriReply::Revert { data }), reservation)
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
struct Object(Vec<u8>);

impl Object {
    fn new() -> Self {
        Self(vec![b'{'])
    }

    fn key(&mut self, key: &str) {
        if self.0.len() > 1 {
            self.0.push(b',');
        }
        quote_into(&mut self.0, key);
        self.0.push(b':');
    }

    fn raw(mut self, key: &str, json: &str) -> Self {
        self.key(key);
        self.0.extend_from_slice(json.as_bytes());
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
        quote_into(&mut self.0, value);
        self
    }

    fn number(mut self, key: &str, value: u64) -> Self {
        self.key(key);
        self.0.extend_from_slice(value.to_string().as_bytes());
        self
    }

    fn finish(mut self) -> Vec<u8> {
        self.0.push(b'}');
        self.0
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
