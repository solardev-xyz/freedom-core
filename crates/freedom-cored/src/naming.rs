//! The naming thread (design 0004): fc-naming's session machine on its own
//! thread, so vault traffic never waits on naming work. The event loop
//! forwards `naming.*` requests, cancels and main's responses to `shell.*`
//! here; this thread writes its own replies and requests to the writer.
//!
//! The machine is sans-I/O: each of its requests becomes a `shell.*`
//! request to main, each answer goes back to it, and its timers run on this
//! thread's monotonic clock.

use std::collections::{BTreeMap, VecDeque};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use fc_naming::jsjson::{self, JsValue};
use fc_naming::session::bounds::Bounds;
use fc_naming::session::ens::{Answer, Config, Direct, Request, Thrown, Verified, VerifiedOp};
use fc_naming::session::exec::Effect;
use fc_naming::session::exec::Ms;
use fc_naming::session::machine::{
    CallOptions, Emitted, Generations, MAX_LIFECYCLE_ATTEMPTS, Machine, Reply,
};
use fc_naming::session::random::Random;
use fc_naming::session::rpc::Transport;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::message;
use serde::Deserialize;
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use crate::requests::{self, Dispatch, Owner, Requests};
use crate::serve::Event;
use crate::transport;
use crate::transport::{Allowance, Credit, Out};

/// The methods the naming thread answers.
pub const METHODS: &[&str] = &[
    "naming.configure",
    "naming.availability",
    "naming.resolve_content",
    "naming.resolve_address",
    "naming.resolve_reverse",
    "naming.resolve_tezos",
    "naming.invalidate_content",
    "naming.invalidate_tezos",
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
        outcome: Result<Box<RawValue>, ErrorBody>,
    },
    /// The writer has room again for frames that wait here.
    Drained,
}

/// A message, with the reader's credit for the frame it came in: the
/// reader counts it until this thread has handled it.
type Mail = (In, Option<Credit>);

/// The event loop's side of the naming thread. The writer's and the
/// gate's wake-ups hold only weak references, so dropping this ends the
/// thread.
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

/// Starts the naming thread. It writes to `out`, sends its `shell.*`
/// requests through `requests` (which routes main's responses back), and
/// reports a protocol error from main, or its own end, to the event loop.
pub fn spawn(
    out: Sender<Out>,
    events: Sender<Event>,
    requests: Arc<Requests>,
) -> std::io::Result<Handle> {
    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(tx);
    // Naming's share of the writer (design 0004, Bounds: the writer).
    let allowance = Allowance::new(usize::MAX, transport::MAX_QUEUED_NAMING_BYTES);
    allowance.on_room(waker(&tx));
    requests.on_room(Owner::Naming, waker(&tx));
    std::thread::Builder::new()
        .name("naming".into())
        .spawn(move || {
            let _notice = transport::DeathNotice::new(events.clone(), "naming");
            let event = match run(&rx, out, allowance, requests) {
                Stop::Protocol(category) => Event::ProtocolError(category),
                Stop::Writer => Event::WriterFailed,
                // The event loop has gone: nothing to report to.
                Stop::Gone => return,
            };
            let _ = events.send(event);
        })?;
    Ok(Handle { tx })
}

/// Uniform values in `[0, 1)` from the OS generator: the shuffle needs no
/// reproducibility outside replays.
struct OsRandom;

impl Random for OsRandom {
    fn next_f64(&mut self) -> f64 {
        let mut bytes = [0u8; 8];
        // A failed read leaves zeros: a fixed but valid shuffle.
        let _ = getrandom::fill(&mut bytes);
        #[allow(clippy::cast_precision_loss)]
        let value = (u64::from_le_bytes(bytes) >> 11) as f64;
        value / (1u64 << 53) as f64
    }
}

/// A configuration with nothing in it, until main's first
/// `naming.configure`.
fn empty_config() -> Config {
    Config {
        rpc: Vec::new(),
        direct: None,
        order: Vec::new(),
        prefer_verified: false,
        quorum: JsValue::Null,
        myotis_enabled: false,
        prover: None,
        tezos: Vec::new(),
        bounds: Bounds::default(),
    }
}

/// Why the naming thread stopped.
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
fn run(
    rx: &Receiver<Mail>,
    out: Sender<Out>,
    allowance: Arc<Allowance>,
    requests: Arc<Requests>,
) -> Stop {
    let started = Instant::now();
    let mut machine = Machine::new(0, empty_config(), Box::new(OsRandom));
    #[allow(clippy::cast_precision_loss)]
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_millis() as f64);
    machine.set_wall_clock(wall);
    let mut naming = Naming {
        machine,
        out,
        allowance,
        requests,
        outbox: VecDeque::new(),
        max_backlog: MAX_NAMING_BACKLOG,
        callers: BTreeMap::new(),
        outgoing: BTreeMap::new(),
        by_io: BTreeMap::new(),
        queued: VecDeque::new(),
    };
    let now = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    loop {
        if let Err(stop) = naming.advance(now()) {
            return stop;
        }
        let wait = naming
            .machine
            .next_due()
            .map_or(Duration::from_secs(3600), |at| {
                Duration::from_millis(at.saturating_sub(now()))
            });
        let flow = match rx.recv_timeout(wait) {
            // The frame's credit goes once its message is handled.
            Ok((message, _credit)) => naming
                .advance(now())
                .and_then(|()| naming.handle(message))
                .and_then(|()| naming.flush()),
            Err(RecvTimeoutError::Timeout) => Ok(()),
            // The event loop has gone (shutdown or EOF): the replies and
            // cancels still waiting go to the writer, which the loop gives
            // its bounded drain. Queued requests are dropped unsent.
            Err(RecvTimeoutError::Disconnected) => {
                naming.drain();
                Err(Stop::Gone)
            }
        };
        if let Err(stop) = flow {
            return stop;
        }
    }
}

/// What a `shell.*` request is for, to read main's answer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Rpc,
    Gateway,
    Tezos,
    Verified,
    Prefetch,
}

struct Outgoing {
    /// The machine's request id; `None` once the machine cancelled it (its
    /// one terminal reply is still due, and dropped).
    io: Option<u64>,
    kind: Kind,
}

/// A verified operation's failure classes (design 0004, Verified
/// operations).
const FAILURE_CLASSES: &[&str] = &[
    "unavailable",
    "lifecycle",
    "timeout",
    "too_large",
    "invalid_argument",
    "error",
];

/// Naming's frames waiting to be written (its writer share and its own
/// queue) past which new lookups are busy (design 0004, Bounds: Memory):
/// their replies can't outgrow it by more than main's 256 outstanding
/// requests' small busy replies.
const MAX_NAMING_BACKLOG: usize = 16 * 1024 * 1024;

struct Naming {
    machine: Machine,
    out: Sender<Out>,
    allowance: Arc<Allowance>,
    /// The core's requests to main, naming's and chain's: one ID counter,
    /// main's limit of outstanding requests (design 0004, Bounds: Work),
    /// and the gate closed at shutdown. Past the limit, requests wait here,
    /// first in, first out.
    requests: Arc<Requests>,
    /// Frames waiting for room in the writer, in order.
    outbox: VecDeque<Zeroizing<Vec<u8>>>,
    /// See MAX_NAMING_BACKLOG.
    max_backlog: usize,
    /// Requests waiting for a slot: the machine's request id, the request,
    /// its attempt's generations, and its session's deadline.
    queued: VecDeque<(u64, Request, Generations, Ms)>,
    /// The machine's callers, by the request ID main gave them.
    callers: BTreeMap<u64, u64>,
    /// This thread's `shell.*` requests, by their message ID.
    outgoing: BTreeMap<u64, Outgoing>,
    /// Message IDs by the machine's request id.
    by_io: BTreeMap<u64, u64>,
}

impl Naming {
    /// Polls the machine, with what waits to be written counted in its
    /// sessions' total (`memory-budgets`).
    fn poll(&mut self) {
        let backlog = self.backlog();
        self.machine.set_output_backlog(backlog);
        self.machine.poll();
    }

    /// Fires the timers due by `now`, polling after each as the executor
    /// requires, then moves the clock to `now`.
    fn advance(&mut self, now: u64) -> Flow {
        while self.machine.fire_next(now).is_some() {
            self.poll();
            self.flush()?;
        }
        self.poll();
        self.flush()
    }

    fn handle(&mut self, message: In) -> Flow {
        match message {
            In::Request { id, method, params } => {
                self.request(id, method, params.as_deref().map(RawValue::get))
            }
            In::Cancel { id } => {
                if let Some(caller) = self.callers.get(&id) {
                    self.machine.cancel(*caller);
                    self.poll();
                }
                Ok(())
            }
            In::Response { id, outcome } => self.response(id, outcome),
            In::Drained => self.pump(),
        }
    }

    fn request(&mut self, id: u64, method: &str, params: Option<&str>) -> Flow {
        let params = params.unwrap_or("{}");
        macro_rules! parse {
            ($ty:ty) => {
                match serde_json::from_str::<$ty>(params) {
                    Ok(params) => params,
                    Err(_) => {
                        return self.error(
                            id,
                            ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters"),
                        );
                    }
                }
            };
        }
        // A lookup's reply can't be written while the backlog is this deep:
        // busy, which is small, in its place.
        let backlog = self.backlog();
        self.machine.set_output_backlog(backlog);
        if method.starts_with("naming.resolve_") && backlog > self.max_backlog {
            return self.error(
                id,
                ErrorBody::new(ErrorCode::Busy, code_message(ErrorCode::Busy)),
            );
        }
        match method {
            "naming.configure" => {
                let snapshot = parse!(Snapshot);
                let Some(config) = snapshot.config() else {
                    return self.error(
                        id,
                        ErrorBody::new(ErrorCode::InvalidArgument, "Invalid configuration"),
                    );
                };
                let reset = snapshot.reset.as_deref() == Some("providers");
                let generations = self.machine.configure(config, reset);
                self.result(
                    id,
                    // All three: `reset: "providers"` advances the
                    // lifecycle, which main tracks for its fence.
                    &serde_json::json!({
                        "ens": generations.ens,
                        "tezos": generations.tezos,
                        "lifecycle": generations.lifecycle,
                    }),
                )
            }
            "naming.availability" => {
                let params = parse!(AvailabilityParams);
                self.machine.set_myotis_enabled(params.enabled);
                self.machine.availability(params.ready);
                let lifecycle = self.machine.generations().lifecycle;
                self.result(id, &serde_json::json!({ "lifecycle": lifecycle }))
            }
            "naming.resolve_content" => {
                let params = parse!(NameParams);
                let Some(options) = params.options() else {
                    return self.error(
                        id,
                        ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters"),
                    );
                };
                let caller = self.machine.resolve_content_with(&params.name, options);
                self.callers.insert(id, caller);
                Ok(())
            }
            "naming.resolve_tezos" => {
                let params = parse!(NameParams);
                let Some(options) = params.options() else {
                    return self.error(
                        id,
                        ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters"),
                    );
                };
                let caller = self.machine.resolve_tezos_with(&params.name, options);
                self.callers.insert(id, caller);
                Ok(())
            }
            "naming.resolve_address" => {
                let params = parse!(AddressParams);
                let Some(options) = params.options() else {
                    return self.error(
                        id,
                        ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters"),
                    );
                };
                let caller =
                    self.machine
                        .resolve_address_with(&params.name, params.chain_id, options);
                self.callers.insert(id, caller);
                Ok(())
            }
            "naming.resolve_reverse" => {
                let params = parse!(ReverseParams);
                let Some(options) = params.options() else {
                    return self.error(
                        id,
                        ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters"),
                    );
                };
                let caller =
                    self.machine
                        .resolve_reverse_with(&params.address, params.chain_id, options);
                self.callers.insert(id, caller);
                Ok(())
            }
            "naming.invalidate_content" => {
                let params = parse!(InvalidateParams);
                let evicted = self
                    .machine
                    .invalidate_content(params.name.as_deref().unwrap_or(""));
                self.result(id, &serde_json::json!({ "evicted": evicted }))
            }
            "naming.invalidate_tezos" => {
                let params = parse!(InvalidateParams);
                self.machine.invalidate_tezos(params.name.as_deref());
                self.result(id, &serde_json::json!({}))
            }
            _ => self.error(
                id,
                ErrorBody::new(ErrorCode::UnknownMethod, "Unknown method"),
            ),
        }
    }

    /// Main's reply to a `shell.*` request, which the event loop routed
    /// here. One for a request the machine cancelled is dropped; one for no
    /// request of naming's is a protocol error.
    fn response(&mut self, id: u64, outcome: Result<Box<RawValue>, ErrorBody>) -> Flow {
        let Some(outgoing) = self.outgoing.remove(&id) else {
            return Err(Stop::Protocol("unsolicited_response"));
        };
        let Some(io) = outgoing.io else {
            return Ok(());
        };
        self.by_io.remove(&io);
        let Some(answer) = answer(outgoing.kind, outcome) else {
            return Err(Stop::Protocol("malformed_shell_reply"));
        };
        self.machine.complete(io, answer);
        Ok(())
    }

    /// Sends the machine's requests, cancels and replies. A request that
    /// completes here (expired, or too large to send) settles at the next
    /// poll, so this polls and goes round again.
    fn flush(&mut self) -> Flow {
        loop {
            self.effects()?;
            let settled = self.dispatch()?;
            for reply in self.machine.take_replies() {
                let Some((&id, _)) = self.callers.iter().find(|(_, c)| **c == reply.caller) else {
                    continue;
                };
                self.callers.remove(&id);
                self.reply(id, &reply)?;
            }
            if !settled {
                return Ok(());
            }
            self.poll();
        }
    }

    fn effects(&mut self) -> Flow {
        for Emitted {
            effect,
            generations,
            deadline,
        } in self.machine.take_effects()
        {
            match effect {
                Effect::Request {
                    id: io, request, ..
                } => self.queued.push_back((io, request, generations, deadline)),
                Effect::Cancel { id: io, .. } => {
                    // Not yet sent: it never is.
                    if let Some(at) = self.queued.iter().position(|(q, ..)| *q == io) {
                        self.queued.remove(at);
                        continue;
                    }
                    let Some(id) = self.by_io.remove(&io) else {
                        continue;
                    };
                    if let Some(outgoing) = self.outgoing.get_mut(&id) {
                        outgoing.io = None;
                    }
                    let payload = serde_json::json!({ "type": "cancel", "id": id });
                    self.send(payload.to_string().as_bytes())?;
                }
            }
        }
        Ok(())
    }

    /// Sends queued requests, first in, first out, while no other frame
    /// waits, a slot at main is free, and the writer has room; the gate
    /// wakes the thread when one is. A request leaves the queue only when
    /// it is sent or settled here, so until then a cancel removes it, and
    /// its deadline is what is left when it goes. True when one settled
    /// here.
    fn dispatch(&mut self) -> Result<bool, Stop> {
        let mut settled = false;
        while self.outbox.is_empty() {
            let Some((io, request, generations, deadline)) = self.queued.front() else {
                break;
            };
            let io = *io;
            // Its session has ended by now: it completes here, unsent.
            let left = deadline.saturating_sub(self.machine.now());
            if left == 0 {
                self.queued.pop_front();
                self.machine
                    .complete(io, Answer::Failed(Transport::Timeout));
                settled = true;
                continue;
            }
            let (method, kind, params) = shell_request(request, *generations, left);
            let params =
                serde_json::to_vec(&params).map_err(|_| Stop::Protocol("unwritable_request"))?;
            let sent = self
                .requests
                .send(Owner::Naming, &self.allowance, &self.out, |id| {
                    requests::request_frame(id, method, &params)
                });
            match sent {
                Dispatch::Sent(id) => {
                    self.queued.pop_front();
                    self.outgoing.insert(id, Outgoing { io: Some(io), kind });
                    self.by_io.insert(io, id);
                }
                // Over 0001's frame: never sent, it completes as too large
                // (design 0004, Requests the core makes).
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

    /// A resolution reply (design 0004, Replies).
    fn reply(&mut self, id: u64, reply: &Reply) -> Flow {
        let generations = generations_json(reply.generations);
        match &reply.outcome {
            Ok(value) => {
                let (result, undefined_keys) = with_placeholders(value);
                let Ok(result) = RawValue::from_string(result.stringify()) else {
                    return Err(Stop::Protocol("unwritable_result"));
                };
                self.result(
                    id,
                    &serde_json::json!({
                        "result": result,
                        "undefined_keys": undefined_keys,
                        "generations": generations,
                        "attempts": reply.attempts,
                    }),
                )
            }
            Err(Thrown {
                code: Some(code), ..
            }) => {
                let code = match *code {
                    "busy" => ErrorCode::Busy,
                    "deadline" => ErrorCode::Deadline,
                    "cancelled" => ErrorCode::Cancelled,
                    _ => ErrorCode::Internal,
                };
                self.error(id, ErrorBody::new(code, code_message(code)))
            }
            Err(thrown) => self.error(
                id,
                ErrorBody::new(ErrorCode::ResolutionFailed, "Resolution failed").with_data(
                    serde_json::json!({
                        "message": thrown.message,
                        "generations": generations,
                        "attempts": reply.attempts,
                    }),
                ),
            ),
        }
    }

    fn result(&mut self, id: u64, result: &serde_json::Value) -> Flow {
        let mut payload = Zeroizing::new(Vec::with_capacity(256));
        message::write_result(&mut *payload, id, result)
            .map_err(|_| Stop::Protocol("unwritable_result"))?;
        self.send(&payload)
    }

    fn error(&mut self, id: u64, error: ErrorBody) -> Flow {
        let mut payload = Zeroizing::new(Vec::with_capacity(256));
        message::write_error(&mut *payload, id, &error)
            .map_err(|_| Stop::Protocol("unwritable_result"))?;
        self.send(&payload)
    }

    /// Queues a reply or a cancel behind any that wait for the writer.
    fn send(&mut self, payload: &[u8]) -> Flow {
        let frame = transport::frame(payload).ok_or(Stop::Protocol("oversized_message"))?;
        self.outbox.push_back(frame);
        self.pump()
    }

    /// Naming's frames not yet written: those the writer holds and those
    /// waiting here.
    fn backlog(&self) -> usize {
        self.allowance.held_bytes() + self.outbox.iter().map(|f| f.len()).sum::<usize>()
    }

    /// Hands every waiting frame to the writer, past the allowance: at
    /// shutdown, where the writer's drain is bounded by time instead.
    fn drain(&mut self) {
        for frame in self.outbox.drain(..) {
            let hold = self.allowance.force(frame.len());
            let _ = self.out.send(Out::Frame { frame, hold });
        }
    }

    /// Hands waiting frames (replies and cancels) to the writer while
    /// naming's allowance has room; the rest wait for [`In::Drained`].
    fn pump(&mut self) -> Flow {
        while let Some(frame) = self.outbox.front() {
            let Some(hold) = self.allowance.take(frame.len()) else {
                return Ok(());
            };
            let Some(frame) = self.outbox.pop_front() else {
                return Ok(());
            };
            self.out
                .send(Out::Frame { frame, hold })
                .map_err(|_| Stop::Writer)?;
        }
        Ok(())
    }
}

/// The answer for a request too large to send.
fn too_large(kind: Kind) -> Answer {
    match kind {
        Kind::Verified => Answer::Verified(Verified::Failure("too_large".into())),
        Kind::Prefetch => Answer::Done,
        Kind::Rpc | Kind::Gateway | Kind::Tezos => Answer::Failed(Transport::TooLarge),
    }
}

fn code_message(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::Busy => "Too many naming requests",
        ErrorCode::Deadline => "The resolution's deadline passed",
        ErrorCode::Cancelled => "Cancelled",
        _ => "Internal error",
    }
}

fn generations_json(generations: Generations) -> serde_json::Value {
    serde_json::json!({
        "ens": generations.ens,
        "tezos": generations.tezos,
        "lifecycle": generations.lifecycle,
    })
}

/// A result with its top-level `undefined` members as `null`
/// placeholders, and their keys (design 0004, Replies).
fn with_placeholders(value: &JsValue) -> (JsValue, Vec<String>) {
    let JsValue::Object(members) = value else {
        return (value.clone(), Vec::new());
    };
    let mut keys = Vec::new();
    let members = members
        .iter()
        .map(|(key, value)| {
            if matches!(value, JsValue::Undefined) {
                keys.push(key.clone());
                (key.clone(), JsValue::Null)
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect();
    (JsValue::Object(members), keys)
}

/// A machine request as a `shell.*` request: its method, how to read the
/// answer, and its params with the generations of its scopes.
/// A `shell.*` request: its method, kind and params. `deadline_ms` is what
/// is left of its session's deadline.
fn shell_request(
    request: &Request,
    generations: Generations,
    deadline_ms: Ms,
) -> (&'static str, Kind, serde_json::Value) {
    let ens = serde_json::json!({ "ens": generations.ens });
    match request {
        Request::Rpc { endpoint, body } => (
            "shell.rpc",
            Kind::Rpc,
            serde_json::json!({ "endpoint": endpoint, "body": body, "generations": ens, "deadline_ms": deadline_ms }),
        ),
        Request::Gateway { url, body } => (
            "shell.gateway",
            Kind::Gateway,
            serde_json::json!({
                "url": url,
                "method": if body.is_some() { "POST" } else { "GET" },
                "body": body,
                "generations": ens,
                "deadline_ms": deadline_ms,
            }),
        ),
        Request::Tezos {
            endpoint,
            post,
            path,
            body,
        } => (
            "shell.tezos",
            Kind::Tezos,
            serde_json::json!({
                "endpoint": endpoint,
                "method": if *post { "POST" } else { "GET" },
                "path": path,
                "body": body,
                "generations": { "tezos": generations.tezos },
                "deadline_ms": deadline_ms,
            }),
        ),
        Request::Verified(op) => {
            let mut params = verified_params(op);
            if let serde_json::Value::Object(map) = &mut params {
                map.insert(
                    "generations".into(),
                    serde_json::json!({ "lifecycle": generations.lifecycle }),
                );
                map.insert("deadline_ms".into(), deadline_ms.into());
            }
            ("shell.verified", Kind::Verified, params)
        }
        Request::Prefetch { uri } => (
            "shell.prefetch",
            Kind::Prefetch,
            serde_json::json!({ "uri": uri, "generations": ens, "deadline_ms": deadline_ms }),
        ),
    }
}

fn hex(bytes: &[u8]) -> String {
    fc_naming::session::rpc::hex(bytes)
}

/// A verified operation as design 0004's table writes it.
fn verified_params(op: &VerifiedOp) -> serde_json::Value {
    match op {
        VerifiedOp::MyotisRecord {
            method,
            name,
            address,
            coin_type,
        } => serde_json::json!({
            "myotis": "record",
            "method": method,
            "name": name,
            "address": address,
            "coin_type": coin_type,
        }),
        VerifiedOp::MyotisCall { to, data } => {
            serde_json::json!({ "myotis": "call", "to": hex(to), "data": hex(data) })
        }
        VerifiedOp::ColibriResolve {
            name,
            call_data,
            resolver,
        } => serde_json::json!({
            "colibri": "resolve",
            "name": name,
            "call_data": hex(call_data),
            "resolver": resolver,
        }),
        VerifiedOp::ColibriReverse { address, coin_type } => serde_json::json!({
            "colibri": "reverse",
            "address": address,
            "coin_type": coin_type,
        }),
    }
}

/// Main's terminal reply as the machine's answer; `None` when it is
/// malformed.
fn answer(kind: Kind, outcome: Result<Box<RawValue>, ErrorBody>) -> Option<Answer> {
    let result = match outcome {
        Ok(result) => result,
        Err(error) => {
            return Some(Answer::Failed(match error.code {
                ErrorCode::Timeout | ErrorCode::Deadline => Transport::Timeout,
                ErrorCode::Refused => Transport::Refused,
                ErrorCode::TooLarge => Transport::TooLarge,
                ErrorCode::Cancelled => Transport::Cancelled,
                ErrorCode::StaleGeneration => Transport::StaleGeneration,
                _ => Transport::Network,
            }));
        }
    };
    match kind {
        Kind::Rpc | Kind::Gateway | Kind::Tezos => {
            #[derive(Deserialize)]
            struct Http {
                status: u16,
                body: String,
            }
            let http: Http = serde_json::from_str(result.get()).ok()?;
            let body = base64::engine::general_purpose::STANDARD
                .decode(http.body)
                .ok()?;
            Some(match kind {
                Kind::Rpc => Answer::Rpc {
                    status: http.status,
                    body,
                },
                Kind::Gateway => Answer::Gateway {
                    status: http.status,
                    body,
                },
                _ => Answer::Tezos {
                    status: http.status,
                    body,
                },
            })
        }
        Kind::Prefetch => Some(Answer::Done),
        Kind::Verified => {
            let value = jsjson::parse(result.get()).ok()?;
            let JsValue::Object(members) = &value else {
                return None;
            };
            let only = |key: &str| members.len() == 1 && members[0].0 == key;
            // A failure is one of design 0004's classes and carries no text;
            // a failure or a revert stands alone.
            if members.iter().any(|(k, _)| k == "failure") {
                let class = value.get("failure").and_then(JsValue::as_str)?;
                if !only("failure") || !FAILURE_CLASSES.contains(&class) {
                    return None;
                }
                return Some(Answer::Verified(Verified::Failure(class.to_owned())));
            }
            if members.iter().any(|(k, _)| k == "revert") {
                let revert = value.get("revert").and_then(JsValue::as_str)?;
                if !only("revert") {
                    return None;
                }
                let data = fc_naming::session::rpc::hex_string(revert)?;
                return Some(Answer::Verified(Verified::Revert(data)));
            }
            Some(Answer::Verified(Verified::Result(adapter_keys(&value))))
        }
    }
}

/// The wire's snake_case keys as the adapters' own (camelCase), which the
/// machine reads.
fn adapter_keys(value: &JsValue) -> JsValue {
    let JsValue::Object(members) = value else {
        return value.clone();
    };
    JsValue::Object(
        members
            .iter()
            .map(|(key, value)| {
                let key = match key.as_str() {
                    "data_hex" => "dataHex",
                    "address_hex" => "addressHex",
                    "block_number" => "blockNumber",
                    "result_hex" => "resultHex",
                    "optimistic_block_number" => "optimisticBlockNumber",
                    "resolved_data" => "resolvedData",
                    "resolver_address" => "resolverAddress",
                    other => other,
                };
                (key.to_owned(), value.clone())
            })
            .collect(),
    )
}

#[derive(Deserialize)]
struct AvailabilityParams {
    ready: bool,
    enabled: bool,
}

/// What every resolution carries besides its subject.
#[derive(Deserialize)]
struct Common {
    /// Today's private-window handlers: the core logs no names anyway.
    #[serde(default)]
    #[allow(dead_code)]
    private: bool,
    #[serde(default)]
    attempts_used: u32,
    #[serde(default)]
    deadline_ms: Option<u64>,
}

impl Common {
    /// The caller's options, or `None` out of range: main resubmits only
    /// with attempts left, and with the remainder of the caller's deadline.
    fn options(&self) -> Option<CallOptions> {
        let deadline = Bounds::default().deadline_ms;
        (self.attempts_used < MAX_LIFECYCLE_ATTEMPTS
            && self.deadline_ms.is_none_or(|ms| ms <= deadline))
        .then_some(CallOptions {
            attempts_used: self.attempts_used,
            deadline_ms: self.deadline_ms,
        })
    }
}

#[derive(Deserialize)]
struct NameParams {
    name: String,
    #[serde(flatten)]
    common: Common,
}

impl NameParams {
    fn options(&self) -> Option<CallOptions> {
        self.common.options()
    }
}

#[derive(Deserialize)]
struct AddressParams {
    name: String,
    #[serde(default = "mainnet")]
    chain_id: f64,
    #[serde(flatten)]
    common: Common,
}

impl AddressParams {
    fn options(&self) -> Option<CallOptions> {
        self.common.options()
    }
}

#[derive(Deserialize)]
struct ReverseParams {
    address: String,
    #[serde(default = "mainnet")]
    chain_id: f64,
    #[serde(flatten)]
    common: Common,
}

impl ReverseParams {
    fn options(&self) -> Option<CallOptions> {
        self.common.options()
    }
}

fn mainnet() -> f64 {
    1.0
}

#[derive(Deserialize)]
struct InvalidateParams {
    #[serde(default)]
    name: Option<String>,
}

/// `naming.configure`'s snapshot (design 0004, Configuration).
#[derive(Deserialize)]
struct Snapshot {
    #[serde(default)]
    reset: Option<String>,
    rpc: Vec<EndpointParam>,
    direct: Option<DirectParam>,
    prover: Option<ProverParam>,
    policy: Policy,
    /// Today's raw `network.quorum` values: the machine applies today's
    /// coercions and clamps where today's code reads them.
    quorum: Option<serde_json::Map<String, serde_json::Value>>,
    myotis_enabled: bool,
    tezos: Vec<String>,
}

#[derive(Deserialize)]
struct EndpointParam {
    endpoint: String,
}

#[derive(Deserialize)]
struct DirectParam {
    endpoint: String,
    user_configured: bool,
}

#[derive(Deserialize)]
struct ProverParam {
    endpoint: String,
    zk: bool,
}

#[derive(Deserialize)]
struct Policy {
    order: Vec<String>,
    prefer_verified: bool,
}

/// At most 64 RPC endpoints (design 0004, Configuration).
const MAX_RPC_ENDPOINTS: usize = 64;

impl Snapshot {
    fn config(&self) -> Option<Config> {
        if self.rpc.len() > MAX_RPC_ENDPOINTS {
            return None;
        }
        // `network.quorum`, with today's names for the keys.
        let quorum = match &self.quorum {
            None => JsValue::Null,
            Some(map) => {
                let renamed: serde_json::Map<String, serde_json::Value> = map
                    .iter()
                    .map(|(key, value)| {
                        let key = match key.as_str() {
                            "timeout_ms" => "timeoutMs",
                            "anchor_ttl_ms" => "anchorTtlMs",
                            other => other,
                        };
                        (key.to_owned(), value.clone())
                    })
                    .collect();
                jsjson::parse(&serde_json::Value::Object(renamed).to_string()).ok()?
            }
        };
        Some(Config {
            rpc: self.rpc.iter().map(|e| e.endpoint.clone()).collect(),
            direct: self.direct.as_ref().map(|d| Direct {
                endpoint: d.endpoint.clone(),
                user_configured: d.user_configured,
            }),
            order: self.policy.order.clone(),
            prefer_verified: self.policy.prefer_verified,
            quorum,
            myotis_enabled: self.myotis_enabled,
            prover: self.prover.as_ref().map(|p| (p.endpoint.clone(), p.zk)),
            tezos: self.tezos.clone(),
            bounds: Bounds::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Pending;

    /// The frames the thread wrote, as JSON.
    /// What the writer got; reading a frame frees its allowance.
    fn written(rx: &mpsc::Receiver<Out>) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        while let Ok(Out::Frame { frame, .. }) = rx.try_recv() {
            out.extend(serde_json::from_slice(&frame[5..]).ok());
        }
        out
    }

    fn naming(max_outstanding: usize, writer_bytes: usize) -> (Naming, mpsc::Receiver<Out>) {
        naming_with(max_outstanding, writer_bytes, Bounds::default())
    }

    fn naming_with(
        max_outstanding: usize,
        writer_bytes: usize,
        bounds: Bounds,
    ) -> (Naming, mpsc::Receiver<Out>) {
        let (tx, rx) = mpsc::channel();
        let config = Config {
            bounds,
            ..empty_config()
        };
        let naming = Naming {
            machine: Machine::new(0, config, Box::new(OsRandom)),
            out: tx,
            allowance: Allowance::new(usize::MAX, writer_bytes),
            requests: Requests::new(max_outstanding, Arc::new(Pending::default())),
            outbox: VecDeque::new(),
            max_backlog: MAX_NAMING_BACKLOG,
            callers: BTreeMap::new(),
            outgoing: BTreeMap::new(),
            by_io: BTreeMap::new(),
            queued: VecDeque::new(),
        };
        (naming, rx)
    }

    /// Main's response, as the event loop routes it: the gate retires the
    /// request, then naming takes the answer.
    fn respond(naming: &mut Naming, id: u64, outcome: Result<Box<RawValue>, ErrorBody>) -> Flow {
        assert_eq!(naming.requests.answered(id), Some(Owner::Naming));
        naming.response(id, outcome)
    }

    const SNAPSHOT: &str = r#"{"rpc":[{"endpoint":"e1"},{"endpoint":"e2"},{"endpoint":"e3"},{"endpoint":"e4"}],
        "direct":null,"prover":null,"policy":{"order":["quorum"],"prefer_verified":false},
        "quorum":{"k":3,"m":2,"timeout_ms":5000,"anchor":"latest","anchor_ttl_ms":30000},
        "myotis_enabled":false,"tezos":[]}"#;

    fn shell(frames: &[serde_json::Value]) -> Vec<&serde_json::Value> {
        frames
            .iter()
            .filter(|f| f["method"] == "shell.rpc")
            .collect()
    }

    #[test]
    fn requests_past_the_cap_wait_their_turn() {
        let (mut naming, rx) = naming(2, usize::MAX);
        assert!(
            naming
                .request(1, "naming.configure", Some(SNAPSHOT))
                .is_ok()
        );
        assert!(
            naming
                .request(
                    2,
                    "naming.resolve_content",
                    Some(r#"{"name":"vitalik.eth"}"#)
                )
                .is_ok()
        );
        assert!(naming.advance(0).is_ok());
        let requests = |frames: &[serde_json::Value]| {
            frames
                .iter()
                .filter(|f| f["method"] == "shell.rpc")
                .map(|f| f["id"].as_u64().unwrap_or(0))
                .collect::<Vec<_>>()
        };
        // Four head probes, two at a time, each with its session's deadline.
        let frames = written(&rx);
        assert!(
            shell(&frames)
                .iter()
                .all(|f| f["params"]["deadline_ms"] == 120_000)
        );
        let first = requests(&frames);
        assert_eq!(first.len(), 2);
        assert_eq!(naming.queued.len(), 2);
        // An answer frees a slot for the next, sent with what is left.
        let body = base64::engine::general_purpose::STANDARD
            .encode(r#"{"jsonrpc":"2.0","id":1,"result":"0x1312d00"}"#);
        let body_answer = RawValue::from_string(format!(r#"{{"status":200,"body":"{body}"}}"#))
            .unwrap_or_else(|_| unreachable!());
        assert!(naming.advance(4).is_ok());
        assert!(respond(&mut naming, first[0], Ok(body_answer)).is_ok());
        assert!(naming.flush().is_ok());
        let frames = written(&rx);
        let second = requests(&frames);
        assert_eq!(second.len(), 1);
        assert_eq!(shell(&frames)[0]["params"]["deadline_ms"], 119_996);
        assert_eq!(naming.queued.len(), 1);
        // The reader knows exactly the requests still waiting for main: a
        // fragmented answer must name one.
        assert!(!naming.requests.is_pending(first[0]));
        assert!(naming.requests.is_pending(first[1]));
        assert!(naming.requests.is_pending(second[0]));
    }

    #[test]
    fn frames_past_the_writer_share_wait_here() {
        // Room for one frame at a time.
        let (mut naming, rx) = naming(256, 1);
        assert!(
            naming
                .request(1, "naming.configure", Some(SNAPSHOT))
                .is_ok()
        );
        assert!(
            naming
                .request(
                    2,
                    "naming.resolve_content",
                    Some(r#"{"name":"vitalik.eth"}"#)
                )
                .is_ok()
        );
        assert!(naming.advance(0).is_ok());
        // The configure reply took the room: the probes wait, in the FIFO
        // behind the waiting frames, rather than ending the process.
        assert_eq!(written(&rx).len(), 1);
        assert_eq!(naming.outbox.len() + naming.queued.len(), 4);
        // Each time the writer frees room, one more goes.
        for _ in 0..4 {
            assert!(naming.handle(In::Drained).is_ok());
            assert!(naming.flush().is_ok());
            assert_eq!(shell(&written(&rx)).len(), 1);
        }
        assert!(naming.outbox.is_empty() && naming.queued.is_empty());
    }

    #[test]
    fn a_request_too_large_to_send_completes_here() {
        let (mut naming, rx) = naming(256, usize::MAX);
        let myotis = SNAPSHOT
            .replace(r#""order":["quorum"]"#, r#""order":["myotis"]"#)
            .replace(r#""myotis_enabled":false"#, r#""myotis_enabled":true"#);
        assert!(naming.request(1, "naming.configure", Some(&myotis)).is_ok());
        let ready = r#"{"ready":true,"enabled":true}"#;
        assert!(
            naming
                .request(2, "naming.availability", Some(ready))
                .is_ok()
        );
        // Its verified operation carries a name of a whole frame (main's
        // own request can come within bytes of one).
        let name = format!("{}.eth", "a".repeat(1 << 20));
        let params = serde_json::json!({ "name": name }).to_string();
        assert!(
            naming
                .request(3, "naming.resolve_content", Some(&params))
                .is_ok()
        );
        assert!(naming.advance(0).is_ok());
        assert!(naming.flush().is_ok());
        // Never sent; the lookup fails, and its reply fits a frame.
        let frames = written(&rx);
        assert!(!frames.iter().any(|f| f["method"] == "shell.verified"));
        let reply = frames.iter().find(|f| f["id"] == 3).unwrap();
        assert_eq!(reply["error"]["code"], "resolution_failed");
        assert!(naming.outgoing.is_empty());
    }

    #[test]
    fn a_request_cancelled_while_waiting_for_room_is_never_sent() {
        let bounds = Bounds {
            deadline_ms: 100,
            ..Bounds::default()
        };
        // Room for one frame at a time; the configure reply takes it.
        let (mut naming, rx) = naming_with(256, 1, bounds);
        assert!(
            naming
                .request(1, "naming.configure", Some(SNAPSHOT))
                .is_ok()
        );
        assert!(
            naming
                .request(
                    2,
                    "naming.resolve_content",
                    Some(r#"{"name":"vitalik.eth"}"#)
                )
                .is_ok()
        );
        assert!(naming.advance(0).is_ok());
        assert_eq!(naming.queued.len(), 4);
        // The session's deadline cancels its probes while they wait.
        assert!(naming.advance(150).is_ok());
        assert!(naming.queued.is_empty());
        // Room again: only the deadline reply goes, no probe and no cancel.
        written(&rx);
        assert!(naming.handle(In::Drained).is_ok());
        assert!(naming.flush().is_ok());
        let frames = written(&rx);
        assert!(frames.iter().all(|f| f["type"] == "response"), "{frames:?}");
        assert!(naming.outgoing.is_empty());
    }

    #[test]
    fn unwritten_replies_count_in_the_sessions_total() {
        let bounds = Bounds {
            total_bytes: 2_000,
            resume_bytes: 1_000,
            ..Bounds::default()
        };
        // Room for one frame at a time; the admission guard out of the way.
        let (mut naming, _rx) = naming_with(256, 1, bounds);
        naming.max_backlog = usize::MAX;
        let filler = format!(
            r#"{{"type":"event","event":"x.y","data":{{"pad":"{}"}}}}"#,
            "x".repeat(2000)
        );
        assert!(naming.send(filler.as_bytes()).is_ok());
        assert!(naming.send(filler.as_bytes()).is_ok());
        assert!(
            naming
                .request(
                    7,
                    "naming.resolve_content",
                    Some(r#"{"name":"vitalik.eth"}"#)
                )
                .is_ok()
        );
        // The machine counted the backlog: no room for a session.
        assert_eq!(naming.machine.running(), 0);
        assert!(naming.flush().is_ok());
        let busy: serde_json::Value =
            serde_json::from_slice(&naming.outbox.back().unwrap()[5..]).unwrap();
        assert_eq!(busy["error"]["code"], "busy");
    }

    #[test]
    fn lookups_are_busy_while_naming_cannot_write() {
        // Room for one frame at a time, and a backlog bound of 1,000 bytes.
        let (mut naming, rx) = naming(256, 1);
        naming.max_backlog = 1000;
        let filler = format!(
            r#"{{"type":"event","event":"x.y","data":{{"pad":"{}"}}}}"#,
            "x".repeat(2000)
        );
        assert!(naming.send(filler.as_bytes()).is_ok());
        assert!(naming.send(filler.as_bytes()).is_ok());
        assert!(naming.backlog() > 1000);
        assert!(
            naming
                .request(
                    7,
                    "naming.resolve_content",
                    Some(r#"{"name":"vitalik.eth"}"#)
                )
                .is_ok()
        );
        // Not started: busy instead, behind the waiting frames.
        assert_eq!(naming.machine.running(), 0);
        let busy: serde_json::Value =
            serde_json::from_slice(&naming.outbox.back().unwrap()[5..]).unwrap();
        assert_eq!(busy["id"], 7);
        assert_eq!(busy["error"]["code"], "busy");
        // Written, the backlog clears and lookups start again.
        drop(written(&rx));
        assert!(naming.handle(In::Drained).is_ok());
        drop(written(&rx));
        assert!(naming.handle(In::Drained).is_ok());
        drop(written(&rx));
        assert!(
            naming
                .request(
                    8,
                    "naming.resolve_content",
                    Some(r#"{"name":"vitalik.eth"}"#)
                )
                .is_ok()
        );
        assert_eq!(naming.machine.running(), 1);
    }

    #[test]
    fn options_out_of_range_are_invalid_arguments() {
        let (mut naming, rx) = naming(256, usize::MAX);
        for (id, params) in [
            (1, r#"{"name":"vitalik.eth","attempts_used":3}"#),
            (2, r#"{"name":"vitalik.eth","deadline_ms":120001}"#),
        ] {
            assert!(
                naming
                    .request(id, "naming.resolve_content", Some(params))
                    .is_ok()
            );
        }
        let frames = written(&rx);
        assert_eq!(frames.len(), 2);
        assert!(
            frames
                .iter()
                .all(|f| f["error"]["code"] == "invalid_argument")
        );
        assert!(naming.callers.is_empty());
    }

    #[test]
    fn verified_replies_are_one_closed_shape() {
        let verified = |text: &str| {
            answer(
                Kind::Verified,
                Ok(RawValue::from_string(text.to_owned()).unwrap_or_else(|_| unreachable!())),
            )
        };
        for class in FAILURE_CLASSES {
            assert!(matches!(
                verified(&format!(r#"{{"failure":"{class}"}}"#)),
                Some(Answer::Verified(Verified::Failure(c))) if c == *class
            ));
        }
        assert!(matches!(
            verified(r#"{"revert":"0x12"}"#),
            Some(Answer::Verified(Verified::Revert(data))) if data == [0x12]
        ));
        // Diagnostic text, a failure beside a revert, extra members, or
        // anything but an object is malformed.
        for text in [
            r#"{"failure":"see https://example.com/key=1"}"#,
            r#"{"failure":"timeout","revert":"0x12"}"#,
            r#"{"revert":"0x12","name":"x"}"#,
            r#"{"failure":1}"#,
            r#""ok""#,
        ] {
            assert!(verified(text).is_none(), "{text}");
        }
    }

    #[test]
    fn os_random_stays_in_range() {
        let mut random = OsRandom;
        for _ in 0..1000 {
            let value = random.next_f64();
            assert!((0.0..1.0).contains(&value));
        }
    }

    #[test]
    fn undefined_members_become_placeholders() {
        let value = jsjson::parse(r#"{"a":1,"b":null}"#).unwrap_or(JsValue::Null);
        let JsValue::Object(members) = &value else {
            return;
        };
        let mut members = members.clone();
        members.push(("ttl".into(), JsValue::Undefined));
        let (result, keys) = with_placeholders(&JsValue::Object(members));
        assert_eq!(result.stringify(), r#"{"a":1,"b":null,"ttl":null}"#);
        assert_eq!(keys, ["ttl"]);
    }

    #[test]
    fn snapshots_rename_quorum_keys() {
        let snapshot: Snapshot = serde_json::from_str(
            r#"{"rpc":[{"endpoint":"e1"}],"direct":null,"prover":null,
               "policy":{"order":["quorum"],"prefer_verified":false},
               "quorum":{"k":3,"m":2,"timeout_ms":5000,"anchor":"latest","anchor_ttl_ms":30000},
               "myotis_enabled":false,"tezos":["t1"]}"#,
        )
        .unwrap_or_else(|_| unreachable!());
        let config = snapshot.config().unwrap_or_else(empty_config);
        assert_eq!(config.rpc, ["e1"]);
        assert_eq!(
            config.quorum.stringify(),
            r#"{"k":3,"m":2,"timeoutMs":5000,"anchor":"latest","anchorTtlMs":30000}"#
        );
    }

    #[test]
    fn verified_replies_take_the_adapters_keys() {
        let value = jsjson::parse(r#"{"result_hex":"0x01","optimistic_block_number":7}"#)
            .unwrap_or(JsValue::Null);
        assert_eq!(
            adapter_keys(&value).stringify(),
            r#"{"resultHex":"0x01","optimisticBlockNumber":7}"#
        );
    }
}
