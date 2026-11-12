//! A service's connection to main: stdin and stdout frames (designs 0001
//! and 0007, "Frames" and "Progress under backpressure").
//!
//! - **The stdin pump** reads stdin into a bounded queue (256 KiB) and sees
//!   its EOF.
//! - **The reader** decodes main's frames and handles each in order, at
//!   once: the handshake, `cancel`, stream credit and `<service>.shutdown`
//!   change state and need no writer room, so **the reader never waits on
//!   the writer** for them. It is also the one thread that calls the
//!   [`Service`]: callbacks run one at a time, in the order of main's
//!   frames, and none after the connection has ended.
//! - **Admission is bounded by what the connection holds.** A request is
//!   live from its admission until its reply, or its stream's terminal, is
//!   written: refusals included. With [`MAX_REQUESTS`] live (0007's 512
//!   admitted plus 256 refusals), the reader parks further requests, up to
//!   0001's reader budget of 256 frames and 16 MiB, and admits them in
//!   order as the writer frees room. Credit, cancels and shutdown behind
//!   them are still handled on arrival. Only with its budget full does the
//!   reader stop reading, which happens only when main sends requests
//!   faster than they can be answered (0007). Even then, an EOF the pump
//!   has seen ends the connection at once, without waiting for the writer.
//! - **The writer** claims one frame at a time: events first, then the
//!   service's own requests and cancels on a two-way connection, then from
//!   `fc-protocol`'s stream [`Duplex`] (credit owed to main, control frames,
//!   then the streams round-robin, as its
//!   [`Sender`](fc_protocol::stream::Sender) orders them). It writes each
//!   before it claims the next. The claim is the
//!   commit: a head opens its stream, a reply or terminal ends its request.
//!   Frames behind the one being written stay queued, so a cancel still
//!   drops an unwritten head (`cancelled` is then the only reply) or beats
//!   an unwritten terminal. The writer never holds the connection's lock
//!   while it writes, and the body bytes it holds count toward its 16 MiB
//!   cap.
//! - **A request's work may claim its commit point** ([`Connection::commit`])
//!   while nothing of it is queued: from then on main's cancel of it queues
//!   no `cancelled`, and reaches the service alone, which answers it (0008,
//!   "Writes": a write cancelled past its start is `outcome_unknown`).
//! - **An event may be about a request** ([`Connection::event_for`]): it
//!   is queued only while nothing of that request is, so none follows the
//!   request's answer, and every one queued before the answer is written
//!   before it, events going first (0008, "Progress").
//! - **An event may be waited for until it is written**
//!   ([`Connection::event_written`]): the caller learns that the writer has
//!   put it in the pipe, whole and flushed, or, past its wait, that it was
//!   taken back unwritten, or that its write had begun and not finished
//!   (0014, "The step marker").
//! - **A service may turn on requests of its own to main**
//!   ([`Options::two_way`], design 0014, COL-3): [`Connection::ask`] sends
//!   one and resolves on main's reply, with a cancel to main when it is
//!   dropped unanswered or its deadline passes, and a result that says
//!   `body: true` opens a stream from main to the service: 0009's frames in
//!   both directions on one connection, through `fc-protocol`'s
//!   [`Duplex`]. A service that doesn't turn them on reads main's data, end
//!   and abort frames as protocol errors (`stream_direction`) and any
//!   response as `unsolicited_response`, as 0007 has it ([`ask`]).
//! - **The lifecycle thread** enforces the handshake's deadline, polls the
//!   parent every 2 s, watches for the writer stall, and ends the service's
//!   requests whose deadline passes.
//! - **Wakers run outside the lock,** so a producer's waker may call back
//!   into its [`Connection`].
//!
//! **What "written" means.** stdout takes blocking writes, and a write that
//! has begun can't be taken back: its bytes are the OS's, even if main
//! hasn't read them yet. So a frame counts as written once the writer has
//! claimed it, which it does only to write it at once.
//!
//! **How it ends** ([`End`]): stdin EOF or a failed write to stdout (exit
//! 0), `<service>.shutdown` (0), the parent gone (0), a protocol error (76),
//! the handshake's deadline (76), the writer stall (76), or the service's
//! own fatal error ([`Connection::fail`]). Then [`run`]:
//! 1. arms the exit watchdog, before anything that could wait: it ends the
//!    process 5 s later whatever its state;
//! 2. waits for the service callback in progress, if any;
//! 3. lets the service tear down ([`Service::end`]). Meanwhile the
//!    connection is *closing*: what requests are owed (replies, heads
//!    without a body, stream terminals) can still be queued, nothing new;
//! 4. lets the writer write what is queued, for at most 1 s;
//! 5. returns the process's result: the end's exit code, unless the
//!    teardown failed ([`Connection::fail`] during [`Service::end`]).
//!
//! **Requests have no caller context.** 0001's envelope carries one, but a
//! service's requests are all main's (0007, "No caller context"), so the
//! reader decodes `{ type, id, method, params }` and ignores a `context`.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::io::{Read, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::frame::{self, Decoder, Frame, KIND_JSON, Kinds};
use fc_protocol::message::{check_id, write_error, write_event, write_result};
use fc_protocol::stream::{
    Abort, Cancel, Credited, Duplex, MAX_DATA, Received, SendError, Settled, Side, StreamError,
    StreamFrame, WRITER_DATA_CAP, Written, Wrote,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::exit::Exit;
use crate::hardening;
use crate::panic::{TaskKind, with_kind};
use crate::watchdog::Watchdog;

mod ask;

pub use ask::{Answer, AskError, AskFailed, Asked, Body, BodyError, Chunk};
use ask::{Ask, Outgoing};

/// The handshake's deadline after spawn (0001: 10 s).
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// The writer stall that ends the process (0001: 30 s with nothing written).
pub const WRITER_STALL: Duration = Duration::from_secs(30);
/// How long after the connection ends the process exits regardless
/// (0007: 5 s).
pub const EXIT_WATCHDOG: Duration = Duration::from_secs(5);
/// How often the parent is checked (0001: 2 s).
pub const PARENT_POLL: Duration = Duration::from_secs(2);
/// The most events waiting for the writer.
pub const MAX_EVENTS: usize = 256;
/// The most requests the connection holds at once, from admission until
/// the reply or the stream's terminal is written: 0007's admission bound
/// (512) plus the refusals the reader's budget allows (256).
pub const MAX_REQUESTS: usize = 512 + 256;
/// The requests the reader parks beyond [`MAX_REQUESTS`]: 0001's reader
/// budget, 256 frames and 16 MiB.
pub const PARKED_FRAMES: usize = 256;
pub const PARKED_BYTES: usize = 16 << 20;
/// Bytes read from stdin and not yet taken by the reader.
const PUMPED: usize = 256 << 10;
/// How long [`run`] lets the writer write what the teardown queued.
const FINAL_FLUSH: Duration = Duration::from_secs(1);
/// The most of a service's own requests the connection holds at once, from
/// [`Connection::ask`] until both main and the service are done with it:
/// as many as main holds of the core's (0004, Bounds: Work; 0009).
pub const MAX_ASKS: usize = 256;

/// How a connection runs.
#[derive(Debug, Clone)]
pub struct Options {
    /// The method prefix: `ipfs` makes `ipfs.hello` and `ipfs.shutdown`.
    pub service: &'static str,
    /// The protocol version the handshake must name.
    pub protocol: u32,
    /// Main's PID, from `--parent-pid`.
    pub parent_pid: Option<u32>,
    /// When the process started: the handshake's deadline counts from here.
    pub started: Instant,
    pub hello_timeout: Duration,
    pub writer_stall: Duration,
    /// `Some`: exit the process this long after the connection ends. `None`
    /// only for tests that run a connection inside a test process.
    pub exit_watchdog: Option<Duration>,
    pub parent_poll: Duration,
    /// The writer's cap on body bytes, queued or being written (0007:
    /// 16 MiB).
    pub data_cap: usize,
    pub max_events: usize,
    /// The most requests held at once ([`MAX_REQUESTS`]).
    pub max_requests: usize,
    /// The requests the reader parks beyond them ([`PARKED_FRAMES`],
    /// [`PARKED_BYTES`]).
    pub parked_frames: usize,
    pub parked_bytes: usize,
    /// Requests from the service to main, and main's bodies in answer to
    /// them (design 0014, COL-3). Off, the connection keeps 0007's one
    /// role: main's data, end and abort frames are refused at their header
    /// (`stream_direction`), a response is `unsolicited_response`, and
    /// [`Connection::ask`] is refused.
    pub two_way: bool,
    /// The most of the service's own requests held at once ([`MAX_ASKS`]).
    pub max_asks: usize,
}

impl Options {
    /// 0001's and 0007's values.
    pub fn new(service: &'static str, protocol: u32, started: Instant) -> Self {
        Options {
            service,
            protocol,
            parent_pid: None,
            started,
            hello_timeout: HELLO_TIMEOUT,
            writer_stall: WRITER_STALL,
            exit_watchdog: Some(EXIT_WATCHDOG),
            parent_poll: PARENT_POLL,
            data_cap: WRITER_DATA_CAP,
            max_events: MAX_EVENTS,
            max_requests: MAX_REQUESTS,
            parked_frames: PARKED_FRAMES,
            parked_bytes: PARKED_BYTES,
            two_way: false,
            max_asks: MAX_ASKS,
        }
    }
}

/// The handshake's parameters (0007, "Methods").
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Hello {
    pub protocol: u32,
    pub shell_version: String,
    /// The frame kinds main takes: a service needs `stream`.
    pub frames: Vec<String>,
}

/// A request from main, after the handshake.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub id: u64,
    pub method: &'a str,
    pub params: Option<&'a RawValue>,
}

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// stdin closed, or a write to stdout failed: main is gone.
    Eof,
    /// `<service>.shutdown`.
    Shutdown,
    /// The parent PID changed.
    ParentGone,
    /// Main broke the protocol; the category is a fixed name.
    Protocol(&'static str),
    /// No handshake within its deadline.
    HelloTimeout,
    /// Main stopped reading: frames waited with nothing written.
    WriterStall,
    /// The service ended the connection ([`Connection::fail`]).
    Fatal(Exit),
}

impl End {
    /// A fixed name, for logs.
    pub fn name(self) -> &'static str {
        match self {
            End::Eof => "eof",
            End::Shutdown => "shutdown",
            End::ParentGone => "parent_gone",
            End::Protocol(_) => "protocol",
            End::HelloTimeout => "hello_timeout",
            End::WriterStall => "writer_stall",
            End::Fatal(_) => "fatal",
        }
    }

    /// The exit code this end calls for, unless the teardown fails.
    pub fn exit(self) -> Exit {
        match self {
            End::Eof | End::Shutdown | End::ParentGone => Exit::Ok,
            End::Protocol(_) | End::HelloTimeout | End::WriterStall => Exit::Protocol,
            End::Fatal(exit) => exit,
        }
    }
}

/// What a service does with its connection. [`Service::hello`],
/// [`Service::request`] and [`Service::cancel`] run on the reader thread,
/// one at a time and in the order of main's frames, so none may block. None
/// runs once the connection has ended.
pub trait Service: Send + Sync + 'static {
    /// Answers the handshake with the result's members other than
    /// `protocol`, or refuses it. Called once, after the protocol version
    /// and frame kinds have been checked.
    fn hello(&self, hello: &Hello)
    -> Result<serde_json::Map<String, serde_json::Value>, ErrorBody>;

    /// A request, admitted to the stream state machine (its ID is above
    /// every earlier one). Answer it exactly once through `conn`, now or
    /// later; never block here.
    fn request(&self, conn: &Connection, request: Request<'_>);

    /// Main cancelled request `id` before its reply or its stream's
    /// terminal was written. Its `cancelled` reply or abort is already
    /// queued: stop its work. (A late cancel never reaches the service.)
    ///
    /// The one exception: a request whose work claimed its commit point
    /// ([`Connection::commit`]) and has queued nothing since. Nothing is
    /// queued for it, and the service owes it its one reply.
    ///
    /// The request isn't settled ([`Connection::settled`]) until this
    /// returns, even if its `cancelled` reply or abort is written
    /// meanwhile: a service that keeps a request's record until it is
    /// settled always finds it here.
    fn cancel(&self, conn: &Connection, id: u64);

    /// The connection ended: tear down. Called once, on [`run`]'s thread,
    /// after the exit watchdog is armed and once no other callback runs.
    ///
    /// While it runs, the connection is closing: what requests are owed
    /// ([`Connection::reply`], [`Connection::reply_error`], a head without a
    /// body, [`Connection::finish`], [`Connection::abort`]) may still be
    /// queued, and the writer writes it for at most 1 s after this returns;
    /// new streams, data and events are refused. After a failed write to
    /// stdout nothing more can be written, so nothing is queued at all:
    /// every call is `Closed`. A teardown that fails
    /// calls [`Connection::fail`]: its exit becomes the process's result
    /// (70 for quiescence it can't prove).
    fn end(&self, conn: &Connection, end: End);
}

/// Why a service's [`Connection::event`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventError {
    /// Too many events wait for the writer.
    Full,
    /// The event didn't serialize, or exceeds one frame.
    Encode,
    /// The connection ended.
    Closed,
    /// The request the event is about has its answer queued, or isn't held
    /// ([`Connection::event_for`]).
    Answered,
}

/// Why [`Connection::event_written`] didn't see its event written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrittenError {
    /// Too many events wait for the writer: nothing was queued.
    Full,
    /// The event didn't serialize, or exceeds one frame: nothing was queued.
    Encode,
    /// The connection ended first. A queued event is taken back and never
    /// written; one whose write had begun may still reach main.
    Closed,
    /// Its wait passed with the event still queued: it was taken back, and
    /// is never written.
    Withdrawn,
    /// Its wait passed while the writer was writing it: it may still reach
    /// main, whole, once main reads.
    Unfinished,
}

/// The service's handle on its connection. Clones share it.
#[derive(Clone)]
pub struct Connection {
    link: Arc<Link>,
}

struct Link {
    state: Mutex<State>,
    /// Wakes the writer: something to write, or the end.
    writer: Condvar,
    /// Wakes [`Connection::event_written`]: an event waited for is written,
    /// or the end.
    written: Condvar,
    /// Wakes [`run`] and the lifecycle thread: the end, the writer done, a
    /// callback returned.
    ended: Condvar,
    /// Wakes the reader: input, a request freed, or the end.
    reader: Condvar,
    /// Wakes the stdin pump: room for input, or the end.
    pump: Condvar,
    /// The process's result: the end's exit code, unless the teardown
    /// failed. Outside the lock, for the exit watchdog.
    result: AtomicU8,
    /// [`Service::end`] has returned.
    torn_down: AtomicBool,
    max_requests: usize,
    /// [`Options::two_way`] and [`Options::max_asks`].
    two_way: bool,
    max_asks: usize,
    /// A failed writer has freed what was queued.
    #[cfg(test)]
    abandoned_freed: AtomicBool,
}

/// A queued event; `ticket` when its sender waits to see it written
/// ([`Connection::event_written`]).
struct Queued {
    json: Vec<u8>,
    ticket: Option<u64>,
}

struct State {
    /// The bodies the service sends, under main's IDs, and, on a two-way
    /// connection, those main sends in answer to the service's own
    /// requests, under the service's ([`Duplex`]). A one-way connection
    /// never takes a frame for the second.
    streams: Duplex,
    events: VecDeque<Queued>,
    max_events: usize,
    /// The last ticket given to an event waited for, the one the writer is
    /// writing, and the last one it wrote and flushed. Tickets are written
    /// in their order, so every ticket up to `written_ticket` is written or
    /// was taken back.
    next_ticket: u64,
    writing_ticket: Option<u64>,
    written_ticket: u64,
    /// The service's requests to main and its cancels of them, in order:
    /// written behind the events, and only once the handshake's reply is.
    /// Dropped at the end ([`ask::close`]).
    outbound: VecDeque<Outgoing>,
    /// The last ID the service's requests took.
    last_ask: u64,
    /// The service's requests, from [`Connection::ask`] until both sides
    /// are done with them ([`ask`]).
    asks: HashMap<u64, Ask>,
    /// Their deadlines, while they wait for main's reply.
    deadlines: BTreeSet<(Instant, u64)>,
    /// The handshake's ID: nothing of the service's own goes before its
    /// reply.
    hello_id: Option<u64>,
    hello_done: bool,
    end: Option<End>,
    /// [`Service::end`] has returned: nothing more may be queued.
    closed: bool,
    /// The reader is in a service callback.
    dispatching: bool,
    /// The request whose accepted cancel the reader is handing to the
    /// service: it isn't settled until [`Service::cancel`] returns.
    cancelling: Option<u64>,
    /// Requests whose work claimed its commit point
    /// ([`Connection::commit`]): a cancel queues nothing for them while
    /// they are unanswered. Pruned to the held ones at each claim.
    committed: HashSet<u64>,
    /// Send futures waiting for room, and settled futures for a request's
    /// end.
    waiters: Vec<Waker>,
    /// The writer holds a frame it hasn't finished writing.
    writing: bool,
    /// The request whose terminal (its reply, a head without a body, its
    /// stream's end or abort) that frame is: the request isn't settled
    /// until the write and its flush are done ([`Connection::settled`]).
    writing_terminal: Option<u64>,
    /// What queued heads hold until the writer takes them, by request.
    charges: HashMap<u64, Charge>,
    /// When the writer last claimed or finished a frame.
    progress: Instant,
    writer_done: bool,
    /// Bytes from stdin, not yet taken by the reader.
    input: VecDeque<Vec<u8>>,
    input_bytes: usize,
    /// stdin ended (EOF or a failed read) after `input`.
    input_end: bool,
}

impl State {
    /// Everyone waiting on the connection: producers, settled futures, and
    /// the service's requests and bodies.
    fn all_waiters(&mut self) -> Vec<Waker> {
        let mut wakers = std::mem::take(&mut self.waiters);
        wakers.extend(self.asks.values_mut().filter_map(|ask| ask.waker.take()));
        wakers
    }
}

impl Link {
    fn new(options: &Options) -> Link {
        Link {
            state: Mutex::new(State {
                // The writer holds at most one data frame outside the
                // queue: the cap covers both.
                streams: Duplex::service(options.data_cap.saturating_sub(MAX_DATA)),
                events: VecDeque::new(),
                max_events: options.max_events,
                next_ticket: 0,
                writing_ticket: None,
                written_ticket: 0,
                outbound: VecDeque::new(),
                last_ask: 0,
                asks: HashMap::new(),
                deadlines: BTreeSet::new(),
                hello_id: None,
                hello_done: false,
                end: None,
                closed: false,
                dispatching: false,
                cancelling: None,
                committed: HashSet::new(),
                waiters: Vec::new(),
                writing: false,
                writing_terminal: None,
                charges: HashMap::new(),
                progress: Instant::now(),
                writer_done: false,
                input: VecDeque::new(),
                input_bytes: 0,
                input_end: false,
            }),
            writer: Condvar::new(),
            written: Condvar::new(),
            ended: Condvar::new(),
            reader: Condvar::new(),
            pump: Condvar::new(),
            result: AtomicU8::new(Exit::Ok.code()),
            torn_down: AtomicBool::new(false),
            max_requests: options.max_requests.max(1),
            two_way: options.two_way,
            max_asks: options.max_asks,
            #[cfg(test)]
            abandoned_freed: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn notify_all(&self) {
        self.writer.notify_all();
        self.written.notify_all();
        self.ended.notify_all();
        self.reader.notify_all();
        self.pump.notify_all();
    }

    /// Ends the connection, once: the first end wins. Nothing more of the
    /// service's own requests goes, or comes, from then on ([`ask::close`]).
    fn end(&self, end: End) {
        let (wakers, outbound) = {
            let mut state = self.lock();
            if state.end.is_some() {
                return;
            }
            state.end = Some(end);
            self.result.store(end.exit().code(), Ordering::SeqCst);
            let outbound = ask::close(&mut state);
            (state.all_waiters(), outbound)
        };
        drop(outbound);
        self.notify_all();
        wake(wakers);
    }

    /// The service's fatal error: it ends the connection, or, once the
    /// connection has ended, sets the process's result. A teardown's
    /// failure replaces the end's code; 70, once set, stays.
    fn fail(&self, exit: Exit) {
        let (wakers, outbound) = {
            let mut state = self.lock();
            if state.end.is_none() {
                state.end = Some(End::Fatal(exit));
                self.result.store(exit.code(), Ordering::SeqCst);
                let outbound = ask::close(&mut state);
                (state.all_waiters(), outbound)
            } else {
                if exit != Exit::Ok && self.result.load(Ordering::SeqCst) != Exit::Internal.code() {
                    self.result.store(exit.code(), Ordering::SeqCst);
                }
                (Vec::new(), VecDeque::new())
            }
        };
        drop(outbound);
        self.notify_all();
        wake(wakers);
    }

    fn result(&self) -> Exit {
        Exit::from_code(self.result.load(Ordering::SeqCst)).unwrap_or(Exit::Internal)
    }

    /// What the exit watchdog exits with: the result, once the teardown has
    /// returned; 70 if it hasn't, since its quiescence is unproven.
    fn watchdog_exit(&self) -> (&'static str, Exit) {
        if self.torn_down.load(Ordering::SeqCst) {
            ("exit_after_end", self.result())
        } else {
            ("teardown_unproven", Exit::Internal)
        }
    }

    /// [`Service::end`] returned: nothing more is queued.
    fn close(&self) {
        self.torn_down.store(true, Ordering::SeqCst);
        self.lock().closed = true;
        self.notify_all();
    }
}

fn wait<'a>(condvar: &Condvar, state: MutexGuard<'a, State>) -> MutexGuard<'a, State> {
    condvar
        .wait(state)
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn wait_timeout<'a>(
    condvar: &Condvar,
    state: MutexGuard<'a, State>,
    timeout: Duration,
) -> MutexGuard<'a, State> {
    match condvar.wait_timeout(state, timeout) {
        Ok((state, _)) => state,
        Err(poisoned) => poisoned.into_inner().0,
    }
}

/// Wakes producers, after the lock is released: a waker may call back into
/// the connection.
fn wake(wakers: Vec<Waker>) {
    for waker in wakers {
        waker.wake();
    }
}

/// What a [`Connection`] call needs of the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Need {
    /// New work: only while the connection is open.
    Open,
    /// What a request is owed (its one reply, its stream's terminal): also
    /// while the connection closes, until [`Service::end`] returns.
    Owed,
}

impl Connection {
    /// Runs `op` on the stream state machine, then wakes the writer, and the
    /// producers if `op` made room.
    fn queue<T>(
        &self,
        need: Need,
        op: impl FnOnce(&mut State) -> (Result<T, SendError>, bool),
    ) -> Result<T, SendError> {
        let (result, wakers) = {
            let mut state = self.link.lock();
            // Nothing more is written once the writer is done, so nothing
            // more is queued.
            if state.closed || state.writer_done || (state.end.is_some() && need == Need::Open) {
                return Err(SendError::Closed);
            }
            let (result, room) = op(&mut state);
            let wakers = if room {
                std::mem::take(&mut state.waiters)
            } else {
                Vec::new()
            };
            (result, wakers)
        };
        self.link.writer.notify_one();
        wake(wakers);
        result
    }

    /// Answers request `id` with `result`: its one reply.
    pub fn reply<T: Serialize>(&self, id: u64, result: &T) -> Result<(), SendError> {
        let mut json = Vec::new();
        write_result(&mut json, id, result).map_err(|_| SendError::TooLarge)?;
        self.queue(Need::Owed, |state| {
            (state.streams.sender_mut().reply(id, json), false)
        })
    }

    /// Answers request `id` with `error`: its one reply.
    pub fn reply_error(&self, id: u64, error: &ErrorBody) -> Result<(), SendError> {
        let mut json = Vec::new();
        write_error(&mut json, id, error).map_err(|_| SendError::TooLarge)?;
        self.queue(Need::Owed, |state| {
            (state.streams.sender_mut().reply(id, json), false)
        })
    }

    /// Answers request `id` with `result`, as [`Connection::reply`] does,
    /// only if it is queued before `deadline`: from `deadline` on, `late`
    /// is queued as its one reply instead, unless something answered it
    /// already. The check and the queueing are one step under the
    /// connection's lock, as for [`Connection::head_by`]: however late its
    /// producer runs, the reply is never queued after its deadline, and one
    /// queued in time stands.
    ///
    /// The reply is encoded in a buffer of exactly its length, and a reply
    /// queued in time keeps `charge` as a head does ([`Connection::head_by`]):
    /// until the writer has written and flushed it and freed its buffers, or
    /// the connection is done; otherwise `charge` is dropped before this
    /// returns. Never under the connection's lock.
    pub fn reply_by<T: Serialize>(
        &self,
        id: u64,
        result: &T,
        deadline: Instant,
        late: &ErrorBody,
        charge: Option<Charge>,
    ) -> Result<Headed, SendError> {
        let json = encode_result(id, result)?;
        self.reply_json_by(id, json, deadline, late, charge)
    }

    /// Answers request `id` with `error`, as [`Connection::reply_error`]
    /// does, only if it is queued before `deadline`, with `charge`: as
    /// [`Connection::reply_by`].
    pub fn reply_error_by(
        &self,
        id: u64,
        error: &ErrorBody,
        deadline: Instant,
        late: &ErrorBody,
        charge: Option<Charge>,
    ) -> Result<Headed, SendError> {
        let mut json = Vec::new();
        write_error(&mut json, id, error).map_err(|_| SendError::TooLarge)?;
        self.reply_json_by(id, json, deadline, late, charge)
    }

    fn reply_json_by(
        &self,
        id: u64,
        json: Vec<u8>,
        deadline: Instant,
        late: &ErrorBody,
        charge: Option<Charge>,
    ) -> Result<Headed, SendError> {
        let mut charge = charge;
        let mut displaced = None;
        let mut late_json = Vec::new();
        write_error(&mut late_json, id, late).map_err(|_| SendError::TooLarge)?;
        let queued = self.queue(Need::Owed, |state| {
            let queued = if Instant::now() < deadline {
                state
                    .streams
                    .sender_mut()
                    .reply(id, json)
                    .map(|()| Headed::Queued)
            } else {
                state
                    .streams
                    .sender_mut()
                    .reply(id, late_json)
                    .map(|()| Headed::Late)
            };
            if let Ok(Headed::Queued) = queued
                && let Some(charge) = charge.take()
            {
                displaced = state.charges.insert(id, charge);
            }
            (queued, false)
        });
        // Outside the lock, as for a head.
        drop(displaced);
        drop(charge);
        queued
    }

    /// Answers request `id` with a head, `result`. With `body`, it opens a
    /// stream once written; data may be pushed behind it now.
    pub fn head<T: Serialize>(&self, id: u64, result: &T, body: bool) -> Result<(), SendError> {
        let mut json = Vec::new();
        write_result(&mut json, id, result).map_err(|_| SendError::TooLarge)?;
        let need = if body { Need::Open } else { Need::Owed };
        self.queue(need, |state| {
            (state.streams.sender_mut().head(id, json, body), false)
        })
    }

    /// Answers request `id` with a head, as [`Connection::head`] does, only
    /// if it is queued before `deadline`: from `deadline` on, `late` is
    /// queued as the request's one reply instead, unless something answered
    /// it already. The check and the queueing are one step under the
    /// connection's lock, so however late its producer runs, a head is never
    /// queued after its deadline, and one queued in time stands (0007,
    /// "`headers_ms`").
    ///
    /// The head is encoded in a buffer of exactly [`head_len`]'s size,
    /// and the writer writes that buffer as it is, without a copy. A queued
    /// head keeps `charge` until the writer has written and flushed it, or
    /// the reply a cancel or a settle put in its place, or the connection
    /// is done: such as the memory reservation of [`head_len`]'s bytes
    /// (0007, "Pending replies"). Otherwise `charge` is dropped before this
    /// returns. A charge is never dropped under the connection's lock, so
    /// its drop may wake work that calls back into the connection.
    pub fn head_by<T: Serialize>(
        &self,
        id: u64,
        result: &T,
        body: bool,
        deadline: Instant,
        late: &ErrorBody,
        charge: Option<Charge>,
    ) -> Result<Headed, SendError> {
        let mut charge = charge;
        let mut displaced = None;
        let json = encode_result(id, result)?;
        let mut late_json = Vec::new();
        write_error(&mut late_json, id, late).map_err(|_| SendError::TooLarge)?;
        let need = if body { Need::Open } else { Need::Owed };
        let queued = self.queue(need, |state| {
            let queued = if Instant::now() < deadline {
                state
                    .streams
                    .sender_mut()
                    .head(id, json, body)
                    .map(|()| Headed::Queued)
            } else {
                state
                    .streams
                    .sender_mut()
                    .reply(id, late_json)
                    .map(|()| Headed::Late)
            };
            if let Ok(Headed::Queued) = queued
                && let Some(charge) = charge.take()
            {
                displaced = state.charges.insert(id, charge);
            }
            (queued, false)
        });
        // Outside the lock: a head that wasn't queued, and whatever a
        // charge for the same ID left behind (never, while IDs are unique).
        drop(displaced);
        drop(charge);
        queued
    }

    /// Queues as much of `bytes` as stream `id`'s window and the writer's cap
    /// allow, without waiting.
    pub fn push(&self, id: u64, bytes: &[u8]) -> Result<usize, SendError> {
        self.queue(Need::Open, |state| {
            (state.streams.sender_mut().push(id, bytes), false)
        })
    }

    /// Queues all of `bytes` on stream `id`, waiting for room as often as
    /// needed: credit from main, or the writer's progress.
    pub fn send<'a>(&'a self, id: u64, bytes: &'a [u8]) -> SendBytes<'a> {
        SendBytes {
            conn: self,
            id,
            bytes,
            sent: 0,
        }
    }

    /// Queues stream `id`'s end, behind every byte queued.
    pub fn finish(&self, id: u64) -> Result<(), SendError> {
        self.queue(Need::Owed, |state| {
            (state.streams.sender_mut().finish(id), false)
        })
    }

    /// Aborts stream `id`.
    pub fn abort(&self, id: u64, abort: &Abort) -> Result<(), SendError> {
        self.queue(Need::Owed, |state| {
            let result = state.streams.sender_mut().abort(id, abort);
            // Its purge made room under the writer's cap.
            let room = result.is_ok();
            (result, room)
        })
    }

    /// Settles request `id` with an outcome the service owes it, unless it
    /// is settled already (0007, "Panics"): `error` is its one reply if
    /// nothing of it was written (a queued head is dropped, as for a
    /// cancel), `abort` ends its stream if the stream is open. See
    /// [`Sender::settle`](fc_protocol::stream::Sender::settle).
    pub fn settle(&self, id: u64, error: &ErrorBody, abort: &Abort) -> Result<Settled, SendError> {
        let mut json = Vec::new();
        write_error(&mut json, id, error).map_err(|_| SendError::TooLarge)?;
        self.queue(Need::Owed, |state| {
            let result = state.streams.sender_mut().settle(id, json, abort);
            // A purge made room under the writer's cap.
            let room = result.is_ok();
            (result, room)
        })
    }

    /// Claims request `id`'s commit point for its work, as 0001's worker
    /// claims its own: `true` if nothing of it is queued yet (no reply, no
    /// head, and no `cancelled` from main's cancel), and from then on
    /// main's cancel of it queues nothing while it stays so. That cancel
    /// reaches [`Service::cancel`] alone, and the service owes the request
    /// its one reply (0008, "Writes": a write cancelled past its start is
    /// `outcome_unknown`, never `cancelled`). `false` otherwise: its answer
    /// is queued, and its work must not commit.
    ///
    /// The check and the claim are one step under the connection's lock,
    /// as main's cancel is: a cancel comes either before the claim, and is
    /// `cancelled`, or after it.
    pub fn commit(&self, id: u64) -> bool {
        let mut state = self.link.lock();
        if !state.streams.sender().is_unanswered(id) {
            return false;
        }
        let State {
            streams, committed, ..
        } = &mut *state;
        // Only requests still held keep their claim.
        committed.retain(|held| streams.sender().is_live(*held));
        committed.insert(id);
        true
    }

    /// Resolves once nothing of request `id` is held any more: its reply,
    /// or its stream's terminal, has been written and flushed to stdout (or
    /// it was never held), or the connection has ended. A terminal the
    /// writer has claimed but is still writing (main isn't reading) holds
    /// it. A service keeps a request's admission until then (0007,
    /// "Admission": heads and open streams count).
    pub fn settled(&self, id: u64) -> SettledFuture<'_> {
        SettledFuture { conn: self, id }
    }

    /// Queues an event for main, ahead of replies and streams.
    pub fn event<T: Serialize>(&self, event: &str, data: &T) -> Result<(), EventError> {
        let mut json = Vec::new();
        write_event(&mut json, event, data).map_err(|_| EventError::Encode)?;
        if json.len() > frame::MAX_PAYLOAD {
            return Err(EventError::Encode);
        }
        let mut state = self.link.lock();
        if state.end.is_some() {
            return Err(EventError::Closed);
        }
        if state.events.len() >= state.max_events {
            return Err(EventError::Full);
        }
        state.events.push_back(Queued { json, ticket: None });
        drop(state);
        self.link.writer.notify_one();
        Ok(())
    }

    /// Queues an event about request `id` for main, as
    /// [`Connection::event`] does, only while the request is held with
    /// nothing of it queued: no reply, no head, and no `cancelled` from
    /// main's cancel ([`EventError::Answered`] otherwise). The check and
    /// the queueing are one step under the connection's lock, as a reply's
    /// queueing is, so no event about a request is queued after its answer;
    /// and since the writer writes every queued event before any reply,
    /// each one queued before the answer is written before it (0008,
    /// "Progress": progress stops at the final answer). A request whose
    /// work claimed its commit point ([`Connection::commit`]) stays so
    /// through main's cancel, until its work answers.
    pub fn event_for<T: Serialize>(
        &self,
        id: u64,
        event: &str,
        data: &T,
    ) -> Result<(), EventError> {
        let mut json = Vec::new();
        write_event(&mut json, event, data).map_err(|_| EventError::Encode)?;
        if json.len() > frame::MAX_PAYLOAD {
            return Err(EventError::Encode);
        }
        let mut state = self.link.lock();
        // Nothing more is written once the writer is done.
        if state.end.is_some() || state.closed || state.writer_done {
            return Err(EventError::Closed);
        }
        if !state.streams.sender().is_unanswered(id) {
            return Err(EventError::Answered);
        }
        if state.events.len() >= state.max_events {
            return Err(EventError::Full);
        }
        state.events.push_back(Queued { json, ticket: None });
        drop(state);
        self.link.writer.notify_one();
        Ok(())
    }

    /// Queues an event for main, as [`Connection::event`] does, and waits
    /// until the writer has written it to stdout, whole and flushed, for at
    /// most `wait` (0014, "The step marker": a marker main reads even if the
    /// process dies right after). Blocks the calling thread: never call it
    /// from a [`Service`] callback.
    ///
    /// Past `wait`, an event still queued is taken back and never written
    /// ([`WrittenError::Withdrawn`]); one the writer is writing can't be,
    /// and may still reach main ([`WrittenError::Unfinished`]). The check
    /// and the taking back are one step under the connection's lock, as the
    /// writer's claim is, so an event is either claimed in time or not at
    /// all. Events go ahead of every other frame, so the wait is for the
    /// frame being written, if any, and the events queued before this one.
    pub fn event_written<T: Serialize>(
        &self,
        event: &str,
        data: &T,
        wait: Duration,
    ) -> Result<(), WrittenError> {
        let mut json = Vec::new();
        write_event(&mut json, event, data).map_err(|_| WrittenError::Encode)?;
        if json.len() > frame::MAX_PAYLOAD {
            return Err(WrittenError::Encode);
        }
        let started = Instant::now();
        let mut state = self.link.lock();
        if state.end.is_some() || state.closed || state.writer_done {
            return Err(WrittenError::Closed);
        }
        if state.events.len() >= state.max_events {
            return Err(WrittenError::Full);
        }
        state.next_ticket += 1;
        let ticket = state.next_ticket;
        state.events.push_back(Queued {
            json,
            ticket: Some(ticket),
        });
        self.link.writer.notify_one();
        loop {
            if state.written_ticket >= ticket {
                return Ok(());
            }
            let ended = state.end.is_some() || state.writer_done;
            let left = wait.checked_sub(started.elapsed());
            if ended || left.is_none() {
                let queued = state
                    .events
                    .iter()
                    .position(|queued| queued.ticket == Some(ticket));
                if let Some(at) = queued {
                    drop(state.events.remove(at));
                }
                return Err(match (ended, queued) {
                    (true, _) => WrittenError::Closed,
                    (false, Some(_)) => WrittenError::Withdrawn,
                    (false, None) => WrittenError::Unfinished,
                });
            }
            state = wait_timeout(
                &self.link.written,
                state,
                left.unwrap_or_default().max(Duration::from_millis(1)),
            );
        }
    }

    /// The service can't go on: ends the connection with `exit`. During
    /// [`Service::end`] it doesn't change the connection's [`End`] but sets
    /// the process's result (0007: a teardown that couldn't prove
    /// quiescence exits 70).
    pub fn fail(&self, exit: Exit) {
        self.link.fail(exit);
    }

    /// Whether the connection has ended.
    pub fn is_ended(&self) -> bool {
        self.link.lock().end.is_some()
    }

    /// What the writer holds, for diagnostics.
    pub fn stats(&self) -> ConnectionStats {
        let state = self.link.lock();
        ConnectionStats {
            live_requests: state.streams.sender().live(),
            held_bytes: state.streams.sender().held(),
            events: state.events.len(),
        }
    }
}

/// What a queued head or reply holds until the writer has written it
/// ([`Connection::head_by`], [`Connection::reply_by`]): dropped then,
/// outside the connection's lock.
pub type Charge = Box<dyn Send>;

/// A JSON frame's header: its length and kind.
const JSON_HEADER: usize = 5;

/// What a head of `result` for request `id` holds from its encoding until
/// the writer has written it ([`Connection::head_by`]): its JSON, in a
/// buffer of exactly its length, and its frame header. A service reserves
/// this much for a pending head (0007, "Pending replies"), as long as
/// `result` serializes the same way each time. `TooLarge` past one frame.
pub fn head_len<T: Serialize>(id: u64, result: &T) -> Result<usize, SendError> {
    Ok(result_len(id, result)?.saturating_add(JSON_HEADER))
}

/// The length of `result`'s response envelope, counted without encoding
/// it: at most one frame's payload.
fn result_len<T: Serialize>(id: u64, result: &T) -> Result<usize, SendError> {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    write_result(&mut count, id, result).map_err(|_| SendError::TooLarge)?;
    if count.0 > frame::MAX_PAYLOAD {
        return Err(SendError::TooLarge);
    }
    Ok(count.0)
}

/// `result`'s response envelope, in a buffer of exactly its length, so
/// what the buffer holds is what [`head_len`] counts.
fn encode_result<T: Serialize>(id: u64, result: &T) -> Result<Vec<u8>, SendError> {
    let mut json = Vec::with_capacity(result_len(id, result)?);
    write_result(&mut json, id, result).map_err(|_| SendError::TooLarge)?;
    Ok(json)
}

/// What [`Connection::head_by`] queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Headed {
    /// The head, in time.
    Queued,
    /// Its deadline had passed: the late reply, in its place.
    Late,
}

/// What a connection's writer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionStats {
    /// Requests with a record: unanswered, with a reply not yet written, or
    /// with a stream not yet ended. At most [`Options::max_requests`].
    pub live_requests: usize,
    /// Queued body bytes across streams.
    pub held_bytes: usize,
    /// Events waiting.
    pub events: usize,
}

/// The future of [`Connection::settled`].
pub struct SettledFuture<'a> {
    conn: &'a Connection,
    id: u64,
}

impl Future for SettledFuture<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.conn.link.lock();
        let held =
            state.streams.sender().is_live(self.id) || state.writing_terminal == Some(self.id);
        // An accepted cancel being handed to the service holds it, even
        // once the connection has ended: the callback is never cut short.
        let cancelling = state.cancelling == Some(self.id);
        if !cancelling && (state.end.is_some() || !held) {
            return Poll::Ready(());
        }
        if !state.waiters.iter().any(|w| w.will_wake(cx.waker())) {
            state.waiters.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

/// The future of [`Connection::send`].
pub struct SendBytes<'a> {
    conn: &'a Connection,
    id: u64,
    bytes: &'a [u8],
    sent: usize,
}

impl SendBytes<'_> {
    /// How many of its bytes are queued so far: all of them once it has
    /// resolved `Ok`, and those queued before it failed otherwise. (Poll it
    /// pinned in place, as `(&mut send).await`, to ask afterwards.)
    pub fn sent(&self) -> usize {
        self.sent
    }
}

impl Future for SendBytes<'_> {
    type Output = Result<(), SendError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let mut state = this.conn.link.lock();
        loop {
            if state.end.is_some() {
                return Poll::Ready(Err(SendError::Closed));
            }
            let rest = this.bytes.get(this.sent..).unwrap_or_default();
            if rest.is_empty() {
                return Poll::Ready(Ok(()));
            }
            match state.streams.sender_mut().push(this.id, rest) {
                Ok(0) => {
                    if !state.waiters.iter().any(|w| w.will_wake(cx.waker())) {
                        state.waiters.push(cx.waker().clone());
                    }
                    return Poll::Pending;
                }
                Ok(taken) => {
                    this.sent += taken;
                    this.conn.link.writer.notify_one();
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }
}

/// Runs a connection on `input` and `output` (stdin and stdout) until it
/// ends, lets `service` tear down, and returns the process's exit code.
///
/// Before it, the process has installed the panic hook
/// ([`crate::panic::install`]) and hardened itself
/// ([`crate::hardening::harden`]). If the parent is already gone, it
/// returns at once.
pub fn run<S: Service>(
    service: Arc<S>,
    options: Options,
    input: impl Read + Send + 'static,
    output: impl Write + Send + 'static,
) -> Exit {
    if !hardening::request_parent_death_signal(options.parent_pid) {
        crate::log::info("the parent is gone", serde_json::json!({}));
        return Exit::Ok;
    }
    let link = Arc::new(Link::new(&options));
    let conn = Connection { link: link.clone() };

    let spawned = [
        spawn("writer", {
            let link = link.clone();
            move || write_loop(&link, output)
        }),
        spawn("stdin", {
            let link = link.clone();
            move || pump_loop(&link, input)
        }),
        spawn("reader", {
            let (link, conn, service, options) =
                (link.clone(), conn.clone(), service.clone(), options.clone());
            move || Reader::new(&link, &conn, &*service, &options).run()
        }),
        spawn("lifecycle", {
            let (link, options) = (link.clone(), options.clone());
            move || lifecycle_loop(&link, &options)
        }),
    ];
    if spawned.iter().any(Option::is_none) {
        link.fail(Exit::Internal);
    }

    let end = wait_end(&link);
    // First, before anything that could wait (a log line on a stderr main
    // stopped draining, a callback, the teardown): the process ends within
    // `after` whatever its state (0007, "Startup and shutdown"). Never
    // disarmed.
    if let Some(after) = options.exit_watchdog {
        let link = link.clone();
        drop(Watchdog::arm_with(after, move || link.watchdog_exit()));
    }
    log_end(end);
    wait_callback(&link);
    service.end(&conn, end);
    link.close();
    // The writer writes what is still queued (the teardown's replies, a
    // refused handshake's), briefly.
    wait_writer(&link, FINAL_FLUSH);
    link.result()
}

fn spawn(name: &'static str, f: impl FnOnce() + Send + 'static) -> Option<()> {
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || with_kind(TaskKind::named(name), f))
        .ok()
        .map(drop)
}

fn wait_end(link: &Link) -> End {
    let mut state = link.lock();
    loop {
        if let Some(end) = state.end {
            return end;
        }
        state = wait(&link.ended, state);
    }
}

/// Waits for the service callback in progress, if any: none starts after
/// the end. Unbounded but for the exit watchdog, armed before.
fn wait_callback(link: &Link) {
    let mut state = link.lock();
    while state.dispatching {
        state = wait(&link.ended, state);
    }
}

fn wait_writer(link: &Link, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut state = link.lock();
    while !state.writer_done {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return;
        };
        state = wait_timeout(&link.ended, state, left);
    }
}

fn log_end(end: End) {
    let fields = match end {
        End::Protocol(category) => serde_json::json!({ "end": "protocol", "category": category }),
        End::Fatal(exit) => serde_json::json!({ "end": "fatal", "exit": exit.code() }),
        other => serde_json::json!({ "end": other.name() }),
    };
    match end {
        End::Eof | End::Shutdown | End::ParentGone => {
            crate::log::info("the connection ended", fields);
        }
        End::WriterStall => crate::log::error("main is not reading replies", fields),
        _ => crate::log::error("the connection ended", fields),
    }
}

// ---- the stdin pump ------------------------------------------------------

fn pump_loop(link: &Link, mut input: impl Read) {
    let mut buffer = vec![0u8; 64 << 10];
    loop {
        // Only this thread adds to the queue, so a read of at most what is
        // left of its allowance keeps it within 256 KiB.
        let room = {
            let mut state = link.lock();
            while state.input_bytes >= PUMPED && state.end.is_none() {
                state = wait(&link.pump, state);
            }
            if state.end.is_some() {
                return;
            }
            PUMPED - state.input_bytes
        };
        // `room` is at least 1, so an empty read still means EOF.
        let limit = room.min(buffer.len());
        let read = match input.read(buffer.get_mut(..limit).unwrap_or_default()) {
            Ok(0) => None,
            Ok(read) => Some(read),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => None,
        };
        {
            let mut state = link.lock();
            match read.and_then(|read| buffer.get(..read)) {
                Some(bytes) => {
                    state.input.push_back(bytes.to_vec());
                    state.input_bytes += bytes.len();
                }
                None => state.input_end = true,
            }
        }
        link.reader.notify_one();
        if read.is_none() {
            return;
        }
    }
}

// ---- the reader ----------------------------------------------------------

/// A message envelope from main: `{ type, id, method, params }`; a
/// `context` and other members are ignored.
#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(rename = "type", borrow)]
    kind: Cow<'a, str>,
    id: Option<u64>,
    #[serde(default, borrow)]
    method: Option<Cow<'a, str>>,
    #[serde(default, borrow)]
    params: Option<&'a RawValue>,
}

fn envelope(frame: &Frame) -> Result<Envelope<'_>, End> {
    let text = std::str::from_utf8(&frame.payload).map_err(|_| End::Protocol("invalid_utf8"))?;
    if !text.trim_start().starts_with('{') {
        return Err(End::Protocol("invalid_message"));
    }
    serde_json::from_str(text).map_err(|_| End::Protocol("invalid_message"))
}

fn valid_id(id: Option<u64>) -> Result<u64, End> {
    check_id(id.ok_or(End::Protocol("invalid_message"))?).map_err(|_| End::Protocol("bad_id"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Request,
    Cancel,
    Event,
    Response,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Hello,
    Shutdown,
    Other,
}

/// A request waiting for the connection to hold fewer than its allowance.
struct Parked {
    id: u64,
    frame: Frame,
    /// Main cancelled it while it waited: `cancelled` is its one reply.
    cancelled: bool,
}

/// What [`Reader::wait_for_room`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Room {
    Free,
    Ended,
    /// stdin's EOF was seen.
    Eof,
}

/// What [`Reader::admit`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admitted {
    Yes,
    /// The connection holds its allowance: park it.
    Full,
    /// The connection ended: drop it.
    Ended,
}

struct Reader<'a> {
    link: &'a Link,
    conn: &'a Connection,
    service: &'a dyn Service,
    options: &'a Options,
    hello_deadline: Instant,
    decoder: Decoder,
    parked: VecDeque<Parked>,
    parked_bytes: usize,
    /// The highest request ID read.
    highest: u64,
    /// The highest request ID admitted: requests above it, up to `highest`,
    /// are parked.
    admitted: u64,
    hello_seen: bool,
}

impl<'a> Reader<'a> {
    fn new(
        link: &'a Link,
        conn: &'a Connection,
        service: &'a dyn Service,
        options: &'a Options,
    ) -> Self {
        Reader {
            link,
            conn,
            service,
            options,
            hello_deadline: options.started + options.hello_timeout,
            // A two-way connection takes main's bodies too (0014, COL-3).
            decoder: Decoder::with_kinds(Kinds::service(if link.two_way {
                Side::Both
            } else {
                Side::Sender
            })),
            parked: VecDeque::new(),
            parked_bytes: 0,
            highest: 0,
            admitted: 0,
            hello_seen: false,
        }
    }

    fn run(mut self) {
        if let Err(end) = self.read() {
            self.link.end(end);
        }
    }

    fn read(&mut self) -> Result<(), End> {
        while let Some(chunk) = self.next_input()? {
            let mut rest = chunk.as_slice();
            while !rest.is_empty() {
                let consumed = self
                    .decoder
                    .push(rest)
                    .map_err(|e| End::Protocol(e.category()))?;
                rest = rest.get(consumed..).unwrap_or_default();
                while let Some(frame) = self.decoder.pop() {
                    self.handle(frame)?;
                    // Nothing more is handled once the connection has
                    // ended, whatever else this read brought.
                    if self.ended() {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

    fn ended(&self) -> bool {
        self.link.lock().end.is_some()
    }

    /// The next bytes from stdin, or `None` once the connection has ended.
    /// While it waits, it admits parked requests as the writer frees room.
    fn next_input(&mut self) -> Result<Option<Vec<u8>>, End> {
        loop {
            {
                let mut state = self.link.lock();
                loop {
                    if state.end.is_some() {
                        return Ok(None);
                    }
                    if !self.parked.is_empty()
                        && state.streams.sender().live() < self.link.max_requests
                    {
                        break;
                    }
                    if let Some(chunk) = state.input.pop_front() {
                        state.input_bytes -= chunk.len();
                        drop(state);
                        self.link.pump.notify_one();
                        return Ok(Some(chunk));
                    }
                    if state.input_end {
                        return Err(End::Eof);
                    }
                    state = wait(&self.link.reader, state);
                }
            }
            self.admit_parked()?;
        }
    }

    fn handle(&mut self, frame: Frame) -> Result<(), End> {
        if frame.kind != KIND_JSON {
            return self.stream_frame(&frame);
        }
        let (kind, id, method) = {
            let envelope = envelope(&frame)?;
            let kind = match envelope.kind.as_ref() {
                "request" => Kind::Request,
                "cancel" => Kind::Cancel,
                "event" => Kind::Event,
                "response" => Kind::Response,
                _ => Kind::Other,
            };
            let method = envelope
                .method
                .as_deref()
                .map(|method| self.classify(method));
            (kind, envelope.id, method)
        };
        // Every message waits for the handshake.
        if !self.hello_seen && !(kind == Kind::Request && method == Some(Method::Hello)) {
            return Err(End::Protocol("not_hello_first"));
        }
        match kind {
            Kind::Request => {
                let method = method.ok_or(End::Protocol("invalid_message"))?;
                self.request(frame, valid_id(id)?, method)
            }
            Kind::Cancel => self.cancel(valid_id(id)?),
            Kind::Event => {
                crate::log::warn("ignoring an event from main", serde_json::json!({}));
                Ok(())
            }
            // One of the service's own requests, on a two-way connection.
            Kind::Response if self.link.two_way => self.response(&frame),
            // The service makes no requests: a response answers nothing.
            Kind::Response => Err(End::Protocol("unsolicited_response")),
            Kind::Other => Err(End::Protocol("invalid_message")),
        }
    }

    fn classify(&self, method: &str) -> Method {
        match method
            .strip_prefix(self.options.service)
            .and_then(|rest| rest.strip_prefix('.'))
        {
            Some("hello") => Method::Hello,
            Some("shutdown") => Method::Shutdown,
            _ => Method::Other,
        }
    }

    fn request(&mut self, frame: Frame, id: u64, method: Method) -> Result<(), End> {
        if id <= self.highest {
            let highest = self.highest;
            return Err(End::Protocol(
                StreamError::RequestOrder { id, highest }.category(),
            ));
        }
        self.highest = id;
        match method {
            Method::Hello if !self.hello_seen => {
                self.hello_seen = true;
                self.hello(id, &frame)
            }
            Method::Hello => Err(End::Protocol("second_hello")),
            Method::Shutdown => Err(End::Shutdown),
            Method::Other => {
                if self.parked.is_empty() && self.admit(id, &frame, false)? != Admitted::Full {
                    return Ok(());
                }
                self.park(id, frame)
            }
        }
    }

    /// Admits request `id` to the stream state machine and hands it to the
    /// service, unless the connection holds its allowance. A request
    /// cancelled while parked gets its `cancelled` reply instead: the
    /// service never sees it.
    fn admit(&mut self, id: u64, frame: &Frame, cancelled: bool) -> Result<Admitted, End> {
        let envelope = envelope(frame)?;
        {
            let mut state = self.link.lock();
            if state.end.is_some() {
                return Ok(Admitted::Ended);
            }
            if state.streams.sender().live() >= self.link.max_requests {
                return Ok(Admitted::Full);
            }
            state
                .streams
                .request(id)
                .map_err(|e| End::Protocol(e.category()))?;
            self.admitted = id;
            if cancelled {
                let _ = state.streams.cancel(id);
                drop(state);
                self.link.writer.notify_one();
                return Ok(Admitted::Yes);
            }
            state.dispatching = true;
        }
        let method = envelope.method.as_deref().unwrap_or_default();
        self.service.request(
            self.conn,
            Request {
                id,
                method,
                params: envelope.params,
            },
        );
        self.leave();
        Ok(Admitted::Yes)
    }

    /// A service callback returned.
    fn leave(&self) {
        self.link.lock().dispatching = false;
        self.link.ended.notify_all();
    }

    /// Parks a request until the connection holds fewer than its allowance.
    /// With the reader's budget full, it waits for room first, admitting
    /// parked requests as the writer frees it: then nothing more is read.
    fn park(&mut self, id: u64, frame: Frame) -> Result<(), End> {
        let len = frame.payload.len();
        while self.parked.len() >= self.options.parked_frames.max(1)
            || (!self.parked.is_empty() && self.parked_bytes + len > self.options.parked_bytes)
        {
            match self.wait_for_room() {
                Room::Free => self.admit_parked()?,
                Room::Ended => return Ok(()),
                Room::Eof => return Err(End::Eof),
            }
        }
        self.parked_bytes += len;
        self.parked.push_back(Parked {
            id,
            frame,
            cancelled: false,
        });
        Ok(())
    }

    /// Waits until the connection holds fewer requests than its allowance,
    /// or it ends, or stdin's EOF has been seen: EOF ends the connection
    /// whatever input and parked requests are left, without waiting for the
    /// writer (0007, "Progress under backpressure").
    fn wait_for_room(&self) -> Room {
        let mut state = self.link.lock();
        loop {
            if state.end.is_some() {
                return Room::Ended;
            }
            if state.streams.sender().live() < self.link.max_requests {
                return Room::Free;
            }
            if state.input_end {
                return Room::Eof;
            }
            state = wait(&self.link.reader, state);
        }
    }

    /// Admits parked requests, in order, while there is room.
    fn admit_parked(&mut self) -> Result<(), End> {
        while let Some(parked) = self.parked.pop_front() {
            match self.admit(parked.id, &parked.frame, parked.cancelled)? {
                Admitted::Yes => self.parked_bytes -= parked.frame.payload.len(),
                Admitted::Full => {
                    self.parked.push_front(parked);
                    break;
                }
                Admitted::Ended => break,
            }
        }
        Ok(())
    }

    fn cancel(&mut self, id: u64) -> Result<(), End> {
        if id > self.admitted {
            // Parked: its `cancelled` reply goes out once it is admitted.
            // Above every request read: late.
            if let Some(parked) = self.parked.iter_mut().find(|parked| parked.id == id) {
                parked.cancelled = true;
            }
            return Ok(());
        }
        let (cancelled, wakers) = {
            let mut state = self.link.lock();
            if state.end.is_some() {
                return Ok(());
            }
            // Its work claimed its commit point: nothing is queued, and
            // the service answers it ([`Connection::commit`]).
            let committed =
                state.committed.contains(&id) && state.streams.sender().is_unanswered(id);
            let cancelled = committed
                || state
                    .streams
                    .cancel(id)
                    .map_err(|e| End::Protocol(e.category()))?
                    == Cancel::Cancelled;
            state.dispatching = cancelled;
            if cancelled {
                state.cancelling = Some(id);
            }
            // A purge made room under the writer's cap.
            let wakers = if cancelled {
                std::mem::take(&mut state.waiters)
            } else {
                Vec::new()
            };
            (cancelled, wakers)
        };
        self.link.writer.notify_one();
        wake(wakers);
        if cancelled {
            self.service.cancel(self.conn, id);
            // The request may be settled now: wake those waiting for it.
            let waiters = {
                let mut state = self.link.lock();
                state.cancelling = None;
                std::mem::take(&mut state.waiters)
            };
            self.leave();
            wake(waiters);
        }
        Ok(())
    }

    /// A stream frame from main: credit for a body the service sends, or,
    /// on a two-way connection, data, end or abort of one main sends in
    /// answer to the service's own request ([`ask`]). A one-way
    /// connection's decoder refused those three at their header.
    fn stream_frame(&mut self, frame: &Frame) -> Result<(), End> {
        if !self.hello_seen {
            return Err(End::Protocol("not_hello_first"));
        }
        let frame = StreamFrame::from_frame(frame).map_err(|e| End::Protocol(e.category()))?;
        let StreamFrame::Credit { id, .. } = frame else {
            return self.inbound(frame);
        };
        if id > self.admitted && id <= self.highest {
            // A parked request: nothing of it was sent.
            return Err(End::Protocol(StreamError::Overgrant(id).category()));
        }
        let wakers = {
            let mut state = self.link.lock();
            if state.end.is_some() {
                return Ok(());
            }
            match state
                .streams
                .receive(frame)
                .map_err(|e| End::Protocol(e.category()))?
            {
                Received::Credited(Credited::Taken(_)) => std::mem::take(&mut state.waiters),
                // Credit arrives only through the sender.
                Received::Credited(Credited::Late) | Received::Arrived(_) => Vec::new(),
            }
        };
        wake(wakers);
        Ok(())
    }

    fn hello(&mut self, id: u64, frame: &Frame) -> Result<(), End> {
        // Past its deadline, the handshake is refused here, whether or not
        // the lifecycle thread has looked yet.
        if Instant::now() >= self.hello_deadline {
            return Err(End::HelloTimeout);
        }
        let hello = envelope(frame)?
            .params
            .filter(|raw| raw.get().trim_start().starts_with('{'))
            .and_then(|raw| serde_json::from_str::<Hello>(raw.get()).ok())
            .ok_or(End::Protocol("bad_hello"))?;
        {
            let mut state = self.link.lock();
            if state.end.is_some() {
                return Ok(());
            }
            state
                .streams
                .request(id)
                .map_err(|e| End::Protocol(e.category()))?;
            state.hello_id = Some(id);
        }
        self.admitted = id;
        let mismatch = if hello.protocol != self.options.protocol {
            Some(format!(
                "protocol {} is not this service's {}",
                hello.protocol, self.options.protocol
            ))
        } else if !hello.frames.iter().any(|kind| kind == "stream") {
            Some("main must take stream frames".to_owned())
        } else {
            None
        };
        if let Some(message) = mismatch {
            // The reply goes out before the process exits: a packaging bug
            // that main must see.
            self.refuse_hello(id, &ErrorBody::new(ErrorCode::ProtocolMismatch, message));
            return Err(End::Protocol("protocol_mismatch"));
        }
        {
            let mut state = self.link.lock();
            if state.end.is_some() {
                return Ok(());
            }
            state.dispatching = true;
        }
        let answer = self.service.hello(&hello);
        self.leave();
        let mut members = match answer {
            Ok(members) => members,
            Err(error) => {
                self.refuse_hello(id, &error);
                return Err(End::Protocol("hello_refused"));
            }
        };
        // The protocol is the connection's to state, whatever the service's
        // members say.
        members.insert("protocol".into(), self.options.protocol.into());
        let mut json = Vec::new();
        write_result(&mut json, id, &members).map_err(|_| End::Fatal(Exit::Internal))?;
        let mut state = self.link.lock();
        if state.end.is_some() {
            return Ok(());
        }
        // The deadline and `hello_done` under the lock the lifecycle thread
        // checks them under: the handshake completes in time, or not at all.
        if Instant::now() >= self.hello_deadline {
            return Err(End::HelloTimeout);
        }
        state
            .streams
            .sender_mut()
            .reply(id, json)
            .map_err(|_| End::Fatal(Exit::Internal))?;
        state.hello_done = true;
        drop(state);
        self.link.writer.notify_one();
        Ok(())
    }

    fn refuse_hello(&self, id: u64, error: &ErrorBody) {
        let mut json = Vec::new();
        if write_error(&mut json, id, error).is_ok() {
            let mut state = self.link.lock();
            if state.end.is_none() {
                let _ = state.streams.sender_mut().reply(id, json);
            }
        }
        self.link.writer.notify_one();
    }
}

// ---- the writer ----------------------------------------------------------

/// A frame the writer claimed.
struct Claimed {
    /// Producers to wake: its body bytes left the queue.
    wakers: Vec<Waker>,
    /// It ended a request: the reader may admit a parked one.
    freed: bool,
    /// A message too large for the writer's buffer, written as it was
    /// queued, after the frame header in the buffer.
    payload: Option<Vec<u8>>,
    /// What its head held, released once the frame is written and flushed
    /// and its buffers freed: the head, or what replaced it.
    charge: Option<Charge>,
}

/// The request a frame belongs to.
fn written_id(written: Written) -> u64 {
    match written {
        Written::Head { id }
        | Written::Reply { id }
        | Written::Cancelled { id }
        | Written::Data { id, .. }
        | Written::End { id }
        | Written::Abort { id, .. } => id,
    }
}

fn write_loop(link: &Link, mut output: impl Write) {
    let mut frame = Vec::with_capacity(MAX_DATA + 64);
    while let Some(Claimed {
        wakers,
        freed,
        payload,
        charge,
    }) = claim(link, &mut frame)
    {
        if freed {
            link.reader.notify_one();
        }
        wake(wakers);
        // Outside the lock: a write may block for as long as main doesn't
        // read, and nothing else waits for it.
        let written = output
            .write_all(&frame)
            .and_then(|()| {
                payload
                    .as_ref()
                    .map_or(Ok(()), |json| output.write_all(json))
            })
            .and_then(|()| output.flush());
        frame.clear();
        // A 1 MiB event's buffer isn't kept.
        frame.shrink_to(MAX_DATA + 64);
        // What paid for the frame's buffers goes once they have.
        drop(payload);
        drop(charge);
        if written.is_err() {
            return writer_failed(link);
        }
        let mut state = link.lock();
        state.writing = false;
        state.progress = Instant::now();
        // An event waited for, written and flushed: its sender sees it.
        if let Some(ticket) = state.writing_ticket.take() {
            state.written_ticket = ticket;
            link.written.notify_all();
        }
        // A terminal written and flushed: its request is settled now.
        let settled = if state.writing_terminal.take().is_some() {
            std::mem::take(&mut state.waiters)
        } else {
            Vec::new()
        };
        drop(state);
        wake(settled);
    }
}

/// A claimed frame that is all in the writer's buffer, and ends nothing.
fn claimed_alone(state: &mut State) -> Claimed {
    state.writing = true;
    state.progress = Instant::now();
    Claimed {
        wakers: Vec::new(),
        freed: false,
        payload: None,
        charge: None,
    }
}

/// Claims the next frame into `frame`, waiting for one: an event, else the
/// service's own request or cancel once the handshake's reply is written,
/// else the stream state machine's next (credit owed to main first). `None`
/// once nothing more will be written: the connection closed (or its stream
/// state failed) with nothing queued.
fn claim(link: &Link, frame: &mut Vec<u8>) -> Option<Claimed> {
    let mut state = link.lock();
    loop {
        let failed = state.streams.failed().is_some();
        if !failed {
            if let Some(event) = state.events.pop_front() {
                if frame::encode_json(&event.json, frame).is_ok() {
                    state.writing_ticket = event.ticket;
                    return Some(claimed_alone(&mut state));
                }
                frame.clear();
                continue;
            }
            // Nothing of the service's own goes before the handshake's
            // reply: once it is claimed, it is no longer live.
            let greeted = state.hello_done
                && state
                    .hello_id
                    .is_some_and(|id| !state.streams.sender().is_live(id));
            if greeted && let Some(outgoing) = state.outbound.pop_front() {
                if frame::encode_json(outgoing.json(), frame).is_ok() {
                    return Some(claimed_alone(&mut state));
                }
                frame.clear();
                continue;
            }
            let live = state.streams.sender().live();
            if let Some((wrote, json)) = state.streams.next_frame_owned(frame) {
                let written = match wrote {
                    // Credit owed for one of main's bodies: control.
                    Wrote::Credit { .. } => return Some(claimed_alone(&mut state)),
                    Wrote::Sent(written) => written,
                };
                let freed = state.streams.sender().live() < live;
                // A terminal: its request is settled once it is written
                // and flushed, not now ([`Connection::settled`]).
                state.writing_terminal = freed.then(|| written_id(written));
                // Data made room for producers.
                let wakers = if matches!(written, Written::Data { .. }) {
                    std::mem::take(&mut state.waiters)
                } else {
                    Vec::new()
                };
                // A head, or the reply that took its place.
                let charge = match written {
                    Written::Head { id } | Written::Reply { id } | Written::Cancelled { id } => {
                        state.charges.remove(&id)
                    }
                    _ => None,
                };
                // A message that fits the buffer as it is joins its header
                // there; a larger one is written from its own buffer, so
                // the writer's never grows for it.
                let payload = match json {
                    Some(json) if json.len() <= frame.capacity() - frame.len() => {
                        frame.extend_from_slice(&json);
                        None
                    }
                    json => json,
                };
                state.writing = true;
                state.progress = Instant::now();
                return Some(Claimed {
                    wakers,
                    freed,
                    payload,
                    charge,
                });
            }
        }
        if state.closed || failed {
            state.writer_done = true;
            let charges = std::mem::take(&mut state.charges);
            drop(state);
            drop(charges);
            link.ended.notify_all();
            link.written.notify_all();
            return None;
        }
        state = wait(&link.writer, state);
    }
}

/// A failed write to stdout: main is gone (0007: the guaranteed path, as
/// stdin EOF is).
///
/// Nothing more is written, so nothing more is queued ([`Connection`]'s
/// calls are `Closed` once the writer is done), and what is queued goes:
/// the stream state, with every queued head's and reply's JSON and every
/// queued body byte, is taken out of the connection and freed, and only
/// then what the heads held, so a reservation is never free while the
/// buffer it pays for still is. Both outside the lock.
fn writer_failed(link: &Link) {
    link.end(End::Eof);
    let mut state = link.lock();
    state.writing = false;
    state.writer_done = true;
    state.writing_ticket = None;
    let abandoned = std::mem::replace(&mut state.streams, Duplex::service(0));
    let events = std::mem::take(&mut state.events);
    let outbound = std::mem::take(&mut state.outbound);
    let charges = std::mem::take(&mut state.charges);
    drop(state);
    drop(abandoned);
    drop(events);
    drop(outbound);
    #[cfg(test)]
    link.abandoned_freed.store(true, Ordering::SeqCst);
    drop(charges);
    link.ended.notify_all();
}

// ---- the lifecycle thread ------------------------------------------------

fn lifecycle_loop(link: &Link, options: &Options) {
    let hello_deadline = options.started + options.hello_timeout;
    let mut next_parent_check = Instant::now() + options.parent_poll;
    let tick = Duration::from_millis(100);
    let mut state = link.lock();
    loop {
        if state.end.is_some() {
            return;
        }
        let now = Instant::now();
        if !state.hello_done && now >= hello_deadline {
            drop(state);
            return link.end(End::HelloTimeout);
        }
        if state.writing && now.duration_since(state.progress) >= options.writer_stall {
            drop(state);
            return link.end(End::WriterStall);
        }
        if now >= next_parent_check {
            drop(state);
            if !hardening::parent_alive(options.parent_pid) {
                return link.end(End::ParentGone);
            }
            next_parent_check = now + options.parent_poll;
            state = link.lock();
            continue;
        }
        // The service's requests whose deadline passed: their cancels go to
        // main, and their askers wake.
        if let Some(expired) = ask::expire_due(&mut state, now) {
            drop(state);
            link.writer.notify_one();
            wake(expired);
            state = link.lock();
            continue;
        }
        // Until the next deadline, if it comes before the tick; a new
        // request wakes this thread to look again.
        let wait = state
            .deadlines
            .first()
            .map_or(tick, |(at, _)| at.saturating_duration_since(now).min(tick));
        state = wait_timeout(&link.ended, state, wait.max(Duration::from_millis(1)));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// The JSON messages `link`'s writer writes once the connection has
    /// closed, in order.
    pub(super) fn written(link: &Link) -> Vec<serde_json::Value> {
        link.close();
        let mut out = Vec::new();
        write_loop(link, &mut out);
        let mut messages = Vec::new();
        let mut rest = &out[..];
        while rest.len() >= 5 {
            let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            assert_eq!(rest[4], 1, "a JSON frame");
            messages.push(serde_json::from_slice(&rest[5..4 + len]).unwrap());
            rest = &rest[4 + len..];
        }
        assert!(rest.is_empty());
        messages
    }

    /// 0008, "Progress": an event about a request is queued only while
    /// nothing of the request is, through main's cancel once its work
    /// claimed its commit point; each is written before the request's
    /// answer, and none after it. The connection's bound applies as to any
    /// event.
    #[test]
    fn an_event_about_a_request_is_queued_only_before_its_answer() {
        let mut options = Options::new("t", 1, Instant::now());
        options.exit_watchdog = None;
        options.max_events = 3;
        let link = Arc::new(Link::new(&options));
        let conn = Connection { link: link.clone() };
        // Not held: nothing of it may be said.
        assert_eq!(
            conn.event_for(1, "t.progress", &0),
            Err(EventError::Answered)
        );
        for id in 1..=3 {
            link.lock().streams.request(id).unwrap();
        }
        assert_eq!(conn.event_for(1, "t.progress", &1), Ok(()));
        // Its commit point claimed, main's cancel queues nothing for it
        // (the reader's `cancel`): it is still unanswered.
        assert!(conn.commit(1));
        assert_eq!(conn.event_for(1, "t.progress", &2), Ok(()));
        // Another, cancelled before any claim: `cancelled` is queued.
        assert_eq!(
            link.lock().streams.cancel(2).unwrap(),
            fc_protocol::stream::Cancel::Cancelled
        );
        assert_eq!(
            conn.event_for(2, "t.progress", &3),
            Err(EventError::Answered)
        );
        // A head is an answer too.
        conn.head(3, &"head", false).unwrap();
        assert_eq!(
            conn.event_for(3, "t.progress", &4),
            Err(EventError::Answered)
        );
        conn.reply(1, &"done").unwrap();
        assert_eq!(
            conn.event_for(1, "t.progress", &5),
            Err(EventError::Answered)
        );
        // The bound: two of three wait, and one more fills it.
        assert_eq!(conn.event("t.other", &6), Ok(()));
        assert_eq!(conn.event("t.other", &7), Err(EventError::Full));
        link.lock().streams.request(4).unwrap();
        assert_eq!(conn.event_for(4, "t.progress", &8), Err(EventError::Full));

        let messages = written(&link);
        // The events first, in their order, then the answers: no event
        // after its request's answer.
        let events: Vec<&serde_json::Value> = messages[..3].iter().map(|m| &m["data"]).collect();
        assert!(
            messages[..3].iter().all(|m| m["type"] == "event"),
            "{messages:?}"
        );
        assert_eq!(
            events,
            [
                &serde_json::json!(1),
                &serde_json::json!(2),
                &serde_json::json!(6)
            ]
        );
        assert!(
            messages[3..].iter().all(|m| m["type"] != "event"),
            "{messages:?}"
        );
        let mut answered: Vec<u64> = messages[3..]
            .iter()
            .map(|m| m["id"].as_u64().unwrap())
            .collect();
        answered.sort_unstable();
        assert_eq!(answered, [1, 2, 3]);
        // After the close, nothing more.
        assert_eq!(conn.event_for(4, "t.progress", &9), Err(EventError::Closed));
    }

    /// 0014, COL-3: nothing of the service's own goes before the
    /// handshake's reply, though events go first otherwise; then its
    /// requests and cancels in their order, ahead of the streams, with the
    /// credit it owes main first among those.
    #[test]
    fn the_services_requests_wait_for_the_handshakes_reply() {
        let mut options = Options::new("t", 1, Instant::now());
        options.exit_watchdog = None;
        options.two_way = true;
        let link = Arc::new(Link::new(&options));
        let conn = Connection { link: link.clone() };
        {
            let mut state = link.lock();
            state.streams.request(1).unwrap();
            state.hello_id = Some(1);
        }
        let asked = conn.ask("t.first", &[1], None).unwrap();
        assert_eq!(asked.id(), 1);
        drop(asked);
        {
            let mut state = link.lock();
            let mut json = Vec::new();
            write_result(&mut json, 1, &"hello").unwrap();
            state.streams.sender_mut().reply(1, json).unwrap();
            state.hello_done = true;
            state.streams.request(2).unwrap();
        }
        conn.reply(2, &"two").unwrap();
        let messages = written(&link);
        assert_eq!(
            messages,
            [
                serde_json::json!({ "type": "response", "id": 1, "result": "hello" }),
                serde_json::json!({ "type": "request", "id": 1, "method": "t.first", "params": [1] }),
                serde_json::json!({ "type": "cancel", "id": 1 }),
                serde_json::json!({ "type": "response", "id": 2, "result": "two" }),
            ]
        );
    }

    /// Review of #141, round 2: when the writer fails, every queued head's
    /// JSON is freed before what its head held: a charge dropped while its
    /// buffer still lived would let others spend those bytes again. A
    /// small head, then a 100,046-byte one, and the first write fails.
    #[test]
    fn a_failed_writer_frees_queued_heads_before_their_charges() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        /// Records, as it is dropped, whether the queued buffers were freed.
        struct Witness(Arc<Link>, Arc<Mutex<Vec<bool>>>);
        impl Drop for Witness {
            fn drop(&mut self) {
                let freed = self.0.abandoned_freed.load(Ordering::SeqCst);
                self.1.lock().unwrap().push(freed);
            }
        }
        let mut options = Options::new("t", 1, Instant::now());
        options.exit_watchdog = None;
        let link = Arc::new(Link::new(&options));
        let conn = Connection { link: link.clone() };
        let seen = Arc::new(Mutex::new(Vec::new()));
        for (id, pad) in [(1, "small".to_owned()), (2, "x".repeat(100_000))] {
            link.lock().streams.request(id).unwrap();
            let head = serde_json::json!({ "pad": pad });
            let charge: Charge = Box::new(Witness(link.clone(), seen.clone()));
            let late = ErrorBody::new(ErrorCode::Deadline, "late");
            let deadline = Instant::now() + Duration::from_secs(60);
            assert_eq!(
                conn.head_by(id, &head, false, deadline, &late, Some(charge)),
                Ok(Headed::Queued)
            );
        }
        // Its JSON is 100,046 bytes, with its frame header 100,051.
        assert_eq!(
            head_len(2, &serde_json::json!({ "pad": "x".repeat(100_000) })),
            Ok(100_051)
        );
        write_loop(&link, Broken);
        // The first head's charge went with its own frame, once written
        // (here: failed); the second's only after the queue was freed.
        assert_eq!(*seen.lock().unwrap(), [false, true]);
        let mut frame = Vec::new();
        let state = link.lock();
        assert_eq!(
            (state.streams.sender().live(), state.streams.sender().held()),
            (0, 0)
        );
        drop(state);
        assert!(link.lock().streams.next_frame_owned(&mut frame).is_none());
        // And nothing more is queued.
        assert_eq!(conn.reply(3, &()), Err(SendError::Closed));
    }

    /// Review of #141: a head's buffer is exactly its length, which
    /// `head_len` counts with its frame header, however large it is.
    #[test]
    fn a_head_is_encoded_in_a_buffer_of_its_length() {
        for pad in ["", "small", &"\u{800}".repeat(40_000)] {
            let head = serde_json::json!({ "status": 200, "pad": pad });
            let json = encode_result(7, &head).unwrap();
            assert_eq!(json.capacity(), json.len());
            assert_eq!(head_len(7, &head).unwrap(), json.len() + JSON_HEADER);
            let mut expected = Vec::new();
            write_result(&mut expected, 7, &head).unwrap();
            assert_eq!(json, expected);
        }
    }
}
