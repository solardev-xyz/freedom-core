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
//! - **The writer** claims one frame at a time from `fc-protocol`'s stream
//!   [`Sender`] (events first, then control frames, then the streams
//!   round-robin) and writes it before it claims the next. The claim is the
//!   commit: a head opens its stream, a reply or terminal ends its request.
//!   Frames behind the one being written stay queued, so a cancel still
//!   drops an unwritten head (`cancelled` is then the only reply) or beats
//!   an unwritten terminal. The writer never holds the connection's lock
//!   while it writes, and the body bytes it holds count toward its 16 MiB
//!   cap.
//! - **The lifecycle thread** enforces the handshake's deadline, polls the
//!   parent every 2 s, and watches for the writer stall.
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
use std::collections::{HashMap, VecDeque};
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
    Abort, Cancel, Credited, MAX_DATA, SendError, Sender, Settled, Side, StreamError, StreamFrame,
    WRITER_DATA_CAP, Written,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::exit::Exit;
use crate::hardening;
use crate::panic::{TaskKind, with_kind};
use crate::watchdog::Watchdog;

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
    /// A failed writer has freed what was queued.
    #[cfg(test)]
    abandoned_freed: AtomicBool,
}

struct State {
    sender: Sender,
    events: VecDeque<Vec<u8>>,
    max_events: usize,
    hello_done: bool,
    end: Option<End>,
    /// [`Service::end`] has returned: nothing more may be queued.
    closed: bool,
    /// The reader is in a service callback.
    dispatching: bool,
    /// The request whose accepted cancel the reader is handing to the
    /// service: it isn't settled until [`Service::cancel`] returns.
    cancelling: Option<u64>,
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

impl Link {
    fn new(options: &Options) -> Link {
        Link {
            state: Mutex::new(State {
                // The writer holds at most one data frame outside the
                // queue: the cap covers both.
                sender: Sender::with_data_cap(options.data_cap.saturating_sub(MAX_DATA)),
                events: VecDeque::new(),
                max_events: options.max_events,
                hello_done: false,
                end: None,
                closed: false,
                dispatching: false,
                cancelling: None,
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
            ended: Condvar::new(),
            reader: Condvar::new(),
            pump: Condvar::new(),
            result: AtomicU8::new(Exit::Ok.code()),
            torn_down: AtomicBool::new(false),
            max_requests: options.max_requests.max(1),
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
        self.ended.notify_all();
        self.reader.notify_all();
        self.pump.notify_all();
    }

    /// Ends the connection, once: the first end wins.
    fn end(&self, end: End) {
        let wakers = {
            let mut state = self.lock();
            if state.end.is_some() {
                return;
            }
            state.end = Some(end);
            self.result.store(end.exit().code(), Ordering::SeqCst);
            std::mem::take(&mut state.waiters)
        };
        self.notify_all();
        wake(wakers);
    }

    /// The service's fatal error: it ends the connection, or, once the
    /// connection has ended, sets the process's result. A teardown's
    /// failure replaces the end's code; 70, once set, stays.
    fn fail(&self, exit: Exit) {
        let wakers = {
            let mut state = self.lock();
            if state.end.is_none() {
                state.end = Some(End::Fatal(exit));
                self.result.store(exit.code(), Ordering::SeqCst);
                std::mem::take(&mut state.waiters)
            } else {
                if exit != Exit::Ok && self.result.load(Ordering::SeqCst) != Exit::Internal.code() {
                    self.result.store(exit.code(), Ordering::SeqCst);
                }
                Vec::new()
            }
        };
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
        self.queue(Need::Owed, |state| (state.sender.reply(id, json), false))
    }

    /// Answers request `id` with `error`: its one reply.
    pub fn reply_error(&self, id: u64, error: &ErrorBody) -> Result<(), SendError> {
        let mut json = Vec::new();
        write_error(&mut json, id, error).map_err(|_| SendError::TooLarge)?;
        self.queue(Need::Owed, |state| (state.sender.reply(id, json), false))
    }

    /// Answers request `id` with `result`, as [`Connection::reply`] does,
    /// only if it is queued before `deadline`: from `deadline` on, `late`
    /// is queued as its one reply instead, unless something answered it
    /// already. The check and the queueing are one step under the
    /// connection's lock, as for [`Connection::head_by`]: however late its
    /// producer runs, the reply is never queued after its deadline, and one
    /// queued in time stands.
    pub fn reply_by<T: Serialize>(
        &self,
        id: u64,
        result: &T,
        deadline: Instant,
        late: &ErrorBody,
    ) -> Result<Headed, SendError> {
        let mut json = Vec::new();
        write_result(&mut json, id, result).map_err(|_| SendError::TooLarge)?;
        self.reply_json_by(id, json, deadline, late)
    }

    /// Answers request `id` with `error`, as [`Connection::reply_error`]
    /// does, only if it is queued before `deadline`: as
    /// [`Connection::reply_by`].
    pub fn reply_error_by(
        &self,
        id: u64,
        error: &ErrorBody,
        deadline: Instant,
        late: &ErrorBody,
    ) -> Result<Headed, SendError> {
        let mut json = Vec::new();
        write_error(&mut json, id, error).map_err(|_| SendError::TooLarge)?;
        self.reply_json_by(id, json, deadline, late)
    }

    fn reply_json_by(
        &self,
        id: u64,
        json: Vec<u8>,
        deadline: Instant,
        late: &ErrorBody,
    ) -> Result<Headed, SendError> {
        let mut late_json = Vec::new();
        write_error(&mut late_json, id, late).map_err(|_| SendError::TooLarge)?;
        self.queue(Need::Owed, move |state| {
            let queued = if Instant::now() < deadline {
                state.sender.reply(id, json).map(|()| Headed::Queued)
            } else {
                state.sender.reply(id, late_json).map(|()| Headed::Late)
            };
            (queued, false)
        })
    }

    /// Answers request `id` with a head, `result`. With `body`, it opens a
    /// stream once written; data may be pushed behind it now.
    pub fn head<T: Serialize>(&self, id: u64, result: &T, body: bool) -> Result<(), SendError> {
        let mut json = Vec::new();
        write_result(&mut json, id, result).map_err(|_| SendError::TooLarge)?;
        let need = if body { Need::Open } else { Need::Owed };
        self.queue(need, |state| (state.sender.head(id, json, body), false))
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
                state.sender.head(id, json, body).map(|()| Headed::Queued)
            } else {
                state.sender.reply(id, late_json).map(|()| Headed::Late)
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
        self.queue(Need::Open, |state| (state.sender.push(id, bytes), false))
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
        self.queue(Need::Owed, |state| (state.sender.finish(id), false))
    }

    /// Aborts stream `id`.
    pub fn abort(&self, id: u64, abort: &Abort) -> Result<(), SendError> {
        self.queue(Need::Owed, |state| {
            let result = state.sender.abort(id, abort);
            // Its purge made room under the writer's cap.
            let room = result.is_ok();
            (result, room)
        })
    }

    /// Settles request `id` with an outcome the service owes it, unless it
    /// is settled already (0007, "Panics"): `error` is its one reply if
    /// nothing of it was written (a queued head is dropped, as for a
    /// cancel), `abort` ends its stream if the stream is open. See
    /// [`Sender::settle`].
    pub fn settle(&self, id: u64, error: &ErrorBody, abort: &Abort) -> Result<Settled, SendError> {
        let mut json = Vec::new();
        write_error(&mut json, id, error).map_err(|_| SendError::TooLarge)?;
        self.queue(Need::Owed, |state| {
            let result = state.sender.settle(id, json, abort);
            // A purge made room under the writer's cap.
            let room = result.is_ok();
            (result, room)
        })
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
        state.events.push_back(json);
        drop(state);
        self.link.writer.notify_one();
        Ok(())
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
            live_requests: state.sender.live(),
            held_bytes: state.sender.held(),
            events: state.events.len(),
        }
    }
}

/// What a queued head holds until the writer has written it
/// ([`Connection::head_by`]): dropped then, outside the connection's lock.
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
        let held = state.sender.is_live(self.id) || state.writing_terminal == Some(self.id);
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
            match state.sender.push(this.id, rest) {
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
            decoder: Decoder::with_kinds(Kinds::service(Side::Sender)),
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
                    if !self.parked.is_empty() && state.sender.live() < self.link.max_requests {
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
            return self.credit(&frame);
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
            if state.sender.live() >= self.link.max_requests {
                return Ok(Admitted::Full);
            }
            state
                .sender
                .request(id)
                .map_err(|e| End::Protocol(e.category()))?;
            self.admitted = id;
            if cancelled {
                let _ = state.sender.cancel(id);
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
            if state.sender.live() < self.link.max_requests {
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
            let outcome = state
                .sender
                .cancel(id)
                .map_err(|e| End::Protocol(e.category()))?;
            let cancelled = outcome == Cancel::Cancelled;
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

    fn credit(&mut self, frame: &Frame) -> Result<(), End> {
        if !self.hello_seen {
            return Err(End::Protocol("not_hello_first"));
        }
        let frame = StreamFrame::from_frame(frame).map_err(|e| End::Protocol(e.category()))?;
        let id = frame.id();
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
                .sender
                .receive(frame)
                .map_err(|e| End::Protocol(e.category()))?
            {
                Credited::Taken(_) => std::mem::take(&mut state.waiters),
                Credited::Late => Vec::new(),
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
                .sender
                .request(id)
                .map_err(|e| End::Protocol(e.category()))?;
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
            .sender
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
                let _ = state.sender.reply(id, json);
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

/// Claims the next frame into `frame`, waiting for one: an event, else the
/// stream state machine's next. `None` once nothing more will be written:
/// the connection closed (or its stream state failed) with nothing queued.
fn claim(link: &Link, frame: &mut Vec<u8>) -> Option<Claimed> {
    let mut state = link.lock();
    loop {
        let failed = state.sender.failed().is_some();
        if !failed {
            if let Some(event) = state.events.pop_front() {
                if frame::encode_json(&event, frame).is_ok() {
                    state.writing = true;
                    state.progress = Instant::now();
                    return Some(Claimed {
                        wakers: Vec::new(),
                        freed: false,
                        payload: None,
                        charge: None,
                    });
                }
                frame.clear();
                continue;
            }
            let live = state.sender.live();
            if let Some((written, json)) = state.sender.next_frame_owned(frame) {
                let freed = state.sender.live() < live;
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
    let abandoned = std::mem::replace(&mut state.sender, Sender::with_data_cap(0));
    let events = std::mem::take(&mut state.events);
    let charges = std::mem::take(&mut state.charges);
    drop(state);
    drop(abandoned);
    drop(events);
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
        state = wait_timeout(&link.ended, state, tick);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

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
            link.lock().sender.request(id).unwrap();
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
        assert_eq!((state.sender.live(), state.sender.held()), (0, 0));
        drop(state);
        assert!(link.lock().sender.next_frame_owned(&mut frame).is_none());
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
