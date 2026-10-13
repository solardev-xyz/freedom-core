//! A service's connection to main: stdin and stdout frames (designs 0001
//! and 0007, "Frames" and "Progress under backpressure").
//!
//! - **One reader thread** decodes main's frames as they arrive and handles
//!   each at once: the handshake, requests (handed to the service, which
//!   must not block), `cancel`, stream credit and `<service>.shutdown`.
//!   None of it needs writer room, so **the reader never waits on the
//!   writer**.
//! - **One writer thread** takes frames from `fc-protocol`'s stream
//!   [`Sender`]: control frames first (replies, heads, aborts, the replies to
//!   `cancel`), then the streams round-robin. Events go ahead of both.
//! - **The service** answers through [`Connection`]: exactly one reply or
//!   head per request, and for a head with a body, its data and one
//!   terminal. Its producers wait for room with [`Connection::send`], a
//!   future that any async runtime can poll.
//! - **A lifecycle thread** enforces the handshake's deadline, polls the
//!   parent every 2 s, and watches for the writer stall.
//!
//! **How it ends** ([`End`]): stdin EOF or a failed write to stdout (exit
//! 0), `<service>.shutdown` (0), the parent gone (0), a protocol error (76),
//! the handshake's deadline (76), the writer stall (76), or the service's
//! own fatal error. [`run`] then arms the exit watchdog, which ends the
//! process after 5 s whatever its state, lets the service tear down, and
//! returns the exit code.
//!
//! **Requests have no caller context.** 0001's envelope carries one, but a
//! service's requests are all main's (0007, "No caller context"), so the
//! reader decodes `{ type, id, method, params }` and ignores a `context`.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::future::Future;
use std::io::{Read, Write};
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::frame::{self, Decoder, Frame, KIND_JSON, Kinds};
use fc_protocol::message::{check_id, write_error, write_event, write_result};
use fc_protocol::stream::{
    Abort, Cancel, Credited, SendError, Sender, Side, StreamFrame, WRITER_DATA_CAP,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::exit::Exit;
use crate::hardening;
use crate::panic::{TaskKind, with_kind};

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
/// The writer writes at most this much per batch taken from the queue.
const BATCH: usize = 256 << 10;
/// How long [`run`] lets the writer flush what the teardown queued.
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
    /// The writer's cap on queued body bytes (0007: 16 MiB).
    pub data_cap: usize,
    pub max_events: usize,
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

    pub fn exit(self) -> Exit {
        match self {
            End::Eof | End::Shutdown | End::ParentGone => Exit::Ok,
            End::Protocol(_) | End::HelloTimeout | End::WriterStall => Exit::Protocol,
            End::Fatal(exit) => exit,
        }
    }
}

/// What a service does with its connection. Every method runs on the reader
/// thread, except [`Service::end`], so none may block.
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
    /// terminal was settled. Its `cancelled` reply or abort is already
    /// queued: stop its work. (A late cancel never reaches the service.)
    fn cancel(&self, conn: &Connection, id: u64);

    /// The connection ended: tear down. Called once, on [`run`]'s thread,
    /// after the exit watchdog is armed.
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
    /// Wakes [`run`] and the lifecycle thread: the end.
    ended: Condvar,
}

struct State {
    sender: Sender,
    events: VecDeque<Vec<u8>>,
    max_events: usize,
    hello_done: bool,
    end: Option<End>,
    /// Send futures waiting for room.
    waiters: Vec<Waker>,
    /// The writer holds frames it hasn't finished writing.
    writing: bool,
    /// The last time the writer finished writing a frame, or started on a
    /// batch.
    progress: Instant,
    writer_done: bool,
}

impl Link {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Ends the connection, once: the first end wins.
    fn end(&self, end: End) {
        let mut state = self.lock();
        if state.end.is_none() {
            state.end = Some(end);
            wake_all(&mut state);
        }
        drop(state);
        self.writer.notify_all();
        self.ended.notify_all();
    }
}

fn wake_all(state: &mut State) {
    for waker in state.waiters.drain(..) {
        waker.wake();
    }
}

impl Connection {
    /// Runs `op` on the stream state machine, then wakes the writer.
    fn queue<T>(
        &self,
        op: impl FnOnce(&mut State) -> Result<T, SendError>,
    ) -> Result<T, SendError> {
        let mut state = self.link.lock();
        if state.end.is_some() {
            return Err(SendError::Closed);
        }
        let result = op(&mut state);
        drop(state);
        self.link.writer.notify_one();
        result
    }

    /// Answers request `id` with `result`: its one reply.
    pub fn reply<T: Serialize>(&self, id: u64, result: &T) -> Result<(), SendError> {
        let mut json = Vec::new();
        write_result(&mut json, id, result).map_err(|_| SendError::TooLarge)?;
        self.queue(|state| state.sender.reply(id, json))
    }

    /// Answers request `id` with `error`: its one reply.
    pub fn reply_error(&self, id: u64, error: &ErrorBody) -> Result<(), SendError> {
        let mut json = Vec::new();
        write_error(&mut json, id, error).map_err(|_| SendError::TooLarge)?;
        self.queue(|state| state.sender.reply(id, json))
    }

    /// Answers request `id` with a head, `result`. With `body`, it opens a
    /// stream once written; data may be pushed behind it now.
    pub fn head<T: Serialize>(&self, id: u64, result: &T, body: bool) -> Result<(), SendError> {
        let mut json = Vec::new();
        write_result(&mut json, id, result).map_err(|_| SendError::TooLarge)?;
        self.queue(|state| state.sender.head(id, json, body))
    }

    /// Queues as much of `bytes` as stream `id`'s window and the writer's cap
    /// allow, without waiting.
    pub fn push(&self, id: u64, bytes: &[u8]) -> Result<usize, SendError> {
        self.queue(|state| state.sender.push(id, bytes))
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
        self.queue(|state| state.sender.finish(id))
    }

    /// Aborts stream `id`.
    pub fn abort(&self, id: u64, abort: &Abort) -> Result<(), SendError> {
        self.queue(|state| {
            let result = state.sender.abort(id, abort);
            wake_all(state);
            result
        })
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

    /// Ends the connection with `exit`: for a service that can't go on
    /// (0007: a teardown that couldn't prove quiescence exits 70).
    pub fn fail(&self, exit: Exit) {
        self.link.end(End::Fatal(exit));
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

/// What a connection's writer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionStats {
    /// Requests with a record: unanswered, or streams not yet ended.
    pub live_requests: usize,
    /// Queued body bytes across streams.
    pub held_bytes: usize,
    /// Events waiting.
    pub events: usize,
}

/// The future of [`Connection::send`].
pub struct SendBytes<'a> {
    conn: &'a Connection,
    id: u64,
    bytes: &'a [u8],
    sent: usize,
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
/// ends, lets `service` tear down, and returns the exit code.
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
    let link = Arc::new(Link {
        state: Mutex::new(State {
            sender: Sender::with_data_cap(options.data_cap),
            events: VecDeque::new(),
            max_events: options.max_events,
            hello_done: false,
            end: None,
            waiters: Vec::new(),
            writing: false,
            progress: Instant::now(),
            writer_done: false,
        }),
        writer: Condvar::new(),
        ended: Condvar::new(),
    });
    let conn = Connection { link: link.clone() };

    let spawned = [
        spawn("writer", {
            let link = link.clone();
            move || write_loop(&link, output)
        }),
        spawn("reader", {
            let (link, conn, service, options) =
                (link.clone(), conn.clone(), service.clone(), options.clone());
            move || read_loop(&link, &conn, &*service, &options, input)
        }),
        spawn("lifecycle", {
            let (link, options) = (link.clone(), options.clone());
            move || lifecycle_loop(&link, &options)
        }),
    ];
    if spawned.iter().any(Option::is_none) {
        link.end(End::Fatal(Exit::Internal));
    }

    let end = wait_end(&link);
    log_end(end);
    if let Some(after) = options.exit_watchdog {
        // Never disarmed: the process ends within `after` whatever its
        // runtimes' state (0007, "Startup and shutdown").
        drop(crate::watchdog::Watchdog::arm(
            "exit_after_end",
            after,
            end.exit(),
        ));
    }
    service.end(&conn, end);
    // The writer writes what is still queued (the teardown's replies, a
    // refused handshake's), briefly.
    wait_writer(&link, FINAL_FLUSH);
    end.exit()
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
        state = link
            .ended
            .wait(state)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
}

fn wait_writer(link: &Link, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut state = link.lock();
    while !state.writer_done {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return;
        };
        state = match link.ended.wait_timeout(state, left) {
            Ok((state, _)) => state,
            Err(poisoned) => poisoned.into_inner().0,
        };
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

// ---- the reader ----------------------------------------------------------

fn read_loop(
    link: &Link,
    conn: &Connection,
    service: &dyn Service,
    options: &Options,
    mut input: impl Read,
) {
    let mut decoder = Decoder::with_kinds(Kinds::service(Side::Sender));
    let mut buffer = vec![0u8; 64 << 10];
    loop {
        let read = match input.read(&mut buffer) {
            Ok(0) => return link.end(End::Eof),
            Ok(read) => read,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return link.end(End::Eof),
        };
        let mut rest = buffer.get(..read).unwrap_or_default();
        while !rest.is_empty() {
            match decoder.push(rest) {
                Ok(consumed) => rest = rest.get(consumed..).unwrap_or_default(),
                Err(e) => return link.end(End::Protocol(e.category())),
            }
            while let Some(frame) = decoder.pop() {
                if let Err(end) = handle(link, conn, service, options, &frame) {
                    return link.end(end);
                }
            }
            if link.lock().end.is_some() {
                return;
            }
        }
    }
}

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

fn handle(
    link: &Link,
    conn: &Connection,
    service: &dyn Service,
    options: &Options,
    frame: &Frame,
) -> Result<(), End> {
    if frame.kind != KIND_JSON {
        return credit(link, frame);
    }
    let text = std::str::from_utf8(&frame.payload).map_err(|_| End::Protocol("invalid_utf8"))?;
    if !text.trim_start().starts_with('{') {
        return Err(End::Protocol("invalid_message"));
    }
    let envelope: Envelope<'_> =
        serde_json::from_str(text).map_err(|_| End::Protocol("invalid_message"))?;
    let id = |id: Option<u64>| -> Result<u64, End> {
        check_id(id.ok_or(End::Protocol("invalid_message"))?).map_err(|_| End::Protocol("bad_id"))
    };
    let hello_done = link.lock().hello_done;
    match envelope.kind.as_ref() {
        "request" => {
            let id = id(envelope.id)?;
            let method = envelope.method.ok_or(End::Protocol("invalid_message"))?;
            let is_hello = method
                .strip_prefix(options.service)
                .is_some_and(|rest| rest == ".hello");
            {
                let mut state = link.lock();
                state
                    .sender
                    .request(id)
                    .map_err(|e| End::Protocol(e.category()))?;
            }
            if !hello_done {
                if !is_hello {
                    return Err(End::Protocol("not_hello_first"));
                }
                return hello(link, conn, service, options, id, envelope.params);
            }
            if is_hello {
                return Err(End::Protocol("second_hello"));
            }
            if method
                .strip_prefix(options.service)
                .is_some_and(|rest| rest == ".shutdown")
            {
                return Err(End::Shutdown);
            }
            service.request(
                conn,
                Request {
                    id,
                    method: &method,
                    params: envelope.params,
                },
            );
            Ok(())
        }
        "cancel" => {
            if !hello_done {
                return Err(End::Protocol("not_hello_first"));
            }
            let id = id(envelope.id)?;
            let outcome = {
                let mut state = link.lock();
                let outcome = state
                    .sender
                    .cancel(id)
                    .map_err(|e| End::Protocol(e.category()))?;
                wake_all(&mut state);
                outcome
            };
            link.writer.notify_one();
            if outcome == Cancel::Cancelled {
                service.cancel(conn, id);
            }
            Ok(())
        }
        "event" => {
            crate::log::warn("ignoring an event from main", serde_json::json!({}));
            Ok(())
        }
        // The service makes no requests: a response answers nothing.
        "response" => Err(End::Protocol("unsolicited_response")),
        _ => Err(End::Protocol("invalid_message")),
    }
}

fn credit(link: &Link, frame: &Frame) -> Result<(), End> {
    let mut state = link.lock();
    if !state.hello_done {
        return Err(End::Protocol("not_hello_first"));
    }
    let frame = StreamFrame::from_frame(frame).map_err(|e| End::Protocol(e.category()))?;
    match state
        .sender
        .receive(frame)
        .map_err(|e| End::Protocol(e.category()))?
    {
        Credited::Taken(_) => wake_all(&mut state),
        Credited::Late => {}
    }
    Ok(())
}

fn hello(
    link: &Link,
    conn: &Connection,
    service: &dyn Service,
    options: &Options,
    id: u64,
    params: Option<&RawValue>,
) -> Result<(), End> {
    let hello = params
        .filter(|raw| raw.get().trim_start().starts_with('{'))
        .and_then(|raw| serde_json::from_str::<Hello>(raw.get()).ok())
        .ok_or(End::Protocol("bad_hello"))?;
    let mismatch = if hello.protocol != options.protocol {
        Some(format!(
            "protocol {} is not this service's {}",
            hello.protocol, options.protocol
        ))
    } else if !hello.frames.iter().any(|kind| kind == "stream") {
        Some("main must take stream frames".to_owned())
    } else {
        None
    };
    if let Some(message) = mismatch {
        // The reply goes out before the process exits: a packaging bug that
        // main must see.
        let _ = conn.reply_error(id, &ErrorBody::new(ErrorCode::ProtocolMismatch, message));
        return Err(End::Protocol("protocol_mismatch"));
    }
    match service.hello(&hello) {
        Ok(members) => {
            // The protocol is the connection's to state, whatever the
            // service's members say.
            let mut result = members;
            result.insert("protocol".into(), options.protocol.into());
            conn.reply(id, &result)
                .map_err(|_| End::Fatal(Exit::Internal))?;
            link.lock().hello_done = true;
            Ok(())
        }
        Err(error) => {
            let _ = conn.reply_error(id, &error);
            Err(End::Protocol("hello_refused"))
        }
    }
}

// ---- the writer ----------------------------------------------------------

fn write_loop(link: &Link, mut output: impl Write) {
    let mut buffer = Vec::with_capacity(BATCH + (64 << 10));
    let mut ends = Vec::new();
    loop {
        {
            let mut state = link.lock();
            loop {
                while buffer.len() < BATCH {
                    let Some(event) = state.events.pop_front() else {
                        break;
                    };
                    if frame::encode_json(&event, &mut buffer).is_ok() {
                        ends.push(buffer.len());
                    }
                }
                while buffer.len() < BATCH && state.sender.next_frame(&mut buffer).is_some() {
                    ends.push(buffer.len());
                }
                if !buffer.is_empty() {
                    // Data left the queue: producers may find room.
                    wake_all(&mut state);
                    state.writing = true;
                    state.progress = Instant::now();
                    break;
                }
                if state.end.is_some() {
                    state.writer_done = true;
                    drop(state);
                    link.ended.notify_all();
                    return;
                }
                state = link
                    .writer
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        }
        let mut start = 0;
        for &end in &ends {
            let written = output.write_all(buffer.get(start..end).unwrap_or_default());
            if written.is_err() {
                return writer_failed(link);
            }
            start = end;
            link.lock().progress = Instant::now();
        }
        if output.flush().is_err() {
            return writer_failed(link);
        }
        link.lock().writing = false;
        buffer.clear();
        ends.clear();
    }
}

/// A failed write to stdout: main is gone (0007: the guaranteed path, as
/// stdin EOF is).
fn writer_failed(link: &Link) {
    link.end(End::Eof);
    let mut state = link.lock();
    state.writing = false;
    state.writer_done = true;
    drop(state);
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
        state = match link.ended.wait_timeout(state, tick) {
            Ok((state, _)) => state,
            Err(poisoned) => poisoned.into_inner().0,
        };
    }
}
