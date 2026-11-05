//! The dweb thread (design 0009, `dweb.verify`: "Thread"; Streams in the
//! core): the [`Engine`] on its own thread, beside naming's and chain's,
//! with the hashing pool and the core's streams. The event loop starts it
//! once a hello settles protocol 2, and forwards it `dweb.verify` and
//! `dweb.forget`, their cancels, main's answers to its `shell.dweb_get`
//! requests, and every stream frame, in the order the reader read them.
//!
//! - **Its streams are one [`Duplex`]:** the verified bodies it sends main,
//!   under main's request IDs, and the pieces main streams to it, under the
//!   core's own. Main's credit goes to the first, main's data, ends and
//!   aborts to the second; a frame either side doesn't hold is a protocol
//!   error, which ends the core as the reader's own do.
//! - **Main's requests:** each is the duplex sender's, so its one reply,
//!   its head or its stream's abort never doubles: a `cancel` that finds
//!   the head unwritten writes `cancelled` in its place, and the engine's
//!   own answer after it is dropped. `dweb.verify`'s params are read
//!   strictly ([`wire::verify_params`]); others are `invalid_argument`.
//!   `dweb.forget` drops the partition's cache and floors, then answers
//!   `{}`.
//! - **Its pieces** go through the core's one gate ([`Requests`]) as
//!   [`Owner::Dweb`]'s, each registered in the duplex before main can
//!   answer it. Main's reply must be one of `shell.dweb_get`'s three forms
//!   ([`wire::get_reply`]), or an error reply, which fails the piece; any
//!   other is a protocol error. A piece the engine cancels is withdrawn:
//!   `cancel` goes to main, its data is dropped as it comes, and the engine
//!   takes its end only once main's terminal for it has arrived, so its
//!   stream counts against the 128 until main has let it go. A piece's
//!   abort maps to its failure: `cancelled` and `body_stream_error` to
//!   aborted, `stalled` to stalled.
//! - **Its share of the writer** is small ([`transport::MAX_QUEUED_DWEB_BYTES`]):
//!   the duplex writes credit first, then heads and replies, then the
//!   bodies round-robin, so what waits for the writer here is in that
//!   order. The verified bodies wait in the duplex's sender, within 0009's
//!   8 MiB ([`WRITER_DATA_CAP`]); bytes the cap can't take yet wait here,
//!   per body, and go as the writer frees room. Cancels of its own pieces
//!   go ahead of the duplex's frames.
//! - **Its waker** is the chain thread's: room in its share of the writer,
//!   a free slot at main, or a hashing result marks its mailbox, through a
//!   weak reference, so dropping the event loop's [`Handle`] ends the
//!   thread.
//! - **Stopping:** when the event loop has gone (shutdown, EOF or a
//!   protocol error), the thread hands the writer the frames it had made,
//!   drops the bodies still queued (main fails them as it closes), and
//!   stops and joins the hashing pool.

use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fc_dweb::ErrorPlan;
use fc_dweb::verifier::{self, Head, Job, PieceFailure, PieceRequest};
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::frame::{Frame, KIND_ABORT, KIND_END};
use fc_protocol::message::{self, MessageError};
use fc_protocol::stream::{
    Abort, AbortCode, Arrived, Credited, Duplex, Received, Replied, Retire, SendError, StreamFrame,
};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use super::engine::{Bounds, Engine, Fault, Get, Io, Ms, Refusal, Reply};
use super::pool::{self, Hashing};
use super::wire;
use crate::log;
use crate::requests::{self, Dispatch, Owner, Requests, Start};
use crate::serve::Event;
use crate::transport::{self, Allowance, Credit, Out, StreamHold};

/// The methods this thread serves, from protocol 2 on (design 0009).
pub const METHODS: &[&str] = &["dweb.verify", "dweb.forget"];

pub fn handles(method: &str) -> bool {
    METHODS.contains(&method)
}

/// The verified bodies the duplex's sender holds unwritten, across every
/// body (0009, Bounds: "the dweb writer, 8 MiB"): 64 bodies' 128 KiB
/// windows.
pub const WRITER_DATA_CAP: usize = 8 << 20;

// The verifier's window for its body is the stream's: main's credit means
// the same to both.
const _: () = assert!(verifier::BODY_WINDOW == fc_protocol::stream::WINDOW);

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
    /// Main's terminal reply to one of this thread's `shell.dweb_get`s: the
    /// message as it was read, and where its `result` or its `error` lies.
    Response {
        id: u64,
        message: Zeroizing<Vec<u8>>,
        outcome: Result<Range<usize>, Range<usize>>,
    },
    /// A stream frame, and its place under the reader's stream cap.
    Stream {
        frame: Frame,
        hold: StreamHold,
    },
    /// Room in the writer, a free slot at main, or a hashing result.
    Drained,
}

/// A message, with the reader's credit for the frame it came in, held
/// until it is handled.
type Mail = (In, Option<Credit>);

// A stream frame's slot here is within what the reader charges it.
const _: () = assert!(transport::stream_slot_fits(std::mem::size_of::<Mail>()));

/// The event loop's side of the dweb thread. The wake-ups hold only weak
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

/// What wakes the thread: room in its share of the writer, a free slot at
/// main, or a result in the hashing pool.
fn waker(tx: &Arc<Sender<Mail>>) -> impl Fn() + Send + Sync + 'static {
    let wake: Weak<Sender<Mail>> = Arc::downgrade(tx);
    move || {
        if let Some(tx) = wake.upgrade() {
            let _ = tx.send((In::Drained, None));
        }
    }
}

/// Starts the dweb thread and its hashing pool. It writes to `out`, sends
/// its pieces through `requests`, and reports a protocol error from main,
/// or its own end, to the event loop.
pub fn spawn(
    out: Sender<Out>,
    events: Sender<Event>,
    requests: Arc<Requests>,
) -> std::io::Result<Handle> {
    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(tx);
    let allowance = Allowance::new(usize::MAX, transport::MAX_QUEUED_DWEB_BYTES);
    allowance.on_room(waker(&tx));
    requests.on_room(Owner::Dweb, waker(&tx));
    let hashing = pool::hashing(waker(&tx), events.clone())?;
    std::thread::Builder::new()
        .name("dweb".into())
        .spawn(move || {
            let _notice = transport::DeathNotice::new(events.clone(), "dweb");
            let wire = Wire {
                duplex: Duplex::with_data_cap(WRITER_DATA_CAP),
                hashing: Some(hashing),
                out,
                allowance,
                requests,
                made: None,
                cancels: VecDeque::new(),
                unpushed: BTreeMap::new(),
                stop: None,
            };
            let thread = Thread {
                engine: Engine::new(Bounds::default()),
                wire,
                started: Instant::now(),
            };
            let event = match run(&rx, thread) {
                Stop::Protocol(category) => Event::ProtocolError(category),
                Stop::Writer => Event::WriterFailed,
                // The event loop has gone: nothing to report to.
                Stop::Gone => return,
            };
            let _ = events.send(event);
        })?;
    Ok(Handle { tx })
}

/// Why the thread stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// Main broke the protocol (a fixed category, never input text).
    Protocol(&'static str),
    /// The writer has gone.
    Writer,
    /// The event loop has gone.
    Gone,
}

type Flow = Result<(), Stop>;

fn fault(f: Fault) -> Stop {
    Stop::Protocol(f.category())
}

/// The thread's loop, until it has to stop.
fn run(rx: &Receiver<Mail>, mut thread: Thread) -> Stop {
    let stop = loop {
        if let Err(stop) = thread.turn() {
            break stop;
        }
        let wait = thread
            .engine
            .next_due()
            .map_or(Duration::from_secs(3600), |at| {
                Duration::from_millis(at.saturating_sub(thread.now()))
            });
        let flow = match rx.recv_timeout(wait) {
            // The frame's credit goes once its message is handled.
            Ok((message, _credit)) => thread.handle(message),
            Err(RecvTimeoutError::Timeout) => Ok(()),
            Err(RecvTimeoutError::Disconnected) => Err(Stop::Gone),
        };
        if let Err(stop) = flow {
            break stop;
        }
    };
    thread.wire.close();
    stop
}

struct Thread {
    engine: Engine,
    wire: Wire,
    started: Instant,
}

impl Thread {
    /// Milliseconds on the thread's monotonic clock.
    fn now(&self) -> Ms {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// The hashing pool's results, the deadlines due, and what can be
    /// written; then whatever stopped the thread meanwhile.
    fn turn(&mut self) -> Flow {
        while let Some(result) = self.wire.hashing.as_mut().and_then(Hashing::take) {
            let now = self.now();
            self.engine
                .hashed(&mut self.wire, now, result)
                .map_err(fault)?;
        }
        let now = self.now();
        if self.engine.next_due().is_some_and(|at| at <= now) {
            self.engine.tick(&mut self.wire, now);
        }
        self.wire.flush()
    }

    fn handle(&mut self, message: In) -> Flow {
        let now = self.now();
        match message {
            In::Request { id, method, params } => self.request(now, id, method, params)?,
            In::Cancel { id } => {
                // Every cancel main sends reaches this thread: one for a
                // request it doesn't hold, or holds no more, changes nothing.
                if self.wire.duplex.sender().is_live(id) {
                    self.wire
                        .duplex
                        .cancel(id)
                        .map_err(|e| Stop::Protocol(e.category()))?;
                    self.engine.cancel(&mut self.wire, now, id);
                }
            }
            In::Response {
                id,
                message,
                outcome,
            } => self.response(now, id, &message, outcome)?,
            In::Stream { frame, hold } => {
                self.stream(now, &frame)?;
                drop(hold);
            }
            In::Drained => self.engine.room(&mut self.wire, now),
        }
        self.wire.flush()
    }

    /// One of main's requests: `dweb.verify` or `dweb.forget`.
    fn request(
        &mut self,
        now: Ms,
        id: u64,
        method: &'static str,
        params: Option<Box<RawValue>>,
    ) -> Flow {
        self.wire
            .duplex
            .request(id)
            .map_err(|e| Stop::Protocol(e.category()))?;
        let params = params.as_deref().map(RawValue::get);
        match method {
            "dweb.verify" => match wire::verify_params(params) {
                Ok(request) => self.engine.verify(&mut self.wire, now, id, request),
                Err(message) => self
                    .wire
                    .refuse_with(id, ErrorCode::InvalidArgument, message),
            },
            _ => match wire::forget_params(params) {
                Ok(partition) => {
                    self.engine.forget(partition.as_deref());
                    self.wire.result(id, &serde_json::json!({}));
                }
                Err(message) => self
                    .wire
                    .refuse_with(id, ErrorCode::InvalidArgument, message),
            },
        }
        Ok(())
    }

    /// Main's answer to the core's `shell.dweb_get` `id`.
    fn response(
        &mut self,
        now: Ms,
        id: u64,
        message: &[u8],
        outcome: Result<Range<usize>, Range<usize>>,
    ) -> Flow {
        let text = |span: Range<usize>| {
            message
                .get(span)
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .ok_or(Stop::Protocol("dweb_get_reply"))
        };
        let reply = match outcome {
            Ok(result) => wire::get_reply(text(result)?).ok_or(Stop::Protocol("dweb_get_reply"))?,
            // Main refused the piece (its `for` had ended, say): the piece
            // failed, as a dial that failed.
            Err(error) => {
                serde_json::from_str::<&RawValue>(text(error)?)
                    .map_err(|e| MessageError::Malformed(e.to_string()))
                    .and_then(ErrorBody::from_raw)
                    .map_err(|_| Stop::Protocol("dweb_get_reply"))?;
                Reply::Failed(PieceFailure::Error)
            }
        };
        let opens = matches!(reply, Reply::Stream { .. });
        match self
            .wire
            .duplex
            .answered(id, opens)
            .map_err(|e| Stop::Protocol(e.category()))?
        {
            Replied::Deliver => self
                .engine
                .reply(&mut self.wire, now, id, reply)
                .map_err(fault),
            // A piece the engine withdrew: it ends here, or, if main opened
            // its stream all the same, at that stream's terminal.
            Replied::Retired if opens => Ok(()),
            Replied::Retired => self.withdrawn_end(now, id),
        }
    }

    /// A stream frame from main.
    fn stream(&mut self, now: Ms, frame: &Frame) -> Flow {
        let parsed = read(frame)?;
        let credit = match &parsed {
            StreamFrame::Credit { bytes, .. } => Some(*bytes),
            _ => None,
        };
        let received = self
            .wire
            .duplex
            .receive(parsed)
            .map_err(|e| Stop::Protocol(e.category()))?;
        match received {
            Received::Credited(Credited::Taken(id)) => {
                let bytes = credit.map_or(0, |n| n as usize);
                self.engine
                    .body_credit(&mut self.wire, now, id, bytes)
                    .map_err(fault)
            }
            Received::Credited(Credited::Late) => Ok(()),
            Received::Arrived(Arrived::Data { id, .. }) => {
                let StreamFrame::Data { bytes, .. } = read(frame)? else {
                    return Ok(());
                };
                self.engine
                    .data(&mut self.wire, now, id, bytes.to_vec())
                    .map_err(fault)
            }
            Received::Arrived(Arrived::End { id }) => self
                .engine
                .ended_stream(&mut self.wire, now, id, None)
                .map_err(fault),
            Received::Arrived(Arrived::Abort { id, abort }) => {
                let failure = match abort.code {
                    AbortCode::Stalled => PieceFailure::Stalled,
                    // `cancelled` or `body_stream_error`: the duplex takes no
                    // other code from main.
                    _ => PieceFailure::Aborted,
                };
                self.engine
                    .ended_stream(&mut self.wire, now, id, Some(failure))
                    .map_err(fault)
            }
            // A withdrawn piece's frame: its data goes, and its terminal
            // ends it for the engine.
            Received::Arrived(Arrived::Dropped { id }) => {
                if matches!(frame.kind, KIND_END | KIND_ABORT) {
                    self.withdrawn_end(now, id)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Main's terminal for a piece the engine had cancelled.
    fn withdrawn_end(&mut self, now: Ms, id: u64) -> Flow {
        self.engine
            .ended_stream(&mut self.wire, now, id, Some(PieceFailure::Aborted))
            .map_err(fault)
    }
}

fn read(frame: &Frame) -> Result<StreamFrame<'_>, Stop> {
    StreamFrame::from_frame(frame).map_err(|e| Stop::Protocol(e.category()))
}

/// Verified body bytes the duplex's cap didn't take yet, and whether the
/// body's end follows them.
#[derive(Default)]
struct Unpushed {
    bytes: VecDeque<u8>,
    end: bool,
}

/// The engine's [`Io`]: the duplex, the hashing pool, the gate and the
/// writer.
struct Wire {
    duplex: Duplex,
    /// `None` once stopped.
    hashing: Option<Hashing>,
    out: Sender<Out>,
    allowance: Arc<Allowance>,
    requests: Arc<Requests>,
    /// A frame the duplex made that the writer had no room for yet.
    made: Option<Zeroizing<Vec<u8>>>,
    /// Cancels of the core's pieces, ahead of the duplex's frames.
    cancels: VecDeque<Zeroizing<Vec<u8>>>,
    /// By main's request ID.
    unpushed: BTreeMap<u64, Unpushed>,
    /// Why the thread must stop, found while acting for the engine.
    stop: Option<Stop>,
}

impl Wire {
    /// Hands the writer what it has room for: the cancels, then the
    /// duplex's frames, with body bytes that waited for the cap pushed as
    /// the writer frees it.
    fn flush(&mut self) -> Flow {
        if let Some(stop) = self.stop {
            return Err(stop);
        }
        loop {
            self.push_unpushed();
            while let Some(frame) = self.cancels.front() {
                let Some(hold) = self.allowance.take(frame.len()) else {
                    return Ok(());
                };
                let Some(frame) = self.cancels.pop_front() else {
                    break;
                };
                self.send(frame, hold)?;
            }
            let mut wrote = false;
            loop {
                let frame = match self.made.take() {
                    Some(frame) => frame,
                    None => {
                        let mut frame = Zeroizing::new(Vec::new());
                        if self.duplex.next_frame(&mut frame).is_none() {
                            break;
                        }
                        frame
                    }
                };
                let Some(hold) = self.allowance.take(frame.len()) else {
                    self.made = Some(frame);
                    return Ok(());
                };
                self.send(frame, hold)?;
                wrote = true;
            }
            // Frames written free the sender's cap for bytes that waited.
            if !wrote || self.unpushed.is_empty() {
                return Ok(());
            }
        }
    }

    fn send(&mut self, frame: Zeroizing<Vec<u8>>, hold: transport::Hold) -> Flow {
        self.out
            .send(Out::Frame { frame, hold })
            .map_err(|_| Stop::Writer)
    }

    /// Body bytes that waited for the sender's cap, as far as it takes
    /// them; a body whose bytes have all gone gets its end.
    fn push_unpushed(&mut self) {
        let sender = self.duplex.sender_mut();
        self.unpushed.retain(|&id, u| {
            let pushed = match sender.push(id, u.bytes.make_contiguous()) {
                Ok(n) => n,
                // Cancelled or aborted meanwhile: its bytes go.
                Err(_) => return false,
            };
            u.bytes.drain(..pushed);
            if !u.bytes.is_empty() {
                return true;
            }
            if u.end {
                let _ = sender.finish(id);
            }
            false
        });
    }

    /// Hands the writer what was made, past the allowance, and stops the
    /// pool: the event loop has gone, and the writer's drain is bounded by
    /// time.
    fn close(&mut self) {
        for frame in self.cancels.drain(..).chain(self.made.take()) {
            let hold = self.allowance.force(frame.len());
            let _ = self.out.send(Out::Frame { frame, hold });
        }
        if let Some(hashing) = self.hashing.take() {
            hashing.shutdown();
        }
    }

    /// Main's request `id`'s one reply, `payload` (a response message).
    fn reply(&mut self, id: u64, payload: Vec<u8>) {
        let result = self.duplex.sender_mut().reply(id, payload);
        settled(id, result);
    }

    fn result(&mut self, id: u64, result: &serde_json::Value) {
        let mut payload = Vec::with_capacity(256);
        if message::write_result(&mut payload, id, result).is_ok() {
            self.reply(id, payload);
        }
    }

    fn refuse_with(&mut self, id: u64, code: ErrorCode, message: &str) {
        let mut payload = Vec::with_capacity(128);
        if message::write_error(&mut payload, id, &ErrorBody::new(code, message)).is_ok() {
            self.reply(id, payload);
        }
    }
}

/// What a producer's call on the sender did. Main's cancel came first when
/// the request is gone (`Gone`, or its stream aborted): the engine's answer
/// after it is dropped, as the cancel settled the request. Anything else is
/// the core's own bug, logged.
fn settled(id: u64, result: Result<(), SendError>) {
    match result {
        Ok(()) | Err(SendError::Gone) => {}
        Err(error) => log::warn(
            "dweb answer refused",
            serde_json::json!({ "id": id, "error": error.name() }),
        ),
    }
}

impl Io for Wire {
    fn get(&mut self, request: u64, piece: &PieceRequest) -> Get {
        let Ok(params) = serde_json::to_vec(&wire::get_params(request, piece)) else {
            return Get::Refused;
        };
        let dispatch = self.requests.send(
            Owner::Dweb,
            &self.allowance,
            &self.out,
            || requests::request_frame("shell.dweb_get", &params, None),
            || Start::Anytime,
        );
        match dispatch {
            Dispatch::Sent(id) => {
                // Before main's answer can be handled: this thread handles
                // it, after this.
                if let Err(error) = self.duplex.ask(id) {
                    log::warn(
                        "dweb piece not registered",
                        serde_json::json!({ "error": error.category() }),
                    );
                }
                Get::Sent(id)
            }
            // The gate's room, or the writer's, wakes the thread.
            Dispatch::Full | Dispatch::NoRoom => Get::Full,
            Dispatch::TooLarge | Dispatch::Closed | Dispatch::Late => Get::Refused,
            Dispatch::WriterGone => {
                self.stop = Some(Stop::Writer);
                Get::Refused
            }
        }
    }

    fn cancel(&mut self, get: u64) {
        if self.duplex.withdraw(get) == Retire::SendCancel {
            let cancel = format!(r#"{{"type":"cancel","id":{get}}}"#);
            if let Some(frame) = transport::frame(cancel.as_bytes()) {
                self.cancels.push_back(frame);
            }
        }
    }

    fn credit(&mut self, get: u64, bytes: usize) {
        if let Err(overcredit) = self.duplex.release(get, bytes) {
            // The verifier credited more than its piece holds: the core's
            // own bug, refused without failing the connection.
            log::warn(
                "dweb piece overcredited",
                serde_json::json!({ "credit": overcredit.credit, "held": overcredit.held }),
            );
        }
    }

    fn hash(&mut self, job: Job) {
        if let Some(hashing) = self.hashing.as_mut() {
            hashing.submit(job);
        }
    }

    fn head(&mut self, request: u64, head: Head) {
        let mut payload = Vec::with_capacity(512);
        if message::write_result(&mut payload, request, &wire::head_result(&head)).is_err() {
            return;
        }
        let result = self.duplex.sender_mut().head(request, payload, head.body);
        settled(request, result);
    }

    fn error(&mut self, request: u64, error: ErrorPlan) {
        self.result(request, &wire::error_result(&error));
    }

    fn refuse(&mut self, request: u64, refusal: Refusal) {
        let (code, message) = match refusal {
            Refusal::Busy => (ErrorCode::Busy, "Too many requests"),
            Refusal::Cancelled => (ErrorCode::Cancelled, "Cancelled"),
        };
        self.refuse_with(request, code, message);
    }

    fn body(&mut self, request: u64, bytes: Vec<u8>) {
        if let Some(u) = self.unpushed.get_mut(&request) {
            u.bytes.extend(bytes);
            return;
        }
        let pushed = match self.duplex.sender_mut().push(request, &bytes) {
            Ok(n) => n,
            Err(error) => return settled(request, Err(error)),
        };
        if pushed < bytes.len() {
            let mut u = Unpushed::default();
            u.bytes.extend(&bytes[pushed..]);
            self.unpushed.insert(request, u);
        }
    }

    fn end(&mut self, request: u64) {
        if let Some(u) = self.unpushed.get_mut(&request) {
            u.end = true;
            return;
        }
        let result = self.duplex.sender_mut().finish(request);
        settled(request, result);
    }

    fn abort(&mut self, request: u64, code: verifier::AbortCode, message: &'static str) {
        self.unpushed.remove(&request);
        let code = AbortCode::ALL
            .into_iter()
            .find(|c| c.as_str() == code.as_str())
            .unwrap_or(AbortCode::Unverifiable);
        let result = self
            .duplex
            .sender_mut()
            .abort(request, &Abort::new(code, message));
        settled(request, result);
    }

    fn wall(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }
}
