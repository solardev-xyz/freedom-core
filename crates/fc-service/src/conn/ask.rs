//! The service's own requests to main, and main's bodies in answer to them
//! (design 0014, "Requests the service makes" and "Bodies"; its COL-3), on a
//! connection whose [`Options::two_way`](super::Options::two_way) is on.
//!
//! - **A request** ([`Connection::ask`]) is `{ type, id, method, params }`,
//!   as main's are, without a caller context. Its ID is the service's own:
//!   from 1, strictly increasing, apart from main's. The connection holds at
//!   most [`Options::max_asks`](super::Options::max_asks) of them, from the
//!   ask until main and the service are both done with it. Requests and
//!   cancels are written in order, behind the events, and none before the
//!   handshake's reply.
//! - **Main's reply** resolves the [`Asked`] future: its `result`, or its
//!   `error` ([`AskFailed::Error`]). A result whose `body` member is `true`
//!   opens a stream from main, as a head does on 0007's streams, and comes
//!   with its [`Body`].
//! - **The body** is 0009's stream, the other way: data, then `end` or
//!   `abort`, within the 128 KiB window. The reader never waits on it: each
//!   data frame's bytes join the stream's queue, which holds at most the
//!   window, and its credit is owed to main only once the consumer takes
//!   them ([`Body::chunk`]), so credit goes only for room the consumer
//!   holds. Owed credit is written ahead of the service's own frames.
//!   Main's abort codes are a piece's: `cancelled`, `stalled` and
//!   `body_stream_error`; any other is the protocol error `abort_code`.
//! - **Room reserved at the head** ([`Connection::ask_reserving`], 0014's
//!   bodies budget): the service's hook sees main's head before any byte
//!   of its body is read, since the reader handles frames in order, and
//!   reserves room for the body's exact length or refuses it. A refused
//!   head is cancelled at once, so none of its body is held or credited
//!   ([`AskFailed::Refused`]). A reserved body is held to its length
//!   ([`fc_protocol::stream::Duplex::answered_sized`]): one that breaks it,
//!   more bytes or fewer at its end, fails alone with
//!   [`BodyError::Mismatch`], past the length with `cancel` to main, while
//!   the connection, its other streams and its control frames go on. The
//!   reservation ([`Hold`]) is the service's with the answer, or goes with
//!   the request if the service never takes the answer.
//! - **Cancel:** dropping the [`Asked`] before it resolves, or the [`Body`]
//!   before its end, sends main `cancel` for the request, unless main's
//!   answer is complete already. Main still sends its reply, or the
//!   stream's terminal; what comes of it is dropped as it is read.
//! - **Deadlines:** a request's deadline covers main's reply. Once it
//!   passes, the request is cancelled as above and resolves
//!   [`AskFailed::Deadline`]. The lifecycle thread watches the deadlines, so
//!   a request nobody polls is cancelled on time too. After the reply the
//!   consumer bounds the body's reads itself, as main's body idle timer
//!   bounds a service's (0007).
//! - **Protocol errors** on either side's streams fail the connection both
//!   ways, as on the core's (0009): main's reply to no pending request
//!   (`unsolicited_response`), data before the reply or after the end
//!   (`stream_not_open`), for an ID above the service's highest
//!   (`stream_unknown`), or beyond the window (`window_overrun`).
//! - **The end:** once the connection ends, nothing more of the service's
//!   requests goes to main, and nothing more of main's answers is read.
//!   Their unwritten requests, cancels and credit go at once, under the
//!   lock that ends the connection, so the writer writes none of them; the
//!   service's answers to main stay, for its teardown. A waiting [`Asked`]
//!   resolves [`AskFailed::Closed`], and a [`Body`] gives what came and
//!   then [`BodyError::Closed`]. Either, polled to that or dropped, leaves
//!   nothing behind.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use fc_protocol::error::ErrorBody;
use fc_protocol::frame::{self, Frame};
use fc_protocol::message::Message;
use fc_protocol::stream::{Abort, Arrived, Received, Replied, Retire, StreamFrame};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::{Connection, End, Reader, State, wake};

/// Why [`Connection::ask`] sent nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskError {
    /// The connection is one-way ([`Options::two_way`](super::Options::two_way)
    /// is off).
    OneWay,
    /// The connection holds [`Options::max_asks`](super::Options::max_asks)
    /// of the service's requests.
    Full,
    /// The request didn't serialize, or exceeds one frame.
    Encode,
    /// The connection ended, or is closing.
    Closed,
}

/// How an [`Asked`] request failed.
#[derive(Debug, Clone, PartialEq)]
pub enum AskFailed {
    /// Main's error reply.
    Error(ErrorBody),
    /// The service's own hook refused main's head, with this refusal
    /// ([`Connection::ask_reserving`]): `cancel` went to main before any of
    /// the body was read, and nothing of it was taken.
    Refused(ErrorBody),
    /// Its deadline passed before main's reply: `cancel` went to main.
    Deadline,
    /// The connection ended before main's reply.
    Closed,
}

/// Main's reply to a request of the service's.
#[derive(Debug)]
pub struct Answer {
    /// Main's `result`, as it was sent.
    pub result: Box<RawValue>,
    /// The body main sends behind it, when the result says `body: true`.
    pub body: Option<Body>,
    /// The room the service's hook reserved for the body
    /// ([`Connection::ask_reserving`]): the service's now, to keep while it
    /// holds the body's bytes.
    pub hold: Option<Hold>,
}

/// Why a [`Body`] ended before its end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// Main aborted it.
    Aborted(Abort),
    /// It broke the length its head was reserved for ([`Reserved::len`]):
    /// `received` bytes, past `declared`, or short of it at its end (design
    /// 0014: `Colibri body length mismatch`). It failed alone, past the
    /// length with `cancel` to main; what it had queued was dropped.
    Mismatch { declared: u64, received: u64 },
    /// The connection ended first.
    Closed,
}

/// What the service's hook reserved for main's body at its head
/// ([`Connection::ask_reserving`]).
#[derive(Debug)]
pub struct Reserved {
    /// The body's exact length in bytes: the connection holds the body to
    /// it ([`BodyError::Mismatch`]).
    pub len: u64,
    /// The room reserved for it.
    pub hold: Hold,
}

/// Room a service reserved for one of main's bodies, as its hook made it
/// ([`Reserved`]): dropping it gives the room back. It goes to the service
/// with main's answer ([`Answer::hold`]), or, if the service never takes the
/// answer (it lets go of the request, its deadline passes, or the
/// connection ends), it is dropped with the request. The connection may
/// drop it on any of its threads, under its lock, so its drop must neither
/// block nor call into the connection; giving back an atomic count does
/// neither.
pub struct Hold {
    /// Kept only to be dropped.
    _room: Box<dyn Send>,
}

impl Hold {
    /// Wraps whatever gives the room back when dropped.
    pub fn new(room: impl Send + 'static) -> Hold {
        Hold {
            _room: Box::new(room),
        }
    }
}

impl std::fmt::Debug for Hold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hold")
    }
}

/// A request's hook for main's head ([`Connection::ask_reserving`]).
type Reserve = Box<dyn FnOnce(&RawValue) -> Result<Reserved, ErrorBody> + Send>;

/// A request of the service's, from [`Connection::ask`] until both sides
/// are done with it: the service's [`Asked`] has resolved without a body,
/// or its [`Body`] has ended or been dropped, and main's reply, and its
/// stream's terminal, have come. So the connection's count of them is
/// everything either side still holds.
pub(super) struct Ask {
    /// When it gives up on main's reply, while it waits for it: also in
    /// [`State::deadlines`].
    pub(super) deadline: Option<Instant>,
    /// Its [`Asked`]'s waker, or its [`Body`]'s.
    pub(super) waker: Option<Waker>,
    /// Main's reply, or how it failed, until the [`Asked`] takes it.
    reply: Option<Result<Box<RawValue>, AskFailed>>,
    /// The body behind a reply that opened one, until its consumer ends or
    /// drops it.
    body: Option<Inflow>,
    /// The service holds it: its [`Asked`], then its [`Body`].
    held: bool,
    /// Its hook for main's head, until the head calls it.
    reserve: Option<Reserve>,
    /// What the hook reserved, until the [`Asked`] hands it over.
    hold: Option<Hold>,
}

/// A body from main, as the connection holds it for its consumer.
#[derive(Default)]
struct Inflow {
    /// Data frames' bytes, as they came. At most the window: credit goes
    /// back only for bytes the consumer has taken.
    chunks: VecDeque<Vec<u8>>,
    /// Its end, main's abort, or the length it broke.
    terminal: Option<Result<(), BodyError>>,
}

/// A request or a cancel of the service's, for the writer: one JSON
/// message.
pub(super) struct Outgoing(Vec<u8>);

impl Outgoing {
    pub(super) fn json(&self) -> &[u8] {
        &self.0
    }

    fn cancel(id: u64) -> Self {
        Outgoing(format!(r#"{{"type":"cancel","id":{id}}}"#).into_bytes())
    }
}

/// The digits of the largest ID, 2^53 - 1.
const ID_SLOT: usize = 16;

/// A request's JSON with a slot for its ID ([`write_id`]), and where the
/// slot is. The params are serialized here, before the connection's lock is
/// taken; under it, only the ID is written.
fn request_json<P: Serialize + ?Sized>(
    method: &str,
    params: &P,
) -> Result<(Vec<u8>, usize), AskError> {
    let mut json = Vec::new();
    json.extend_from_slice(br#"{"type":"request","id":"#);
    let slot = json.len();
    json.resize(slot + ID_SLOT, b' ');
    json.extend_from_slice(br#","method":"#);
    serde_json::to_writer(&mut json, method).map_err(|_| AskError::Encode)?;
    json.extend_from_slice(br#","params":"#);
    serde_json::to_writer(&mut json, params).map_err(|_| AskError::Encode)?;
    json.push(b'}');
    if json.len() > frame::MAX_PAYLOAD {
        return Err(AskError::Encode);
    }
    Ok((json, slot))
}

/// Writes `id` into its slot, right-aligned: JSON allows the spaces before
/// a value, so the message keeps its length whatever the ID.
fn write_id(slot: &mut [u8], id: u64) {
    let digits = id.to_string();
    let at = slot.len().saturating_sub(digits.len());
    if let Some(tail) = slot.get_mut(at..) {
        tail.copy_from_slice(digits.as_bytes().get(..tail.len()).unwrap_or_default());
    }
}

impl Connection {
    /// Sends main request `method` with `params` (design 0014, "Requests the
    /// service makes"), on a two-way connection, and returns the future of
    /// main's reply. Dropping it before it resolves cancels the request;
    /// past `deadline`, without main's reply, the request is cancelled and
    /// the future resolves [`AskFailed::Deadline`]. Never blocks.
    pub fn ask<P: Serialize + ?Sized>(
        &self,
        method: &str,
        params: &P,
        deadline: Option<Instant>,
    ) -> Result<Asked, AskError> {
        self.ask_with(method, params, deadline, None)
    }

    /// As [`Connection::ask`], for a body the service reserves room for
    /// before it takes any of it (design 0014, "Requests the service makes":
    /// the bodies budget's reservation before credit).
    ///
    /// When main's reply is a head that opens a body, `reserve` runs with
    /// its result on the reader thread, before any of the body is read, and
    /// either reserves room for the body and gives its exact length, or
    /// refuses it:
    /// - **Reserved:** the body is held to its length ([`BodyError::Mismatch`])
    ///   and the reservation goes to the service with the answer
    ///   ([`Answer::hold`]), or with the request if the answer is never
    ///   taken.
    /// - **Refused:** the request is cancelled at once, so none of the body
    ///   is held or credited, and the [`Asked`] resolves
    ///   [`AskFailed::Refused`] with the refusal.
    ///
    /// It isn't called for a reply that opens no body, for a request the
    /// service has let go of or whose deadline has passed, or once the
    /// connection has ended; it is then dropped uncalled, possibly under the
    /// connection's lock. Like a [`Service`](super::Service) callback it
    /// must not block, and the connection's teardown waits for it.
    pub fn ask_reserving<P, R>(
        &self,
        method: &str,
        params: &P,
        deadline: Option<Instant>,
        reserve: R,
    ) -> Result<Asked, AskError>
    where
        P: Serialize + ?Sized,
        R: FnOnce(&RawValue) -> Result<Reserved, ErrorBody> + Send + 'static,
    {
        self.ask_with(method, params, deadline, Some(Box::new(reserve)))
    }

    fn ask_with<P: Serialize + ?Sized>(
        &self,
        method: &str,
        params: &P,
        deadline: Option<Instant>,
        reserve: Option<Reserve>,
    ) -> Result<Asked, AskError> {
        if !self.link.two_way {
            return Err(AskError::OneWay);
        }
        let (mut json, slot) = request_json(method, params)?;
        let id = {
            let mut state = self.link.lock();
            if state.end.is_some() || state.closed || state.writer_done {
                return Err(AskError::Closed);
            }
            if state.asks.len() >= self.link.max_asks {
                return Err(AskError::Full);
            }
            let id = state.last_ask.saturating_add(1);
            // Only a failed connection refuses the next ID.
            state.streams.ask(id).map_err(|_| AskError::Closed)?;
            state.last_ask = id;
            write_id(json.get_mut(slot..slot + ID_SLOT).unwrap_or_default(), id);
            state.outbound.push_back(Outgoing(json));
            state.asks.insert(
                id,
                Ask {
                    deadline,
                    waker: None,
                    reply: None,
                    body: None,
                    held: true,
                    reserve,
                    hold: None,
                },
            );
            if let Some(at) = deadline {
                state.deadlines.insert((at, id));
            }
            id
        };
        self.link.writer.notify_one();
        if deadline.is_some() {
            // The lifecycle thread looks at the deadlines again.
            self.link.ended.notify_all();
        }
        Ok(Asked {
            conn: self.clone(),
            id,
            done: false,
        })
    }

    /// The service's requests the connection holds ([`Ask`]).
    pub fn asks(&self) -> usize {
        self.link.lock().asks.len()
    }

    /// The service let go of request `id` before its end: main gets
    /// `cancel` unless its answer is complete, and what it held goes.
    fn let_go(&self, id: u64) {
        let mut state = self.link.lock();
        // What it held, freed outside the lock: a reservation among it.
        let mut held = None;
        if let Some(ask) = state.asks.get_mut(&id) {
            ask.held = false;
            ask.waker = None;
            held = Some((
                ask.reply.take(),
                ask.body.take(),
                ask.hold.take(),
                ask.reserve.take(),
            ));
            let deadline = ask.deadline.take();
            if let Some(at) = deadline {
                state.deadlines.remove(&(at, id));
            }
        }
        withdraw(&mut state, id);
        prune(&mut state, id);
        drop(state);
        drop(held);
        self.link.writer.notify_one();
    }
}

/// The service cancels request `id`: main gets `cancel` while its reply or
/// its stream's terminal is still to come, and what comes is dropped.
fn withdraw(state: &mut State, id: u64) {
    if state.streams.withdraw(id) == Retire::SendCancel && state.end.is_none() {
        state.outbound.push_back(Outgoing::cancel(id));
    }
}

/// Forgets request `id` once neither side holds anything of it.
fn prune(state: &mut State, id: u64) {
    let done = state.asks.get(&id).is_some_and(|ask| !ask.held)
        && state.streams.inbound().info(id).is_none();
    if done
        && let Some(ask) = state.asks.remove(&id)
        && let Some(at) = ask.deadline
    {
        state.deadlines.remove(&(at, id));
    }
}

/// The connection ended, and this end won: nothing more comes from main for
/// the service's requests, and nothing more of them goes. Their records in
/// the stream state go, with the credit owed for them, and so do the
/// requests the service let go of and their deadlines. What the service
/// still holds stays until its [`Asked`] or [`Body`] says `Closed` or is
/// dropped, and neither waits on main any more. The unwritten requests and
/// cancels are returned, to be freed outside the lock. The service's
/// answers to main stay queued, for its teardown's writes.
pub(super) fn close(state: &mut State) -> VecDeque<Outgoing> {
    state.streams.close_inbound();
    state.deadlines.clear();
    state.asks.retain(|_, ask| {
        ask.deadline = None;
        ask.held
    });
    std::mem::take(&mut state.outbound)
}

/// Request `id`'s deadline passed: unless main's reply came, it is
/// cancelled and fails with [`AskFailed::Deadline`]. Its waker, to wake.
fn expire(state: &mut State, id: u64) -> Option<Waker> {
    let ask = state.asks.get_mut(&id)?;
    let at = ask.deadline.take()?;
    if ask.reply.is_some() || ask.body.is_some() || !ask.held {
        return None;
    }
    ask.reply = Some(Err(AskFailed::Deadline));
    let waker = ask.waker.take();
    state.deadlines.remove(&(at, id));
    withdraw(state, id);
    waker
}

/// Every request whose deadline is at or before `now`, expired: whether
/// there was one, and their wakers. The caller wakes the writer for their
/// cancels, whether or not anyone polls them.
pub(super) fn expire_due(state: &mut State, now: Instant) -> Option<Vec<Waker>> {
    let mut expired = None;
    while let Some(&(at, id)) = state.deadlines.first()
        && at <= now
    {
        state.deadlines.pop_first();
        let wakers: &mut Vec<Waker> = expired.get_or_insert_default();
        wakers.extend(expire(state, id));
    }
    expired
}

/// The future of main's reply to a request of the service's
/// ([`Connection::ask`]). Dropped before it resolves, it cancels the
/// request.
#[must_use = "dropping it cancels the request"]
pub struct Asked {
    conn: Connection,
    id: u64,
    /// It resolved: the request is its [`Body`]'s now, or over.
    done: bool,
}

impl Asked {
    /// The request's ID, in the service's ID space.
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl std::fmt::Debug for Asked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Asked").field("id", &self.id).finish()
    }
}

impl Future for Asked {
    type Output = Result<Answer, AskFailed>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        if this.done {
            return Poll::Ready(Err(AskFailed::Closed));
        }
        let id = this.id;
        let mut state = this.conn.link.lock();
        // Its deadline, whether or not the lifecycle thread has looked yet.
        let due = state
            .asks
            .get(&id)
            .and_then(|ask| ask.deadline)
            .is_some_and(|at| Instant::now() >= at);
        if due {
            drop(expire(&mut state, id));
        }
        let ended = state.end.is_some();
        let Some(ask) = state.asks.get_mut(&id) else {
            this.done = true;
            return Poll::Ready(Err(AskFailed::Closed));
        };
        let outcome = match ask.reply.take() {
            Some(Ok(result)) => {
                let body = ask.body.is_some();
                ask.held = body;
                Ok(Answer {
                    result,
                    body: body.then(|| Body {
                        conn: this.conn.clone(),
                        id,
                        ended: None,
                    }),
                    hold: ask.hold.take(),
                })
            }
            Some(Err(failed)) => {
                ask.held = false;
                Err(failed)
            }
            None if ended => {
                ask.held = false;
                Err(AskFailed::Closed)
            }
            None => {
                ask.waker = Some(cx.waker().clone());
                // A cancel its deadline queued.
                drop(state);
                if due {
                    this.conn.link.writer.notify_one();
                }
                return Poll::Pending;
            }
        };
        this.done = true;
        prune(&mut state, id);
        drop(state);
        if due {
            this.conn.link.writer.notify_one();
        }
        Poll::Ready(outcome)
    }
}

impl Drop for Asked {
    fn drop(&mut self) {
        if !self.done {
            self.conn.let_go(self.id);
        }
    }
}

/// A body main sends in answer to a request of the service's. Dropped
/// before its end, it cancels the request.
pub struct Body {
    conn: Connection,
    id: u64,
    /// How it ended, once [`Body::chunk`] has said so.
    ended: Option<Result<(), BodyError>>,
}

impl Body {
    /// The request's ID, which is the stream's.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The future of the body's next bytes, as one data frame brought them
    /// (1 to 64 KiB): `None` at its end. Taking them owes main their
    /// credit, so the bytes taken are the consumer's to hold. A body that
    /// broke its reserved length gives no more bytes:
    /// [`BodyError::Mismatch`] is next.
    pub fn chunk(&mut self) -> Chunk<'_> {
        Chunk { body: self }
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Body").field("id", &self.id).finish()
    }
}

impl Drop for Body {
    fn drop(&mut self) {
        if self.ended.is_none() {
            self.conn.let_go(self.id);
        }
    }
}

/// The future of [`Body::chunk`].
pub struct Chunk<'a> {
    body: &'a mut Body,
}

impl Future for Chunk<'_> {
    type Output = Result<Option<Vec<u8>>, BodyError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let body = &mut *self.body;
        if let Some(ended) = &body.ended {
            return Poll::Ready(ended.clone().map(|()| None));
        }
        let id = body.id;
        let mut state = body.conn.link.lock();
        let ended = state.end.is_some();
        let inflow = state.asks.get_mut(&id).and_then(|ask| ask.body.as_mut());
        let next = match inflow {
            None => Err(None),
            Some(inflow) => match inflow.chunks.pop_front() {
                Some(chunk) => Ok(chunk),
                None => Err(inflow.terminal.clone()),
            },
        };
        let outcome = match next {
            Ok(chunk) => {
                // The consumer holds them now: their credit is owed. Nothing
                // is owed once the stream has ended.
                let _ = state.streams.release(id, chunk.len());
                drop(state);
                body.conn.link.writer.notify_one();
                return Poll::Ready(Ok(Some(chunk)));
            }
            Err(Some(Ok(()))) => Ok(()),
            Err(Some(Err(error))) => Err(error),
            Err(None) if ended || !state.asks.contains_key(&id) => Err(BodyError::Closed),
            Err(None) => {
                if let Some(ask) = state.asks.get_mut(&id) {
                    ask.waker = Some(cx.waker().clone());
                }
                return Poll::Pending;
            }
        };
        // Its end, its abort, or the connection's end: the service is done
        // with it.
        if let Some(ask) = state.asks.get_mut(&id) {
            ask.held = false;
            ask.body = None;
            ask.waker = None;
        }
        prune(&mut state, id);
        drop(state);
        body.ended = Some(outcome.clone());
        Poll::Ready(outcome.map(|()| None))
    }
}

/// Whether a result opens a body: an object whose `body` member is `true`,
/// as 0007's heads say it.
fn opens_body(result: &RawValue) -> Result<bool, End> {
    #[derive(Deserialize)]
    struct Head<'a> {
        #[serde(default, borrow)]
        body: Option<&'a RawValue>,
    }
    if !result.get().trim_start().starts_with('{') {
        return Ok(false);
    }
    let head: Head<'_> =
        serde_json::from_str(result.get()).map_err(|_| End::Protocol("invalid_message"))?;
    Ok(head
        .body
        .is_some_and(|body| serde_json::from_str::<bool>(body.get()).unwrap_or(false)))
}

impl Reader<'_> {
    /// Main's reply to one of the service's requests.
    pub(super) fn response(&mut self, frame: &Frame) -> Result<(), End> {
        let Ok(Message::Response { id, outcome }) = Message::decode(&frame.payload) else {
            return Err(End::Protocol("invalid_message"));
        };
        let (reply, opens) = match outcome {
            Ok(result) => (Ok(result.to_owned()), opens_body(result)?),
            Err(error) => {
                let error = error
                    .parse()
                    .map_err(|_| End::Protocol("invalid_message"))?;
                (Err(AskFailed::Error(error)), false)
            }
        };
        // A head that opens a body, for a request that reserves room for
        // it: its hook runs first, before any of the body is read.
        let reserved = match &reply {
            Ok(result) if opens => self.reserve(id, result),
            _ => None,
        };
        let (waker, unused) = {
            let mut state = self.link.lock();
            if state.end.is_some() {
                drop(state);
                return Ok(());
            }
            let replied = match &reserved {
                Some(Ok(reserved)) => state.streams.answered_sized(id, reserved.len),
                _ => state.streams.answered(id, opens),
            }
            .map_err(|e| End::Protocol(e.category()))?;
            match replied {
                Replied::Deliver => match state.asks.get_mut(&id) {
                    Some(ask) => {
                        let waker = ask.waker.take();
                        let deadline = ask.deadline.take();
                        let refused = match reserved {
                            Some(Err(refusal)) => {
                                ask.reply = Some(Err(AskFailed::Refused(refusal)));
                                true
                            }
                            Some(Ok(Reserved { hold, .. })) => {
                                ask.reply = Some(reply);
                                ask.body = Some(Inflow::default());
                                ask.hold = Some(hold);
                                false
                            }
                            None => {
                                ask.reply = Some(reply);
                                if opens {
                                    ask.body = Some(Inflow::default());
                                }
                                false
                            }
                        };
                        if let Some(at) = deadline {
                            state.deadlines.remove(&(at, id));
                        }
                        // Refused: its body is cancelled before any of it
                        // is read.
                        if refused {
                            withdraw(&mut state, id);
                        }
                        (waker, None)
                    }
                    // Not held: a pending request always is. Its body goes.
                    None => {
                        withdraw(&mut state, id);
                        (None, reserved)
                    }
                },
                // Cancelled before it, or while its hook ran: dropped, and
                // a body it opened is dropped as it comes.
                Replied::Retired => {
                    prune(&mut state, id);
                    (None, reserved)
                }
            }
        };
        // A reservation nobody takes goes outside the lock.
        drop(unused);
        self.link.writer.notify_one();
        wake(waker.into_iter().collect());
        Ok(())
    }

    /// Request `id`'s hook, on main's head that opens its body
    /// ([`Connection::ask_reserving`]): run outside the lock, as a service
    /// callback, unless the service has let go of the request, its deadline
    /// has passed, or the connection has ended. The reader reads nothing
    /// meanwhile, so nothing of the body is read before it returns.
    fn reserve(&self, id: u64, result: &RawValue) -> Option<Result<Reserved, ErrorBody>> {
        let hook = {
            let mut state = self.link.lock();
            if state.end.is_some() {
                return None;
            }
            let ask = state.asks.get_mut(&id)?;
            if !ask.held || ask.reply.is_some() {
                return None;
            }
            let hook = ask.reserve.take()?;
            state.dispatching = true;
            hook
        };
        let reserved = hook(result);
        self.leave();
        Some(reserved)
    }

    /// Data, end or abort of a body main sends in answer to one of the
    /// service's requests.
    pub(super) fn inbound(&mut self, frame: StreamFrame<'_>) -> Result<(), End> {
        let bytes = match &frame {
            StreamFrame::Data { bytes, .. } => Some(*bytes),
            _ => None,
        };
        let terminal = matches!(frame, StreamFrame::End { .. } | StreamFrame::Abort { .. });
        let waker = {
            let mut state = self.link.lock();
            if state.end.is_some() {
                return Ok(());
            }
            let received = state
                .streams
                .receive(frame)
                .map_err(|e| End::Protocol(e.category()))?;
            let arrived = match received {
                Received::Arrived(arrived) => arrived,
                // Credit goes through the sender, never here.
                Received::Credited(_) => return Ok(()),
            };
            let id = match &arrived {
                Arrived::Data { id, .. }
                | Arrived::End { id }
                | Arrived::Abort { id, .. }
                | Arrived::Dropped { id }
                | Arrived::Mismatch { id, .. } => *id,
            };
            let inflow = state.asks.get_mut(&id).and_then(|ask| {
                let inflow = ask.body.as_mut()?;
                Some((inflow, ask.waker.take()))
            });
            match (arrived, inflow) {
                (Arrived::Data { .. }, Some((inflow, waker))) => {
                    inflow
                        .chunks
                        .push_back(bytes.map(<[u8]>::to_vec).unwrap_or_default());
                    waker
                }
                (Arrived::End { .. }, Some((inflow, waker))) => {
                    inflow.terminal = Some(Ok(()));
                    waker
                }
                (Arrived::Abort { abort, .. }, Some((inflow, waker))) => {
                    inflow.terminal = Some(Err(BodyError::Aborted(abort)));
                    waker
                }
                // It broke its reserved length: it fails alone, what it
                // queued goes, and past the length main gets `cancel` (the
                // stream retires, its frames dropped until its terminal).
                (
                    Arrived::Mismatch {
                        declared,
                        received,
                        retire,
                        ..
                    },
                    inflow,
                ) => {
                    let waker = match inflow {
                        Some((inflow, waker)) => {
                            inflow.chunks.clear();
                            inflow.terminal = Some(Err(BodyError::Mismatch { declared, received }));
                            waker
                        }
                        // Never: a reserved body is held until it ends.
                        None => None,
                    };
                    if retire == Retire::SendCancel {
                        state.outbound.push_back(Outgoing::cancel(id));
                    }
                    prune(&mut state, id);
                    waker
                }
                // A body the service let go of: its frames go, and its
                // terminal ends the record.
                (Arrived::Dropped { .. }, _) => {
                    if terminal {
                        prune(&mut state, id);
                    }
                    None
                }
                // An open stream nobody holds: never, as a body is held
                // until its record is let go of. Cancelled, to be safe.
                (_, None) => {
                    withdraw(&mut state, id);
                    prune(&mut state, id);
                    None
                }
            }
        };
        self.link.writer.notify_one();
        wake(waker.into_iter().collect());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;

    use fc_protocol::error::ErrorCode;
    use fc_protocol::stream::InboundState;
    use serde_json::json;

    use super::super::tests::written;
    use super::super::{Hello, Link, Options, Request, Service};
    use super::*;

    struct Idle;

    impl Service for Idle {
        fn hello(
            &self,
            _hello: &Hello,
        ) -> Result<serde_json::Map<String, serde_json::Value>, ErrorBody> {
            Ok(serde_json::Map::new())
        }
        fn request(&self, _conn: &Connection, _request: Request<'_>) {}
        fn cancel(&self, _conn: &Connection, _id: u64) {}
        fn end(&self, _conn: &Connection, _end: End) {}
    }

    fn poll<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
        Pin::new(future).poll(&mut Context::from_waker(Waker::noop()))
    }

    fn json_frame(message: &serde_json::Value) -> Frame {
        Frame {
            kind: frame::KIND_JSON,
            payload: message.to_string().into_bytes().into(),
        }
    }

    /// Review of #334, round 1: the end closes every request of the
    /// service's, waiting for main's reply or reading main's body. Their
    /// unwritten requests, cancels and credit go at once, so the writer
    /// writes none of them, and the service's answers to main are still
    /// written in its teardown. What the service still holds, polled to
    /// `Closed` or dropped, leaves nothing behind.
    #[test]
    fn the_end_leaves_nothing_of_the_services_requests() {
        let mut options = Options::new("t", 1, Instant::now());
        options.exit_watchdog = None;
        options.two_way = true;
        let link = Arc::new(Link::new(&options));
        let conn = Connection { link: link.clone() };
        let service = Idle;
        let mut reader = Reader::new(&link, &conn, &service, &options);
        // The handshake's reply is queued, unwritten, and main's request 2
        // waits for its answer.
        {
            let mut state = link.lock();
            state.streams.request(1).unwrap();
            state.hello_id = Some(1);
            state.hello_done = true;
            state.streams.request(2).unwrap();
        }
        conn.reply(1, &"hello").unwrap();
        // 1 and 2 wait for main's reply, 1 polled after the end and 2
        // dropped; 3 is dropped now, its cancel queued; 4's and 5's bodies
        // are open, 4 read after the end, with credit owed, and 5 dropped.
        let later = Instant::now() + Duration::from_secs(60);
        let mut waiting = conn.ask("t.one", &1, Some(later)).unwrap();
        let dropped = conn.ask("t.two", &2, None).unwrap();
        drop(conn.ask("t.three", &3, None).unwrap());
        let mut fourth = conn.ask("t.four", &4, None).unwrap();
        let mut fifth = conn.ask("t.five", &5, None).unwrap();
        for id in [4u8, 5] {
            let reply = json!({ "type": "response", "id": id, "result": { "body": true } });
            reader.response(&json_frame(&reply)).unwrap();
            let bytes = [id; 3];
            reader
                .inbound(StreamFrame::Data {
                    id: u64::from(id),
                    bytes: &bytes,
                })
                .unwrap();
        }
        let Poll::Ready(Ok(Answer {
            body: Some(mut read),
            ..
        })) = poll(&mut fourth)
        else {
            panic!("4's body");
        };
        let Poll::Ready(Ok(Answer {
            body: Some(held), ..
        })) = poll(&mut fifth)
        else {
            panic!("5's body");
        };
        assert_eq!(poll(&mut read.chunk()), Poll::Ready(Ok(Some(vec![4; 3]))));
        assert!(poll(&mut waiting).is_pending());
        {
            let state = link.lock();
            assert_eq!(state.asks.len(), 5);
            assert_eq!(state.outbound.len(), 6);
            assert_eq!(state.deadlines.len(), 1);
            assert_eq!(
                (state.streams.inbound().outstanding(), state.streams.owed()),
                (5, 1)
            );
        }

        link.end(End::Eof);
        {
            let state = link.lock();
            // 3, let go of, went with the end; the rest wait for the
            // service.
            assert_eq!(state.asks.len(), 4);
            assert!(state.outbound.is_empty());
            assert!(state.deadlines.is_empty());
            assert_eq!(
                (state.streams.inbound().outstanding(), state.streams.owed()),
                (0, 0)
            );
        }
        // Main's late frames are read no more.
        let late = json!({ "type": "response", "id": 1, "result": "late" });
        reader.response(&json_frame(&late)).unwrap();
        reader
            .inbound(StreamFrame::Data { id: 4, bytes: &[9] })
            .unwrap();
        assert!(matches!(
            poll(&mut waiting),
            Poll::Ready(Err(AskFailed::Closed))
        ));
        drop(dropped);
        assert_eq!(poll(&mut read.chunk()), Poll::Ready(Err(BodyError::Closed)));
        drop(held);
        assert_eq!(conn.asks(), 0);
        assert_eq!(link.lock().streams.inbound().outstanding(), 0);
        drop((waiting, read, fourth, fifth));
        assert_eq!(conn.asks(), 0);

        // The teardown answers main's request; nothing of the service's
        // requests is written, and no credit (`written` reads JSON only).
        conn.reply(2, &"bye").unwrap();
        assert_eq!(
            written(&link),
            [
                json!({ "type": "response", "id": 1, "result": "hello" }),
                json!({ "type": "response", "id": 2, "result": "bye" }),
            ]
        );
    }

    /// A two-way link whose handshake is answered, its reply queued.
    fn linked() -> (Options, Arc<Link>, Connection) {
        let mut options = Options::new("t", 1, Instant::now());
        options.exit_watchdog = None;
        options.two_way = true;
        let link = Arc::new(Link::new(&options));
        let conn = Connection { link: link.clone() };
        {
            let mut state = link.lock();
            state.streams.request(1).unwrap();
            state.hello_id = Some(1);
            state.hello_done = true;
        }
        conn.reply(1, &"hello").unwrap();
        (options, link, conn)
    }

    fn head(id: u64, bytes: u64) -> Frame {
        json_frame(&json!({ "type": "response", "id": id,
            "result": { "node": 0, "bytes": bytes, "body": true } }))
    }

    /// Room reserved from a count, given back when dropped.
    struct Room(Arc<AtomicU64>, u64);

    impl Drop for Room {
        fn drop(&mut self) {
            self.0.fetch_sub(self.1, Ordering::SeqCst);
        }
    }

    /// Sets its flag when dropped: a hook dropped uncalled.
    struct Dropped(Arc<AtomicBool>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// A hook that reserves the head's `bytes` from `room`, counting its
    /// calls.
    fn reserving(
        room: &Arc<AtomicU64>,
        calls: &Arc<AtomicUsize>,
    ) -> impl FnOnce(&RawValue) -> Result<Reserved, ErrorBody> + Send + 'static {
        let (room, calls) = (room.clone(), calls.clone());
        move |result| {
            calls.fetch_add(1, Ordering::SeqCst);
            let head: serde_json::Value = serde_json::from_str(result.get()).unwrap();
            let len = head["bytes"].as_u64().unwrap();
            room.fetch_add(len, Ordering::SeqCst);
            Ok(Reserved {
                len,
                hold: Hold::new(Room(room, len)),
            })
        }
    }

    /// Design 0014, "Requests the service makes": the hook sees main's
    /// head before any byte of its body is read, as a service callback,
    /// and the room it reserved goes to the service with the answer.
    #[test]
    fn a_head_is_reserved_before_any_of_its_body_is_read() {
        let (options, link, conn) = linked();
        let service = Idle;
        let mut reader = Reader::new(&link, &conn, &service, &options);
        let room = Arc::new(AtomicU64::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = link.clone();
        let reserve = reserving(&room, &calls);
        let mut asked = conn
            .ask_reserving("shell.t", &json!({}), None, move |result: &RawValue| {
                {
                    let state = seen.lock();
                    // Its stream isn't open yet, and the teardown waits.
                    assert_eq!(
                        state.streams.inbound().info(1).map(|info| info.state),
                        Some(InboundState::Pending)
                    );
                    assert!(state.dispatching);
                }
                reserve(result)
            })
            .unwrap();
        reader.response(&head(1, 5)).unwrap();
        assert_eq!(
            (calls.load(Ordering::SeqCst), room.load(Ordering::SeqCst)),
            (1, 5)
        );
        assert!(!link.lock().dispatching);
        reader
            .inbound(StreamFrame::Data {
                id: 1,
                bytes: &[1, 2, 3],
            })
            .unwrap();
        reader
            .inbound(StreamFrame::Data {
                id: 1,
                bytes: &[4, 5],
            })
            .unwrap();
        reader.inbound(StreamFrame::End { id: 1 }).unwrap();
        let Poll::Ready(Ok(Answer {
            body: Some(mut body),
            hold: Some(hold),
            ..
        })) = poll(&mut asked)
        else {
            panic!("the answer, its body and its hold");
        };
        assert_eq!(
            poll(&mut body.chunk()),
            Poll::Ready(Ok(Some(vec![1, 2, 3])))
        );
        assert_eq!(poll(&mut body.chunk()), Poll::Ready(Ok(Some(vec![4, 5]))));
        assert_eq!(poll(&mut body.chunk()), Poll::Ready(Ok(None)));
        assert_eq!(conn.asks(), 0);
        // The room is the service's until it drops the hold.
        assert_eq!(room.load(Ordering::SeqCst), 5);
        drop(hold);
        assert_eq!(room.load(Ordering::SeqCst), 0);
        drop((body, asked));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A head the hook refuses (0014: `busy`) is cancelled as it is read,
    /// so none of its body is held or credited, and the request fails with
    /// the refusal; the connection goes on.
    #[test]
    fn a_head_the_hook_refuses_is_cancelled_before_its_body() {
        let (options, link, conn) = linked();
        let service = Idle;
        let mut reader = Reader::new(&link, &conn, &service, &options);
        let busy = ErrorBody::new(ErrorCode::Busy, "Colibri fetch busy");
        let refusal = busy.clone();
        let mut asked = conn
            .ask_reserving("shell.t", &json!({}), None, move |_: &RawValue| {
                Err(refusal)
            })
            .unwrap();
        reader.response(&head(1, 1 << 20)).unwrap();
        assert_eq!(
            link.lock().streams.inbound().info(1).map(|info| info.state),
            Some(InboundState::Retiring)
        );
        assert!(matches!(
            poll(&mut asked),
            Poll::Ready(Err(AskFailed::Refused(error))) if error == busy
        ));
        // Main's body, sent before it read the cancel, is dropped as read.
        for _ in 0..2 {
            reader
                .inbound(StreamFrame::Data {
                    id: 1,
                    bytes: &[7; 64 << 10],
                })
                .unwrap();
        }
        assert_eq!(link.lock().streams.owed(), 0);
        assert_eq!(conn.asks(), 1);
        reader
            .inbound(StreamFrame::Abort {
                id: 1,
                abort: Abort::cancelled(),
            })
            .unwrap();
        assert_eq!(conn.asks(), 0);
        drop(asked);
        assert_eq!(
            written(&link),
            [
                json!({ "type": "response", "id": 1, "result": "hello" }),
                json!({ "type": "request", "id": 1, "method": "shell.t", "params": {} }),
                json!({ "type": "cancel", "id": 1 }),
            ]
        );
    }

    /// The hook runs only for a head that opens a body the service can
    /// still take: not for a reply without one, a request let go of or
    /// past its deadline, or after the end. Each is dropped uncalled.
    #[test]
    fn the_hook_runs_only_for_a_body_the_service_can_take() {
        let (options, link, conn) = linked();
        let service = Idle;
        let mut reader = Reader::new(&link, &conn, &service, &options);
        let calls = Arc::new(AtomicUsize::new(0));
        let hook = |dropped: &Arc<AtomicBool>| {
            let (calls, dropped) = (calls.clone(), Dropped(dropped.clone()));
            move |_: &RawValue| {
                let _dropped = dropped;
                calls.fetch_add(1, Ordering::SeqCst);
                Err(ErrorBody::new(ErrorCode::Busy, "busy"))
            }
        };
        let flags: Vec<Arc<AtomicBool>> = (0..4).map(|_| Arc::default()).collect();
        // 1: a reply that opens no body.
        let mut plain = conn
            .ask_reserving("shell.t", &1, None, hook(&flags[0]))
            .unwrap();
        let reply = json!({ "type": "response", "id": 1, "result": { "error": "e" } });
        reader.response(&json_frame(&reply)).unwrap();
        let Poll::Ready(Ok(Answer {
            body: None,
            hold: None,
            ..
        })) = poll(&mut plain)
        else {
            panic!("a plain answer");
        };
        assert!(flags[0].load(Ordering::SeqCst));
        // 2: let go of before main's head, which then opens a retiring
        // stream.
        drop(
            conn.ask_reserving("shell.t", &2, None, hook(&flags[1]))
                .unwrap(),
        );
        assert!(flags[1].load(Ordering::SeqCst));
        reader.response(&head(2, 10)).unwrap();
        reader
            .inbound(StreamFrame::Data { id: 2, bytes: &[1] })
            .unwrap();
        reader.inbound(StreamFrame::End { id: 2 }).unwrap();
        // 3: past its deadline.
        let mut late = conn
            .ask_reserving("shell.t", &3, Some(Instant::now()), hook(&flags[2]))
            .unwrap();
        assert!(matches!(
            poll(&mut late),
            Poll::Ready(Err(AskFailed::Deadline))
        ));
        reader.response(&head(3, 10)).unwrap();
        reader.inbound(StreamFrame::End { id: 3 }).unwrap();
        drop(late);
        assert!(flags[2].load(Ordering::SeqCst));
        assert_eq!(conn.asks(), 0);
        // 4: after the end.
        let mut ended = conn
            .ask_reserving("shell.t", &4, None, hook(&flags[3]))
            .unwrap();
        link.end(End::Eof);
        reader.response(&head(4, 10)).unwrap();
        assert!(matches!(
            poll(&mut ended),
            Poll::Ready(Err(AskFailed::Closed))
        ));
        assert!(flags[3].load(Ordering::SeqCst));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(conn.asks(), 0);
    }

    /// Room reserved for an answer the service never takes goes with the
    /// request: one it lets go of, and one the connection's end closes.
    #[test]
    fn a_reservation_never_taken_goes_with_its_request() {
        let (options, link, conn) = linked();
        let service = Idle;
        let mut reader = Reader::new(&link, &conn, &service, &options);
        let room = Arc::new(AtomicU64::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let dropped = conn
            .ask_reserving("shell.t", &1, None, reserving(&room, &calls))
            .unwrap();
        let mut closed = conn
            .ask_reserving("shell.t", &2, None, reserving(&room, &calls))
            .unwrap();
        reader.response(&head(1, 100)).unwrap();
        reader.response(&head(2, 20)).unwrap();
        assert_eq!(room.load(Ordering::SeqCst), 120);
        // Let go of unpolled: its body is cancelled, its room given back.
        drop(dropped);
        assert_eq!(room.load(Ordering::SeqCst), 20);
        // The end: the answer is still the service's to take, with its
        // room, and dropping it gives the room back.
        link.end(End::Eof);
        let Poll::Ready(Ok(Answer {
            body: Some(mut body),
            hold: Some(hold),
            ..
        })) = poll(&mut closed)
        else {
            panic!("the answer");
        };
        assert_eq!(poll(&mut body.chunk()), Poll::Ready(Err(BodyError::Closed)));
        drop((hold, body, closed));
        assert_eq!(room.load(Ordering::SeqCst), 0);
        assert_eq!(conn.asks(), 0);
    }

    /// Design 0014: a body that breaks its reserved length fails alone.
    /// Past it, what it queued goes and main gets `cancel`; short of it at
    /// its end, its record goes. Another body and the connection go on.
    #[test]
    fn a_body_that_breaks_its_length_fails_alone() {
        let (options, link, conn) = linked();
        let service = Idle;
        let mut reader = Reader::new(&link, &conn, &service, &options);
        let room = Arc::new(AtomicU64::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut long = conn
            .ask_reserving("shell.t", &1, None, reserving(&room, &calls))
            .unwrap();
        let mut plain = conn.ask("shell.t", &2, None).unwrap();
        let mut short = conn
            .ask_reserving("shell.t", &3, None, reserving(&room, &calls))
            .unwrap();
        reader.response(&head(1, 4)).unwrap();
        reader.response(&head(2, 0)).unwrap();
        reader.response(&head(3, 10)).unwrap();
        let mut bodies = [&mut long, &mut plain, &mut short].map(|asked| match poll(asked) {
            Poll::Ready(Ok(Answer {
                body: Some(body), ..
            })) => body,
            other => panic!("{other:?}"),
        });
        let data = |reader: &mut Reader<'_>, id: u64, bytes: &[u8]| {
            reader.inbound(StreamFrame::Data { id, bytes }).unwrap();
        };
        // Body 1: 3 bytes queued, then 2 more, one past its 4.
        data(&mut reader, 1, &[1, 2, 3]);
        data(&mut reader, 2, &[9]);
        data(&mut reader, 3, &[1, 2, 3, 4]);
        data(&mut reader, 1, &[4, 5]);
        assert_eq!(
            poll(&mut bodies[0].chunk()),
            Poll::Ready(Err(BodyError::Mismatch {
                declared: 4,
                received: 5
            }))
        );
        // Main's frames for it, sent before it read the cancel, go.
        data(&mut reader, 1, &[6]);
        assert_eq!(conn.asks(), 3);
        reader
            .inbound(StreamFrame::Abort {
                id: 1,
                abort: Abort::cancelled(),
            })
            .unwrap();
        assert_eq!(conn.asks(), 2);
        // Body 3: 4 of its 10 bytes, then its end.
        reader.inbound(StreamFrame::End { id: 3 }).unwrap();
        assert_eq!(
            poll(&mut bodies[2].chunk()),
            Poll::Ready(Err(BodyError::Mismatch {
                declared: 10,
                received: 4
            }))
        );
        // Its error stays its error.
        assert_eq!(
            poll(&mut bodies[2].chunk()),
            Poll::Ready(Err(BodyError::Mismatch {
                declared: 10,
                received: 4
            }))
        );
        // Body 2, without a length, takes what comes.
        assert_eq!(poll(&mut bodies[1].chunk()), Poll::Ready(Ok(Some(vec![9]))));
        reader.inbound(StreamFrame::End { id: 2 }).unwrap();
        assert_eq!(poll(&mut bodies[1].chunk()), Poll::Ready(Ok(None)));
        assert_eq!((conn.asks(), link.lock().streams.owed()), (0, 0));
        drop(bodies);
        drop((long, plain, short));
        assert_eq!(room.load(Ordering::SeqCst), 0);
        // One cancel, for body 1; credit for body 2's byte went with its
        // end.
        assert_eq!(
            written(&link),
            [
                json!({ "type": "response", "id": 1, "result": "hello" }),
                json!({ "type": "request", "id": 1, "method": "shell.t", "params": 1 }),
                json!({ "type": "request", "id": 2, "method": "shell.t", "params": 2 }),
                json!({ "type": "request", "id": 3, "method": "shell.t", "params": 3 }),
                json!({ "type": "cancel", "id": 1 }),
            ]
        );
    }
}
