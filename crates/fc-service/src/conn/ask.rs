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
}

/// Why a [`Body`] ended before its end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// Main aborted it.
    Aborted(Abort),
    /// The connection ended first.
    Closed,
}

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
}

/// A body from main, as the connection holds it for its consumer.
#[derive(Default)]
struct Inflow {
    /// Data frames' bytes, as they came. At most the window: credit goes
    /// back only for bytes the consumer has taken.
    chunks: VecDeque<Vec<u8>>,
    /// Its end, or main's abort.
    terminal: Option<Result<(), Abort>>,
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
        if let Some(ask) = state.asks.get_mut(&id) {
            ask.held = false;
            ask.waker = None;
            let reply = ask.reply.take();
            let body = ask.body.take();
            let deadline = ask.deadline.take();
            if let Some(at) = deadline {
                state.deadlines.remove(&(at, id));
            }
            drop((reply, body));
        }
        withdraw(&mut state, id);
        prune(&mut state, id);
        drop(state);
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
    /// credit, so the bytes taken are the consumer's to hold.
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
            Err(Some(Err(abort))) => Err(BodyError::Aborted(abort)),
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
        let waker = {
            let mut state = self.link.lock();
            if state.end.is_some() {
                return Ok(());
            }
            let replied = state
                .streams
                .answered(id, opens)
                .map_err(|e| End::Protocol(e.category()))?;
            match replied {
                Replied::Deliver => match state.asks.get_mut(&id) {
                    Some(ask) => {
                        ask.reply = Some(reply);
                        if opens {
                            ask.body = Some(Inflow::default());
                        }
                        let waker = ask.waker.take();
                        if let Some(at) = ask.deadline.take() {
                            state.deadlines.remove(&(at, id));
                        }
                        waker
                    }
                    // Not held: a pending request always is. Its body goes.
                    None => {
                        withdraw(&mut state, id);
                        None
                    }
                },
                // Cancelled before it: dropped, and a body it opened is
                // dropped as it comes.
                Replied::Retired => {
                    prune(&mut state, id);
                    None
                }
            }
        };
        self.link.writer.notify_one();
        wake(waker.into_iter().collect());
        Ok(())
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
                | Arrived::Dropped { id } => *id,
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
                    inflow.terminal = Some(Err(abort));
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
    use std::time::Duration;

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
}
