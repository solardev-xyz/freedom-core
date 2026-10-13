//! The side that sends bodies: the service (design 0007, Frames).
//!
//! **What it holds, per request** (every request main sends, by its ID):
//! - its state: working, a head queued and unwritten, a stream open, or
//!   its one reply queued;
//! - for a body, its account and its FIFO: the body bytes queued and not
//!   yet written, and whether `end` follows them.
//!
//! **Order.** The writer takes the control queue first (heads, replies,
//! aborts and the replies to `cancel`), then the open streams round-robin,
//! one data frame or `end` each. A stream's data is written only after its
//! head, and `end` only once its last byte has been written. `abort`
//! purges what is queued and goes in the control queue, behind the head if
//! that is still unwritten. Nothing of a stream is written after its
//! terminal.
//!
//! **Credit.** `sent` counts the body bytes queued; `credited` the bytes
//! main returned. A push queues at most `128 KiB − (sent − credited)`, so
//! the debit happens at queueing, and credit beyond `sent` is a protocol
//! error. Nothing is refunded: an abort's purge ends the stream.
//!
//! **Coalescing.** A stream's queued bytes are one FIFO, not one frame per
//! push. The writer cuts each data frame as large as the queue and the
//! 64 KiB limit allow, so a frame under 4 KiB is all that was queued. And
//! what a push queues is all the producer had pending or all the credit
//! allowed, unless the writer's cap cut it: then it is at least 4 KiB, or
//! nothing, and the producer waits for the writer.
//!
//! **Cancel.** Against a request still working, or whose head is queued
//! but unwritten, the head and body are dropped and `cancelled` is the
//! request's one reply; no stream opens. Against an open stream it purges
//! and writes `abort { code: "cancelled" }`, unless the stream's terminal
//! is already settled; then, as for every ID this side doesn't hold, the
//! cancel is late and changes nothing.
//!
//! **Bounds.** The writer holds at most its data cap of queued body bytes
//! across streams (16 MiB by default); a producer that finds no room
//! waits, with its bytes, until credit or the writer makes some. Each
//! stream's FIFO is a chain of 4 KiB blocks, each freed once it is written,
//! so the storage follows the bytes queued: at most two blocks more per
//! stream with bytes queued, and nothing for a drained one, however the
//! pushes and frames were cut. The control queue holds at most three entries per live
//! request: its head, its abort, and the `cancelled` reply that a cancel
//! put in their place. Entries a cancel made stale are skipped when they
//! come up, and all of a request's entries come up before its record goes.

use std::collections::{BTreeMap, VecDeque};

use super::{
    Abort, AbortCode, MAX_DATA, SMALL_FRAME, StreamError, StreamFrame, WINDOW, put_header,
};
use crate::frame::{FrameError, KIND_ABORT, KIND_DATA, KIND_END, KIND_JSON, MAX_PAYLOAD};
use crate::message::check_id;

/// A stream's FIFO is a chain of blocks of this size.
const BLOCK: usize = 4 << 10;

/// Why a producer's call was refused. None of these is a protocol error:
/// the connection is fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// The request's reply or terminal is already settled without this
    /// call (a cancel, an abort, or the end written): stop producing.
    #[error("the request is settled")]
    Gone,
    /// An ID above every request this side has seen.
    #[error("not a request this side has seen")]
    Unknown,
    /// A second head or reply.
    #[error("the request already has its head or reply")]
    Answered,
    /// Body work for a request without a body: no head yet, a head with
    /// `body: false`, or an error reply.
    #[error("the request has no body")]
    NotOpen,
    /// Body work after `finish`.
    #[error("the body is finished")]
    Ended,
    /// A head or reply over one frame, an abort over 1 KiB, or a body over
    /// 2^64 bytes.
    #[error("too large")]
    TooLarge,
    /// The connection failed with a protocol error.
    #[error("the connection failed")]
    Closed,
}

impl SendError {
    /// A fixed name, as `vectors/streams.json` writes it.
    pub fn name(&self) -> &'static str {
        match self {
            SendError::Gone => "gone",
            SendError::Unknown => "unknown",
            SendError::Answered => "answered",
            SendError::NotOpen => "not_open",
            SendError::Ended => "ended",
            SendError::TooLarge => "too_large",
            SendError::Closed => "closed",
        }
    }
}

/// What main's `cancel` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cancel {
    /// The request's `cancelled` reply, or its stream's `cancelled` abort,
    /// is queued: cancel its work.
    Cancelled,
    /// Its reply or terminal was already settled, or the ID isn't one this
    /// side holds: nothing changes.
    Late,
}

/// What a credit frame did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credited {
    /// The credit is in stream `id`'s account: its room grew, and its
    /// producer may push again.
    Taken(u64),
    /// The stream had ended: the credit crossed its terminal and is
    /// ignored.
    Late,
}

/// The frame [`Sender::next_frame`] wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Written {
    /// A head: the request's response. With a body, its stream is open.
    Head { id: u64 },
    /// The request's reply, given to [`Sender::reply`].
    Reply { id: u64 },
    /// The `cancelled` reply that a cancel made the request's only one.
    Cancelled { id: u64 },
    /// `len` body bytes of stream `id`.
    Data { id: u64, len: usize },
    /// Stream `id`'s end: its last byte was written before it.
    End { id: u64 },
    /// Stream `id`'s abort.
    Abort { id: u64, code: AbortCode },
}

#[derive(Debug, Clone, Copy)]
enum Control {
    Head,
    Reply,
    Abort,
}

enum State {
    /// Admitted; nothing queued for it yet.
    Working,
    /// Its head is queued and unwritten. A body may already be queued
    /// behind it.
    Head { json: Vec<u8>, body: Option<Body> },
    /// Its head is written: the stream is open.
    Open(Body),
    /// Its one reply is queued and unwritten.
    Reply { json: Vec<u8>, cancelled: bool },
}

#[derive(Default)]
struct Body {
    /// Queued body bytes, debited and unwritten.
    queue: Fifo,
    sent: u64,
    credited: u64,
    /// `end` follows the queue.
    end: bool,
    /// The abort's code and JSON, once one is queued.
    abort: Option<(AbortCode, Vec<u8>)>,
    /// In the writer's rotation.
    scheduled: bool,
}

impl Body {
    /// What the window still allows queueing.
    fn room(&self) -> usize {
        let in_flight = self.sent.saturating_sub(self.credited);
        usize::try_from(in_flight).map_or(0, |n| WINDOW.saturating_sub(n))
    }

    /// Whether the writer has something of it to write.
    fn writable(&self) -> bool {
        self.abort.is_none() && (!self.queue.is_empty() || self.end)
    }

    /// Drops the queued bytes and their storage; returns how many.
    fn purge(&mut self) -> usize {
        let purged = self.queue.len();
        self.queue = Fifo::default();
        self.end = false;
        purged
    }
}

/// A stream's queued bytes, in blocks of [`BLOCK`]: every block but the
/// last is full, and the first is freed once it has been read.
#[derive(Default)]
struct Fifo {
    blocks: VecDeque<Vec<u8>>,
    /// Where reading resumes in the first block.
    start: usize,
    len: usize,
}

impl Fifo {
    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The storage it takes.
    fn capacity(&self) -> usize {
        self.blocks.iter().map(Vec::capacity).sum()
    }

    fn push(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.blocks.back().is_none_or(|block| block.len() == BLOCK) {
                self.blocks.push_back(Vec::with_capacity(BLOCK));
            }
            let Some(block) = self.blocks.back_mut() else {
                return;
            };
            let (now, rest) = bytes.split_at(bytes.len().min(BLOCK - block.len()));
            block.extend_from_slice(now);
            self.len += now.len();
            bytes = rest;
        }
    }

    /// Moves up to `n` bytes from the front to `out`, freeing each block
    /// that is read to its end.
    fn take(&mut self, n: usize, out: &mut Vec<u8>) {
        let mut n = n.min(self.len);
        while n > 0 {
            let Some(block) = self.blocks.front() else {
                break;
            };
            let part = block.get(self.start..).unwrap_or_default();
            let part = &part[..n.min(part.len())];
            if part.is_empty() {
                break;
            }
            out.extend_from_slice(part);
            let (taken, block_len) = (part.len(), block.len());
            self.start += taken;
            self.len -= taken;
            n -= taken;
            if self.start == block_len && (block_len == BLOCK || self.len == 0) {
                self.blocks.pop_front();
                self.start = 0;
            }
        }
        if self.len == 0 {
            self.blocks.clear();
            self.start = 0;
        }
    }
}

/// The service's side of every stream on one connection.
pub struct Sender {
    data_cap: usize,
    highest: u64,
    requests: BTreeMap<u64, State>,
    control: VecDeque<(Control, u64)>,
    rotation: VecDeque<u64>,
    held: usize,
    failed: Option<StreamError>,
}

impl Default for Sender {
    fn default() -> Self {
        Self::new()
    }
}

impl Sender {
    /// A sender whose writer holds at most 16 MiB of queued data.
    pub fn new() -> Self {
        Self::with_data_cap(super::WRITER_DATA_CAP)
    }

    /// A sender whose writer holds at most `data_cap` bytes of queued data,
    /// and at least 4 KiB, so a producer waiting for the writer's room
    /// always gets enough of it.
    pub fn with_data_cap(data_cap: usize) -> Self {
        Sender {
            data_cap: data_cap.max(SMALL_FRAME),
            highest: 0,
            requests: BTreeMap::new(),
            control: VecDeque::new(),
            rotation: VecDeque::new(),
            held: 0,
            failed: None,
        }
    }

    // ---- main's frames ---------------------------------------------------

    /// A request arrived. Its ID must be above every earlier one.
    pub fn request(&mut self, id: u64) -> Result<(), StreamError> {
        self.alive()?;
        if check_id(id).is_err() {
            return Err(self.fail(StreamError::BadId(id)));
        }
        if id <= self.highest {
            let highest = self.highest;
            return Err(self.fail(StreamError::RequestOrder { id, highest }));
        }
        self.highest = id;
        self.requests.insert(id, State::Working);
        Ok(())
    }

    /// Main's `cancel` for request `id`. It needs no writer room: what it
    /// queues is one control entry, in place of what it drops.
    pub fn cancel(&mut self, id: u64) -> Result<Cancel, StreamError> {
        self.alive()?;
        let Some(state) = self.requests.get_mut(&id) else {
            return Ok(Cancel::Late);
        };
        match state {
            State::Working | State::Head { .. } => {
                if let State::Head {
                    body: Some(body), ..
                } = state
                {
                    self.held -= body.purge();
                }
                *state = State::Reply {
                    json: cancelled_reply(id),
                    cancelled: true,
                };
                self.control.push_back((Control::Reply, id));
                Ok(Cancel::Cancelled)
            }
            State::Open(body) if body.abort.is_none() => {
                self.held -= body.purge();
                body.abort = Some((AbortCode::Cancelled, CANCELLED_ABORT.to_vec()));
                self.control.push_back((Control::Abort, id));
                Ok(Cancel::Cancelled)
            }
            State::Open(_) | State::Reply { .. } => Ok(Cancel::Late),
        }
    }

    /// A stream frame from main: only credit is main's to send.
    pub fn receive(&mut self, frame: StreamFrame<'_>) -> Result<Credited, StreamError> {
        self.alive()?;
        let StreamFrame::Credit { id, bytes } = frame else {
            return Err(self.fail(StreamError::Frame(FrameError::Direction(frame.kind()))));
        };
        if bytes == 0 {
            return Err(self.fail(StreamError::CreditZero));
        }
        if id > self.highest {
            return Err(self.fail(StreamError::Unknown(id)));
        }
        // An ID at or below the highest that isn't live has ended: the
        // credit crossed its terminal.
        let Some(state) = self.requests.get_mut(&id) else {
            return Ok(Credited::Late);
        };
        let credited = match state {
            State::Head {
                body: Some(body), ..
            }
            | State::Open(body) => body
                .credited
                .checked_add(u64::from(bytes))
                .filter(|credited| *credited <= body.sent)
                .map(|credited| body.credited = credited),
            // Nothing of it was ever sent.
            _ => None,
        };
        match credited {
            Some(()) => Ok(Credited::Taken(id)),
            None => Err(self.fail(StreamError::Overgrant(id))),
        }
    }

    // ---- the service's producers -----------------------------------------

    /// Queues request `id`'s head: its `0x01` response, `json`. With `body`,
    /// it opens a stream once written; data may be queued behind it now.
    pub fn head(&mut self, id: u64, json: Vec<u8>, body: bool) -> Result<(), SendError> {
        self.usable()?;
        if json.len() > MAX_PAYLOAD {
            return Err(SendError::TooLarge);
        }
        self.answer(
            id,
            State::Head {
                json,
                body: body.then(Body::default),
            },
            Control::Head,
        )
    }

    /// Queues request `id`'s one reply: an error, or any response without
    /// a body.
    pub fn reply(&mut self, id: u64, json: Vec<u8>) -> Result<(), SendError> {
        self.usable()?;
        if json.len() > MAX_PAYLOAD {
            return Err(SendError::TooLarge);
        }
        self.answer(
            id,
            State::Reply {
                json,
                cancelled: false,
            },
            Control::Reply,
        )
    }

    fn answer(&mut self, id: u64, next: State, entry: Control) -> Result<(), SendError> {
        match self.requests.get_mut(&id) {
            Some(state @ State::Working) => {
                *state = next;
                self.control.push_back((entry, id));
                Ok(())
            }
            Some(State::Reply {
                cancelled: true, ..
            }) => Err(SendError::Gone),
            Some(_) => Err(SendError::Answered),
            None => Err(self.absent(id)),
        }
    }

    /// Queues as much of `bytes` as stream `id`'s window and the writer's
    /// cap allow, and returns how much that was: zero when there is no
    /// room. The producer keeps the rest until [`Sender::room`] grows.
    ///
    /// `bytes` is what the producer has pending now. A push the writer's
    /// cap would cut below 4 KiB takes nothing and waits for the writer, so
    /// that every data frame under 4 KiB is all that was pending or all the
    /// credit allowed (coalescing).
    pub fn push(&mut self, id: u64, bytes: &[u8]) -> Result<usize, SendError> {
        self.usable()?;
        let cap_room = self.data_cap.saturating_sub(self.held);
        let (body, open) = body_of(&mut self.requests, self.highest, id)?;
        let wanted = bytes.len().min(body.room());
        let n = match wanted.min(cap_room) {
            n if n < wanted && n < SMALL_FRAME => 0,
            n => n,
        };
        if n == 0 {
            return Ok(0);
        }
        let sent = u64::try_from(n)
            .ok()
            .and_then(|n| body.sent.checked_add(n))
            .ok_or(SendError::TooLarge)?;
        body.queue.push(&bytes[..n]);
        body.sent = sent;
        self.held += n;
        if open && !body.scheduled {
            body.scheduled = true;
            self.rotation.push_back(id);
        }
        Ok(n)
    }

    /// Queues stream `id`'s end, behind every byte queued so far.
    pub fn finish(&mut self, id: u64) -> Result<(), SendError> {
        self.usable()?;
        let (body, open) = body_of(&mut self.requests, self.highest, id)?;
        body.end = true;
        if open && !body.scheduled {
            body.scheduled = true;
            self.rotation.push_back(id);
        }
        Ok(())
    }

    /// Aborts stream `id`: its queued bytes and end are dropped, and the
    /// abort is queued with the control frames, behind its head if that is
    /// unwritten.
    pub fn abort(&mut self, id: u64, abort: &Abort) -> Result<(), SendError> {
        self.usable()?;
        let json = abort.to_json().map_err(|_| SendError::TooLarge)?;
        let body = match self.requests.get_mut(&id) {
            Some(
                State::Head {
                    body: Some(body), ..
                }
                | State::Open(body),
            ) => body,
            Some(State::Reply {
                cancelled: true, ..
            }) => return Err(SendError::Gone),
            Some(_) => return Err(SendError::NotOpen),
            None => return Err(self.absent(id)),
        };
        if body.abort.is_some() {
            return Err(SendError::Gone);
        }
        self.held -= body.purge();
        body.abort = Some((abort.code, json));
        self.control.push_back((Control::Abort, id));
        Ok(())
    }

    // ---- the writer ------------------------------------------------------

    /// Appends the next frame to write to `out` and says what it was, or
    /// returns `None` when there is nothing to write. Control entries go
    /// first, then the open streams round-robin, one frame each.
    pub fn next_frame(&mut self, out: &mut Vec<u8>) -> Option<Written> {
        if self.failed.is_some() {
            return None;
        }
        while let Some((entry, id)) = self.control.pop_front() {
            if let Some(written) = self.write_control(entry, id, out) {
                return Some(written);
            }
        }
        while let Some(id) = self.rotation.pop_front() {
            if let Some(written) = self.write_stream(id, out) {
                return Some(written);
            }
        }
        None
    }

    /// Writes a control entry, unless a cancel has made it stale: a head
    /// or abort dropped in favour of the `cancelled` reply.
    fn write_control(&mut self, entry: Control, id: u64, out: &mut Vec<u8>) -> Option<Written> {
        let state = self.requests.remove(&id)?;
        match (entry, state) {
            (Control::Head, State::Head { json, body }) => {
                put_json(out, &json);
                if let Some(mut body) = body {
                    if body.writable() {
                        body.scheduled = true;
                        self.rotation.push_back(id);
                    }
                    self.requests.insert(id, State::Open(body));
                }
                Some(Written::Head { id })
            }
            (Control::Reply, State::Reply { json, cancelled }) => {
                put_json(out, &json);
                Some(if cancelled {
                    Written::Cancelled { id }
                } else {
                    Written::Reply { id }
                })
            }
            (
                Control::Abort,
                State::Open(Body {
                    abort: Some((code, json)),
                    ..
                }),
            ) => {
                put_header(out, KIND_ABORT, id, json.len());
                out.extend_from_slice(&json);
                Some(Written::Abort { id, code })
            }
            (_, state) => {
                self.requests.insert(id, state);
                None
            }
        }
    }

    /// Writes one frame of stream `id`, unless it has nothing to write.
    fn write_stream(&mut self, id: u64, out: &mut Vec<u8>) -> Option<Written> {
        let Some(State::Open(body)) = self.requests.get_mut(&id) else {
            return None;
        };
        body.scheduled = false;
        if body.abort.is_some() {
            return None;
        }
        if !body.queue.is_empty() {
            let len = body.queue.len().min(MAX_DATA);
            put_header(out, KIND_DATA, id, len);
            body.queue.take(len, out);
            self.held -= len;
            if body.writable() {
                body.scheduled = true;
                self.rotation.push_back(id);
            }
            return Some(Written::Data { id, len });
        }
        if body.end {
            put_header(out, KIND_END, id, 0);
            self.requests.remove(&id);
            return Some(Written::End { id });
        }
        None
    }

    // ---- what it holds ---------------------------------------------------

    /// How much stream `id`'s producer may push now, at most: its window's
    /// room, within the writer's. A push the writer's cap would cut below
    /// 4 KiB waits instead ([`Sender::push`]). `None` without a body that
    /// takes bytes.
    pub fn room(&self, id: u64) -> Option<usize> {
        let body = match self.requests.get(&id)? {
            State::Head {
                body: Some(body), ..
            }
            | State::Open(body) => body,
            _ => return None,
        };
        if body.end || body.abort.is_some() {
            return None;
        }
        Some(body.room().min(self.data_cap.saturating_sub(self.held)))
    }

    /// Stream `id`'s queued, unwritten body bytes.
    pub fn queued(&self, id: u64) -> Option<usize> {
        match self.requests.get(&id)? {
            State::Head {
                body: Some(body), ..
            }
            | State::Open(body) => Some(body.queue.len()),
            _ => None,
        }
    }

    /// Whether request `id` is still held: not yet answered, or its stream
    /// not yet ended.
    pub fn is_live(&self, id: u64) -> bool {
        self.requests.contains_key(&id)
    }

    /// The live requests.
    pub fn live(&self) -> usize {
        self.requests.len()
    }

    /// Queued body bytes across every stream.
    pub fn held(&self) -> usize {
        self.held
    }

    /// The storage the queued bytes take: at most two 4 KiB blocks more
    /// than [`Sender::held`] per stream with bytes queued.
    pub fn held_capacity(&self) -> usize {
        self.requests
            .values()
            .map(|state| match state {
                State::Head {
                    body: Some(body), ..
                }
                | State::Open(body) => body.queue.capacity(),
                _ => 0,
            })
            .sum()
    }

    /// Control entries waiting, stale ones included: at most three per
    /// live request.
    pub fn control_entries(&self) -> usize {
        self.control.len()
    }

    /// The protocol error the connection failed with, if it did.
    pub fn failed(&self) -> Option<StreamError> {
        self.failed
    }

    fn alive(&self) -> Result<(), StreamError> {
        self.failed.map_or(Ok(()), Err)
    }

    fn usable(&self) -> Result<(), SendError> {
        match self.failed {
            Some(_) => Err(SendError::Closed),
            None => Ok(()),
        }
    }

    fn absent(&self, id: u64) -> SendError {
        if id <= self.highest {
            SendError::Gone
        } else {
            SendError::Unknown
        }
    }

    /// Fails the connection: nothing more is written, and every later call
    /// reports it.
    fn fail(&mut self, error: StreamError) -> StreamError {
        self.failed = Some(error);
        self.requests.clear();
        self.control.clear();
        self.rotation.clear();
        self.held = 0;
        error
    }
}

/// Stream `id`'s body, while it takes bytes, and whether its head is
/// written.
fn body_of(
    requests: &mut BTreeMap<u64, State>,
    highest: u64,
    id: u64,
) -> Result<(&mut Body, bool), SendError> {
    let (body, open) = match requests.get_mut(&id) {
        Some(State::Head {
            body: Some(body), ..
        }) => (body, false),
        Some(State::Open(body)) => (body, true),
        Some(State::Reply {
            cancelled: true, ..
        }) => return Err(SendError::Gone),
        Some(_) => return Err(SendError::NotOpen),
        None if id <= highest => return Err(SendError::Gone),
        None => return Err(SendError::Unknown),
    };
    if body.abort.is_some() {
        return Err(SendError::Gone);
    }
    if body.end {
        return Err(SendError::Ended);
    }
    Ok((body, open))
}

/// The abort a cancel writes on an open stream: [`Abort::cancelled`]'s JSON.
const CANCELLED_ABORT: &[u8] = br#"{"code":"cancelled","message":"Cancelled"}"#;

/// The reply a cancel makes a request's only one.
fn cancelled_reply(id: u64) -> Vec<u8> {
    format!(
        r#"{{"type":"response","id":{id},"error":{{"code":"cancelled","message":"Cancelled"}}}}"#
    )
    .into_bytes()
}

/// Appends a JSON frame; `json` is within one frame, as queueing checked.
fn put_json(out: &mut Vec<u8>, json: &[u8]) {
    let len = u32::try_from(json.len().min(MAX_PAYLOAD) + 1).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.push(KIND_JSON);
    out.extend_from_slice(json);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::WRITER_DATA_CAP;

    fn drain(sender: &mut Sender) -> Vec<Written> {
        let mut out = Vec::new();
        std::iter::from_fn(|| sender.next_frame(&mut out)).collect()
    }

    #[test]
    fn one_byte_pushes_coalesce_within_the_window() {
        let mut s = Sender::new();
        s.request(1).unwrap();
        s.head(1, b"{}".to_vec(), true).unwrap();
        for _ in 0..WINDOW {
            assert_eq!(s.push(1, &[9]).unwrap(), 1);
        }
        assert_eq!(s.push(1, &[9]).unwrap(), 0);
        // One FIFO, never more storage than the window.
        assert_eq!(s.held(), WINDOW);
        assert_eq!(s.held_capacity(), WINDOW);
        assert_eq!(s.queued(1), Some(WINDOW));
        assert_eq!(
            drain(&mut s),
            [
                Written::Head { id: 1 },
                Written::Data {
                    id: 1,
                    len: MAX_DATA
                },
                Written::Data {
                    id: 1,
                    len: MAX_DATA
                }
            ]
        );
        assert_eq!(s.held_capacity(), 0, "a drained FIFO is freed");
    }

    #[test]
    fn storage_follows_the_queued_bytes() {
        let mut s = Sender::new();
        s.request(1).unwrap();
        s.head(1, b"{}".to_vec(), true).unwrap();
        let mut out = Vec::new();
        assert_eq!(s.next_frame(&mut out), Some(Written::Head { id: 1 }));
        let body: Vec<u8> = (0..WINDOW).map(|i| (i % 251) as u8).collect();
        assert_eq!(s.push(1, &body[..10]).unwrap(), 10);
        assert_eq!(s.held_capacity(), BLOCK);
        assert_eq!(s.push(1, &body[10..]).unwrap(), WINDOW - 10);
        assert_eq!(s.held_capacity(), WINDOW);
        // Each block goes once it is written; a partly read one stays.
        out.clear();
        assert_eq!(
            s.next_frame(&mut out),
            Some(Written::Data {
                id: 1,
                len: MAX_DATA
            })
        );
        assert_eq!(out[13..], body[..MAX_DATA]);
        assert_eq!(s.held_capacity(), WINDOW - MAX_DATA);
        assert_eq!(
            s.receive(StreamFrame::Credit { id: 1, bytes: 100 }),
            Ok(Credited::Taken(1))
        );
        assert_eq!(s.push(1, &body[..100]).unwrap(), 100);
        assert_eq!(s.held_capacity(), WINDOW - MAX_DATA + BLOCK);
        out.clear();
        s.next_frame(&mut out).unwrap();
        assert_eq!(out[13..], body[MAX_DATA..]);
        // 100 bytes left, in the last block: one block.
        assert_eq!((s.held(), s.held_capacity()), (100, BLOCK));
        out.clear();
        assert_eq!(
            s.next_frame(&mut out),
            Some(Written::Data { id: 1, len: 100 })
        );
        assert_eq!(out[13..], body[..100]);
        assert_eq!((s.held(), s.held_capacity()), (0, 0));
        assert_eq!(WRITER_DATA_CAP, 16 << 20);
    }

    #[test]
    fn a_fifo_reads_across_blocks() {
        let mut fifo = Fifo::default();
        let bytes: Vec<u8> = (0..3 * BLOCK + 7).map(|i| (i % 253) as u8).collect();
        for piece in bytes.chunks(1000) {
            fifo.push(piece);
        }
        assert_eq!((fifo.len(), fifo.blocks.len()), (bytes.len(), 4));
        let mut out = Vec::new();
        for n in [1, BLOCK - 1, 5, 2 * BLOCK, 100] {
            fifo.take(n, &mut out);
        }
        assert_eq!(out, bytes);
        assert!(fifo.is_empty() && fifo.blocks.is_empty());
        fifo.take(10, &mut out);
        assert_eq!(out.len(), bytes.len());
    }

    #[test]
    fn a_cancels_abort_is_the_cancelled_abort() {
        assert_eq!(Abort::cancelled().to_json().unwrap(), CANCELLED_ABORT);
    }

    #[test]
    fn a_cancelled_reply_is_a_cancelled_error() {
        let json = cancelled_reply(41);
        match crate::message::Message::decode(&json).unwrap() {
            crate::message::Message::Response {
                id,
                outcome: Err(error),
            } => {
                assert_eq!(id, 41);
                assert_eq!(
                    error.parse().unwrap().code,
                    crate::error::ErrorCode::Cancelled
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_writers_cap_never_cuts_a_push_below_4k() {
        let mut s = Sender::with_data_cap(WINDOW + 1000);
        for id in [1, 2] {
            s.request(id).unwrap();
            s.head(id, b"{}".to_vec(), true).unwrap();
        }
        assert_eq!(s.push(1, &[0; WINDOW]).unwrap(), WINDOW);
        // 1000 bytes of cap left: a 5000-byte push waits; an 800-byte one,
        // all that is pending, goes.
        assert_eq!(s.room(2), Some(1000));
        assert_eq!(s.push(2, &[0; 5000]).unwrap(), 0);
        assert_eq!(s.push(2, &[0; 800]).unwrap(), 800);
        // A cap below 4 KiB is raised to it.
        let mut s = Sender::with_data_cap(1);
        s.request(1).unwrap();
        s.head(1, b"{}".to_vec(), true).unwrap();
        assert_eq!(s.push(1, &[0; 5000]).unwrap(), SMALL_FRAME);
    }

    #[test]
    fn oversized_heads_and_aborts_are_refused() {
        let mut s = Sender::new();
        s.request(1).unwrap();
        assert_eq!(
            s.head(1, vec![b' '; MAX_PAYLOAD + 1], true),
            Err(SendError::TooLarge)
        );
        s.head(1, b"{}".to_vec(), true).unwrap();
        let wordy = Abort::new(AbortCode::Internal, "x".repeat(2000));
        assert_eq!(s.abort(1, &wordy), Err(SendError::TooLarge));
    }
}
