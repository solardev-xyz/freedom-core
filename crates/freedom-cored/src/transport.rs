//! Stdio transport (design 0001, "Transport"; design 0005, "Frames"):
//!
//! - **Reader thread:** turns stdin into frames.
//!   - **Whole messages** (kind `0x01`) take the reader's [`Credits`]: at
//!     most [`MAX_QUEUED_FRAMES`] frames and [`MAX_QUEUED_FRAME_BYTES`] wait
//!     to be handled at any time, by the event loop or the thread a frame is
//!     forwarded to; beyond that the reader stops reading, which is
//!     backpressure on main.
//!   - **Fragmented responses** don't. Main holds one bulk credit for them.
//!     A begin reserves exactly its declared bytes, outside the queued-frame
//!     credits, and fragments append to that reservation, so the reader
//!     never waits on a fragment. The completed response goes on with a
//!     [`Credit`] whose drop returns main's credit (`0x13`): once its
//!     consumer has handled it, delivered or dropped as late or cancelled.
//!   - **A begin** must name one of the core's [`Pending`] requests, and
//!     claims it. A response read whole retires its request too, and a
//!     whole response for the request in reassembly is a duplicate: either
//!     way each request gets one response, as 0001 requires.
//! - **Writer thread:** one serialized writer for stdout. Each producer has
//!   its own [`Allowance`] of queued frames, so naming traffic can't take
//!   the vault loop's room (0001's reserved control capacity).
//!   - **Whole frames** are written in the order they come.
//!   - **A response over one frame** goes fragmented, and only to a peer
//!     that offered fragments ([`Reply`]). It begins only while the core
//!     holds main's credit, and beginning spends it. Once begun, it is
//!     written to its end, one fragment at a time, with the whole frames
//!     queued meanwhile written between fragments: replies, events, cancels
//!     and the `0x13` credit never wait behind a fragmented response, nor
//!     for main's credit.
//!   - **Requests** never fragment: one over a frame isn't sent, and its
//!     producer completes it as `too_large` (deviation `request-size`), so
//!     request IDs keep their write order and a `cancel` finds its request.
//! - **Consumers never block on the writer,** so the reader always gets its
//!   credits back and main always gets its bulk credit back:
//!   - the writer's queue is unbounded, so handing it a frame never waits;
//!     the allowances bound it instead;
//!   - the vault loop's full allowance means main has stopped reading, and
//!     the core exits rather than buffer without limit;
//!   - naming's frames past its allowance wait in the naming thread, which
//!     keeps taking messages (design 0004);
//!   - the chain thread's replies will wait in its own queue the same way,
//!     past an allowance of one message cap ([`MAX_QUEUED_CHAIN_BYTES`]);
//!     the `test.*` methods stand in for it until then;
//!   - the `0x13` credit is queued from the consumer's drop, never waited
//!     on.
//!
//! Lifecycle events (EOF, framing errors, writer failure, a thread dying) go
//! through an unbounded channel that frames can't fill.

use std::collections::{BTreeSet, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Condvar, Mutex};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::fragment::{self, Delivery, FragmentError, Reassembler, Splitter};
use fc_protocol::frame::{Decoder, MAX_MESSAGE, MAX_PAYLOAD};
use fc_protocol::message;
use zeroize::Zeroizing;

use crate::serve::Event;

const READ_CHUNK: usize = 64 * 1024;
/// Frames read and not yet handled...
pub const MAX_QUEUED_FRAMES: usize = 256;
/// ...and their bytes (a frame alone always passes).
pub const MAX_QUEUED_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// The vault loop's replies waiting for the writer.
pub const MAX_QUEUED_REPLIES: usize = 256;
/// Naming's frames waiting for the writer (design 0004, Bounds: the writer).
pub const MAX_QUEUED_NAMING_BYTES: usize = 8 * 1024 * 1024;
/// The chain thread's bytes waiting for the writer: one message cap
/// (design 0005, Frames). A fragmented reply is charged at its whole size
/// and released as its fragments are written.
pub const MAX_QUEUED_CHAIN_BYTES: usize = MAX_MESSAGE;
/// The most whole frames the writer writes between two fragments of a
/// response, so a steady stream of small frames can't stall it.
const MAX_WHOLE_BETWEEN_FRAGMENTS: usize = 64;

/// Counts frames read and not yet handled, and their bytes.
#[derive(Default)]
pub struct Credits {
    in_flight: Mutex<(usize, usize)>,
    freed: Condvar,
}

impl Credits {
    /// Waits for room for a frame of `len` bytes.
    fn acquire(self: &Arc<Self>, len: usize) -> Credit {
        if let Ok(mut held) = self.in_flight.lock() {
            while held.0 >= MAX_QUEUED_FRAMES
                || (held.0 > 0 && held.1 + len > MAX_QUEUED_FRAME_BYTES)
            {
                held = match self.freed.wait(held) {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
            held.0 += 1;
            held.1 += len;
        }
        Credit(Return::Frame {
            credits: Arc::clone(self),
            len,
        })
    }

    fn release(&self, len: usize) {
        if let Ok(mut held) = self.in_flight.lock() {
            held.0 = held.0.saturating_sub(1);
            held.1 = held.1.saturating_sub(len);
            self.freed.notify_one();
        }
    }
}

/// What a message read from main holds of the reader's room, given back
/// when dropped: once the event loop has handled the message, or the
/// thread it forwarded the message to.
pub struct Credit(Return);

enum Return {
    /// A whole frame's place in [`Credits`].
    Frame { credits: Arc<Credits>, len: usize },
    /// A reassembled response: dropping it returns main's bulk credit.
    Bulk(Arc<Link>),
}

impl Drop for Credit {
    fn drop(&mut self) {
        match &self.0 {
            Return::Frame { credits, len } => credits.release(*len),
            Return::Bulk(link) => link.return_credit(),
        }
    }
}

/// One producer's share of the writer: the frames it has queued and the
/// writer hasn't written yet.
pub struct Allowance {
    held: Mutex<(usize, usize)>,
    max_frames: usize,
    max_bytes: usize,
    /// Set by a refusal; the next release then calls `wake`.
    refused: AtomicBool,
    wake: Mutex<Option<Box<dyn Fn() + Send>>>,
}

impl Allowance {
    pub fn new(max_frames: usize, max_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            held: Mutex::new((0, 0)),
            max_frames,
            max_bytes,
            refused: AtomicBool::new(false),
            wake: Mutex::new(None),
        })
    }

    /// What to call when room frees up after a refusal.
    pub fn on_room(&self, wake: impl Fn() + Send + 'static) {
        if let Ok(mut slot) = self.wake.lock() {
            *slot = Some(Box::new(wake));
        }
    }

    /// Room for a frame of `len` bytes, or `None` when the producer has
    /// used its share (a frame alone always fits).
    pub fn take(self: &Arc<Self>, len: usize) -> Option<Hold> {
        let mut held = self.held.lock().ok()?;
        if held.0 > 0 && (held.0 >= self.max_frames || held.1 + len > self.max_bytes) {
            self.refused.store(true, Ordering::SeqCst);
            return None;
        }
        held.0 += 1;
        held.1 += len;
        Some(Hold {
            allowance: Arc::clone(self),
            len,
        })
    }

    /// The bytes this producer has queued and the writer hasn't written.
    pub fn held_bytes(&self) -> usize {
        self.held.lock().map_or(0, |held| held.1)
    }

    /// Room for a frame however full the share is: for the shutdown drain,
    /// which time bounds instead.
    pub fn force(self: &Arc<Self>, len: usize) -> Hold {
        if let Ok(mut held) = self.held.lock() {
            held.0 += 1;
            held.1 += len;
        }
        Hold {
            allowance: Arc::clone(self),
            len,
        }
    }

    /// Frees `frames` places and `bytes`, and wakes a refused producer.
    fn release(&self, frames: usize, bytes: usize) {
        if let Ok(mut held) = self.held.lock() {
            held.0 = held.0.saturating_sub(frames);
            held.1 = held.1.saturating_sub(bytes);
        }
        if self.refused.swap(false, Ordering::SeqCst)
            && let Ok(wake) = self.wake.lock()
            && let Some(wake) = wake.as_ref()
        {
            wake();
        }
    }
}

/// A queued frame's place in its producer's [`Allowance`], freed once the
/// writer has written it.
pub struct Hold {
    allowance: Arc<Allowance>,
    len: usize,
}

impl Hold {
    /// Frees `len` of the held bytes, as a fragmented response's fragments
    /// are written. Its place goes when the hold is dropped.
    fn release(&mut self, len: usize) {
        let len = len.min(self.len);
        self.len -= len;
        self.allowance.release(0, len);
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.allowance.release(1, self.len);
    }
}

/// What the writer takes.
pub enum Out {
    /// One whole frame, with its place in its producer's allowance.
    Frame {
        frame: Zeroizing<Vec<u8>>,
        hold: Hold,
    },
    /// A response over one frame, to a peer that offered fragments:
    /// written as a begin, fragments and a last fragment once the core holds
    /// main's credit. Its hold is released as its fragments go.
    Fragmented {
        id: u64,
        payload: Zeroizing<Vec<u8>>,
        hold: Hold,
    },
    /// Main returned the core's credit: a waiting response may begin.
    Credit,
}

/// A response, ready for its producer's allowance: one frame, or a payload
/// to fragment.
pub enum Reply {
    Whole(Zeroizing<Vec<u8>>),
    Fragmented {
        id: u64,
        payload: Zeroizing<Vec<u8>>,
    },
}

impl Reply {
    /// Response `id`, serialized as `payload`. A response over one frame is
    /// fragmented, if main offered fragments and it is within the message
    /// cap. `None` when it can't go out at all: the producer replaces it with
    /// a `too_large` failure.
    pub fn new(link: &Link, id: u64, payload: Zeroizing<Vec<u8>>) -> Option<Self> {
        if payload.len() <= MAX_PAYLOAD {
            return frame(&payload).map(Reply::Whole);
        }
        (link.offered() && payload.len() <= MAX_MESSAGE)
            .then_some(Reply::Fragmented { id, payload })
    }

    /// The bytes it charges to its producer's allowance.
    pub fn len(&self) -> usize {
        match self {
            Reply::Whole(frame) => frame.len(),
            Reply::Fragmented { payload, .. } => payload.len(),
        }
    }

    pub fn into_out(self, hold: Hold) -> Out {
        match self {
            Reply::Whole(frame) => Out::Frame { frame, hold },
            Reply::Fragmented { id, payload } => Out::Fragmented { id, payload, hold },
        }
    }
}

/// The bulk-credit state both threads and the producers share (design
/// 0005, Frames).
pub struct Link {
    /// Main offered fragments in its hello.
    offered: AtomicBool,
    /// The core holds main's credit: it may begin a fragmented response.
    credit: AtomicBool,
    /// A consumer has returned main's credit since the reader last looked.
    returned: AtomicBool,
    /// The writer's queue, for the frames the transport sends itself (the
    /// `0x13` credit) and its wake-ups. Taken at exit, so the writer can
    /// finish once the producers have.
    writer: Mutex<Option<Sender<Out>>>,
    /// The `0x13` frames' share of the writer. Main can begin again only
    /// once its credit is back, so a few at most are ever queued.
    control: Arc<Allowance>,
}

impl Link {
    pub fn new() -> Arc<Self> {
        Arc::new(Link {
            offered: AtomicBool::new(false),
            credit: AtomicBool::new(false),
            returned: AtomicBool::new(false),
            writer: Mutex::new(None),
            control: Allowance::new(usize::MAX, usize::MAX),
        })
    }

    /// Main offered fragments (`frames: ["fragment"]` in its hello): the
    /// handshake grants the core main's credit.
    pub fn offer(&self) {
        self.offered.store(true, Ordering::SeqCst);
        self.credit.store(true, Ordering::SeqCst);
    }

    /// Whether main offered fragments.
    pub fn offered(&self) -> bool {
        self.offered.load(Ordering::SeqCst)
    }

    /// Stops the transport's own frames, so the writer ends with the
    /// producers' queues.
    pub fn detach(&self) {
        if let Ok(mut writer) = self.writer.lock() {
            *writer = None;
        }
    }

    fn attach(&self, writer: Sender<Out>) {
        if let Ok(mut slot) = self.writer.lock() {
            *slot = Some(writer);
        }
    }

    fn send(&self, out: Out) {
        if let Ok(writer) = self.writer.lock()
            && let Some(writer) = writer.as_ref()
        {
            let _ = writer.send(out);
        }
    }

    fn holds_credit(&self) -> bool {
        self.credit.load(Ordering::SeqCst)
    }

    /// The writer begins a response: spent before the begin is written, so
    /// main's `0x13` can't come first.
    fn spend_credit(&self) -> bool {
        self.credit
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Main returned the core's credit. False when it owed none: it never
    /// offered fragments, or the core holds the credit already.
    fn restore_credit(&self) -> bool {
        self.offered()
            && self
                .credit
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
    }

    /// Whether a consumer has returned main's credit since the last call.
    fn took_return(&self) -> bool {
        self.returned.swap(false, Ordering::SeqCst)
    }

    /// A reassembled response has been handled: main may begin again. The
    /// reader learns it before main can, from the `0x13` queued after.
    fn return_credit(&self) {
        self.returned.store(true, Ordering::SeqCst);
        let frame = Zeroizing::new(fragment::credit_frame().to_vec());
        let hold = self.control.force(frame.len());
        self.send(Out::Frame { frame, hold });
    }
}

/// The core's own requests to main whose response hasn't started arriving:
/// a begin must name one (design 0005, Frames). The reader retires an ID as
/// soon as its response appears, whole or begun; its producer retires it
/// once the response is consumed, which covers producers tested without a
/// reader.
#[derive(Default)]
pub struct Pending {
    ids: Mutex<BTreeSet<u64>>,
}

impl Pending {
    /// Before the request goes to the writer, so its response can't come
    /// first.
    pub fn insert(&self, id: u64) {
        if let Ok(mut ids) = self.ids.lock() {
            ids.insert(id);
        }
    }

    /// Once its response has been read, or consumed.
    pub fn remove(&self, id: u64) {
        if let Ok(mut ids) = self.ids.lock() {
            ids.remove(&id);
        }
    }

    /// Retires `id` for a response that begins: true if it was pending.
    fn take(&self, id: u64) -> bool {
        self.ids.lock().is_ok_and(|mut ids| ids.remove(&id))
    }

    #[cfg(test)]
    pub fn contains(&self, id: u64) -> bool {
        self.ids.lock().is_ok_and(|ids| ids.contains(&id))
    }
}

/// Reports a thread that ends by panicking.
pub struct DeathNotice {
    events: Sender<Event>,
    name: &'static str,
}

impl DeathNotice {
    pub fn new(events: Sender<Event>, name: &'static str) -> Self {
        DeathNotice { events, name }
    }
}

impl Drop for DeathNotice {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let _ = self.events.send(Event::ThreadDied(self.name));
        }
    }
}

/// The reader's side of the stream.
struct Reader {
    events: Sender<Event>,
    credits: Arc<Credits>,
    link: Arc<Link>,
    pending: Arc<Pending>,
    decoder: Decoder,
    reassembler: Reassembler,
}

/// Reads stdin until EOF or a framing error.
pub fn spawn_reader(
    events: Sender<Event>,
    credits: Arc<Credits>,
    link: Arc<Link>,
    pending: Arc<Pending>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("stdin".into())
        .spawn(move || {
            let _notice = DeathNotice {
                events: events.clone(),
                name: "stdin",
            };
            let mut stdin = std::io::stdin().lock();
            let mut buffer = Zeroizing::new(vec![0u8; READ_CHUNK]);
            let mut reader = Reader {
                events,
                credits,
                link,
                pending,
                decoder: Decoder::new(),
                // The core always offers fragments: the handshake grants
                // main its credit. No begin can name a pending request
                // before then.
                reassembler: Reassembler::new(),
            };
            loop {
                let read = match stdin.read(&mut buffer[..]) {
                    Ok(0) => {
                        let _ = reader.events.send(Event::Eof {
                            at_boundary: reader.decoder.is_at_boundary(),
                            // The partial response is discarded with the
                            // reassembler.
                            in_response: reader.reassembler.in_progress(),
                        });
                        return;
                    }
                    Ok(read) => read,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        let _ = reader.events.send(Event::Eof {
                            at_boundary: false,
                            in_response: reader.reassembler.in_progress(),
                        });
                        return;
                    }
                };
                if !reader.feed(&buffer[..read]) {
                    return;
                }
            }
        })
}

impl Reader {
    /// Decodes `input` and hands its frames on. False when reading must
    /// stop.
    fn feed(&mut self, mut input: &[u8]) -> bool {
        // The decoder takes input up to its budget; hand its frames on, then
        // feed it the rest.
        while !input.is_empty() {
            let consumed = match self.decoder.push(input) {
                Ok(consumed) => consumed,
                Err(e) => {
                    let _ = self.events.send(Event::ProtocolError(frame_category(&e)));
                    return false;
                }
            };
            input = &input[consumed..];
            while let Some(frame) = self.decoder.pop() {
                if !self.deliver(frame) {
                    return false;
                }
            }
        }
        true
    }

    fn deliver(&mut self, frame: fc_protocol::frame::Frame) -> bool {
        // A consumer returned main's credit: main may begin again.
        if self.link.took_return() {
            self.reassembler.grant();
        }
        let pending = &self.pending;
        match self.reassembler.push(frame, |id| pending.take(id)) {
            Ok(Delivery::Message { frame, answers }) => {
                // Answered: no begin may follow for that request.
                if let Some(id) = answers {
                    self.pending.remove(id);
                }
                let credit = self.credits.acquire(frame.payload.len());
                self.events.send(Event::Frame(frame, credit)).is_ok()
            }
            // Outside the frame credits: the begin reserved it, and main's
            // credit bounds it to one at a time.
            Ok(Delivery::Response { id, payload }) => self
                .events
                .send(Event::Response {
                    id,
                    payload,
                    credit: Credit(Return::Bulk(Arc::clone(&self.link))),
                })
                .is_ok(),
            Ok(Delivery::Credit) => {
                if !self.link.restore_credit() {
                    let _ = self.events.send(Event::ProtocolError("unsolicited_credit"));
                    return false;
                }
                self.link.send(Out::Credit);
                true
            }
            Ok(Delivery::Taken) => true,
            Err(e) => {
                let _ = self
                    .events
                    .send(Event::ProtocolError(fragment_category(&e)));
                false
            }
        }
    }
}

fn frame_category(error: &fc_protocol::frame::FrameError) -> &'static str {
    match error {
        fc_protocol::frame::FrameError::BadLength(_) => "bad_frame_length",
        fc_protocol::frame::FrameError::UnknownKind(_) => "unknown_frame_kind",
    }
}

fn fragment_category(error: &FragmentError) -> &'static str {
    match error {
        FragmentError::NoCredit => "begin_without_credit",
        FragmentError::UnknownId(_) => "begin_unknown_id",
        FragmentError::DuplicateResponse(_) => "duplicate_response",
        FragmentError::BadSize(_) => "begin_size",
        FragmentError::BadHeader => "begin_header",
        FragmentError::EmptyFragment => "empty_fragment",
        FragmentError::NoResponse => "fragment_without_begin",
        FragmentError::LengthMismatch { .. } => "fragment_length",
        FragmentError::CreditPayload => "credit_payload",
        FragmentError::UnexpectedKind(_) => "unknown_frame_kind",
    }
}

/// The writer's handles: its queue, bounded by each producer's
/// [`Allowance`], and a signal when it finishes.
pub struct Writer {
    pub queue: Sender<Out>,
    pub done: Receiver<()>,
}

/// Writes framed messages to stdout until the queue closes.
pub fn spawn_writer(events: Sender<Event>, link: Arc<Link>) -> std::io::Result<Writer> {
    let (queue, frames) = mpsc::channel::<Out>();
    let (done_tx, done) = mpsc::channel();
    link.attach(queue.clone());
    std::thread::Builder::new()
        .name("stdout".into())
        .spawn(move || {
            let _notice = DeathNotice {
                events: events.clone(),
                name: "stdout",
            };
            let mut stdout = std::io::stdout().lock();
            if write_frames(&mut stdout, &frames, &link).is_err() {
                let _ = events.send(Event::WriterFailed);
                return;
            }
            let _ = done_tx.send(());
        })?;
    Ok(Writer { queue, done })
}

/// A fragmented response, waiting for main's credit or being written.
struct Bulk {
    id: u64,
    payload: Zeroizing<Vec<u8>>,
    hold: Hold,
}

/// Writes what `queue` brings until it closes and nothing more can go: whole
/// frames in order, and fragmented responses one at a time, each begun
/// only while the core holds main's credit and then written to its end.
/// Whole frames go first, so between two fragments the writer writes the
/// whole frames queued meanwhile (at most [`MAX_WHOLE_BETWEEN_FRAGMENTS`]).
fn write_frames<W: Write>(sink: &mut W, queue: &Receiver<Out>, link: &Link) -> std::io::Result<()> {
    let mut waiting: VecDeque<Bulk> = VecDeque::new();
    let mut sending: Option<(Bulk, Splitter)> = None;
    let mut open = true;
    let mut whole_since_fragment = 0;
    loop {
        let fragment_due = sending.is_some() || (!waiting.is_empty() && link.holds_credit());
        if open && (!fragment_due || whole_since_fragment < MAX_WHOLE_BETWEEN_FRAGMENTS) {
            // Whole frames first: what the queue holds, or, with no
            // fragment due, whatever it brings next.
            let next = if fragment_due {
                match queue.try_recv() {
                    Ok(out) => Some(out),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Disconnected) => {
                        open = false;
                        None
                    }
                }
            } else {
                queue.recv().ok().or_else(|| {
                    open = false;
                    None
                })
            };
            if let Some(out) = next {
                match out {
                    Out::Frame { frame, hold } => {
                        sink.write_all(&frame)?;
                        sink.flush()?;
                        // Written: its place in the producer's allowance is
                        // free.
                        drop(hold);
                        whole_since_fragment += 1;
                    }
                    Out::Fragmented { id, payload, hold } => {
                        waiting.push_back(Bulk { id, payload, hold });
                    }
                    // `holds_credit` says so now.
                    Out::Credit => {}
                }
                continue;
            }
        }
        if sending.is_none()
            && !waiting.is_empty()
            && link.spend_credit()
            && let Some(bulk) = waiting.pop_front()
        {
            sending = begin(sink, bulk, link)?;
        }
        if let Some((bulk, splitter)) = sending.as_mut() {
            let ended = match splitter.next_fragment() {
                Some((header, range)) => {
                    let len = range.len();
                    sink.write_all(&header)?;
                    sink.write_all(&bulk.payload[range])?;
                    sink.flush()?;
                    bulk.hold.release(len);
                    splitter.is_done()
                }
                // The splitter ends with its last fragment: unreachable.
                None => true,
            };
            if ended {
                sending = None;
            }
            whole_since_fragment = 0;
            continue;
        }
        if !open {
            // Closed, and what still waits has no credit to begin with.
            return Ok(());
        }
    }
}

/// Writes `bulk`'s begin frame, the credit already spent. A response that
/// can't begin (unreachable: [`Reply::new`] checked its size, and its ID is
/// main's) gives the credit back and fails with `too_large` instead, so its
/// request still gets its one response.
fn begin<W: Write>(
    sink: &mut W,
    bulk: Bulk,
    link: &Link,
) -> std::io::Result<Option<(Bulk, Splitter)>> {
    match Splitter::begin(bulk.id, bulk.payload.len()) {
        Ok((begin, splitter)) => {
            sink.write_all(&begin)?;
            Ok(Some((bulk, splitter)))
        }
        Err(_) => {
            link.credit.store(true, Ordering::SeqCst);
            let error = ErrorBody::new(ErrorCode::TooLarge, "Response too large");
            let mut payload = Zeroizing::new(Vec::with_capacity(128));
            if message::write_error(&mut *payload, bulk.id, &error).is_ok()
                && let Some(frame) = frame(&payload)
            {
                sink.write_all(&frame)?;
                sink.flush()?;
            }
            Ok(None)
        }
    }
}

/// Frames one JSON message.
pub fn frame(payload: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(payload.len() + 5));
    fc_protocol::frame::encode_json(payload, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fc_protocol::fragment::Begin;
    use fc_protocol::frame::{KIND_BEGIN, KIND_CREDIT, KIND_FRAGMENT, KIND_JSON};

    #[test]
    fn an_allowance_refuses_past_its_share_and_wakes_once_freed() {
        let allowance = Allowance::new(usize::MAX, 10);
        let woken = Arc::new(Mutex::new(0));
        let count = Arc::clone(&woken);
        allowance.on_room(move || *count.lock().unwrap() += 1);
        let first = allowance.take(8).unwrap();
        assert!(allowance.take(3).is_none());
        // Freed after a refusal: one wake.
        drop(first);
        assert_eq!(*woken.lock().unwrap(), 1);
        // A frame alone always fits, whatever its size.
        let big = allowance.take(64).unwrap();
        let small = allowance.take(1);
        assert!(small.is_none());
        drop(big);
        assert_eq!(*woken.lock().unwrap(), 2);
        let frames = Allowance::new(1, usize::MAX);
        let _one = frames.take(1).unwrap();
        assert!(frames.take(1).is_none());
    }

    #[test]
    fn a_partly_released_hold_frees_its_bytes_and_wakes() {
        let allowance = Allowance::new(usize::MAX, 10);
        let woken = Arc::new(Mutex::new(0));
        let count = Arc::clone(&woken);
        allowance.on_room(move || *count.lock().unwrap() += 1);
        let mut bulk = allowance.take(10).unwrap();
        assert!(allowance.take(4).is_none());
        // Its fragments go: room for the next frame, before the last one.
        bulk.release(6);
        assert_eq!(allowance.held_bytes(), 4);
        assert_eq!(*woken.lock().unwrap(), 1);
        let next = allowance.take(4).unwrap();
        bulk.release(100);
        assert_eq!(allowance.held_bytes(), 4);
        drop(bulk);
        drop(next);
        assert_eq!(allowance.held_bytes(), 0);
        assert_eq!(*allowance.held.lock().unwrap(), (0, 0));
    }

    #[test]
    fn credits_bound_bytes_as_well_as_frames() {
        let credits = Arc::new(Credits::default());
        let big = credits.acquire(MAX_QUEUED_FRAME_BYTES);
        let waiter = {
            let credits = Arc::clone(&credits);
            std::thread::spawn(move || drop(credits.acquire(1)))
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!waiter.is_finished(), "the next frame waits for room");
        drop(big);
        waiter.join().unwrap();
    }

    /// What a peer reads: whole messages as JSON, fragmented responses
    /// reassembled, credit frames counted, in order.
    #[derive(Debug, PartialEq)]
    enum Seen {
        Message(serde_json::Value),
        Begin(u64),
        Fragment,
        Response(u64, Vec<u8>),
        Credit,
    }

    fn read_back(bytes: &[u8]) -> Vec<Seen> {
        let mut decoder = Decoder::new();
        let mut reassembler = Reassembler::new();
        let mut seen = Vec::new();
        let mut input = bytes;
        while !input.is_empty() {
            let consumed = decoder.push(input).unwrap();
            input = &input[consumed..];
            while let Some(frame) = decoder.pop() {
                let kind = frame.kind;
                if kind == KIND_BEGIN {
                    seen.push(Seen::Begin(Begin::decode(&frame.payload).unwrap().id));
                }
                match reassembler.push(frame, |_| true).unwrap() {
                    Delivery::Message { frame, .. } => {
                        assert_eq!(frame.kind, KIND_JSON);
                        seen.push(Seen::Message(
                            serde_json::from_slice(&frame.payload).unwrap(),
                        ));
                    }
                    Delivery::Response { id, payload } => {
                        seen.push(Seen::Response(id, payload.to_vec()));
                        reassembler.grant();
                    }
                    Delivery::Credit => seen.push(Seen::Credit),
                    Delivery::Taken if kind == KIND_FRAGMENT => seen.push(Seen::Fragment),
                    Delivery::Taken => {}
                }
            }
        }
        assert!(decoder.is_at_boundary() && !reassembler.in_progress());
        seen
    }

    fn whole(allowance: &Arc<Allowance>, json: &serde_json::Value) -> Out {
        let frame = frame(json.to_string().as_bytes()).unwrap();
        let hold = allowance.take(frame.len()).unwrap();
        Out::Frame { frame, hold }
    }

    fn large(allowance: &Arc<Allowance>, link: &Link, id: u64, len: usize) -> (Out, Vec<u8>) {
        let payload: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
        let reply = Reply::new(link, id, Zeroizing::new(payload.clone())).unwrap();
        assert!(matches!(reply, Reply::Fragmented { .. }));
        let hold = allowance.take(reply.len()).unwrap();
        (reply.into_out(hold), payload)
    }

    fn offered() -> Arc<Link> {
        let link = Link::new();
        link.offer();
        link
    }

    #[test]
    fn replies_fragment_only_over_a_frame_and_only_when_offered() {
        let link = Link::new();
        let small = Zeroizing::new(vec![b'x'; MAX_PAYLOAD]);
        let big = Zeroizing::new(vec![b'x'; MAX_PAYLOAD + 1]);
        let over = Zeroizing::new(vec![b'x'; MAX_MESSAGE + 1]);
        // Not offered: one frame at most, as before.
        assert!(
            matches!(Reply::new(&link, 1, small.clone()), Some(Reply::Whole(f)) if f.len() == MAX_PAYLOAD + 5)
        );
        assert!(Reply::new(&link, 1, big.clone()).is_none());
        link.offer();
        assert!(matches!(Reply::new(&link, 1, small), Some(Reply::Whole(_))));
        assert!(matches!(
            Reply::new(&link, 1, big),
            Some(Reply::Fragmented { id: 1, .. })
        ));
        assert!(Reply::new(&link, 1, over).is_none());
        assert!(matches!(
            Reply::new(&link, 1, Zeroizing::new(vec![b'x'; MAX_MESSAGE])),
            Some(Reply::Fragmented { .. })
        ));
    }

    #[test]
    fn a_response_waits_for_credit_while_whole_frames_go() {
        let link = offered();
        let producer = Allowance::new(usize::MAX, MAX_QUEUED_CHAIN_BYTES);
        let control = Allowance::new(usize::MAX, usize::MAX);
        let (queue, frames) = mpsc::channel();
        let (a, a_bytes) = large(&producer, &link, 5, 2 * MAX_PAYLOAD + 7);
        let (b, b_bytes) = large(&producer, &link, 6, MAX_PAYLOAD + 1);
        queue.send(a).unwrap();
        queue.send(b).unwrap();
        queue
            .send(whole(&control, &serde_json::json!({ "n": 1 })))
            .unwrap();
        drop(queue);
        let mut out = Vec::new();
        write_frames(&mut out, &frames, &link).unwrap();
        // A spends the credit; B waits for it and never begins, while the
        // whole frame still goes.
        assert_eq!(
            read_back(&out),
            [
                Seen::Message(serde_json::json!({ "n": 1 })),
                Seen::Begin(5),
                Seen::Fragment,
                Seen::Fragment,
                Seen::Response(5, a_bytes),
            ]
        );
        assert!(!link.holds_credit());
        // A is released as written; B, unsent, is dropped with the writer.
        assert_eq!(producer.held_bytes(), 0);

        // Main's credit comes back (as the reader passes it on): B begins.
        let link = offered();
        let (queue, frames) = mpsc::channel();
        let (a, a_bytes2) = large(&producer, &link, 5, 2 * MAX_PAYLOAD + 7);
        let (b, _) = large(&producer, &link, 6, MAX_PAYLOAD + 1);
        queue.send(a).unwrap();
        queue.send(b).unwrap();
        let link2 = Arc::clone(&link);
        let writer = std::thread::spawn(move || {
            let mut out = Vec::new();
            write_frames(&mut out, &frames, &link2).unwrap();
            out
        });
        // Whatever the writer is doing, a whole frame goes, and the credit.
        queue
            .send(whole(&control, &serde_json::json!({ "n": 2 })))
            .unwrap();
        while link.holds_credit() {
            std::thread::yield_now();
        }
        assert!(link.restore_credit());
        queue.send(Out::Credit).unwrap();
        drop(queue);
        let seen = read_back(&writer.join().unwrap());
        let responses: Vec<_> = seen
            .iter()
            .filter_map(|s| match s {
                Seen::Response(id, bytes) => Some((*id, bytes.len())),
                _ => None,
            })
            .collect();
        assert_eq!(responses, [(5, a_bytes2.len()), (6, b_bytes.len())]);
        assert!(seen.contains(&Seen::Message(serde_json::json!({ "n": 2 }))));
    }

    /// A sink that queues a whole frame the moment the first fragment's
    /// bytes reach it, as a reply made while a response is being written.
    struct Interrupting {
        out: Vec<u8>,
        inject: Option<(Sender<Out>, Out)>,
    }

    impl Write for Interrupting {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.out.extend_from_slice(buf);
            if buf.len() == 5
                && buf[4] == KIND_FRAGMENT
                && let Some((queue, out)) = self.inject.take()
            {
                queue.send(out).unwrap();
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn whole_frames_go_between_fragments() {
        let link = offered();
        let producer = Allowance::new(usize::MAX, MAX_QUEUED_CHAIN_BYTES);
        let control = Allowance::new(usize::MAX, usize::MAX);
        let (queue, frames) = mpsc::channel();
        let (a, a_bytes) = large(&producer, &link, 9, 3 * MAX_PAYLOAD);
        queue.send(a).unwrap();
        let mut sink = Interrupting {
            out: Vec::new(),
            inject: Some((
                queue,
                whole(&control, &serde_json::json!({ "type": "event" })),
            )),
        };
        write_frames(&mut sink, &frames, &link).unwrap();
        assert_eq!(
            read_back(&sink.out),
            [
                Seen::Begin(9),
                Seen::Fragment,
                Seen::Message(serde_json::json!({ "type": "event" })),
                Seen::Fragment,
                Seen::Response(9, a_bytes),
            ]
        );
    }

    #[test]
    fn a_steady_stream_of_whole_frames_cannot_stall_a_response() {
        let link = offered();
        let producer = Allowance::new(usize::MAX, MAX_QUEUED_CHAIN_BYTES);
        let control = Allowance::new(usize::MAX, usize::MAX);
        let (queue, frames) = mpsc::channel();
        let (a, _) = large(&producer, &link, 9, 2 * MAX_PAYLOAD + 1);
        queue.send(a).unwrap();
        for n in 0..(3 * MAX_WHOLE_BETWEEN_FRAGMENTS) {
            queue
                .send(whole(&control, &serde_json::json!({ "n": n })))
                .unwrap();
        }
        drop(queue);
        let mut out = Vec::new();
        write_frames(&mut out, &frames, &link).unwrap();
        let seen = read_back(&out);
        let at = |wanted: fn(&Seen) -> bool| seen.iter().position(wanted).unwrap();
        // The first 64 whole frames, then a fragment, and so on.
        assert_eq!(
            at(|s| matches!(s, Seen::Begin(9))),
            MAX_WHOLE_BETWEEN_FRAGMENTS
        );
        assert_eq!(
            at(|s| matches!(s, Seen::Response(9, _))),
            3 * MAX_WHOLE_BETWEEN_FRAGMENTS + 3
        );
    }

    #[test]
    fn credit_comes_back_when_a_reassembled_response_is_dropped() {
        let link = offered();
        let (queue, frames) = mpsc::channel();
        link.attach(queue);
        assert!(!link.took_return());
        drop(Credit(Return::Bulk(Arc::clone(&link))));
        // The reader learns it first; then the 0x13 frame is queued.
        assert!(link.took_return());
        assert!(!link.took_return());
        match frames.try_recv() {
            Ok(Out::Frame { frame, .. }) => {
                assert_eq!(frame.as_slice(), [0, 0, 0, 1, KIND_CREDIT]);
            }
            _ => panic!("no credit frame"),
        }
        // After exit, nothing is queued.
        link.detach();
        drop(Credit(Return::Bulk(Arc::clone(&link))));
        assert!(matches!(frames.try_recv(), Err(TryRecvError::Disconnected)));
    }

    #[test]
    fn main_returns_only_a_credit_it_owes() {
        // Not offered: any credit is unsolicited.
        let link = Link::new();
        assert!(!link.restore_credit());
        // Offered: held from the handshake, so a credit is unsolicited until
        // a response has begun.
        link.offer();
        assert!(!link.restore_credit());
        assert!(link.spend_credit());
        assert!(!link.spend_credit());
        assert!(link.restore_credit());
        assert!(!link.restore_credit());
    }

    fn reader(link: Arc<Link>, pending: &[u64]) -> (Reader, Receiver<Event>) {
        let (events, received) = mpsc::channel();
        let ids = Arc::new(Pending::default());
        for id in pending {
            ids.insert(*id);
        }
        let reader = Reader {
            events,
            credits: Arc::new(Credits::default()),
            link,
            pending: ids,
            decoder: Decoder::new(),
            reassembler: Reassembler::new(),
        };
        (reader, received)
    }

    /// A fragmented response's frames, `chunk` bytes per fragment at most.
    fn fragmented(id: u64, response: &[u8]) -> Vec<u8> {
        let (mut stream, mut splitter) = Splitter::begin(id, response.len()).unwrap();
        while let Some((header, range)) = splitter.next_fragment() {
            stream.extend_from_slice(&header);
            stream.extend_from_slice(&response[range]);
        }
        stream
    }

    #[test]
    fn the_reader_reassembles_and_returns_credit_after_its_consumer() {
        let (mut reader, received) = reader(offered(), &[4, 5]);
        let response = br#"{"type":"response","id":4,"result":"abc"}"#;
        let stream = fragmented(4, response);
        // A whole message between the begin and the last fragment: decoded
        // at once, with a frame credit.
        let split = stream.len() - response.len() - 5;
        let mut input = stream[..split].to_vec();
        fc_protocol::frame::encode_json(br#"{"type":"cancel","id":3}"#, &mut input).unwrap();
        input.extend_from_slice(&stream[split..]);
        assert!(reader.feed(&input));
        assert!(matches!(received.try_recv(), Ok(Event::Frame(f, _)) if f.kind == KIND_JSON));
        let Ok(Event::Response {
            id: 4,
            payload,
            credit,
        }) = received.try_recv()
        else {
            panic!("no response");
        };
        assert_eq!(payload.as_slice(), response);
        // Its consumer is done with it: main may begin again.
        drop(credit);
        assert!(reader.feed(&fragmented(5, b"{}")));
        assert!(matches!(
            received.try_recv(),
            Ok(Event::Response { id: 5, .. })
        ));
    }

    #[test]
    fn the_reader_never_waits_on_a_fragment() {
        let (mut reader, received) = reader(offered(), &[4]);
        // Whole frames left unhandled fill the queued-frame credits...
        let held = reader.credits.acquire(MAX_QUEUED_FRAME_BYTES);
        let credits = Arc::clone(&reader.credits);
        // ...yet a response of 3 MiB in fragments still goes through: the
        // begin reserved its bytes, outside them.
        let response = format!(
            r#"{{"type":"response","id":4,"result":"{}"}}"#,
            "x".repeat(3 << 20)
        );
        let (done, finished) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(reader.feed(&fragmented(4, response.as_bytes())));
        });
        assert_eq!(
            finished.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(true),
            "the reader waited"
        );
        assert!(matches!(
            received.try_recv(),
            Ok(Event::Response { id: 4, .. })
        ));
        assert_eq!(
            *credits.in_flight.lock().unwrap(),
            (1, MAX_QUEUED_FRAME_BYTES)
        );
        drop(held);
    }

    #[test]
    fn the_reader_refuses_a_begin_for_no_pending_request() {
        let (mut reader, received) = reader(offered(), &[4]);
        assert!(!reader.feed(&fragmented(8, b"{}")));
        assert!(matches!(
            received.try_recv(),
            Ok(Event::ProtocolError("begin_unknown_id"))
        ));
    }

    #[test]
    fn each_request_gets_one_response_across_a_begin() {
        let whole = |json: &str| {
            let mut frame = Vec::new();
            fc_protocol::frame::encode_json(json.as_bytes(), &mut frame).unwrap();
            frame
        };
        // A begin claims its request; a whole response for another one
        // still passes, and retires that one.
        let (mut first, received) = reader(offered(), &[4, 5]);
        let (begin, _) = Splitter::begin(4, 10).unwrap();
        assert!(first.feed(&begin));
        assert!(!first.pending.contains(4));
        assert!(first.feed(&whole(r#"{"type":"response","id":5,"result":{}}"#)));
        assert!(matches!(received.try_recv(), Ok(Event::Frame(..))));
        assert!(!first.pending.contains(5));
        // A whole response for the request whose response has begun is its
        // second.
        assert!(!first.feed(&whole(
            r#"{"type":"response","id":4,"error":{"code":"internal","message":"x"}}"#
        )));
        assert!(matches!(
            received.try_recv(),
            Ok(Event::ProtocolError("duplicate_response"))
        ));

        // The other way round: once a response was read whole, a begin for
        // its request names nothing pending, whether or not its consumer
        // has handled the response yet.
        let (mut second, received) = reader(offered(), &[4]);
        assert!(second.feed(&whole(r#"{"type":"response","id":4,"result":{}}"#)));
        assert!(matches!(received.try_recv(), Ok(Event::Frame(..))));
        assert!(!second.feed(&fragmented(4, b"{}")));
        assert!(matches!(
            received.try_recv(),
            Ok(Event::ProtocolError("begin_unknown_id"))
        ));
    }

    #[test]
    fn the_reader_refuses_a_begin_before_credit_returns() {
        let (mut reader, received) = reader(offered(), &[4, 5]);
        let mut stream = fragmented(4, b"{}");
        stream.extend_from_slice(&fragmented(5, b"{}"));
        assert!(!reader.feed(&stream));
        // The first is delivered; its credit is still held, so the second
        // begin is a protocol error.
        assert!(matches!(
            received.try_recv(),
            Ok(Event::Response { id: 4, .. })
        ));
        assert!(matches!(
            received.try_recv(),
            Ok(Event::ProtocolError("begin_without_credit"))
        ));
    }

    #[test]
    fn the_reader_passes_main_credit_to_the_writer() {
        let link = offered();
        let (queue, frames) = mpsc::channel();
        link.attach(queue);
        // Unsolicited while the core holds the credit.
        let (mut first, received) = reader(Arc::clone(&link), &[]);
        assert!(!first.feed(&fragment::credit_frame()));
        assert!(matches!(
            received.try_recv(),
            Ok(Event::ProtocolError("unsolicited_credit"))
        ));
        // Owed once a response has begun: the writer is woken.
        let (mut second, _received) = reader(Arc::clone(&link), &[]);
        assert!(link.spend_credit());
        assert!(second.feed(&fragment::credit_frame()));
        assert!(link.holds_credit());
        assert!(matches!(frames.try_recv(), Ok(Out::Credit)));
    }
}
