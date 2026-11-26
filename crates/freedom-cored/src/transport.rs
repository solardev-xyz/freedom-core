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
//!   - **Each request's bound** (design 0015, "The swarm thread's memory";
//!     SWM-4, D4): the request's entry in [`Pending`] carries the most
//!     bytes its reply may take, which its owner reserved before sending
//!     it. A begin past it is a protocol error before anything is reserved
//!     (`begin_over_bound`), and so is a whole reply past it
//!     (`reply_over_bound`). The bound stays until the reply is read, also
//!     after the core cancels the request: a cancel doesn't recall a reply
//!     already sent (0001). Every request but the Swarm thread's has the
//!     message cap.
//!   - **Stream frames** (design 0009, Streams in the core) are decoded on
//!     every connection (`Kinds::CORE_STREAMS`), and taken only once the
//!     hello, which settles protocol 2, has set the link's streams flag
//!     ([`Link::streams`]); before that, one is `unknown_frame_kind`. The
//!     core speaks no other version: protocol 1, which took none, is gone.
//!     They go on in the order read, with the whole messages, to the event
//!     loop, which hands each stream's entry to its owner ([`StreamRoutes`]:
//!     the dweb thread unless a route says otherwise, design 0015's D4),
//!     outside the frame credits: the reader never waits on a stream's
//!     data. Main's credit bounds the data in flight (16 MiB for the dweb
//!     thread's streams, 4 MiB for the Swarm thread's), not the frames that
//!     carry it, so the reader coalesces them, one entry per stream
//!     ([`StreamMark`]), under a hard memory cap that holds the most a peer
//!     within credit can send, whatever its framing: past
//!     [`MAX_QUEUED_STREAM_BYTES`] (or [`MAX_QUEUED_STREAM_ENTRIES`], a
//!     defence) not yet handled, the connection ends (`stream_backlog`).
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
//!   - **Progress:** the writer notes when it last wrote a frame
//!     ([`Link::last_write`]), which moves only while main reads stdout.
//! - **Consumers never block on the writer,** so they keep handling what
//!   reaches them, and main's bulk credit comes back once its response is
//!   read:
//!   - the writer's queue is unbounded, so handing it a frame never waits;
//!     the allowances bound it instead;
//!   - the vault loop's frames past its allowance wait in the loop, and
//!     meanwhile it takes no new request (`serve`, design 0001): requests
//!     keep their credits, so the reader stops reading, which is
//!     backpressure on main. The loop still runs its timers, the auto-lock
//!     among them, and handles everything else that reaches it, a
//!     `vault.lock` or `core.shutdown` among the waiting requests included.
//!     It exits only once the writer has written nothing for a long bound:
//!     then main has stopped reading;
//!   - naming's frames past its allowance wait in the naming thread, which
//!     keeps taking messages (design 0004);
//!   - the chain thread's replies wait in its own queue the same way, past
//!     an allowance of one message cap ([`MAX_QUEUED_CHAIN_BYTES`]); its
//!     cancels, small replies and requests have an allowance of their own
//!     ([`MAX_QUEUED_CHAIN_CONTROL_BYTES`]), so they never wait behind a
//!     bulk reply;
//!   - the `0x13` credit is queued from the consumer's drop, never waited
//!     on.
//! - **A hold's guard** ([`Hold::guard`]): a producer may hang what its
//!   reply keeps alive (the Swarm thread's memory charge for a read, design
//!   0015) on the reply's hold, so it goes when the writer has written the
//!   reply, its last fragment for a fragmented one, or drops it unwritten.
//!
//! Lifecycle events (EOF, framing errors, writer failure, a thread dying) go
//! through an unbounded channel that frames can't fill.
//!
//! **No stray copies of secret frames** (design 0001, "Secrets in memory";
//! #79). Both threads use stdin and stdout through their own duplicates of
//! the descriptors (handles), never through std's buffered `Stdin` and
//! `Stdout`: std copies a write smaller than its 1 KiB `LineWriter` buffer
//! into that buffer, and a flush resets its length, never its bytes, so a
//! `vault.export_private_key` or `vault.export_mnemonic` reply stayed there until
//! later frames happened to overwrite it. The reader wipes each part of the
//! chunk it read as soon as the decoder has copied it into the frames' own
//! wiped buffers, before it hands on any frame: a delivery can wait for
//! credit, and a `password_b64` mustn't wait in the chunk meanwhile, nor
//! for a later read to cover it.

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::fragment::{self, Delivery, FragmentError, Reassembler, Splitter};
use fc_protocol::frame::{Decoder, Kinds, MAX_MESSAGE, MAX_PAYLOAD};
use fc_protocol::message;
use zeroize::{Zeroize, Zeroizing};

use crate::serve::Event;

const READ_CHUNK: usize = 64 * 1024;
/// Frames read and not yet handled...
pub const MAX_QUEUED_FRAMES: usize = 256;
/// ...and their bytes (a frame alone always passes).
pub const MAX_QUEUED_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// The vault loop's replies and events waiting for the writer. Past it,
/// they wait in the loop, which then takes no new request.
pub const MAX_QUEUED_REPLIES: usize = 256;
/// Naming's frames waiting for the writer (design 0004, Bounds: the writer).
pub const MAX_QUEUED_NAMING_BYTES: usize = 8 * 1024 * 1024;
/// The chain thread's bytes waiting for the writer: one message cap
/// (design 0005, Frames). A fragmented reply is charged at its whole size
/// and released as its fragments are written.
pub const MAX_QUEUED_CHAIN_BYTES: usize = MAX_MESSAGE;
/// The chain thread's control frames waiting for the writer, apart from its
/// bulk replies: cancels, small replies and its requests to main, so a
/// bulk reply waiting for main's credit can't hold them up (0001's
/// reserved control capacity).
pub const MAX_QUEUED_CHAIN_CONTROL_BYTES: usize = 4 * 1024 * 1024;
/// The most whole frames the writer writes between two fragments of a
/// response, so a steady stream of small frames can't stall it.
const MAX_WHOLE_BETWEEN_FRAGMENTS: usize = 64;
/// Stream frames read and not yet handled by their owners (design 0009,
/// Streams in the core; design 0015, D4), as the memory they hold. They
/// wait coalesced, one entry per stream ([`StreamMark`]): a piece's data
/// joined in the order read, with its terminal, or main's credit for one
/// of the core's bodies, summed. Each entry is charged
/// [`STREAM_ENTRY_COST`] and its buffers, so the cap is the most a peer
/// within credit can make them hold, whatever its framing: the dweb
/// thread's share and the Swarm thread's.
pub const MAX_QUEUED_STREAM_BYTES: usize = DWEB_STREAM_SHARE + SWARM_STREAM_SHARE;
/// The dweb thread's share of [`MAX_QUEUED_STREAM_BYTES`]:
/// - each of the 128 incoming streams ([`STREAMS`]) a whole 128 KiB window
///   of data (its buffer grows by powers of two, so to the window at most)
///   and its terminal at its largest, an abort with all of its 1 KiB of
///   JSON;
/// - one more such stream's worth: the entry the dweb thread is handling
///   while the same stream's next one gathers;
/// - a credit entry for each body main can credit ([`MAIN_FETCHES`]).
///
/// 129 × (131,072 + 1,032 + 2,048) + 256 × 2,048 = 17,829,896 bytes,
/// 16 MiB and 1,052,680 (design 0009, Bounds).
pub const DWEB_STREAM_SHARE: usize =
    (STREAMS + 1) * PIECE_ENTRY_MOST + MAIN_FETCHES * STREAM_ENTRY_COST;
/// The Swarm thread's share of [`MAX_QUEUED_STREAM_BYTES`] (design 0015,
/// D4), counted as the dweb thread's is:
/// - each of its [`SWARM_STREAMS`] incoming streams a whole window and its
///   largest terminal, and one more such stream's worth for the entry it
///   is handling;
/// - a credit entry for each of its uploads ([`SWARM_BODIES`]).
///
/// 33 × 134,152 + 4 × 2,048 = 4,435,208 bytes, about 4.23 MiB.
pub const SWARM_STREAM_SHARE: usize =
    (SWARM_STREAMS + 1) * PIECE_ENTRY_MOST + SWARM_BODIES * STREAM_ENTRY_COST;
/// The incoming streams with credit at once (the engine's bound).
const STREAMS: usize = crate::dweb::engine::STREAMS;
/// The Swarm thread's incoming streams with credit at once (design 0015,
/// D4): its 4 MiB allowance of stream credit ([`SWARM_STREAM_ALLOWANCE`])
/// in windows of 128 KiB, since every stream starts with one. Its driver
/// keeps to them.
pub const SWARM_STREAMS: usize = 32;
/// The stream credit the Swarm thread's incoming streams take, apart from
/// the dweb thread's 16 MiB (design 0015, Streams).
pub const SWARM_STREAM_ALLOWANCE: usize = 4 << 20;
/// The `swarm.body` uploads streaming at once (design 0015, Streams and
/// Budgets): main credits each.
pub const SWARM_BODIES: usize = 4;
/// The bodies main can credit at once: only one whose fetch it holds, and
/// it holds at most 256 fetches (design 0009, Bounds: fetch admission).
/// A credit past a body's end is late, and main sends none after reading
/// the end.
pub const MAIN_FETCHES: usize = 256;
/// The most a piece's entry holds within credit: its window's data, its
/// largest terminal, and the entry itself.
const PIECE_ENTRY_MOST: usize = fc_protocol::stream::WINDOW
    + fc_protocol::stream::ID_LEN
    + fc_protocol::stream::MAX_ABORT
    + STREAM_ENTRY_COST;
/// The most entries waiting at once: a defence only, which a peer within
/// credit can't reach (it has at most one entry per stream, and one being
/// handled). The byte cap stops a flood of entries first, at about 8,700.
pub const MAX_QUEUED_STREAM_ENTRIES: usize = 16 * 1024;
/// What an entry holds beyond its buffers: its mark's slot in the event
/// loop's channel or the dweb thread's mailbox ([`STREAM_SLOT`]), its place
/// in the backlog's two maps (a whole B-tree node of each, since a map has
/// no more nodes than entries), and the allocator's slack for its two
/// buffers. Checked below.
pub const STREAM_ENTRY_COST: usize = 2048;
/// A mark's slot in a channel: the message and std's state word beside it.
/// `serve::Event` and the dweb thread's mail are checked against it where
/// they are defined ([`stream_slot_fits`]).
pub const STREAM_SLOT: usize = 256;
/// The allocator's header and rounding for one allocation: glibc's malloc
/// adds at most 24 bytes to a request (an 8-byte header, 16-byte steps,
/// 32-byte chunks at least).
pub const STREAM_ALLOC_SLACK: usize = 32;
/// What one node of a std B-tree map with `kv`-byte entries takes, at most:
/// its 11 keys and values, 12 edges, its parent link and lengths, and the
/// allocator's slack.
const fn btree_node(kv: usize) -> usize {
    11 * kv + 12 * 8 + 32 + STREAM_ALLOC_SLACK
}
/// One node of each of the backlog's maps ([`Backlog`]).
const PENDING_NODE: usize =
    btree_node(std::mem::size_of::<u64>() + std::mem::size_of::<(StreamEntry, usize)>());
const OPEN_NODE: usize = btree_node(std::mem::size_of::<StreamKey>() + std::mem::size_of::<u64>());
const _: () =
    assert!(STREAM_SLOT + PENDING_NODE + OPEN_NODE + 2 * STREAM_ALLOC_SLACK <= STREAM_ENTRY_COST);
// The window is a power of two, so a buffer grown by powers of two to hold
// it is the window; the figure is 0009's; and a peer within credit (one
// entry per stream and body, and one being handled) is within the entry
// bound.
const _: () = assert!(fc_protocol::stream::WINDOW.is_power_of_two());
const _: () = assert!(DWEB_STREAM_SHARE == 16 * 1024 * 1024 + 1_052_680);
const _: () = assert!(SWARM_STREAM_SHARE == 4_435_208);
const _: () = assert!(MAX_QUEUED_STREAM_BYTES == 17_829_896 + 4_435_208);
const _: () = assert!(
    STREAMS + 1 + MAIN_FETCHES + SWARM_STREAMS + 1 + SWARM_BODIES <= MAX_QUEUED_STREAM_ENTRIES
);
// The Swarm thread's slots are its allowance in windows (design 0015, D4),
// and its uploads' windows are 0015's 512 KiB.
const _: () = assert!(SWARM_STREAMS * fc_protocol::stream::WINDOW == SWARM_STREAM_ALLOWANCE);
const _: () = assert!(SWARM_BODIES * fc_protocol::stream::WINDOW == 512 * 1024);

/// Whether a channel message of `size` bytes that carries a stream mark is
/// within [`STREAM_SLOT`], with the state word std's channels keep beside
/// it.
pub const fn stream_slot_fits(size: usize) -> bool {
    size + std::mem::size_of::<usize>() <= STREAM_SLOT
}
/// The swarm thread's answers to `swarm.request` waiting for the writer:
/// one message cap, as the chain thread's (design 0015, "The swarm
/// thread's memory": what an answer holds is within its request's charges
/// until the writer has written it).
pub const MAX_QUEUED_SWARM_BYTES: usize = MAX_MESSAGE;
/// The swarm thread's control frames waiting for the writer, apart from
/// its large answers: its requests to main, its cancels and its small
/// answers (0001's reserved control capacity).
pub const MAX_QUEUED_SWARM_CONTROL_BYTES: usize = 4 * 1024 * 1024;
/// The dweb thread's frames handed to the writer and not yet written: a
/// few frames' worth. Its bodies wait in its own sender instead, within
/// 0009's 8 MiB writer allowance, where its control frames (credit,
/// heads, replies, cancels) still go first.
pub const MAX_QUEUED_DWEB_BYTES: usize = 1024 * 1024;

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
            guard: None,
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
            guard: None,
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
/// writer has written it, with whatever its producer hung on it
/// ([`Hold::guard`]).
pub struct Hold {
    allowance: Arc<Allowance>,
    len: usize,
    /// Dropped with the hold, after its place is freed.
    guard: Option<Box<dyn Send>>,
}

impl Hold {
    /// Hangs `guard` on the hold: it is dropped when the hold is, once the
    /// writer has written the frame (a fragmented reply's last fragment),
    /// or drops it unwritten at its end. The Swarm thread's memory charge
    /// for a read goes this way, as its reply is written (design 0015,
    /// "The swarm thread's memory").
    pub fn guard(mut self, guard: impl Send + 'static) -> Self {
        self.guard = Some(Box::new(guard));
        self
    }

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
        drop(self.guard.take());
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

/// The state both threads and the producers share: bulk credit (design
/// 0005, Frames), and the writer's progress.
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
    /// When the writer last wrote and flushed a frame, whole or a fragment.
    last_write: Mutex<Option<Instant>>,
    /// The hello settled protocol 2: the reader takes stream frames.
    streams: AtomicBool,
    /// Stream frames read and not yet handled, coalesced ([`StreamMark`]).
    stream_backlog: Mutex<Backlog>,
}

impl Link {
    pub fn new() -> Arc<Self> {
        Arc::new(Link {
            offered: AtomicBool::new(false),
            credit: AtomicBool::new(false),
            returned: AtomicBool::new(false),
            writer: Mutex::new(None),
            control: Allowance::new(usize::MAX, usize::MAX),
            last_write: Mutex::new(None),
            streams: AtomicBool::new(false),
            stream_backlog: Mutex::new(Backlog::default()),
        })
    }

    /// The hello settled protocol 2 (design 0009), the only version the
    /// core speaks: from now on the reader takes stream frames. Set before the hello's reply is queued, so no
    /// stream frame main sends after reading it can be refused.
    pub fn enable_streams(&self) {
        self.streams.store(true, Ordering::SeqCst);
    }

    /// Whether the reader takes stream frames.
    pub fn streams(&self) -> bool {
        self.streams.load(Ordering::SeqCst)
    }

    /// A stream frame, read: it joins its stream's entry, or starts one,
    /// whose mark goes to the dweb thread. A refusal is the protocol error:
    /// the frame's own, or `stream_backlog` past the cap.
    fn push_stream(
        self: &Arc<Self>,
        frame: fc_protocol::frame::Frame,
    ) -> Result<Option<StreamMark>, &'static str> {
        use fc_protocol::stream::StreamFrame;
        enum Kind {
            Data,
            Terminal,
            Credit(u32),
        }
        let (id, kind) = match StreamFrame::from_frame(&frame).map_err(|e| e.category())? {
            StreamFrame::Data { id, .. } => (id, Kind::Data),
            StreamFrame::End { id } | StreamFrame::Abort { id, .. } => (id, Kind::Terminal),
            StreamFrame::Credit { id, bytes } => (id, Kind::Credit(bytes)),
        };
        let mut backlog = self.stream_backlog.lock().map_err(|_| BACKLOG)?;
        match kind {
            Kind::Data => {
                let data = frame
                    .payload
                    .get(fc_protocol::stream::ID_LEN..)
                    .unwrap_or_default();
                backlog.data(self, id, data)
            }
            Kind::Terminal => backlog.terminal(self, id, frame),
            Kind::Credit(bytes) => backlog.credit(self, id, bytes),
        }
    }

    /// Stream frames read and not yet handled: their charge, and how many
    /// entries hold them.
    #[cfg(test)]
    pub fn stream_backlog(&self) -> (usize, usize) {
        self.stream_backlog
            .lock()
            .map_or((0, 0), |held| (held.bytes, held.entries))
    }

    /// What the waiting entries hold, counted from them: each mark's slot
    /// as an `Event`, the buffers as allocated with the allocator's slack,
    /// and a node of each map per entry (a map has no more nodes).
    #[cfg(test)]
    pub fn stream_memory(&self) -> usize {
        let Ok(held) = self.stream_backlog.lock() else {
            return 0;
        };
        let slot = std::mem::size_of::<crate::serve::Event>() + std::mem::size_of::<usize>();
        let buffers: usize = held
            .pending
            .values()
            .map(|(entry, _)| match entry {
                StreamEntry::Piece { data, terminal, .. } => {
                    data.capacity() + terminal.as_ref().map_or(0, |f| f.payload.capacity())
                }
                StreamEntry::Credit { .. } => 0,
            })
            .sum();
        held.pending.len() * (slot + 2 * STREAM_ALLOC_SLACK + PENDING_NODE)
            + held.open.len() * OPEN_NODE
            + buffers
    }

    /// When the writer last wrote a frame: its progress, which moves only
    /// while main reads stdout. The vault loop watches it while its frames
    /// wait for room.
    pub fn last_write(&self) -> Option<Instant> {
        self.last_write.lock().ok().and_then(|at| *at)
    }

    /// The writer wrote and flushed a frame `at` then.
    pub(crate) fn wrote(&self, at: Instant) {
        if let Ok(mut last) = self.last_write.lock() {
            *last = Some(at);
        }
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

/// The writer's progress, watched for a producer whose frames wait past its
/// allowance: while they wait, since when the writer has written nothing,
/// since they started waiting or since its last write if later. Once that
/// lasts the stall bound, main has stopped reading, and the core exits
/// (design 0001). The vault loop watches its frames so, and the swarm
/// thread its own (design 0015): each producer that holds new requests
/// while its frames wait.
pub struct Watchdog {
    link: Arc<Link>,
    /// Since when frames have waited.
    since: Option<Instant>,
    /// The stall bound.
    stall: Duration,
}

impl Watchdog {
    pub fn new(link: Arc<Link>, stall: Duration) -> Self {
        Watchdog {
            link,
            since: None,
            stall,
        }
    }

    /// Whether frames wait `now`: a wait starts its clock, its end stops it.
    pub fn waiting(&mut self, waiting: bool, now: Instant) {
        if !waiting {
            self.since = None;
        } else if self.since.is_none() {
            self.since = Some(now);
        }
    }

    /// While frames wait, since when the writer has written nothing.
    pub fn still(&self) -> Option<Instant> {
        let since = self.since?;
        Some(self.link.last_write().map_or(since, |at| at.max(since)))
    }

    /// When the stall bound passes unless the writer moves: the producer
    /// wakes then to look.
    pub fn deadline(&self) -> Option<Instant> {
        self.still()?.checked_add(self.stall)
    }

    /// How long frames have waited with the writer writing nothing, once
    /// that is the stall bound or more: main has stopped reading.
    pub fn stalled(&self, now: Instant) -> Option<Duration> {
        let waited = now.saturating_duration_since(self.still()?);
        (waited >= self.stall).then_some(waited)
    }
}

/// The protocol error past the stream cap.
const BACKLOG: &str = "stream_backlog";

/// A stream, as the reader and the routes know it: main's frames for the
/// core's pieces (data and terminals) and its credit for the core's bodies
/// name two sets of streams, each in its requester's ID space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StreamKey {
    /// A body main sends in answer to the core's request: its ID.
    Piece(u64),
    /// A body the core sends in answer to main's request: its ID.
    Body(u64),
}

/// One stream's frames, read and not yet handled, coalesced.
pub enum StreamEntry {
    /// A piece's data, joined in the order read, and its terminal (`end` or
    /// `abort`, as read) once it has come: nothing joins after it.
    Piece {
        id: u64,
        data: Vec<u8>,
        terminal: Option<fc_protocol::frame::Frame>,
    },
    /// Main's credit for one of the core's bodies, summed.
    Credit { id: u64, bytes: u64 },
}

impl StreamEntry {
    /// Its stream.
    fn key(&self) -> StreamKey {
        match self {
            StreamEntry::Piece { id, .. } => StreamKey::Piece(*id),
            StreamEntry::Credit { id, .. } => StreamKey::Body(*id),
        }
    }
}

/// The stream frames read and not yet handled ([`MAX_QUEUED_STREAM_BYTES`]).
/// An entry is made by its stream's first frame, whose mark goes to the
/// dweb thread in the order read, with the whole messages; the stream's
/// next frames join it until the thread takes it. So a piece's head, a
/// message read before its first frame, still reaches the thread first,
/// and its terminal comes after its data. A frame that joins an entry is
/// handled with it, before messages read between them: none of those is
/// about that stream's data (a cancel of the request only drops it).
#[derive(Default)]
struct Backlog {
    /// The entries' charge, and how many there are.
    bytes: usize,
    entries: usize,
    /// The next entry's number.
    next: u64,
    /// The entries not yet taken, by number, each with its charge.
    pending: BTreeMap<u64, (StreamEntry, usize)>,
    /// The entry each stream's next frame joins. A piece's entry leaves
    /// here at its terminal, and any entry once taken.
    open: BTreeMap<StreamKey, u64>,
}

/// A buffer's size for `len` bytes: the next power of two, so a window's
/// data takes the window at most, and joining frames one by one copies
/// each byte about twice.
fn room_for(len: usize) -> Result<usize, &'static str> {
    len.checked_next_power_of_two().ok_or(BACKLOG)
}

impl Backlog {
    /// Takes `bytes` more under the cap, and one entry more if `entry`.
    fn admit(&mut self, bytes: usize, entry: bool) -> Result<(), &'static str> {
        let total = self
            .bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_QUEUED_STREAM_BYTES)
            .ok_or(BACKLOG)?;
        if entry && self.entries >= MAX_QUEUED_STREAM_ENTRIES {
            return Err(BACKLOG);
        }
        self.bytes = total;
        self.entries += usize::from(entry);
        Ok(())
    }

    /// Gives back an entry's charge, once it has been handled or dropped.
    fn release(&mut self, charge: usize) {
        self.bytes = self.bytes.saturating_sub(charge);
        self.entries = self.entries.saturating_sub(1);
    }

    fn insert(
        &mut self,
        link: &Arc<Link>,
        open: Option<StreamKey>,
        entry: StreamEntry,
        charge: usize,
    ) -> StreamMark {
        let seq = self.next;
        self.next += 1;
        let key = entry.key();
        self.pending.insert(seq, (entry, charge));
        if let Some(key) = open {
            self.open.insert(key, seq);
        }
        StreamMark {
            link: Arc::clone(link),
            seq,
            key,
        }
    }

    /// A piece's data: joined to its open entry, grown by powers of two, or
    /// a new one.
    fn data(
        &mut self,
        link: &Arc<Link>,
        id: u64,
        data: &[u8],
    ) -> Result<Option<StreamMark>, &'static str> {
        let key = StreamKey::Piece(id);
        if let Some(seq) = self.open.get(&key).copied() {
            let Some((StreamEntry::Piece { data: buffer, .. }, _)) = self.pending.get(&seq) else {
                return Err(BACKLOG);
            };
            let need = buffer.len().checked_add(data.len()).ok_or(BACKLOG)?;
            let room = room_for(need)?.max(buffer.capacity());
            let more = room - buffer.capacity();
            self.admit(more, false)?;
            if let Some((StreamEntry::Piece { data: buffer, .. }, charge)) =
                self.pending.get_mut(&seq)
            {
                buffer.reserve_exact(room - buffer.len());
                buffer.extend_from_slice(data);
                *charge += more;
            }
            return Ok(None);
        }
        let room = room_for(data.len())?;
        let charge = STREAM_ENTRY_COST + room;
        self.admit(charge, true)?;
        let mut buffer = Vec::with_capacity(room);
        buffer.extend_from_slice(data);
        let entry = StreamEntry::Piece {
            id,
            data: buffer,
            terminal: None,
        };
        Ok(Some(self.insert(link, Some(key), entry, charge)))
    }

    /// A piece's `end` or `abort`: it closes its open entry, or comes alone.
    fn terminal(
        &mut self,
        link: &Arc<Link>,
        id: u64,
        frame: fc_protocol::frame::Frame,
    ) -> Result<Option<StreamMark>, &'static str> {
        let key = StreamKey::Piece(id);
        let size = frame.payload.capacity();
        if let Some(seq) = self.open.get(&key).copied() {
            self.admit(size, false)?;
            self.open.remove(&key);
            if let Some((StreamEntry::Piece { terminal, .. }, charge)) = self.pending.get_mut(&seq)
            {
                *terminal = Some(frame);
                *charge += size;
            }
            return Ok(None);
        }
        let charge = STREAM_ENTRY_COST + size;
        self.admit(charge, true)?;
        let entry = StreamEntry::Piece {
            id,
            data: Vec::new(),
            terminal: Some(frame),
        };
        Ok(Some(self.insert(link, None, entry, charge)))
    }

    /// Main's credit for a body: summed into its open entry, or a new one.
    fn credit(
        &mut self,
        link: &Arc<Link>,
        id: u64,
        bytes: u32,
    ) -> Result<Option<StreamMark>, &'static str> {
        let key = StreamKey::Body(id);
        if let Some(seq) = self.open.get(&key).copied() {
            if let Some((StreamEntry::Credit { bytes: sum, .. }, _)) = self.pending.get_mut(&seq) {
                *sum = sum.saturating_add(u64::from(bytes));
            }
            return Ok(None);
        }
        self.admit(STREAM_ENTRY_COST, true)?;
        let entry = StreamEntry::Credit {
            id,
            bytes: u64::from(bytes),
        };
        Ok(Some(self.insert(link, Some(key), entry, STREAM_ENTRY_COST)))
    }

    /// Entry `seq`, out of the backlog: its stream's next frame starts a
    /// new one.
    fn take(&mut self, seq: u64) -> Option<(StreamEntry, usize)> {
        let (entry, charge) = self.pending.remove(&seq)?;
        let key = entry.key();
        if self.open.get(&key) == Some(&seq) {
            self.open.remove(&key);
        }
        Some((entry, charge))
    }
}

/// An entry's mark, on its way to its stream's owner with the whole
/// messages ([`StreamRoutes`]). Dropped untaken (the owner gone), it frees
/// its entry.
pub struct StreamMark {
    link: Arc<Link>,
    seq: u64,
    key: StreamKey,
}

impl StreamMark {
    /// Its stream, which the event loop routes it by.
    pub fn key(&self) -> StreamKey {
        self.key
    }

    /// The owner takes the entry. Its charge stays until the [`Taken`] is
    /// dropped, once the owner has handled it.
    pub fn take(self) -> Option<Taken> {
        let (entry, charge) = self.link.stream_backlog.lock().ok()?.take(self.seq)?;
        Some(Taken {
            link: Arc::clone(&self.link),
            entry,
            charge,
        })
    }
}

impl Drop for StreamMark {
    fn drop(&mut self) {
        if let Ok(mut backlog) = self.link.stream_backlog.lock()
            && let Some((_, charge)) = backlog.take(self.seq)
        {
            backlog.release(charge);
        }
    }
}

/// An entry its owner has taken, still charged while it handles it.
pub struct Taken {
    link: Arc<Link>,
    entry: StreamEntry,
    charge: usize,
}

impl Taken {
    pub fn entry(&self) -> &StreamEntry {
        &self.entry
    }
}

impl Drop for Taken {
    fn drop(&mut self) {
        if let Ok(mut backlog) = self.link.stream_backlog.lock() {
            backlog.release(self.charge);
        }
    }
}

/// Whether `kind` is one of the four stream frames' (design 0007).
fn is_stream_kind(kind: u8) -> bool {
    use fc_protocol::frame::{KIND_ABORT, KIND_DATA, KIND_END, KIND_STREAM_CREDIT};
    matches!(kind, KIND_DATA | KIND_END | KIND_ABORT | KIND_STREAM_CREDIT)
}

/// The core's own requests to main whose response hasn't started arriving,
/// each with its reply's bound: a begin must name one (design 0005,
/// Frames), and keep to its bound (design 0015, D4). The reader retires an
/// ID as soon as its response appears, whole or begun; its producer retires
/// it once the response is consumed, which covers producers tested without
/// a reader. A cancel leaves it: the reply may already be on its way, and
/// is read within its bound all the same.
#[derive(Default)]
pub struct Pending {
    ids: Mutex<BTreeMap<u64, usize>>,
}

impl Pending {
    /// Before the request goes to the writer, so its response can't come
    /// first: its reply may take up to the message cap.
    pub fn insert(&self, id: u64) {
        self.insert_bounded(id, MAX_MESSAGE);
    }

    /// As [`Pending::insert`], its reply taking at most `bound` bytes
    /// serialized, the room its owner reserved for it: past it, whole or
    /// fragmented, the reply is a protocol error.
    pub fn insert_bounded(&self, id: u64, bound: usize) {
        if let Ok(mut ids) = self.ids.lock() {
            ids.insert(id, bound.min(MAX_MESSAGE));
        }
    }

    /// Once its response has been read, or consumed: its bound, if it was
    /// pending.
    pub fn remove(&self, id: u64) -> Option<usize> {
        self.ids.lock().ok()?.remove(&id)
    }

    /// Retires `id` for a response that begins: its bound, if it was
    /// pending.
    fn take(&self, id: u64) -> Option<usize> {
        self.remove(id)
    }

    /// Whether `id`'s response has yet to appear.
    pub fn contains(&self, id: u64) -> bool {
        self.ids.lock().is_ok_and(|ids| ids.contains_key(&id))
    }
}

/// Which thread each stream's entries go to (design 0015, D4): the dweb
/// thread's by default, the only owner of streams before the Swarm thread.
/// The event loop routes every [`StreamMark`] by its key here.
///
/// - **A piece's route** (a body main sends in answer to the core's
///   request) is registered by the requests gate under its lock, before
///   the writer has the request ([`crate::requests::Requests::send_with`]),
///   so no frame of main's answer can find it missing.
/// - **A body's route** (the core's answer to main's request, which main
///   credits) is registered by the event loop as it forwards the request
///   to its owner, before the owner can open the body.
/// - **A route goes** when its owner says no frame of the stream can come
///   any more ([`StreamRoutes::forget`]). For a piece that is once its
///   terminal, or a reply that opens no stream, has been handled. A body
///   is credited late, past its end, until main has read the end, so its
///   route must outlast that: a late credit routed to the dweb thread is a
///   protocol error there if the ID is above every request it was given.
/// - **A body's route closed** ([`StreamRoutes::close`]): the Swarm thread
///   closes a `swarm.body`'s route once main has answered the call it is
///   the body of, or cancelled it, after which main sends no credit for it
///   (design 0015, D4). A credit for one of the last [`CLOSED_BODIES`]
///   bodies closed is main breaking the protocol, which the event loop
///   refuses ([`Route::Closed`]); an older one's falls to the dweb thread's
///   default, as a stray credit for any other request's ID does.
/// - **One lock** holds the routes and the closed bodies together: a close
///   takes a route out and remembers it as closed in one step, and the
///   event loop reads a stream's route, its owner or its close, in one
///   ([`StreamRoutes::route`]), so no frame can find a body neither routed
///   nor closed in between.
#[derive(Default)]
pub struct StreamRoutes {
    table: Mutex<Routes>,
}

#[derive(Default)]
struct Routes {
    /// Each routed stream's owner.
    owners: BTreeMap<StreamKey, crate::requests::Owner>,
    /// The bodies whose routes were closed last, oldest first, each once.
    closed: VecDeque<StreamKey>,
}

/// Where a stream's frames go ([`StreamRoutes::route`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// To this owner: the dweb thread unless a route says otherwise.
    Owner(crate::requests::Owner),
    /// Nowhere: the stream's route was closed, and a frame for it is main
    /// breaking the protocol.
    Closed,
}

/// How many closed bodies' routes [`StreamRoutes`] remembers: sixteen
/// times the uploads that stream at once (design 0015, Budgets).
pub const CLOSED_BODIES: usize = 16 * SWARM_BODIES;

impl StreamRoutes {
    fn table(&self) -> std::sync::MutexGuard<'_, Routes> {
        self.table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Where `key`'s frames go, read in one step: closed, or its owner (the
    /// dweb thread unless a route says otherwise).
    pub fn route(&self, key: StreamKey) -> Route {
        let table = self.table();
        if table.closed.contains(&key) {
            return Route::Closed;
        }
        Route::Owner(
            table
                .owners
                .get(&key)
                .copied()
                .unwrap_or(crate::requests::Owner::Dweb),
        )
    }

    /// Routes `key`'s stream to `owner`: before main can send a frame of
    /// it. The dweb thread's need none.
    pub fn register(&self, key: StreamKey, owner: crate::requests::Owner) {
        if owner == crate::requests::Owner::Dweb {
            return;
        }
        self.table().owners.insert(key, owner);
    }

    /// `key`'s stream can take no frame any more: its route goes.
    pub fn forget(&self, key: StreamKey) {
        self.table().owners.remove(&key);
    }

    /// `key`'s stream can take no frame any more, and one that comes is
    /// main breaking the protocol: in one step its route goes and it is
    /// remembered as closed, once, among the last [`CLOSED_BODIES`].
    pub fn close(&self, key: StreamKey) {
        let mut table = self.table();
        table.owners.remove(&key);
        if table.closed.contains(&key) {
            return;
        }
        if table.closed.len() >= CLOSED_BODIES {
            table.closed.pop_front();
        }
        table.closed.push_back(key);
    }

    /// The routes held.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.table().owners.len()
    }

    /// The closed bodies remembered.
    #[cfg(test)]
    pub fn closed_len(&self) -> usize {
        self.table().closed.len()
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
            let Ok(mut stdin) = unbuffered_stdin() else {
                let _ = events.send(Event::Eof {
                    at_boundary: false,
                    in_response: false,
                });
                return;
            };
            let mut buffer = Zeroizing::new(vec![0u8; READ_CHUNK]);
            let mut reader = Reader {
                events,
                credits,
                link,
                pending,
                // Every kind the connection reads; stream frames are refused
                // in `deliver` until the hello settles protocol 2.
                decoder: Decoder::with_kinds(Kinds::CORE_STREAMS),
                // The core always offers fragments: the handshake grants
                // main its credit. No begin can name a pending request
                // before then.
                reassembler: Reassembler::new(),
            };
            while reader.read_once(&mut stdin, &mut buffer) {}
        })
}

/// A duplicate of stdin's descriptor (handle), read without std's buffer.
#[cfg(unix)]
fn unbuffered_stdin() -> std::io::Result<File> {
    use std::os::fd::AsFd;
    Ok(File::from(std::io::stdin().as_fd().try_clone_to_owned()?))
}

#[cfg(windows)]
fn unbuffered_stdin() -> std::io::Result<File> {
    use std::os::windows::io::AsHandle;
    Ok(File::from(
        std::io::stdin().as_handle().try_clone_to_owned()?,
    ))
}

/// A duplicate of stdout's descriptor (handle), written without std's
/// buffer: each frame goes straight to the pipe, and no copy of it stays
/// behind in a buffer the core doesn't wipe.
#[cfg(unix)]
fn unbuffered_stdout() -> std::io::Result<File> {
    use std::os::fd::AsFd;
    Ok(File::from(std::io::stdout().as_fd().try_clone_to_owned()?))
}

#[cfg(windows)]
fn unbuffered_stdout() -> std::io::Result<File> {
    use std::os::windows::io::AsHandle;
    Ok(File::from(
        std::io::stdout().as_handle().try_clone_to_owned()?,
    ))
}

#[cfg(not(any(unix, windows)))]
fn unbuffered_stdin() -> std::io::Result<File> {
    Err(std::io::Error::other(
        "no unbuffered stdin on this platform",
    ))
}

#[cfg(not(any(unix, windows)))]
fn unbuffered_stdout() -> std::io::Result<File> {
    Err(std::io::Error::other(
        "no unbuffered stdout on this platform",
    ))
}

impl Reader {
    /// Reads one chunk from `source` into `buffer`, hands its frames on, and
    /// wipes what it read. False when reading must stop (EOF, a read error,
    /// a framing error, the loop gone).
    fn read_once(&mut self, source: &mut impl Read, buffer: &mut [u8]) -> bool {
        let read = loop {
            match source.read(buffer) {
                Ok(0) => {
                    let _ = self.events.send(Event::Eof {
                        at_boundary: self.decoder.is_at_boundary(),
                        // The partial response is discarded with the
                        // reassembler.
                        in_response: self.reassembler.in_progress(),
                    });
                    return false;
                }
                Ok(read) => break read,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    let _ = self.events.send(Event::Eof {
                        at_boundary: false,
                        in_response: self.reassembler.in_progress(),
                    });
                    return false;
                }
            }
        };
        let read = read.min(buffer.len());
        let more = self.feed(&mut buffer[..read]);
        // `feed` wiped what the decoder took; whatever it didn't take (it
        // stopped on an error, or the loop is gone) goes too (#79).
        buffer[..read].zeroize();
        more
    }

    /// Decodes `input` and hands its frames on, wiping each part of `input`
    /// as soon as the decoder has copied it (#79): before any frame is
    /// handed on, since a delivery can wait for credit. False when reading
    /// must stop.
    fn feed(&mut self, input: &mut [u8]) -> bool {
        // The decoder takes input up to its budget; hand its frames on, then
        // feed it the rest.
        let mut start = 0;
        while start < input.len() {
            let consumed = match self.decoder.push(&input[start..]) {
                Ok(consumed) => consumed.min(input.len() - start),
                Err(e) => {
                    let _ = self.events.send(Event::ProtocolError(frame_category(&e)));
                    return false;
                }
            };
            // Copied into the frames' own wiped buffers (or the decoder's
            // header): nothing of it needs to stay here.
            input[start..start + consumed].zeroize();
            start += consumed;
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
        if is_stream_kind(frame.kind) {
            return self.deliver_stream(frame);
        }
        let pending = &self.pending;
        match self.reassembler.push_bounded(frame, |id| pending.take(id)) {
            Ok(Delivery::Message { frame, answers }) => {
                // Answered: no begin may follow for that request, and the
                // reply keeps to its bound, as a fragmented one does.
                if let Some(id) = answers
                    && let Some(bound) = self.pending.remove(id)
                    && frame.payload.len() > bound
                {
                    let _ = self.events.send(Event::ProtocolError("reply_over_bound"));
                    return false;
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

impl Reader {
    /// A stream frame: refused until the hello, as an unknown kind;
    /// then on to the dweb thread, in order with the whole messages, under
    /// the stream cap rather than the frame credits.
    fn deliver_stream(&mut self, frame: fc_protocol::frame::Frame) -> bool {
        if !self.link.streams() {
            let _ = self.events.send(Event::ProtocolError("unknown_frame_kind"));
            return false;
        }
        match self.link.push_stream(frame) {
            Ok(None) => true,
            Ok(Some(mark)) => self.events.send(Event::Stream(mark)).is_ok(),
            Err(category) => {
                let _ = self.events.send(Event::ProtocolError(category));
                false
            }
        }
    }
}

fn frame_category(error: &fc_protocol::frame::FrameError) -> &'static str {
    match error {
        fc_protocol::frame::FrameError::BadLength(_) => "bad_frame_length",
        fc_protocol::frame::FrameError::UnknownKind(_) => "unknown_frame_kind",
        // A stream frame's length or direction (design 0007's checks),
        // read on every connection (`Kinds::CORE_STREAMS`).
        other => other.category(),
    }
}

fn fragment_category(error: &FragmentError) -> &'static str {
    match error {
        FragmentError::NoCredit => "begin_without_credit",
        FragmentError::UnknownId(_) => "begin_unknown_id",
        FragmentError::DuplicateResponse(_) => "duplicate_response",
        FragmentError::BadSize(_) => "begin_size",
        FragmentError::OverBound { .. } => "begin_over_bound",
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
            let Ok(mut stdout) = unbuffered_stdout() else {
                let _ = events.send(Event::WriterFailed);
                return;
            };
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
                        link.wrote(Instant::now());
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
                    link.wrote(Instant::now());
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
                link.wrote(Instant::now());
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

    #[test]
    fn the_writer_notes_when_it_writes() {
        let link = offered();
        let producer = Allowance::new(usize::MAX, MAX_QUEUED_CHAIN_BYTES);
        let control = Allowance::new(usize::MAX, usize::MAX);
        // Whole frames and fragments alike move it.
        for out in [
            whole(&control, &serde_json::json!({ "n": 1 })),
            large(&producer, &link, 5, 2 * MAX_PAYLOAD + 7).0,
        ] {
            let (queue, frames) = mpsc::channel();
            queue.send(out).unwrap();
            drop(queue);
            let before = Instant::now();
            write_frames(&mut Vec::new(), &frames, &link).unwrap();
            let last = link.last_write().unwrap();
            assert!(before <= last && last <= Instant::now());
        }
        // Nothing written: nothing moves.
        let (queue, frames) = mpsc::channel();
        drop(queue);
        let last = link.last_write();
        write_frames(&mut Vec::new(), &frames, &link).unwrap();
        assert_eq!(link.last_write(), last);
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
        let bounds: Vec<(u64, usize)> = pending.iter().map(|id| (*id, MAX_MESSAGE)).collect();
        bounded_reader(link, &bounds)
    }

    /// A reader whose pending requests have these bounds.
    fn bounded_reader(link: Arc<Link>, pending: &[(u64, usize)]) -> (Reader, Receiver<Event>) {
        let (events, received) = mpsc::channel();
        let ids = Arc::new(Pending::default());
        for (id, bound) in pending {
            ids.insert_bounded(*id, *bound);
        }
        let reader = Reader {
            events,
            credits: Arc::new(Credits::default()),
            link,
            pending: ids,
            decoder: Decoder::with_kinds(Kinds::CORE_STREAMS),
            reassembler: Reassembler::new(),
        };
        (reader, received)
    }

    fn stream(kind: u8, id: u64, rest: &[u8]) -> Vec<u8> {
        let mut payload = id.to_be_bytes().to_vec();
        payload.extend_from_slice(rest);
        // `frame::encode` writes only the kinds the core sends whole.
        let mut out = u32::try_from(payload.len() + 1)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        out.push(kind);
        out.extend_from_slice(&payload);
        out
    }

    /// Design 0009: a stream frame before the hello, which settles protocol
    /// 2, is an unknown kind; after it, it goes on, in order with the whole
    /// messages and outside the frame credits.
    #[test]
    fn stream_frames_go_on_only_after_the_hello() {
        use fc_protocol::frame::{KIND_DATA, KIND_STREAM_CREDIT};
        let (mut before, received) = reader(Link::new(), &[]);
        assert!(!before.feed(&mut stream(KIND_STREAM_CREDIT, 2, &[0, 0, 0, 1])));
        assert!(matches!(
            received.try_recv(),
            Ok(Event::ProtocolError("unknown_frame_kind"))
        ));

        let (link, mut reader, received) = streaming();
        let mut input = Vec::new();
        input.extend_from_slice(&frame(br#"{"type":"cancel","id":1}"#).unwrap());
        input.extend_from_slice(&stream(KIND_DATA, 3, &[7; 100]));
        assert!(reader.feed(&mut input));
        assert!(matches!(received.try_recv(), Ok(Event::Frame(..))));
        let Ok(Event::Stream(mark)) = received.try_recv() else {
            panic!("the data's mark, after the message");
        };
        // Its entry counts until the dweb thread has handled it.
        assert_eq!(link.stream_backlog(), (128 + STREAM_ENTRY_COST, 1));
        let taken = mark.take().unwrap();
        assert!(matches!(
            taken.entry(),
            StreamEntry::Piece { id: 3, data, terminal: None } if data == &[7u8; 100]
        ));
        assert_eq!(link.stream_backlog(), (128 + STREAM_ENTRY_COST, 1));
        drop(taken);
        assert_eq!(link.stream_backlog(), (0, 0));
    }

    /// A reader past the hello.
    fn streaming() -> (Arc<Link>, Reader, Receiver<Event>) {
        let link = Link::new();
        link.enable_streams();
        let (reader, received) = reader(Arc::clone(&link), &[]);
        (link, reader, received)
    }

    /// The marks the reader sent, and the protocol error it ended with.
    fn drain(received: &Receiver<Event>) -> (Vec<StreamMark>, Option<&'static str>) {
        let mut marks = Vec::new();
        while let Ok(event) = received.try_recv() {
            match event {
                Event::Stream(mark) => marks.push(mark),
                Event::ProtocolError(category) => return (marks, Some(category)),
                _ => panic!("only stream frames are fed"),
            }
        }
        (marks, None)
    }

    /// Feeds `frames` one at a time, none of them handled, until the reader
    /// refuses one or they run out: the marks, and the error.
    fn flood(
        frames: impl Iterator<Item = Vec<u8>>,
    ) -> (Arc<Link>, Vec<StreamMark>, Option<&'static str>) {
        let (link, mut reader, received) = streaming();
        let mut all = Vec::new();
        for mut frame in frames {
            let fed = reader.feed(&mut frame);
            let (marks, error) = drain(&received);
            all.extend(marks);
            if !fed {
                return (link, all, error);
            }
        }
        (link, all, None)
    }

    /// The charge is within the cap and the entry bound, and what the
    /// waiting entries hold, counted from them, within the charge.
    fn within_bounds(link: &Link) {
        let (charged, entries) = link.stream_backlog();
        assert!(charged <= MAX_QUEUED_STREAM_BYTES, "{charged}");
        assert!(entries <= MAX_QUEUED_STREAM_ENTRIES, "{entries}");
        let held = link.stream_memory();
        assert!(held <= charged, "{held} > {charged}");
    }

    /// A valid abort of exactly `len` bytes of JSON (41 at least).
    fn abort_json(len: usize) -> Vec<u8> {
        let mut abort = br#"{"code":"body_stream_error","message":""#.to_vec();
        assert!(len >= abort.len() + 2);
        abort.resize(len - 2, b'x');
        abort.extend_from_slice(br#""}"#);
        assert!(fc_protocol::stream::Abort::from_json(&abort).is_ok());
        abort
    }

    /// Main may send a window as 131,072 one-byte data frames, within
    /// credit, while the dweb thread is held: they join one entry, in
    /// order, with the terminal after them, and a message read before the
    /// first is still ahead of it. A frame after the terminal, or after the
    /// thread has taken the entry, starts another, which comes after.
    #[test]
    fn a_window_of_one_byte_frames_is_one_entry_in_order() {
        use fc_protocol::frame::{KIND_DATA, KIND_END};
        use fc_protocol::stream::{ID_LEN, WINDOW};
        let (link, mut reader, received) = streaming();
        let mut input = Vec::new();
        input.extend_from_slice(&frame(br#"{"type":"cancel","id":1}"#).unwrap());
        for i in 0..WINDOW {
            input.extend_from_slice(&stream(KIND_DATA, 3, &[(i % 251) as u8]));
        }
        input.extend_from_slice(&stream(KIND_END, 3, &[]));
        assert!(reader.feed(&mut input));
        assert!(matches!(received.try_recv(), Ok(Event::Frame(..))));
        let (mut marks, error) = drain(&received);
        assert_eq!((marks.len(), error), (1, None));
        let entry = WINDOW + ID_LEN + STREAM_ENTRY_COST;
        assert_eq!(link.stream_backlog(), (entry, 1));
        within_bounds(&link);

        assert!(reader.feed(&mut stream(KIND_DATA, 3, &[1])));
        marks.extend(drain(&received).0);
        assert_eq!(link.stream_backlog(), (entry + 1 + STREAM_ENTRY_COST, 2));
        let mut marks = marks.into_iter();
        let taken = marks.next().unwrap().take().unwrap();
        let StreamEntry::Piece {
            id: 3,
            data,
            terminal: Some(end),
        } = taken.entry()
        else {
            panic!("the window and its end");
        };
        assert!(data.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
        assert_eq!(
            (data.len(), data.capacity(), end.kind),
            (WINDOW, WINDOW, KIND_END)
        );
        let after = marks.next().unwrap().take().unwrap();
        assert!(
            matches!(after.entry(), StreamEntry::Piece { id: 3, data, terminal: None } if data == &[1u8])
        );
        drop((taken, after));

        assert!(reader.feed(&mut stream(KIND_DATA, 5, &[1; 10])));
        let (marks, _) = drain(&received);
        let taken = marks.into_iter().next().unwrap().take().unwrap();
        assert!(reader.feed(&mut stream(KIND_DATA, 5, &[2; 10])));
        assert_eq!(drain(&received).0.len(), 1);
        drop(taken);
    }

    /// A burst of one-byte credits for every body main can credit, 512
    /// each, while the dweb thread is held: one entry per body, summed. A
    /// mark dropped untaken (the thread gone) frees its entry.
    #[test]
    fn a_burst_of_tiny_credits_is_one_entry_per_body() {
        use fc_protocol::frame::KIND_STREAM_CREDIT;
        let (link, mut reader, received) = streaming();
        let mut input = Vec::new();
        for _ in 0..512 {
            for body in 0..MAIN_FETCHES as u64 {
                input.extend_from_slice(&stream(
                    KIND_STREAM_CREDIT,
                    2 * body + 2,
                    &1u32.to_be_bytes(),
                ));
            }
        }
        assert!(reader.feed(&mut input));
        let (marks, error) = drain(&received);
        assert_eq!((marks.len(), error), (MAIN_FETCHES, None));
        let all = MAIN_FETCHES * STREAM_ENTRY_COST;
        assert_eq!(link.stream_backlog(), (all, MAIN_FETCHES));
        within_bounds(&link);
        let mut marks = marks.into_iter();
        for body in 0..MAIN_FETCHES as u64 - 1 {
            let taken = marks.next().unwrap().take().unwrap();
            assert!(matches!(
                taken.entry(),
                StreamEntry::Credit { id, bytes: 512 } if *id == 2 * body + 2
            ));
        }
        assert_eq!(link.stream_backlog(), (STREAM_ENTRY_COST, 1));
        drop(marks);
        assert_eq!(link.stream_backlog(), (0, 0));
    }

    /// The most a peer within credit can make the backlog hold, in frames
    /// of many sizes: every incoming stream's window, in 64 KiB, 4 KiB,
    /// 1,000- or 333-byte frames, each ending with a 1 KiB abort; one
    /// stream's entry taken by the thread while its next one gathers; and
    /// every body's credit. All of it is taken, within the derived bounds.
    #[test]
    fn the_most_main_can_send_within_credit_fits() {
        use fc_protocol::frame::{KIND_ABORT, KIND_DATA, KIND_STREAM_CREDIT};
        use fc_protocol::stream::{ID_LEN, MAX_ABORT, MAX_DATA, WINDOW};
        let abort = abort_json(MAX_ABORT);
        let (link, mut reader, received) = streaming();
        let mut input = stream(KIND_DATA, 1, &[0; MAX_DATA]);
        input.extend_from_slice(&stream(KIND_DATA, 1, &[0; 1]));
        assert!(reader.feed(&mut input));
        let taken = drain(&received).0.remove(0).take().unwrap();

        let mut input = stream(KIND_DATA, 1, &[0; MAX_DATA - 1]);
        input.extend_from_slice(&stream(KIND_ABORT, 1, &abort));
        for n in 1..STREAMS as u64 {
            let size = [MAX_DATA, 4096, 1000, 333][n as usize % 4];
            let mut left = WINDOW;
            while left > 0 {
                let len = size.min(left);
                input.extend_from_slice(&stream(KIND_DATA, 2 * n + 1, &vec![0; len]));
                left -= len;
            }
            input.extend_from_slice(&stream(KIND_ABORT, 2 * n + 1, &abort));
        }
        for _ in 0..3 {
            for body in 0..MAIN_FETCHES as u64 {
                input.extend_from_slice(&stream(
                    KIND_STREAM_CREDIT,
                    2 * body + 2,
                    &7u32.to_be_bytes(),
                ));
            }
        }
        assert!(reader.feed(&mut input));
        let (marks, error) = drain(&received);
        assert_eq!((marks.len(), error), (STREAMS + MAIN_FETCHES, None));
        let terminal = ID_LEN + MAX_ABORT;
        let expected = (WINDOW + STREAM_ENTRY_COST)
            + (MAX_DATA + terminal + STREAM_ENTRY_COST)
            + (STREAMS - 1) * (WINDOW + terminal + STREAM_ENTRY_COST)
            + MAIN_FETCHES * STREAM_ENTRY_COST;
        assert_eq!(
            link.stream_backlog(),
            (expected, STREAMS + 1 + MAIN_FETCHES)
        );
        assert!(expected <= MAX_QUEUED_STREAM_BYTES);
        within_bounds(&link);
        drop((taken, marks));
        assert_eq!(link.stream_backlog(), (0, 0));
    }

    /// Past the cap the connection ends. One stream's full data frames join
    /// one entry: 256 fit (16 MiB), and the 257th would grow its buffer
    /// past the cap. Each on its own stream, they stop at the cap's share
    /// of entries: 329 with the Swarm thread's share (design 0015, D4),
    /// 263 before it. Before that, 272 frames were taken (data only, under
    /// 16 MiB and a 1 MiB frame's slack).
    #[test]
    fn stream_frames_past_the_cap_end_the_connection() {
        use fc_protocol::frame::KIND_DATA;
        use fc_protocol::stream::MAX_DATA;
        let full = stream(KIND_DATA, 3, &[0; MAX_DATA]);
        let (link, marks, error) = flood(std::iter::repeat_n(full, 257));
        assert_eq!((marks.len(), error), (1, Some("stream_backlog")));
        assert_eq!(
            link.stream_backlog(),
            (16 * 1024 * 1024 + STREAM_ENTRY_COST, 1)
        );
        within_bounds(&link);
        drop(marks);
        assert_eq!(link.stream_backlog(), (0, 0));

        let each = (1..).map(|n: u64| stream(KIND_DATA, 2 * n + 1, &[0; MAX_DATA]));
        let (link, marks, error) = flood(each);
        let fits = MAX_QUEUED_STREAM_BYTES / (MAX_DATA + STREAM_ENTRY_COST);
        assert_eq!(
            (marks.len(), error, fits),
            (fits, Some("stream_backlog"), 329)
        );
        within_bounds(&link);
    }

    /// A flood of the smallest frames, none of them handled. Terminals each
    /// make an entry (a terminal closes its stream's), and so do credits
    /// for distinct bodies: the cap stops them, below the entry bound, with
    /// what they hold within it. Credits for one body only sum. Before the
    /// fix, 2,228,224 `end`s were taken, about 425 MiB of events.
    #[test]
    fn a_flood_of_small_stream_frames_stays_within_the_cap() {
        use fc_protocol::frame::{KIND_ABORT, KIND_END, KIND_STREAM_CREDIT};
        use fc_protocol::stream::ID_LEN;
        let abort = abort_json(48);
        let credit = 1u32.to_be_bytes();
        for (kind, rest, one) in [
            (KIND_END, &[][..], true),
            (KIND_END, &[][..], false),
            (KIND_STREAM_CREDIT, &credit[..], false),
            (KIND_ABORT, &abort[..], false),
        ] {
            let ids = (0u64..).map(|n| if one { 1 } else { 2 * n + 1 });
            let (link, marks, error) = flood(ids.map(|id| stream(kind, id, rest)));
            assert_eq!(error, Some("stream_backlog"));
            let charge = match kind {
                KIND_STREAM_CREDIT => STREAM_ENTRY_COST,
                _ => STREAM_ENTRY_COST + ID_LEN + rest.len(),
            };
            assert_eq!(marks.len(), MAX_QUEUED_STREAM_BYTES / charge);
            assert!(marks.len() < MAX_QUEUED_STREAM_ENTRIES);
            within_bounds(&link);
        }
        let mut input = Vec::new();
        for _ in 0..100_000 {
            input.extend_from_slice(&stream(KIND_STREAM_CREDIT, 2, &credit));
        }
        let (link, mut reader, received) = streaming();
        assert!(reader.feed(&mut input));
        let (marks, error) = drain(&received);
        assert_eq!((marks.len(), error), (1, None));
        assert_eq!(link.stream_backlog(), (STREAM_ENTRY_COST, 1));
        let taken = marks.into_iter().next().unwrap().take().unwrap();
        assert!(matches!(
            taken.entry(),
            StreamEntry::Credit {
                id: 2,
                bytes: 100_000
            }
        ));
    }

    /// Any mix of stream frames over a few streams, none of them handled:
    /// the reader ends the connection at the cap, and what the entries hold
    /// stays within their charge, the charge within the cap.
    #[test]
    fn no_mix_of_stream_frames_holds_more_than_the_cap() {
        use fc_protocol::frame::{KIND_ABORT, KIND_DATA, KIND_END, KIND_STREAM_CREDIT};
        use fc_protocol::stream::{MAX_ABORT, MAX_DATA};
        for seed in 1..=8u64 {
            let mut state = seed;
            let mut next = move || {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 33) as usize
            };
            let frames = std::iter::from_fn(move || {
                let pick = next();
                let id = 1 + 2 * (next() % 8) as u64;
                Some(match pick % 8 {
                    0 => stream(KIND_END, id, &[]),
                    1 => stream(KIND_STREAM_CREDIT, id + 1, &[0, 0, 0, 1]),
                    2 => stream(KIND_ABORT, id, &abort_json(48 + next() % (MAX_ABORT - 48))),
                    3 | 4 => stream(KIND_DATA, id, &vec![0; MAX_DATA]),
                    5 => stream(KIND_DATA, id, &vec![0; 1 + next() % 64]),
                    _ => stream(KIND_DATA, id, &vec![0; 1 + next() % MAX_DATA]),
                })
            });
            let (link, marks, error) = flood(frames);
            assert_eq!(error, Some("stream_backlog"), "seed {seed}");
            assert_eq!(link.stream_backlog().1, marks.len(), "seed {seed}");
            within_bounds(&link);
        }
    }

    /// #79: the chunk a frame was read into holds nothing of it once the
    /// decoder has it, whole or in part: a `password_b64` doesn't wait there
    /// for a later, longer read to cover it.
    #[test]
    fn the_read_chunk_is_wiped_once_decoded() {
        let (mut reader, received) = reader(Link::new(), &[]);
        let message = br#"{"type":"request","id":2,"method":"vault.unlock","params":{"password_b64":"c2VjcmV0LXBhc3N3b3Jk"},"context":{"caller":"chrome"}}"#;
        let mut input = Vec::new();
        fc_protocol::frame::encode_json(message, &mut input).unwrap();
        let wiped = |buffer: &[u8]| buffer.iter().all(|b| *b == 0);
        let mut buffer = vec![0u8; READ_CHUNK];

        // A whole frame in one read.
        let mut source = std::io::Cursor::new(input.clone());
        assert!(reader.read_once(&mut source, &mut buffer));
        assert!(wiped(&buffer));
        let Ok(Event::Frame(frame, _credit)) = received.try_recv() else {
            panic!("no frame");
        };
        assert_eq!(&frame.payload[..], &message[..]);

        // Split across two reads: the first half waits in the decoder's own
        // buffer, not in the chunk.
        let half = input.len() / 2;
        let mut first = std::io::Cursor::new(input[..half].to_vec());
        assert!(reader.read_once(&mut first, &mut buffer));
        assert!(wiped(&buffer));
        assert!(received.try_recv().is_err());
        let mut second = std::io::Cursor::new(input[half..].to_vec());
        assert!(reader.read_once(&mut second, &mut buffer));
        assert!(wiped(&buffer));
        let Ok(Event::Frame(frame, _credit)) = received.try_recv() else {
            panic!("no frame");
        };
        assert_eq!(&frame.payload[..], &message[..]);

        // EOF ends reading.
        assert!(!reader.read_once(&mut second, &mut buffer));
        assert!(matches!(
            received.try_recv(),
            Ok(Event::Eof {
                at_boundary: true,
                ..
            })
        ));
    }

    /// Set in the child process a memory test runs in ([`in_child`]).
    #[cfg(target_os = "linux")]
    const MEMORY_CHILD: &str = "FREEDOM_CORED_TEST_MEMORY_CHILD";

    /// Runs the test `name` (this module's) again in a child process, whose
    /// stdout is a pipe as the core's is, and checks that it passed. True
    /// in the child, which then runs the test's body: memory tests look for
    /// a secret in their own process (`/proc/self/mem`), so nothing else
    /// may run there.
    #[cfg(target_os = "linux")]
    fn in_child(name: &str) -> bool {
        if std::env::var_os(MEMORY_CHILD).is_some() {
            return true;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                &format!("transport::tests::{name}"),
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(MEMORY_CHILD, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "child failed:\n{stdout}\n{stderr}"
        );
        false
    }

    /// The secret of a memory test, as two halves of 48 hex digits that are
    /// never side by side but where the test puts them, so the search holds
    /// no copy of it.
    #[cfg(target_os = "linux")]
    fn secret_halves() -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
        let half = || {
            let mut random = [0u8; 24];
            getrandom::fill(&mut random).unwrap();
            let hex: Vec<u8> = random
                .iter()
                .flat_map(|b| format!("{b:02x}").into_bytes())
                .collect();
            Zeroizing::new(hex)
        };
        (half(), half())
    }

    /// #79, review of #115: a chunk read whole can hold a password frame and
    /// then frames whose delivery waits for credit. The password's bytes in
    /// the chunk are wiped before any delivery, not after the last one: no
    /// copy of it is left while a later frame of the same chunk waits.
    #[cfg(target_os = "linux")]
    #[test]
    fn no_copy_of_a_password_while_a_later_frame_waits_for_credit() {
        if !in_child("no_copy_of_a_password_while_a_later_frame_waits_for_credit") {
            return;
        }
        /// One read that hands over its bytes and wipes its own copy.
        struct OneRead(Zeroizing<Vec<u8>>);
        impl Read for OneRead {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.len();
                out[..n].copy_from_slice(&self.0);
                self.0.zeroize();
                Ok(n)
            }
        }
        let (first, second) = secret_halves();
        let mut payload = Zeroizing::new(Vec::with_capacity(512));
        payload.extend_from_slice(
            br#"{"type":"request","id":1,"method":"vault.unlock","params":{"password_b64":""#,
        );
        payload.extend_from_slice(&first);
        payload.extend_from_slice(&second);
        payload.extend_from_slice(br#""},"context":{"caller":"chrome"}}"#);
        let mut input = Zeroizing::new(Vec::with_capacity(1024));
        fc_protocol::frame::encode_json(&payload, &mut input).unwrap();
        fc_protocol::frame::encode_json(b"{}", &mut input).unwrap();
        fc_protocol::frame::encode_json(b"{}", &mut input).unwrap();
        drop(payload);

        // All but one of the reader's credits are taken: the password frame
        // gets the last, and the next frame waits for it.
        let (mut reader, events) = reader(Link::new(), &[]);
        let held: Vec<Credit> = (0..MAX_QUEUED_FRAMES - 1)
            .map(|_| reader.credits.acquire(1))
            .collect();
        let read = std::thread::spawn(move || {
            let mut source = OneRead(input);
            let mut chunk = Zeroizing::new(vec![0u8; READ_CHUNK]);
            assert!(reader.read_once(&mut source, &mut chunk));
            assert!(chunk.iter().all(|b| *b == 0));
        });
        let within = std::time::Duration::from_secs(10);
        // The password frame is handled (and wiped): the second frame gets
        // its credit, and the third waits for one.
        let Ok(Event::Frame(password, credit)) = events.recv_timeout(within) else {
            panic!("no password frame");
        };
        drop(password);
        drop(credit);
        let Ok(Event::Frame(waiting, credit)) = events.recv_timeout(within) else {
            panic!("no second frame");
        };
        assert!(
            events
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "the third frame doesn't wait"
        );
        assert_eq!(
            copies_in_memory(&first, &second),
            0,
            "the password is still in the chunk while a frame waits"
        );
        drop((waiting, credit, held));
        read.join().unwrap();
        assert!(matches!(events.recv_timeout(within), Ok(Event::Frame(..))));
    }

    /// #79: a secret reply written to stdout leaves no copy in the process
    /// once the core's own buffers are wiped. std's `Stdout` kept one in its
    /// `LineWriter` buffer until later frames happened to overwrite it. The
    /// test runs in a child process, with its stdout a pipe as the core's
    /// is, which looks for the secret in its own memory
    /// (`/proc/self/mem`).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_written_secret_leaves_no_copy_in_memory() {
        if in_child("a_written_secret_leaves_no_copy_in_memory") {
            memory_child();
        }
    }

    /// Writes a frame holding a secret, then a smaller one, through the
    /// writer as the core does; wipes every copy the core owns; then counts
    /// the copies left in memory.
    #[cfg(target_os = "linux")]
    fn memory_child() {
        let (first, second) = secret_halves();
        let mut payload = Zeroizing::new(Vec::with_capacity(256));
        payload.extend_from_slice(br#"{"type":"response","id":7,"result":{"private_key_hex":"0x"#);
        payload.extend_from_slice(&first);
        payload.extend_from_slice(&second);
        payload.extend_from_slice(br#""}}"#);
        let secret = frame(&payload).unwrap();
        drop(payload);
        // No newline: std's LineWriter would pass part of it straight
        // through.
        assert!(!secret.contains(&b'\n'));
        let small = frame(br#"{"type":"event","event":"vault.locked","data":{}}"#).unwrap();

        let allowance = Allowance::new(16, usize::MAX);
        let (queue, frames) = mpsc::channel();
        for frame in [secret, small] {
            let hold = allowance.take(frame.len()).unwrap();
            queue.send(Out::Frame { frame, hold }).unwrap();
        }
        drop(queue);
        let mut stdout = unbuffered_stdout().unwrap();
        write_frames(&mut stdout, &frames, &Link::new()).unwrap();
        drop(frames);

        let copies = copies_in_memory(&first, &second);
        assert_eq!(copies, 0, "the secret is still in memory");
    }

    /// How often `first` directly followed by `second` occurs in this
    /// process's readable memory.
    #[cfg(target_os = "linux")]
    fn copies_in_memory(first: &[u8], second: &[u8]) -> usize {
        use std::os::unix::fs::FileExt;
        let needle = first.len() + second.len();
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let memory = std::fs::File::open("/proc/self/mem").unwrap();
        let mut chunk = Zeroizing::new(vec![0u8; 1 << 20]);
        let mut copies = 0;
        for line in maps.lines() {
            let mut fields = line.split_whitespace();
            let (Some(range), Some(perms)) = (fields.next(), fields.next()) else {
                continue;
            };
            let Some((start, end)) = range.split_once('-') else {
                continue;
            };
            let (Ok(start), Ok(end)) =
                (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
            else {
                continue;
            };
            if !perms.starts_with('r') {
                continue;
            }
            let mut at = start;
            while at < end {
                let want = usize::try_from((end - at).min(chunk.len() as u64)).unwrap();
                // Some mappings ([vvar], guard pages) can't be read.
                let Ok(got) = memory.read_at(&mut chunk[..want], at) else {
                    break;
                };
                if got < needle {
                    break;
                }
                copies += chunk[..got]
                    .windows(needle)
                    .filter(|w| w.starts_with(first) && w.ends_with(second))
                    .count();
                chunk[..got].zeroize();
                // Overlapping, so a copy across two chunks is seen once.
                at += (got - needle + 1) as u64;
            }
        }
        copies
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
        assert!(reader.feed(&mut input));
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
        assert!(reader.feed(&mut fragmented(5, b"{}")));
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
            let _ = done.send(reader.feed(&mut fragmented(4, response.as_bytes())));
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
        assert!(!reader.feed(&mut fragmented(8, b"{}")));
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
        let (mut begin, _) = Splitter::begin(4, 10).unwrap();
        assert!(first.feed(&mut begin));
        assert!(!first.pending.contains(4));
        assert!(first.feed(&mut whole(r#"{"type":"response","id":5,"result":{}}"#)));
        assert!(matches!(received.try_recv(), Ok(Event::Frame(..))));
        assert!(!first.pending.contains(5));
        // A whole response for the request whose response has begun is its
        // second.
        assert!(!first.feed(&mut whole(
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
        assert!(second.feed(&mut whole(r#"{"type":"response","id":4,"result":{}}"#)));
        assert!(matches!(received.try_recv(), Ok(Event::Frame(..))));
        assert!(!second.feed(&mut fragmented(4, b"{}")));
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
        assert!(!reader.feed(&mut stream));
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
        assert!(!first.feed(&mut fragment::credit_frame()));
        assert!(matches!(
            received.try_recv(),
            Ok(Event::ProtocolError("unsolicited_credit"))
        ));
        // Owed once a response has begun: the writer is woken.
        let (mut second, _received) = reader(Arc::clone(&link), &[]);
        assert!(link.spend_credit());
        assert!(second.feed(&mut fragment::credit_frame()));
        assert!(link.holds_credit());
        assert!(matches!(frames.try_recv(), Ok(Out::Credit)));
    }

    /// Design 0015, D4: a stream's owner is the dweb thread unless a route
    /// says otherwise; a route is per stream, a piece's apart from a body's
    /// of the same number, and goes when forgotten. The dweb thread's own
    /// need none.
    #[test]
    fn streams_go_to_the_dweb_thread_unless_routed() {
        use crate::requests::Owner;
        let routes = StreamRoutes::default();
        let owner = |key| routes.route(key);
        for key in [StreamKey::Piece(5), StreamKey::Body(5), StreamKey::Piece(1)] {
            assert_eq!(owner(key), Route::Owner(Owner::Dweb), "{key:?}");
        }
        routes.register(StreamKey::Piece(5), Owner::Swarm);
        assert_eq!(owner(StreamKey::Piece(5)), Route::Owner(Owner::Swarm));
        assert_eq!(owner(StreamKey::Body(5)), Route::Owner(Owner::Dweb));
        routes.register(StreamKey::Body(9), Owner::Swarm);
        assert_eq!(owner(StreamKey::Body(9)), Route::Owner(Owner::Swarm));
        routes.register(StreamKey::Piece(6), Owner::Dweb);
        assert_eq!(routes.len(), 2);
        routes.forget(StreamKey::Piece(5));
        assert_eq!(owner(StreamKey::Piece(5)), Route::Owner(Owner::Dweb));
        assert_eq!(owner(StreamKey::Body(9)), Route::Owner(Owner::Swarm));
        assert_eq!(routes.len(), 1);
        assert_eq!(routes.closed_len(), 0);
    }

    /// Design 0015, D4: a body's route closed goes, and a frame for it is
    /// refused while it is among the last closed, each remembered once: the
    /// oldest is let go of past the bound, and closing one twice takes one
    /// place (#500's review: close 0 once, 1 twice, then 2 to 63, and 0 is
    /// still remembered).
    #[test]
    fn a_closed_bodys_route_is_remembered_once_within_its_bound() {
        use crate::requests::Owner;
        let routes = StreamRoutes::default();
        routes.register(StreamKey::Body(0), Owner::Swarm);
        routes.close(StreamKey::Body(0));
        assert_eq!(routes.len(), 0);
        assert_eq!(routes.route(StreamKey::Body(0)), Route::Closed);
        assert_eq!(routes.route(StreamKey::Piece(0)), Route::Owner(Owner::Dweb));
        routes.close(StreamKey::Body(1));
        routes.close(StreamKey::Body(1));
        for id in 2..CLOSED_BODIES as u64 {
            routes.close(StreamKey::Body(id));
        }
        assert_eq!(routes.closed_len(), CLOSED_BODIES);
        assert_eq!(routes.route(StreamKey::Body(0)), Route::Closed);
        routes.close(StreamKey::Body(1000));
        assert_eq!(routes.route(StreamKey::Body(0)), Route::Owner(Owner::Dweb));
        assert_eq!(routes.route(StreamKey::Body(1)), Route::Closed);
        assert_eq!(routes.route(StreamKey::Body(1000)), Route::Closed);
        assert_eq!(routes.closed_len(), CLOSED_BODIES);
    }

    /// #500's review: a close and the event loop's reading of a route race.
    /// The closer and the reader start together at a barrier; the reader
    /// reads the body the closer is closing, over and over. A body routed
    /// to the Swarm thread is its or closed at every read, never the dweb
    /// thread's default in between (but for one evicted from the closed
    /// set, which the reader then sees has fallen past the bound).
    #[test]
    fn closing_a_route_and_reading_it_never_part() {
        use crate::requests::Owner;
        use std::sync::Barrier;
        use std::sync::atomic::Ordering::SeqCst;
        use std::sync::atomic::{AtomicBool, AtomicU64};
        const BODIES: u64 = 20_000;
        let routes = Arc::new(StreamRoutes::default());
        for id in 1..=BODIES {
            routes.register(StreamKey::Body(id), Owner::Swarm);
        }
        let closing = Arc::new(AtomicU64::new(1));
        let done = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(Barrier::new(2));
        let closer = {
            let (routes, closing, done, barrier) = (
                Arc::clone(&routes),
                Arc::clone(&closing),
                Arc::clone(&done),
                Arc::clone(&barrier),
            );
            std::thread::spawn(move || {
                barrier.wait();
                for id in 1..=BODIES {
                    closing.store(id, SeqCst);
                    routes.close(StreamKey::Body(id));
                }
                done.store(true, SeqCst);
            })
        };
        barrier.wait();
        let mut reads = 0u64;
        while !done.load(SeqCst) {
            let id = closing.load(SeqCst);
            match routes.route(StreamKey::Body(id)) {
                Route::Owner(Owner::Swarm) | Route::Closed => {}
                other => {
                    let now = closing.load(SeqCst);
                    assert!(
                        now - id >= CLOSED_BODIES as u64,
                        "body {id} read as {other:?} while {now} closes"
                    );
                }
            }
            reads += 1;
        }
        closer.join().unwrap();
        assert!(reads > 0);
        assert_eq!(routes.len(), 0);
    }

    /// Each mark carries its stream's key, which the event loop routes it
    /// by: a piece's data and terminal by the core's request ID, main's
    /// credit by its own.
    #[test]
    fn a_mark_carries_its_streams_key() {
        use fc_protocol::frame::{KIND_DATA, KIND_END, KIND_STREAM_CREDIT};
        let (_link, mut reader, received) = streaming();
        let mut input = stream(KIND_DATA, 3, &[7; 10]);
        input.extend_from_slice(&stream(KIND_STREAM_CREDIT, 3, &[0, 0, 0, 1]));
        input.extend_from_slice(&stream(KIND_END, 4, &[]));
        assert!(reader.feed(&mut input));
        let (marks, error) = drain(&received);
        assert_eq!(error, None);
        let keys: Vec<StreamKey> = marks.iter().map(StreamMark::key).collect();
        assert_eq!(
            keys,
            [StreamKey::Piece(3), StreamKey::Body(3), StreamKey::Piece(4)]
        );
        for mark in marks {
            let key = mark.key();
            assert_eq!(mark.take().unwrap().entry().key(), key);
        }
    }

    /// The most main can send within credit to both owners at once (design
    /// 0015, D4): every dweb stream and every one of the Swarm thread's 32
    /// a whole window and its largest abort, each owner handling one
    /// stream's entry while its next gathers, and every body's credit,
    /// the dweb thread's and the Swarm thread's uploads'. All of it is
    /// taken, within the cap, which is both shares.
    #[test]
    fn the_most_main_can_send_to_both_owners_fits() {
        use fc_protocol::frame::{KIND_ABORT, KIND_DATA, KIND_STREAM_CREDIT};
        use fc_protocol::stream::{ID_LEN, MAX_ABORT, MAX_DATA, WINDOW};
        let abort = abort_json(MAX_ABORT);
        let (link, mut reader, received) = streaming();
        // The two streams each owner is handling: their first entries.
        let handled = [1u64, 2 * (STREAMS + SWARM_STREAMS) as u64 + 1];
        let mut input = Vec::new();
        for id in handled {
            input.extend_from_slice(&stream(KIND_DATA, id, &[0; MAX_DATA]));
            input.extend_from_slice(&stream(KIND_DATA, id, &[0; 1]));
        }
        assert!(reader.feed(&mut input));
        let taken: Vec<Taken> = drain(&received)
            .0
            .into_iter()
            .map(|mark| mark.take().unwrap())
            .collect();
        assert_eq!(taken.len(), 2);

        let mut input = Vec::new();
        for id in handled {
            input.extend_from_slice(&stream(KIND_DATA, id, &[0; MAX_DATA - 1]));
            input.extend_from_slice(&stream(KIND_ABORT, id, &abort));
        }
        let others =
            (1..STREAMS as u64).chain(STREAMS as u64 + 1..(STREAMS + SWARM_STREAMS) as u64);
        for n in others {
            let size = [MAX_DATA, 4096, 1000, 333][n as usize % 4];
            let mut left = WINDOW;
            while left > 0 {
                let len = size.min(left);
                input.extend_from_slice(&stream(KIND_DATA, 2 * n + 1, &vec![0; len]));
                left -= len;
            }
            input.extend_from_slice(&stream(KIND_ABORT, 2 * n + 1, &abort));
        }
        for body in 0..(MAIN_FETCHES + SWARM_BODIES) as u64 {
            input.extend_from_slice(&stream(
                KIND_STREAM_CREDIT,
                2 * body + 2,
                &7u32.to_be_bytes(),
            ));
        }
        assert!(reader.feed(&mut input));
        let (marks, error) = drain(&received);
        let streams = STREAMS + SWARM_STREAMS;
        let bodies = MAIN_FETCHES + SWARM_BODIES;
        assert_eq!((marks.len(), error), (streams + bodies, None));
        let terminal = ID_LEN + MAX_ABORT;
        let expected = 2 * (WINDOW + STREAM_ENTRY_COST)
            + 2 * (MAX_DATA + terminal + STREAM_ENTRY_COST)
            + (streams - 2) * (WINDOW + terminal + STREAM_ENTRY_COST)
            + bodies * STREAM_ENTRY_COST;
        assert_eq!(link.stream_backlog(), (expected, streams + 2 + bodies));
        assert!(expected <= MAX_QUEUED_STREAM_BYTES, "{expected}");
        // Past the dweb thread's share alone: the Swarm thread's is needed.
        assert!(expected > DWEB_STREAM_SHARE, "{expected}");
        within_bounds(&link);
        drop((taken, marks));
        assert_eq!(link.stream_backlog(), (0, 0));
    }

    /// A whole response for `id` of exactly `len` bytes.
    fn response_of(id: u64, len: usize) -> Vec<u8> {
        let mut json = format!(r#"{{"type":"response","id":{id},"result":""#).into_bytes();
        assert!(len >= json.len() + 2);
        json.resize(len - 2, b'x');
        json.extend_from_slice(br#""}"#);
        json
    }

    /// Design 0015, D4: a reply keeps to its request's bound, the room its
    /// owner reserved. A fragmented one's begin past it is a protocol error
    /// before anything is reserved; a whole one past it is too. At the
    /// bound it is taken. A request with no bound of its own takes up to
    /// the message cap.
    #[test]
    fn a_reply_keeps_to_its_requests_bound() {
        let len = MAX_PAYLOAD + 100;
        let (mut reader, received) = bounded_reader(offered(), &[(4, len), (5, len - 1)]);
        assert!(reader.feed(&mut fragmented(4, &response_of(4, len))));
        let Ok(Event::Response { id: 4, credit, .. }) = received.try_recv() else {
            panic!("the reply at its bound");
        };
        drop(credit);
        assert!(!reader.feed(&mut fragmented(5, &response_of(5, len))));
        assert!(matches!(
            received.try_recv(),
            Ok(Event::ProtocolError("begin_over_bound"))
        ));
        assert!(!reader.reassembler.in_progress());
        assert_eq!(reader.reassembler.reserved(), 0);

        let whole = |id: u64, len: usize| {
            let mut frame = Vec::new();
            fc_protocol::frame::encode_json(&response_of(id, len), &mut frame).unwrap();
            frame
        };
        let (mut reader, received) =
            bounded_reader(offered(), &[(6, 100), (7, 99), (8, MAX_MESSAGE)]);
        assert!(reader.feed(&mut whole(6, 100)));
        assert!(matches!(received.try_recv(), Ok(Event::Frame(..))));
        assert!(reader.feed(&mut whole(8, MAX_PAYLOAD)));
        assert!(matches!(received.try_recv(), Ok(Event::Frame(..))));
        assert!(!reader.feed(&mut whole(7, 100)));
        assert!(matches!(
            received.try_recv(),
            Ok(Event::ProtocolError("reply_over_bound"))
        ));
        // Unbounded: the message cap, as before.
        let pending = Pending::default();
        pending.insert(9);
        assert_eq!(pending.remove(9), Some(MAX_MESSAGE));
        pending.insert_bounded(10, usize::MAX);
        assert_eq!(pending.take(10), Some(MAX_MESSAGE));
        assert_eq!(pending.take(10), None);
    }

    /// The output of a writer, shared with a guard that notes how much of
    /// it was written when the guard went.
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct Noted {
        out: Shared,
        at: Arc<Mutex<Option<usize>>>,
    }

    impl Drop for Noted {
        fn drop(&mut self) {
            *self.at.lock().unwrap() = Some(self.out.0.lock().unwrap().len());
        }
    }

    /// Design 0015: what a producer hangs on a reply's hold goes once the
    /// writer has written the reply: a whole frame, or a fragmented reply's
    /// last fragment; one that never goes (no credit to begin with) drops
    /// it with the writer.
    #[test]
    fn a_holds_guard_goes_once_its_reply_is_written() {
        let link = offered();
        let producer = Allowance::new(usize::MAX, usize::MAX);
        let out = Shared::default();
        let (queue, frames) = mpsc::channel();
        let noted = || Arc::new(Mutex::new(None));
        let (first, second, third) = (noted(), noted(), noted());
        // A whole frame.
        let frame = frame(br#"{"n":1}"#).unwrap();
        let whole_len = frame.len();
        let hold = producer.take(frame.len()).unwrap().guard(Noted {
            out: out.clone(),
            at: Arc::clone(&first),
        });
        queue.send(Out::Frame { frame, hold }).unwrap();
        // A fragmented reply, which spends main's credit...
        let payload = Zeroizing::new(vec![b'y'; 2 * MAX_PAYLOAD + 7]);
        let reply = Reply::new(&link, 5, payload).unwrap();
        let hold = producer.take(reply.len()).unwrap().guard(Noted {
            out: out.clone(),
            at: Arc::clone(&second),
        });
        queue.send(reply.into_out(hold)).unwrap();
        // ...so this one never begins.
        let payload = Zeroizing::new(vec![b'z'; MAX_PAYLOAD + 1]);
        let reply = Reply::new(&link, 6, payload).unwrap();
        let hold = producer.take(reply.len()).unwrap().guard(Noted {
            out: out.clone(),
            at: Arc::clone(&third),
        });
        queue.send(reply.into_out(hold)).unwrap();
        drop(queue);
        let mut sink = out.clone();
        write_frames(&mut sink, &frames, &link).unwrap();
        let written = out.0.lock().unwrap().len();
        assert_eq!(*first.lock().unwrap(), Some(whole_len));
        // Every fragment of the second was written before its guard went.
        assert_eq!(*second.lock().unwrap(), Some(written));
        assert!(written > whole_len + 2 * MAX_PAYLOAD + 7);
        assert_eq!(*third.lock().unwrap(), Some(written));
        assert_eq!(producer.held_bytes(), 0);
    }
}
