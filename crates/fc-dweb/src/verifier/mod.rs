//! The verifier (design 0009, `dweb.verify`): one sans-I/O machine per
//! request, which walks a [`Verify`] plan's root piece by piece, checks
//! every piece against what names it, and builds the bundled node's
//! answer from what passed. It does no I/O: the caller (freedom-cored's
//! dweb thread) fetches each [`Output::Piece`] through main, runs each
//! [`Output::Hash`] job on its hashing pool, and feeds the results back.
//!
//! - **Inputs:** a piece's whole reply ([`Verifier::piece_whole`]), or a
//!   streamed piece's head, data and end ([`Verifier::piece_head`],
//!   [`Verifier::piece_data`], [`Verifier::piece_end`]); a piece's failure
//!   ([`Verifier::piece_failed`]); a hash job's result
//!   ([`Verifier::hashed`]); credit for the verified body
//!   ([`Verifier::body_credit`]); [`Verifier::cancel`] and
//!   [`Verifier::deadline`].
//! - **Outputs** ([`Verifier::poll`]): pieces to fetch and cancel, credit
//!   for the streamed pieces, hash jobs, then either an error before the
//!   head or the head, the verified body and its end or abort. Main may
//!   take them as seldom as it likes and what waits stays bounded: one
//!   credit at most for each stream, carrying all it is owed, and four
//!   chunks for the structure cache at most. Main answers only the pieces
//!   it has taken.
//! - **Memory:** a request runs within its scheme's grant ([`grant`]):
//!   2 MiB for Swarm, 8 MiB for IPFS. Everything it holds counts against
//!   its budget ([`budget`]), the grant less a fixed allowance for the few
//!   bounded allocations the count doesn't follow ([`SWARM_ALLOWANCE`],
//!   [`IPFS_ALLOWANCE`], the same), and is reserved before it is allocated:
//!   each walk holds its memory only as values under their charges
//!   ([`charged`]). A walk
//!   that can't fit and has no other way on ends with the budget's own text
//!   ([`MEMORY`]). A streamed piece's 128 KiB window is reserved when the
//!   piece is asked for, held whole while the piece is open, and is the
//!   one buffer its bytes wait in ([`Stash`]); credit goes back only for
//!   bytes that have left the machine, released or dropped, so a piece
//!   never has more in flight than its window. The verified body goes out
//!   within main's credit ([`BODY_WINDOW`]), and stays counted until main
//!   takes each frame ([`Verifier::poll`]).
//! - **Release:** a byte reaches [`Output::Body`] only once the chunk it
//!   came from passed its check; after a failure, the page has a prefix of
//!   the right content and then the abort.
//!
//! The Swarm walk is [`swarm`]'s; the heads are Ant's ([`ant`]).

mod ant;
mod charged;
mod gateway;
mod ipfs;
mod jobs;
mod swarm;

use std::collections::{BTreeMap, VecDeque};

pub use jobs::{Hashed, Job, JobId};

use charged::Charged;

use crate::plan::{Backend, ContentTrust, ErrorPlan, Node, ResponseOp, Root, Trust, Verify};
use crate::validate::Refusal;
use crate::verify::PastBound;

/// A Swarm request's grant (0009, Bounds): what admission reserves for it,
/// and the most it allocates. Its largest holding is a manifest lookup, the
/// root node parsed beside the next node's join and parse; a file's leaves
/// stream through one 128 KiB window.
pub const SWARM_GRANT: usize = 2 << 20;
/// An IPFS request's grant: a CAR's reading room and its sections' jobs,
/// or raw blocks of up to 2 MiB, and a directory's or a HAMT's structure.
pub const IPFS_GRANT: usize = 8 << 20;
/// What a Swarm request allocates beside what its budget counts, at most
/// (0009, Bounds): the body frame being made for main ([`MAX_FRAME`]) and
/// the outputs main hasn't taken, however seldom it polls (a request for
/// each open piece, a credit for each open stream, at most four verified
/// chunks' copies for the cache), the body queue's joined tail and the
/// queue's and outputs' slots, and the machine's own structures. Measured
/// in the tests (`verifier_memory`), which fail past it. The Swarm vectors'
/// manifest inside the limit needs 2,002,470 bytes, so it can be at most
/// about 94 KiB.
pub const SWARM_ALLOWANCE: usize = 64 << 10;
/// What an IPFS request allocates beside what its budget counts: the same
/// as a Swarm request, as its walk charges every value it keeps as the
/// Swarm walk does (its pages, heads, tags and types, and an IPNS record's
/// value while it waits for the floor among them). Measured in the same
/// tests, which fail past it.
pub const IPFS_ALLOWANCE: usize = SWARM_ALLOWANCE;
/// A Swarm request's budget: its grant less its allowance.
pub const SWARM_BUDGET: usize = SWARM_GRANT - SWARM_ALLOWANCE;
/// An IPFS request's budget: its grant less its allowance.
pub const IPFS_BUDGET: usize = IPFS_GRANT - IPFS_ALLOWANCE;
/// The larger budget, IPFS's.
pub const REQUEST_BUDGET: usize = IPFS_BUDGET;

/// A request's grant by its plan's root: what admission reserves for it
/// (0009, Bounds), its budget and its allowance together.
pub fn grant(root: &Root) -> usize {
    match root {
        Root::Swarm(_) => SWARM_GRANT,
        Root::Ipfs(_) | Root::Ipns(_) => IPFS_GRANT,
    }
}

/// A request's budget by its plan's root ([`Options::budget`]): its piece
/// windows, the pieces and blocks it holds, its parsed structure, its jobs'
/// bytes and its body until main takes it (0009, Bounds).
pub fn budget(root: &Root) -> usize {
    match root {
        Root::Swarm(_) => SWARM_BUDGET,
        Root::Ipfs(_) | Root::Ipns(_) => IPFS_BUDGET,
    }
}
/// A streamed piece's window, each direction (0007).
pub const STREAM_WINDOW: usize = 128 << 10;
/// The verified body's window: how far the body may run ahead of main's
/// credit.
pub const BODY_WINDOW: usize = 128 << 10;
/// The largest data frame (0007).
pub const MAX_FRAME: usize = 64 << 10;
/// The largest whole piece main reads (`shell.dweb_get`, `stream: false`).
pub const MAX_WHOLE: usize = 64 << 10;
/// Chunk requests a Swarm walk has open at once (0009, Leaves).
pub const MAX_CHUNK_PIECES: usize = 4;
/// The most bytes a verify plan's path holds, with a Swarm plan's query,
/// and each of its headers' values (0009, Bounds). An IPFS or IPNS plan's
/// query isn't counted: its walk never reads it. `dweb.open` plans a 414
/// or a 431 past it, and a longer plan is refused before anything is made
/// of it: the plan's check copies the path a few times, uncounted, before
/// the request's machine exists, and the machine keeps a Swarm request's
/// path, query and range and an IPFS request's range and tag within the
/// grant's allowance.
pub const MAX_PATH: usize = 8 << 10;

/// The request's method, as main read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
}

/// A piece's number within its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PieceId(pub u64);

/// What `shell.dweb_get` asks main for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceRequest {
    pub id: PieceId,
    /// One of the closed set of forms (`/chunks/<64 hex>`, `/bytes/<64
    /// hex>`, `/feeds/<40 hex>/<64 hex>`).
    pub path: String,
    pub headers: Vec<(String, String)>,
    /// Whether the body streams under credit, or comes whole.
    pub stream: bool,
    /// A whole piece's bound; none for a stream the walk ends itself.
    pub max_bytes: Option<usize>,
}

/// Why a piece failed, as main reports it: `shell.dweb_get`'s `failed`
/// before the piece's head, or the piece stream's abort after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PieceFailure {
    /// The dial was refused, reset, or found no host.
    Unreachable,
    /// Any other dial failure.
    Error,
    /// Aborted.
    Aborted,
    /// A whole piece past its `max_bytes`.
    TooLarge,
    /// Main's body idle timer ended it.
    Stalled,
}

/// The verified head (0009, Heads).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Whether a body stream follows: false for a HEAD.
    pub body: bool,
    /// The plan's name trust, and the final content label.
    pub trust: Trust,
}

/// An abort's code (0009, Failures: after the head).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortCode {
    VerificationFailed,
    Unverifiable,
    Malformed,
    PieceFailed,
    Busy,
    Cancelled,
}

impl AbortCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerificationFailed => "verification_failed",
            Self::Unverifiable => "unverifiable",
            Self::Malformed => "malformed",
            Self::PieceFailed => "piece_failed",
            Self::Busy => "busy",
            Self::Cancelled => "cancelled",
        }
    }
}

/// What the machine asks of its caller.
#[derive(Debug, Clone)]
pub enum Output {
    /// Fetch this piece through main.
    Piece(PieceRequest),
    /// The piece isn't needed any more: send `cancel`. Its terminal (a
    /// reply, an end or a failure) still comes, and is taken.
    CancelPiece(PieceId),
    /// Credit for a streamed piece: bytes that have left the machine.
    Credit {
        piece: PieceId,
        bytes: usize,
    },
    /// Run on the hashing pool, and hand the result to [`Verifier::hashed`].
    Hash(Job),
    /// Before the head, the request fails: the core's `{ code, message }`
    /// with its status.
    Error(ErrorPlan),
    /// Cancelled before the head.
    Cancelled,
    Head(Head),
    /// The next verified bytes of the body, at most [`MAX_FRAME`].
    Body(Vec<u8>),
    End,
    Abort {
        code: AbortCode,
        message: &'static str,
    },
    /// A chunk the walk verified that is structure (a manifest node's
    /// chunk, an intermediate chunk), for the partition's structure cache
    /// ([`crate::store::Store::remember`]). Main never sees it.
    Remember {
        address: [u8; 32],
        wire: Vec<u8>,
    },
    /// A record the walk verified: check it against the partition's floor
    /// and raise the floor, in one step ([`crate::store::Store::floor`]),
    /// and give the verdict to [`Verifier::floor`]. The walk waits for it.
    Floor {
        /// The name's CID bytes.
        name: Vec<u8>,
        sequence: u64,
        /// When the record's validity ends, in Unix seconds, rounded up.
        valid_until: i64,
    },
}

/// An input the machine can't take: a protocol error by its caller. The
/// machine is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Misuse {
    #[error("no floor check was asked for")]
    Floor,
    #[error("no piece with this id was asked for")]
    UnknownPiece,
    #[error("the piece has ended")]
    EndedPiece,
    /// A whole reply for a streamed piece, or a stream for a whole one.
    #[error("the reply doesn't fit the piece's kind")]
    WrongKind,
    #[error("the piece's head came already")]
    SecondHead,
    #[error("stream data before the piece's head")]
    BeforeHead,
    /// More data than the piece's window allows.
    #[error("data beyond the piece's credit")]
    BeyondCredit,
    #[error("an empty data frame or one past the frame limit")]
    Frame,
    #[error("no such job was asked for")]
    UnknownJob,
    #[error("the job's result came already")]
    DuplicateJob,
    /// Credit for more of the body than was sent, or none.
    #[error("body credit beyond what was sent")]
    BodyCredit,
}

/// The fixed texts (0009, Failures).
pub const SWARM_VERIFICATION_FAILED: &str = "Swarm content verification failed";
pub const SWARM_UNVERIFIABLE: &str = "This content can't be verified with the external Swarm node";
pub const SWARM_NOT_FOUND: &str = "Not found on the external Swarm node";
pub const SWARM_STOPPED: &str = "The external Swarm node stopped sending";
pub const IPFS_VERIFICATION_FAILED: &str = "IPFS content verification failed";
pub const IPFS_UNVERIFIABLE: &str = "This content can't be verified with the external IPFS gateway";
pub const IPFS_MALFORMED: &str = "This IPFS content is malformed";
pub const IPFS_NOT_FOUND: &str = "Not found on the external IPFS gateway";
pub const IPFS_STOPPED: &str = "The external IPFS gateway stopped sending";
/// A walk that needs more memory than its request's budget, where it has
/// no other way on: the core's limit, not the node's or the content's.
pub const MEMORY: &str = "This content needs more memory to verify than one request may use";
pub const DEADLINE_PASSED: &str = "Deadline passed";
pub const TOO_MANY_REQUESTS: &str = "Too many requests";
pub const CANCELLED: &str = "The request was cancelled";

/// Why a walk ended early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// A piece isn't what its address, CID or signature commits to.
    VerificationFailed,
    /// Content the core can't check, or a walk past its bounds.
    Unverifiable,
    /// A reservation that doesn't fit the request's memory, where the walk
    /// has no other way on: no fallback (raw blocks for a CAR) and nothing
    /// to wait for. Its own text ([`MEMORY`]), so a page and a report tell
    /// the core's limit from content it can't check.
    Memory,
    /// Authentic content that can't be decoded or is inconsistent (IPFS).
    Malformed,
    /// A piece's final answer was this status.
    Status(u16),
    /// A piece's dial failed, or its stream stopped.
    Piece(PieceFailure),
    /// A streamed piece ended early or answered another interval.
    Stopped,
    Deadline,
    /// The decoded path isn't UTF-8: Ant's router refuses it.
    InvalidPath,
}

/// A node's texts.
struct Texts {
    verification_failed: &'static str,
    unverifiable: &'static str,
    not_found: &'static str,
    stopped: &'static str,
    who: &'static str,
}

fn texts(node: Node) -> Texts {
    match node {
        Node::Ant => Texts {
            verification_failed: SWARM_VERIFICATION_FAILED,
            unverifiable: SWARM_UNVERIFIABLE,
            not_found: SWARM_NOT_FOUND,
            stopped: SWARM_STOPPED,
            who: "Swarm node",
        },
        Node::Ipfs => Texts {
            verification_failed: IPFS_VERIFICATION_FAILED,
            unverifiable: IPFS_UNVERIFIABLE,
            not_found: IPFS_NOT_FOUND,
            stopped: IPFS_STOPPED,
            who: "IPFS gateway",
        },
    }
}

impl Failure {
    fn before_head(self, node: Node) -> ErrorPlan {
        let t = texts(node);
        match self {
            Self::VerificationFailed | Self::Piece(PieceFailure::TooLarge) => {
                ErrorPlan::new(502, t.verification_failed)
            }
            Self::Unverifiable => ErrorPlan::new(502, t.unverifiable),
            Self::Memory => ErrorPlan::new(502, MEMORY),
            Self::Malformed => ErrorPlan::new(502, IPFS_MALFORMED),
            Self::Status(404) => ErrorPlan::new(404, t.not_found),
            Self::Status(status) => {
                let shown = if (400..600).contains(&status) {
                    status
                } else {
                    502
                };
                ErrorPlan::new(shown, format!("The external {} answered {status}", t.who))
            }
            Self::Piece(failure) => {
                let code = (failure == PieceFailure::Unreachable).then_some("ECONNREFUSED");
                let backend = match node {
                    Node::Ant => Backend::ant(crate::plan::Ant::External, true),
                    Node::Ipfs => Backend::ipfs(crate::plan::Ipfs::Gateway, true),
                };
                crate::failure::after_dial(
                    backend,
                    &crate::failure::Thrown {
                        code,
                        ..Default::default()
                    },
                )
            }
            Self::Stopped => ErrorPlan::new(502, t.stopped),
            Self::Deadline => ErrorPlan::new(504, DEADLINE_PASSED),
            Self::InvalidPath => ErrorPlan::new(400, "Invalid URL"),
        }
    }

    fn after_head(self, node: Node) -> (AbortCode, &'static str) {
        let t = texts(node);
        match self {
            Self::VerificationFailed | Self::Piece(PieceFailure::TooLarge) => {
                (AbortCode::VerificationFailed, t.verification_failed)
            }
            Self::Unverifiable => (AbortCode::Unverifiable, t.unverifiable),
            Self::Memory => (AbortCode::Unverifiable, MEMORY),
            Self::Malformed => (AbortCode::Malformed, IPFS_MALFORMED),
            Self::Status(_)
            | Self::Piece(_)
            | Self::Stopped
            | Self::Deadline
            | Self::InvalidPath => (AbortCode::PieceFailed, t.stopped),
        }
    }
}

/// What a piece is asked as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ask {
    /// Read whole, up to this many bytes.
    Whole(usize),
    /// Streamed under credit; main ends it past this many bytes, if any.
    Stream(Option<usize>),
    /// Streamed under credit, its bytes waiting in a [`Stash`]: its room is
    /// its window and one frame beside it, for main's frame while it is
    /// copied in.
    Stashed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Walking toward the head.
    Walking,
    /// The head is out; the body follows.
    Headed,
    /// The body failed after the head: what was verified before the failure
    /// goes out, as main's credit allows, then this abort.
    Draining(AbortCode, &'static str),
    /// The terminal output is queued: nothing more but cancels and credit.
    Ended,
}

#[derive(Debug)]
struct Stream {
    /// Its bytes wait in a stash ([`Ask::Stashed`]).
    stashed: bool,
    headed: bool,
    received: usize,
    credited: usize,
    /// Credit main hasn't taken: the one [`Output::Credit`] waiting for the
    /// stream carries all of it, as main takes it.
    owed: usize,
    /// A credit for the stream waits among the outputs.
    credit_waits: bool,
}

#[derive(Debug)]
enum Kind {
    Whole { max: usize },
    Stream(Stream),
}

#[derive(Debug)]
struct Piece<T> {
    tag: T,
    kind: Kind,
    cancelled: bool,
    /// Main has taken its request ([`Output::Piece`]): only then may main
    /// answer it.
    asked: bool,
    /// What its request holds while it waits for main, when it is counted
    /// ([`Core::fetch_charged`]).
    request: usize,
}

/// A segment of verified body: sent as main's credit allows, and kept,
/// counted, until main has taken all of it in its frames
/// ([`Verifier::poll`]); `from` is the piece its bytes came from, which
/// gets their credit once they are sent.
#[derive(Debug)]
struct Queued {
    bytes: Vec<u8>,
    /// Bytes sent, against main's credit.
    at: usize,
    /// Bytes main has taken, in its frames.
    taken: usize,
    /// What the queue counts for it ([`Core::reserved`]).
    held: usize,
    from: Option<PieceId>,
}

/// The most of small body slices a queue segment joins (0009, Bounds):
/// the tail grows to it at most, and its room past its bytes is the
/// allowance's.
const SEGMENT: usize = 16 << 10;
/// The outputs' slots kept once main has taken them all.
const OUTPUTS_KEPT: usize = 16;
/// Verified chunks' copies for the structure cache waiting for main, at
/// most: past them, a chunk isn't given to the cache until main takes them,
/// so however seldom main polls, the copies stay within the allowance.
const REMEMBER_WAITING: usize = 4;

/// A stream's bytes the walk hasn't used yet, in one buffer of the stream's
/// window (design 0009, Bounds): made at the stream's first frame and never
/// grown, so what a stream holds is its window however main frames it.
/// Each frame is copied in and goes at once. The buffer is the window's
/// room while the piece is open; once the piece ends with bytes still
/// here, the machine keeps the window for them until they are used or
/// dropped ([`Core::window_done`]).
#[derive(Debug, Default)]
pub(crate) struct Stash {
    bytes: VecDeque<u8>,
    /// The piece has ended, and its window is kept for these bytes.
    kept: bool,
}

impl Stash {
    /// A frame's bytes, within the window: main never sends past its
    /// credit, and a byte is credited only once it has left the stash.
    pub(crate) fn push(&mut self, frame: &[u8]) {
        if self.bytes.capacity() == 0 {
            self.bytes.reserve_exact(STREAM_WINDOW);
        }
        debug_assert!(self.bytes.len() + frame.len() <= STREAM_WINDOW);
        self.bytes.extend(frame);
    }

    /// The first bytes in order: all of them, or up to where the buffer
    /// wraps.
    pub(crate) fn front(&self) -> &[u8] {
        self.bytes.as_slices().0
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The first `n` bytes are used; once the piece has ended and none are
    /// left, the buffer and its window go.
    pub(crate) fn consume<T: Copy>(&mut self, core: &mut Core<T>, n: usize) {
        self.bytes.drain(..n.min(self.bytes.len()));
        if self.kept && self.bytes.is_empty() {
            self.free(core);
        }
    }

    /// The piece has ended: the bytes left keep its window, or with none
    /// left it goes.
    pub(crate) fn keep<T: Copy>(&mut self, core: &mut Core<T>) {
        self.kept = true;
        if self.bytes.is_empty() {
            self.free(core);
        }
    }

    /// The buffer goes, then any window kept for it.
    pub(crate) fn free<T: Copy>(&mut self, core: &mut Core<T>) {
        self.bytes = VecDeque::new();
        if std::mem::take(&mut self.kept) {
            core.window_done();
        }
    }
}

/// The machine's bookkeeping, which the walk drives; `T` is the walk's
/// own record of what each piece and job is for.
#[derive(Debug)]
pub(crate) struct Core<T> {
    request: u64,
    node: Node,
    pub(crate) head_only: bool,
    trust_name: Option<String>,
    limit: usize,
    outputs: VecDeque<Output>,
    phase: Phase,
    pieces: BTreeMap<PieceId, Piece<T>>,
    next_piece: u64,
    jobs: BTreeMap<u64, (T, usize)>,
    /// The jobs' bytes, all together.
    jobs_held: usize,
    next_job: u64,
    /// Bytes the walk holds: piece bodies, stream bytes, parsed structure.
    /// Its count, its faults (a release without its hold,
    /// [`Verifier::over_released`]) and the probe's ledger are
    /// [`charged`]'s, which alone writes them.
    walk_held: charged::Held,
    /// The most the request has reserved at once ([`Verifier::peak`]).
    peak: usize,
    /// The head's headers, once the walk made them within its room, until
    /// main takes the head ([`Core::head_charged`]).
    head_held: usize,
    /// The pieces' requests counted while they wait for main
    /// ([`Core::fetch_charged`]).
    asking: usize,
    queue: VecDeque<Queued>,
    /// Body not yet sent.
    queued: usize,
    /// Every byte the queue holds, sent or not, until main has taken it.
    queue_len: usize,
    /// [`Output::Remember`]s main hasn't taken ([`REMEMBER_WAITING`]).
    remembering: usize,
    /// The segment being sent: those before it are sent, waiting for main.
    sending: usize,
    /// The body frames waiting for main, by length: each is made from the
    /// queue, at its length, as main takes it.
    frames: VecDeque<usize>,
    /// Streamed pieces that ended while the walk still holds bytes of
    /// theirs: each keeps its window until the walk lets it go
    /// ([`Core::window_done`]).
    kept_windows: usize,
    /// The verified body sent, and main's credit for it.
    sent: usize,
    credited: usize,
    /// End once the queue drains.
    end_after_queue: bool,
}

impl<T: Copy> Core<T> {
    fn new(
        request: u64,
        node: Node,
        head_only: bool,
        trust_name: Option<String>,
        limit: usize,
    ) -> Self {
        Self {
            request,
            node,
            head_only,
            trust_name,
            limit,
            outputs: VecDeque::new(),
            phase: Phase::Walking,
            pieces: BTreeMap::new(),
            next_piece: 0,
            jobs: BTreeMap::new(),
            jobs_held: 0,
            next_job: 0,
            walk_held: charged::Held::default(),
            peak: 0,
            head_held: 0,
            asking: 0,
            queue: VecDeque::new(),
            queued: 0,
            queue_len: 0,
            remembering: 0,
            sending: 0,
            frames: VecDeque::new(),
            kept_windows: 0,
            sent: 0,
            credited: 0,
            end_after_queue: false,
        }
    }

    /// Every byte the request holds or has room reserved for. A streamed
    /// piece holds its whole window while it is open, its bytes in the
    /// stash included, and after its end while the walk still has bytes of
    /// it; the body's queue holds each segment whole until main has taken
    /// all of it.
    fn reserved(&self) -> usize {
        let pieces: usize = self
            .pieces
            .values()
            .map(|p| match &p.kind {
                Kind::Whole { max } => *max,
                Kind::Stream(s) if s.stashed => STREAM_WINDOW + MAX_FRAME,
                Kind::Stream(_) => STREAM_WINDOW,
            })
            .sum();
        pieces
            + self.kept_windows * STREAM_WINDOW
            + self.jobs_held
            + self.walk_held.get()
            + self.queue_len
            + self.head_held
            + self.asking
    }

    /// A streamed piece that ended has had its last bytes used or dropped:
    /// the window kept for them goes.
    pub(crate) fn window_done(&mut self) {
        self.kept_windows = self.kept_windows.saturating_sub(1);
        self.released();
    }

    /// Notes a reservation's growth in the request's peak.
    fn grew(&mut self) {
        self.peak = self.peak.max(self.reserved());
    }

    /// Whether `n` more bytes fit the request's memory.
    pub(crate) fn fits(&self, n: usize) -> bool {
        self.reserved().saturating_add(n) <= self.limit
    }

    /// Verified body the page hasn't read: queued, or sent and not yet
    /// credited.
    pub(crate) fn awaiting(&self) -> usize {
        self.queued + self.sent.saturating_sub(self.credited)
    }

    /// Hash jobs out: their bytes come back with their results.
    pub(crate) fn hashing(&self) -> bool {
        !self.jobs.is_empty()
    }

    /// Pieces cancelled whose terminal hasn't come: the room main may
    /// still fill on them comes back with it.
    pub(crate) fn cancelling(&self) -> bool {
        self.pieces.values().any(|p| p.cancelled)
    }

    /// The walk is over: the terminal output is out, or follows what is
    /// queued.
    pub(crate) fn ended(&self) -> bool {
        matches!(self.phase, Phase::Draining(..) | Phase::Ended)
    }

    /// Chunk pieces open: whole pieces not yet answered.
    pub(crate) fn whole_pieces(&self) -> usize {
        self.pieces
            .values()
            .filter(|p| matches!(p.kind, Kind::Whole { .. }) && !p.cancelled)
            .count()
    }

    /// After a release of the walk's memory, the test's look at the
    /// allocator ([`probe`]).
    fn released(&self) {
        #[cfg(feature = "memory-probe")]
        probe::released(self.reserved());
    }

    /// The walk's holding goes at once, at the request's end: nothing it
    /// charged may still be live.
    fn drop_walk_held(&mut self) {
        self.walk_held.clear();
        self.kept_windows = 0;
        self.released();
    }

    /// After an input (each walk's memory is all [`Charged`]): what the
    /// walk holds is what its live values are charged
    /// ([`charged::Held::audit`]).
    pub(crate) fn audit_charged(&mut self) {
        self.walk_held.audit();
    }

    /// Asks for a piece, reserving its room: a whole piece's bound, or a
    /// stream's window. `None` when it doesn't fit.
    pub(crate) fn fetch(
        &mut self,
        tag: T,
        path: String,
        headers: Vec<(String, String)>,
        ask: Ask,
    ) -> Option<PieceId> {
        if !self.fits(piece_room(ask)) || self.ended() {
            return None;
        }
        let id = self.ask(tag, path, headers, ask, 0);
        self.grew();
        Some(id)
    }

    /// [`Core::fetch`] for a request whose path the walk made within its
    /// charge: the request counts what its path and headers hold until main
    /// takes it ([`Verifier::poll`]), and the walk's charge goes after the
    /// request has the path. `None`, the path gone and then its charge, when
    /// the piece's room and the headers don't fit.
    pub(crate) fn fetch_charged(
        &mut self,
        tag: T,
        path: Charged<String>,
        headers: Vec<(String, String)>,
        ask: Ask,
    ) -> Option<PieceId> {
        let held = headers_cost(&headers);
        if !self.fits(piece_room(ask).saturating_add(held)) || self.ended() {
            drop(headers);
            path.release(self);
            return None;
        }
        let mut id = None;
        path.hand_over(self, |core, path| {
            let cost = held + path.capacity();
            core.asking += cost;
            id = Some(core.ask(tag, path, headers, ask, cost));
        });
        self.grew();
        id
    }

    /// The piece and its request for main, its room within the request's
    /// memory; `request` is what the request holds, counted until main
    /// takes it.
    fn ask(
        &mut self,
        tag: T,
        path: String,
        headers: Vec<(String, String)>,
        ask: Ask,
        request: usize,
    ) -> PieceId {
        let id = PieceId(self.next_piece);
        self.next_piece += 1;
        let (kind, stream, max_bytes) = match ask {
            Ask::Whole(max) => (Kind::Whole { max }, false, Some(max)),
            Ask::Stream(_) | Ask::Stashed => (
                Kind::Stream(Stream {
                    stashed: ask == Ask::Stashed,
                    headed: false,
                    received: 0,
                    credited: 0,
                    owed: 0,
                    credit_waits: false,
                }),
                true,
                match ask {
                    Ask::Stream(max) => max,
                    _ => None,
                },
            ),
        };
        self.pieces.insert(
            id,
            Piece {
                tag,
                kind,
                cancelled: false,
                asked: false,
                request,
            },
        );
        self.outputs.push_back(Output::Piece(PieceRequest {
            id,
            path,
            headers,
            stream,
            max_bytes,
        }));
        id
    }

    /// The walk no longer needs the piece.
    pub(crate) fn cancel_piece(&mut self, id: PieceId) {
        if let Some(p) = self.pieces.get_mut(&id)
            && !p.cancelled
        {
            p.cancelled = true;
            if let Kind::Stream(s) = &mut p.kind {
                s.owed = 0;
            }
            self.outputs.push_back(Output::CancelPiece(id));
        }
    }

    /// `n` bytes of a stream's have left the walk, dropped: their room
    /// goes back to the piece as credit.
    pub(crate) fn consumed(&mut self, id: PieceId, n: usize) {
        if let Some(p) = self.pieces.get_mut(&id)
            && let Kind::Stream(s) = &mut p.kind
        {
            s.credited += n;
            if !p.cancelled {
                s.owed += n;
            }
        }
    }

    /// Sends work to the hashing pool; its bytes leave the walk's holding
    /// and count as the job's.
    /// A verified structure chunk, given back for the partition's cache.
    /// A verified record, for the partition's floor ([`Output::Floor`]).
    pub(crate) fn ask_floor(&mut self, name: Vec<u8>, sequence: u64, valid_until: i64) {
        self.outputs.push_back(Output::Floor {
            name,
            sequence,
            valid_until,
        });
    }

    pub(crate) fn remember(&mut self, address: [u8; 32], wire: &[u8]) {
        if self.remembering >= REMEMBER_WAITING {
            return;
        }
        self.remembering += 1;
        self.outputs.push_back(Output::Remember {
            address,
            wire: wire.to_vec(),
        });
    }

    /// Work for the hashing pool, charged: the job has it, counted as its
    /// size, before the walk's charge goes.
    pub(crate) fn hash_charged(&mut self, tag: T, work: Charged<jobs::Work>) {
        work.hand_over(self, |core, work| core.queue_job(tag, work));
        self.grew();
    }

    /// The job out, its bytes counted as its own.
    fn queue_job(&mut self, tag: T, work: jobs::Work) {
        let size = work.size();
        let id = JobId {
            request: self.request,
            seq: self.next_job,
        };
        self.next_job += 1;
        self.jobs.insert(id.seq, (tag, size));
        self.jobs_held += size;
        self.outputs.push_back(Output::Hash(Job { id, work }));
    }

    pub(crate) fn trust(&self, content: ContentTrust) -> Trust {
        Trust {
            name: self.trust_name.clone(),
            content,
        }
    }

    /// Sends the head. For a HEAD, or a GET with no body, nothing follows.
    fn head(&mut self, status: u16, headers: Vec<(String, String)>, content: ContentTrust) {
        if self.phase != Phase::Walking {
            return;
        }
        let body = !self.head_only;
        let trust = self.trust(content);
        self.outputs.push_back(Output::Head(Head {
            status,
            headers,
            body,
            trust,
        }));
        self.phase = Phase::Headed;
        if !body {
            self.close();
        }
    }

    /// Verified bytes for the body, charged; `from` is the streamed piece
    /// they came from. The queue has them, shrunk to their length, which
    /// it counts, before the walk's charge goes.
    pub(crate) fn body_charged(&mut self, bytes: Charged<Vec<u8>>, from: Option<PieceId>) {
        bytes.hand_over(self, |core, mut bytes| {
            bytes.shrink_to_fit();
            core.enqueue(bytes, from);
        });
        self.grew();
        self.pump();
    }

    /// The body's bytes into the queue, counted there; dropped, with
    /// their credit, when no body follows.
    fn enqueue(&mut self, bytes: Vec<u8>, from: Option<PieceId>) {
        let n = bytes.len();
        if n == 0 {
            return;
        }
        if self.phase != Phase::Headed {
            drop(bytes);
            if let Some(id) = from {
                self.consumed(id, n);
            }
            return;
        }
        self.queued += n;
        self.queue_len += n;
        // Small pieces without a stream to credit join the queue's tail, up
        // to a segment: its room grows by doubling to that at most, and a
        // tail that stops being one gives back the room it didn't use.
        let last = self.queue.len().wrapping_sub(1);
        match self.queue.back_mut() {
            Some(t) if from.is_none() && t.from.is_none() && t.bytes.len() + n <= SEGMENT => {
                let len = t.bytes.len();
                if len + n > t.bytes.capacity() {
                    let room = (t.bytes.capacity() * 2).max(len + n).min(SEGMENT);
                    t.bytes.reserve_exact(room - len);
                }
                if t.at == len {
                    // It was all sent: it is the one being sent again.
                    self.sending = last;
                }
                t.bytes.extend_from_slice(&bytes);
                t.held += n;
            }
            t => {
                if let Some(t) = t {
                    t.bytes.shrink_to_fit();
                }
                self.queue.push_back(Queued {
                    bytes,
                    at: 0,
                    taken: 0,
                    held: n,
                    from,
                });
            }
        }
    }

    /// [`Core::head`] with headers the walk made within `room`: the head
    /// counts what the headers hold until main takes it
    /// ([`Verifier::poll`]), and the room goes from the walk's holding
    /// after the head has them.
    pub(crate) fn head_charged(
        &mut self,
        status: u16,
        headers: Vec<(String, String)>,
        content: ContentTrust,
        room: Charged<()>,
    ) {
        if self.phase != Phase::Walking {
            drop(headers);
            return room.release(self);
        }
        let cost = headers_cost(&headers);
        room.hand_over(self, |core, ()| core.head_held = cost);
        self.grew();
        self.head(status, headers, content);
    }

    /// The body is complete: `End` once what is queued has gone out.
    pub(crate) fn finish(&mut self) {
        if self.phase == Phase::Headed {
            self.end_after_queue = true;
            self.pump();
        }
    }

    /// Ends the request early: an error before the head, an abort after.
    pub(crate) fn fail(&mut self, failure: Failure) {
        match self.phase {
            Phase::Walking => self
                .outputs
                .push_back(Output::Error(failure.before_head(self.node))),
            Phase::Headed => {
                // The verified bytes before the failure are the page's: they
                // go out first. Nothing more is fetched.
                let (code, message) = failure.after_head(self.node);
                self.phase = Phase::Draining(code, message);
                let open: Vec<PieceId> = self.pieces.keys().copied().collect();
                for id in open {
                    self.cancel_piece(id);
                }
                self.drop_walk_held();
                self.pump();
                return;
            }
            Phase::Draining(..) | Phase::Ended => return,
        }
        self.close();
    }

    /// The terminal output is out: cancel every open piece and drop what
    /// is queued.
    fn close(&mut self) {
        self.phase = Phase::Ended;
        let open: Vec<PieceId> = self.pieces.keys().copied().collect();
        for id in open {
            self.cancel_piece(id);
        }
        // What isn't sent goes, its credit given back; what is sent stays,
        // counted, until main takes it.
        while self.queue.len() > self.sending {
            let Some(q) = self.queue.back_mut() else {
                break;
            };
            let (from, unsent, at) = (q.from, q.bytes.len() - q.at, q.at);
            if at == 0 {
                if let Some(q) = self.queue.pop_back() {
                    self.queue_len -= q.held;
                }
            } else {
                q.bytes.truncate(at);
                self.sending += 1;
            }
            if let Some(id) = from {
                self.consumed(id, unsent);
            }
        }
        self.queued = 0;
        self.drop_walk_held();
    }

    /// The next output for main. A body frame is made here, at its length,
    /// from the sent part of the queue, and the segments it takes the last
    /// of go; the head's headers are main's now. A credit carries what its
    /// stream is owed now, and none goes once the stream is cancelled or
    /// has ended.
    fn take_output(&mut self) -> Option<Output> {
        let out = loop {
            let Some(next) = self.outputs.pop_front() else {
                break None;
            };
            match next {
                Output::Body(_) => break Some(Output::Body(self.take_frame())),
                Output::Head(h) => {
                    self.head_held = 0;
                    break Some(Output::Head(h));
                }
                Output::Credit { piece, .. } => {
                    if let Some(bytes) = self.take_credit(piece) {
                        break Some(Output::Credit { piece, bytes });
                    }
                }
                Output::Piece(r) => {
                    if let Some(p) = self.pieces.get_mut(&r.id) {
                        p.asked = true;
                        self.asking -= std::mem::take(&mut p.request);
                    }
                    break Some(Output::Piece(r));
                }
                Output::Remember { address, wire } => {
                    self.remembering -= 1;
                    break Some(Output::Remember { address, wire });
                }
                other => break Some(other),
            }
        };
        if self.outputs.is_empty() && self.outputs.capacity() > 4 * OUTPUTS_KEPT {
            self.outputs.shrink_to(OUTPUTS_KEPT);
        }
        out
    }

    /// What a stream is owed as main takes its credit, if anything.
    fn take_credit(&mut self, piece: PieceId) -> Option<usize> {
        let Some(Piece {
            kind: Kind::Stream(s),
            ..
        }) = self.pieces.get_mut(&piece)
        else {
            return None;
        };
        s.credit_waits = false;
        Some(std::mem::take(&mut s.owed)).filter(|&n| n > 0)
    }

    fn take_frame(&mut self) -> Vec<u8> {
        let n = self.frames.pop_front().unwrap_or(0);
        let mut frame = Vec::with_capacity(n);
        while frame.len() < n {
            let Some(q) = self.queue.front_mut() else {
                break;
            };
            let k = (n - frame.len()).min(q.at - q.taken);
            if k == 0 {
                debug_assert!(false, "a frame past what is sent");
                break;
            }
            frame.extend_from_slice(&q.bytes[q.taken..q.taken + k]);
            q.taken += k;
            if q.taken == q.bytes.len()
                && let Some(q) = self.queue.pop_front()
            {
                self.queue_len -= q.held;
                self.sending = self.sending.saturating_sub(1);
            }
        }
        if self.queue.is_empty() && self.queue.capacity() > 4 * OUTPUTS_KEPT {
            self.queue.shrink_to(OUTPUTS_KEPT);
        }
        frame
    }

    /// Sends what main's credit allows.
    fn pump(&mut self) {
        while matches!(self.phase, Phase::Headed | Phase::Draining(..)) {
            let room = BODY_WINDOW - (self.sent - self.credited);
            let Some(front) = self.queue.get_mut(self.sending) else {
                if let Phase::Draining(code, message) = self.phase {
                    self.outputs.push_back(Output::Abort { code, message });
                    self.close();
                } else if self.end_after_queue {
                    self.outputs.push_back(Output::End);
                    self.close();
                }
                return;
            };
            if room == 0 {
                return;
            }
            let left = front.bytes.len() - front.at;
            let n = left.min(room).min(MAX_FRAME);
            front.at += n;
            let from = front.from;
            if front.at == front.bytes.len() {
                self.sending += 1;
            }
            // Small pieces of body join the frame main hasn't taken yet, so
            // a walk that releases many small slices sends few frames. The
            // frame is made only as main takes it ([`Core::take_output`]).
            match (self.outputs.back(), self.frames.back_mut()) {
                (Some(Output::Body(_)), Some(last)) if *last + n <= MAX_FRAME => *last += n,
                _ => {
                    self.outputs.push_back(Output::Body(Vec::new()));
                    self.frames.push_back(n);
                }
            }
            self.queued -= n;
            self.sent += n;
            if let Some(id) = from {
                self.consumed(id, n);
            }
        }
    }

    /// A stream owed credit gets one [`Output::Credit`], unless one waits
    /// for it already: what it carries is counted as main takes it
    /// ([`Core::take_output`]). So however seldom main polls, the outputs
    /// hold one credit at most for each stream, not one for each input.
    fn flush_credit(&mut self) {
        for (&piece, p) in &mut self.pieces {
            if let Kind::Stream(s) = &mut p.kind
                && s.owed > 0
                && !s.credit_waits
            {
                s.credit_waits = true;
                self.outputs.push_back(Output::Credit { piece, bytes: 0 });
            }
        }
    }
}

/// The walk's raw hold and release, by count. The machine uses them, for
/// what it takes in for the walk; neither walk imports them, and each holds
/// its memory only as [`Charged`] values. With the probe, a release that leaves a live
/// `Charged` value uncovered is a fault at that release
/// ([`charged::Held::take`]).
pub(crate) trait Holding {
    /// Takes `n` bytes into the walk's holding; the caller checked
    /// [`Core::fits`] for any it allocates.
    fn hold(&mut self, n: usize);
    /// `n` bytes leave the walk's holding, once what they covered has
    /// gone. More than it holds, while the walk runs, is a release without
    /// its hold: counted, and never taken below zero. Once the walk has
    /// ended its holding is gone at once, and what it releases after that
    /// is nothing.
    fn unhold(&mut self, n: usize);
}

impl<T: Copy> Holding for Core<T> {
    fn hold(&mut self, n: usize) {
        self.walk_held.add(n);
        self.grew();
    }

    fn unhold(&mut self, n: usize) {
        let running = !self.ended();
        self.walk_held.take(n, running);
        self.released();
    }
}

/// A piece's room in the request's memory: a whole piece's bound, or a
/// stream's window, and for a stashed stream a frame beside it.
fn piece_room(ask: Ask) -> usize {
    match ask {
        Ask::Whole(max) => max,
        Ask::Stream(_) => STREAM_WINDOW,
        Ask::Stashed => STREAM_WINDOW + MAX_FRAME,
    }
}

/// The heap a head's headers hold: their strings and their vector.
fn headers_cost(headers: &Vec<(String, String)>) -> usize {
    headers.capacity() * std::mem::size_of::<(String, String)>()
        + headers
            .iter()
            .map(|(n, v)| n.capacity() + v.capacity())
            .sum::<usize>()
}

/// A test's look at the allocator at each release of a walk's memory
/// (design 0009, Bounds): built with the `memory-probe` feature only.
#[cfg(feature = "memory-probe")]
pub mod probe {
    use std::cell::Cell;

    thread_local! {
        static AT_RELEASE: Cell<Option<fn(usize)>> = const { Cell::new(None) };
    }

    /// Has `f` called on this thread with the request's reservation after
    /// every release of its walk's memory, or after none.
    pub fn at_release(f: Option<fn(usize)>) {
        AT_RELEASE.with(|c| c.set(f));
    }

    pub(super) fn released(reserved: usize) {
        if let Some(f) = AT_RELEASE.with(Cell::get) {
            f(reserved);
        }
    }
}

/// What a piece's input is.
enum PieceEvent {
    Whole {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    Head {
        status: u16,
        headers: Vec<(String, String)>,
    },
    Data(Vec<u8>),
    End,
    Failed(PieceFailure),
}

/// What a walk takes from the machine: its pieces' inputs, already checked
/// against each piece, and its jobs' results.
pub(crate) trait Events<T> {
    fn whole(
        &mut self,
        core: &mut Core<T>,
        tag: T,
        status: u16,
        headers: &[(String, String)],
        body: Vec<u8>,
    );
    fn stream_head(
        &mut self,
        core: &mut Core<T>,
        tag: T,
        id: PieceId,
        status: u16,
        headers: &[(String, String)],
    );
    /// A frame within the piece's window, which its bytes stay in: the walk
    /// copies them into its stash or block buffer and drops the frame.
    fn stream_data(&mut self, core: &mut Core<T>, tag: T, id: PieceId, bytes: Vec<u8>);
    /// A streamed piece's end, and its failure: its window is kept until
    /// the walk lets it go ([`Core::window_done`]), once for each.
    fn stream_end(&mut self, core: &mut Core<T>, tag: T, id: PieceId);
    fn failed(&mut self, core: &mut Core<T>, tag: T, failure: PieceFailure);
    fn hashed(&mut self, core: &mut Core<T>, tag: T, verdict: jobs::Verdict, work: jobs::Work);
    /// Room came back: main's credit made room in the body's queue, or a
    /// cancelled piece ended.
    fn room(&mut self, _core: &mut Core<T>) {}
    /// The floor's verdict on the record the walk asked about; false when
    /// it asked about none.
    fn floor(&mut self, _core: &mut Core<T>, _check: crate::store::FloorCheck) -> bool {
        false
    }
    /// After every input: the walk's own check that what it holds is
    /// charged ([`Core::audit_charged`]).
    fn audit(&self, _core: &mut Core<T>) {}
}

/// A core and the walk it drives.
#[derive(Debug)]
struct Machine<T, W> {
    core: Core<T>,
    walk: Option<W>,
}

impl<T: Copy, W: Events<T>> Machine<T, W> {
    fn piece(&mut self, id: PieceId, event: PieceEvent) -> Result<(), Misuse> {
        if id.0 >= self.core.next_piece {
            return Err(Misuse::UnknownPiece);
        }
        let Some(piece) = self.core.pieces.get_mut(&id) else {
            return Err(Misuse::EndedPiece);
        };
        // Main answers only what it was asked: a request it hasn't taken
        // has nothing of main's yet.
        if !piece.asked {
            return Err(Misuse::UnknownPiece);
        }
        // Main reads a whole piece up to its bound; past it is `too_large`.
        let event = match (&piece.kind, event) {
            (Kind::Whole { max }, PieceEvent::Whole { body, .. }) if body.len() > *max => {
                PieceEvent::Failed(PieceFailure::TooLarge)
            }
            (_, event) => event,
        };
        // Check the input against the piece before anything changes.
        match (&mut piece.kind, &event) {
            (Kind::Whole { .. }, PieceEvent::Whole { .. } | PieceEvent::Failed(_)) => {}
            (Kind::Stream(s), PieceEvent::Head { .. }) => {
                if s.headed {
                    return Err(Misuse::SecondHead);
                }
            }
            (Kind::Stream(s), PieceEvent::Data(bytes)) => {
                if !s.headed {
                    return Err(Misuse::BeforeHead);
                }
                if bytes.is_empty() || bytes.len() > MAX_FRAME {
                    return Err(Misuse::Frame);
                }
                if !piece.cancelled
                    && s.received.saturating_sub(s.credited) + bytes.len() > STREAM_WINDOW
                {
                    return Err(Misuse::BeyondCredit);
                }
            }
            (Kind::Stream(s), PieceEvent::End) => {
                if !s.headed {
                    return Err(Misuse::BeforeHead);
                }
            }
            (Kind::Stream(_), PieceEvent::Failed(_)) => {}
            _ => return Err(Misuse::WrongKind),
        }
        let tag = piece.tag;
        let cancelled = piece.cancelled;
        let stream = matches!(piece.kind, Kind::Stream(_));
        let terminal = matches!(
            event,
            PieceEvent::Whole { .. } | PieceEvent::End | PieceEvent::Failed(_)
        );
        if let (Kind::Stream(s), PieceEvent::Head { .. }) = (&mut piece.kind, &event) {
            s.headed = true;
        }
        if cancelled {
            // A cancelled piece's late input is dropped, as read. Its
            // terminal gives back the room main might have filled, which
            // a walk waiting for room may use.
            if terminal {
                self.core.pieces.remove(&id);
                if let Some(walk) = self.walk.as_mut() {
                    walk.room(&mut self.core);
                }
            }
            self.settle();
            return Ok(());
        }
        if let (Kind::Stream(s), PieceEvent::Data(bytes)) = (&mut piece.kind, &event) {
            s.received += bytes.len();
        }
        if terminal {
            self.core.pieces.remove(&id);
        }
        if let Some(walk) = self.walk.as_mut() {
            let core = &mut self.core;
            if stream && terminal {
                // The piece's window stays held for the bytes the walk
                // still has of it, until it lets them go
                // ([`Core::window_done`]).
                core.kept_windows += 1;
            }
            match event {
                PieceEvent::Whole {
                    status,
                    headers,
                    body,
                } => {
                    core.hold(body.len());
                    walk.whole(core, tag, status, &headers, body);
                }
                PieceEvent::Head { status, headers } => {
                    walk.stream_head(core, tag, id, status, &headers);
                }
                // A frame's bytes are within its piece's window.
                PieceEvent::Data(bytes) => walk.stream_data(core, tag, id, bytes),
                PieceEvent::End => walk.stream_end(core, tag, id),
                PieceEvent::Failed(failure) => walk.failed(core, tag, failure),
            }
        }
        self.settle();
        Ok(())
    }

    fn hashed(&mut self, result: Hashed) -> Result<(), Misuse> {
        let id = result.id;
        if id.request != self.core.request || id.seq >= self.core.next_job {
            return Err(Misuse::UnknownJob);
        }
        let Some((tag, size)) = self.core.jobs.remove(&id.seq) else {
            return Err(Misuse::DuplicateJob);
        };
        self.core.jobs_held = self.core.jobs_held.saturating_sub(size);
        if let Some(walk) = self.walk.as_mut() {
            self.core.hold(size);
            walk.hashed(&mut self.core, tag, result.verdict, result.work);
        }
        self.settle();
        Ok(())
    }

    fn floor(&mut self, check: crate::store::FloorCheck) -> Result<(), Misuse> {
        let asked = match self.walk.as_mut() {
            Some(walk) => walk.floor(&mut self.core, check),
            None => false,
        };
        self.settle();
        if asked { Ok(()) } else { Err(Misuse::Floor) }
    }

    fn body_credit(&mut self, bytes: usize) -> Result<(), Misuse> {
        if bytes == 0 || self.core.credited + bytes > self.core.sent {
            return Err(Misuse::BodyCredit);
        }
        self.core.credited += bytes;
        self.core.pump();
        if let Some(walk) = self.walk.as_mut() {
            walk.room(&mut self.core);
        }
        self.settle();
        Ok(())
    }

    fn cancel(&mut self) {
        if self.core.phase != Phase::Ended {
            // The walk goes with what it holds before its holding does.
            self.walk = None;
        }
        match self.core.phase {
            Phase::Walking => {
                self.core.outputs.push_back(Output::Cancelled);
                self.core.close();
            }
            Phase::Headed | Phase::Draining(..) => {
                // The page is gone: what is queued is dropped.
                self.core.outputs.push_back(Output::Abort {
                    code: AbortCode::Cancelled,
                    message: CANCELLED,
                });
                self.core.close();
            }
            Phase::Ended => {}
        }
        self.settle();
    }

    fn deadline(&mut self) {
        if self.core.phase == Phase::Walking {
            self.walk = None;
            self.core.fail(Failure::Deadline);
        }
        self.settle();
    }

    /// After each input: a walk that has ended is dropped with what it
    /// held, and a stream owed credit has a credit waiting for main.
    fn settle(&mut self) {
        if let Some(walk) = self.walk.as_ref() {
            walk.audit(&mut self.core);
        }
        if self.core.ended() {
            self.walk = None;
            self.core.drop_walk_held();
        }
        self.core.flush_credit();
    }

    fn finished(&self) -> bool {
        self.core.phase == Phase::Ended
            && self.core.pieces.is_empty()
            && self.core.jobs.is_empty()
            && self.core.outputs.is_empty()
    }
}

#[derive(Debug)]
enum Inner {
    Swarm(Box<Machine<swarm::Tag, swarm::Walk>>),
    Ipfs(Box<Machine<ipfs::Tag, ipfs::Walk>>),
}

/// The same call on whichever machine the request has.
macro_rules! machine {
    ($self:expr, $m:ident => $body:expr) => {
        match &mut $self.inner {
            Inner::Swarm($m) => $body,
            Inner::Ipfs($m) => $body,
        }
    };
}

/// What a request runs under, beside its plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// The request's memory bound ([`budget`] for its scheme; smaller in
    /// tests of budgets exhausted at each reservation).
    pub budget: usize,
    /// The wall clock, in Unix seconds, for an IPNS record's validity.
    pub now: i64,
    /// Whether the gateway's probe found ordered CARs (0009, Modes): without
    /// them every block is fetched raw.
    pub car: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            budget: REQUEST_BUDGET,
            now: 0,
            car: true,
        }
    }
}

/// A request's verifier. See the module documentation.
#[derive(Debug)]
pub struct Verifier {
    inner: Inner,
    partition: Option<String>,
    private: bool,
}

impl Verifier {
    /// A machine for `plan`, which it checks again against `method` and
    /// itself (0009, `dweb.verify`): a refusal is a core fault, answered
    /// 502 as 0006's refused plans are. `request` is the `dweb.verify`
    /// request's id; it tags the machine's jobs.
    pub fn new(
        request: u64,
        plan: &Verify,
        method: Method,
        partition: Option<&str>,
        private: bool,
        options: Options,
    ) -> Result<Self, Refusal> {
        check_plan(plan)?;
        let header = |name: &str| {
            plan.headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        let head_only = method == Method::Head;
        let name = plan.trust.name.clone();
        let inner = match &plan.root {
            Root::Swarm(root) => {
                let mut core = Core::new(request, Node::Ant, head_only, name, options.budget);
                let walk =
                    swarm::Walk::start(&mut core, root, &plan.path, &plan.query, header("range"))?;
                Inner::Swarm(Box::new(Machine {
                    core,
                    walk: Some(walk),
                }))
            }
            Root::Ipfs(_) | Root::Ipns(_) => {
                let mut core = Core::new(request, Node::Ipfs, head_only, name, options.budget);
                let walk = ipfs::Walk::start(
                    &mut core,
                    &plan.root,
                    &plan.path,
                    ipfs::Asked {
                        range: header("range"),
                        if_none_match: header("if-none-match"),
                        now: options.now,
                        car: options.car,
                    },
                )?;
                Inner::Ipfs(Box::new(Machine {
                    core,
                    walk: Some(walk),
                }))
            }
        };
        let mut v = Self {
            inner,
            partition: partition.map(str::to_owned),
            private,
        };
        machine!(v, m => m.settle());
        Ok(v)
    }

    /// The request's partition, as main named it.
    pub fn partition(&self) -> Option<&str> {
        self.partition.as_deref()
    }

    /// A private window's request: its references are never logged.
    pub fn private(&self) -> bool {
        self.private
    }

    /// The next output, if any.
    pub fn poll(&mut self) -> Option<Output> {
        machine!(self, m => m.core.take_output())
    }

    /// Bytes the request holds or has reserved.
    pub fn reserved(&self) -> usize {
        match &self.inner {
            Inner::Swarm(m) => m.core.reserved(),
            Inner::Ipfs(m) => m.core.reserved(),
        }
    }

    /// The most the request has reserved at once, within an input too: what
    /// its memory reached, by its own count.
    pub fn peak(&self) -> usize {
        match &self.inner {
            Inner::Swarm(m) => m.core.peak,
            Inner::Ipfs(m) => m.core.peak,
        }
    }

    /// The peak starts again from what the request reserves now: a test's
    /// look at one input's peak beside the allocator's.
    #[cfg(feature = "memory-probe")]
    pub fn reset_peak(&mut self) {
        machine!(self, m => m.core.peak = m.core.reserved());
    }

    /// Bytes the walk released without holding them: zero unless its
    /// accounting is wrong, which the tests check after every input. With
    /// the `memory-probe` feature, memory it still had once its charge had
    /// gone counts too, at every release and as its holding goes at the
    /// end, and so does any difference, after each input, between what the
    /// walk holds and what its live values are charged.
    pub fn over_released(&self) -> usize {
        match &self.inner {
            Inner::Swarm(m) => m.core.walk_held.faults(),
            Inner::Ipfs(m) => m.core.walk_held.faults(),
        }
    }

    /// The terminal output is out, every piece has ended and every job has
    /// come back: the request's memory is released.
    pub fn finished(&self) -> bool {
        match &self.inner {
            Inner::Swarm(m) => m.finished(),
            Inner::Ipfs(m) => m.finished(),
        }
    }

    /// A whole piece's reply.
    pub fn piece_whole(
        &mut self,
        id: PieceId,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<(), Misuse> {
        let event = PieceEvent::Whole {
            status,
            headers,
            body,
        };
        machine!(self, m => m.piece(id, event))
    }

    /// A streamed piece's head.
    pub fn piece_head(
        &mut self,
        id: PieceId,
        status: u16,
        headers: Vec<(String, String)>,
    ) -> Result<(), Misuse> {
        machine!(self, m => m.piece(id, PieceEvent::Head { status, headers }))
    }

    /// A streamed piece's data frame: 1 to [`MAX_FRAME`] bytes, within the
    /// piece's window.
    pub fn piece_data(&mut self, id: PieceId, bytes: Vec<u8>) -> Result<(), Misuse> {
        machine!(self, m => m.piece(id, PieceEvent::Data(bytes)))
    }

    /// A streamed piece's end.
    pub fn piece_end(&mut self, id: PieceId) -> Result<(), Misuse> {
        machine!(self, m => m.piece(id, PieceEvent::End))
    }

    /// A piece failed: before its head, or its stream after.
    pub fn piece_failed(&mut self, id: PieceId, failure: PieceFailure) -> Result<(), Misuse> {
        machine!(self, m => m.piece(id, PieceEvent::Failed(failure)))
    }

    /// A hash job's result.
    pub fn hashed(&mut self, result: Hashed) -> Result<(), Misuse> {
        machine!(self, m => m.hashed(result))
    }

    /// Main's credit for the verified body: bytes it has handed on.
    pub fn body_credit(&mut self, bytes: usize) -> Result<(), Misuse> {
        machine!(self, m => m.body_credit(bytes))
    }

    /// The floor's verdict on the record of [`Output::Floor`].
    pub fn floor(&mut self, check: crate::store::FloorCheck) -> Result<(), Misuse> {
        machine!(self, m => m.floor(check))
    }

    /// The page went away: every piece is cancelled, and the request ends
    /// `cancelled`.
    pub fn cancel(&mut self) {
        machine!(self, m => m.cancel());
    }

    /// `deadline_ms` passed: before the head, a 504; after it there is no
    /// core deadline.
    pub fn deadline(&mut self) {
        machine!(self, m => m.deadline());
    }
}

/// The plan, checked again: the node and its root, the path below it, the
/// headers the bundled node reads, the operations, and the promise.
fn check_plan(plan: &Verify) -> Result<(), Refusal> {
    let scheme = match (&plan.node, &plan.root) {
        (Node::Ant, Root::Swarm(_)) => crate::plan::Scheme::Bzz,
        (Node::Ipfs, Root::Ipfs(_)) => crate::plan::Scheme::Ipfs,
        (Node::Ipfs, Root::Ipns(_)) => crate::plan::Scheme::Ipns,
        _ => return Err(Refusal::Root),
    };
    if !crate::verify::root_in_form(&plan.root) {
        return Err(Refusal::Root);
    }
    // Lengths first, before any copy is made: the bound `dweb.open` plans
    // by, so only a plan it didn't make passes it.
    match crate::verify::past_bound(plan) {
        Some(PastBound::Path) => return Err(Refusal::Path),
        Some(PastBound::Query) => return Err(Refusal::Query),
        Some(PastBound::Header) => return Err(Refusal::Header),
        None => {}
    }
    let path = &plan.path;
    if !(path.is_empty() || path.starts_with('/')) || path.contains(['?', '#']) {
        return Err(Refusal::Path);
    }
    crate::validate::check_path(
        &format!("/{}/{}{path}", scheme.as_str(), plan.root.reference()),
        scheme,
    )?;
    let q = &plan.query;
    if !(q.is_empty() || (q.starts_with('?') && q.len() > 1)) || q.contains('#') {
        return Err(Refusal::Query);
    }
    let headers: Vec<(&str, &str)> = plan
        .headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    crate::validate::check_verify_headers(&headers, scheme)?;
    let allowed: &[ResponseOp] = match scheme {
        crate::plan::Scheme::Bzz => &[ResponseOp::CanonicalizeRedirect, ResponseOp::StripPageState],
        _ => &[ResponseOp::StripPageState, ResponseOp::SmallText],
    };
    for (i, op) in plan.response.iter().enumerate() {
        if !allowed.contains(op) || plan.response[..i].contains(op) {
            return Err(Refusal::Response);
        }
    }
    if plan.trust.content != ContentTrust::Verified {
        return Err(Refusal::Trust);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// However many inputs a stream's credit comes due over, one credit
    /// waits for main, and it carries all of it when main takes it; a
    /// credit still waiting when its stream is cancelled goes with it.
    #[test]
    fn a_stream_has_one_credit_waiting_carrying_all_it_is_owed() {
        let mut core: Core<()> = Core::new(1, Node::Ipfs, false, None, IPFS_BUDGET);
        let id = core
            .fetch((), "/ipfs/x".to_owned(), vec![], Ask::Stream(None))
            .unwrap();
        assert!(matches!(core.take_output(), Some(Output::Piece(r)) if r.id == id));
        for _ in 0..1_000 {
            core.consumed(id, 1);
            core.flush_credit();
        }
        assert_eq!(core.outputs.len(), 1);
        match (core.take_output(), core.take_output()) {
            (Some(Output::Credit { piece, bytes }), None) => {
                assert_eq!((piece, bytes), (id, 1_000))
            }
            other => panic!("{other:?}"),
        }
        core.consumed(id, 5);
        core.flush_credit();
        core.consumed(id, 7);
        core.flush_credit();
        assert!(matches!(
            core.take_output(),
            Some(Output::Credit { bytes: 12, .. })
        ));
        core.consumed(id, 3);
        core.flush_credit();
        core.cancel_piece(id);
        assert!(matches!(core.take_output(), Some(Output::CancelPiece(p)) if p == id));
        assert!(core.take_output().is_none());
    }

    /// A request whose path the walk made within its charge counts the
    /// path and its headers until main takes it, the walk's charge gone
    /// once the request has the path; one that doesn't fit releases the
    /// path's charge after the path.
    #[test]
    fn a_requests_path_is_counted_until_main_takes_it() {
        let mut core: Core<()> = Core::new(1, Node::Ipfs, false, None, IPFS_BUDGET);
        let path = Charged::make(&mut core, MAX_PATH, || "a".repeat(MAX_PATH)).unwrap();
        let headers = vec![("accept".to_owned(), "x".repeat(60))];
        let held = headers_cost(&headers);
        let id = core.fetch_charged((), path, headers, Ask::Stashed).unwrap();
        assert_eq!(core.walk_held.get(), 0);
        let room = STREAM_WINDOW + MAX_FRAME;
        assert_eq!(core.reserved(), room + MAX_PATH + held);
        assert_eq!(core.peak, room + MAX_PATH + held);
        assert!(matches!(core.take_output(), Some(Output::Piece(r)) if r.id == id));
        assert_eq!(core.reserved(), room);
        // Room for the path, but not for the piece beside it.
        let mut core: Core<()> = Core::new(1, Node::Ipfs, false, None, room + MAX_PATH);
        let path = Charged::make(&mut core, MAX_PATH, || "a".repeat(MAX_PATH)).unwrap();
        let headers = vec![("accept".to_owned(), "x".to_owned())];
        assert!(
            core.fetch_charged((), path, headers, Ask::Stashed)
                .is_none()
        );
        assert_eq!((core.reserved(), core.walk_held.faults()), (0, 0));
        assert!(core.take_output().is_none());
    }

    /// At most four verified chunks' copies wait for the structure cache:
    /// past them a chunk isn't given to it, until main takes them.
    #[test]
    fn at_most_four_copies_wait_for_the_cache() {
        let mut core: Core<()> = Core::new(1, Node::Ant, false, None, SWARM_BUDGET);
        let remembered = |core: &mut Core<()>| {
            std::iter::from_fn(|| core.take_output())
                .filter(|o| matches!(o, Output::Remember { .. }))
                .count()
        };
        for i in 0..6 {
            core.remember([i; 32], &[i; 4_104]);
        }
        assert_eq!(remembered(&mut core), REMEMBER_WAITING);
        core.remember([9; 32], &[9; 8]);
        assert_eq!(remembered(&mut core), 1);
    }
}
