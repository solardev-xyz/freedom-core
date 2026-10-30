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
//!   head or the head, the verified body and its end or abort.
//! - **Memory:** everything the request holds counts against its 8 MiB
//!   ([`REQUEST_BUDGET`]), reserved before it is asked for. A streamed
//!   piece's 128 KiB window is reserved when the piece is asked for, and
//!   credit goes back only for bytes that have left the machine, released
//!   or dropped, so a piece never has more in flight than its window.
//!   The verified body goes out within main's credit ([`BODY_WINDOW`]).
//! - **Release:** a byte reaches [`Output::Body`] only once the chunk it
//!   came from passed its check; after a failure, the page has a prefix of
//!   the right content and then the abort.
//!
//! The Swarm walk is [`swarm`]'s; the heads are Ant's ([`ant`]).

mod ant;
mod gateway;
mod ipfs;
mod jobs;
mod swarm;

use std::collections::{BTreeMap, VecDeque};

pub use jobs::{Hashed, Job, JobId};

use crate::plan::{Backend, ContentTrust, ErrorPlan, Node, ResponseOp, Root, Trust, Verify};
use crate::validate::Refusal;

/// A request's memory: its piece windows, the pieces and blocks it holds,
/// its jobs' bytes and its queued body (0009, Bounds).
pub const REQUEST_BUDGET: usize = 8 << 20;
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
}

/// An input the machine can't take: a protocol error by its caller. The
/// machine is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Misuse {
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
    headed: bool,
    received: usize,
    credited: usize,
    /// Credit not yet sent: flushed once per input.
    owed: usize,
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
}

/// A segment of verified body waiting for main's credit, and the piece its
/// bytes came from, which gets their credit once they are sent.
#[derive(Debug)]
struct Queued {
    bytes: Vec<u8>,
    at: usize,
    from: Option<PieceId>,
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
    next_job: u64,
    /// Bytes the walk holds: piece bodies, stream bytes, parsed structure.
    walk_held: usize,
    queue: VecDeque<Queued>,
    queued: usize,
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
            next_job: 0,
            walk_held: 0,
            queue: VecDeque::new(),
            queued: 0,
            sent: 0,
            credited: 0,
            end_after_queue: false,
        }
    }

    /// Every byte the request holds or has room reserved for.
    fn reserved(&self) -> usize {
        let pieces: usize = self
            .pieces
            .values()
            .map(|p| match &p.kind {
                Kind::Whole { max } => *max,
                Kind::Stream(s) => {
                    STREAM_WINDOW.saturating_sub(s.received.saturating_sub(s.credited))
                }
            })
            .sum();
        let jobs: usize = self.jobs.values().map(|(_, size)| size).sum();
        pieces + jobs + self.walk_held + self.queued
    }

    /// Whether `n` more bytes fit the request's memory.
    pub(crate) fn fits(&self, n: usize) -> bool {
        self.reserved().saturating_add(n) <= self.limit
    }

    /// Verified body waiting for main's credit.
    pub(crate) fn queued(&self) -> usize {
        self.queued
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

    /// Takes `n` bytes into the walk's holding; the caller checked
    /// [`Core::fits`] for any it allocates.
    pub(crate) fn hold(&mut self, n: usize) {
        self.walk_held += n;
    }

    pub(crate) fn unhold(&mut self, n: usize) {
        self.walk_held = self.walk_held.saturating_sub(n);
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
        let room = match ask {
            Ask::Whole(max) => max,
            Ask::Stream(_) => STREAM_WINDOW,
        };
        if !self.fits(room) || self.ended() {
            return None;
        }
        let id = PieceId(self.next_piece);
        self.next_piece += 1;
        let (kind, stream, max_bytes) = match ask {
            Ask::Whole(max) => (Kind::Whole { max }, false, Some(max)),
            Ask::Stream(max) => (
                Kind::Stream(Stream {
                    headed: false,
                    received: 0,
                    credited: 0,
                    owed: 0,
                }),
                true,
                max,
            ),
        };
        self.pieces.insert(
            id,
            Piece {
                tag,
                kind,
                cancelled: false,
            },
        );
        self.outputs.push_back(Output::Piece(PieceRequest {
            id,
            path,
            headers,
            stream,
            max_bytes,
        }));
        Some(id)
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
    pub(crate) fn hash(&mut self, tag: T, work: jobs::Work) {
        let size = work.size();
        self.walk_held = self.walk_held.saturating_sub(size);
        let id = JobId {
            request: self.request,
            seq: self.next_job,
        };
        self.next_job += 1;
        self.jobs.insert(id.seq, (tag, size));
        self.outputs.push_back(Output::Hash(Job { id, work }));
    }

    pub(crate) fn trust(&self, content: ContentTrust) -> Trust {
        Trust {
            name: self.trust_name.clone(),
            content,
        }
    }

    /// Sends the head. For a HEAD, or a GET with no body, nothing follows.
    pub(crate) fn head(
        &mut self,
        status: u16,
        headers: Vec<(String, String)>,
        content: ContentTrust,
    ) {
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

    /// Verified bytes for the body, from the walk's holding; `from` is the
    /// streamed piece they came from.
    pub(crate) fn body(&mut self, bytes: Vec<u8>, from: Option<PieceId>) {
        let n = bytes.len();
        self.walk_held = self.walk_held.saturating_sub(n);
        if n == 0 {
            return;
        }
        if self.phase != Phase::Headed {
            if let Some(id) = from {
                self.consumed(id, n);
            }
            return;
        }
        self.queued += n;
        self.queue.push_back(Queued { bytes, at: 0, from });
        self.pump();
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
                self.walk_held = 0;
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
        while let Some(q) = self.queue.pop_front() {
            if let Some(id) = q.from {
                self.consumed(id, q.bytes.len() - q.at);
            }
        }
        self.queued = 0;
        self.walk_held = 0;
    }

    /// Sends what main's credit allows.
    fn pump(&mut self) {
        while matches!(self.phase, Phase::Headed | Phase::Draining(..)) {
            let room = BODY_WINDOW - (self.sent - self.credited);
            let Some(front) = self.queue.front_mut() else {
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
            let frame = front.bytes[front.at..front.at + n].to_vec();
            front.at += n;
            let from = front.from;
            if front.at == front.bytes.len() {
                self.queue.pop_front();
            }
            self.queued -= n;
            self.sent += n;
            self.outputs.push_back(Output::Body(frame));
            if let Some(id) = from {
                self.consumed(id, n);
            }
        }
    }

    fn flush_credit(&mut self) {
        let mut credit = Vec::new();
        for (id, p) in &mut self.pieces {
            if let Kind::Stream(s) = &mut p.kind
                && s.owed > 0
            {
                credit.push((*id, s.owed));
                s.owed = 0;
            }
        }
        for (piece, bytes) in credit {
            self.outputs.push_back(Output::Credit { piece, bytes });
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
    fn stream_data(&mut self, core: &mut Core<T>, tag: T, id: PieceId, bytes: Vec<u8>);
    fn stream_end(&mut self, core: &mut Core<T>, tag: T, id: PieceId);
    fn failed(&mut self, core: &mut Core<T>, tag: T, failure: PieceFailure);
    fn hashed(&mut self, core: &mut Core<T>, tag: T, verdict: jobs::Verdict, work: jobs::Work);
    /// Main's credit made room in the body's queue.
    fn room(&mut self, _core: &mut Core<T>) {}
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
        let terminal = matches!(
            event,
            PieceEvent::Whole { .. } | PieceEvent::End | PieceEvent::Failed(_)
        );
        if let (Kind::Stream(s), PieceEvent::Head { .. }) = (&mut piece.kind, &event) {
            s.headed = true;
        }
        if cancelled {
            // A cancelled piece's late input is dropped, as read.
            if terminal {
                self.core.pieces.remove(&id);
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
                PieceEvent::Data(bytes) => {
                    core.hold(bytes.len());
                    walk.stream_data(core, tag, id, bytes);
                }
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
        if let Some(walk) = self.walk.as_mut() {
            self.core.hold(size);
            walk.hashed(&mut self.core, tag, result.verdict, result.work);
        }
        self.settle();
        Ok(())
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
            self.core.fail(Failure::Deadline);
        }
        self.settle();
    }

    /// After each input: a walk that has ended is dropped with what it
    /// held, and credit owed goes out.
    fn settle(&mut self) {
        if self.core.ended() {
            self.walk = None;
            self.core.walk_held = 0;
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
    /// The request's memory bound ([`REQUEST_BUDGET`]; smaller in tests of
    /// budgets exhausted at each reservation).
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
        machine!(self, m => m.core.outputs.pop_front())
    }

    /// Bytes the request holds or has reserved.
    pub fn reserved(&self) -> usize {
        match &self.inner {
            Inner::Swarm(m) => m.core.reserved(),
            Inner::Ipfs(m) => m.core.reserved(),
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
