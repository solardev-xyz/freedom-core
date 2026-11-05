//! The dweb thread's engine (design 0009, `dweb.verify`; Admission,
//! deadlines and cancel; Bounds): each `dweb.verify` request's verifier,
//! the memory granted to it, the pieces it asks main for, and the
//! structure cache and IPNS floors they share. It does no I/O: the thread
//! (step 5c) gives it main's messages and the hashing pool's results, and
//! it acts through an [`Io`], which the tests fake.
//!
//! - **Grants.** A request runs only once its whole grant, by its scheme
//!   (2 MiB for Swarm, 8 MiB for IPFS: `fc_dweb::verifier::grant`), fits
//!   what is left of the thread's grants: the 128 MiB less the structure
//!   cache's 24 MiB and the IPNS floors' 3 MiB ([`GRANTS`]), so 12 IPFS
//!   or 50 Swarm requests at once. Its verifier's budget is the grant less
//!   the scheme's allowance, what a request allocates beside what its
//!   budget counts (`fc_dweb::verifier::budget`). At most
//!   [`RUNNING`] run at once. The rest wait in order, at most [`WAITING`],
//!   and one that waits [`GRANT_WAIT_MS`] for its grant ends `busy`. One
//!   that arrives with that many waiting is `busy` at once. A grant is held
//!   until the request's verifier has finished: its last piece has ended
//!   and its last job has come back.
//! - **Pieces.** Each piece the verifier asks for becomes a `shell.dweb_get`
//!   through the core's one gate ([`Io::get`]). A `/chunks` piece the
//!   partition's cache holds is answered at once instead. Pieces wait in
//!   one queue, first in, first out across requests, while the gate is full
//!   (main holds 256 of the core's requests). At most [`STREAMS`] streamed
//!   pieces hold a stream at once: one past that waits for one to end. A
//!   piece cancelled before it goes is never sent; one already sent gets a
//!   cancel, and main's terminal for it is still taken.
//! - **Deadlines.** A request's `deadline_ms` runs from its arrival, while
//!   it waits for its grant too, until its head: then a 504.
//! - **Faults.** An input main had no business sending (data past credit,
//!   a reply for a piece that has ended) is a protocol error, which the
//!   thread answers as the reader answers its own ([`Fault`]).
//! - **Logging.** Each request's outcome is logged with fixed codes only:
//!   never a reference or a path, in a private window or any other.

use std::collections::{BTreeMap, VecDeque};

use fc_dweb::ErrorPlan;
use fc_dweb::store::{Store, Ticket};
use fc_dweb::verifier::{
    self, AbortCode, Hashed, Head, Job, Method, Options, Output, PieceFailure, PieceId,
    PieceRequest, Verifier,
};

/// Milliseconds on the thread's monotonic clock.
pub type Ms = u64;

/// Running `dweb.verify` requests at most (0009, Admission).
pub const RUNNING: usize = 64;
/// Requests waiting to run at most; past that, `busy` at once.
pub const WAITING: usize = 256;
/// What the dweb thread's 128 MiB keeps beside the grants: the structure
/// caches' allowances (24 MiB, `fc_dweb::store`), and a reserve for the
/// IPNS floors, which hold 2.17 MB at most (0009, Bounds).
pub const SHARED: usize = fc_dweb::store::PROFILE_CACHE
    + fc_dweb::store::PRIVATE_PARTITIONS * fc_dweb::store::PRIVATE_CACHE
    + FLOORS;
/// The IPNS floors' reserve.
pub const FLOORS: usize = 3 << 20;
/// The dweb thread's memory in all.
pub const THREAD_MEMORY: usize = 128 << 20;
/// What the running requests' grants may come to: 101 MiB.
pub const GRANTS: usize = THREAD_MEMORY - SHARED;
/// How long a request waits for its grant before it ends `busy`.
pub const GRANT_WAIT_MS: Ms = 10_000;
/// Streamed pieces holding a stream at once, across requests (0009,
/// Streams in the core: 128 × 128 KiB of node bytes in flight).
pub const STREAMS: usize = 128;

/// The engine's bounds; the tests use smaller ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub running: usize,
    pub waiting: usize,
    pub grants: usize,
    pub grant_wait_ms: Ms,
    pub streams: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            running: RUNNING,
            waiting: WAITING,
            grants: GRANTS,
            grant_wait_ms: GRANT_WAIT_MS,
            streams: STREAMS,
        }
    }
}

/// What a `dweb.verify` asks, its params read.
#[derive(Debug, Clone)]
pub struct Request {
    pub plan: fc_dweb::Verify,
    pub method: Method,
    /// `None`: the profile's partition.
    pub partition: Option<String>,
    pub private: bool,
    pub deadline_ms: Ms,
    /// Whether the gateway's probe found ordered CARs (0009, Modes).
    pub car: bool,
}

/// Main's answer to a `shell.dweb_get`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// A whole piece's reply.
    Whole {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// A streamed piece's head; its data, end or abort follow.
    Stream {
        status: u16,
        headers: Vec<(String, String)>,
    },
    /// The dial failed, before any head.
    Failed(PieceFailure),
}

/// What became of a piece offered to the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Get {
    /// Sent as this request of the core's.
    Sent(u64),
    /// Main holds as many of the core's requests as it takes: the piece
    /// waits, and [`Engine::room`] tries again.
    Full,
    /// It can't go: over one frame, or the gate has closed. The verifier
    /// takes it as failed.
    Refused,
}

/// A `dweb.verify` answered with one of the protocol's error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The thread is full, or the request's grant didn't come in time:
    /// main answers 503.
    Busy,
    /// Main's cancel came before the head.
    Cancelled,
}

impl Refusal {
    /// Its error code, as the protocol writes it.
    #[allow(dead_code)]
    pub fn code(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Main sent what the protocol doesn't allow: the thread ends the core,
/// as the reader ends it on main's protocol errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// A reply, data or an end for a request of the core's that isn't a
    /// piece, or whose piece has ended.
    UnknownPiece,
    /// A piece's input its verifier refuses: data past its credit, a second
    /// head, a whole reply for a streamed piece; or body credit past what
    /// was sent.
    Misuse(verifier::Misuse),
}

impl Fault {
    /// A fixed category, for the protocol error and its log line.
    pub fn category(self) -> &'static str {
        match self {
            Self::UnknownPiece => "dweb piece unknown",
            Self::Misuse(_) => "dweb piece misused",
        }
    }
}

/// What the engine does, through the dweb thread.
pub trait Io {
    /// `shell.dweb_get` for `piece` of main's request `request`.
    fn get(&mut self, request: u64, piece: &PieceRequest) -> Get;
    /// `cancel` for the core's request `get`.
    fn cancel(&mut self, get: u64);
    /// Credit for the stream of the core's request `get`.
    fn credit(&mut self, get: u64, bytes: usize);
    /// A job for the hashing pool; its result comes to [`Engine::hashed`].
    fn hash(&mut self, job: Job);
    /// `dweb.verify`'s head.
    fn head(&mut self, request: u64, head: Head);
    /// A failure before the head, as HTTP: a status and the core's
    /// `{ code, message }`.
    fn error(&mut self, request: u64, error: ErrorPlan);
    /// An error reply before the head.
    fn refuse(&mut self, request: u64, refusal: Refusal);
    /// The verified body, at most a frame.
    fn body(&mut self, request: u64, bytes: Vec<u8>);
    fn end(&mut self, request: u64);
    fn abort(&mut self, request: u64, code: AbortCode, message: &'static str);
    /// The wall clock, in Unix seconds: an IPNS record's validity.
    fn wall(&self) -> i64;
}

/// The text of a plan the core refuses on its second check (0009,
/// `dweb.verify`): main's validation should have refused it first, so it
/// is a core fault, answered 502 as 0006's refused plans are.
pub const REFUSED_PLAN: &str = "The core refused the request's plan";

struct Running {
    v: Verifier,
    ticket: Ticket,
    grant: usize,
    /// Until the head; `None` after it.
    deadline: Option<Ms>,
    /// Its pieces sent, by the core's request ID for each.
    sent: BTreeMap<PieceId, u64>,
    node: &'static str,
    /// How it ended, for its log line.
    outcome: &'static str,
}

struct Waiting {
    id: u64,
    request: Request,
    since: Ms,
    deadline: Ms,
}

/// A piece waiting for the gate or for a stream.
struct Queued {
    request: u64,
    piece: PieceRequest,
}

/// A piece sent: whose, and whether it holds a stream.
#[derive(Debug, Clone, Copy)]
struct Sent {
    request: u64,
    piece: PieceId,
    stream: bool,
}

/// See the module documentation.
pub struct Engine {
    bounds: Bounds,
    store: Store,
    running: BTreeMap<u64, Running>,
    waiting: VecDeque<Waiting>,
    /// The running requests' grants, together.
    granted: usize,
    /// Pieces waiting for the gate, first in, first out.
    ready: VecDeque<Queued>,
    /// Streamed pieces waiting for a stream.
    for_stream: VecDeque<Queued>,
    /// Streams held: streamed pieces in `ready` or sent.
    streams: usize,
    /// The pieces sent, by the core's request ID.
    gets: BTreeMap<u64, Sent>,
}

impl Engine {
    pub fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            store: Store::new(),
            running: BTreeMap::new(),
            waiting: VecDeque::new(),
            granted: 0,
            ready: VecDeque::new(),
            for_stream: VecDeque::new(),
            streams: 0,
            gets: BTreeMap::new(),
        }
    }

    // ---- main's requests --------------------------------------------------

    /// `dweb.verify` `id`, arrived at `now`.
    pub fn verify(&mut self, io: &mut dyn Io, now: Ms, id: u64, request: Request) {
        let w = Waiting {
            id,
            deadline: now.saturating_add(request.deadline_ms),
            request,
            since: now,
        };
        if self.waiting.len() >= self.bounds.waiting {
            log_outcome(node_of(&w.request), "busy");
            return io.refuse(id, Refusal::Busy);
        }
        self.waiting.push_back(w);
        self.admit(io, now);
        self.dispatch(io, now);
    }

    /// Main's `cancel` for `dweb.verify` `id`.
    pub fn cancel(&mut self, io: &mut dyn Io, now: Ms, id: u64) {
        if let Some(r) = self.running.get_mut(&id) {
            r.v.cancel();
            self.pump(io, id);
            self.settle(io, now, id);
        } else if let Some(at) = self.waiting.iter().position(|w| w.id == id) {
            if let Some(w) = self.waiting.remove(at) {
                log_outcome(node_of(&w.request), "cancelled");
            }
            io.refuse(id, Refusal::Cancelled);
        }
        // Otherwise the request has ended already: nothing to do.
        self.dispatch(io, now);
    }

    /// Main's credit for the verified body of `dweb.verify` `id`. Credit
    /// for a request that has finished is late, and nothing to do: its body
    /// may have ended before main handed its last bytes on.
    pub fn body_credit(
        &mut self,
        io: &mut dyn Io,
        now: Ms,
        id: u64,
        bytes: usize,
    ) -> Result<(), Fault> {
        let Some(r) = self.running.get_mut(&id) else {
            return Ok(());
        };
        r.v.body_credit(bytes).map_err(Fault::Misuse)?;
        self.pump(io, id);
        self.settle(io, now, id);
        self.dispatch(io, now);
        Ok(())
    }

    /// `dweb.forget`: the partition's cache and floors go.
    pub fn forget(&mut self, partition: Option<&str>) {
        self.store.forget(partition);
    }

    // ---- main's answers to the core's pieces ------------------------------

    /// Main's reply to the core's request `get`.
    pub fn reply(&mut self, io: &mut dyn Io, now: Ms, get: u64, reply: Reply) -> Result<(), Fault> {
        let sent = *self.gets.get(&get).ok_or(Fault::UnknownPiece)?;
        let terminal = !matches!(reply, Reply::Stream { .. });
        let r = self
            .running
            .get_mut(&sent.request)
            .ok_or(Fault::UnknownPiece)?;
        let result = match reply {
            Reply::Whole {
                status,
                headers,
                body,
            } => r.v.piece_whole(sent.piece, status, headers, body),
            Reply::Stream { status, headers } => r.v.piece_head(sent.piece, status, headers),
            Reply::Failed(failure) => r.v.piece_failed(sent.piece, failure),
        };
        result.map_err(Fault::Misuse)?;
        if terminal {
            self.ended(get);
        }
        self.after(io, now, sent.request);
        Ok(())
    }

    /// A data frame of the core's streamed request `get`.
    pub fn data(
        &mut self,
        io: &mut dyn Io,
        now: Ms,
        get: u64,
        bytes: Vec<u8>,
    ) -> Result<(), Fault> {
        let sent = *self.gets.get(&get).ok_or(Fault::UnknownPiece)?;
        let r = self
            .running
            .get_mut(&sent.request)
            .ok_or(Fault::UnknownPiece)?;
        r.v.piece_data(sent.piece, bytes).map_err(Fault::Misuse)?;
        self.after(io, now, sent.request);
        Ok(())
    }

    /// The end of the core's streamed request `get`; or, with `failure`,
    /// its abort.
    pub fn ended_stream(
        &mut self,
        io: &mut dyn Io,
        now: Ms,
        get: u64,
        failure: Option<PieceFailure>,
    ) -> Result<(), Fault> {
        let sent = *self.gets.get(&get).ok_or(Fault::UnknownPiece)?;
        let r = self
            .running
            .get_mut(&sent.request)
            .ok_or(Fault::UnknownPiece)?;
        match failure {
            None => r.v.piece_end(sent.piece),
            Some(f) => r.v.piece_failed(sent.piece, f),
        }
        .map_err(Fault::Misuse)?;
        self.ended(get);
        self.after(io, now, sent.request);
        Ok(())
    }

    // ---- the hashing pool, the clock and the gate -------------------------

    /// A hash job's result. A request keeps its verifier until each of its
    /// jobs has come back, so the result always finds it.
    pub fn hashed(&mut self, io: &mut dyn Io, now: Ms, result: Hashed) -> Result<(), Fault> {
        let request = result.id().request;
        let Some(r) = self.running.get_mut(&request) else {
            return Ok(());
        };
        r.v.hashed(result).map_err(Fault::Misuse)?;
        self.after(io, now, request);
        Ok(())
    }

    /// The clock reached `now`: deadlines before a head pass, and requests
    /// that have waited too long for their grant end `busy`.
    pub fn tick(&mut self, io: &mut dyn Io, now: Ms) {
        let due: Vec<u64> = self
            .running
            .iter()
            .filter(|(_, r)| r.deadline.is_some_and(|d| d <= now))
            .map(|(&id, _)| id)
            .collect();
        for id in due {
            if let Some(r) = self.running.get_mut(&id) {
                r.deadline = None;
                r.v.deadline();
            }
            self.pump(io, id);
            self.settle(io, now, id);
        }
        let wait = self.bounds.grant_wait_ms;
        let mut kept = VecDeque::with_capacity(self.waiting.len());
        while let Some(w) = self.waiting.pop_front() {
            if w.deadline <= now {
                log_outcome(node_of(&w.request), "deadline");
                io.error(
                    w.id,
                    ErrorPlan {
                        status: 504,
                        message: verifier::DEADLINE_PASSED.to_owned(),
                    },
                );
            } else if w.since.saturating_add(wait) <= now {
                log_outcome(node_of(&w.request), "busy");
                io.refuse(w.id, Refusal::Busy);
            } else {
                kept.push_back(w);
            }
        }
        self.waiting = kept;
        self.admit(io, now);
        self.dispatch(io, now);
    }

    /// When [`Engine::tick`] next has something to do.
    pub fn next_due(&self) -> Option<Ms> {
        let running = self.running.values().filter_map(|r| r.deadline);
        let waiting = self.waiting.iter().map(|w| {
            w.deadline
                .min(w.since.saturating_add(self.bounds.grant_wait_ms))
        });
        running.chain(waiting).min()
    }

    /// The gate has room again: pieces that waited for it go.
    pub fn room(&mut self, io: &mut dyn Io, now: Ms) {
        self.dispatch(io, now);
    }
}

/// What the tests read, and 5d's gates will.
#[allow(dead_code)]
impl Engine {
    /// Requests running, and waiting for their grant.
    pub fn counts(&self) -> (usize, usize) {
        (self.running.len(), self.waiting.len())
    }

    /// The running requests' grants, together.
    pub fn granted(&self) -> usize {
        self.granted
    }

    /// What the running requests' verifiers reserve, together.
    pub fn reserved(&self) -> usize {
        self.running.values().map(|r| r.v.reserved()).sum()
    }

    /// Pieces waiting for the gate, and for a stream.
    pub fn queued(&self) -> (usize, usize) {
        (self.ready.len(), self.for_stream.len())
    }

    /// Streams held.
    pub fn streams(&self) -> usize {
        self.streams
    }

    /// What the structure caches hold.
    pub fn cached(&self) -> usize {
        self.store.cached()
    }

    /// Requests running whose deadline hasn't passed.
    pub fn is_running(&self, id: u64) -> bool {
        self.running.contains_key(&id)
    }
}

impl Engine {
    // ---- inside ------------------------------------------------------------

    /// Starts what waits, in order, while the front's grant fits.
    fn admit(&mut self, io: &mut dyn Io, now: Ms) {
        while let Some(front) = self.waiting.front() {
            let grant = verifier::grant(&front.request.plan.root);
            if self.running.len() >= self.bounds.running
                || self.granted.saturating_add(grant) > self.bounds.grants
            {
                return;
            }
            let Some(w) = self.waiting.pop_front() else {
                return;
            };
            self.start(io, now, w, grant);
        }
    }

    fn start(&mut self, io: &mut dyn Io, now: Ms, w: Waiting, grant: usize) {
        let node = node_of(&w.request);
        let req = w.request;
        let v = Verifier::new(
            w.id,
            &req.plan,
            req.method,
            req.partition.as_deref(),
            req.private,
            Options {
                budget: verifier::budget(&req.plan.root),
                now: io.wall(),
                car: req.car,
            },
        );
        let v = match v {
            Ok(v) => v,
            Err(refusal) => {
                // Main's validation let it through: a core fault.
                crate::log::warn(
                    "dweb.verify plan refused",
                    serde_json::json!({ "node": node, "check": refusal.as_str() }),
                );
                return io.error(
                    w.id,
                    ErrorPlan {
                        status: 502,
                        message: REFUSED_PLAN.to_owned(),
                    },
                );
            }
        };
        if w.deadline <= now {
            log_outcome(node, "deadline");
            return io.error(
                w.id,
                ErrorPlan {
                    status: 504,
                    message: verifier::DEADLINE_PASSED.to_owned(),
                },
            );
        }
        let ticket = self.store.begin(req.partition.as_deref());
        self.granted += grant;
        self.running.insert(
            w.id,
            Running {
                v,
                ticket,
                grant,
                deadline: Some(w.deadline),
                sent: BTreeMap::new(),
                node,
                outcome: "ended",
            },
        );
        self.pump(io, w.id);
        self.settle(io, now, w.id);
    }

    /// After an input for `request`: its outputs, its end if it has
    /// finished, and what may go now.
    fn after(&mut self, io: &mut dyn Io, now: Ms, request: u64) {
        self.pump(io, request);
        self.settle(io, now, request);
        self.dispatch(io, now);
    }

    /// The request's outputs, acted on.
    fn pump(&mut self, io: &mut dyn Io, id: u64) {
        loop {
            let Some(r) = self.running.get_mut(&id) else {
                return;
            };
            let Some(output) = r.v.poll() else {
                return;
            };
            match output {
                Output::Piece(piece) => {
                    if let Some(wire) = self.store.answer(&r.ticket, &piece) {
                        // The partition's cache holds it: no piece goes.
                        // A whole reply for a whole piece it asked for
                        // can't be refused.
                        let _ = r.v.piece_whole(piece.id, 200, Vec::new(), wire);
                        continue;
                    }
                    let q = Queued { request: id, piece };
                    if !q.piece.stream {
                        self.ready.push_back(q);
                    } else if self.streams < self.bounds.streams {
                        self.streams += 1;
                        self.ready.push_back(q);
                    } else {
                        self.for_stream.push_back(q);
                    }
                }
                Output::CancelPiece(piece) => {
                    if let Some(&get) = r.sent.get(&piece) {
                        io.cancel(get);
                    } else {
                        self.unqueue(id, piece);
                    }
                }
                Output::Credit { piece, bytes } => {
                    if let Some(&get) = r.sent.get(&piece) {
                        io.credit(get, bytes);
                    }
                }
                Output::Hash(job) => io.hash(job),
                Output::Error(error) => {
                    r.deadline = None;
                    r.outcome = "error";
                    io.error(id, error);
                }
                Output::Cancelled => {
                    r.deadline = None;
                    r.outcome = "cancelled";
                    io.refuse(id, Refusal::Cancelled);
                }
                Output::Head(head) => {
                    r.deadline = None;
                    io.head(id, head);
                }
                Output::Body(bytes) => io.body(id, bytes),
                Output::End => {
                    r.outcome = "end";
                    io.end(id);
                }
                Output::Abort { code, message } => {
                    r.outcome = code.as_str();
                    io.abort(id, code, message);
                }
                Output::Remember { address, wire } => {
                    self.store.remember(&r.ticket, address, wire);
                }
                Output::Floor {
                    name,
                    sequence,
                    valid_until,
                } => {
                    let check =
                        self.store
                            .floor(&r.ticket, &name, sequence, valid_until, io.wall());
                    // It asked for this check: its verdict can't be refused.
                    let _ = r.v.floor(check);
                }
            }
        }
    }

    /// A piece the verifier no longer needs, not yet sent: it never goes,
    /// and the verifier takes it as ended.
    fn unqueue(&mut self, id: u64, piece: PieceId) {
        let is = |q: &Queued| q.request == id && q.piece.id == piece;
        let mut found = None;
        if let Some(at) = self.ready.iter().position(is) {
            found = self.ready.remove(at);
            if found.as_ref().is_some_and(|q| q.piece.stream) {
                self.release_stream();
            }
        } else if let Some(at) = self.for_stream.iter().position(is) {
            found = self.for_stream.remove(at);
        }
        if found.is_some()
            && let Some(r) = self.running.get_mut(&id)
        {
            // A piece it asked for, not yet ended: taken.
            let _ = r.v.piece_failed(piece, PieceFailure::Aborted);
        }
    }

    /// The core's request `get` has had its terminal.
    fn ended(&mut self, get: u64) {
        let Some(sent) = self.gets.remove(&get) else {
            return;
        };
        if let Some(r) = self.running.get_mut(&sent.request) {
            r.sent.remove(&sent.piece);
        }
        if sent.stream {
            self.release_stream();
        }
    }

    /// A stream is free: the oldest piece waiting for one takes it.
    fn release_stream(&mut self) {
        self.streams = self.streams.saturating_sub(1);
        if let Some(q) = self.for_stream.pop_front() {
            self.streams += 1;
            self.ready.push_back(q);
        }
    }

    /// Sends what waits for the gate, in order, until it is full.
    fn dispatch(&mut self, io: &mut dyn Io, now: Ms) {
        while let Some(q) = self.ready.pop_front() {
            if !self.running.contains_key(&q.request) {
                continue;
            }
            match io.get(q.request, &q.piece) {
                Get::Sent(get) => {
                    self.gets.insert(
                        get,
                        Sent {
                            request: q.request,
                            piece: q.piece.id,
                            stream: q.piece.stream,
                        },
                    );
                    if let Some(r) = self.running.get_mut(&q.request) {
                        r.sent.insert(q.piece.id, get);
                    }
                }
                Get::Full => {
                    self.ready.push_front(q);
                    return;
                }
                Get::Refused => {
                    if q.piece.stream {
                        self.release_stream();
                    }
                    if let Some(r) = self.running.get_mut(&q.request) {
                        let _ = r.v.piece_failed(q.piece.id, PieceFailure::Error);
                    }
                    self.pump(io, q.request);
                    self.settle(io, now, q.request);
                }
            }
        }
    }

    /// A request whose verifier has finished gives up its grant, and what
    /// waits may start.
    fn settle(&mut self, io: &mut dyn Io, now: Ms, id: u64) {
        let done = self.running.get(&id).is_some_and(|r| r.v.finished());
        if !done {
            return;
        }
        if let Some(r) = self.running.remove(&id) {
            self.granted = self.granted.saturating_sub(r.grant);
            log_outcome(r.node, r.outcome);
        }
        self.admit(io, now);
    }
}

fn node_of(request: &Request) -> &'static str {
    request.plan.node.as_str()
}

/// A request's outcome: fixed codes only, never a reference or a path.
fn log_outcome(node: &'static str, outcome: &'static str) {
    crate::log::info(
        "dweb.verify",
        serde_json::json!({ "node": node, "outcome": outcome }),
    );
}

#[cfg(test)]
mod tests {
    //! The engine against fake mains: an honest Ant and an honest gateway
    //! built from vectors/dweb-verify.json, and a main that holds pieces
    //! back, for the bounds.

    use std::collections::{BTreeMap, HashMap, VecDeque};

    use base64::Engine as _;
    use fc_dweb::{Backend, ContentTrust, Node, ResponseOp, Root, Trust, retry, timers};
    use sha2::{Digest, Sha256};

    use super::*;

    const WINDOW: usize = fc_dweb::verifier::STREAM_WINDOW;

    fn doc() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/dweb-verify.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn b64(v: &serde_json::Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(v.as_str().unwrap())
            .unwrap()
    }

    /// The vectors' content: SHA-256(seed ‖ u64_be(i)), concatenated, cut.
    fn content(seed: &str, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n + 32);
        let mut i = 0u64;
        while out.len() < n {
            let mut h = Sha256::new();
            h.update(seed.as_bytes());
            h.update(i.to_be_bytes());
            out.extend_from_slice(&h.finalize());
            i += 1;
        }
        out.truncate(n);
        out
    }

    /// What main answers a piece.
    enum Answer {
        Whole(u16, Vec<(String, String)>, Vec<u8>),
        Stream(u16, Vec<(String, String)>, Vec<u8>),
        /// Never answered: the piece stays out.
        Hold,
    }

    /// The honest nodes of the vectors: Ant's chunks and the files'
    /// contents, the gateway's blocks.
    struct World {
        chunks: HashMap<String, Vec<u8>>,
        files: HashMap<String, Vec<u8>>,
        blocks: HashMap<String, Vec<u8>>,
        /// Pieces whose path starts so are held back.
        hold: Option<String>,
        /// The record answered for any name.
        record: Option<Vec<u8>>,
        /// Entity CARs, by the path they answer.
        cars: HashMap<String, Vec<u8>>,
    }

    impl World {
        fn new() -> Self {
            let d = doc();
            let mut chunks = HashMap::new();
            for (a, w) in d["swarm"]["chunks"].as_object().unwrap() {
                chunks.insert(a.clone(), b64(w));
            }
            let mut files = HashMap::new();
            for m in d["swarm"]["manifests"].as_array().unwrap() {
                for e in m["entries"].as_array().unwrap() {
                    if let (Some(r), Some(seed)) = (e["data_ref"].as_str(), e["seed"].as_str()) {
                        let size = e["size"].as_u64().unwrap() as usize;
                        files.insert(r.to_owned(), content(seed, size));
                    }
                }
            }
            let mut blocks = HashMap::new();
            for (c, b) in d["ipfs"]["blocks"].as_object().unwrap() {
                blocks.insert(c.clone(), b64(b));
            }
            for dir in d["ipfs"]["directories"].as_array().unwrap() {
                for e in dir["entries"].as_array().unwrap() {
                    let size = e["size"].as_u64().unwrap() as usize;
                    let bytes = match (e["text"].as_str(), e["seed"].as_str()) {
                        (Some(t), _) => t.as_bytes().to_vec(),
                        (None, Some(seed)) => content(seed, size),
                        _ => continue,
                    };
                    for l in e["leaves"].as_array().unwrap() {
                        let from = l["from"].as_u64().unwrap() as usize;
                        let len = l["length"].as_u64().unwrap() as usize;
                        blocks
                            .entry(l["cid"].as_str().unwrap().to_owned())
                            .or_insert_with(|| bytes[from..from + len].to_vec());
                    }
                }
            }
            Self {
                chunks,
                files,
                blocks,
                hold: None,
                record: None,
                cars: HashMap::new(),
            }
        }

        /// The CAR a conforming gateway answers for `path`: these blocks,
        /// by their CIDs' text, the first the root.
        fn car(&mut self, path: &str, cids: &[&str]) {
            let sections: Vec<(Vec<u8>, Vec<u8>)> = cids
                .iter()
                .map(|c| (cid_bytes(c), self.blocks[*c].clone()))
                .collect();
            self.cars.insert(path.to_owned(), car(&sections));
        }

        /// The vectors' record `id`.
        fn record(id: &str) -> Vec<u8> {
            let d = doc();
            let r = d["ipfs"]["ipns"]["records"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == id)
                .unwrap()
                .clone();
            b64(&r["record"])
        }

        fn answer(&self, p: &PieceRequest) -> Answer {
            if self.hold.as_deref().is_some_and(|h| p.path.starts_with(h)) {
                return Answer::Hold;
            }
            if let Some(car) = self.cars.get(&p.path) {
                let kind = "application/vnd.ipld.car; version=1; order=dfs; dups=y";
                return Answer::Stream(
                    200,
                    vec![("content-type".into(), kind.into())],
                    car.clone(),
                );
            }
            let not_found = || Answer::Whole(404, vec![], b"{}".to_vec());
            if let Some(a) = p.path.strip_prefix("/chunks/") {
                return match self.chunks.get(a) {
                    Some(w) => Answer::Whole(200, vec![], w.clone()),
                    None => not_found(),
                };
            }
            if let Some(r) = p.path.strip_prefix("/bytes/") {
                let Some(file) = self.files.get(r) else {
                    return Answer::Stream(404, vec![], vec![]);
                };
                let range = p.headers.iter().find(|(n, _)| n == "range").unwrap();
                let (a, b) = range
                    .1
                    .strip_prefix("bytes=")
                    .unwrap()
                    .split_once('-')
                    .unwrap();
                let (a, b): (usize, usize) = (a.parse().unwrap(), b.parse().unwrap());
                let b = b.min(file.len() - 1);
                let cr = format!("bytes {a}-{b}/{}", file.len());
                return Answer::Stream(
                    206,
                    vec![("content-range".into(), cr)],
                    file[a..=b].to_vec(),
                );
            }
            if p.path.starts_with("/ipns/") {
                return match &self.record {
                    Some(r) => Answer::Whole(200, vec![], r.clone()),
                    None => not_found(),
                };
            }
            let cid = p
                .path
                .strip_prefix("/ipfs/")
                .unwrap()
                .split('?')
                .next()
                .unwrap();
            match self.blocks.get(cid) {
                Some(b) => Answer::Stream(
                    200,
                    vec![("content-type".into(), "application/vnd.ipld.raw".into())],
                    b.clone(),
                ),
                None => Answer::Stream(404, vec![], vec![]),
            }
        }
    }

    /// A CIDv1's bytes from its text: `b`, then lowercase base32 without
    /// padding.
    fn cid_bytes(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let (mut acc, mut bits) = (0u32, 0);
        for c in text.strip_prefix('b').unwrap().bytes() {
            let v = match c {
                b'a'..=b'z' => c - b'a',
                b'2'..=b'7' => c - b'2' + 26,
                _ => panic!("{text}"),
            };
            acc = acc << 5 | u32::from(v);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        out
    }

    fn varint(mut v: u64, out: &mut Vec<u8>) {
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    /// A CAR v1 of these sections, rooted at the first.
    fn car(sections: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let root = &sections[0].0;
        let mut h = vec![0xa2, 0x65];
        h.extend_from_slice(b"roots");
        h.extend_from_slice(&[0x81, 0xd8, 0x2a, 0x58, (root.len() + 1) as u8, 0x00]);
        h.extend_from_slice(root);
        h.push(0x67);
        h.extend_from_slice(b"version");
        h.push(0x01);
        let mut out = Vec::new();
        varint(h.len() as u64, &mut out);
        out.extend_from_slice(&h);
        for (cid, block) in sections {
            varint((cid.len() + block.len()) as u64, &mut out);
            out.extend_from_slice(cid);
            out.extend_from_slice(block);
        }
        out
    }

    /// What a `dweb.verify` got.
    #[derive(Debug, Default)]
    struct Got {
        head: Option<Head>,
        body: Vec<u8>,
        ending: Option<String>,
        /// Body bytes not yet credited.
        owed: usize,
    }

    /// The fake thread: it records what the engine does, and holds at
    /// most `cap` of the core's requests at main.
    struct Fake {
        next: u64,
        cap: usize,
        out: Vec<(u64, u64, PieceRequest)>,
        sent: Vec<(u64, PieceRequest)>,
        cancels: Vec<u64>,
        credits: VecDeque<(u64, usize)>,
        jobs: VecDeque<Job>,
        got: BTreeMap<u64, Got>,
    }

    impl Fake {
        fn new(cap: usize) -> Self {
            Self {
                next: 1,
                cap,
                out: Vec::new(),
                sent: Vec::new(),
                cancels: Vec::new(),
                credits: VecDeque::new(),
                jobs: VecDeque::new(),
                got: BTreeMap::new(),
            }
        }

        fn ending(&self, id: u64) -> Option<&str> {
            self.got.get(&id).and_then(|g| g.ending.as_deref())
        }
    }

    impl Io for Fake {
        fn get(&mut self, request: u64, piece: &PieceRequest) -> Get {
            if self.out.len() >= self.cap {
                return Get::Full;
            }
            let get = self.next;
            self.next += 1;
            self.out.push((get, request, piece.clone()));
            self.sent.push((request, piece.clone()));
            Get::Sent(get)
        }
        fn cancel(&mut self, get: u64) {
            self.cancels.push(get);
        }
        fn credit(&mut self, get: u64, bytes: usize) {
            self.credits.push_back((get, bytes));
        }
        fn hash(&mut self, job: Job) {
            self.jobs.push_back(job);
        }
        fn head(&mut self, request: u64, head: Head) {
            self.got.entry(request).or_default().head = Some(head);
        }
        fn error(&mut self, request: u64, error: ErrorPlan) {
            self.got.entry(request).or_default().ending =
                Some(format!("error {} {}", error.status, error.message));
        }
        fn refuse(&mut self, request: u64, refusal: Refusal) {
            self.got.entry(request).or_default().ending = Some(refusal.code().to_owned());
        }
        fn body(&mut self, request: u64, bytes: Vec<u8>) {
            let g = self.got.entry(request).or_default();
            g.owed += bytes.len();
            g.body.extend_from_slice(&bytes);
        }
        fn end(&mut self, request: u64) {
            self.got.entry(request).or_default().ending = Some("end".into());
        }
        fn abort(&mut self, request: u64, code: AbortCode, _: &'static str) {
            self.got.entry(request).or_default().ending = Some(format!("abort {}", code.as_str()));
        }
        fn wall(&self) -> i64 {
            1_760_000_000
        }
    }

    /// A stream main is sending: what is left of its body, and its credit.
    struct Flow {
        body: Vec<u8>,
        at: usize,
        room: usize,
    }

    /// Main and the hashing pool, until nothing moves: each piece answered
    /// as `world` answers it, each job run, the page reading every byte.
    fn settle(e: &mut Engine, f: &mut Fake, w: &World, now: Ms) {
        let mut flows: BTreeMap<u64, Flow> = BTreeMap::new();
        let mut held: Vec<u64> = Vec::new();
        loop {
            if let Some(job) = f.jobs.pop_front() {
                e.hashed(f, now, job.run()).unwrap();
                continue;
            }
            if let Some((get, bytes)) = f.credits.pop_front() {
                if let Some(flow) = flows.get_mut(&get) {
                    flow.room += bytes;
                }
                continue;
            }
            let owed: Vec<(u64, usize)> = f
                .got
                .iter()
                .filter(|(_, g)| g.owed > 0)
                .map(|(&id, g)| (id, g.owed))
                .collect();
            if !owed.is_empty() {
                for (id, n) in owed {
                    f.got.get_mut(&id).unwrap().owed = 0;
                    e.body_credit(f, now, id, n).unwrap();
                }
                continue;
            }
            let fresh: Vec<(u64, u64, PieceRequest)> = f
                .out
                .iter()
                .filter(|(g, _, _)| !flows.contains_key(g) && !held.contains(g))
                .cloned()
                .collect();
            if let Some((get, _, piece)) = fresh.into_iter().next() {
                match w.answer(&piece) {
                    Answer::Whole(status, headers, body) => {
                        f.out.retain(|(g, _, _)| *g != get);
                        let reply = Reply::Whole {
                            status,
                            headers,
                            body,
                        };
                        e.reply(f, now, get, reply).unwrap();
                    }
                    Answer::Stream(status, headers, body) => {
                        flows.insert(
                            get,
                            Flow {
                                body,
                                at: 0,
                                room: WINDOW,
                            },
                        );
                        e.reply(f, now, get, Reply::Stream { status, headers })
                            .unwrap();
                    }
                    Answer::Hold => held.push(get),
                }
                continue;
            }
            // A cancelled piece's terminal, as main answers it.
            if let Some(&get) = f
                .cancels
                .iter()
                .find(|g| f.out.iter().any(|(o, _, _)| o == *g))
            {
                f.out.retain(|(g, _, _)| *g != get);
                held.retain(|g| *g != get);
                let stream = flows.remove(&get).is_some();
                if stream {
                    e.ended_stream(f, now, get, Some(PieceFailure::Aborted))
                        .unwrap();
                } else {
                    e.reply(f, now, get, Reply::Failed(PieceFailure::Aborted))
                        .unwrap();
                }
                continue;
            }
            let mut moved = false;
            for (&get, flow) in flows.iter_mut() {
                if flow.at < flow.body.len() && flow.room > 0 {
                    let n = flow.room.min(64 << 10).min(flow.body.len() - flow.at);
                    let bytes = flow.body[flow.at..flow.at + n].to_vec();
                    flow.at += n;
                    flow.room -= n;
                    e.data(f, now, get, bytes).unwrap();
                    moved = true;
                    break;
                }
                if flow.at == flow.body.len() {
                    f.out.retain(|(g, _, _)| *g != get);
                    flows.remove(&get);
                    e.ended_stream(f, now, get, None).unwrap();
                    moved = true;
                    break;
                }
            }
            if moved {
                continue;
            }
            e.room(f, now);
            if f.jobs.is_empty() && f.credits.is_empty() && f.got.values().all(|g| g.owed == 0) {
                let waiting = f
                    .out
                    .iter()
                    .any(|(g, _, _)| !flows.contains_key(g) && !held.contains(g));
                if !waiting {
                    return;
                }
            }
        }
    }

    fn swarm(root: &str, path: &str) -> Request {
        let backend = Backend::ant(fc_dweb::Ant::External, true);
        Request {
            plan: fc_dweb::Verify {
                node: Node::Ant,
                root: Root::Swarm(root.to_owned()),
                path: path.to_owned(),
                query: String::new(),
                headers: vec![],
                retry: retry(backend),
                timers: timers(backend),
                response: vec![ResponseOp::CanonicalizeRedirect, ResponseOp::StripPageState],
                trust: Trust {
                    name: None,
                    content: ContentTrust::Verified,
                },
            },
            method: Method::Get,
            partition: None,
            private: false,
            deadline_ms: 360_000,
            car: true,
        }
    }

    fn ipfs(root: &str, path: &str) -> Request {
        let backend = Backend::ipfs(fc_dweb::Ipfs::Gateway, true);
        Request {
            plan: fc_dweb::Verify {
                node: Node::Ipfs,
                root: Root::Ipfs(root.to_owned()),
                path: path.to_owned(),
                query: String::new(),
                headers: vec![],
                retry: retry(backend),
                timers: timers(backend),
                response: vec![ResponseOp::StripPageState],
                trust: Trust {
                    name: None,
                    content: ContentTrust::Verified,
                },
            },
            method: Method::Get,
            partition: None,
            private: false,
            deadline_ms: 360_000,
            car: false,
        }
    }

    const SITE_A: &str = "3c8b9184787f719e7184f51b5c595a950d8cec49c765dc0e5a8f1c253e54591c";
    /// The vectors' Ed25519 IPNS name, whose records point at site-v1.
    const NAME: &str = "k51qzi5uqu5dgyzs7wc9fb3dpul2l0yq1x1w2pi7ef703292ycquyorqqukz56";
    const SITE_V1: &str = "bafybeiguwjmddvr4iiah6ekgvrovb5zfb6eg5c6loikxvxlxzlwea5dabm";

    #[test]
    fn honest_requests_through_the_engine() {
        let w = World::new();
        let mut e = Engine::new(Bounds::default());
        let mut f = Fake::new(256);
        e.verify(&mut f, 0, 1, swarm(SITE_A, "/index.html"));
        e.verify(&mut f, 0, 2, swarm(SITE_A, "/style.css"));
        e.verify(&mut f, 0, 3, ipfs(SITE_V1, "/index.html"));
        e.verify(&mut f, 0, 4, ipfs(SITE_V1, "/style.css"));
        settle(&mut e, &mut f, &w, 0);
        for id in 1..=4 {
            assert_eq!(f.ending(id), Some("end"), "{id}: {:?}", f.got.get(&id));
            assert_eq!(f.got[&id].head.as_ref().unwrap().status, 200, "{id}");
        }
        assert_eq!(f.got[&1].body, content("site-index", 300));
        assert_eq!(f.got[&2].body, content("site-style", 5000));
        assert_eq!(
            f.got[&3].body,
            b"<!doctype html><title>site</title><p>index</p>\n"
        );
        assert_eq!(f.got[&4].body, content("ipfs-site-style", 3000));
        // Every grant and stream given back, nothing left queued.
        assert_eq!((e.counts(), e.granted(), e.streams()), ((0, 0), 0, 0));
        assert_eq!(e.queued(), (0, 0));
    }

    #[test]
    fn an_ipfs_file_through_a_car() {
        let mut w = World::new();
        let leaf = "bafkreibllxsbtjemt7nvti7ilxfrqdyml7ne7oe4a7q4fryqj5vkv5hiia";
        let path = format!("/ipfs/{SITE_V1}/index.html?format=car&dag-scope=entity");
        w.car(&path, &[SITE_V1, leaf]);
        let mut e = Engine::new(Bounds::default());
        let mut f = Fake::new(256);
        let mut r = ipfs(SITE_V1, "/index.html");
        r.car = true;
        e.verify(&mut f, 0, 1, r);
        settle(&mut e, &mut f, &w, 0);
        assert_eq!(f.ending(1), Some("end"), "{:?}", f.got.get(&1));
        assert_eq!(
            f.got[&1].body,
            b"<!doctype html><title>site</title><p>index</p>\n"
        );
        // One piece: the CAR, a stream, its blocks hashed on the pool.
        assert_eq!(f.sent.len(), 1, "{:?}", f.sent);
        assert!(f.sent[0].1.stream);
        assert_eq!((e.granted(), e.streams()), (0, 0));
    }

    #[test]
    fn a_range_and_an_ipns_name() {
        let mut w = World::new();
        let mut e = Engine::new(Bounds::default());
        let mut f = Fake::new(256);
        let mut r = swarm(SITE_A, "/style.css");
        r.plan.headers = vec![("range".into(), "bytes=100-199".into())];
        e.verify(&mut f, 0, 1, r);
        // An IPNS name, its record at sequence 4, in the profile's partition.
        w.record = Some(World::record("ed25519-legacy"));
        let mut r = ipfs(SITE_V1, "/index.html");
        r.plan.root = Root::Ipns(NAME.into());
        e.verify(&mut f, 0, 2, r.clone());
        settle(&mut e, &mut f, &w, 0);
        assert_eq!(f.got[&1].head.as_ref().unwrap().status, 206);
        assert_eq!(f.got[&1].body, content("site-style", 5000)[100..200]);
        assert_eq!(f.ending(2), Some("end"));
        let head = f.got[&2].head.as_ref().unwrap();
        assert_eq!(head.trust.content, ContentTrust::LatestAsserted);
        // A record below the floor, in the same partition, is refused; in
        // another, it is accepted.
        w.record = Some(World::record("ed25519-v2"));
        e.verify(&mut f, 0, 3, r.clone());
        let mut other = r;
        other.partition = Some("private-1".into());
        other.private = true;
        e.verify(&mut f, 0, 4, other);
        settle(&mut e, &mut f, &w, 0);
        assert_eq!(
            f.ending(3),
            Some("error 502 IPFS content verification failed")
        );
        assert_eq!(f.ending(4), Some("end"));
        assert_eq!(e.granted(), 0);
    }

    #[test]
    fn a_second_request_reads_the_cache() {
        let w = World::new();
        let mut e = Engine::new(Bounds::default());
        let mut f = Fake::new(256);
        e.verify(&mut f, 0, 1, swarm(SITE_A, "/index.html"));
        settle(&mut e, &mut f, &w, 0);
        let first = f.sent.len();
        assert!(e.cached() > 0);
        e.verify(&mut f, 0, 2, swarm(SITE_A, "/index.html"));
        settle(&mut e, &mut f, &w, 0);
        assert_eq!(f.got[&2].body, f.got[&1].body);
        // The manifest's nodes came from the cache: only the file's root.
        assert!(
            f.sent.len() - first < first,
            "{first} then {}",
            f.sent.len() - first
        );
        // Forgotten, the next request fetches them all again.
        e.forget(None);
        assert_eq!(e.cached(), 0);
        let before = f.sent.len();
        e.verify(&mut f, 0, 3, swarm(SITE_A, "/index.html"));
        settle(&mut e, &mut f, &w, 0);
        assert_eq!(f.sent.len() - before, first);
    }

    #[test]
    fn grants_admit_in_order_and_wait_then_busy() {
        // A gateway that never answers: each request holds its 8 MiB.
        let mut w = World::new();
        w.hold = Some("/ipfs/".into());
        let mut e = Engine::new(Bounds::default());
        let mut f = Fake::new(256);
        for id in 1..=14 {
            e.verify(&mut f, 0, id, ipfs(SITE_V1, "/index.html"));
        }
        settle(&mut e, &mut f, &w, 0);
        // 101 MiB holds twelve 8 MiB grants.
        assert_eq!(e.counts(), (12, 2));
        assert_eq!(e.granted(), 12 * verifier::IPFS_GRANT);
        // A Swarm request behind them waits too, in order, though its
        // 2 MiB would fit.
        e.verify(&mut f, 0, 15, swarm(SITE_A, "/index.html"));
        assert_eq!(e.counts(), (12, 3));
        // One cancelled: its grant goes once its piece has ended, and the
        // first waiting starts.
        e.cancel(&mut f, 1, 1);
        assert_eq!(f.ending(1), Some("cancelled"));
        assert!(e.is_running(1), "its piece is still out");
        settle(&mut e, &mut f, &w, 1);
        assert!(!e.is_running(1));
        assert!(e.is_running(13) && !e.is_running(14));
        assert_eq!(e.counts(), (12, 2));
        // The rest wait 10 s for a grant, then end busy.
        assert_eq!(e.next_due(), Some(GRANT_WAIT_MS));
        e.tick(&mut f, GRANT_WAIT_MS - 1);
        assert_eq!(e.counts().1, 2);
        e.tick(&mut f, GRANT_WAIT_MS);
        assert_eq!((f.ending(14), f.ending(15)), (Some("busy"), Some("busy")));
        assert_eq!(e.counts(), (12, 0));
    }

    #[test]
    fn admission_takes_the_grant_not_the_budget() {
        // A Swarm node that never answers: each request holds its 2 MiB.
        let mut w = World::new();
        w.hold = Some("/".into());
        let mut e = Engine::new(Bounds::default());
        let mut f = Fake::new(256);
        for id in 1..=52 {
            e.verify(&mut f, 0, id, swarm(SITE_A, "/index.html"));
        }
        settle(&mut e, &mut f, &w, 0);
        // 101 MiB holds fifty 2 MiB grants; by the budgets, 52 would run.
        assert_eq!(e.counts(), (50, 2));
        assert_eq!(e.granted(), 50 * verifier::SWARM_GRANT);
    }

    #[test]
    fn past_the_waiting_bound_is_busy_at_once() {
        let mut w = World::new();
        w.hold = Some("/ipfs/".into());
        let bounds = Bounds {
            running: 2,
            waiting: 3,
            ..Bounds::default()
        };
        let mut e = Engine::new(bounds);
        let mut f = Fake::new(256);
        for id in 1..=6 {
            e.verify(&mut f, 0, id, ipfs(SITE_V1, "/index.html"));
        }
        assert_eq!(e.counts(), (2, 3));
        assert_eq!(f.ending(6), Some("busy"));
        // A waiting one cancelled is answered at once, and leaves its place.
        e.cancel(&mut f, 0, 4);
        assert_eq!((f.ending(4), e.counts()), (Some("cancelled"), (2, 2)));
        let _ = w;
    }

    #[test]
    fn a_full_gate_queues_pieces_in_order() {
        let w = World::new();
        let mut e = Engine::new(Bounds::default());
        // Main takes one of the core's requests at a time.
        let mut f = Fake::new(1);
        e.verify(&mut f, 0, 1, swarm(SITE_A, "/index.html"));
        e.verify(&mut f, 0, 2, swarm(SITE_A, "/error.html"));
        // The first request's root went; the second's waits for the gate.
        assert_eq!(f.sent.len(), 1);
        assert_eq!(e.queued(), (1, 0));
        settle(&mut e, &mut f, &w, 0);
        assert_eq!((f.ending(1), f.ending(2)), (Some("end"), Some("end")));
        // Each piece went once, the first request's root before the second's.
        assert_eq!(f.sent[0].0, 1);
        assert_eq!(f.sent[1].0, 2);
    }

    #[test]
    fn past_the_stream_bound_a_streamed_piece_waits() {
        // Streams held back: each IPFS request holds one raw block's stream.
        let mut w = World::new();
        w.hold = Some("/ipfs/".into());
        let bounds = Bounds {
            streams: 2,
            ..Bounds::default()
        };
        let mut e = Engine::new(bounds);
        let mut f = Fake::new(256);
        for id in 1..=3 {
            e.verify(&mut f, 0, id, ipfs(SITE_V1, "/index.html"));
        }
        settle(&mut e, &mut f, &w, 0);
        assert_eq!(e.streams(), 2);
        assert_eq!(e.queued(), (0, 1));
        assert_eq!(f.sent.len(), 2);
        // One cancelled: when its stream ends, the third's piece goes.
        e.cancel(&mut f, 0, 1);
        settle(&mut e, &mut f, &w, 0);
        assert_eq!(e.queued(), (0, 0));
        assert_eq!(f.sent.len(), 3);
        assert_eq!(f.sent[2].0, 3);
    }

    #[test]
    fn a_piece_cancelled_before_it_goes_is_never_sent() {
        let w = World::new();
        let mut e = Engine::new(Bounds::default());
        // Main takes none of the core's requests: every piece waits.
        let mut f = Fake::new(0);
        e.verify(&mut f, 0, 1, swarm(SITE_A, "/index.html"));
        assert_eq!(e.queued(), (1, 0));
        e.cancel(&mut f, 0, 1);
        assert_eq!(f.ending(1), Some("cancelled"));
        // Dropped from the queue, and the request is over: nothing went.
        assert_eq!(e.queued(), (0, 0));
        assert!(!e.is_running(1));
        f.cap = 256;
        settle(&mut e, &mut f, &w, 0);
        assert!(f.sent.is_empty());
        assert_eq!(e.granted(), 0);
    }

    #[test]
    fn deadlines_before_the_head_and_none_after() {
        let mut w = World::new();
        w.hold = Some("/chunks/".into());
        let mut e = Engine::new(Bounds::default());
        let mut f = Fake::new(256);
        let mut r = swarm(SITE_A, "/index.html");
        r.deadline_ms = 1_000;
        e.verify(&mut f, 0, 1, r);
        settle(&mut e, &mut f, &w, 0);
        assert_eq!(e.next_due(), Some(1_000));
        e.tick(&mut f, 1_000);
        assert_eq!(f.ending(1), Some("error 504 Deadline passed"));
        // Its piece is still out: the grant goes once it has ended.
        assert!(e.is_running(1));
        let (get, _, _) = f.out[0].clone();
        f.out.clear();
        e.reply(&mut f, 1_001, get, Reply::Failed(PieceFailure::Aborted))
            .unwrap();
        assert!(!e.is_running(1));
        assert_eq!(e.granted(), 0);
        // After the head, no deadline: a held stream, cancelled, aborts.
        let mut w = World::new();
        w.hold = Some("/bytes/".into());
        let mut r = swarm(SITE_A, "/style.css");
        r.deadline_ms = 1_000;
        e.verify(&mut f, 2_000, 2, r);
        settle(&mut e, &mut f, &w, 2_000);
        assert!(f.got[&2].head.is_some());
        assert_eq!(e.next_due(), None);
        e.tick(&mut f, 10_000);
        assert_eq!(f.ending(2), None);
        e.cancel(&mut f, 10_000, 2);
        assert_eq!(f.ending(2), Some("abort cancelled"));
        settle(&mut e, &mut f, &w, 10_000);
        assert!(!e.is_running(2));
        assert_eq!((e.granted(), e.streams()), (0, 0));
    }

    #[test]
    fn a_waiting_request_past_its_deadline_is_504() {
        let mut w = World::new();
        w.hold = Some("/ipfs/".into());
        let bounds = Bounds {
            running: 1,
            ..Bounds::default()
        };
        let mut e = Engine::new(bounds);
        let mut f = Fake::new(256);
        e.verify(&mut f, 0, 1, ipfs(SITE_V1, "/index.html"));
        let mut r = ipfs(SITE_V1, "/index.html");
        r.deadline_ms = 500;
        e.verify(&mut f, 0, 2, r);
        assert_eq!(e.next_due(), Some(500));
        e.tick(&mut f, 500);
        assert_eq!(f.ending(2), Some("error 504 Deadline passed"));
        assert_eq!(e.counts(), (1, 0));
        let _ = w;
    }

    #[test]
    fn main_faults_are_refused() {
        let mut w = World::new();
        w.hold = Some("/bytes/".into());
        let mut e = Engine::new(Bounds::default());
        let mut f = Fake::new(256);
        e.verify(&mut f, 0, 1, swarm(SITE_A, "/style.css"));
        settle(&mut e, &mut f, &w, 0);
        // A reply for a request of the core's that was never sent.
        assert_eq!(
            e.reply(&mut f, 0, 999, Reply::Failed(PieceFailure::Error)),
            Err(Fault::UnknownPiece)
        );
        // Data before the stream's head.
        let (get, _, _) = f.out[0].clone();
        assert!(matches!(
            e.data(&mut f, 0, get, vec![1]),
            Err(Fault::Misuse(_))
        ));
        // Body credit past what was sent; late credit for a request that
        // has finished is nothing.
        assert!(matches!(
            e.body_credit(&mut f, 0, 1, 1),
            Err(Fault::Misuse(_))
        ));
        assert_eq!(e.body_credit(&mut f, 0, 42, 1), Ok(()));
    }

    #[test]
    fn a_private_request_logs_no_reference() {
        // The log line's fields are fixed codes: the node and the outcome.
        let w = World::new();
        let mut e = Engine::new(Bounds::default());
        let mut f = Fake::new(256);
        let mut r = swarm(SITE_A, "/index.html");
        r.private = true;
        r.partition = Some("private-1".into());
        e.verify(&mut f, 0, 1, r);
        settle(&mut e, &mut f, &w, 0);
        assert_eq!(f.ending(1), Some("end"));
        // Its partition's cache is its own, and forgetting it leaves nothing.
        assert!(e.cached() > 0);
        e.forget(Some("private-1"));
        assert_eq!(e.cached(), 0);
    }
}
