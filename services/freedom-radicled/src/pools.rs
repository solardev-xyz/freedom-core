//! The pools and the write queue (design 0008, "Pools and budgets",
//! "Deadlines", "Writes" and "Start, stop and reconciliation").
//!
//! **Three pools, process-wide** ([`Pools`]), each a fixed set of threads
//! and one bounded FIFO queue ([`Shape`]):
//! - **the read pool:** 4 threads, with 320 queued: main's dweb admission of
//!   256, plus 64 for its other callers ([`READ`]);
//! - **the network pool:** 8 threads, with 16 queued, for `connect_seeds`
//!   and `clone` ([`NETWORK`]);
//! - **the write queue:** one writer, with 16 queued ([`WRITE`]).
//!
//! Their threads start with the service, after confinement, and wait for
//! `RUNNING`: a thread that can't be started fails the service's start, as
//! the unit watchdog's does.
//!
//! **Admission** ([`Pool::submit`]) runs on the reader thread and never
//! waits:
//! - before `RUNNING` ([`Pools::open`]), and from the stop on: `stopped`;
//! - with as many requests admitted as the pool has threads and queue
//!   places together: `busy`. A request counts from its admission until its
//!   work returns. So a running request keeps its slot, its thread, until
//!   then, even after its reply, its deadline or a cancel (0008: "keeps its
//!   slot until libradicle returns", "the slot held until the call
//!   returns");
//! - otherwise it is queued behind every request admitted before it, and
//!   the pool's threads take the oldest first.
//!
//! **Deadlines** run from admission ([`Ticket::deadline`]), the time queued
//! included. Each pool's timer thread enforces them from outside the work:
//! - **queued:** a request still queued at its deadline is removed before
//!   its work starts, and answered `deadline`. A thread that takes one at or
//!   past its deadline does the same;
//! - **running:** a request past its deadline is answered `deadline` if
//!   nothing of it has been answered yet (no head and no reply queued), and
//!   its token is cancelled. Once its head is queued it has no service
//!   deadline (0008: "After the head there is no service deadline"). Work
//!   queues its head with `Connection::head_by` at [`Ticket::deadline`], so
//!   one produced past it is never sent.
//!
//! **Cancel** (main's, [`Pools::cancel`]): the connection has answered
//! `cancelled` already. A queued request is removed before its work starts.
//! A running one has its token cancelled, and keeps its slot until its work
//! returns.
//!
//! **The mutation-start boundary** (0008, "Writes"; [`Ticket::begin`]): a
//! write *starts* when its work calls into libradicle's mutation, which it
//! does only once `begin` has claimed the boundary for it. The claim is one
//! decision with each way a request can be answered first, so exactly one
//! of them wins:
//! - **the stop**, which fences the pool under its lock;
//! - **the deadline**, which the timer, or `begin` itself, marks under that
//!   lock before it answers;
//! - **main's cancel**, which the connection answers under its own lock:
//!   `begin` claims the request's commit point there
//!   ([`Connection::commit`]), and fails if anything of it is queued.
//!
//! **Before it, failure is definitive:** a write cancelled, past its
//! deadline or met by the stop never starts, and its answer (`cancelled`,
//! `deadline`, `stopped`) says so. **After it, only a success is proven.**
//! The pool answers a started request `outcome_unknown`, never `deadline`,
//! `cancelled` or `stopped`: at its deadline, at main's cancel (for which
//! the connection queued nothing), past the stop's drain, after a panic,
//! and when its work answers nothing. Its work runs on to its end and keeps
//! its slot. A reply it queues after that is lost: the request has its
//! answer. A started request whose work doesn't mark its outcome proven
//! ([`Ticket::proven`]) leaves the run uncertain ([`Pools::uncertain`]), and
//! the dirty marker stays ([`crate::node`]).
//!
//! **The work** runs on a pool thread, marked as request work for the panic
//! hook. A panic is that request's `internal` error, or its stream's
//! `internal` abort, and the thread goes on. Its token ([`Ticket::cancel`])
//! is libradicle's, which its walk or its clone checks. Work that returns
//! without answering at all is answered `internal`: never a request left
//! waiting.
//!
//! **The stop** ([`Pools::stop`], before the node is asked to stop), within
//! one deadline:
//! 1. every pool is fenced: what arrives from then on is `stopped`;
//! 2. every queued request is removed and answered `stopped`: none ran;
//! 3. every running request has its token cancelled;
//! 4. it waits for every pool thread to end. A request whose work returns
//!    meanwhile is answered `stopped`, or its stream aborted `stopped`,
//!    unless it is settled already, so a reply queued in time stands. Past
//!    the deadline, each request still running is settled so, and the
//!    drain hasn't completed.
//!
//! The drain is complete once every pool thread has ended and been joined:
//! no work is running, so none can still write. The dirty marker is
//! cleared only after a complete drain ([`crate::node`]).
//!
//! **The online repair's turns on the writer** (0008, "Writes": "Online
//! repair after an uncertain write"; [`Repairer`], [`crate::repair`]). A
//! write names the repository it mutates ([`Mutates`]), as it is admitted:
//! - **queued as the call returns:** a write past its start whose work
//!   returns without a proven outcome has its repository's repair queued,
//!   before the writer takes its next task. Until it is over the run is
//!   uncertain ([`Pools::uncertain`]);
//! - **one unit a turn:** the writer takes the repair's turns and the
//!   writes that may run in alternation, so a write to another repository
//!   waits at most one unit, and a repair alone runs unit after unit.
//!   Repairs run in the order they were queued;
//! - **writes to it wait behind it:** a queued write to a repository whose
//!   repair is queued isn't taken until the repair is over. It keeps its
//!   place and its deadline, so the timer, main's cancel and the stop
//!   answer it as any queued request;
//! - **over:** repaired, or quarantined, the repository is certain again,
//!   and its writes run, in their order. A repair that can't go on in this
//!   run, stopped or failed outside its repository, no longer holds its
//!   writes, and leaves the run uncertain for good;
//! - **the stop** fences the repair with the pool: the turn running
//!   finishes its unit, no unit starts after the fence, and the drain waits
//!   for the writer as for any work.
//!
//! **Later steps add operations, not machinery:** a method's work is a
//! closure given its [`Ticket`]. A read's waits for the output budget run
//! inside its deadline and its token ([`crate::output::Until`]).

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::stream::{Abort, AbortCode, Settled};
use fc_service::conn::Connection;
use fc_service::log;
use fc_service::panic::{TaskKind, with_kind};
use libradicle::CancelToken;
use radicle::prelude::RepoId;
use serde_json::json;

/// A pool's threads, and how many requests may wait for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    pub threads: usize,
    pub queued: usize,
}

impl Shape {
    /// The most requests admitted at once, running and queued.
    fn admitted(self) -> usize {
        self.threads + self.queued
    }
}

/// The read pool (0008, "Pools and budgets").
pub const READ: Shape = Shape {
    threads: 4,
    queued: 320,
};

/// The network pool.
pub const NETWORK: Shape = Shape {
    threads: 8,
    queued: 16,
};

/// The write queue.
pub const WRITE: Shape = Shape {
    threads: 1,
    queued: 16,
};

/// A read's deadline, from admission to its head (0008, "Deadlines").
pub const READ_DEADLINE: Duration = Duration::from_secs(60);

/// A write's deadline, from admission.
pub const WRITE_DEADLINE: Duration = Duration::from_secs(60);

/// What a request's work is given.
pub struct Ticket {
    /// The request's ID.
    pub id: u64,
    /// Its deadline, from admission: the head's, for a read.
    pub deadline: Instant,
    /// Cancelled by main's cancel, by the deadline before the head, and by
    /// the stop.
    pub cancel: CancelToken,
    /// Its pool, where its boundary is claimed.
    boundary: Arc<dyn Boundary>,
}

impl Ticket {
    /// The mutation-start boundary (see the module's doc): `true` if this
    /// request's work may call into its mutation now, and the pool answers
    /// it `outcome_unknown` from now on unless its work answers first.
    /// `false` if it is answered or being answered: main cancelled it, its
    /// deadline passed (then this answers it `deadline`, if the timer
    /// hasn't yet), or the stop has begun. Its work must then return
    /// without starting anything, and its answer stands.
    pub fn begin(&self) -> bool {
        self.boundary.begin(self.id)
    }

    /// The work's outcome past the boundary is proven: its mutation
    /// returned success, or failed leaving nothing that needs a repair.
    /// Without it, a started request leaves the run uncertain.
    pub fn proven(&self) {
        self.boundary.proven(self.id);
    }
}

/// A pool's side of [`Ticket::begin`] and [`Ticket::proven`].
trait Boundary: Send + Sync {
    fn begin(&self, id: u64) -> bool;
    fn proven(&self, id: u64);
}

/// A request's work, run once on a pool thread. It answers its request
/// through the connection it holds.
pub type Work = Box<dyn FnOnce(&Ticket) + Send + 'static>;

/// The repository a write mutates, named as it is admitted (see the
/// module's doc): it waits behind that repository's online repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mutates {
    pub rid: RepoId,
    /// Whether an outcome it leaves unknown is repaired online: a COB
    /// write's is. Otherwise the run stays uncertain for good.
    pub repaired: bool,
}

/// What a turn of an online repair did ([`Repairer::turn`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Turn {
    /// It ran a unit, or waited for its repository to close, and more
    /// remain.
    More,
    /// Its repository is repaired, or quarantined: certain again.
    Over,
    /// It can't go on in this run: stopped, or failed outside its
    /// repository. The run stays uncertain.
    Abandoned,
}

/// The online repair, as the writer runs it ([`crate::repair`]).
pub trait Repairer: Send + Sync {
    /// `rid`'s repair is queued: a write to it whose outcome is unknown has
    /// returned. On the writer, before it takes its next task; never waits.
    fn queued(&self, rid: RepoId);

    /// `rid`'s next turn, on the writer: at most one unit, and none once
    /// `stop` is set (the stop's fence).
    fn turn(&self, rid: RepoId, stop: &Arc<AtomicBool>) -> Turn;
}

/// How a pool answers for its requests: the connection, or a test's record.
pub trait Answers: Clone + Send + 'static {
    /// Queues `error` as request `id`'s one reply, unless something
    /// answered it already: whether it did.
    fn refuse(&self, id: u64, error: &ErrorBody) -> bool;

    /// Settles request `id`: `error` as its one reply if nothing of it was
    /// written, `abort` if its stream is open, and nothing if it is settled
    /// already ([`Connection::settle`]): whether it did either.
    fn settle(&self, id: u64, error: &ErrorBody, abort: &Abort) -> bool;

    /// Claims request `id`'s commit point, if nothing of it is queued:
    /// main's cancel then queues nothing for it ([`Connection::commit`]).
    fn commit(&self, id: u64) -> bool;
}

impl Answers for Connection {
    fn refuse(&self, id: u64, error: &ErrorBody) -> bool {
        self.reply_error(id, error).is_ok()
    }

    fn settle(&self, id: u64, error: &ErrorBody, abort: &Abort) -> bool {
        matches!(
            Connection::settle(self, id, error, abort),
            Ok(Settled::Replied | Settled::Aborted)
        )
    }

    fn commit(&self, id: u64) -> bool {
        Connection::commit(self, id)
    }
}

/// What [`Pool::submit`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Queued: its work runs once a thread takes it.
    Queued,
    /// Answered `busy`.
    Busy,
    /// Answered `stopped`.
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Before `RUNNING`.
    Closed,
    Open,
    /// From the stop on, for good.
    Stopped,
}

struct Queued<A> {
    ticket: Ticket,
    answers: A,
    work: Work,
    mutates: Option<Mutates>,
}

/// A request whose work runs: it holds its thread until the work returns.
struct Running<A> {
    id: u64,
    deadline: Instant,
    /// Whether its deadline has been handled: by the timer, or by
    /// [`Ticket::begin`].
    expired: bool,
    cancel: CancelToken,
    answers: A,
    /// Whether its work has passed its mutation start ([`Ticket::begin`]).
    started: bool,
    /// Whether its work marked its outcome proven ([`Ticket::proven`]).
    proven: bool,
    /// The repository it mutates, if it names one.
    mutates: Option<Mutates>,
}

struct State<A> {
    phase: Phase,
    /// Oldest first.
    queue: VecDeque<Queued<A>>,
    running: Vec<Running<A>>,
    /// The pool's threads that haven't ended: its workers and its timer.
    alive: usize,
    /// A started request ended without a proven outcome that no repair
    /// covers, or was still running past the stop's drain, or a repair was
    /// abandoned: for good.
    uncertain: bool,
    /// The repositories whose online repair is queued, oldest first: the
    /// write queue's alone.
    repairs: VecDeque<RepoId>,
    /// Whether the writer's last turn was a repair's: the next goes to a
    /// write, if one may run.
    repaired_last: bool,
}

impl<A> State<A> {
    /// Whether a write of this run may have left a partial mutation that
    /// isn't repaired or quarantined since.
    fn uncertain(&self) -> bool {
        self.uncertain || !self.repairs.is_empty()
    }

    /// Whether `queued` must wait: a write to a repository whose repair is
    /// queued.
    fn held(&self, queued: &Queued<A>) -> bool {
        queued
            .mutates
            .is_some_and(|mutates| self.repairs.contains(&mutates.rid))
    }
}

struct Inner<A> {
    name: &'static str,
    shape: Shape,
    state: Mutex<State<A>>,
    /// The online repair, once the service gives the write queue one.
    repairer: OnceLock<Arc<dyn Repairer>>,
    /// Set by the stop's fence: no repair unit starts after it.
    stopping: Arc<AtomicBool>,
    /// The workers wait on it for queued work, or the stop.
    work: Condvar,
    /// The timer waits on it for its next deadline, a new one, or the stop.
    timer: Condvar,
    /// Notified as each thread ends.
    ended: Condvar,
}

impl<A> Inner<A> {
    fn lock(&self) -> MutexGuard<'_, State<A>> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

fn wait<'a, T>(condvar: &Condvar, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    condvar.wait(guard).unwrap_or_else(|p| p.into_inner())
}

fn wait_for<'a, T>(
    condvar: &Condvar,
    guard: MutexGuard<'a, T>,
    within: Duration,
) -> MutexGuard<'a, T> {
    match condvar.wait_timeout(guard, within) {
        Ok((guard, _)) => guard,
        Err(poisoned) => poisoned.into_inner().0,
    }
}

fn not_running() -> ErrorBody {
    ErrorBody::new(ErrorCode::Stopped, "the Radicle node is not running")
}

fn stopping() -> ErrorBody {
    ErrorBody::new(ErrorCode::Stopped, "the Radicle service is stopping")
}

fn stopping_abort() -> Abort {
    Abort::new(AbortCode::Stopped, "the Radicle service is stopping")
}

fn past_deadline() -> ErrorBody {
    ErrorBody::new(ErrorCode::Deadline, "past its deadline")
}

fn internal() -> ErrorBody {
    ErrorBody::new(ErrorCode::Internal, "Internal error")
}

/// A write past its mutation start whose outcome isn't proven, and `why`
/// (0008, "Writes").
pub fn outcome_unknown(why: &str) -> ErrorBody {
    ErrorBody::new(
        ErrorCode::OutcomeUnknown,
        format!("the write started, and its outcome is unknown: {why}"),
    )
}

/// Logs that request `id` was answered `outcome_unknown`, and why: with its
/// code, never with the write's content (0008, "Writes").
pub fn unknown_logged(id: u64, why: &str) {
    log::error(
        "a write's outcome is unknown",
        json!({ "id": id, "code": "outcome_unknown", "why": why }),
    );
}

/// Answers request `id` `outcome_unknown` for `why` through `answers`, as
/// its one reply, or settles it so (`settle`): logged if it was answered.
fn answer_unknown<A: Answers>(answers: &A, id: u64, why: &str, settle: bool) {
    let error = outcome_unknown(why);
    let answered = if settle {
        answers.settle(id, &error, &stopping_abort())
    } else {
        answers.refuse(id, &error)
    };
    if answered {
        unknown_logged(id, why);
    }
}

/// One pool: its threads, its queue and its timer.
pub struct Pool<A: Answers> {
    inner: Arc<Inner<A>>,
    /// Joined once the drain is complete.
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl<A: Answers> Pool<A> {
    /// Starts the pool's threads, `name`d: `shape.threads` workers and the
    /// timer. Closed until [`Pool::open`].
    pub fn start(name: &'static str, shape: Shape) -> std::io::Result<Self> {
        let pool = Self {
            inner: Arc::new(Inner {
                name,
                shape,
                state: Mutex::new(State {
                    phase: Phase::Closed,
                    queue: VecDeque::new(),
                    running: Vec::new(),
                    alive: 0,
                    uncertain: false,
                    repairs: VecDeque::new(),
                    repaired_last: false,
                }),
                repairer: OnceLock::new(),
                stopping: Arc::new(AtomicBool::new(false)),
                work: Condvar::new(),
                timer: Condvar::new(),
                ended: Condvar::new(),
            }),
            threads: Mutex::new(Vec::new()),
        };
        for n in 0..=shape.threads {
            let inner = pool.inner.clone();
            pool.inner.lock().alive += 1;
            let spawned = if n < shape.threads {
                std::thread::Builder::new()
                    .name(format!("{name}-{}", n + 1))
                    .spawn(move || worker(&inner))
            } else {
                std::thread::Builder::new()
                    .name(format!("{name}-timer"))
                    .spawn(move || timer(&inner))
            };
            match spawned {
                Ok(handle) => pool.lock_threads().push(handle),
                Err(e) => {
                    pool.inner.lock().alive -= 1;
                    // Dropping the pool ends the threads started.
                    return Err(e);
                }
            }
        }
        Ok(pool)
    }

    fn lock_threads(&self) -> MutexGuard<'_, Vec<JoinHandle<()>>> {
        self.threads.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `RUNNING`: the pool admits requests from now on, unless it has
    /// stopped.
    pub fn open(&self) {
        let mut state = self.inner.lock();
        if state.phase == Phase::Closed {
            state.phase = Phase::Open;
        }
    }

    /// Admits request `id`, whose `work` runs before `deadline`, or answers
    /// it `busy` or `stopped` through `answers`. Never waits.
    #[cfg(test)]
    pub fn submit(&self, id: u64, deadline: Instant, answers: A, work: Work) -> Admission {
        self.submit_mutating(id, deadline, answers, work, None)
    }

    /// As [`Pool::submit`], for work that `mutates` a repository, if it
    /// names one: it waits behind that repository's online repair (see the
    /// module's doc).
    pub fn submit_mutating(
        &self,
        id: u64,
        deadline: Instant,
        answers: A,
        work: Work,
        mutates: Option<Mutates>,
    ) -> Admission {
        let mut state = self.inner.lock();
        let refusal = match state.phase {
            Phase::Closed => Some((Admission::Stopped, not_running())),
            Phase::Stopped => Some((Admission::Stopped, stopping())),
            Phase::Open
                if state.queue.len() + state.running.len() >= self.inner.shape.admitted() =>
            {
                Some((
                    Admission::Busy,
                    ErrorBody::new(
                        ErrorCode::Busy,
                        format!("the {} queue is full", self.inner.name),
                    ),
                ))
            }
            Phase::Open => None,
        };
        if let Some((admission, error)) = refusal {
            drop(state);
            answers.refuse(id, &error);
            drop(work);
            return admission;
        }
        state.queue.push_back(Queued {
            ticket: Ticket {
                id,
                deadline,
                cancel: CancelToken::new(),
                boundary: self.inner.clone(),
            },
            answers,
            work,
            mutates,
        });
        drop(state);
        self.inner.work.notify_one();
        self.inner.timer.notify_one();
        Admission::Queued
    }

    /// Main cancelled request `id`, and the connection has answered it: a
    /// queued request is removed, a running one's token cancelled. One
    /// past its mutation start, for which the connection queued nothing,
    /// is answered `outcome_unknown` here. Whether the pool held it.
    pub fn cancel(&self, id: u64) -> bool {
        let mut state = self.inner.lock();
        if let Some(at) = state.queue.iter().position(|q| q.ticket.id == id) {
            let removed = state.queue.remove(at);
            drop(state);
            // Its work is dropped outside the lock, and never runs.
            drop(removed);
            return true;
        }
        if let Some(running) = state.running.iter().find(|r| r.id == id) {
            running.cancel.cancel();
            if running.started {
                let answers = running.answers.clone();
                drop(state);
                // Its work runs on to its end: its reply would be lost.
                answer_unknown(&answers, id, "main cancelled it", false);
            }
            return true;
        }
        false
    }

    /// Whether a write to `rid` that an online repair covers
    /// ([`Mutates::repaired`]) has passed its mutation start without a
    /// proven outcome yet, or `rid`'s repair is queued: until then the
    /// repository may hold a partial mutation (see the module's doc), and
    /// its COB reads are fenced ([`crate::reads`]). Its call still running
    /// counts, whether or not it has been answered `outcome_unknown`, until
    /// its repair is queued, under the same lock, as its work returns.
    pub fn writing(&self, rid: &RepoId) -> bool {
        let state = self.inner.lock();
        state.repairs.contains(rid)
            || state.running.iter().any(|running| {
                running.started
                    && !running.proven
                    && running
                        .mutates
                        .is_some_and(|mutates| mutates.repaired && mutates.rid == *rid)
            })
    }

    /// The stop's first half: fences the pool, answers every queued request
    /// `stopped`, and cancels the running ones' tokens and the online
    /// repair's.
    fn fence(&self) {
        let (queued, running) = {
            let mut state = self.inner.lock();
            state.phase = Phase::Stopped;
            // Under the lock that decides the writer's next turn: no unit
            // starts after it.
            self.inner.stopping.store(true, Ordering::Release);
            let queued = std::mem::take(&mut state.queue);
            let running: Vec<CancelToken> =
                state.running.iter().map(|r| r.cancel.clone()).collect();
            (queued, running)
        };
        self.inner.work.notify_all();
        self.inner.timer.notify_all();
        for queued in queued {
            queued.answers.refuse(queued.ticket.id, &stopping());
        }
        for cancel in running {
            cancel.cancel();
        }
    }

    /// The stop's second half: waits until `deadline` for every thread to
    /// end, then joins them. Past it, settles every request still running
    /// `stopped`. Whether the drain is complete.
    fn drain(&self, deadline: Instant) -> bool {
        let mut state = self.inner.lock();
        while state.alive > 0 {
            match deadline.checked_duration_since(Instant::now()) {
                Some(left) if !left.is_zero() => {
                    state = wait_for(&self.inner.ended, state, left);
                }
                _ => break,
            }
        }
        if state.alive > 0 {
            if state.running.iter().any(|r| r.started && !r.proven) {
                state.uncertain = true;
            }
            let running: Vec<(u64, A, bool)> = state
                .running
                .iter()
                .map(|r| (r.id, r.answers.clone(), r.started))
                .collect();
            drop(state);
            for (id, answers, started) in running {
                if started {
                    answer_unknown(&answers, id, "the service stopped before it returned", true);
                } else {
                    answers.settle(id, &stopping(), &stopping_abort());
                }
            }
            return false;
        }
        drop(state);
        for thread in std::mem::take(&mut *self.lock_threads()) {
            // Each ended its loop: the join returns at once.
            let _ = thread.join();
        }
        true
    }

    /// Fences the pool, then drains it until `deadline` (see the module's
    /// doc): whether the drain is complete.
    #[cfg(test)]
    fn stop(&self, deadline: Instant) -> bool {
        self.fence();
        self.drain(deadline)
    }
}

impl<A: Answers> Boundary for Inner<A> {
    fn begin(&self, id: u64) -> bool {
        let mut state = self.lock();
        if state.phase == Phase::Stopped {
            return false;
        }
        let Some(running) = state.running.iter_mut().find(|r| r.id == id) else {
            return false;
        };
        if running.expired {
            return false;
        }
        if Instant::now() >= running.deadline {
            // Before the timer came to it: answered as the timer answers.
            running.expired = true;
            let (answers, cancel) = (running.answers.clone(), running.cancel.clone());
            drop(state);
            if answers.refuse(id, &past_deadline()) {
                cancel.cancel();
            }
            return false;
        }
        // Main's cancel is decided under the connection's lock: the claim
        // is made there too, nested in this one.
        if !running.answers.commit(id) {
            return false;
        }
        running.started = true;
        true
    }

    fn proven(&self, id: u64) {
        if let Some(running) = self.lock().running.iter_mut().find(|r| r.id == id) {
            running.proven = true;
        }
    }
}

impl<A: Answers> Drop for Pool<A> {
    /// Ends the pool's threads, without waiting for them.
    fn drop(&mut self) {
        self.fence();
    }
}

/// Ends a pool thread's count as the thread ends, however it ends.
struct Leaving<'a, A>(&'a Inner<A>);

impl<A> Drop for Leaving<'_, A> {
    fn drop(&mut self) {
        self.0.lock().alive -= 1;
        self.0.ended.notify_all();
    }
}

/// What a worker runs next.
enum Next<A> {
    /// A request, now running.
    Request(Queued<A>),
    /// A turn of this repository's online repair.
    Repair(RepoId),
}

/// The next task for a worker, once there is one; `None` once the pool has
/// stopped. It is the oldest queued request that isn't held behind an
/// online repair, now running, or the oldest repair's turn: the two take
/// turns while both are there (see the module's doc). A request taken at
/// or past its deadline is answered `deadline`, and its work dropped.
fn next<A: Answers>(inner: &Inner<A>) -> Option<Next<A>> {
    let mut state = inner.lock();
    loop {
        if state.phase == Phase::Stopped {
            return None;
        }
        let request = state.queue.iter().position(|queued| !state.held(queued));
        match (request, state.repairs.front().copied()) {
            (Some(_), Some(_)) if state.repaired_last => {}
            (_, Some(rid)) => {
                state.repaired_last = true;
                return Some(Next::Repair(rid));
            }
            (Some(_), None) => {}
            (None, None) => {
                state = wait(&inner.work, state);
                continue;
            }
        }
        let Some(queued) = request.and_then(|at| state.queue.remove(at)) else {
            continue;
        };
        if Instant::now() >= queued.ticket.deadline {
            drop(state);
            queued.answers.refuse(queued.ticket.id, &past_deadline());
            drop(queued);
            state = inner.lock();
            continue;
        }
        state.repaired_last = false;
        state.running.push(Running {
            id: queued.ticket.id,
            deadline: queued.ticket.deadline,
            expired: false,
            cancel: queued.ticket.cancel.clone(),
            answers: queued.answers.clone(),
            started: false,
            proven: false,
            mutates: queued.mutates,
        });
        return Some(Next::Request(queued));
    }
}

/// A worker: runs the queued requests' work, oldest first, and on the
/// writer the online repair's turns between them, until the pool stops.
fn worker<A: Answers>(inner: &Inner<A>) {
    let _leaving = Leaving(inner);
    while let Some(next) = next(inner) {
        match next {
            Next::Request(queued) => run(inner, queued),
            Next::Repair(rid) => repair_turn(inner, rid),
        }
    }
}

/// One turn of `rid`'s online repair. A panic in it ends the process (70),
/// as one in reconciliation does: a crash, whose next start repairs.
fn repair_turn<A>(inner: &Inner<A>, rid: RepoId) {
    let turn = match inner.repairer.get() {
        Some(repairer) => with_kind(TaskKind::named("repair"), || {
            repairer.turn(rid, &inner.stopping)
        }),
        // Never queued without one.
        None => Turn::Abandoned,
    };
    let mut state = inner.lock();
    match turn {
        Turn::More => {}
        Turn::Over => state.repairs.retain(|queued| *queued != rid),
        Turn::Abandoned => {
            state.repairs.retain(|queued| *queued != rid);
            state.uncertain = true;
        }
    }
}

/// Runs a request's work, answers what it left unanswered, and lets go of
/// its slot.
fn run<A: Answers>(inner: &Inner<A>, queued: Queued<A>) {
    let Queued {
        ticket,
        answers,
        work,
        mutates,
    } = queued;
    let outcome = with_kind(TaskKind::REQUEST, || {
        catch_unwind(AssertUnwindSafe(|| work(&ticket)))
    });
    let (stopping_now, expired, started, proven) = {
        let state = inner.lock();
        let (expired, started, proven) = state
            .running
            .iter()
            .find(|r| r.id == ticket.id)
            .map_or((false, false, false), |r| (r.expired, r.started, r.proven));
        (state.phase == Phase::Stopped, expired, started, proven)
    };
    let id = ticket.id;
    let internal_abort = Abort::new(AbortCode::Internal, "Internal error");
    // A write has no stream: past its start, an abort never applies.
    match (outcome.is_err(), stopping_now, started) {
        (true, _, true) => answer_unknown(&answers, id, "an internal error", true),
        (true, _, false) => {
            answers.settle(id, &internal(), &internal_abort);
        }
        (false, true, true) => answer_unknown(&answers, id, "the service is stopping", true),
        (false, true, false) => {
            answers.settle(id, &stopping(), &stopping_abort());
        }
        // Work that answered nothing: never a request left waiting.
        (false, false, true) => answer_unknown(&answers, id, "it answered nothing", false),
        // Past its deadline: whoever marked it so answers `deadline`,
        // perhaps not yet (a write that didn't start for it).
        (false, false, false) if expired => {}
        (false, false, false) => {
            answers.refuse(id, &internal());
        }
    }
    // Its slot is let go of only now, after its answer: its work has
    // returned. Past its start, an outcome left unknown has its
    // repository's repair queued, before the writer's next task.
    let repairer = inner.repairer.get();
    let mut state = inner.lock();
    let mut queued = None;
    if started && !proven {
        match mutates.filter(|mutates| mutates.repaired).zip(repairer) {
            Some((Mutates { rid, .. }, repairer)) => {
                if !state.repairs.contains(&rid) {
                    state.repairs.push_back(rid);
                }
                queued = Some((rid, repairer));
            }
            None => state.uncertain = true,
        }
    }
    state.running.retain(|r| r.id != id);
    drop(state);
    if let Some((rid, repairer)) = queued {
        repairer.queued(rid);
    }
}

/// The pool's timer: the deadlines of queued and running requests.
fn timer<A: Answers>(inner: &Inner<A>) {
    let _leaving = Leaving(inner);
    let mut state = inner.lock();
    loop {
        if state.phase == Phase::Stopped {
            return;
        }
        let now = Instant::now();
        let expired: VecDeque<Queued<A>> = if state.queue.iter().any(|q| q.ticket.deadline <= now) {
            let (expired, kept) = std::mem::take(&mut state.queue)
                .into_iter()
                .partition(|q| q.ticket.deadline <= now);
            state.queue = kept;
            expired
        } else {
            VecDeque::new()
        };
        let overdue: Vec<(u64, A, CancelToken, bool)> = state
            .running
            .iter_mut()
            .filter(|r| !r.expired && r.deadline <= now)
            .map(|r| {
                r.expired = true;
                (r.id, r.answers.clone(), r.cancel.clone(), r.started)
            })
            .collect();
        if expired.is_empty() && overdue.is_empty() {
            let next = state
                .queue
                .iter()
                .map(|q| q.ticket.deadline)
                .chain(
                    state
                        .running
                        .iter()
                        .filter(|r| !r.expired)
                        .map(|r| r.deadline),
                )
                .min();
            state = match next {
                Some(at) => wait_for(&inner.timer, state, at.saturating_duration_since(now)),
                None => wait(&inner.timer, state),
            };
            continue;
        }
        drop(state);
        for queued in expired {
            queued.answers.refuse(queued.ticket.id, &past_deadline());
        }
        for (id, answers, cancel, started) in overdue {
            if started {
                // Past its mutation start: its work runs on to its end.
                answer_unknown(&answers, id, "its deadline passed", false);
                cancel.cancel();
            } else if answers.refuse(id, &past_deadline()) {
                // Nothing of it answered yet: its head never goes out, and
                // its work stops at its next check.
                cancel.cancel();
            }
        }
        state = inner.lock();
    }
}

/// The service's pools.
pub struct Pools {
    read: Pool<Connection>,
    network: Pool<Connection>,
    write: Pool<Connection>,
}

impl Pools {
    /// Starts every pool's threads, closed until [`Pools::open`].
    pub fn start() -> std::io::Result<Self> {
        Ok(Self {
            read: Pool::start("read", READ)?,
            network: Pool::start("network", NETWORK)?,
            write: Pool::start("write", WRITE)?,
        })
    }

    /// The read pool.
    pub fn read(&self) -> &Pool<Connection> {
        &self.read
    }

    /// The write queue.
    pub fn write(&self) -> &Pool<Connection> {
        &self.write
    }

    /// `RUNNING`: every pool admits requests, unless the stop has begun.
    pub fn open(&self) {
        for pool in self.all() {
            pool.open();
        }
    }

    /// Main cancelled request `id` (see [`Pool::cancel`]).
    pub fn cancel(&self, id: u64) {
        let _ = self.all().iter().any(|pool| pool.cancel(id));
    }

    /// Whether a COB write to `rid` is past its start and unproven, or its
    /// repository's online repair is queued ([`Pool::writing`]).
    pub fn writing(&self, rid: &RepoId) -> bool {
        self.write.writing(rid)
    }

    /// The write queue's online repair, given once (see the module's doc):
    /// until then, a write's unknown outcome leaves the run uncertain for
    /// good.
    pub fn repair_with(&self, repairer: Arc<dyn Repairer>) {
        let _ = self.write.inner.repairer.set(repairer);
    }

    /// Whether a write in this run passed its mutation start without a
    /// proven outcome, and its repository isn't repaired or quarantined
    /// since (see the module's doc): it may hold a partial mutation.
    pub fn uncertain(&self) -> bool {
        self.all().iter().any(|pool| pool.inner.lock().uncertain())
    }

    /// The stop (see the module's doc): every pool fenced, then drained
    /// until `deadline`. Whether every drain is complete.
    pub fn stop(&self, deadline: Instant) -> bool {
        let all = self.all();
        for pool in all {
            pool.fence();
        }
        // Each pool is drained, even past one that isn't.
        let drained: Vec<bool> = all.iter().map(|pool| pool.drain(deadline)).collect();
        drained.into_iter().all(|complete| complete)
    }

    fn all(&self) -> [&Pool<Connection>; 3] {
        [&self.read, &self.network, &self.write]
    }
}

#[cfg(test)]
mod tests;
