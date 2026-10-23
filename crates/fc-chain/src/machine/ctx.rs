//! What a request's futures share: the executor, the configuration, the
//! router's state tables and the verifier operations held until main's
//! terminal reply.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use fc_naming::session::exec::{Io, Rt, Sleep};

use super::bounds::Bounds;
use super::budget::{self, Budget, Charge};
use super::config::Chain;
use super::faults::{BackedOff, ColibriFaults};
use super::io::{Delivered, Ms, Request, Verdict};
use super::logs::LogState;
use super::route::Adaptive;

/// `MAX_MYOTIS_IN_FLIGHT` and `MAX_MYOTIS_QUEUED`.
pub(crate) const MYOTIS_IN_FLIGHT: usize = 1;
pub(crate) const MYOTIS_QUEUED: usize = 16;
/// `MAX_COLIBRI_IN_FLIGHT` and `MAX_COLIBRI_IN_FLIGHT_PER_ROUTE`.
pub(crate) const COLIBRI_IN_FLIGHT: usize = 8;
pub(crate) const COLIBRI_PER_ROUTE: usize = 2;

pub(crate) type Executor = Rt<Request, Delivered>;

/// A chain's Myotis slots (`myotisSlots`): one read in flight, and the
/// waiters, in order. A waiter holds the slot once granted.
#[derive(Debug, Default)]
pub(crate) struct Slots {
    pub in_flight: usize,
    pub waiters: VecDeque<u64>,
    pub granted: BTreeSet<u64>,
}

/// Colibri's work in flight: in all, and per route (a `Map`, in order).
#[derive(Debug, Default)]
pub(crate) struct ColibriWork {
    pub in_flight: usize,
    pub routes: Vec<(String, usize)>,
}

impl ColibriWork {
    pub(crate) fn route(&self, key: &str) -> usize {
        self.routes
            .iter()
            .find(|(k, _)| k == key)
            .map_or(0, |(_, n)| *n)
    }

    fn add(&mut self, key: &str) {
        self.in_flight += 1;
        match self.routes.iter_mut().find(|(k, _)| k == key) {
            Some(entry) => entry.1 += 1,
            None => self.routes.push((key.to_owned(), 1)),
        }
    }

    fn release(&mut self, key: &str) {
        self.in_flight = self.in_flight.saturating_sub(1);
        if let Some(at) = self.routes.iter().position(|(k, _)| k == key) {
            if self.routes[at].1 > 1 {
                self.routes[at].1 -= 1;
            } else {
                self.routes.remove(at);
            }
        }
    }
}

/// The router's state, shared by every request.
#[derive(Default)]
pub(crate) struct State {
    /// Each configured chain, with its generation.
    pub chains: BTreeMap<u64, (Rc<Chain>, u64)>,
    /// Myotis's readiness per chain, from the last `chain.availability`
    /// (deviation `myotis-readiness`).
    pub ready: BTreeMap<u64, bool>,
    pub adaptive: Adaptive,
    pub myotis: BTreeMap<u64, Slots>,
    pub colibri: ColibriWork,
    /// Colibri's verifier-fault records (design 0005, Colibri).
    pub colibri_faults: ColibriFaults,
    /// Cooldowns started and not yet taken by the driver, for its log.
    pub backed_off: Vec<BackedOff>,
    pub logs: LogState,
    /// Bumped by every grant and release, so the machine polls again.
    pub progress: u64,
    pub next_waiter: u64,
}

/// What a held operation frees when main's terminal reply comes.
#[derive(Debug, Clone)]
pub(crate) enum Release {
    Myotis(u64),
    /// A Colibri slot on its route, and the operation's chain and method,
    /// whose fault record the reply updates.
    Colibri {
        key: String,
        chain_id: u64,
        method: String,
    },
    Nothing,
}

/// Where a held operation's reply goes, if anyone still waits for it.
pub(crate) type ReplyCell = Rc<RefCell<Option<Delivered>>>;

/// A verifier operation kept until main's terminal reply: its slot stays
/// taken until then, whatever the request did (parity).
pub(crate) struct Held {
    io: Io<Request, Delivered>,
    cell: ReplyCell,
    release: Release,
}

/// Everything the requests share.
pub(crate) struct Ctx {
    pub rt: Executor,
    pub bounds: Bounds,
    pub budget: Rc<RefCell<Budget>>,
    pub state: RefCell<State>,
    pub held: RefCell<Vec<Held>>,
    /// The request being polled: what its futures charge goes to it.
    pub current: Cell<u64>,
    /// The charges of requests made and not yet taken by the driver.
    pub pending: RefCell<Vec<Charge>>,
}

/// A request crossed its memory budget (`memory-budgets`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Over;

/// What a future does once its request is over its budget: nothing more.
/// The machine ends the request with `budget` (a broadcast through its
/// outcome table) before it would poll it again.
pub(crate) async fn stall<T>() -> T {
    std::future::pending::<T>().await
}

/// Reserves bytes for the request being polled, or stops its future when
/// that crosses the budget.
macro_rules! reserve {
    ($ctx:expr, $bytes:expr) => {
        match $ctx.reserve($bytes) {
            Ok(charge) => charge,
            Err(_) => return $crate::machine::ctx::stall().await,
        }
    };
}
pub(crate) use reserve;

/// Stops a future whose request crossed its budget.
macro_rules! within {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err($crate::machine::ctx::Over) => return $crate::machine::ctx::stall().await,
        }
    };
}
pub(crate) use within;

impl Ctx {
    pub(crate) fn new(now: Ms, bounds: Bounds) -> Self {
        Self {
            rt: Rt::new(now),
            bounds,
            budget: Rc::new(RefCell::new(Budget::new(
                bounds.request_bytes,
                bounds.total_bytes,
            ))),
            state: RefCell::new(State::default()),
            held: RefCell::new(Vec::new()),
            current: Cell::new(0),
            pending: RefCell::new(Vec::new()),
        }
    }

    pub(crate) fn now(&self) -> Ms {
        self.rt.now()
    }

    /// Reserves `bytes` for the request being polled, before what they
    /// cover is allocated. `Err` once that crosses its budget: the request
    /// is over, and its future must stop ([`stall`]); the machine ends it
    /// with `budget` before polling it again.
    pub(crate) fn reserve(&self, bytes: usize) -> Result<Charge, Over> {
        budget::charge(&self.budget, self.current.get(), bytes).map_err(|_| Over)
    }

    /// A request made: its bytes stay charged to the request until the
    /// driver takes it ([`Ctx::take_pending`]).
    pub(crate) fn pend(&self, charge: Charge) {
        self.pending.borrow_mut().push(charge);
    }

    /// The driver took the requests made: their charges end, and the
    /// driver's backlog counts them until written.
    pub(crate) fn take_pending(&self) {
        self.pending.borrow_mut().clear();
    }

    pub(crate) fn ready(&self, chain_id: u64) -> bool {
        self.state
            .borrow()
            .ready
            .get(&chain_id)
            .copied()
            .unwrap_or(false)
    }

    /// `acquireMyotisSlot`: `Ok(None)` when the slot was free (it is ours),
    /// `Ok(Some(waiter))` when queued, `Err` when the queue is full or a
    /// background caller would have to queue.
    pub(crate) fn acquire_myotis(&self, chain_id: u64, queue: bool) -> Result<Option<u64>, ()> {
        let mut state = self.state.borrow_mut();
        let waiter = state.next_waiter + 1;
        let slots = state.myotis.entry(chain_id).or_default();
        if slots.in_flight < MYOTIS_IN_FLIGHT {
            slots.in_flight += 1;
            return Ok(None);
        }
        if !queue || slots.waiters.len() >= MYOTIS_QUEUED {
            return Err(());
        }
        slots.waiters.push_back(waiter);
        state.next_waiter = waiter;
        Ok(Some(waiter))
    }

    /// Whether `waiter` has been handed the slot.
    pub(crate) fn granted(&self, chain_id: u64, waiter: u64) -> bool {
        let mut state = self.state.borrow_mut();
        let Some(slots) = state.myotis.get_mut(&chain_id) else {
            return false;
        };
        slots.granted.remove(&waiter)
    }

    /// The waiter gave up: out of the queue, or, when it was granted the
    /// slot at that moment, the slot passed along.
    pub(crate) fn abandon_myotis(&self, chain_id: u64, waiter: u64) {
        let queued = {
            let mut state = self.state.borrow_mut();
            let slots = state.myotis.entry(chain_id).or_default();
            match slots.waiters.iter().position(|w| *w == waiter) {
                Some(at) => {
                    slots.waiters.remove(at);
                    true
                }
                None => {
                    slots.granted.remove(&waiter);
                    false
                }
            }
        };
        if !queued {
            self.release_myotis(chain_id);
        }
    }

    /// `releaseMyotisSlot`: handed straight to the next waiter, or freed.
    pub(crate) fn release_myotis(&self, chain_id: u64) {
        let mut state = self.state.borrow_mut();
        state.progress += 1;
        let slots = state.myotis.entry(chain_id).or_default();
        match slots.waiters.pop_front() {
            Some(next) => {
                slots.granted.insert(next);
            }
            None => slots.in_flight = slots.in_flight.saturating_sub(1),
        }
        if slots.in_flight == 0 && slots.waiters.is_empty() && slots.granted.is_empty() {
            state.myotis.remove(&chain_id);
        }
    }

    /// `acquireMyotisSlot` as a claim that gives the slot up when dropped
    /// before its operation is dispatched ([`MyotisClaim`]).
    pub(crate) fn claim_myotis(
        self: &Rc<Self>,
        chain_id: u64,
        queue: bool,
    ) -> Result<MyotisClaim, ()> {
        let state = match self.acquire_myotis(chain_id, queue)? {
            None => Claim::Held,
            Some(waiter) => Claim::Waiting(waiter),
        };
        Ok(MyotisClaim {
            ctx: Rc::clone(self),
            chain_id,
            state,
        })
    }

    /// Takes a Colibri slot for `key`.
    pub(crate) fn add_colibri(&self, key: &str) {
        self.state.borrow_mut().colibri.add(key);
    }

    /// Starts a verifier operation that keeps its slot until main's
    /// terminal reply. The request is made now; its reply lands in the
    /// returned cell, if the cell is still wanted.
    pub(crate) fn hold(&self, request: Request, release: Release) -> ReplyCell {
        let mut io = self.rt.request(request);
        let cell: ReplyCell = Rc::new(RefCell::new(None));
        let mut cx = Context::from_waker(Waker::noop());
        // The first poll emits the request.
        if let Poll::Ready(delivered) = Pin::new(&mut io).poll(&mut cx) {
            self.release(&release, delivered.verdict);
            *cell.borrow_mut() = Some(delivered);
            return cell;
        }
        self.held.borrow_mut().push(Held {
            io,
            cell: Rc::clone(&cell),
            release,
        });
        cell
    }

    /// Frees what a held operation took. A Colibri reply also updates its
    /// chain and method's fault record, as it arrives, whether or not
    /// anyone still reads it (design 0005, Colibri: verifier faults).
    fn release(&self, release: &Release, verdict: Verdict) {
        match release {
            Release::Myotis(chain_id) => self.release_myotis(*chain_id),
            Release::Colibri {
                key,
                chain_id,
                method,
            } => {
                let now = self.now();
                let mut state = self.state.borrow_mut();
                state.progress += 1;
                state.colibri.release(key);
                match verdict {
                    Verdict::Answer => state.colibri_faults.answer(*chain_id, method),
                    Verdict::Fault => {
                        let limit = self.bounds.colibri_fault_records;
                        if let Some(started) =
                            state.colibri_faults.fault(*chain_id, method, now, limit)
                        {
                            state.backed_off.push(started);
                        }
                    }
                    Verdict::Neither => {}
                }
            }
            Release::Nothing => {}
        }
    }

    /// Polls the held operations: each that has its reply frees its slot
    /// and hands the reply on. True when any finished.
    pub(crate) fn poll_held(&self) -> bool {
        let mut cx = Context::from_waker(Waker::noop());
        let mut finished = Vec::new();
        {
            let mut held = self.held.borrow_mut();
            let mut i = 0;
            while i < held.len() {
                if let Poll::Ready(delivered) = Pin::new(&mut held[i].io).poll(&mut cx) {
                    let op = held.remove(i);
                    finished.push((op, delivered));
                } else {
                    i += 1;
                }
            }
        }
        let any = !finished.is_empty();
        for (op, delivered) in finished {
            // Main's terminal reply frees the slot, even one whose payload
            // was over its request's budget and is discarded.
            self.release(&op.release, delivered.verdict);
            // Nobody waits any more: the outcome is dropped.
            if !delivered.discarded && Rc::strong_count(&op.cell) > 1 {
                *op.cell.borrow_mut() = Some(delivered);
            }
        }
        any
    }

    pub(crate) fn progress(&self) -> u64 {
        self.state.borrow().progress
    }
}

/// A request's claim on a chain's Myotis slot: queued, holding the slot,
/// or handed to the operation it dispatched. Dropped before that hand-off
/// (its request cancelled, retired by a configuration change, past its
/// deadline or over its budget; or the read gave up), it gives the slot
/// up: a waiter leaves the queue, a slot granted or held passes on. A
/// dispatched operation keeps the slot until main's terminal reply.
pub(crate) struct MyotisClaim {
    ctx: Rc<Ctx>,
    chain_id: u64,
    state: Claim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Claim {
    Waiting(u64),
    Held,
    Dispatched,
}

impl MyotisClaim {
    /// Whether it is queued, not yet granted the slot.
    pub(crate) fn waiting(&self) -> bool {
        matches!(self.state, Claim::Waiting(_))
    }

    /// Waits until the slot is this claim's.
    pub(crate) async fn granted(&mut self) {
        let Claim::Waiting(waiter) = self.state else {
            return;
        };
        let (ctx, chain_id) = (&self.ctx, self.chain_id);
        std::future::poll_fn(|_| {
            if ctx.granted(chain_id, waiter) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        self.state = Claim::Held;
    }

    /// Dispatches the operation, which keeps the slot until main's
    /// terminal reply.
    pub(crate) fn dispatch(mut self, request: Request) -> ReplyCell {
        self.state = Claim::Dispatched;
        self.ctx.hold(request, Release::Myotis(self.chain_id))
    }
}

impl Drop for MyotisClaim {
    fn drop(&mut self) {
        match self.state {
            Claim::Waiting(waiter) => self.ctx.abandon_myotis(self.chain_id, waiter),
            Claim::Held => self.ctx.release_myotis(self.chain_id),
            Claim::Dispatched => {}
        }
    }
}

/// A sleep that has registered its timer: [`Sleep`] starts counting when
/// first polled, and a timer created before a request fires before that
/// request's answer at the same instant, as in JavaScript.
pub(crate) fn started<Q, A>(mut sleep: Sleep<Q, A>) -> Sleep<Q, A> {
    let mut cx = Context::from_waker(Waker::noop());
    let _ = Pin::new(&mut sleep).poll(&mut cx);
    sleep
}

/// Waits for a held operation's reply.
pub(crate) async fn reply(cell: &ReplyCell) -> Delivered {
    std::future::poll_fn(|_| match cell.borrow_mut().take() {
        Some(delivered) => Poll::Ready(delivered),
        None => Poll::Pending,
    })
    .await
}

/// One chain request's context.
pub(crate) struct Req {
    pub ctx: Rc<Ctx>,
    pub chain: Rc<Chain>,
    /// JSON-RPC ids, per request (deviation `rpc-id`).
    rpc_id: Cell<u64>,
}

impl Req {
    pub(crate) fn new(ctx: Rc<Ctx>, chain: Rc<Chain>) -> Self {
        Self {
            ctx,
            chain,
            rpc_id: Cell::new(0),
        }
    }

    pub(crate) fn next_rpc_id(&self) -> u64 {
        let id = self.rpc_id.get() + 1;
        self.rpc_id.set(id);
        id
    }

    pub(crate) fn now(&self) -> Ms {
        self.ctx.now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slots(ctx: &Ctx, chain_id: u64) -> (usize, usize) {
        ctx.state
            .borrow()
            .myotis
            .get(&chain_id)
            .map_or((0, 0), |s| (s.in_flight, s.waiters.len()))
    }

    #[test]
    fn the_slot_is_handed_straight_to_the_next_waiter() {
        let ctx = Ctx::new(0, Bounds::default());
        assert_eq!(ctx.acquire_myotis(1, true), Ok(None));
        let waiter = ctx.acquire_myotis(1, true).unwrap().unwrap();
        // A background caller never queues.
        assert_eq!(ctx.acquire_myotis(1, false), Err(()));
        assert_eq!(slots(&ctx, 1), (1, 1));
        ctx.release_myotis(1);
        // Handed over, not counted down and up.
        assert_eq!(slots(&ctx, 1), (1, 0));
        assert!(ctx.granted(1, waiter));
        ctx.release_myotis(1);
        assert_eq!(slots(&ctx, 1), (0, 0));
    }

    #[test]
    fn a_slot_granted_as_its_waiter_gives_up_passes_on() {
        // The design leaves this case to the machine's own tests: the slot
        // is handed to a waiter in the very turn its deadline fires. The
        // waiter, gone, passes the slot along rather than leaking it.
        let ctx = Ctx::new(0, Bounds::default());
        ctx.acquire_myotis(1, true).unwrap();
        let first = ctx.acquire_myotis(1, true).unwrap().unwrap();
        let second = ctx.acquire_myotis(1, true).unwrap().unwrap();
        ctx.release_myotis(1);
        // `first` was granted the slot, and abandons it.
        ctx.abandon_myotis(1, first);
        assert!(ctx.granted(1, second));
        assert_eq!(slots(&ctx, 1), (1, 0));
        // A waiter still queued just leaves the queue.
        let third = ctx.acquire_myotis(1, true).unwrap().unwrap();
        ctx.abandon_myotis(1, third);
        assert_eq!(slots(&ctx, 1), (1, 0));
        ctx.release_myotis(1);
        assert_eq!(slots(&ctx, 1), (0, 0));
    }

    #[test]
    fn at_most_sixteen_wait() {
        let ctx = Ctx::new(0, Bounds::default());
        ctx.acquire_myotis(1, true).unwrap();
        for _ in 0..MYOTIS_QUEUED {
            assert!(ctx.acquire_myotis(1, true).unwrap().is_some());
        }
        assert_eq!(ctx.acquire_myotis(1, true), Err(()));
        // Another chain has its own slot.
        assert_eq!(ctx.acquire_myotis(100, true), Ok(None));
    }
}
