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
use super::error::Thrown;
use super::io::{Delivered, Ms, Request};
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
    pub logs: LogState,
    /// Bumped by every grant and release, so the machine polls again.
    pub progress: u64,
    pub next_waiter: u64,
}

/// What a held operation frees when main's terminal reply comes.
#[derive(Debug, Clone)]
pub(crate) enum Release {
    Myotis(u64),
    Colibri(String),
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
}

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
        }
    }

    pub(crate) fn now(&self) -> Ms {
        self.rt.now()
    }

    /// Charges the request being polled. `Err` once it is over its budget;
    /// it then ends at the machine's next poll.
    pub(crate) fn charge(&self, bytes: usize) -> Result<Charge, Thrown> {
        budget::charge(&self.budget, self.current.get(), bytes)
            .map_err(|_| Thrown::error("The request is over its memory budget"))
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
            *cell.borrow_mut() = Some(delivered);
            self.release(&release);
            return cell;
        }
        self.held.borrow_mut().push(Held {
            io,
            cell: Rc::clone(&cell),
            release,
        });
        cell
    }

    fn release(&self, release: &Release) {
        match release {
            Release::Myotis(chain_id) => self.release_myotis(*chain_id),
            Release::Colibri(key) => {
                let mut state = self.state.borrow_mut();
                state.progress += 1;
                state.colibri.release(key);
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
            self.release(&op.release);
            // Nobody waits any more: the outcome is dropped.
            if Rc::strong_count(&op.cell) > 1 {
                *op.cell.borrow_mut() = Some(delivered);
            }
        }
        any
    }

    pub(crate) fn progress(&self) -> u64 {
        self.state.borrow().progress
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
