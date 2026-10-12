//! A sans-I/O executor for the resolvers' JavaScript-shaped control flow.
//!
//! The reference is a tree of promises: `Promise.allSettled`, `Promise.race`
//! and timeouts around I/O. The machine keeps that shape as `async` Rust,
//! and this module drives it without a runtime, threads or `unsafe`:
//!
//! - **Time** moves only when the driver fires a timer. Timers fire one at a
//!   time in (time, sequence) order, sequence being creation order, and the
//!   driver polls after each: JavaScript runs a timer's callback, then its
//!   microtasks, then the next timer.
//! - **I/O** is a request the machine emits as an [`Effect`] and the driver
//!   later completes. Dropping an unfinished request emits a cancellation,
//!   and a completion that arrives after that is ignored.
//! - **External events** (a driver's own deliveries) take a place in the same
//!   timer order, so a replay can interleave them exactly as the reference's
//!   timers did.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

/// Milliseconds on the machine's monotonic clock.
pub type Ms = u64;

/// What the machine asks of its driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect<Q> {
    /// Perform `request`; answer with [`Rt::complete`] and `id`. `owner`
    /// is the owner current when it was made ([`Rt::set_owner`]).
    Request {
        id: u64,
        at: Ms,
        owner: u64,
        request: Q,
    },
    /// The machine no longer waits for request `id`.
    Cancel { id: u64, at: Ms },
}

/// What [`Rt::fire_next`] fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fired {
    /// One of the machine's own timers.
    Timer,
    /// An event the driver scheduled with [`Rt::schedule`].
    External(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Pending,
    Fired,
    External(u64),
}

struct Inner<Q, A> {
    now: Ms,
    seq: u64,
    next_id: u64,
    timers: BTreeMap<(Ms, u64), Slot>,
    /// Each outstanding request's owner, and its answer once it has one.
    io: HashMap<u64, (u64, Option<A>)>,
    effects: Vec<Effect<Q>>,
    owner: u64,
}

/// Decides, as a request is made, whether it may be: one refused is never
/// emitted, and its future never resolves.
type Admit<Q> = Rc<dyn Fn(&Q) -> bool>;

/// The executor's shared state: the clock, timers and outstanding I/O.
/// Clones share it.
pub struct Rt<Q, A> {
    inner: Rc<RefCell<Inner<Q, A>>>,
    admit: Rc<RefCell<Option<Admit<Q>>>>,
}

impl<Q, A> Clone for Rt<Q, A> {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
            admit: Rc::clone(&self.admit),
        }
    }
}

impl<Q, A> Rt<Q, A> {
    pub fn new(now: Ms) -> Self {
        Self {
            inner: Rc::new(RefCell::new(Inner {
                now,
                seq: 0,
                next_id: 1,
                timers: BTreeMap::new(),
                io: HashMap::new(),
                effects: Vec::new(),
                owner: 0,
            })),
            admit: Rc::new(RefCell::new(None)),
        }
    }

    /// Sets the check every request passes as it is made.
    pub fn set_admit(&self, admit: impl Fn(&Q) -> bool + 'static) {
        *self.admit.borrow_mut() = Some(Rc::new(admit));
    }

    pub fn now(&self) -> Ms {
        self.inner.borrow().now
    }

    /// Resolves once `ms` have passed from its first poll, like a
    /// `setTimeout` created at that moment.
    pub fn sleep(&self, ms: Ms) -> Sleep<Q, A> {
        Sleep {
            rt: self.clone(),
            ms,
            key: None,
        }
    }

    /// Emits `request` on its first poll and resolves with the driver's
    /// answer.
    pub fn request(&self, request: Q) -> Io<Q, A> {
        Io {
            rt: self.clone(),
            request: Some(request),
            id: None,
            done: false,
            refused: false,
        }
    }

    /// Tags the requests made from now on with `owner` (0 for none): a
    /// driver polling several roots tells their requests apart by it.
    pub fn set_owner(&self, owner: u64) {
        self.inner.borrow_mut().owner = owner;
    }

    /// The effects emitted since the last call, in order.
    pub fn take_effects(&self) -> Vec<Effect<Q>> {
        std::mem::take(&mut self.inner.borrow_mut().effects)
    }

    /// Answers request `id`. Returns false, and drops the answer, when the
    /// request is unknown, cancelled or already answered.
    pub fn complete(&self, id: u64, answer: A) -> bool {
        match self.inner.borrow_mut().io.get_mut(&id) {
            Some((_, slot @ None)) => {
                *slot = Some(answer);
                true
            }
            _ => false,
        }
    }

    /// The owner of outstanding request `id`.
    pub fn owner_of(&self, id: u64) -> Option<u64> {
        self.inner.borrow().io.get(&id).map(|(owner, _)| *owner)
    }

    /// Schedules an external event `token` at `at`, ordered after every
    /// timer created before it at the same time.
    pub fn schedule(&self, at: Ms, token: u64) {
        let mut inner = self.inner.borrow_mut();
        let seq = inner.seq;
        inner.seq += 1;
        inner.timers.insert((at, seq), Slot::External(token));
    }

    /// When the next timer or external event is due.
    pub fn next_due(&self) -> Option<Ms> {
        self.inner
            .borrow()
            .timers
            .iter()
            .find(|(_, slot)| **slot != Slot::Fired)
            .map(|((at, _), _)| *at)
    }

    /// Fires the first due timer or external event at or before `until`,
    /// moving the clock to its time. With none, moves the clock to `until`
    /// and returns `None`. The clock never goes back.
    pub fn fire_next(&self, until: Ms) -> Option<Fired> {
        let mut inner = self.inner.borrow_mut();
        let next = inner
            .timers
            .iter()
            .find(|(_, slot)| **slot != Slot::Fired)
            .map(|(key, slot)| (*key, *slot));
        match next {
            Some(((at, seq), slot)) if at <= until => {
                inner.now = inner.now.max(at);
                match slot {
                    Slot::External(token) => {
                        inner.timers.remove(&(at, seq));
                        Some(Fired::External(token))
                    }
                    _ => {
                        inner.timers.insert((at, seq), Slot::Fired);
                        Some(Fired::Timer)
                    }
                }
            }
            _ => {
                inner.now = inner.now.max(until);
                None
            }
        }
    }
}

/// See [`Rt::sleep`].
pub struct Sleep<Q, A> {
    rt: Rt<Q, A>,
    ms: Ms,
    key: Option<(Ms, u64)>,
}

impl<Q, A> Future for Sleep<Q, A> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        let rt = self.rt.clone();
        let mut inner = rt.inner.borrow_mut();
        match self.key {
            None => {
                let key = (inner.now.saturating_add(self.ms), inner.seq);
                inner.seq += 1;
                inner.timers.insert(key, Slot::Pending);
                self.key = Some(key);
                Poll::Pending
            }
            Some(key) if inner.timers.get(&key) == Some(&Slot::Fired) => {
                inner.timers.remove(&key);
                Poll::Ready(())
            }
            Some(_) => Poll::Pending,
        }
    }
}

impl<Q, A> Drop for Sleep<Q, A> {
    fn drop(&mut self) {
        if let Some(key) = self.key {
            self.rt.inner.borrow_mut().timers.remove(&key);
        }
    }
}

/// See [`Rt::request`].
pub struct Io<Q, A> {
    rt: Rt<Q, A>,
    request: Option<Q>,
    id: Option<u64>,
    done: bool,
    /// Refused as it was made: never emitted, never resolved.
    refused: bool,
}

impl<Q: Unpin, A> Future for Io<Q, A> {
    type Output = A;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<A> {
        let this = &mut *self;
        if this.refused {
            return Poll::Pending;
        }
        if this.id.is_none() {
            let admit = this.rt.admit.borrow().clone();
            if let (Some(admit), Some(request)) = (admit, this.request.as_ref())
                && !admit(request)
            {
                this.refused = true;
                this.request = None;
                return Poll::Pending;
            }
        }
        let mut inner = this.rt.inner.borrow_mut();
        match this.id {
            None => {
                let id = inner.next_id;
                inner.next_id += 1;
                let (at, owner) = (inner.now, inner.owner);
                inner.io.insert(id, (owner, None));
                if let Some(request) = this.request.take() {
                    inner.effects.push(Effect::Request {
                        id,
                        at,
                        owner,
                        request,
                    });
                }
                this.id = Some(id);
                Poll::Pending
            }
            Some(id) => match inner.io.get_mut(&id).and_then(|(_, slot)| slot.take()) {
                Some(answer) => {
                    inner.io.remove(&id);
                    this.done = true;
                    Poll::Ready(answer)
                }
                None => Poll::Pending,
            },
        }
    }
}

impl<Q, A> Drop for Io<Q, A> {
    fn drop(&mut self) {
        if let (Some(id), false) = (self.id, self.done) {
            let mut inner = self.rt.inner.borrow_mut();
            inner.io.remove(&id);
            let at = inner.now;
            inner.effects.push(Effect::Cancel { id, at });
        }
    }
}

/// A boxed future, as the combinators take them.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// `Promise.allSettled`: every future runs to completion; results keep the
/// input order. Unfinished children are polled in order on each poll.
pub async fn all<T>(futures: Vec<BoxFuture<'_, T>>) -> Vec<T> {
    let mut results: Vec<Option<T>> = futures.iter().map(|_| None).collect();
    let mut futures: Vec<Option<BoxFuture<'_, T>>> = futures.into_iter().map(Some).collect();
    std::future::poll_fn(move |cx| {
        for (result, future) in results.iter_mut().zip(futures.iter_mut()) {
            if let Some(running) = future
                && let Poll::Ready(value) = running.as_mut().poll(cx)
            {
                *result = Some(value);
                *future = None;
            }
        }
        if results.iter().all(Option::is_some) {
            Poll::Ready(results.iter_mut().filter_map(Option::take).collect())
        } else {
            Poll::Pending
        }
    })
    .await
}

/// `Promise.all`: every output in input order, or the first error as soon
/// as it settles. The others are dropped then, which cancels their I/O.
pub async fn try_all<T, E>(futures: Vec<BoxFuture<'_, Result<T, E>>>) -> Result<Vec<T>, E> {
    let mut results: Vec<Option<T>> = futures.iter().map(|_| None).collect();
    let mut futures: Vec<Option<BoxFuture<'_, Result<T, E>>>> =
        futures.into_iter().map(Some).collect();
    std::future::poll_fn(move |cx| {
        for (result, future) in results.iter_mut().zip(futures.iter_mut()) {
            if let Some(running) = future
                && let Poll::Ready(value) = running.as_mut().poll(cx)
            {
                *future = None;
                match value {
                    Ok(value) => *result = Some(value),
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
        }
        if results.iter().all(Option::is_some) {
            Poll::Ready(Ok(results.iter_mut().filter_map(Option::take).collect()))
        } else {
            Poll::Pending
        }
    })
    .await
}

/// One of two outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Either<L, R> {
    Left(L),
    Right(R),
}

/// `Promise.race` of two: the first to finish wins, `left` when both are
/// ready on the same poll. The loser is dropped, which cancels its I/O.
pub async fn race<L, R>(
    left: impl Future<Output = L>,
    right: impl Future<Output = R>,
) -> Either<L, R> {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    std::future::poll_fn(move |cx| {
        if let Poll::Ready(value) = left.as_mut().poll(cx) {
            return Poll::Ready(Either::Left(value));
        }
        if let Poll::Ready(value) = right.as_mut().poll(cx) {
            return Poll::Ready(Either::Right(value));
        }
        Poll::Pending
    })
    .await
}

/// A root future, polled by the driver after each event.
pub struct Task<'a, T> {
    future: BoxFuture<'a, T>,
    output: Option<T>,
    /// Set once the future has completed: it is never polled again, even
    /// after [`Task::take`] emptied `output`.
    done: bool,
}

impl<'a, T> Task<'a, T> {
    pub fn new(future: impl Future<Output = T> + 'a) -> Self {
        Self {
            future: Box::pin(future),
            output: None,
            done: false,
        }
    }

    /// Polls once; true once the future has completed.
    pub fn poll(&mut self) -> bool {
        if !self.done {
            let mut cx = Context::from_waker(Waker::noop());
            if let Poll::Ready(value) = self.future.as_mut().poll(&mut cx) {
                self.output = Some(value);
                self.done = true;
            }
        }
        self.done
    }

    pub fn take(&mut self) -> Option<T> {
        self.output.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type R = Rt<&'static str, &'static str>;

    #[test]
    fn try_all_fails_fast_and_cancels_the_rest() {
        let rt = R::new(0);
        let slow = rt.request("slow");
        let failing = rt.sleep(10);
        let mut task = Task::new(try_all::<&str, &str>(vec![
            Box::pin(async move { Ok(slow.await) }),
            Box::pin(async move {
                failing.await;
                Err("failed")
            }),
        ]));
        assert!(!task.poll());
        let effects = rt.take_effects();
        let Some(Effect::Request { id, .. }) = effects.first() else {
            panic!("no request");
        };
        let id = *id;
        assert_eq!(rt.fire_next(100), Some(Fired::Timer));
        assert!(task.poll());
        assert_eq!(task.take(), Some(Err("failed")));
        // The slow request was cancelled when the error settled, at 10 ms.
        assert!(matches!(
            rt.take_effects().as_slice(),
            [Effect::Cancel { id: cancelled, at: 10 }] if *cancelled == id
        ));
    }

    #[test]
    fn a_completed_task_is_never_polled_again() {
        let mut task = Task::new(async { 42 });
        assert!(task.poll());
        assert_eq!(task.take(), Some(42));
        assert!(task.poll());
        assert_eq!(task.take(), None);
    }

    async fn with_timeout(
        rt: &R,
        ms: Ms,
        request: &'static str,
    ) -> Result<&'static str, &'static str> {
        match race(rt.request(request), rt.sleep(ms)).await {
            Either::Left(answer) => Ok(answer),
            Either::Right(()) => Err("timeout"),
        }
    }

    /// Drives `task` to completion, firing everything due up to `until`.
    fn run<T>(rt: &R, task: &mut Task<'_, T>, until: Ms) -> bool {
        loop {
            if task.poll() {
                return true;
            }
            if rt.fire_next(until).is_none() {
                return task.poll();
            }
        }
    }

    #[test]
    fn a_timed_out_request_is_cancelled_and_its_late_answer_dropped() {
        let rt: R = Rt::new(0);
        let legs = rt.clone();
        let mut task = Task::new(async move {
            all(vec![
                Box::pin(with_timeout(&legs, 5000, "a")),
                Box::pin(with_timeout(&legs, 5000, "b")),
            ])
            .await
        });
        assert!(!task.poll());
        assert_eq!(
            rt.take_effects(),
            vec![
                Effect::Request {
                    id: 1,
                    at: 0,
                    owner: 0,
                    request: "a"
                },
                Effect::Request {
                    id: 2,
                    at: 0,
                    owner: 0,
                    request: "b"
                },
            ]
        );
        assert!(rt.complete(1, "A"));
        assert!(run(&rt, &mut task, 10_000));
        assert_eq!(task.take(), Some(vec![Ok("A"), Err("timeout")]));
        assert_eq!(rt.now(), 5000);
        assert_eq!(rt.take_effects(), vec![Effect::Cancel { id: 2, at: 5000 }]);
        // The winner's timer went with it.
        assert_eq!(rt.next_due(), None);
        assert!(!rt.complete(2, "late"));
    }

    #[test]
    fn timers_fire_in_time_then_creation_order() {
        let rt: R = Rt::new(0);
        let log = Rc::new(RefCell::new(Vec::new()));
        let (r, l) = (rt.clone(), Rc::clone(&log));
        let mut task = Task::new(async move {
            let tick = |name: &'static str, ms: Ms| {
                let (r, l) = (r.clone(), Rc::clone(&l));
                Box::pin(async move {
                    r.sleep(ms).await;
                    l.borrow_mut().push((name, r.now()));
                }) as BoxFuture<'_, ()>
            };
            all(vec![
                tick("late", 20),
                tick("first", 10),
                tick("second", 10),
            ])
            .await;
        });
        assert!(run(&rt, &mut task, 100));
        assert_eq!(
            *log.borrow(),
            vec![("first", 10), ("second", 10), ("late", 20)]
        );
    }

    #[test]
    fn external_events_take_their_place_in_timer_order() {
        let rt: R = Rt::new(0);
        let r = rt.clone();
        let mut task = Task::new(async move { with_timeout(&r, 10, "a").await });
        assert!(!task.poll());
        // Scheduled after the timeout's timer at the same instant: the
        // timeout fires first, as in JavaScript.
        rt.schedule(10, 7);
        assert_eq!(rt.fire_next(100), Some(Fired::Timer));
        assert!(task.poll());
        assert_eq!(task.take(), Some(Err("timeout")));
        assert_eq!(rt.fire_next(100), Some(Fired::External(7)));
        assert!(!rt.complete(1, "too late"));
    }

    #[test]
    fn the_clock_moves_to_the_horizon_when_nothing_is_due() {
        let rt: R = Rt::new(5);
        assert_eq!(rt.fire_next(40), None);
        assert_eq!(rt.now(), 40);
        assert_eq!(rt.fire_next(10), None);
        assert_eq!(rt.now(), 40);
    }
}
