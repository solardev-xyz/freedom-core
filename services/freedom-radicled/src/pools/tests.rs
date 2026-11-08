#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use super::*;

/// What a request got, as the connection's sender would hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    /// An error reply.
    Error(ErrorCode),
    /// The work's own reply.
    Done,
    /// A network operation's `{ cancelled }` result.
    Cancelled,
    /// The work's head, its stream open.
    Head,
    /// Its stream aborted.
    Abort(AbortCode),
}

/// The answers, as the connection's sender keeps them: one reply or head
/// per request, and an abort only for an open stream; and the requests
/// whose commit point their work claimed.
#[derive(Clone, Default)]
struct Record {
    answers: Arc<Mutex<HashMap<u64, Answer>>>,
    committed: Arc<Mutex<HashSet<u64>>>,
    /// While set for an ID, a refusal of it waits until this is cleared:
    /// the timer held between deciding a deadline and answering it.
    stall: Arc<Mutex<Option<u64>>>,
}

impl Record {
    fn get(&self, id: u64) -> Option<Answer> {
        self.answers.lock().unwrap().get(&id).cloned()
    }

    /// Queues `answer` as `id`'s reply or head, unless it has one.
    fn answer(&self, id: u64, answer: Answer) -> bool {
        let mut answers = self.answers.lock().unwrap();
        if answers.contains_key(&id) {
            return false;
        }
        answers.insert(id, answer);
        true
    }

    /// Main's cancel, as the connection handles it: `cancelled`, unless
    /// answered or committed; then the pool is told.
    fn cancel(&self, pool: &Pool<Record>, id: u64) -> bool {
        if !self.committed.lock().unwrap().contains(&id) {
            self.answer(id, Answer::Error(ErrorCode::Cancelled));
        }
        pool.cancel(id)
    }

    /// Main's cancel as the connection queues it, before it tells the
    /// pool.
    fn cancelled_unseen(&self, id: u64) {
        assert!(!self.committed.lock().unwrap().contains(&id));
        self.answer(id, Answer::Error(ErrorCode::Cancelled));
    }

    fn stall(&self, id: Option<u64>) {
        *self.stall.lock().unwrap() = id;
    }

    fn count(&self, answer: &Answer) -> usize {
        self.answers
            .lock()
            .unwrap()
            .values()
            .filter(|a| *a == answer)
            .count()
    }
}

impl Answers for Record {
    fn refuse(&self, id: u64, error: &ErrorBody) -> bool {
        while *self.stall.lock().unwrap() == Some(id) {
            std::thread::sleep(Duration::from_millis(2));
        }
        self.answer(id, Answer::Error(error.code))
    }

    fn settle(&self, id: u64, error: &ErrorBody, abort: &Abort) -> bool {
        let mut answers = self.answers.lock().unwrap();
        match answers.get(&id) {
            None => {
                answers.insert(id, Answer::Error(error.code));
                true
            }
            Some(Answer::Head) => {
                answers.insert(id, Answer::Abort(abort.code));
                true
            }
            Some(_) => false,
        }
    }

    fn commit(&self, id: u64) -> bool {
        let answers = self.answers.lock().unwrap();
        if answers.contains_key(&id) {
            return false;
        }
        self.committed.lock().unwrap().insert(id);
        true
    }
}

/// Holds work until released.
#[derive(Clone, Default)]
struct Hold(Arc<AtomicBool>);

impl Hold {
    fn release(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn released(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// How a test's work behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Waits for its release, or its token: released, it answers; cancelled,
    /// it returns without answering, as a walk stopped at its check does.
    Heeds,
    /// Waits for its release only, whatever its token: a call that doesn't
    /// check it. Then it answers.
    Deaf,
    /// Queues its head first, then waits as `Heeds` does: released, it
    /// ends its stream; cancelled, it returns with its stream open.
    Headed,
}

/// What a test's work reports: its ID as it starts, and, as it returns,
/// whether its token was cancelled.
struct Probe {
    started: mpsc::Receiver<u64>,
    returned: mpsc::Receiver<(u64, bool)>,
    tx: (mpsc::Sender<u64>, mpsc::Sender<(u64, bool)>),
}

impl Probe {
    fn new() -> Self {
        let (started_tx, started) = mpsc::channel();
        let (returned_tx, returned) = mpsc::channel();
        Self {
            started,
            returned,
            tx: (started_tx, returned_tx),
        }
    }

    fn work(&self, record: &Record, hold: &Hold, kind: Kind) -> Work {
        let (started, returned) = self.tx.clone();
        let (record, hold) = (record.clone(), hold.clone());
        Box::new(move |ticket: &Ticket| {
            let _ = started.send(ticket.id);
            if kind == Kind::Headed {
                record.answer(ticket.id, Answer::Head);
            }
            loop {
                if hold.released() {
                    if kind == Kind::Headed {
                        record
                            .answers
                            .lock()
                            .unwrap()
                            .insert(ticket.id, Answer::Done);
                    } else {
                        record.answer(ticket.id, Answer::Done);
                    }
                    break;
                }
                if kind != Kind::Deaf && ticket.cancel.is_cancelled() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            let _ = returned.send((ticket.id, ticket.cancel.is_cancelled()));
        })
    }

    fn started(&self) -> u64 {
        self.started.recv_timeout(GUARD).unwrap()
    }

    fn returned(&self) -> (u64, bool) {
        self.returned.recv_timeout(GUARD).unwrap()
    }

    /// Nothing more starts within a short wait.
    fn no_start(&self) {
        assert_eq!(
            self.started.recv_timeout(Duration::from_millis(150)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
    }
}

/// How long a wait for something that should happen gets: a hang guard,
/// never a timing assertion. Generous, because a slow runner's disk can
/// stall every process of a test binary for seconds at once (on Windows
/// CI, 5.9 s seen, issue #311), work that touches no disk included.
const GUARD: Duration = Duration::from_secs(60);

fn far() -> Instant {
    Instant::now() + Duration::from_secs(600)
}

fn soon(ms: u64) -> Instant {
    Instant::now() + Duration::from_millis(ms)
}

/// A stop's or a drain's deadline when it should complete: [`GUARD`].
fn guard() -> Instant {
    Instant::now() + GUARD
}

/// Puts running request `id`'s deadline at now, and wakes the timer: past
/// its deadline from the point the test chose, as after its work started.
/// A short deadline given at admission would race the work's start, which
/// a stalled runner can hold up past it.
fn expire(pool: &Pool<Record>, id: u64) {
    let mut state = pool.inner.lock();
    let running = state.running.iter_mut().find(|r| r.id == id);
    running.expect("it runs").deadline = Instant::now();
    drop(state);
    pool.inner.timer.notify_all();
}

fn until(done: impl Fn() -> bool) -> bool {
    let end = Instant::now() + GUARD;
    while !done() {
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    true
}

fn open(shape: Shape) -> Pool<Record> {
    let pool = Pool::start("test", shape).unwrap();
    pool.open();
    pool
}

fn alive(pool: &Pool<Record>) -> usize {
    pool.inner.lock().alive
}

/// The pool's threads have ended and been joined.
fn joined(pool: &Pool<Record>) -> bool {
    alive(pool) == 0 && pool.lock_threads().is_empty()
}

fn shape(threads: usize, queued: usize) -> Shape {
    Shape { threads, queued }
}

#[test]
fn the_pools_have_0008s_shapes_and_their_stop_joins_every_thread() {
    assert_eq!(READ, shape(4, 320));
    assert_eq!(NETWORK, shape(8, 16));
    assert_eq!(WRITE, shape(1, 16));
    assert_eq!(READ_DEADLINE, Duration::from_secs(60));
    assert_eq!(WRITE_DEADLINE, Duration::from_secs(60));

    let pools = Pools::start().unwrap();
    assert_eq!(pools.read.inner.shape, READ);
    assert_eq!(pools.network.inner.shape, NETWORK);
    assert_eq!(pools.write.inner.shape, WRITE);
    // Each pool's workers and its timer.
    for (pool, threads) in [(&pools.read, 5), (&pools.network, 9), (&pools.write, 2)] {
        assert_eq!(pool.inner.lock().alive, threads);
        assert_eq!(pool.lock_threads().len(), threads);
    }
    pools.open();
    assert!(pools.stop(guard()));
    for pool in pools.all() {
        assert_eq!(pool.inner.lock().alive, 0);
        assert!(pool.lock_threads().is_empty());
        assert_eq!(pool.inner.lock().phase, Phase::Stopped);
    }
}

#[test]
fn the_read_pool_admits_4_running_and_320_queued_then_is_busy() {
    let (record, hold, probe) = (Record::default(), Hold::default(), Probe::new());
    let pool = open(READ);
    for id in 1..=324 {
        let work = probe.work(&record, &hold, Kind::Heeds);
        assert_eq!(
            pool.submit(id, far(), record.clone(), work),
            Admission::Queued
        );
    }
    let work = probe.work(&record, &hold, Kind::Heeds);
    assert_eq!(
        pool.submit(325, far(), record.clone(), work),
        Admission::Busy
    );
    assert_eq!(record.get(325), Some(Answer::Error(ErrorCode::Busy)));
    // The four oldest run; the rest wait.
    let mut running: Vec<u64> = (0..4).map(|_| probe.started()).collect();
    running.sort_unstable();
    assert_eq!(running, vec![1, 2, 3, 4]);
    probe.no_start();

    assert!(pool.stop(guard()));
    assert_eq!(record.count(&Answer::Error(ErrorCode::Stopped)), 324);
    assert!(joined(&pool));
}

#[test]
fn a_running_request_keeps_its_slot_until_its_work_returns() {
    let (record, hold, probe) = (Record::default(), Hold::default(), Probe::new());
    let pool = open(shape(2, 1));
    for id in 1..=3 {
        let work = probe.work(&record, &hold, Kind::Deaf);
        assert_eq!(
            pool.submit(id, far(), record.clone(), work),
            Admission::Queued
        );
    }
    let work = probe.work(&record, &hold, Kind::Deaf);
    assert_eq!(pool.submit(4, far(), record.clone(), work), Admission::Busy);
    probe.started();
    probe.started();
    // Cancelled, a running request still holds its thread.
    assert!(record.cancel(&pool, 1));
    let work = probe.work(&record, &hold, Kind::Deaf);
    assert_eq!(pool.submit(5, far(), record.clone(), work), Admission::Busy);

    hold.release();
    // Returned, they let go: the queued one runs, and two more fit.
    for _ in 0..3 {
        probe.returned();
    }
    assert!(until(|| pool.inner.lock().running.is_empty()));
    for id in 6..=8 {
        let work = probe.work(&record, &hold, Kind::Deaf);
        assert_eq!(
            pool.submit(id, far(), record.clone(), work),
            Admission::Queued
        );
    }
    // Released, they run at once; the stop comes after.
    assert!(until(|| (6..=8).all(|id| record.get(id).is_some())));
    assert!(pool.stop(guard()));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Cancelled)));
    for id in [2, 3, 6, 7, 8] {
        assert_eq!(record.get(id), Some(Answer::Done), "{id}");
    }
}

#[test]
fn requests_before_open_and_after_the_stop_are_stopped() {
    let (record, hold, probe) = (Record::default(), Hold::default(), Probe::new());
    let pool = Pool::start("test", shape(1, 1)).unwrap();
    let work = probe.work(&record, &hold, Kind::Heeds);
    assert_eq!(
        pool.submit(1, far(), record.clone(), work),
        Admission::Stopped
    );
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Stopped)));
    pool.open();
    assert!(pool.stop(guard()));
    // The stop is for good.
    pool.open();
    let work = probe.work(&record, &hold, Kind::Heeds);
    assert_eq!(
        pool.submit(2, far(), record.clone(), work),
        Admission::Stopped
    );
    assert_eq!(record.get(2), Some(Answer::Error(ErrorCode::Stopped)));
    probe.no_start();
    assert!(joined(&pool));
}

#[test]
fn the_queue_runs_in_admission_order() {
    let (record, hold, probe) = (Record::default(), Hold::default(), Probe::new());
    let pool = open(shape(1, 8));
    let order = Arc::new(Mutex::new(Vec::new()));
    let work = probe.work(&record, &hold, Kind::Deaf);
    pool.submit(1, far(), record.clone(), work);
    assert_eq!(probe.started(), 1);
    for id in 2..=9 {
        let (order, answering) = (order.clone(), record.clone());
        let work: Work = Box::new(move |ticket: &Ticket| {
            order.lock().unwrap().push(ticket.id);
            answering.answer(ticket.id, Answer::Done);
        });
        assert_eq!(
            pool.submit(id, far(), record.clone(), work),
            Admission::Queued
        );
    }
    hold.release();
    assert!(until(|| order.lock().unwrap().len() == 8));
    assert_eq!(*order.lock().unwrap(), (2..=9).collect::<Vec<u64>>());
    assert!(pool.stop(guard()));
}

#[test]
fn a_cancelled_queued_request_never_runs_and_frees_its_place() {
    let (record, hold, probe) = (Record::default(), Hold::default(), Probe::new());
    let pool = open(shape(1, 1));
    let work = probe.work(&record, &hold, Kind::Deaf);
    pool.submit(1, far(), record.clone(), work);
    assert_eq!(probe.started(), 1);
    let work = probe.work(&record, &hold, Kind::Deaf);
    assert_eq!(
        pool.submit(2, far(), record.clone(), work),
        Admission::Queued
    );
    let work = probe.work(&record, &hold, Kind::Deaf);
    assert_eq!(pool.submit(3, far(), record.clone(), work), Admission::Busy);

    assert!(record.cancel(&pool, 2));
    let work = probe.work(&record, &hold, Kind::Deaf);
    assert_eq!(
        pool.submit(4, far(), record.clone(), work),
        Admission::Queued
    );
    hold.release();
    assert_eq!(probe.returned(), (1, false));
    assert_eq!(probe.started(), 4);
    assert_eq!(probe.returned(), (4, false));
    probe.no_start();
    assert_eq!(record.get(2), Some(Answer::Error(ErrorCode::Cancelled)));
    // A request the pool doesn't hold.
    assert!(!pool.cancel(2));
    assert!(pool.stop(guard()));
}

#[test]
fn a_cancelled_running_request_has_its_token_cancelled() {
    let (record, hold, probe) = (Record::default(), Hold::default(), Probe::new());
    let pool = open(shape(1, 0));
    let work = probe.work(&record, &hold, Kind::Heeds);
    pool.submit(1, far(), record.clone(), work);
    assert_eq!(probe.started(), 1);
    assert!(record.cancel(&pool, 1));
    assert_eq!(probe.returned(), (1, true));
    // The connection answered it; its work answered nothing more.
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Cancelled)));
    assert!(pool.stop(guard()));
}

#[test]
fn a_queued_request_past_its_deadline_is_deadline_and_never_runs() {
    let (record, hold, probe) = (Record::default(), Hold::default(), Probe::new());
    let pool = open(shape(1, 3));
    let work = probe.work(&record, &hold, Kind::Deaf);
    pool.submit(1, far(), record.clone(), work);
    assert_eq!(probe.started(), 1);
    let work = probe.work(&record, &hold, Kind::Deaf);
    pool.submit(2, soon(100), record.clone(), work);
    // Due at admission.
    let work = probe.work(&record, &hold, Kind::Deaf);
    pool.submit(3, Instant::now(), record.clone(), work);
    let work = probe.work(&record, &hold, Kind::Deaf);
    pool.submit(4, far(), record.clone(), work);
    // Answered at its deadline, while the thread is still busy. A timer
    // held up past both deadlines refuses the two in one pass, 2 first.
    assert!(until(|| record.get(2).is_some() && record.get(3).is_some()));
    assert_eq!(record.get(2), Some(Answer::Error(ErrorCode::Deadline)));
    assert_eq!(record.get(3), Some(Answer::Error(ErrorCode::Deadline)));
    assert_eq!(record.get(1), None);
    // Their places are free.
    for id in 5..=6 {
        let work = probe.work(&record, &hold, Kind::Deaf);
        assert_eq!(
            pool.submit(id, far(), record.clone(), work),
            Admission::Queued
        );
    }
    hold.release();
    let ran: Vec<u64> = (0..3).map(|_| probe.started()).collect();
    assert_eq!(ran, vec![4, 5, 6]);
    probe.no_start();
    assert!(pool.stop(guard()));
}

#[test]
fn a_running_request_past_its_deadline_is_deadline_and_cancelled_unless_headed() {
    let (record, hold, probe) = (Record::default(), Hold::default(), Probe::new());
    let pool = open(shape(2, 0));
    let work = probe.work(&record, &hold, Kind::Heeds);
    pool.submit(1, far(), record.clone(), work);
    let work = probe.work(&record, &hold, Kind::Headed);
    pool.submit(2, far(), record.clone(), work);
    probe.started();
    probe.started();
    // Both running, 2's head queued: now past their deadlines.
    assert!(until(|| record.get(2) == Some(Answer::Head)));
    expire(&pool, 1);
    assert_eq!(probe.returned(), (1, true));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Deadline)));
    // Its head was queued in time: no service deadline after it.
    expire(&pool, 2);
    assert!(until(|| pool
        .inner
        .lock()
        .running
        .iter()
        .any(|r| r.id == 2 && r.expired)));
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(record.get(2), Some(Answer::Head));
    hold.release();
    assert_eq!(probe.returned(), (2, false));
    assert_eq!(record.get(2), Some(Answer::Done));
    assert!(pool.stop(guard()));
}

#[test]
fn the_stop_answers_queued_stopped_settles_running_and_joins_every_thread() {
    let (record, hold, probe) = (Record::default(), Hold::default(), Probe::new());
    let pool = open(shape(3, 3));
    // Returns at its token without answering.
    let work = probe.work(&record, &hold, Kind::Heeds);
    pool.submit(1, far(), record.clone(), work);
    // Its stream open.
    let work = probe.work(&record, &hold, Kind::Headed);
    pool.submit(2, far(), record.clone(), work);
    // Answers as its token is cancelled: a reply queued in time stands.
    let (started, returned) = probe.tx.clone();
    let answering = record.clone();
    pool.submit(
        3,
        far(),
        record.clone(),
        Box::new(move |ticket: &Ticket| {
            let _ = started.send(ticket.id);
            while !ticket.cancel.is_cancelled() {
                std::thread::sleep(Duration::from_millis(2));
            }
            answering.answer(ticket.id, Answer::Done);
            let _ = returned.send((ticket.id, true));
        }),
    );
    for id in 4..=6 {
        let work = probe.work(&record, &hold, Kind::Heeds);
        pool.submit(id, far(), record.clone(), work);
    }
    for _ in 0..3 {
        probe.started();
    }
    assert!(pool.stop(guard()));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Stopped)));
    assert_eq!(record.get(2), Some(Answer::Abort(AbortCode::Stopped)));
    assert_eq!(record.get(3), Some(Answer::Done));
    for id in 4..=6 {
        assert_eq!(
            record.get(id),
            Some(Answer::Error(ErrorCode::Stopped)),
            "{id}"
        );
    }
    probe.no_start();
    assert!(joined(&pool));
}

#[test]
fn work_still_running_at_the_drains_deadline_is_settled_stopped() {
    let (record, hold, probe) = (Record::default(), Hold::default(), Probe::new());
    let pool = open(shape(1, 0));
    let work = probe.work(&record, &hold, Kind::Deaf);
    pool.submit(1, far(), record.clone(), work);
    probe.started();
    let began = Instant::now();
    assert!(!pool.stop(soon(200)));
    assert!(began.elapsed() >= Duration::from_millis(200));
    // At its deadline, not the work's end, which comes only below. The
    // bound is the property, so it has headroom: 100 times the deadline,
    // and over three times the longest stall a runner has shown (5.9 s on
    // Windows CI, issue #311).
    assert!(began.elapsed() < Duration::from_secs(20));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Stopped)));
    // Its timer ended; its worker is the work's.
    assert_eq!(alive(&pool), 1);
    // Once its work returns, the thread ends: nothing is left behind.
    hold.release();
    assert_eq!(probe.returned(), (1, true));
    assert!(until(|| alive(&pool) == 0));
    assert!(pool.drain(guard()));
    assert!(joined(&pool));
    // A reply after the settle is refused.
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Stopped)));
}

#[test]
fn a_panic_is_internal_and_its_thread_goes_on() {
    let (record, hold, probe) = (Record::default(), Hold::default(), Probe::new());
    let pool = open(shape(1, 3));
    pool.submit(
        1,
        far(),
        record.clone(),
        Box::new(|_: &Ticket| panic!("a test panic")),
    );
    let headed = record.clone();
    pool.submit(
        2,
        far(),
        record.clone(),
        Box::new(move |ticket: &Ticket| {
            headed.answer(ticket.id, Answer::Head);
            panic!("a test panic after the head");
        }),
    );
    hold.release();
    let work = probe.work(&record, &hold, Kind::Deaf);
    pool.submit(3, far(), record.clone(), work);
    assert_eq!(probe.returned(), (3, false));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Internal)));
    assert_eq!(record.get(2), Some(Answer::Abort(AbortCode::Internal)));
    assert_eq!(record.get(3), Some(Answer::Done));
    assert!(pool.stop(guard()));
    assert!(joined(&pool));
}

#[test]
fn work_that_answers_nothing_is_internal() {
    let record = Record::default();
    let pool = open(shape(1, 0));
    pool.submit(1, far(), record.clone(), Box::new(|_: &Ticket| {}));
    assert!(until(|| record.get(1).is_some()));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Internal)));
    assert!(pool.stop(guard()));
}

#[test]
fn dropping_a_pool_ends_its_threads() {
    let pool = Pool::<Record>::start("test", shape(3, 1)).unwrap();
    let inner = pool.inner.clone();
    assert_eq!(inner.lock().alive, 4);
    drop(pool);
    assert!(until(|| inner.lock().alive == 0));
}

/// What a test write does past its boundary, once told to finish.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Past {
    /// Answers its success, and marks it proven.
    Proven,
    /// Answers `outcome_unknown` itself, as a libradicle error is.
    Fails,
    /// Answers nothing.
    Silent,
    /// Panics.
    Panics,
}

/// A write's work as the writes run it: once `go` is released it claims
/// its boundary, and says whether it could on `began`; past it, it waits
/// for `finish` whatever its token, as libradicle's mutation does, then
/// does as `past` says.
fn write(
    record: &Record,
    go: &Hold,
    finish: &Hold,
    began: &mpsc::Sender<bool>,
    past: Past,
) -> Work {
    let (record, go, finish, began) = (record.clone(), go.clone(), finish.clone(), began.clone());
    Box::new(move |ticket: &Ticket| {
        while !go.released() {
            std::thread::sleep(Duration::from_millis(2));
        }
        let begun = ticket.begin();
        let _ = began.send(begun);
        if !begun {
            return;
        }
        while !finish.released() {
            std::thread::sleep(Duration::from_millis(2));
        }
        match past {
            Past::Proven => {
                record.answer(ticket.id, Answer::Done);
                ticket.proven();
            }
            Past::Fails => {
                record.answer(ticket.id, Answer::Error(ErrorCode::OutcomeUnknown));
            }
            Past::Silent => {}
            Past::Panics => panic!("a test panic past the boundary"),
        }
    })
}

fn began(rx: &mpsc::Receiver<bool>) -> bool {
    rx.recv_timeout(GUARD).unwrap()
}

fn running(pool: &Pool<Record>) -> usize {
    pool.inner.lock().running.len()
}

fn uncertain(pool: &Pool<Record>) -> bool {
    pool.inner.lock().uncertain()
}

/// 0008, "Writes": main's cancel, queued by the connection before the pool
/// hears of it, keeps a write from starting: the claim is made where the
/// connection decides. And one the pool has heard of.
#[test]
fn a_write_cancelled_before_its_boundary_never_starts() {
    let (record, finish) = (Record::default(), Hold::default());
    let (go, go2) = (Hold::default(), Hold::default());
    let (tx, rx) = mpsc::channel();
    finish.release();
    let pool = open(shape(1, 1));
    pool.submit(
        1,
        far(),
        record.clone(),
        write(&record, &go, &finish, &tx, Past::Proven),
    );
    pool.submit(
        2,
        far(),
        record.clone(),
        write(&record, &go2, &finish, &tx, Past::Proven),
    );
    assert!(until(|| running(&pool) == 1));
    // The connection has queued `cancelled`; the reader hasn't told the
    // pool yet.
    record.cancelled_unseen(1);
    go.release();
    assert!(!began(&rx));
    // The reader's callback, late: the work may have returned already.
    let _ = pool.cancel(1);
    // The next, cancelled while it runs, before its boundary.
    assert!(until(|| pool
        .inner
        .lock()
        .running
        .iter()
        .any(|r| r.id == 2)));
    assert!(record.cancel(&pool, 2));
    go2.release();
    assert!(!began(&rx));
    assert!(until(|| running(&pool) == 0));
    for id in [1, 2] {
        assert_eq!(
            record.get(id),
            Some(Answer::Error(ErrorCode::Cancelled)),
            "{id}"
        );
    }
    assert!(!uncertain(&pool));
    assert!(pool.stop(guard()));
}

/// A deadline the timer has decided, but not yet answered, keeps a write
/// from starting; and so does a deadline the timer hasn't come to:
/// `begin` answers it itself.
#[test]
fn a_write_past_its_deadline_before_its_boundary_never_starts() {
    let (record, go, finish) = (Record::default(), Hold::default(), Hold::default());
    let (tx, rx) = mpsc::channel();
    finish.release();
    let pool = open(shape(2, 0));
    // Decided, its answer held up.
    record.stall(Some(1));
    pool.submit(
        1,
        far(),
        record.clone(),
        write(&record, &go, &finish, &tx, Past::Proven),
    );
    assert!(until(|| running(&pool) == 1));
    expire(&pool, 1);
    assert!(until(|| pool
        .inner
        .lock()
        .running
        .iter()
        .any(|r| r.id == 1 && r.expired)));
    // Behind it, the timer can't reach the second's deadline.
    pool.submit(
        2,
        far(),
        record.clone(),
        write(&record, &go, &finish, &tx, Past::Proven),
    );
    assert!(until(|| running(&pool) == 2));
    expire(&pool, 2);
    go.release();
    assert!(!began(&rx));
    assert!(!began(&rx));
    assert_eq!(record.get(2), Some(Answer::Error(ErrorCode::Deadline)));
    record.stall(None);
    assert!(until(|| record.get(1).is_some()));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Deadline)));
    assert!(!uncertain(&pool));
    assert!(pool.stop(guard()));
}

/// A write the stop meets before its boundary never starts: `stopped`.
#[test]
fn a_write_met_by_the_stop_before_its_boundary_never_starts() {
    let (record, go, finish) = (Record::default(), Hold::default(), Hold::default());
    let (tx, rx) = mpsc::channel();
    finish.release();
    let pool = open(shape(1, 0));
    pool.submit(
        1,
        far(),
        record.clone(),
        write(&record, &go, &finish, &tx, Past::Proven),
    );
    assert!(until(|| running(&pool) == 1));
    pool.fence();
    go.release();
    assert!(!began(&rx));
    assert!(pool.drain(guard()));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Stopped)));
    assert!(!uncertain(&pool));
}

/// Past its boundary, a write's deadline is `outcome_unknown`, and its work
/// runs on to its end, holding its slot: its success, later, is lost, and
/// proven.
#[test]
fn past_its_boundary_a_deadline_is_outcome_unknown_and_the_write_runs_on() {
    let (record, go, finish) = (Record::default(), Hold::default(), Hold::default());
    let (tx, rx) = mpsc::channel();
    go.release();
    let pool = open(shape(1, 0));
    pool.submit(
        1,
        far(),
        record.clone(),
        write(&record, &go, &finish, &tx, Past::Proven),
    );
    assert!(began(&rx));
    expire(&pool, 1);
    assert!(until(|| record.get(1).is_some()));
    assert_eq!(
        record.get(1),
        Some(Answer::Error(ErrorCode::OutcomeUnknown))
    );
    assert_eq!(running(&pool), 1);
    let work = write(&record, &go, &finish, &tx, Past::Proven);
    assert_eq!(pool.submit(2, far(), record.clone(), work), Admission::Busy);
    finish.release();
    assert!(until(|| running(&pool) == 0));
    assert_eq!(
        record.get(1),
        Some(Answer::Error(ErrorCode::OutcomeUnknown))
    );
    assert!(!uncertain(&pool));
    assert!(pool.stop(guard()));
}

/// Past its boundary, main's cancel queues nothing at the connection, and
/// the pool answers it `outcome_unknown`.
#[test]
fn past_its_boundary_a_cancel_is_outcome_unknown() {
    let (record, go, finish) = (Record::default(), Hold::default(), Hold::default());
    let (tx, rx) = mpsc::channel();
    go.release();
    let pool = open(shape(1, 0));
    pool.submit(
        1,
        far(),
        record.clone(),
        write(&record, &go, &finish, &tx, Past::Fails),
    );
    assert!(began(&rx));
    assert!(record.cancel(&pool, 1));
    assert_eq!(
        record.get(1),
        Some(Answer::Error(ErrorCode::OutcomeUnknown))
    );
    finish.release();
    assert!(until(|| running(&pool) == 0));
    assert!(uncertain(&pool));
    assert!(pool.stop(guard()));
}

/// The stop waits for a started write within its drain, and a reply it
/// queues in time stands; one still running past the drain is
/// `outcome_unknown`, and leaves the run uncertain.
#[test]
fn the_stop_keeps_a_started_writes_reply_and_settles_one_past_the_drain_unknown() {
    let (record, go, finish) = (Record::default(), Hold::default(), Hold::default());
    let (tx, rx) = mpsc::channel();
    go.release();
    let pool = open(shape(1, 0));
    pool.submit(
        1,
        far(),
        record.clone(),
        write(&record, &go, &finish, &tx, Past::Proven),
    );
    assert!(began(&rx));
    let finishing = finish.clone();
    let later = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        finishing.release();
    });
    assert!(pool.stop(guard()));
    later.join().unwrap();
    assert_eq!(record.get(1), Some(Answer::Done));
    assert!(!uncertain(&pool));

    let (record, finish) = (Record::default(), Hold::default());
    let pool = open(shape(1, 0));
    pool.submit(
        1,
        far(),
        record.clone(),
        write(&record, &go, &finish, &tx, Past::Proven),
    );
    assert!(began(&rx));
    assert!(!pool.stop(soon(200)));
    assert_eq!(
        record.get(1),
        Some(Answer::Error(ErrorCode::OutcomeUnknown))
    );
    assert!(uncertain(&pool));
    finish.release();
    assert!(until(|| alive(&pool) == 0));
    assert_eq!(
        record.get(1),
        Some(Answer::Error(ErrorCode::OutcomeUnknown))
    );
}

/// Past its boundary, a panic and work that answers nothing are
/// `outcome_unknown`; they, and a write that answers `outcome_unknown`
/// itself, leave the run uncertain. A proven one doesn't.
#[test]
fn past_its_boundary_only_a_proven_outcome_leaves_the_run_certain() {
    for (past, answer, left_uncertain) in [
        (Past::Proven, Answer::Done, false),
        (Past::Fails, Answer::Error(ErrorCode::OutcomeUnknown), true),
        (Past::Silent, Answer::Error(ErrorCode::OutcomeUnknown), true),
        (Past::Panics, Answer::Error(ErrorCode::OutcomeUnknown), true),
    ] {
        let (record, go, finish) = (Record::default(), Hold::default(), Hold::default());
        let (tx, rx) = mpsc::channel();
        go.release();
        finish.release();
        let pool = open(shape(1, 0));
        pool.submit(
            1,
            far(),
            record.clone(),
            write(&record, &go, &finish, &tx, past),
        );
        assert!(began(&rx));
        assert!(until(|| running(&pool) == 0));
        assert_eq!(record.get(1), Some(answer.clone()));
        assert_eq!(uncertain(&pool), left_uncertain);
        // Before its boundary, the same work is `internal`, and certain.
        if past == Past::Panics {
            let pool = open(shape(1, 0));
            pool.submit(
                2,
                far(),
                record.clone(),
                Box::new(|_: &Ticket| panic!("before")),
            );
            assert!(until(|| record.get(2).is_some()));
            assert_eq!(record.get(2), Some(Answer::Error(ErrorCode::Internal)));
            assert!(!uncertain(&pool));
            assert!(pool.stop(guard()));
        }
        assert!(pool.stop(guard()));
    }
}

/// What the writer did, in order: a write's work running, a repair queued,
/// a repair's turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Write(u64),
    Queued(RepoId),
    Turn(RepoId),
}

type Timeline = Arc<Mutex<Vec<Event>>>;

/// How a test's repair goes: over, or abandoned, at its nth turn, or on
/// and on.
#[derive(Clone, Copy)]
enum Script {
    Over(usize),
    Abandoned(usize),
    Forever,
}

/// A repairer that keeps to its scripts, and records its calls on the
/// timeline. Its turns wait for `hold`'s release, and record what the stop
/// said as they returned.
struct Fake {
    timeline: Timeline,
    scripts: Mutex<HashMap<RepoId, (Script, usize)>>,
    hold: Hold,
    stops: Mutex<Vec<bool>>,
}

impl Fake {
    fn new(timeline: &Timeline, scripts: &[(RepoId, Script)]) -> Arc<Self> {
        let hold = Hold::default();
        hold.release();
        Arc::new(Self {
            timeline: timeline.clone(),
            scripts: Mutex::new(
                scripts
                    .iter()
                    .map(|(rid, script)| (*rid, (*script, 0)))
                    .collect(),
            ),
            hold,
            stops: Mutex::new(Vec::new()),
        })
    }
}

impl Repairer for Fake {
    fn queued(&self, rid: RepoId) {
        self.timeline.lock().unwrap().push(Event::Queued(rid));
    }

    fn turn(&self, rid: RepoId, stop: &Arc<AtomicBool>) -> Turn {
        self.timeline.lock().unwrap().push(Event::Turn(rid));
        while !self.hold.released() {
            std::thread::sleep(Duration::from_millis(2));
        }
        self.stops.lock().unwrap().push(stop.load(Ordering::SeqCst));
        let mut scripts = self.scripts.lock().unwrap();
        let (script, taken) = scripts.get_mut(&rid).unwrap();
        *taken += 1;
        match *script {
            Script::Over(at) if *taken >= at => Turn::Over,
            Script::Abandoned(at) if *taken >= at => Turn::Abandoned,
            _ => {
                std::thread::sleep(Duration::from_millis(2));
                Turn::More
            }
        }
    }
}

fn repo(byte: u8) -> RepoId {
    RepoId::from(radicle::git::Oid::from_sha1([byte; 20]))
}

/// A write to `rid` as the writes run it: once `go` is released, its
/// start, then its outcome, proven or unknown.
fn mutating(timeline: &Timeline, record: &Record, go: &Hold, proven: bool) -> Work {
    let (timeline, record, go) = (timeline.clone(), record.clone(), go.clone());
    Box::new(move |ticket: &Ticket| {
        while !go.released() {
            std::thread::sleep(Duration::from_millis(2));
        }
        timeline.lock().unwrap().push(Event::Write(ticket.id));
        if !ticket.begin() {
            return;
        }
        if proven {
            record.answer(ticket.id, Answer::Done);
            ticket.proven();
        } else {
            record.answer(ticket.id, Answer::Error(ErrorCode::OutcomeUnknown));
        }
    })
}

/// The writer, with `fake` its online repair.
fn writer(fake: &Arc<Fake>) -> Pool<Record> {
    let pool = open(WRITE);
    let repairer: Arc<dyn Repairer> = fake.clone();
    assert!(pool.inner.repairer.set(repairer).is_ok());
    pool
}

fn submit(
    pool: &Pool<Record>,
    id: u64,
    deadline: Instant,
    record: &Record,
    work: Work,
    mutates: Option<Mutates>,
) {
    assert_eq!(
        pool.submit_mutating(id, deadline, record.clone(), work, mutates),
        Admission::Queued
    );
}

fn writing(rid: RepoId) -> Option<Mutates> {
    Some(Mutates {
        rid,
        repaired: true,
    })
}

fn events(timeline: &Timeline) -> Vec<Event> {
    timeline.lock().unwrap().clone()
}

/// 0008, "Writes": a write whose outcome is unknown has its repository's
/// repair queued as its call returns. The repair runs one unit a turn,
/// taking turns with the writes to other repositories, in their order;
/// a write to its repository, admitted before them, waits until it is
/// over. The run is uncertain until then.
#[test]
fn an_unknown_outcome_queues_a_repair_that_takes_turns_and_holds_its_writes() {
    let (record, go, timeline) = (Record::default(), Hold::default(), Timeline::default());
    let (repaired, other) = (repo(1), repo(2));
    let fake = Fake::new(&timeline, &[(repaired, Script::Over(3))]);
    let pool = writer(&fake);
    let work = |proven| mutating(&timeline, &record, &go, proven);
    submit(&pool, 1, far(), &record, work(false), writing(repaired));
    submit(&pool, 2, far(), &record, work(true), writing(repaired));
    submit(&pool, 3, far(), &record, work(true), writing(other));
    submit(&pool, 4, far(), &record, work(true), writing(other));
    go.release();
    assert!(until(|| record.count(&Answer::Done) == 3));
    assert_eq!(
        events(&timeline),
        [
            Event::Write(1),
            Event::Queued(repaired),
            Event::Turn(repaired),
            Event::Write(3),
            Event::Turn(repaired),
            Event::Write(4),
            Event::Turn(repaired),
            Event::Write(2),
        ]
    );
    assert_eq!(
        record.get(1),
        Some(Answer::Error(ErrorCode::OutcomeUnknown))
    );
    assert!(!uncertain(&pool));
    assert_eq!(*fake.stops.lock().unwrap(), [false, false, false]);
    assert!(pool.stop(guard()));
}

/// A repair alone runs turn after turn, and the run is uncertain until it
/// is over. Repairs run in the order they were queued.
#[test]
fn repairs_run_in_their_order_and_the_run_is_uncertain_until_they_are_over() {
    let (record, go, timeline) = (Record::default(), Hold::default(), Timeline::default());
    let (first, second) = (repo(1), repo(2));
    let fake = Fake::new(
        &timeline,
        &[(first, Script::Over(2)), (second, Script::Over(2))],
    );
    fake.hold.0.store(false, Ordering::SeqCst);
    let pool = writer(&fake);
    let work = |proven| mutating(&timeline, &record, &go, proven);
    submit(&pool, 1, far(), &record, work(false), writing(first));
    submit(&pool, 2, far(), &record, work(false), writing(second));
    go.release();
    assert!(until(|| events(&timeline).contains(&Event::Turn(first))));
    assert!(uncertain(&pool));
    fake.hold.release();
    assert!(until(|| events(&timeline).len() == 8));
    assert_eq!(
        events(&timeline),
        [
            Event::Write(1),
            Event::Queued(first),
            Event::Turn(first),
            Event::Write(2),
            Event::Queued(second),
            Event::Turn(first),
            Event::Turn(second),
            Event::Turn(second),
        ]
    );
    assert!(until(|| !uncertain(&pool)));
    assert!(pool.stop(guard()));
}

/// A proven write queues no repair. An unknown outcome that no repair
/// covers, a write that names no repaired repository, or one with no
/// repairer, leaves the run uncertain for good.
#[test]
fn only_an_unknown_outcome_a_repair_covers_is_repaired() {
    let (record, go, timeline) = (Record::default(), Hold::default(), Timeline::default());
    go.release();
    let rid = repo(1);
    let fake = Fake::new(&timeline, &[(rid, Script::Over(1))]);
    let pool = writer(&fake);
    let work = |proven| mutating(&timeline, &record, &go, proven);
    submit(&pool, 1, far(), &record, work(true), writing(rid));
    assert!(until(|| running(&pool) == 0 && record.get(1).is_some()));
    assert!(!uncertain(&pool));
    let unseeding = Some(Mutates {
        rid,
        repaired: false,
    });
    submit(&pool, 2, far(), &record, work(false), unseeding);
    assert!(until(|| running(&pool) == 0 && record.get(2).is_some()));
    assert!(uncertain(&pool));
    assert_eq!(events(&timeline), [Event::Write(1), Event::Write(2)]);
    assert!(pool.stop(guard()));

    let pool = open(WRITE);
    submit(&pool, 3, far(), &record, work(false), writing(rid));
    assert!(until(|| running(&pool) == 0 && record.get(3).is_some()));
    assert!(uncertain(&pool));
    assert!(pool.inner.lock().repairs.is_empty());
    assert!(pool.stop(guard()));
}

/// A repair that can't go on lets the writes to its repository run, and
/// leaves the run uncertain for good.
#[test]
fn an_abandoned_repair_lets_its_writes_run_and_leaves_the_run_uncertain() {
    let (record, go, timeline) = (Record::default(), Hold::default(), Timeline::default());
    let rid = repo(1);
    let fake = Fake::new(&timeline, &[(rid, Script::Abandoned(2))]);
    let pool = writer(&fake);
    let work = |proven| mutating(&timeline, &record, &go, proven);
    submit(&pool, 1, far(), &record, work(false), writing(rid));
    submit(&pool, 2, far(), &record, work(true), writing(rid));
    go.release();
    assert!(until(|| record.get(2).is_some()));
    assert_eq!(
        events(&timeline),
        [
            Event::Write(1),
            Event::Queued(rid),
            Event::Turn(rid),
            Event::Turn(rid),
            Event::Write(2),
        ]
    );
    assert!(until(|| running(&pool) == 0));
    assert!(uncertain(&pool));
    assert!(pool.inner.lock().repairs.is_empty());
    assert!(pool.stop(guard()));
}

/// A write held behind a repair keeps its deadline, and main's cancel
/// still reaches it: answered so, it never runs.
#[test]
fn a_write_held_behind_a_repair_keeps_its_deadline_and_its_cancel() {
    let (record, go, timeline) = (Record::default(), Hold::default(), Timeline::default());
    let rid = repo(1);
    let fake = Fake::new(&timeline, &[(rid, Script::Forever)]);
    let pool = writer(&fake);
    let work = |proven| mutating(&timeline, &record, &go, proven);
    submit(&pool, 1, far(), &record, work(false), writing(rid));
    go.release();
    assert!(until(|| events(&timeline).contains(&Event::Turn(rid))));
    submit(&pool, 2, soon(150), &record, work(true), writing(rid));
    submit(&pool, 3, far(), &record, work(true), writing(rid));
    assert!(until(|| record.get(2).is_some()));
    assert_eq!(record.get(2), Some(Answer::Error(ErrorCode::Deadline)));
    assert!(record.cancel(&pool, 3));
    assert_eq!(record.get(3), Some(Answer::Error(ErrorCode::Cancelled)));
    assert!(pool.inner.lock().queue.is_empty());
    assert!(!events(&timeline).contains(&Event::Write(2)));
    assert!(!events(&timeline).contains(&Event::Write(3)));
    assert!(pool.stop(guard()));
}

/// 0008, "The deadline" ("`rad.shutdown` stops after the current unit"):
/// the stop's fence reaches the turn in progress, which starts no unit
/// after it, and no turn follows. A write held behind the repair is
/// `stopped`; the drain completes, and the run stays uncertain.
#[test]
fn the_stop_reaches_the_turn_in_progress_and_no_turn_follows() {
    let (record, go, timeline) = (Record::default(), Hold::default(), Timeline::default());
    let rid = repo(1);
    let fake = Fake::new(&timeline, &[(rid, Script::Forever)]);
    fake.hold.0.store(false, Ordering::SeqCst);
    let pool = writer(&fake);
    let work = |proven| mutating(&timeline, &record, &go, proven);
    submit(&pool, 1, far(), &record, work(false), writing(rid));
    submit(&pool, 2, far(), &record, work(true), writing(rid));
    go.release();
    assert!(until(|| events(&timeline).contains(&Event::Turn(rid))));
    pool.fence();
    assert_eq!(record.get(2), Some(Answer::Error(ErrorCode::Stopped)));
    fake.hold.release();
    assert!(pool.drain(guard()));
    assert_eq!(*fake.stops.lock().unwrap(), [true]);
    assert_eq!(
        events(&timeline),
        [Event::Write(1), Event::Queued(rid), Event::Turn(rid)]
    );
    assert!(uncertain(&pool));
}

/// A COB write's work held at both ends, as [`write`]'s is, its outcome
/// proven or left unknown.
fn held_write(
    record: &Record,
    go: &Hold,
    finish: &Hold,
    proven: bool,
) -> (Work, mpsc::Receiver<bool>) {
    let (began, rx) = mpsc::channel();
    let past = if proven { Past::Proven } else { Past::Fails };
    (write(record, go, finish, &began, past), rx)
}

/// 0008, "Methods" ("The repair fence"), and #259's note for the reads:
/// a COB write to a repository fences it from its mutation start until its
/// outcome is proven, or, unknown, until its repair is over; queued, or
/// once proven, it fences nothing. Neither another repository nor a write
/// no repair covers is fenced.
#[test]
fn a_cob_write_fences_its_repository_from_its_start_until_proven_or_repaired() {
    let (record, timeline) = (Record::default(), Timeline::default());
    let (fenced, other) = (repo(1), repo(2));
    let fake = Fake::new(&timeline, &[(fenced, Script::Over(2))]);
    fake.hold.0.store(false, Ordering::SeqCst);
    let pool = writer(&fake);

    // Proven: fenced only while its call runs, not once proven, though its
    // work still runs.
    let (go, finish, after) = (Hold::default(), Hold::default(), Hold::default());
    let (began, rx) = mpsc::channel();
    let work: Work = {
        let (record, go, finish, after) =
            (record.clone(), go.clone(), finish.clone(), after.clone());
        Box::new(move |ticket: &Ticket| {
            while !go.released() {
                std::thread::sleep(Duration::from_millis(2));
            }
            let _ = began.send(ticket.begin());
            while !finish.released() {
                std::thread::sleep(Duration::from_millis(2));
            }
            record.answer(ticket.id, Answer::Done);
            ticket.proven();
            while !after.released() {
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    submit(&pool, 1, far(), &record, work, writing(fenced));
    assert!(until(|| running(&pool) == 1));
    assert!(!pool.writing(&fenced));
    go.release();
    assert!(self::began(&rx));
    assert!(pool.writing(&fenced));
    assert!(!pool.writing(&other));
    finish.release();
    assert!(until(|| record.get(1) == Some(Answer::Done)));
    assert!(until(|| !pool.writing(&fenced)));
    assert_eq!(running(&pool), 1);
    after.release();
    assert!(until(|| running(&pool) == 0));
    assert!(!pool.writing(&fenced));

    // Unknown: fenced while its call runs, then until its repair is over.
    let (go, finish) = (Hold::default(), Hold::default());
    let (work, began) = held_write(&record, &go, &finish, false);
    submit(&pool, 2, far(), &record, work, writing(fenced));
    go.release();
    assert!(self::began(&began));
    assert!(pool.writing(&fenced));
    finish.release();
    assert!(until(|| events(&timeline).contains(&Event::Turn(fenced))));
    assert!(pool.writing(&fenced));
    assert!(!pool.writing(&other));
    fake.hold.release();
    assert!(until(|| !pool.writing(&fenced)));
    assert!(pool.inner.lock().repairs.is_empty());

    // A write no repair covers fences nothing, even unknown.
    let (go, finish) = (Hold::default(), Hold::default());
    let (work, began) = held_write(&record, &go, &finish, false);
    let unseeding = Some(Mutates {
        rid: fenced,
        repaired: false,
    });
    submit(&pool, 3, far(), &record, work, unseeding);
    go.release();
    assert!(self::began(&began));
    assert!(!pool.writing(&fenced));
    finish.release();
    assert!(until(|| running(&pool) == 0));
    assert!(!pool.writing(&fenced));
    assert!(pool.stop(guard()));
}

/// How a network operation's libradicle call behaves past its start.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Call {
    /// Returns cancelled once its token is, as a clone does between
    /// candidates; or `Ok` once `finish` is released.
    Heeds,
    /// Returns `Ok` once `finish` is released, whatever its token: a fetch
    /// in flight finishes first.
    Deaf,
    /// Panics once `finish` is released.
    Panics,
}

/// A network operation's work as `rad.clone`'s runs it: once `go` is
/// released it claims its start, and says whether it could on `began`;
/// past it, it calls as `call` says, then answers as the clone does:
/// `Done` for `Ok`, proven; for cancelled, the `{ cancelled }` result
/// (`Answer::Cancelled`) only if main cancelled it, and unproven.
fn network(
    record: &Record,
    go: &Hold,
    finish: &Hold,
    began: &mpsc::Sender<bool>,
    call: Call,
) -> Work {
    let (record, go, finish, began) = (record.clone(), go.clone(), finish.clone(), began.clone());
    Box::new(move |ticket: &Ticket| {
        while !go.released() {
            std::thread::sleep(Duration::from_millis(2));
        }
        let claimed = ticket.claim();
        let _ = began.send(claimed);
        if !claimed {
            return;
        }
        loop {
            if finish.released() {
                if call == Call::Panics {
                    panic!("a test panic past the network start");
                }
                ticket.proven();
                record.answer(ticket.id, Answer::Done);
                return;
            }
            if call == Call::Heeds && ticket.cancel.is_cancelled() {
                if ticket.cancelled_by_main() {
                    record.answer(ticket.id, Answer::Cancelled);
                }
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    })
}

/// 0008, "Methods": past its start, main's cancel queues nothing at the
/// connection, and the pool answers nothing either: it cancels the token,
/// and the work answers `{ cancelled }` once libradicle returns, holding
/// its slot until then. Cut off, the run is uncertain.
#[test]
fn past_its_start_main_cancels_a_network_operation_through_its_token() {
    let (record, go, finish) = (Record::default(), Hold::default(), Hold::default());
    let (tx, rx) = mpsc::channel();
    go.release();
    let pool = open(shape(1, 0));
    pool.submit(
        1,
        far(),
        record.clone(),
        network(&record, &go, &finish, &tx, Call::Deaf),
    );
    assert!(began(&rx));
    assert!(record.cancel(&pool, 1));
    // Nothing answered yet, and its token is cancelled: the call runs on,
    // in its slot.
    assert_eq!(record.get(1), None);
    let cancel = pool.inner.lock().running[0].cancel.clone();
    assert!(cancel.is_cancelled());
    let work = network(&record, &go, &finish, &tx, Call::Heeds);
    assert_eq!(pool.submit(2, far(), record.clone(), work), Admission::Busy);
    // A deaf call that then succeeds answers its success, proven.
    finish.release();
    assert!(until(|| running(&pool) == 0));
    assert_eq!(record.get(1), Some(Answer::Done));
    assert!(!uncertain(&pool));

    // One that heeds its token answers `{ cancelled }`, and is cut off.
    let finish = Hold::default();
    pool.submit(
        3,
        far(),
        record.clone(),
        network(&record, &go, &finish, &tx, Call::Heeds),
    );
    assert!(began(&rx));
    assert!(record.cancel(&pool, 3));
    assert!(until(|| running(&pool) == 0));
    assert_eq!(record.get(3), Some(Answer::Cancelled));
    assert!(uncertain(&pool));
    assert!(pool.stop(guard()));
}

/// Before its start, main's cancel is the connection's `cancelled`, as
/// for any request, and nothing starts: the run stays certain.
#[test]
fn a_network_operation_cancelled_before_its_start_never_starts() {
    let (record, go, finish) = (Record::default(), Hold::default(), Hold::default());
    let (tx, rx) = mpsc::channel();
    let pool = open(shape(1, 1));
    pool.submit(
        1,
        far(),
        record.clone(),
        network(&record, &go, &finish, &tx, Call::Heeds),
    );
    assert!(until(|| running(&pool) == 1));
    assert!(record.cancel(&pool, 1));
    // A queued one is removed, and never runs.
    pool.submit(
        2,
        far(),
        record.clone(),
        network(&record, &go, &finish, &tx, Call::Heeds),
    );
    assert!(record.cancel(&pool, 2));
    go.release();
    assert!(!began(&rx));
    assert!(until(|| running(&pool) == 0));
    assert!(rx.recv_timeout(Duration::from_millis(150)).is_err());
    for id in [1, 2] {
        assert_eq!(record.get(id), Some(Answer::Error(ErrorCode::Cancelled)));
    }
    assert!(!uncertain(&pool));
    assert!(pool.stop(guard()));
}

/// 0008, "Deadlines": past its start, a network operation past its
/// deadline is `deadline`, never `outcome_unknown`, its token cancelled;
/// it keeps its slot until libradicle returns. One that then succeeds is
/// proven; one cancelled by it leaves the run uncertain.
#[test]
fn past_its_start_a_network_deadline_is_deadline_and_keeps_its_slot() {
    let (record, go, finish) = (Record::default(), Hold::default(), Hold::default());
    let (tx, rx) = mpsc::channel();
    go.release();
    let pool = open(shape(1, 0));
    pool.submit(
        1,
        far(),
        record.clone(),
        network(&record, &go, &finish, &tx, Call::Deaf),
    );
    assert!(began(&rx));
    expire(&pool, 1);
    assert!(until(|| record.get(1).is_some()));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Deadline)));
    // The timer cancels its token once it has answered it.
    assert!(until(|| pool.inner.lock().running[0].cancel.is_cancelled()));
    let work = network(&record, &go, &finish, &tx, Call::Heeds);
    assert_eq!(pool.submit(2, far(), record.clone(), work), Admission::Busy);
    finish.release();
    assert!(until(|| running(&pool) == 0));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Deadline)));
    assert!(!uncertain(&pool));

    let finish = Hold::default();
    pool.submit(
        3,
        far(),
        record.clone(),
        network(&record, &go, &finish, &tx, Call::Heeds),
    );
    assert!(began(&rx));
    expire(&pool, 3);
    assert!(until(|| running(&pool) == 0));
    assert_eq!(record.get(3), Some(Answer::Error(ErrorCode::Deadline)));
    assert!(uncertain(&pool));
    assert!(pool.stop(guard()));
}

/// Before its start, the deadline and the stop keep it from starting, as
/// a write's boundary does.
#[test]
fn a_network_operation_past_its_deadline_or_met_by_the_stop_never_starts() {
    let (record, go, finish) = (Record::default(), Hold::default(), Hold::default());
    let (tx, rx) = mpsc::channel();
    let pool = open(shape(1, 0));
    pool.submit(
        1,
        far(),
        record.clone(),
        network(&record, &go, &finish, &tx, Call::Heeds),
    );
    // Running, before its start: now past its deadline.
    assert!(until(|| running(&pool) == 1));
    expire(&pool, 1);
    assert!(until(|| record.get(1).is_some()));
    go.release();
    assert!(!began(&rx));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Deadline)));
    assert!(until(|| running(&pool) == 0));

    let go = Hold::default();
    pool.submit(
        2,
        far(),
        record.clone(),
        network(&record, &go, &finish, &tx, Call::Heeds),
    );
    assert!(until(|| running(&pool) == 1));
    pool.fence();
    go.release();
    assert!(!began(&rx));
    assert!(pool.drain(guard()));
    assert_eq!(record.get(2), Some(Answer::Error(ErrorCode::Stopped)));
    assert!(!uncertain(&pool));
}

/// The stop, past a network start: its token cancelled, the operation
/// returns cancelled and is answered `stopped`, never `{ cancelled }`, and
/// cut off. One still running past the drain is settled `stopped` too,
/// and the drain is incomplete. Either way the run is uncertain.
#[test]
fn the_stop_answers_a_started_network_operation_stopped_and_marks_it() {
    let (record, go, finish) = (Record::default(), Hold::default(), Hold::default());
    let (tx, rx) = mpsc::channel();
    go.release();
    let pool = open(shape(1, 0));
    pool.submit(
        1,
        far(),
        record.clone(),
        network(&record, &go, &finish, &tx, Call::Heeds),
    );
    assert!(began(&rx));
    assert!(pool.stop(guard()));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Stopped)));
    assert!(uncertain(&pool));

    let (record, finish) = (Record::default(), Hold::default());
    let pool = open(shape(1, 0));
    pool.submit(
        2,
        far(),
        record.clone(),
        network(&record, &go, &finish, &tx, Call::Deaf),
    );
    assert!(began(&rx));
    assert!(!pool.stop(soon(150)));
    assert_eq!(record.get(2), Some(Answer::Error(ErrorCode::Stopped)));
    assert!(uncertain(&pool));
    finish.release();
}

/// A panic past a network start is `internal`, never `outcome_unknown`,
/// and leaves the run uncertain.
#[test]
fn a_panic_past_a_network_start_is_internal_and_marks_the_run() {
    let (record, go, finish) = (Record::default(), Hold::default(), Hold::default());
    let (tx, rx) = mpsc::channel();
    go.release();
    finish.release();
    let pool = open(shape(1, 0));
    pool.submit(
        1,
        far(),
        record.clone(),
        network(&record, &go, &finish, &tx, Call::Panics),
    );
    assert!(began(&rx));
    assert!(until(|| running(&pool) == 0));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Internal)));
    assert!(uncertain(&pool));
    assert!(pool.stop(guard()));
}
