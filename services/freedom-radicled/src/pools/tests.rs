#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
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
    /// The work's head, its stream open.
    Head,
    /// Its stream aborted.
    Abort(AbortCode),
}

/// The answers, as the connection's sender keeps them: one reply or head
/// per request, and an abort only for an open stream.
#[derive(Clone, Default)]
struct Record(Arc<Mutex<HashMap<u64, Answer>>>);

impl Record {
    fn get(&self, id: u64) -> Option<Answer> {
        self.0.lock().unwrap().get(&id).cloned()
    }

    /// Queues `answer` as `id`'s reply or head, unless it has one.
    fn answer(&self, id: u64, answer: Answer) -> bool {
        let mut answers = self.0.lock().unwrap();
        if answers.contains_key(&id) {
            return false;
        }
        answers.insert(id, answer);
        true
    }

    /// Main's cancel, as the connection handles it: `cancelled`, unless
    /// answered.
    fn cancel(&self, pool: &Pool<Record>, id: u64) -> bool {
        self.answer(id, Answer::Error(ErrorCode::Cancelled));
        pool.cancel(id)
    }

    fn count(&self, answer: &Answer) -> usize {
        self.0
            .lock()
            .unwrap()
            .values()
            .filter(|a| *a == answer)
            .count()
    }
}

impl Answers for Record {
    fn refuse(&self, id: u64, error: &ErrorBody) -> bool {
        self.answer(id, Answer::Error(error.code))
    }

    fn settle(&self, id: u64, error: &ErrorBody, abort: &Abort) {
        let mut answers = self.0.lock().unwrap();
        match answers.get(&id) {
            None => {
                answers.insert(id, Answer::Error(error.code));
            }
            Some(Answer::Head) => {
                answers.insert(id, Answer::Abort(abort.code));
            }
            Some(_) => {}
        }
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
                        record.0.lock().unwrap().insert(ticket.id, Answer::Done);
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
        self.started.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    fn returned(&self) -> (u64, bool) {
        self.returned.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    /// Nothing more starts within a short wait.
    fn no_start(&self) {
        assert_eq!(
            self.started.recv_timeout(Duration::from_millis(150)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
    }
}

fn far() -> Instant {
    Instant::now() + Duration::from_secs(600)
}

fn soon(ms: u64) -> Instant {
    Instant::now() + Duration::from_millis(ms)
}

fn until(done: impl Fn() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(5);
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
    assert!(pools.stop(soon(2000)));
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

    assert!(pool.stop(soon(2000)));
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
    assert!(pool.stop(soon(2000)));
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
    assert!(pool.stop(soon(2000)));
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
    assert!(pool.stop(soon(2000)));
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
    assert!(pool.stop(soon(2000)));
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
    assert!(pool.stop(soon(2000)));
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
    // Answered at its deadline, while the thread is still busy.
    assert!(until(|| record.get(2).is_some()));
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
    assert!(pool.stop(soon(2000)));
}

#[test]
fn a_running_request_past_its_deadline_is_deadline_and_cancelled_unless_headed() {
    let (record, hold, probe) = (Record::default(), Hold::default(), Probe::new());
    let pool = open(shape(2, 0));
    let work = probe.work(&record, &hold, Kind::Heeds);
    pool.submit(1, soon(150), record.clone(), work);
    let work = probe.work(&record, &hold, Kind::Headed);
    pool.submit(2, soon(150), record.clone(), work);
    probe.started();
    probe.started();
    assert_eq!(probe.returned(), (1, true));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Deadline)));
    // Its head was queued in time: no service deadline after it.
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(record.get(2), Some(Answer::Head));
    hold.release();
    assert_eq!(probe.returned(), (2, false));
    assert_eq!(record.get(2), Some(Answer::Done));
    assert!(pool.stop(soon(2000)));
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
    assert!(pool.stop(soon(3000)));
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
    assert!(began.elapsed() < Duration::from_secs(2));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Stopped)));
    // Its timer ended; its worker is the work's.
    assert_eq!(alive(&pool), 1);
    // Once its work returns, the thread ends: nothing is left behind.
    hold.release();
    assert_eq!(probe.returned(), (1, true));
    assert!(until(|| alive(&pool) == 0));
    assert!(pool.drain(soon(1000)));
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
    assert!(pool.stop(soon(2000)));
    assert!(joined(&pool));
}

#[test]
fn work_that_answers_nothing_is_internal() {
    let record = Record::default();
    let pool = open(shape(1, 0));
    pool.submit(1, far(), record.clone(), Box::new(|_: &Ticket| {}));
    assert!(until(|| record.get(1).is_some()));
    assert_eq!(record.get(1), Some(Answer::Error(ErrorCode::Internal)));
    assert!(pool.stop(soon(2000)));
}

#[test]
fn dropping_a_pool_ends_its_threads() {
    let pool = Pool::<Record>::start("test", shape(3, 1)).unwrap();
    let inner = pool.inner.clone();
    assert_eq!(inner.lock().alive, 4);
    drop(pool);
    assert!(until(|| inner.lock().alive == 0));
}
