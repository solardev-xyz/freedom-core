//! The dweb thread's hashing pool (design 0009, `dweb.verify`: "A pool of
//! two hashing threads computes BMT roots and SHA-256 digests, and checks
//! RSA signatures, for it").
//!
//! - **What runs here:** the verifier's hash jobs ([`Job::run`]): a chunk's
//!   BMT root and keccak, a feed update's signature recovery, a leaf's
//!   digest, an IPFS block's digest, an IPNS record's signature. The dweb
//!   thread runs the walks; the pool keeps the hashing off it, so one large
//!   block never holds up every other request's next step.
//! - **Two slots, and no queue of the pool's own.** The pool takes a job only
//!   while one of its threads has neither a job nor a result the dweb thread
//!   hasn't taken ([`Pool::try_run`]); otherwise it hands the job back. Jobs
//!   wait in the dweb thread's FIFO ([`Queue`]), which that thread owns, and
//!   each job's bytes count against its request's memory in the verifier
//!   until its result comes back (0009, Bounds: "jobs queue in the dweb
//!   thread, under the request's memory"). So the pool holds at most two
//!   jobs and their two results.
//! - **Results** wait in the pool until the dweb thread takes them
//!   ([`Pool::take`]), and a slot frees only then. Room for a result is held
//!   from its job's dispatch, so a thread never waits to hand one over.
//!   A thread that parks a result calls `wake`, once until the results are
//!   taken: a marker on the dweb thread's mailbox, which must not block, as
//!   naming's and chain's wakers don't.
//! - **No call waits on a job.** The pool's lock is held for constant-time
//!   handoffs only, never while a job runs.
//! - **Matching:** the pool knows no requests. Each result carries its job's
//!   ID, and a verifier refuses one that isn't its own. A request that ends
//!   keeps its verifier, and the job's bytes charged, until each of its jobs
//!   has come back ([`fc_dweb::verifier::Verifier::finished`]).
//! - **Stopping:** an explicit [`Pool::shutdown`], a drop or an unwind, and a
//!   start that fails part way all take one path. The pool closes, drops the
//!   jobs no thread has started and the results not taken, and joins every
//!   thread it started, each after the job it is running. No thread waits on
//!   the dweb thread, so the join can't deadlock. A thread that panics is
//!   reported, as every thread of the core is ([`DeathNotice`]), and the
//!   core exits.

use std::collections::VecDeque;
use std::io;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use fc_dweb::verifier::{Hashed, Job};

use crate::serve::Event;
use crate::transport::DeathNotice;

/// The hashing threads (0009, Bounds: "hashing pool: 2 threads").
pub const THREADS: usize = 2;

struct State<T, R> {
    /// Jobs handed over that no thread has started.
    jobs: VecDeque<T>,
    /// Results the owner hasn't taken.
    results: VecDeque<R>,
    /// Slots taken: jobs handed over whose results haven't been taken. At
    /// most the pool's slots, so neither deque grows past them.
    busy: usize,
    /// A wake has gone since the owner last emptied `results`.
    woken: bool,
    closed: bool,
}

struct Shared<T, R> {
    state: Mutex<State<T, R>>,
    ready: Condvar,
}

/// The state, also after a thread panicked while holding the lock: no
/// handoff leaves it half done, and stopping must still see it.
fn lock<T, R>(shared: &Shared<T, R>) -> MutexGuard<'_, State<T, R>> {
    shared.state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A pool of threads that run jobs of type `T` into results of type `R`,
/// at most one job per thread at a time.
pub struct Pool<T: Send + 'static, R: Send + 'static> {
    shared: Arc<Shared<T, R>>,
    slots: usize,
    threads: Vec<JoinHandle<()>>,
}

type Body = Box<dyn FnOnce() + Send + 'static>;

impl<T: Send + 'static, R: Send + 'static> Pool<T, R> {
    /// Starts `slots` threads named `name`, each running `work` on the jobs
    /// it takes. `wake` tells the owner a result waits, and must not block.
    /// A thread that panics is reported through `events`.
    pub fn spawn(
        name: &'static str,
        slots: usize,
        work: impl Fn(T) -> R + Send + Sync + 'static,
        wake: impl Fn() + Send + Sync + 'static,
        events: Sender<Event>,
    ) -> io::Result<Self> {
        Self::start(name, slots, work, wake, events, |name, body: Body| {
            std::thread::Builder::new().name(name.into()).spawn(body)
        })
    }

    /// [`Pool::spawn`], starting each thread with `spawn`.
    fn start(
        name: &'static str,
        slots: usize,
        work: impl Fn(T) -> R + Send + Sync + 'static,
        wake: impl Fn() + Send + Sync + 'static,
        events: Sender<Event>,
        mut spawn: impl FnMut(&'static str, Body) -> io::Result<JoinHandle<()>>,
    ) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                jobs: VecDeque::with_capacity(slots),
                results: VecDeque::with_capacity(slots),
                busy: 0,
                woken: false,
                closed: false,
            }),
            ready: Condvar::new(),
        });
        let work = Arc::new(work);
        let wake = Arc::new(wake);
        // On an error below, the pool is dropped, which stops and joins the
        // threads already started.
        let mut pool = Pool {
            shared,
            slots,
            threads: Vec::with_capacity(slots),
        };
        for _ in 0..slots {
            let shared = Arc::clone(&pool.shared);
            let work = Arc::clone(&work);
            let wake = Arc::clone(&wake);
            let events = events.clone();
            let body: Body = Box::new(move || {
                let _notice = DeathNotice::new(events, name);
                serve(&shared, &*work, &*wake);
            });
            pool.threads.push(spawn(name, body)?);
        }
        Ok(pool)
    }

    /// Hands `job` to a free thread. When every slot is taken (a job running
    /// or handed over, or a result not yet taken), the job comes back.
    pub fn try_run(&self, job: T) -> Result<(), T> {
        let mut state = lock(&self.shared);
        if state.closed || state.busy >= self.slots {
            return Err(job);
        }
        state.busy += 1;
        state.jobs.push_back(job);
        drop(state);
        self.shared.ready.notify_one();
        Ok(())
    }

    /// The oldest result not yet taken, whose slot is free from now on.
    pub fn take(&self) -> Option<R> {
        let mut state = lock(&self.shared);
        let result = state.results.pop_front();
        if result.is_some() {
            state.busy = state.busy.saturating_sub(1);
        }
        if state.results.is_empty() {
            state.woken = false;
        }
        result
    }

    /// Slots taken.
    pub fn busy(&self) -> usize {
        lock(&self.shared).busy
    }

    /// Stops the pool: see [`Pool::stop`].
    pub fn shutdown(mut self) {
        self.stop();
    }

    /// Closes the pool, drops the jobs not started and the results not
    /// taken, and joins every thread, each after the job it is running.
    fn stop(&mut self) {
        let (jobs, results) = {
            let mut state = lock(&self.shared);
            state.closed = true;
            (
                std::mem::take(&mut state.jobs),
                std::mem::take(&mut state.results),
            )
        };
        drop((jobs, results));
        self.shared.ready.notify_all();
        for handle in self.threads.drain(..) {
            // A thread that panicked has been reported already.
            let _ = handle.join();
        }
    }

    /// Results parked and not taken.
    #[cfg(test)]
    fn parked(&self) -> usize {
        lock(&self.shared).results.len()
    }
}

impl<T: Send + 'static, R: Send + 'static> Drop for Pool<T, R> {
    /// A pool dropped without [`Pool::shutdown`], in an unwind too, stops
    /// and joins its threads all the same.
    fn drop(&mut self) {
        self.stop();
    }
}

/// A thread's loop: take a job, run it, park its result, until closed.
fn serve<T, R>(shared: &Shared<T, R>, work: &dyn Fn(T) -> R, wake: &dyn Fn()) {
    loop {
        let job = {
            let mut state = lock(shared);
            loop {
                if state.closed {
                    return;
                }
                if let Some(job) = state.jobs.pop_front() {
                    break job;
                }
                state = shared
                    .ready
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        };
        let result = work(job);
        let notify = {
            let mut state = lock(shared);
            if state.closed {
                return;
            }
            // Its slot holds its room: `results` never grows past the slots.
            state.results.push_back(result);
            !std::mem::replace(&mut state.woken, true)
        };
        if notify {
            wake();
        }
    }
}

/// The dweb thread's side of a pool: its own FIFO of jobs waiting for a
/// slot, first in, first out across every request, and the pool. The dweb
/// thread owns it; nothing here locks but the pool's handoffs.
pub struct Queue<T: Send + 'static, R: Send + 'static> {
    pool: Pool<T, R>,
    waiting: VecDeque<T>,
}

/// The dweb thread's hashing: two threads running the verifier's jobs.
pub type Hashing = Queue<Job, Hashed>;

/// Starts the dweb thread's hashing. `wake` is the dweb thread's waker.
pub fn hashing(
    wake: impl Fn() + Send + Sync + 'static,
    events: Sender<Event>,
) -> io::Result<Hashing> {
    Pool::spawn("dweb-hash", THREADS, Job::run, wake, events).map(Queue::new)
}

impl<T: Send + 'static, R: Send + 'static> Queue<T, R> {
    pub fn new(pool: Pool<T, R>) -> Self {
        Self {
            pool,
            waiting: VecDeque::new(),
        }
    }

    /// Queues `job` behind those waiting, and hands the pool what it takes.
    pub fn submit(&mut self, job: T) {
        self.waiting.push_back(job);
        self.pump();
    }

    /// The next result; its slot goes to the job that has waited longest.
    pub fn take(&mut self) -> Option<R> {
        let result = self.pool.take();
        self.pump();
        result
    }

    /// Jobs waiting for a slot.
    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }

    /// Jobs in the pool: running, handed over, or with a result not taken.
    pub fn running(&self) -> usize {
        self.pool.busy()
    }

    /// Stops the pool and drops what waits.
    pub fn shutdown(self) {
        self.pool.shutdown();
    }

    fn pump(&mut self) {
        while let Some(job) = self.waiting.pop_front() {
            if let Err(job) = self.pool.try_run(job) {
                self.waiting.push_front(job);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{self, Receiver};
    use std::sync::{Barrier, Mutex as StdMutex};
    use std::time::Duration;

    use super::*;

    const WAIT: Duration = Duration::from_secs(10);

    fn events() -> (Sender<Event>, Receiver<Event>) {
        mpsc::channel()
    }

    /// A waker on a channel, and its receiving end.
    fn waker() -> (impl Fn() + Send + Sync + 'static, Receiver<()>) {
        let (tx, rx) = mpsc::channel();
        (
            move || {
                let _ = tx.send(());
            },
            rx,
        )
    }

    /// Takes `n` results, waiting on the waker between them.
    fn take_n<T: Send, R: Send>(q: &mut Queue<T, R>, woken: &Receiver<()>, n: usize) -> Vec<R> {
        let mut got = Vec::new();
        while got.len() < n {
            match q.take() {
                Some(r) => got.push(r),
                None => woken.recv_timeout(WAIT).unwrap(),
            }
        }
        got
    }

    /// Counts its drops.
    struct Counted(Arc<AtomicUsize>);

    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A job that signals it has started, then waits to be released, and
    /// marks itself finished: for the tests that stop a pool mid-job.
    struct Held {
        started: Receiver<()>,
        release: Sender<()>,
        finished: Arc<AtomicBool>,
        /// Held by `work`, so by every thread: one count left means each
        /// thread has ended.
        marker: Arc<()>,
    }

    fn held() -> (Held, impl Fn(()) + Send + Sync + 'static) {
        let (started_tx, started) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let release_rx = StdMutex::new(release_rx);
        let finished = Arc::new(AtomicBool::new(false));
        let marker = Arc::new(());
        let (done, mark) = (Arc::clone(&finished), Arc::clone(&marker));
        let work = move |()| {
            let _mark = &mark;
            started_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            done.store(true, Ordering::SeqCst);
        };
        (
            Held {
                started,
                release,
                finished,
                marker,
            },
            work,
        )
    }

    /// Releases the held job a little later, from another thread, so the
    /// caller is inside its stop by then.
    fn release_later(release: Sender<()>) -> JoinHandle<()> {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            release.send(()).unwrap();
        })
    }

    #[test]
    fn every_job_runs_once() {
        let (events, _gone) = events();
        let (wake, woken) = waker();
        let pool = Pool::spawn("test-pool", THREADS, |n: u32| n, wake, events).unwrap();
        let mut q = Queue::new(pool);
        for n in 0..1000 {
            q.submit(n);
            // Never more than the slots in the pool.
            assert!(q.running() <= THREADS);
        }
        let mut got = take_n(&mut q, &woken, 1000);
        got.sort_unstable();
        assert_eq!(got, (0..1000).collect::<Vec<_>>());
        assert_eq!((q.waiting(), q.running()), (0, 0));
        assert!(q.take().is_none());
        q.shutdown();
    }

    #[test]
    fn a_slow_job_holds_up_no_other() {
        // The first job blocks until the second has run: one thread alone
        // would never get there.
        let gate = Arc::new(Barrier::new(2));
        let order = Arc::new(StdMutex::new(Vec::new()));
        let (events, _gone) = events();
        let (wake, woken) = waker();
        let (job_gate, log) = (Arc::clone(&gate), Arc::clone(&order));
        let pool = Pool::spawn(
            "test-pool",
            THREADS,
            move |slow: bool| {
                if slow {
                    job_gate.wait();
                    log.lock().unwrap().push("slow");
                } else {
                    log.lock().unwrap().push("fast");
                    job_gate.wait();
                }
                slow
            },
            wake,
            events,
        )
        .unwrap();
        let mut q = Queue::new(pool);
        q.submit(true);
        q.submit(false);
        take_n(&mut q, &woken, 2);
        assert_eq!(*order.lock().unwrap(), ["fast", "slow"]);
        q.shutdown();
    }

    #[test]
    fn jobs_start_first_in_first_out_across_requests() {
        // Three requests' jobs, interleaved, through one slot: each starts
        // in the order it was submitted, whichever request it is for.
        let order = Arc::new(StdMutex::new(Vec::new()));
        let (events, _gone) = events();
        let (wake, woken) = waker();
        let log = Arc::clone(&order);
        let pool = Pool::spawn(
            "test-pool",
            1,
            move |job: (u32, u32)| log.lock().unwrap().push(job),
            wake,
            events,
        )
        .unwrap();
        let mut q = Queue::new(pool);
        let jobs: Vec<(u32, u32)> = (0..60).map(|i| (i % 3, i / 3)).collect();
        for &job in &jobs {
            q.submit(job);
        }
        // One slot: the rest wait in the dweb thread, not in the pool.
        assert_eq!((q.running(), q.waiting()), (1, 59));
        take_n(&mut q, &woken, jobs.len());
        assert_eq!(*order.lock().unwrap(), jobs);
        q.shutdown();
    }

    #[test]
    fn a_full_pool_hands_jobs_back_and_its_threads_never_wait() {
        // Results nobody takes: the slots stay taken, the next job comes
        // back, and the threads, their results parked, still stop at once.
        let dropped = Arc::new(AtomicUsize::new(0));
        let (events, _gone) = events();
        let (wake, woken) = waker();
        let count = Arc::clone(&dropped);
        let pool = Pool::spawn(
            "test-pool",
            THREADS,
            move |()| Counted(Arc::clone(&count)),
            wake,
            events,
        )
        .unwrap();
        for _ in 0..THREADS {
            assert!(pool.try_run(()).is_ok());
        }
        assert_eq!(pool.try_run(()), Err(()));
        // One wake for both results, until they are taken.
        woken.recv_timeout(WAIT).unwrap();
        while pool.parked() < THREADS {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(woken.try_recv().is_err());
        assert_eq!(pool.busy(), THREADS);
        assert_eq!(pool.try_run(()), Err(()));
        // Each result taken frees one slot.
        drop(pool.take());
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(pool.try_run(()).is_ok());
        assert_eq!(pool.try_run(()), Err(()));
        while pool.parked() < THREADS {
            std::thread::sleep(Duration::from_millis(1));
        }
        // Stopped with results parked: they are dropped, and the join
        // returns, since no thread waits to hand one over.
        pool.shutdown();
        assert_eq!(dropped.load(Ordering::SeqCst), THREADS + 1);
    }

    #[test]
    fn shutdown_drops_the_jobs_waiting() {
        let (h, work) = held();
        let dropped = Arc::new(AtomicUsize::new(0));
        let (events, _gone) = events();
        let (wake, _woken) = waker();
        let pool = Pool::spawn(
            "test-pool",
            1,
            move |c: Counted| {
                drop(c);
                work(());
            },
            wake,
            events,
        )
        .unwrap();
        let mut q = Queue::new(pool);
        for _ in 0..11 {
            q.submit(Counted(Arc::clone(&dropped)));
        }
        h.started.recv_timeout(WAIT).unwrap();
        // Released first, so a failed check below can't leave the stop
        // waiting on the held job.
        let later = release_later(h.release);
        // The running job's own value is gone; ten wait.
        assert_eq!((q.running(), q.waiting()), (1, 10));
        q.shutdown();
        later.join().unwrap();
        assert!(h.finished.load(Ordering::SeqCst));
        assert_eq!(dropped.load(Ordering::SeqCst), 11);
        assert_eq!(Arc::strong_count(&h.marker), 1);
    }

    #[test]
    fn a_drop_joins_every_thread() {
        let (h, work) = held();
        let (events, _gone) = events();
        let (wake, _woken) = waker();
        let pool = Pool::spawn("test-pool", THREADS, work, wake, events).unwrap();
        pool.try_run(()).unwrap();
        h.started.recv_timeout(WAIT).unwrap();
        let later = release_later(h.release);
        drop(pool);
        // Back only once the running job has finished and every thread ended.
        assert!(h.finished.load(Ordering::SeqCst));
        assert_eq!(Arc::strong_count(&h.marker), 1);
        later.join().unwrap();
    }

    #[test]
    fn an_unwind_joins_every_thread() {
        let (h, work) = held();
        let (events, _gone) = events();
        let (wake, _woken) = waker();
        let Held {
            started,
            release,
            finished,
            marker,
        } = h;
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let pool = Pool::spawn("test-pool", THREADS, work, wake, events).unwrap();
            pool.try_run(()).unwrap();
            started.recv_timeout(WAIT).unwrap();
            let _later = release_later(release);
            panic!("the owner unwinds");
        }));
        assert!(unwound.is_err());
        assert!(finished.load(Ordering::SeqCst));
        assert_eq!(Arc::strong_count(&marker), 1);
    }

    #[test]
    fn a_start_that_fails_joins_what_it_started() {
        let marker = Arc::new(());
        let mark = Arc::clone(&marker);
        let (events, _gone) = events();
        let (wake, _woken) = waker();
        let mut started = 0;
        let failed = Pool::<(), ()>::start(
            "test-pool",
            THREADS,
            move |()| {
                let _mark = &mark;
            },
            wake,
            events,
            |name, body| {
                started += 1;
                if started == 2 {
                    return Err(io::Error::other("no second thread"));
                }
                std::thread::Builder::new().name(name.into()).spawn(body)
            },
        );
        assert!(failed.is_err());
        // The first thread had started, and has ended.
        assert_eq!(started, 2);
        assert_eq!(Arc::strong_count(&marker), 1);
    }

    #[test]
    fn a_panicking_job_is_reported() {
        let (events, rx) = events();
        let (wake, _woken) = waker();
        let pool = Pool::spawn(
            "test-pool",
            1,
            |boom: bool| {
                if boom {
                    panic!("a job panicked");
                }
            },
            wake,
            events,
        )
        .unwrap();
        pool.try_run(true).unwrap();
        match rx.recv_timeout(WAIT).unwrap() {
            Event::ThreadDied(name) => assert_eq!(name, "test-pool"),
            _ => panic!("another event"),
        }
        pool.shutdown();
    }

    /// The verifier's own jobs through the dweb thread's hashing: each
    /// request's root chunk is hashed off the caller's thread, and its
    /// result is its verifier's. A request cancelled while its job waits or
    /// runs keeps its job's bytes until the result comes back.
    #[test]
    fn verifier_jobs_come_back_to_their_verifier() {
        use fc_dweb::verifier::{Method, Output, Verifier};
        use fc_dweb::{
            Backend, ContentTrust, Node, ResponseOp, Root, Trust, Verify, retry, timers,
        };

        let doc: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../vectors/dweb-verify.json"
            ))
            .unwrap(),
        )
        .unwrap();
        // A file's root chunk, as Ant answers /chunks.
        let (address, wire) = doc["swarm"]["chunks"]
            .as_object()
            .unwrap()
            .iter()
            .next()
            .map(|(a, w)| {
                use base64::Engine as _;
                let wire = base64::engine::general_purpose::STANDARD
                    .decode(w.as_str().unwrap())
                    .unwrap();
                (a.clone(), wire)
            })
            .unwrap();
        let backend = Backend::ant(fc_dweb::Ant::External, true);
        let plan = Verify {
            node: Node::Ant,
            root: Root::Swarm(address.clone()),
            path: "/".into(),
            query: String::new(),
            headers: vec![],
            retry: retry(backend),
            timers: timers(backend),
            response: vec![ResponseOp::CanonicalizeRedirect, ResponseOp::StripPageState],
            trust: Trust {
                name: None,
                content: ContentTrust::Verified,
            },
        };
        let (events, _gone) = events();
        let (wake, woken) = waker();
        let mut q = hashing(wake, events).unwrap();
        let mut verifiers: Vec<Verifier> = (1..=50)
            .map(|request| {
                Verifier::new(request, &plan, Method::Get, None, false, Default::default()).unwrap()
            })
            .collect();
        for v in &mut verifiers {
            let Some(Output::Piece(piece)) = v.poll() else {
                panic!("the root first");
            };
            assert_eq!(piece.path, format!("/chunks/{address}"));
            v.piece_whole(piece.id, 200, vec![], wire.clone()).unwrap();
            let Some(Output::Hash(job)) = v.poll() else {
                panic!("its hash");
            };
            q.submit(job);
        }
        assert!(q.running() <= THREADS);
        // Every other request is cancelled with its job out: it isn't
        // finished, and holds the job's bytes, until the result is back.
        for v in verifiers.iter_mut().step_by(2) {
            v.cancel();
            while v.poll().is_some() {}
            assert!(!v.finished());
            assert!(v.reserved() > 0);
        }
        for hashed in take_n(&mut q, &woken, verifiers.len()) {
            let request = hashed.id().request;
            let v = &mut verifiers[usize::try_from(request - 1).unwrap()];
            v.hashed(hashed).unwrap();
            if request % 2 == 1 {
                // Cancelled: the result ends it.
                assert!(v.poll().is_none(), "{request}");
                assert!(v.finished(), "{request}");
                assert_eq!(v.reserved(), 0, "{request}");
            } else {
                // Checked: the walk moves on past the root.
                assert!(v.poll().is_some(), "{request}");
            }
        }
        assert_eq!((q.waiting(), q.running()), (0, 0));
        q.shutdown();
    }
}
