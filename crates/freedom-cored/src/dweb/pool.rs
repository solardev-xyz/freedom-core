//! The dweb thread's hashing pool (design 0009, `dweb.verify`: "A pool of
//! two hashing threads computes BMT roots and SHA-256 digests for it").
//!
//! - **What runs here:** the verifier's hash jobs ([`Job::run`]): a chunk's
//!   BMT root and keccak, a feed update's signature recovery, a leaf's
//!   digest, an IPFS block's digest, an IPNS record's signature. The dweb
//!   thread runs the walks; the pool keeps the hashing off it, so one large
//!   block never holds up every other request's next step.
//! - **Order:** one queue, first in, first out, taken by whichever thread is
//!   free. Two jobs may finish in either order; each result carries its
//!   job's ID, and the verifier matches it.
//! - **Submitting never blocks,** and the queue has no bound of its own:
//!   each job's bytes count against its request's memory in the verifier
//!   (0009, Bounds: "jobs queue in the dweb thread, under the request's
//!   memory"), so what waits here is bounded there.
//! - **Results** go to a sink: the dweb thread's mailbox. The pool knows no
//!   requests. A result for a request that has ended is the dweb thread's
//!   to drop, and the verifier refuses one that isn't its own.
//! - **Shutdown** closes the queue and drops what is queued; the threads
//!   finish the job each is running and stop. A thread that panics is
//!   reported, as every thread of the core is ([`DeathNotice`]), and the
//!   core exits.

use std::collections::VecDeque;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use fc_dweb::verifier::{Hashed, Job};

use crate::serve::Event;
use crate::transport::DeathNotice;

/// The hashing threads (0009, Bounds: "hashing pool: 2 threads").
pub const THREADS: usize = 2;

struct State<T> {
    queue: VecDeque<T>,
    closed: bool,
}

struct Shared<T> {
    state: Mutex<State<T>>,
    ready: Condvar,
}

/// A pool of threads that run jobs of type `T`, first in, first out.
pub struct Pool<T: Send + 'static> {
    shared: Arc<Shared<T>>,
    threads: Vec<JoinHandle<()>>,
}

/// The dweb thread's pool: each job's result goes to `done`.
pub fn hashing(
    done: impl Fn(Hashed) + Send + Sync + 'static,
    events: Sender<Event>,
) -> std::io::Result<Pool<Job>> {
    Pool::spawn(
        "dweb-hash",
        THREADS,
        move |job: Job| done(job.run()),
        events,
    )
}

impl<T: Send + 'static> Pool<T> {
    /// Starts `threads` threads named `name`, each running `work` on the
    /// jobs it takes. A thread that panics is reported through `events`.
    pub fn spawn(
        name: &'static str,
        threads: usize,
        work: impl Fn(T) + Send + Sync + 'static,
        events: Sender<Event>,
    ) -> std::io::Result<Self> {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                queue: VecDeque::new(),
                closed: false,
            }),
            ready: Condvar::new(),
        });
        let work = Arc::new(work);
        let mut pool = Pool {
            shared,
            threads: Vec::with_capacity(threads),
        };
        for _ in 0..threads {
            let shared = Arc::clone(&pool.shared);
            let work = Arc::clone(&work);
            let events = events.clone();
            let handle = std::thread::Builder::new()
                .name(name.into())
                .spawn(move || {
                    let _notice = DeathNotice::new(events, name);
                    while let Some(job) = take(&shared) {
                        work(job);
                    }
                });
            match handle {
                Ok(handle) => pool.threads.push(handle),
                Err(error) => {
                    // The threads already started stop with the pool.
                    pool.close();
                    return Err(error);
                }
            }
        }
        Ok(pool)
    }

    /// Queues a job. False once the pool is shut down.
    pub fn submit(&self, job: T) -> bool {
        let Ok(mut state) = self.shared.state.lock() else {
            return false;
        };
        if state.closed {
            return false;
        }
        state.queue.push_back(job);
        drop(state);
        self.shared.ready.notify_one();
        true
    }

    /// Jobs queued and not yet taken.
    pub fn queued(&self) -> usize {
        self.shared.state.lock().map_or(0, |s| s.queue.len())
    }

    /// Closes the queue, drops what is queued, and waits for the threads to
    /// finish the jobs they are running.
    pub fn shutdown(mut self) {
        self.close();
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }

    fn close(&mut self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.closed = true;
            state.queue.clear();
        }
        self.shared.ready.notify_all();
    }
}

impl<T: Send + 'static> Drop for Pool<T> {
    /// A pool dropped without [`Pool::shutdown`] still stops its threads;
    /// it doesn't wait for them.
    fn drop(&mut self) {
        self.close();
    }
}

/// The next job, or `None` once the pool is closed.
fn take<T>(shared: &Shared<T>) -> Option<T> {
    let mut state = shared.state.lock().ok()?;
    loop {
        if state.closed {
            return None;
        }
        if let Some(job) = state.queue.pop_front() {
            return Some(job);
        }
        state = shared.ready.wait(state).ok()?;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::sync::{Barrier, Mutex as StdMutex};
    use std::time::Duration;

    use super::*;

    fn events() -> (Sender<Event>, mpsc::Receiver<Event>) {
        mpsc::channel()
    }

    #[test]
    fn every_job_runs_once() {
        let (tx, rx) = mpsc::channel();
        let (events, _gone) = events();
        let pool = Pool::spawn(
            "test-pool",
            THREADS,
            move |n: u32| tx.send(n).unwrap(),
            events,
        )
        .unwrap();
        for n in 0..1000 {
            assert!(pool.submit(n));
        }
        let mut got: Vec<u32> = (0..1000)
            .map(|_| rx.recv_timeout(Duration::from_secs(10)).unwrap())
            .collect();
        got.sort_unstable();
        assert_eq!(got, (0..1000).collect::<Vec<_>>());
        pool.shutdown();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_slow_job_holds_up_no_other() {
        // The first job blocks until the second has run: one thread alone
        // would never get there.
        let gate = Arc::new(Barrier::new(2));
        let (tx, rx) = mpsc::channel();
        let (events, _gone) = events();
        let job_gate = Arc::clone(&gate);
        let pool = Pool::spawn(
            "test-pool",
            THREADS,
            move |slow: bool| {
                if slow {
                    job_gate.wait();
                    tx.send("slow").unwrap();
                } else {
                    tx.send("fast").unwrap();
                    job_gate.wait();
                }
            },
            events,
        )
        .unwrap();
        pool.submit(true);
        pool.submit(false);
        let first = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let second = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!((first, second), ("fast", "slow"));
        pool.shutdown();
    }

    #[test]
    fn jobs_are_taken_first_in_first_out() {
        // One thread: the jobs run in the order they were queued.
        let order = Arc::new(StdMutex::new(Vec::new()));
        let (events, _gone) = events();
        let seen = Arc::clone(&order);
        let (tx, rx) = mpsc::channel();
        let pool = Pool::spawn(
            "test-pool",
            1,
            move |n: u32| {
                seen.lock().unwrap().push(n);
                tx.send(()).unwrap();
            },
            events,
        )
        .unwrap();
        for n in 0..200 {
            pool.submit(n);
        }
        for _ in 0..200 {
            rx.recv_timeout(Duration::from_secs(10)).unwrap();
        }
        assert_eq!(*order.lock().unwrap(), (0..200).collect::<Vec<_>>());
        pool.shutdown();
    }

    #[test]
    fn shutdown_drops_what_is_queued() {
        // Both threads held inside a job; ten more queued behind them.
        let hold = Arc::new(Barrier::new(THREADS + 1));
        let release = Arc::new(Barrier::new(THREADS + 1));
        let ran = Arc::new(StdMutex::new(0));
        let (events, _gone) = events();
        let (h, r, count) = (Arc::clone(&hold), Arc::clone(&release), Arc::clone(&ran));
        let pool = Pool::spawn(
            "test-pool",
            THREADS,
            move |()| {
                *count.lock().unwrap() += 1;
                h.wait();
                r.wait();
            },
            events,
        )
        .unwrap();
        for _ in 0..THREADS + 10 {
            pool.submit(());
        }
        hold.wait();
        assert_eq!(pool.queued(), 10);
        // Closed while both run: the queued ten never run.
        let mut pool = pool;
        pool.close();
        assert_eq!(pool.queued(), 0);
        release.wait();
        pool.shutdown();
        assert_eq!(*ran.lock().unwrap(), THREADS);
    }

    #[test]
    fn a_closed_pool_takes_nothing() {
        let (events, _gone) = events();
        let mut pool = Pool::spawn("test-pool", THREADS, |_: u32| {}, events).unwrap();
        pool.close();
        assert!(!pool.submit(1));
        pool.shutdown();
    }

    #[test]
    fn a_panicking_job_is_reported() {
        let (events, rx) = events();
        let pool = Pool::spawn(
            "test-pool",
            1,
            |boom: bool| {
                if boom {
                    panic!("a job panicked");
                }
            },
            events,
        )
        .unwrap();
        pool.submit(true);
        match rx.recv_timeout(Duration::from_secs(10)).unwrap() {
            Event::ThreadDied(name) => assert_eq!(name, "test-pool"),
            _ => panic!("another event"),
        }
        pool.shutdown();
    }

    /// The verifier's own jobs through the pool: a request's root chunk is
    /// hashed off the caller's thread, and its result is the verifier's.
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
        let (tx, rx) = mpsc::channel();
        let (events, _gone) = events();
        let pool = hashing(move |hashed| tx.send(hashed).unwrap(), events).unwrap();
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
            assert!(pool.submit(job));
        }
        for _ in 0..verifiers.len() {
            let hashed = rx.recv_timeout(Duration::from_secs(10)).unwrap();
            let request = hashed.id().request;
            let v = &mut verifiers[usize::try_from(request - 1).unwrap()];
            v.hashed(hashed).unwrap();
            // Checked: the walk moves on past the root.
            assert!(v.poll().is_some(), "{request}");
        }
        pool.shutdown();
    }
}
