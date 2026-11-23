//! The verifier thread's executor (design 0014, "Inside the process"): plain
//! threads and no async runtime, so this is a small single-threaded one.
//!
//! Each request is a future that owns its context and holds the C core's
//! pending requests across its waits for main's fetches. Only this thread
//! polls them, so every call into the C core is made on it. A waker puts
//! its task back in the ready queue and wakes the thread; jobs from the
//! connection's reader thread arrive through the same queue. Timers (a
//! fetch's `delay`) are kept here too, so the thread sleeps until the next
//! one is due.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Instant;

/// A task's future.
pub type Task = Pin<Box<dyn Future<Output = ()>>>;

/// The queue the verifier thread waits on: tasks woken, and jobs `J` from
/// other threads.
pub struct Queue<J> {
    inner: Mutex<Inner<J>>,
    signal: Condvar,
}

struct Inner<J> {
    ready: VecDeque<u64>,
    jobs: VecDeque<J>,
}

impl<J> Queue<J> {
    pub fn new() -> Arc<Queue<J>> {
        Arc::new(Queue {
            inner: Mutex::new(Inner {
                ready: VecDeque::new(),
                jobs: VecDeque::new(),
            }),
            signal: Condvar::new(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner<J>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hands `job` to the verifier thread. Never blocks for long: the lock
    /// is held only to push.
    pub fn push(&self, job: J) {
        self.lock().jobs.push_back(job);
        self.signal.notify_one();
    }

    fn wake(&self, task: u64) {
        self.lock().ready.push_back(task);
        self.signal.notify_one();
    }

    /// Waits until a job or a woken task is there, or `until` passes, and
    /// takes them all.
    fn wait(&self, until: Option<Instant>) -> (Vec<J>, Vec<u64>) {
        let mut inner = self.lock();
        while inner.ready.is_empty() && inner.jobs.is_empty() {
            match until {
                None => {
                    inner = self
                        .signal
                        .wait(inner)
                        .unwrap_or_else(PoisonError::into_inner)
                }
                Some(until) => {
                    let now = Instant::now();
                    if now >= until {
                        break;
                    }
                    inner = self
                        .signal
                        .wait_timeout(inner, until - now)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            }
        }
        (
            inner.jobs.drain(..).collect(),
            inner.ready.drain(..).collect(),
        )
    }
}

/// A task's waker: puts the task back in the ready queue.
struct TaskWaker<J> {
    task: u64,
    queue: Arc<Queue<J>>,
}

impl<J: Send + 'static> Wake for TaskWaker<J> {
    fn wake(self: Arc<Self>) {
        self.queue.wake(self.task);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.queue.wake(self.task);
    }
}

/// The timers, by when they are due: a [`sleep`] registers its waker here.
#[derive(Default)]
pub struct Timers {
    due: RefCell<BTreeMap<(Instant, u64), Waker>>,
    next: RefCell<u64>,
}

impl Timers {
    /// The earliest timer.
    fn next_due(&self) -> Option<Instant> {
        self.due.borrow().keys().next().map(|(at, _)| *at)
    }

    /// Wakes the timers due by now.
    fn fire(&self) {
        let now = Instant::now();
        let due: Vec<Waker> = {
            let mut due = self.due.borrow_mut();
            let later = due.split_off(&(now, u64::MAX));
            std::mem::replace(&mut *due, later).into_values().collect()
        };
        for waker in due {
            waker.wake();
        }
    }
}

/// A future that is ready once `until` has passed.
pub fn sleep(timers: Rc<Timers>, until: Instant) -> impl Future<Output = ()> {
    std::future::poll_fn(move |cx| {
        if Instant::now() >= until {
            return Poll::Ready(());
        }
        let id = {
            let mut next = timers.next.borrow_mut();
            *next += 1;
            *next
        };
        timers
            .due
            .borrow_mut()
            .insert((until, id), cx.waker().clone());
        Poll::Pending
    })
}

/// The executor: the tasks, keyed by an id the caller chooses.
pub struct Executor<J> {
    queue: Arc<Queue<J>>,
    tasks: HashMap<u64, Task>,
    pub timers: Rc<Timers>,
}

impl<J: Send + 'static> Executor<J> {
    pub fn new(queue: Arc<Queue<J>>) -> Executor<J> {
        Executor {
            queue,
            tasks: HashMap::new(),
            timers: Rc::new(Timers::default()),
        }
    }

    /// Adds a task and polls it once. An id already in use is the caller's
    /// error; the old task is dropped.
    pub fn spawn(&mut self, id: u64, task: Task) {
        self.tasks.insert(id, task);
        self.poll(id);
    }

    /// The number of tasks not yet finished.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Whether every task has finished.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Whether task `id` hasn't finished.
    pub fn contains(&self, id: u64) -> bool {
        self.tasks.contains_key(&id)
    }

    /// Wakes task `id`: it is polled in the next round.
    pub fn wake(&self, id: u64) {
        self.queue.wake(id);
    }

    fn poll(&mut self, id: u64) {
        let Some(task) = self.tasks.get_mut(&id) else {
            return;
        };
        let waker = Waker::from(Arc::new(TaskWaker {
            task: id,
            queue: Arc::clone(&self.queue),
        }));
        if task
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
        {
            self.tasks.remove(&id);
        }
    }

    /// Waits for work, then polls every task woken and returns the jobs
    /// that came, for the caller to handle before the next round.
    pub fn turn(&mut self) -> Vec<J> {
        let (jobs, ready) = self.queue.wait(self.timers.next_due());
        self.timers.fire();
        let mut seen = HashSet::new();
        for id in ready {
            if seen.insert(id) {
                self.poll(id);
            }
        }
        jobs
    }

    /// Polls the tasks woken since the last round, without waiting. For a
    /// caller that has just changed what a task waits on.
    pub fn run_ready(&mut self) {
        let ready: Vec<u64> = self.queue.lock().ready.drain(..).collect();
        let mut seen = HashSet::new();
        for id in ready {
            if seen.insert(id) {
                self.poll(id);
            }
        }
    }

    /// Drops every task, and what each holds: its context is freed.
    pub fn clear(&mut self) {
        self.tasks.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::time::Duration;

    #[test]
    fn tasks_jobs_and_timers() {
        let queue: Arc<Queue<u32>> = Queue::new();
        let mut exec = Executor::new(Arc::clone(&queue));
        let done = Rc::new(Cell::new(0));
        let timers = Rc::clone(&exec.timers);
        let d = Rc::clone(&done);
        exec.spawn(
            1,
            Box::pin(async move {
                sleep(timers, Instant::now() + Duration::from_millis(20)).await;
                d.set(d.get() + 1);
            }),
        );
        assert_eq!(exec.len(), 1);
        let pusher = Arc::clone(&queue);
        let thread = std::thread::spawn(move || pusher.push(7));
        let mut jobs = Vec::new();
        let started = Instant::now();
        while !exec.is_empty() || jobs.is_empty() {
            jobs.extend(exec.turn());
            assert!(started.elapsed() < Duration::from_secs(5));
        }
        thread.join().unwrap();
        assert_eq!(jobs, [7]);
        assert_eq!(done.get(), 1);
        assert!(started.elapsed() >= Duration::from_millis(20));
    }
}
