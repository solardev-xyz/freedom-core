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

/// The timers, by when they are due: a [`Sleep`] keeps its waker here.
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

/// A future that is ready once `until` has passed. It keeps one entry in
/// the timers, updated when polled again and removed when it is dropped, so
/// a cancelled wait leaves nothing behind.
pub struct Sleep {
    timers: Rc<Timers>,
    until: Instant,
    key: Option<(Instant, u64)>,
}

impl Sleep {
    fn remove(&mut self) {
        if let Some(key) = self.key.take() {
            self.timers.due.borrow_mut().remove(&key);
        }
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if Instant::now() >= self.until {
            self.remove();
            return Poll::Ready(());
        }
        let key = match self.key {
            Some(key) => key,
            None => {
                let id = {
                    let mut next = self.timers.next.borrow_mut();
                    *next += 1;
                    *next
                };
                let key = (self.until, id);
                self.key = Some(key);
                key
            }
        };
        self.timers.due.borrow_mut().insert(key, cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        self.remove();
    }
}

/// [`Sleep`] until `until`.
pub fn sleep(timers: Rc<Timers>, until: Instant) -> Sleep {
    Sleep {
        timers,
        until,
        key: None,
    }
}

/// Ready on its second poll: the task goes back to the queue once, so the
/// jobs queued meanwhile (a cancel) are handled before it runs on.
pub fn yield_now() -> impl Future<Output = ()> {
    let mut yielded = false;
    std::future::poll_fn(move |cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
}

/// The executor: the tasks, keyed by an id the caller chooses.
pub struct Executor<J> {
    queue: Arc<Queue<J>>,
    tasks: HashMap<u64, Task>,
    pub timers: Rc<Timers>,
    /// The tasks woken by the last [`Executor::wait`], polled by the next
    /// [`Executor::run_woken`].
    woken: Vec<u64>,
}

impl<J: Send + 'static> Executor<J> {
    pub fn new(queue: Arc<Queue<J>>) -> Executor<J> {
        Executor {
            queue,
            tasks: HashMap::new(),
            timers: Rc::new(Timers::default()),
            woken: Vec::new(),
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

    /// Waits for work and returns the jobs that came. The tasks woken are
    /// polled by [`Executor::run_woken`], after the caller has handled the
    /// jobs: a cancel queued with a fetch's answer is seen first.
    pub fn wait(&mut self) -> Vec<J> {
        let (jobs, ready) = self.queue.wait(self.timers.next_due());
        self.timers.fire();
        self.woken.extend(ready);
        jobs
    }

    /// Polls the tasks woken by the last [`Executor::wait`], and those woken
    /// since, each once.
    pub fn run_woken(&mut self) {
        let mut woken = std::mem::take(&mut self.woken);
        woken.extend(self.queue.lock().ready.drain(..));
        let mut seen = HashSet::new();
        for id in woken {
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
        let started = Instant::now();
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
        while !exec.is_empty() || jobs.is_empty() {
            jobs.extend(exec.wait());
            exec.run_woken();
            assert!(started.elapsed() < Duration::from_secs(5));
        }
        thread.join().unwrap();
        assert_eq!(jobs, [7]);
        assert_eq!(done.get(), 1);
        assert!(started.elapsed() >= Duration::from_millis(20));
    }

    #[test]
    fn jobs_come_before_the_tasks_woken_with_them() {
        let queue: Arc<Queue<u32>> = Queue::new();
        let mut exec = Executor::new(Arc::clone(&queue));
        let polled = Rc::new(Cell::new(0));
        let p = Rc::clone(&polled);
        exec.spawn(
            1,
            Box::pin(async move {
                loop {
                    p.set(p.get() + 1);
                    yield_now().await;
                }
            }),
        );
        assert_eq!(polled.get(), 1);
        // The task is woken (its yield) and a job arrives: the job is
        // handed over before the task runs again.
        queue.push(9);
        let jobs = exec.wait();
        assert_eq!(jobs, [9]);
        assert_eq!(polled.get(), 1, "the task ran before its job was seen");
        exec.run_woken();
        assert_eq!(polled.get(), 2);
    }

    #[test]
    fn a_dropped_sleep_leaves_no_timer() {
        let queue: Arc<Queue<u32>> = Queue::new();
        let mut exec = Executor::new(Arc::clone(&queue));
        let timers = Rc::clone(&exec.timers);
        let t = Rc::clone(&timers);
        exec.spawn(
            1,
            Box::pin(async move {
                sleep(t, Instant::now() + Duration::from_secs(3600)).await;
            }),
        );
        assert_eq!(timers.due.borrow().len(), 1);
        // Polled again (a spurious wake): still one entry.
        exec.wake(1);
        exec.run_woken();
        assert_eq!(timers.due.borrow().len(), 1);
        // Dropped with its task: none.
        exec.clear();
        assert_eq!(timers.due.borrow().len(), 0);
    }
}
