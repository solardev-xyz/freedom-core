//! Watchdogs: plain threads, independent of any async runtime, that end the
//! process unless disarmed in time (design 0007, "Startup and shutdown" and
//! "Instances and their teardown").
//!
//! - **The exit watchdog** ends the process 5 s after the connection ends,
//!   whatever the state of its runtimes ([`crate::conn::run`] arms it).
//! - **A teardown's bound:** a service arms one before an instance's
//!   teardown and disarms it once quiescence is proven. If it fires, it
//!   logs its fixed reason (`teardown_unproven`) and exits 70, releasing
//!   nothing.
//! - **A standing watchdog** ([`Standing`]) is one thread for the service's
//!   lifetime, armed and disarmed for one bound after another: radicled's
//!   repair units (design 0008, "The unit watchdog"). No thread per bound,
//!   so never two at once, and one that can't be started fails the
//!   service's start, not a bound.
//!
//! A firing watchdog never waits on stderr: its line has at most 150 ms,
//! under a bound armed before it is written. The line names the bound that
//! ran out (`bound_ms`) and how long before it was armed (`elapsed_ms`, the
//! bound or more, if its thread ran late), so the bound that ended a
//! process is known from its line alone.

use std::cell::Cell;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::exit::Exit;

/// An armed watchdog. Dropping it without [`Watchdog::disarm`] leaves it
/// armed.
pub struct Watchdog {
    disarmed: Arc<(Mutex<bool>, Condvar)>,
}

impl Watchdog {
    /// Ends the process with `exit` after `after`, logging `reason` (a fixed
    /// name), unless disarmed first. If no thread can be started, it fires
    /// at once: a bound that can't be kept is no bound.
    pub fn arm(reason: &'static str, after: Duration, exit: Exit) -> Watchdog {
        Watchdog::arm_with(after, move || (reason, exit))
    }

    /// As [`Watchdog::arm`], with the reason and the exit decided when it
    /// fires: the connection's exit watchdog exits with the process's
    /// result as it stands then.
    pub(crate) fn arm_with(
        after: Duration,
        decide: impl FnOnce() -> (&'static str, Exit) + Send + 'static,
    ) -> Watchdog {
        let disarmed = Arc::new((Mutex::new(false), Condvar::new()));
        let state = disarmed.clone();
        let armed = Instant::now();
        let deadline = armed + after;
        let spawned = std::thread::Builder::new()
            .name("watchdog".into())
            .spawn(move || {
                let (flag, wake) = &*state;
                let mut flag = flag.lock().unwrap_or_else(|p| p.into_inner());
                while !*flag {
                    let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                        let (reason, exit) = decide();
                        fire(reason, exit, Some((after, armed.elapsed())));
                    };
                    flag = match wake.wait_timeout(flag, left) {
                        Ok((flag, _)) => flag,
                        Err(poisoned) => poisoned.into_inner().0,
                    };
                }
            });
        if let Err(error) = spawned {
            // The closure, and so `decide`, went with the error.
            drop(error);
            fire("watchdog_unavailable", Exit::Internal, None);
        }
        Watchdog { disarmed }
    }

    /// Stands the watchdog down.
    pub fn disarm(self) {
        let (flag, wake) = &*self.disarmed;
        *flag.lock().unwrap_or_else(|p| p.into_inner()) = true;
        wake.notify_all();
    }
}

/// A watchdog on one thread of its own for its whole life, armed for one
/// bound after another. Arming it replaces the bound before; [`Armed`] names
/// the bound, so standing down a bound that was replaced does nothing.
///
/// Dropping it waits for its thread to end. With no bound armed, that is at
/// once. A bound still armed is kept, and fires: the drop never returns,
/// because the process ends first. The one exception is a thread already
/// ending the process ([`crate::exit::claim`]): a bound firing then would
/// wait for that thread, so its drop returns at once, and the exit it began
/// ends the thread with the process.
pub struct Standing {
    shared: Arc<Shared>,
    /// The thread, until the drop joins it.
    worker: Option<JoinHandle<()>>,
}

/// A bound [`Standing::arm`] armed: its generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Armed(u64);

struct Shared {
    bound: Mutex<Bound>,
    wake: Condvar,
}

struct Bound {
    /// The last bound armed's generation.
    generation: u64,
    /// When the bound armed ends, if one is.
    deadline: Option<Instant>,
    /// The bound last armed, as [`Standing::arm`] was given it: what a
    /// firing watchdog logs.
    after: Duration,
    /// The `Standing` is gone: no bound can be armed again.
    dropped: bool,
    /// A test's clock, read in place of the system's once set.
    #[cfg(test)]
    clock: Option<Clock>,
}

impl Bound {
    /// The time now: the system's, or a test's clock.
    fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(clock) = &self.clock {
            return clock.now;
        }
        Instant::now()
    }
}

/// A test's clock. It stands still until the test moves it on, so no stall
/// of the test's thread can run a bound out.
#[cfg(test)]
struct Clock {
    now: Instant,
    /// The thread has checked the bound armed at `now`, and it held.
    checked: bool,
}

impl Standing {
    /// Starts its thread, named `reason`, which ends the process with `exit`,
    /// logging `reason` (a fixed name), when a bound runs out. An error if
    /// the thread can't be started.
    pub fn start(reason: &'static str, exit: Exit) -> std::io::Result<Standing> {
        let shared = Arc::new(Shared {
            bound: Mutex::new(Bound {
                generation: 0,
                deadline: None,
                after: Duration::ZERO,
                dropped: false,
                #[cfg(test)]
                clock: None,
            }),
            wake: Condvar::new(),
        });
        let state = shared.clone();
        let worker = std::thread::Builder::new()
            .name(reason.into())
            .spawn(move || {
                let _ = WORKER.try_with(|worker| worker.set(true));
                state.watch(reason, exit);
            })?;
        Ok(Standing {
            shared,
            worker: Some(worker),
        })
    }

    /// Arms it to end the process `after` from now, replacing the bound
    /// armed before, if any.
    pub fn arm(&self, after: Duration) -> Armed {
        let mut bound = self.shared.lock();
        bound.generation += 1;
        bound.deadline = Some(bound.now() + after);
        bound.after = after;
        let armed = Armed(bound.generation);
        drop(bound);
        self.shared.wake.notify_all();
        armed
    }

    /// Stands `armed` down, if it is still the bound armed.
    pub fn disarm(&self, armed: Armed) {
        let mut bound = self.shared.lock();
        if bound.generation == armed.0 {
            bound.deadline = None;
            drop(bound);
            self.shared.wake.notify_all();
        }
    }
}

thread_local! {
    // Set on a standing watchdog's thread. No destructor, so it stays
    // readable while thread-locals are torn down.
    static WORKER: Cell<bool> = const { Cell::new(false) };
}

impl Drop for Standing {
    fn drop(&mut self) {
        // Two threads must not wait here. One ending the process: a bound
        // that fires then parks for that exit holding the lock
        // (`exit::claim`), so neither the lock nor the join would return.
        // And a watchdog's own thread, which can't join itself. It runs only
        // its loop and holds no `Standing`, so that one is a guard.
        if crate::exit::ending_here() || WORKER.try_with(Cell::get).unwrap_or(false) {
            return;
        }
        // The lock is released before the join, so the thread can see it.
        self.shared.lock().dropped = true;
        self.shared.wake.notify_all();
        if let Some(worker) = self.worker.take() {
            // With no bound armed, the thread returns at once. With one, it
            // fires, and the process ends during the join.
            let _ = worker.join();
        }
    }
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, Bound> {
        self.bound.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The thread: waits for a bound, and fires if one runs out.
    fn watch(&self, reason: &'static str, exit: Exit) {
        let mut bound = self.lock();
        loop {
            bound = match bound.deadline {
                Some(deadline) => {
                    let now = bound.now();
                    let Some(left) = deadline.checked_duration_since(now) else {
                        // Armed `after` before the deadline, which `now` is
                        // at or past.
                        let elapsed = bound.after + now.saturating_duration_since(deadline);
                        fire(reason, exit, Some((bound.after, elapsed)));
                    };
                    #[cfg(test)]
                    if let Some(clock) = &mut bound.clock {
                        clock.checked = true;
                    }
                    match self.wake.wait_timeout(bound, left) {
                        Ok((bound, _)) => bound,
                        Err(poisoned) => poisoned.into_inner().0,
                    }
                }
                None if bound.dropped => return,
                None => self.wake.wait(bound).unwrap_or_else(|p| p.into_inner()),
            };
        }
    }
}

/// Ends the process with `exit`, logging `reason` and, for a bound that ran
/// out, the bound and how long before it was armed.
fn fire(reason: &'static str, exit: Exit, ran_out: Option<(Duration, Duration)>) -> ! {
    crate::exit::exit_reporting(exit, crate::exit::REPORT_BOUND, || {
        let mut fields = serde_json::json!({ "reason": reason, "exit": exit.code() });
        if let (Some((bound, elapsed)), Some(map)) = (ran_out, fields.as_object_mut()) {
            map.insert("bound_ms".into(), millis(bound).into());
            map.insert("elapsed_ms".into(), millis(elapsed).into());
        }
        crate::log::error("a watchdog ends the process", fields);
    })
}

/// `duration` in whole milliseconds.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::mem::ManuallyDrop;
    use std::process::Command;
    use std::sync::atomic::Ordering;

    const CHILD: &str = "FC_SERVICE_WATCHDOG_CHILD";

    #[test]
    fn child() {
        let Ok(mode) = std::env::var(CHILD) else {
            return;
        };
        match mode.as_str() {
            "fire" => {
                let _armed = Watchdog::arm(
                    "teardown_unproven",
                    Duration::from_millis(100),
                    Exit::Internal,
                );
                std::thread::sleep(Duration::from_secs(10));
            }
            "disarm" => {
                // Disarmed, its thread ends, so nothing is left to fire. The
                // bound outlasts the run: no stall here can run it out first.
                let watchdog =
                    Watchdog::arm("teardown_unproven", Duration::from_secs(60), Exit::Internal);
                let thread = Arc::downgrade(&watchdog.disarmed);
                watchdog.disarm();
                wait_until("the disarmed watchdog's thread ended", || {
                    thread.strong_count() == 0
                });
            }
            "standing-fire" => {
                let standing = Standing::start("unit_overrun", Exit::Internal).unwrap();
                let _armed = standing.arm(Duration::from_millis(100));
                std::thread::sleep(Duration::from_secs(10));
            }
            "standing-disarm" => {
                // Each bound is short enough to fire within the run unless
                // it is stood down. The run is on a test's clock, so only
                // the test moves time on, never a stall of this thread. A
                // failed assertion's unwinding skips the drop, which would
                // wait for a bound that clock never runs out.
                let standing =
                    ManuallyDrop::new(Standing::start("unit_overrun", Exit::Internal).unwrap());
                standing.on_test_clock();
                let started = threads();
                assert_eq!(started.is_some(), cfg!(target_os = "linux"));
                for _ in 0..50 {
                    let armed = standing.arm(Duration::from_millis(200));
                    assert_eq!(threads(), started, "a bound starts no thread");
                    standing.disarm(armed);
                }
                // Arming again replaces the bound before: the first would
                // have run out by the end of the second advance.
                standing.arm(Duration::from_millis(300));
                standing.advance(Duration::from_millis(200));
                let second = standing.arm(Duration::from_millis(300));
                standing.advance(Duration::from_millis(200));
                standing.disarm(second);
                standing.advance(Duration::from_millis(400));
                assert_eq!(threads(), started, "one thread for every bound");
                // No bound is armed, so the drop returns at once.
                drop(ManuallyDrop::into_inner(standing));
            }
            "standing-replaced" => {
                // Standing down a bound that was replaced leaves the one
                // that replaced it.
                let standing = Standing::start("unit_overrun", Exit::Internal).unwrap();
                let first = standing.arm(Duration::from_secs(10));
                let _second = standing.arm(Duration::from_millis(100));
                standing.disarm(first);
                std::thread::sleep(Duration::from_secs(10));
            }
            "standing-dropped" => {
                // A bound still armed when the watchdog is dropped is kept,
                // and the drop doesn't return: the bound ends the process.
                let standing = Standing::start("unit_overrun", Exit::Internal).unwrap();
                standing.arm(Duration::from_millis(100));
                drop(standing);
                mark(DROP_RETURNED);
                std::thread::sleep(Duration::from_secs(10));
            }
            "standing-dropped-exiting" => {
                // This thread ends the process, so no drop waits on a bound.
                crate::exit::claim();
                // One that has fired, and parks for this thread's exit
                // holding the watchdog's lock: its claim is the second.
                let fired = Standing::start("unit_overrun", Exit::Internal).unwrap();
                fired.arm(Duration::from_millis(50));
                wait_until("the bound fired", || {
                    crate::exit::ATTEMPTS.load(Ordering::SeqCst) >= 2
                });
                drop(fired);
                mark("dropped fired");
                // One still armed, and one idle.
                let armed = Standing::start("unit_overrun", Exit::Internal).unwrap();
                armed.arm(Duration::from_secs(10));
                drop(armed);
                mark("dropped armed");
                drop(Standing::start("unit_overrun", Exit::Internal).unwrap());
                mark("dropped idle");
            }
            other => panic!("unknown mode {other}"),
        }
    }

    impl Standing {
        /// Puts it on a test's clock, at the system's time now.
        fn on_test_clock(&self) {
            self.shared.lock().clock = Some(Clock {
                now: Instant::now(),
                checked: false,
            });
        }

        /// Moves its clock on by `by`, and returns once the thread has
        /// checked the bound armed, if any, at the new time. A bound run
        /// out by then ends the process first.
        fn advance(&self, by: Duration) {
            let mut bound = self.shared.lock();
            let clock = bound.clock.as_mut().expect("on a test's clock");
            clock.now += by;
            clock.checked = false;
            drop(bound);
            self.shared.wake.notify_all();
            wait_until("the thread checked its bound", || {
                let bound = self.shared.lock();
                bound.deadline.is_none() || bound.clock.as_ref().is_some_and(|clock| clock.checked)
            });
        }
    }

    /// Waits until `done`, or panics past 5 s, naming `what`.
    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let until = Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(Instant::now() < until, "waited 5 s for: {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// What the child writes once `drop` has returned on an armed watchdog.
    const DROP_RETURNED: &str = "the drop returned";

    /// Writes `marker` to stderr, as its own line.
    fn mark(marker: &str) {
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "{marker}");
    }

    /// How many threads the process has; `None` where `/proc` doesn't list
    /// them (Linux does).
    fn threads() -> Option<usize> {
        Some(std::fs::read_dir("/proc/self/task").ok()?.count())
    }

    /// Runs the child in `mode`; its exit code (`None` for a signal) and
    /// stderr, or a panic past 10 s, which a hang would hit.
    fn run_child(mode: &str) -> (Option<i32>, String) {
        use std::io::Read;
        let within = Duration::from_secs(10);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "watchdog::tests::child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, mode)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut pipe = child.stderr.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut stderr = Vec::new();
            let _ = pipe.read_to_end(&mut stderr);
            stderr
        });
        let deadline = Instant::now() + within;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("the {mode} child did not exit within {within:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let stderr = String::from_utf8_lossy(&reader.join().unwrap()).into_owned();
        (status.code(), stderr)
    }

    /// The line a firing watchdog logged, parsed.
    fn fired(stderr: &str) -> serde_json::Value {
        stderr
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|line| line["msg"] == "a watchdog ends the process")
            .unwrap_or_else(|| panic!("no watchdog line: {stderr}"))
    }

    /// The line names the bound that ran out, and how long before it was
    /// armed: at least the bound.
    fn assert_ran_out(stderr: &str, reason: &str, bound_ms: u64) {
        let line = fired(stderr);
        assert_eq!(line["reason"], reason, "{stderr}");
        assert_eq!(line["exit"], 70, "{stderr}");
        assert_eq!(line["bound_ms"], bound_ms, "{stderr}");
        let elapsed = line["elapsed_ms"].as_u64().unwrap();
        assert!(elapsed >= bound_ms, "{stderr}");
    }

    #[test]
    fn an_armed_watchdog_ends_the_process_with_its_code() {
        let started = Instant::now();
        let (code, stderr) = run_child("fire");
        assert_eq!(code, Some(70), "{stderr}");
        assert_ran_out(&stderr, "teardown_unproven", 100);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_disarmed_watchdog_does_nothing() {
        let (code, stderr) = run_child("disarm");
        assert_eq!(code, Some(0), "{stderr}");
        assert!(!stderr.contains("watchdog ends"), "{stderr}");
    }

    #[test]
    fn a_standing_watchdog_fires_when_its_bound_runs_out() {
        for mode in ["standing-fire", "standing-replaced"] {
            let started = Instant::now();
            let (code, stderr) = run_child(mode);
            assert_eq!(code, Some(70), "{mode}: {stderr}");
            // The bound that replaced the 10 s one is the one named.
            assert_ran_out(&stderr, "unit_overrun", 100);
            assert!(started.elapsed() < Duration::from_secs(5), "{mode}");
        }
    }

    #[test]
    fn dropping_an_armed_standing_watchdog_waits_for_its_bound() {
        let started = Instant::now();
        let (code, stderr) = run_child("standing-dropped");
        assert_eq!(code, Some(70), "{stderr}");
        assert_ran_out(&stderr, "unit_overrun", 100);
        assert!(!stderr.contains(DROP_RETURNED), "{stderr}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_thread_ending_the_process_drops_a_standing_watchdog_at_once() {
        let started = Instant::now();
        let (code, stderr) = run_child("standing-dropped-exiting");
        assert_eq!(code, Some(0), "{stderr}");
        for marker in ["dropped fired", "dropped armed", "dropped idle"] {
            assert!(stderr.contains(marker), "{marker}: {stderr}");
        }
        // The bound that fired parked: this thread's exit ends the process.
        assert!(!stderr.contains("watchdog ends"), "{stderr}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_standing_watchdog_rearms_one_thread() {
        let (code, stderr) = run_child("standing-disarm");
        assert_eq!(code, Some(0), "{stderr}");
        assert!(!stderr.contains("watchdog ends"), "{stderr}");
    }

    #[test]
    fn an_idle_standing_watchdog_ends_its_thread_when_dropped() {
        let standing = Standing::start("dropped_idle", Exit::Internal).unwrap();
        let shared = Arc::downgrade(&standing.shared);
        standing.disarm(standing.arm(Duration::from_secs(10)));
        drop(standing);
        // The drop joined the thread, which held the last reference.
        assert_eq!(shared.strong_count(), 0, "the thread ended");
    }
}
