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
//! under a bound armed before it is written.

use std::sync::{Arc, Condvar, Mutex};
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
        let deadline = Instant::now() + after;
        let spawned = std::thread::Builder::new()
            .name("watchdog".into())
            .spawn(move || {
                let (flag, wake) = &*state;
                let mut flag = flag.lock().unwrap_or_else(|p| p.into_inner());
                while !*flag {
                    let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                        let (reason, exit) = decide();
                        fire(reason, exit);
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
            fire("watchdog_unavailable", Exit::Internal);
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
/// Dropping it ends its thread once no bound is armed: a bound still armed
/// is kept, and fires.
pub struct Standing {
    shared: Arc<Shared>,
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
    /// The `Standing` is gone: no bound can be armed again.
    dropped: bool,
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
                dropped: false,
            }),
            wake: Condvar::new(),
        });
        let state = shared.clone();
        std::thread::Builder::new()
            .name(reason.into())
            .spawn(move || state.watch(reason, exit))?;
        Ok(Standing { shared })
    }

    /// Arms it to end the process `after` from now, replacing the bound
    /// armed before, if any.
    pub fn arm(&self, after: Duration) -> Armed {
        let deadline = Instant::now() + after;
        let mut bound = self.shared.lock();
        bound.generation += 1;
        bound.deadline = Some(deadline);
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

impl Drop for Standing {
    fn drop(&mut self) {
        self.shared.lock().dropped = true;
        self.shared.wake.notify_all();
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
                    let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                        fire(reason, exit);
                    };
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

fn fire(reason: &'static str, exit: Exit) -> ! {
    crate::exit::exit_reporting(exit, crate::exit::REPORT_BOUND, || {
        crate::log::error(
            "a watchdog ends the process",
            serde_json::json!({ "reason": reason, "exit": exit.code() }),
        );
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::process::Command;

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
                Watchdog::arm(
                    "teardown_unproven",
                    Duration::from_millis(200),
                    Exit::Internal,
                )
                .disarm();
                std::thread::sleep(Duration::from_millis(400));
            }
            "standing-fire" => {
                let standing = Standing::start("unit_overrun", Exit::Internal).unwrap();
                let _armed = standing.arm(Duration::from_millis(100));
                std::thread::sleep(Duration::from_secs(10));
            }
            "standing-disarm" => {
                // Each bound is short enough to fire within the run unless
                // it is stood down.
                let standing = Standing::start("unit_overrun", Exit::Internal).unwrap();
                let started = threads();
                assert_eq!(started.is_some(), cfg!(target_os = "linux"));
                for _ in 0..50 {
                    let armed = standing.arm(Duration::from_millis(200));
                    assert_eq!(threads(), started, "a bound starts no thread");
                    standing.disarm(armed);
                }
                // Arming again replaces the bound before: the first would
                // have run out by the end of the second sleep.
                standing.arm(Duration::from_millis(300));
                std::thread::sleep(Duration::from_millis(200));
                let second = standing.arm(Duration::from_millis(300));
                std::thread::sleep(Duration::from_millis(200));
                standing.disarm(second);
                std::thread::sleep(Duration::from_millis(400));
                assert_eq!(threads(), started, "one thread for every bound");
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
                // A bound still armed when the watchdog is dropped is kept.
                let standing = Standing::start("unit_overrun", Exit::Internal).unwrap();
                standing.arm(Duration::from_millis(100));
                drop(standing);
                std::thread::sleep(Duration::from_secs(10));
            }
            other => panic!("unknown mode {other}"),
        }
    }

    /// How many threads the process has; `None` where `/proc` doesn't list
    /// them (Linux does).
    fn threads() -> Option<usize> {
        Some(std::fs::read_dir("/proc/self/task").ok()?.count())
    }

    fn run_child(mode: &str) -> (Option<i32>, String) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "watchdog::tests::child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, mode)
            .output()
            .unwrap();
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    #[test]
    fn an_armed_watchdog_ends_the_process_with_its_code() {
        let started = Instant::now();
        let (code, stderr) = run_child("fire");
        assert_eq!(code, Some(70), "{stderr}");
        assert!(
            stderr.contains(r#""reason":"teardown_unproven""#),
            "{stderr}"
        );
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
        for mode in ["standing-fire", "standing-replaced", "standing-dropped"] {
            let started = Instant::now();
            let (code, stderr) = run_child(mode);
            assert_eq!(code, Some(70), "{mode}: {stderr}");
            assert!(
                stderr.contains(r#""reason":"unit_overrun""#),
                "{mode}: {stderr}"
            );
            assert!(started.elapsed() < Duration::from_secs(5), "{mode}");
        }
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
        // The thread held the last reference.
        let started = Instant::now();
        while shared.strong_count() > 0 {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the thread ended"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
