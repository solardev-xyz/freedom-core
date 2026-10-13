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
            other => panic!("unknown mode {other}"),
        }
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
}
