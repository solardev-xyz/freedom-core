//! The unit watchdog (design 0008, "The unit watchdog"): every repair unit
//! has a time limit, enforced from outside the worker.
//!
//! - **A unit that doesn't return can't be interrupted from inside the
//!   process.** So each unit, as it starts, arms the watchdog with its
//!   limit, 30 s ([`UNIT_LIMIT`]), and disarms it when it returns. One that
//!   fires ends the process with 70, logging `unit_overrun`: the worker, and
//!   every thread that could still mutate, ends with it.
//! - **One thread** ([`fc_service::watchdog::Standing`]) for the service's
//!   lifetime: a unit re-arms it, and starts no thread of its own. So no two
//!   units' watchdogs overlap, and a thread that can't be started fails the
//!   service's start, before any unit, not a unit.
//! - **The record survives.** The driver records each unit in progress
//!   before it starts, and the dirty marker stays, so the next start sees
//!   which unit overran, reruns it in its smallest form, and quarantines its
//!   repository after a second process ends during it.
//! - **What is running** is kept for `rad.stats` (a later step): the unit's
//!   kind, and how long it has run.
//!
//! The same watch is reconciliation's at a start, and the online repair's
//! while the node runs ([`crate::repair`]): the service holds it.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use fc_service::Exit;
use fc_service::watchdog::{Armed, Standing};
use radicle::storage::git::reconcile::driver::Watch;
use radicle::storage::git::reconcile::state::Unit;

/// A unit's time limit.
pub const UNIT_LIMIT: Duration = Duration::from_secs(30);

/// The fixed reason a firing watchdog logs, and its thread's name.
const OVERRUN: &str = "unit_overrun";

/// The unit running, and the bound it armed.
struct Running {
    kind: String,
    started: Instant,
    armed: Armed,
}

/// The watch the driver tells of each unit.
pub struct UnitWatch {
    limit: Duration,
    watchdog: Standing,
    running: Mutex<Option<Running>>,
}

impl UnitWatch {
    /// A watch that gives each unit `limit`, with its watchdog's thread
    /// started; an error if that thread can't be.
    pub fn start(limit: Duration) -> std::io::Result<Self> {
        Ok(Self {
            limit,
            watchdog: Standing::start(OVERRUN, Exit::Internal)?,
            running: Mutex::new(None),
        })
    }

    /// The unit running, by its kind, and how long it has run.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "rad.stats reads it, a later step")
    )]
    pub fn current(&self) -> Option<(String, Duration)> {
        self.lock()
            .as_ref()
            .map(|running| (running.kind.clone(), running.started.elapsed()))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Running>> {
        self.running.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Watch for UnitWatch {
    fn started(&self, unit: &Unit) {
        let mut running = self.lock();
        // A unit starts only after the one before it ended; if one hadn't,
        // this bound replaces its.
        *running = Some(Running {
            kind: unit.kind.clone(),
            started: Instant::now(),
            armed: self.watchdog.arm(self.limit),
        });
        drop(running);
        crate::testhooks::at_unit_start(&unit.kind);
    }

    fn ended(&self) {
        if let Some(running) = self.lock().take() {
            self.watchdog.disarm(running.armed);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn unit(kind: &str) -> Unit {
        Unit {
            rid: radicle::prelude::RepoId::from(radicle::git::Oid::from_sha1([1; 20])),
            kind: kind.to_owned(),
            position: String::new(),
        }
    }

    #[test]
    fn a_unit_that_returns_in_time_is_disarmed() {
        // A limit this short fires within the test unless disarmed.
        let watch = UnitWatch::start(Duration::from_millis(200)).unwrap();
        for kind in ["cache", "namespace", "publish"] {
            watch.started(&unit(kind));
            assert_eq!(watch.current().map(|(k, _)| k).as_deref(), Some(kind));
            watch.ended();
            assert!(watch.current().is_none());
        }
        std::thread::sleep(Duration::from_millis(400));
    }

    /// The kinds the units below cycle through.
    const KINDS: [&str; 4] = ["cache", "namespace", "resign", "publish"];

    const CHILD: &str = "FREEDOM_RADICLED_UNITS_CHILD";

    /// Runs this module's `child` test alone in a process of its own, as
    /// `mode`: its exit code and stderr.
    fn run_child(mode: &str) -> (Option<i32>, String) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "units::tests::child",
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

    /// The process's threads, by name; `None` where `/proc` doesn't list
    /// them (Linux does).
    fn threads() -> Option<Vec<String>> {
        let tasks = std::fs::read_dir("/proc/self/task").ok()?;
        let mut names: Vec<String> = tasks
            .filter_map(Result::ok)
            .filter_map(|task| std::fs::read_to_string(task.path().join("comm")).ok())
            .map(|comm| comm.trim_end().to_owned())
            .collect();
        names.sort();
        Some(names)
    }

    #[test]
    fn child() {
        let Ok(mode) = std::env::var(CHILD) else {
            return;
        };
        match mode.as_str() {
            "successive" => {
                let before = threads();
                let watch = UnitWatch::start(Duration::from_millis(200)).unwrap();
                // The watchdog's thread names itself as it starts.
                let named_by = Instant::now() + Duration::from_secs(5);
                let started = loop {
                    let started = threads();
                    let named = started
                        .as_ref()
                        .is_none_or(|names| names.iter().any(|name| name == OVERRUN));
                    if named || Instant::now() > named_by {
                        break started;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                assert_eq!(started.is_some(), cfg!(target_os = "linux"));
                if let (Some(before), Some(started)) = (&before, &started) {
                    // One thread more, the watchdog's.
                    assert_eq!(started.len(), before.len() + 1, "{started:?}");
                    let named = started.iter().filter(|name| *name == OVERRUN).count();
                    assert_eq!(named, 1, "{started:?}");
                }
                // Many units, as a repair with one per COB, or a namespace in
                // pages, runs: the one thread, re-armed, and no other.
                for kind in KINDS.iter().cycle().take(200) {
                    watch.started(&unit(kind));
                    assert_eq!(threads(), started, "{kind} started");
                    watch.ended();
                    assert_eq!(threads(), started, "{kind} ended");
                }
                // Past every unit's limit: each was stood down.
                std::thread::sleep(Duration::from_millis(400));
                assert_eq!(threads(), started);
            }
            "overrun" => {
                // A unit that doesn't end, after units that did.
                let watch = UnitWatch::start(Duration::from_millis(200)).unwrap();
                for kind in KINDS {
                    watch.started(&unit(kind));
                    watch.ended();
                }
                watch.started(&unit("cache"));
                std::thread::sleep(Duration::from_secs(10));
            }
            other => panic!("unknown mode {other}"),
        }
    }

    #[test]
    fn successive_units_rearm_one_watchdog_thread() {
        let (code, stderr) = run_child("successive");
        assert_eq!(code, Some(0), "{stderr}");
        assert!(!stderr.contains("watchdog ends"), "{stderr}");
    }

    #[test]
    fn the_rearmed_watchdog_still_ends_an_overrun() {
        let started = Instant::now();
        let (code, stderr) = run_child("overrun");
        assert_eq!(code, Some(70), "{stderr}");
        assert!(stderr.contains(r#""reason":"unit_overrun""#), "{stderr}");
        assert!(started.elapsed() < Duration::from_secs(5), "{stderr}");
    }
}
