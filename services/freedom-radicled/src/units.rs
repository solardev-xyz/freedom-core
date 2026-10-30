//! The unit watchdog (design 0008, "The unit watchdog"): every repair unit
//! has a time limit, enforced from outside the worker.
//!
//! - **A unit that doesn't return can't be interrupted from inside the
//!   process.** So each unit, as it starts, arms a watchdog thread
//!   ([`fc_service::watchdog::Watchdog`]) with its limit, 30 s
//!   ([`UNIT_LIMIT`]), and disarms it when it returns. One that fires ends
//!   the process with 70, logging `unit_overrun`: the worker, and every
//!   thread that could still mutate, ends with it.
//! - **The record survives.** The driver records each unit in progress
//!   before it starts, and the dirty marker stays, so the next start sees
//!   which unit overran, reruns it in its smallest form, and quarantines its
//!   repository after a second process ends during it.
//! - **What is running** is kept for `rad.stats` (a later step): the unit's
//!   kind, and how long it has run.
//!
//! The watchdog is reconciliation's at a start, and the online repair's
//! while the node runs (a later step).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use fc_service::Exit;
use fc_service::watchdog::Watchdog;
use radicle::storage::git::reconcile::driver::Watch;
use radicle::storage::git::reconcile::state::Unit;

/// A unit's time limit.
pub const UNIT_LIMIT: Duration = Duration::from_secs(30);

/// The unit running, and its watchdog.
struct Running {
    kind: String,
    started: Instant,
    watchdog: Watchdog,
}

/// The watch the driver tells of each unit.
pub struct UnitWatch {
    limit: Duration,
    running: Mutex<Option<Running>>,
}

impl UnitWatch {
    /// A watch that gives each unit `limit`.
    pub fn new(limit: Duration) -> Self {
        Self {
            limit,
            running: Mutex::new(None),
        }
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
        let watchdog = Watchdog::arm("unit_overrun", self.limit, Exit::Internal);
        let previous = self.lock().replace(Running {
            kind: unit.kind.clone(),
            started: Instant::now(),
            watchdog,
        });
        // A unit starts only after the one before it ended.
        if let Some(previous) = previous {
            previous.watchdog.disarm();
        }
        crate::testhooks::at_unit_start(&unit.kind);
    }

    fn ended(&self) {
        if let Some(running) = self.lock().take() {
            running.watchdog.disarm();
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
        let watch = UnitWatch::new(Duration::from_millis(200));
        for kind in ["cache", "namespace", "publish"] {
            watch.started(&unit(kind));
            assert_eq!(watch.current().map(|(k, _)| k).as_deref(), Some(kind));
            watch.ended();
            assert!(watch.current().is_none());
        }
        std::thread::sleep(Duration::from_millis(400));
    }
}
