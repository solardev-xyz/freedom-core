//! The online repair (design 0008, "Writes": "Online repair after an
//! uncertain write"; "The unit watchdog", "The escape" and "The repository
//! gate"): libradicle's `Embedded::repair_step`, heartwood's
//! `Repair::online` signed with the key the node runs as, one unit a turn on
//! the writer ([`crate::pools`]), under the service's [`UnitWatch`].
//!
//! **Queued as the write's call returns** ([`Online::queued`]): a COB write
//! past its mutation start whose outcome is unknown has its repository's
//! repair queued, and the repository's gate is set to `repairing` at once,
//! without waiting. From then until the repair is over, the node defers
//! its fetches and refs announcements of it, and the writes to it wait
//! behind the repair in the write queue.
//!
//! **Each turn** ([`Online::turn`]):
//! 1. **the node,** through its lock ([`crate::node::Handle`]), only while
//!    it runs: otherwise the stop has it, or it is down, and the repair is
//!    abandoned;
//! 2. **the repair begins** on its first turn: its progress in
//!    `cobs/cache.db` and the quarantine record in `node/reconcile.db`, as
//!    reconciliation keeps them, and libradicle's `online_repair` (its own
//!    namespace, then its COB cache);
//! 3. **its repository closes:** the gate's close returns once every
//!    mutation of the node's admitted before it has ended, so nothing
//!    mutates the repository underneath its repair. A turn waits up to
//!    [`CLOSE_WAIT`] for that, and gives the writer back if it hasn't;
//! 4. **one unit,** with the node held shared, as reads hold it: the
//!    watchdog arms each unit's 30 s, and an overrun ends the process (70),
//!    the unit's record kept. No unit starts once the stop has fenced the
//!    writer.
//!
//! **How it ends:**
//! - **done:** the namespace is checked, and re-signed if it was stale, and
//!   the cache published, which deletes the repository's progress. The gate
//!   opens it, and the node runs what it deferred;
//! - **quarantined:** a unit failed with an error, or was in progress when
//!   two processes ended. heartwood has recorded the quarantine durably, in
//!   the step; the gate closes it for its kind before the writer's next
//!   task, so writes to it are `quarantined`;
//! - **stopped** by the stop's fence: its progress and the dirty marker
//!   stay, for the next start;
//! - **failed outside its repository** (the progress state, the quarantine
//!   record, the storage, the host's environment), which quarantines
//!   nothing: it is logged, naming the step, and the repository stays
//!   `repairing` until the next start, whose reconciliation repairs it. The
//!   writes to it no longer wait, and are `stopped`.
//!
//! Repaired or quarantined, the write's repository is certain again: a
//! clean stop may clear the dirty marker ([`crate::node`]). Stopped or
//! failed, the run stays uncertain, and the marker stays.
//!
//! **Logs** carry repository IDs and steps, never a path or a ref.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use fc_service::log;
use radicle::node::gate::{self, RepoGate, RepoState};
use radicle::prelude::RepoId;
use radicle::storage::git::reconcile::driver::{Progress, Repair, Stop};
use radicle::storage::git::reconcile::quarantine::{self, Quarantine};
use radicle::storage::git::reconcile::state::State;
use serde_json::json;

use crate::node::{Handle, Node};
use crate::pools::{Repairer, Turn};
use crate::testhooks;
use crate::units::UnitWatch;

/// How long a turn waits for its repository to close, before it gives the
/// writer back.
pub const CLOSE_WAIT: Duration = Duration::from_millis(100);

/// A repair in progress: the writer's alone.
struct Active {
    repair: Repair,
    state: State,
    record: Quarantine,
    /// Whether its repository's close has returned.
    closed: bool,
}

/// The online repair of the service's node.
pub struct Online {
    node: Weak<Node>,
    home: PathBuf,
    watch: Arc<UnitWatch>,
    active: Mutex<HashMap<RepoId, Active>>,
}

impl Online {
    /// The repair of `node`'s repositories, in the home at `home`, its
    /// units told to `watch`.
    pub fn new(node: Weak<Node>, home: PathBuf, watch: Arc<UnitWatch>) -> Self {
        Self {
            node,
            home,
            watch,
            active: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<RepoId, Active>> {
        self.active.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The node, while it runs.
    fn handle(&self) -> Option<Handle> {
        self.node.upgrade()?.handle()
    }

    /// Step 2 of the module's doc: `rid`'s repair, its progress and its
    /// record; what failed otherwise, never a path.
    fn begin(&self, rid: RepoId, handle: &Handle) -> Result<Active, String> {
        let state = State::open(
            self.home
                .join("cobs")
                .join(radicle::cob::cache::COBS_DB_FILE),
        )
        .map_err(|e| format!("the reconcile state: {}", crate::reconcile::state_error(&e)))?;
        let record = Quarantine::open(self.home.join("node").join(quarantine::QUARANTINE_DB_FILE))
            .map_err(|e| {
                format!(
                    "the quarantine record: {}",
                    crate::reconcile::record_error(&e)
                )
            })?;
        let repair = handle.node().online_repair(rid);
        Ok(Active {
            repair,
            state,
            record,
            closed: false,
        })
    }
}

/// Whether `rid` is closed for its repair (step 3 of the module's doc):
/// once `gate`'s close has returned, recorded in `closed`, no mutation of
/// the node's admitted before it still runs. Waits up to [`CLOSE_WAIT`].
fn closed(gate: &RepoGate, rid: RepoId, closed: &mut bool) -> bool {
    if !*closed {
        *closed = gate.close(rid, RepoState::Repairing, CLOSE_WAIT).is_ok();
    }
    *closed
}

/// A failure outside the repository, as the log names it: its step, never
/// a path.
fn described(e: &libradicle::Error) -> String {
    match e {
        libradicle::Error::Reconcile(e) => crate::reconcile::failure(e).0.message,
        // The node's own key signs, so none other is expected.
        _ => "libradicle refused the repair".to_owned(),
    }
}

/// Logs that `rid`'s repair failed outside its repository, `why`.
fn failed(rid: RepoId, why: &str) {
    log::error(
        "an online repair failed outside its repository; it stays closed until the next start, and the dirty marker stays",
        json!({ "rid": rid.to_string(), "error": why }),
    );
}

impl Repairer for Online {
    fn queued(&self, rid: RepoId) {
        let Some(handle) = self.handle() else {
            return;
        };
        // One the gate holds quarantined stays so: its first turn ends it.
        if handle.repositories.state(&rid).is_open() {
            // Never waits: its first turn waits for the node's work on it.
            let _ = handle
                .repositories
                .close(rid, RepoState::Repairing, Duration::ZERO);
        }
        log::info(
            "an online repair is queued: a write's outcome is unknown",
            json!({ "rid": rid.to_string() }),
        );
    }

    fn turn(&self, rid: RepoId, stop: &Arc<AtomicBool>) -> Turn {
        let mut active = self.lock();
        let Some(handle) = self.handle() else {
            active.remove(&rid);
            log::info(
                "an online repair stopped: the node isn't running; the dirty marker stays",
                json!({ "rid": rid.to_string() }),
            );
            return Turn::Abandoned;
        };
        if let RepoState::Quarantined(_) = handle.repositories.state(&rid) {
            active.remove(&rid);
            return Turn::Over;
        }
        let entry = match active.entry(rid) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(vacant) => match self.begin(rid, &handle) {
                Ok(begun) => vacant.insert(begun),
                Err(why) => {
                    failed(rid, &why);
                    return Turn::Abandoned;
                }
            },
        };
        if !closed(&handle.repositories, rid, &mut entry.closed) {
            return Turn::More;
        }
        let node = handle.node();
        testhooks::hold_repair_turn();
        let stop = Stop {
            cancel: stop.clone(),
            cutoff: None,
        };
        let stepped = node.repair_step(
            &mut entry.repair,
            &mut entry.state,
            &mut entry.record,
            &stop,
            &*self.watch,
        );
        drop(node);
        let did = entry.repair.did().clone();
        match stepped {
            Ok(Progress::More) => return Turn::More,
            Ok(Progress::Done) => {
                handle.repositories.open(rid);
                log::info(
                    "an online repair is done; its repository is open",
                    json!({
                        "rid": rid.to_string(),
                        "namespaces": did.namespaces,
                        "resigned": did.resigned,
                        "cache": did.cache,
                    }),
                );
            }
            Ok(Progress::Quarantined(record)) => {
                let kind = match record.kind {
                    quarantine::Kind::Cache => gate::Quarantine::Cache,
                    quarantine::Kind::Namespace => gate::Quarantine::Namespace,
                };
                // Closed for good: the passes its kind refuses aren't waited
                // for, and it stays closed either way.
                let _ =
                    handle
                        .repositories
                        .close(rid, RepoState::Quarantined(kind), Duration::ZERO);
                log::error(
                    "an online repair quarantined its repository",
                    json!({
                        "rid": rid.to_string(),
                        "kind": record.kind.as_str(),
                        "step": record.step,
                    }),
                );
            }
            Ok(Progress::Stopped(_)) => {
                active.remove(&rid);
                log::info(
                    "an online repair stopped between units; the dirty marker stays",
                    json!({ "rid": rid.to_string() }),
                );
                return Turn::Abandoned;
            }
            Err(e) => {
                active.remove(&rid);
                failed(rid, &described(&e));
                return Turn::Abandoned;
            }
        }
        active.remove(&rid);
        Turn::Over
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn rid(byte: u8) -> RepoId {
        RepoId::from(radicle::git::Oid::from_sha1([byte; 20]))
    }

    /// A repair begins only once the node's mutations of its repository
    /// admitted before the close have ended, and doesn't close it again
    /// after.
    #[test]
    fn a_repair_waits_for_the_nodes_mutations_of_its_repository() {
        let (gate, repaired, other) = (RepoGate::new(), rid(1), rid(2));
        let fetch = gate.enter(repaired).unwrap();
        let _elsewhere = gate.enter(other).unwrap();
        let mut done = false;
        let asked = std::time::Instant::now();
        assert!(!closed(&gate, repaired, &mut done));
        assert!(asked.elapsed() >= CLOSE_WAIT);
        assert!(!done);
        // Closed, though: nothing new is admitted.
        assert_eq!(gate.state(&repaired), RepoState::Repairing);
        assert!(gate.enter(repaired).is_none());
        drop(fetch);
        assert!(closed(&gate, repaired, &mut done));
        assert!(done);
        // Not closed again: a turn after it doesn't wait.
        gate.open(repaired);
        assert!(closed(&gate, repaired, &mut done));
        assert_eq!(gate.state(&repaired), RepoState::Open);
        // Serving it and listing it in the inventory go on while it is
        // repaired; an announcement under way is waited for, as a fetch is.
        let mut again = false;
        let _serving = gate.admit(repaired, gate::Purpose::Serve).unwrap();
        let _listing = gate.admit(repaired, gate::Purpose::Inventory).unwrap();
        let announcing = gate.admit(repaired, gate::Purpose::Announce).unwrap();
        assert!(!closed(&gate, repaired, &mut again));
        drop(announcing);
        assert!(closed(&gate, repaired, &mut again));
    }

    /// A failure outside the repository is named by its step, never a path.
    #[test]
    fn a_failure_outside_the_repository_names_its_step() {
        use radicle::storage::git::reconcile::driver::Error;
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "/home/alice/storage");
        let named = described(&libradicle::Error::Reconcile(Box::new(Error::Io(io))));
        assert!(named.starts_with("the storage: "), "{named}");
        assert!(!named.contains("alice"), "{named}");
        let named = described(&libradicle::Error::Reconcile(Box::new(Error::NotBegun)));
        assert!(named.starts_with("a repair: "), "{named}");
    }
}
