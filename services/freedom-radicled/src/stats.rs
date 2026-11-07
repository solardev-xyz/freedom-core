//! `rad.stats` (design 0008, "Methods", "The unit watchdog" and "Main's
//! side": readiness), answered inline: on the reader thread, at once, with
//! no pool, so a full read pool or a repair on the writer never delays it.
//!
//! **It never waits.** Everything in it is what the service already holds
//! in memory, each behind a lock that is only held briefly: nothing in it
//! takes the node's lock, asks heartwood, or reads the disk.
//! - `node`, the node's phase ([`crate::node`]): `waiting` before
//!   `rad.start`, `starting`, `running`, `down` once its thread ended while
//!   it should run (the process is ending), and `stopped` once the start
//!   failed or the connection ended;
//! - `node_alive`: whether the node runs: `running`, and its thread still
//!   runs, as `Embedded::node_alive` says when no work holds the node
//!   exclusively (the lock is only tried; while it is held so, the node's
//!   watch hasn't found it down);
//! - `connected_peers`: the node's connected sessions, as the node's watch
//!   last counted them, once a second ([`crate::node`]): null until it has,
//!   after a count that failed, and whenever the node isn't `running`;
//! - `unit`: the repair unit in progress ([`crate::units::UnitWatch`]),
//!   reconciliation's or the online repair's, `{ kind, elapsed_ms,
//!   limit_ms }`, or null: so a healthy node thread isn't mistaken for a
//!   healthy repair;
//! - `quarantined_count`: the repositories the quarantine record holds, as
//!   the service last counted them where it changes the record
//!   ([`Quarantined`]): null before `rad.reconcile` has counted them;
//! - `pools`: each pool's requests running and queued, with its threads and
//!   its queue's places ([`crate::pools`]), and the write queue's online
//!   repairs queued;
//! - `budget.output`: the output budget's bytes reserved, and its total
//!   ([`crate::output`]);
//! - `network`: the process's mode, and in `direct` mode, while the node
//!   runs, NAT64 discovery's state, its prefixes and why its last round's
//!   resolvers failed (`nat64::Discovery::stats`), or null.
//!
//! **Bounded:** every list is cut, NAT64's prefixes to the 16 a state holds
//! ([`Nat64State::MAX_PREFIXES`]) and its failures to the first 16
//! ([`NAT64_FAILURES`]), whatever the OS lists; every other member is a
//! number, a fixed name or a unit's kind. So the result is at most 4 KiB,
//! one frame (the tests hold its largest to it). It reserves nothing from
//! the output budget: it reports it, and must answer while the budget is
//! full, as the reference's contract suite asks it with four 32 MiB bodies
//! held. The connection bounds how many replies wait for its writer.
//!
//! **Params:** none, null or `{}`; anything else is `invalid_argument`, and
//! the process goes on.

use std::sync::Mutex;
use std::time::Duration;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::{Connection, Request};
use freedom_ipfs_addr::Nat64State;
use radicle::storage::git::reconcile::quarantine::Quarantine;
use serde_json::{Map, Value, json};

use crate::pools::Usage;

/// The most NAT64 failures reported, the first of the last round's.
pub const NAT64_FAILURES: usize = 16;

/// The node's phase, as `rad.stats` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Waiting,
    Starting,
    Running,
    Down,
    Stopped,
}

impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Phase::Waiting => "waiting",
            Phase::Starting => "starting",
            Phase::Running => "running",
            Phase::Down => "down",
            Phase::Stopped => "stopped",
        }
    }
}

/// What the node gives `rad.stats` ([`crate::node::Node::view`]).
#[derive(Debug, Clone, PartialEq)]
pub struct NodeView {
    pub phase: Phase,
    /// Whether its thread still runs, if no one held it exclusively: `None`
    /// otherwise, and when no node runs.
    pub alive: Option<bool>,
    /// The watch's last count of its peers.
    pub peers: Option<usize>,
    /// NAT64 discovery's stats, while its lease is held (`direct` mode).
    pub nat64: Option<Value>,
}

/// The repair unit in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    pub kind: String,
    pub elapsed: Duration,
    pub limit: Duration,
}

/// Everything `rad.stats` reports, as the service holds it now.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub node: NodeView,
    pub unit: Option<Unit>,
    pub quarantined: Option<usize>,
    /// Each pool's use, by its name, in order.
    pub pools: [(&'static str, Usage); 3],
    /// The output budget: bytes reserved, and its total.
    pub output: (u64, u64),
    /// The process's network mode: `direct` or `socks5`.
    pub mode: &'static str,
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// `nat64`'s stats, every list cut to its bound.
fn bounded_nat64(mut nat64: Value) -> Value {
    for (list, bound) in [
        ("prefixes", Nat64State::MAX_PREFIXES),
        ("failures", NAT64_FAILURES),
    ] {
        if let Some(items) = nat64.get_mut(list).and_then(Value::as_array_mut) {
            items.truncate(bound);
        }
    }
    nat64
}

/// `rad.stats`'s result for `snapshot` (see the module's doc).
pub fn result(snapshot: &Snapshot) -> Value {
    let node = &snapshot.node;
    let running = node.phase == Phase::Running;
    let pools: Map<String, Value> = snapshot
        .pools
        .iter()
        .map(|(name, usage)| {
            let mut pool = json!({
                "running": usage.running,
                "queued": usage.queued,
                "threads": usage.shape.threads,
                "queue": usage.shape.queued,
            });
            if *name == "write" {
                pool["repairs"] = usage.repairs.into();
            }
            ((*name).to_owned(), pool)
        })
        .collect();
    let nat64 = match (&node.nat64, running) {
        (Some(nat64), true) => bounded_nat64(nat64.clone()),
        _ => Value::Null,
    };
    json!({
        "node": node.phase.name(),
        "node_alive": running && node.alive != Some(false),
        "connected_peers": if running { node.peers } else { None },
        "unit": snapshot.unit.as_ref().map(|unit| json!({
            "kind": unit.kind,
            "elapsed_ms": millis(unit.elapsed),
            "limit_ms": millis(unit.limit),
        })),
        "quarantined_count": snapshot.quarantined,
        "pools": pools,
        "budget": { "output": { "used": snapshot.output.0, "limit": snapshot.output.1 } },
        "network": { "mode": snapshot.mode, "nat64": nat64 },
    })
}

/// Whether `request`'s params are none: absent, null or `{}`.
fn no_params(request: &Request<'_>) -> bool {
    request.params.is_none_or(|raw| {
        serde_json::from_str::<Value>(raw.get())
            .is_ok_and(|value| value.is_null() || value.as_object().is_some_and(Map::is_empty))
    })
}

/// Answers `rad.stats` with `snapshot`'s result, taken only once its params
/// are checked.
pub fn answer(conn: &Connection, request: &Request<'_>, snapshot: impl FnOnce() -> Snapshot) {
    if !no_params(request) {
        let _ = conn.reply_error(
            request.id,
            &ErrorBody::new(ErrorCode::InvalidArgument, "rad.stats takes no params"),
        );
        return;
    }
    let _ = conn.reply(request.id, &result(&snapshot()));
}

/// The repositories the quarantine record holds, as the service last
/// counted them: from `rad.reconcile`'s report, and again from the record
/// itself wherever the service changes it, on the thread that changed it,
/// after an online repair quarantines a repository and after
/// `rad.remove_repo`'s removal ([`crate::repair`], [`crate::quarantine`]).
/// A count that fails leaves it unknown until the next.
#[derive(Debug, Default)]
pub struct Quarantined(Mutex<Option<usize>>);

impl Quarantined {
    pub fn get(&self) -> Option<usize> {
        *self.lock()
    }

    pub fn set(&self, count: Option<usize>) {
        *self.lock() = count;
    }

    /// Counts `record` again.
    pub fn recount(&self, record: &Quarantine) {
        self.set(record.count().ok());
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<usize>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
mod tests;
