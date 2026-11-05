//! `rad.start` and the node's life (design 0008, "Start, stop and
//! reconciliation", "Crashes and restarts" and "Network policy").
//!
//! **`rad.start`** runs on a thread of its own, once, after `rad.reconcile`
//! has succeeded, and answers within 30 s ([`START_DEADLINE`]): past it,
//! `deadline`, and the process ends, as for any failed start step. In order:
//! 1. **the configured targets,** `config.json`'s `preferredSeeds` and
//!    `connect` peers, which the dial gate exempts by exact address. A home
//!    with no `config.json` yet has none: libradicle writes the defaults,
//!    whose seeds are public names. One that doesn't load fails the start in
//!    libradicle, with libradicle's message;
//! 2. **NAT64 discovery,** in `direct` mode, its lease held for the node's
//!    life, so that the gate learns the network's prefixes as freedom-ipfsd's
//!    does. In `socks5` mode the proxy's exit makes every connection, and the
//!    local network's prefixes don't apply;
//! 3. **the routing** ([`dial::routing`]): the service's dial gate, with the
//!    proxy and the onion route of `--network`;
//! 4. **the repository gate,** every repository in the quarantine record
//!    closed as quarantined, for its kind, before the node can fetch,
//!    announce or serve it ("The repository gate");
//! 5. **`keys/radicle` checked again** (0008, "The switch"): anything there
//!    is `key_file_present`;
//! 6. **`Embedded::start_with_key`,** with the key `rad.identity` delivered,
//!    which the start takes: the service keeps no copy of it. The node
//!    listens nowhere, has no control socket, and its default seeding policy
//!    is `block`, whatever `config.json` says ("Seeding and serving").
//!    libradicle's failure is `start_failed`, with its message.
//!
//! The reply is `{ did, nid, alias }`: the profile's alias, which the
//! `alias` param sets only on a home that has none yet.
//!
//! **Re-signed repositories are announced by the node itself:** heartwood's
//! start queues a refs announcement for each seeded repository whose signed
//! refs changed while the node was stopped, so those `rad.reconcile`
//! re-signed are among them.
//!
//! **The node's watch** ([`WATCH_INTERVAL`]): a thread asks
//! `Embedded::node_alive` once a second. A node thread that ends while the
//! node should run ends the process: `node_down`, exit 70, a crash, which
//! main restarts. heartwood's own panics are caught by nothing, so this is
//! how the service learns of them.
//!
//! **The pools open with the node** ([`crate::pools`]): just before
//! `rad.start`'s reply, so main's first request after it is admitted.
//!
//! **The stop** ([`Node::stop`], at the connection's end), within 3 s
//! ([`SHUTDOWN_WITHIN`]), inside the connection's 5 s exit:
//! 1. the pools are fenced and drained (0008: "the service fences new work,
//!    answers waiting requests `stopped`"): queued requests are answered
//!    `stopped`, running ones cancelled, and their threads waited for;
//! 2. the node is asked to stop, and waited for in the time left.
//!
//! **How the node ended is one decision,** whichever of the watch and the
//! stop comes first:
//! - **Both decide under the phase's lock.** The watch marks a node whose
//!   thread has ended `Down`; the stop takes the node out of the phase.
//! - **libradicle records who asked the node to stop.** Every stop call of
//!   its `Embedded` records its request, and `Embedded::shutdown_within`'s
//!   `Shutdown` says, from the same check that sends its own:
//!   `Asked::ThisCall` if it was the first to ask, while the node's thread
//!   ran; `Asked::Earlier` if a stop call had asked before; `Asked::Never`
//!   if the thread had ended before any asked. The service makes its stop
//!   calls only through [`Running::ask_stop`], and only where no other
//!   thread can reach the node: under the phase's lock, or once the stop
//!   has taken the node out of the phase. Dropping a node asks too, but
//!   only one the phase never held, or after the stop. So a stop that finds
//!   `Asked::ThisCall` is the first to ask the node, and the only one.
//! - **heartwood's run ends `Ok` only once it was asked to stop** (its
//!   `Runtime::run` at the pinned commit). Its reactor ends on its
//!   controller's `Shutdown`, on a fatal error of heartwood's service, which
//!   the run returns, or on a panic, which is an error too. libradicle asks
//!   through that controller only from its own stop calls. The node has no
//!   control socket, and libradicle sends its signal channel nothing.
//!
//! So a node that ended, or began to stop, behind the stop is `node_down`,
//! exit 70, with the marker kept, whichever thread finds it. The watch finds
//! a thread that has ended. The stop finds `Asked::Earlier` or
//! `Asked::Never`, or a thread that ended with an error
//! (`ThreadEnd::Failed`), which is how a node that ended by itself always
//! ends. libradicle reports the thread's end apart from the home, so a name
//! lookup that still holds the home past the deadline doesn't hide it.
//! - **Whoever finds the node down claims exit 70 itself.** The watch fails
//!   the connection only after it has published `Down` and let go of the
//!   lock, so a stop that takes a `Down` node fails it too: otherwise a
//!   watch held up between the two would let the stop's teardown end 0.
//!   `Connection::fail` is idempotent, and 70, once set, stays.
//!
//! **The dirty marker is cleared only after a proven clean stop**
//! ("Reconciliation"): `rad.shutdown` ended the connection; the pools'
//! drain was complete before the node's stop, so every pool thread ended,
//! no write is queued or running, and this build has no write that could
//! be uncertain; and the stop's `Shutdown` is `Asked::ThisCall`,
//! `ThreadEnd::Stopped` and `HomeLock::Released`, within the time the drain
//! left. So the node stopped because this stop asked it, it let go of its
//! home, and heartwood's workers have finished their fetches. A node down
//! behind the stop is `node_down` whatever the drain; otherwise an
//! incomplete drain leaves the stop unproven. Anything else leaves the
//! marker, and the next start runs the full repair.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::{Connection, End};
use fc_service::network::NetworkPolicy;
use fc_service::{Exit, log};
use freedom_ipfs_addr::Nat64State;
use radicle::node::config::{ConnectAddress, DefaultSeedingPolicy};
use radicle::node::gate::{self, RepoGate, RepoState};
use radicle::storage::git::reconcile::quarantine::{self, Quarantine};
use serde_json::json;

use crate::pools::Pools;
use crate::{dial, identity, marker, nat64, testhooks};

/// `rad.start`'s bound (0008, "Bounds").
pub const START_DEADLINE: Duration = Duration::from_secs(30);

/// How long the stop takes, the pools' drain and then the node's: inside
/// the connection's 5 s exit, with room for the marker's removal and the
/// final replies.
pub const SHUTDOWN_WITHIN: Duration = Duration::from_secs(3);

/// How often the node's watch asks whether the node thread runs.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(1);

/// The quarantine record's page, as the start reads it.
const PAGE: usize = 64;

/// A running node, and what runs with it.
struct Running {
    embedded: libradicle::Embedded,
    /// The host's half of the node's repository gate: the online repair and
    /// quarantine's removal (later steps) open and close repositories
    /// through it.
    repositories: RepoGate,
    /// NAT64 discovery, running while its lease is held: `direct` mode's,
    /// for the node's life (`rad.stats` reads it, a later step).
    nat64: Option<(nat64::Discovery, nat64::Lease)>,
}

impl Running {
    /// Asks the node to stop, and waits up to `within` for it
    /// (`Embedded::shutdown_within`): the one place the service asks.
    /// libradicle records the request, and the outcome says who asked
    /// first (see the module's doc).
    fn ask_stop(&mut self, within: Duration) -> libradicle::Shutdown {
        self.embedded.shutdown_within(within)
    }
}

/// Where the node stands.
enum Phase {
    /// No `rad.start` yet.
    Waiting,
    /// `rad.start` is running.
    Starting,
    /// The node runs.
    Running(Running),
    /// The node thread ended while the node should run: the process is
    /// ending (`node_down`).
    Down(Running),
    /// The start failed or passed its deadline, or the connection ended:
    /// nothing starts again in this process.
    Over,
}

/// What `rad.start` needs.
pub struct Start {
    pub home: PathBuf,
    pub alias: String,
    pub network: NetworkPolicy,
    pub key: libradicle::HostKey,
}

/// The node, from `rad.start` to the stop.
pub struct Node {
    phase: Mutex<Phase>,
    /// Notified when the phase changes: the start's deadline and the node's
    /// watch wait on it.
    changed: Condvar,
    /// The pools, opened as the node runs and drained before it stops.
    pools: Arc<Pools>,
}

impl Node {
    pub fn new(pools: Arc<Pools>) -> Self {
        Self {
            phase: Mutex::new(Phase::Waiting),
            changed: Condvar::new(),
            pools,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Phase> {
        self.phase.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Admits `rad.start`, once: `false` for a second.
    pub fn admit(&self) -> bool {
        let mut phase = self.lock();
        if !matches!(*phase, Phase::Waiting) {
            return false;
        }
        *phase = Phase::Starting;
        true
    }

    /// Runs the admitted start of request `id` on a thread of its own, and
    /// its deadline on another; whichever settles first answers.
    pub fn start(self: &Arc<Self>, conn: &Connection, id: u64, start: Start) {
        let deadline = Instant::now() + testhooks::start_deadline(START_DEADLINE);
        let timer = {
            let (node, conn) = (self.clone(), conn.clone());
            std::thread::Builder::new()
                .name("start-deadline".into())
                .spawn(move || node.expire(&conn, id, deadline))
        };
        let worker = timer.is_ok().then(|| {
            let (node, conn) = (self.clone(), conn.clone());
            std::thread::Builder::new()
                .name("start".into())
                .spawn(move || {
                    let outcome = fc_service::panic::with_kind(
                        fc_service::panic::TaskKind::named("start"),
                        || run(start),
                    );
                    match outcome {
                        Ok(running) => node.started(&conn, id, running),
                        Err(error) => node.failed(&conn, id, &error),
                    }
                })
        });
        if !matches!(worker, Some(Ok(_))) {
            self.failed(
                conn,
                id,
                &ErrorBody::new(ErrorCode::Internal, "Internal error"),
            );
        }
    }

    /// The start's deadline: `deadline` unless it settled first.
    fn expire(&self, conn: &Connection, id: u64, deadline: Instant) {
        let mut phase = self.lock();
        while matches!(*phase, Phase::Starting) {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                *phase = Phase::Over;
                drop(phase);
                self.changed.notify_all();
                return crate::service::fail_start(
                    conn,
                    id,
                    &ErrorBody::new(
                        ErrorCode::Deadline,
                        "the node didn't start within its deadline",
                    ),
                );
            };
            phase = match self.changed.wait_timeout(phase, left) {
                Ok((phase, _)) => phase,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    /// The start failed: its answer, then the process ends, unless the
    /// deadline answered first.
    fn failed(&self, conn: &Connection, id: u64, error: &ErrorBody) {
        {
            let mut phase = self.lock();
            if !matches!(*phase, Phase::Starting) {
                return;
            }
            *phase = Phase::Over;
        }
        self.changed.notify_all();
        crate::service::fail_start(conn, id, error);
    }

    /// The node runs: the reply, and its watch. Past the deadline, or once
    /// the connection has ended, it is stopped instead.
    fn started(self: &Arc<Self>, conn: &Connection, id: u64, mut running: Running) {
        let mut phase = self.lock();
        if !matches!(*phase, Phase::Starting) {
            drop(phase);
            // Dropping it stops the node; nothing was answered.
            drop(running);
            return;
        }
        let watch = {
            let (node, conn) = (self.clone(), conn.clone());
            std::thread::Builder::new()
                .name("node-watch".into())
                .spawn(move || node.watch(&conn))
        };
        if watch.is_err() {
            *phase = Phase::Over;
            drop(phase);
            self.changed.notify_all();
            drop(running);
            return crate::service::fail_start(
                conn,
                id,
                &ErrorBody::new(ErrorCode::Internal, "Internal error"),
            );
        }
        let identity = running.embedded.identity();
        log::info("the node runs", json!({ "nid": identity.nid }));
        // `RUNNING`: before the reply, so that main's next request is admitted.
        self.pools.open();
        let _ = conn.reply(
            id,
            &json!({ "did": identity.did, "nid": identity.nid, "alias": identity.alias }),
        );
        if testhooks::stop_node() {
            // No time to wait: the node is asked, and its thread ends after.
            let _ = running.ask_stop(Duration::ZERO);
        }
        *phase = Phase::Running(running);
        drop(phase);
        self.changed.notify_all();
    }

    /// The node's watch: ends the process if the node thread ends while
    /// the node should run.
    fn watch(&self, conn: &Connection) {
        let mut phase = self.lock();
        loop {
            match &*phase {
                Phase::Running(running) if running.embedded.node_alive() => {}
                Phase::Running(_) => {
                    if let Phase::Running(running) = std::mem::replace(&mut *phase, Phase::Over) {
                        *phase = Phase::Down(running);
                    }
                    drop(phase);
                    self.changed.notify_all();
                    // Between publishing `Down` and claiming the exit: a
                    // stop may take the node here (see the module's doc).
                    testhooks::at_node_down();
                    return node_down(conn);
                }
                // Still starting, or over.
                Phase::Waiting | Phase::Starting => {}
                Phase::Down(_) | Phase::Over => return,
            }
            phase = match self.changed.wait_timeout(phase, WATCH_INTERVAL) {
                Ok((phase, _)) => phase,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    /// The connection ended with `end`: drains the pools, stops the node,
    /// if one runs, and clears the dirty marker in `home` after a proven
    /// clean stop. A node that ended, or began to stop, behind it is
    /// `node_down` (see the module's doc). Nothing starts after this.
    pub fn stop(&self, conn: &Connection, home: &Path, end: End) {
        let deadline = Instant::now() + testhooks::shutdown_within(SHUTDOWN_WITHIN);
        let drained = self.pools.stop(deadline);
        if !drained {
            log::error("work was still running past the pools' drain", json!({}));
        }
        // The node is taken under the phase's lock, where the watch marks it
        // down: whichever comes first decides.
        let previous = std::mem::replace(&mut *self.lock(), Phase::Over);
        self.changed.notify_all();
        let (mut running, watched) = match previous {
            Phase::Running(running) => (running, false),
            // The watch found its thread ended. It may not have claimed the
            // exit yet: this stop claims it too, below.
            Phase::Down(running) => (running, true),
            Phase::Waiting | Phase::Starting | Phase::Over => return,
        };
        // Nothing else can reach the node now: the outcome says whether
        // this stop was the first to ask it. In the time the drain left, if
        // any: asked all the same.
        let stopped = running.ask_stop(deadline.saturating_duration_since(Instant::now()));
        let Running {
            embedded,
            repositories,
            nat64,
            ..
        } = running;
        drop(nat64);
        drop(repositories);
        match ending(watched, drained, &stopped, end) {
            Ending::Clean => match marker::remove(home) {
                Ok(()) => log::info(
                    "the node stopped cleanly; the dirty marker is cleared",
                    json!({}),
                ),
                Err(e) => log::error(
                    "the node stopped cleanly, but the dirty marker wasn't cleared",
                    json!({ "error": e.to_string() }),
                ),
            },
            Ending::Stopped => log::info(
                "the node stopped; the dirty marker stays",
                json!({ "end": end.name() }),
            ),
            // The watch logs `node_down`; the exit is claimed here as well,
            // whether or not the watch has claimed it yet.
            Ending::Down if watched => {
                log::info(
                    "the node was down; the dirty marker stays",
                    json!({ "end": end.name() }),
                );
                conn.fail(Exit::Internal);
            }
            Ending::Down => node_down(conn),
            Ending::Unproven(why) => log::error(
                "the node didn't stop cleanly; the dirty marker stays",
                json!({ "error": why }),
            ),
        }
        // A node that didn't stop in time is waited for once more as it
        // drops, within the connection's 5 s exit.
        drop(embedded);
    }
}

/// The node thread ended while the node should run, or the node began to
/// stop behind the service: the process ends with 70, a crash, and the
/// marker stays. Nothing else is in flight in this build to answer.
fn node_down(conn: &Connection) {
    log::error("the node thread ended", json!({ "reason": "node_down" }));
    conn.fail(Exit::Internal);
}

/// How a stop left the node.
#[derive(Debug, PartialEq, Eq)]
enum Ending {
    /// After a complete drain, `rad.shutdown`'s stop was the first to ask
    /// a running node, and it stopped and let go of its home in time: the
    /// marker is cleared.
    Clean,
    /// The same, but the connection ended otherwise: the marker stays.
    Stopped,
    /// The node ended, or began to stop, behind the stop, or its thread
    /// ended with an error: `node_down`.
    Down,
    /// Work was still running past the drain, or this stop asked the node
    /// but it didn't stop, or let go of its home, in time, or its home's
    /// lock failed, and why: the marker stays.
    Unproven(&'static str),
}

/// How the stop left the node, from `stopped`, its call's outcome;
/// `watched`: the watch found the node down first; and `drained`: the
/// pools' drain was complete. heartwood's run ends `Ok` only once it was
/// asked, so a node thread that ended by itself is `ThreadEnd::Failed`,
/// before this request or after it, as is one that panicked; libradicle
/// reports it whatever the home. A node down behind the stop is `Down`
/// whatever the drain; otherwise work still running leaves nothing proven.
fn ending(watched: bool, drained: bool, stopped: &libradicle::Shutdown, end: End) -> Ending {
    use libradicle::{Asked, HomeLock, ThreadEnd};
    match (stopped.asked, &stopped.thread, &stopped.home) {
        _ if watched => Ending::Down,
        // Whatever the home and whoever asked: a held home doesn't hide it.
        (_, ThreadEnd::Failed(_), _) => Ending::Down,
        (Asked::Earlier | Asked::Never, _, _) => Ending::Down,
        // Only after the `Down` arms: an incomplete drain hides no crash.
        _ if !drained => Ending::Unproven("work was still running"),
        (Asked::ThisCall, ThreadEnd::Running, _) => Ending::Unproven("it didn't stop in time"),
        (Asked::ThisCall, ThreadEnd::Stopped, HomeLock::Held) => {
            Ending::Unproven("it didn't let go of its home in time")
        }
        // Without the error: it can name a path.
        (Asked::ThisCall, ThreadEnd::Stopped, HomeLock::Unknown(_)) => {
            Ending::Unproven("its home's lock failed")
        }
        (Asked::ThisCall, ThreadEnd::Stopped, HomeLock::Released) if end == End::Shutdown => {
            Ending::Clean
        }
        (Asked::ThisCall, ThreadEnd::Stopped, HomeLock::Released) => Ending::Stopped,
    }
}

fn start_failed(message: impl Into<String>) -> ErrorBody {
    ErrorBody::new(ErrorCode::StartFailed, message)
}

/// The start itself, steps 1 to 6 of the module's doc.
fn run(start: Start) -> Result<Running, ErrorBody> {
    let Start {
        home,
        alias,
        network,
        key,
    } = start;
    let configured = configured(&home);
    let (state, nat64) = match network {
        NetworkPolicy::Direct => {
            let discovery = nat64::Discovery::new(
                testhooks::nat64_source().unwrap_or_else(nat64::Discovery::os_source),
                nat64::Timing::DESIGN,
            );
            let lease = discovery.lease();
            (discovery.state(), Some((discovery, lease)))
        }
        NetworkPolicy::Socks5 { .. } => (dial::Nat64::fixed(Nat64State::NONE), None),
    };
    let routing = dial::routing(&network, &configured, state)
        .map_err(|e| ErrorBody::new(ErrorCode::Internal, e.to_string()))?;
    let routing = testhooks::routing(routing);
    let repositories = repository_gate(&home)?;
    if identity::key_file_present(&home) {
        return Err(ErrorBody::new(
            ErrorCode::KeyFilePresent,
            "keys/radicle exists",
        ));
    }
    let embedded = libradicle::Embedded::start_with_key(
        libradicle::Options {
            home,
            alias,
            listen: vec![],
            control_socket: false,
            routing: Some(routing),
            seeding_policy: Some(DefaultSeedingPolicy::Block),
            isolated: false,
            repositories: Some(repositories.clone()),
        },
        key,
    )
    .map_err(|e| start_failed(e.to_string()))?;
    Ok(Running {
        embedded,
        repositories,
        nat64,
    })
}

/// `config.json`'s configured targets: its `preferredSeeds` and its
/// `connect` peers. None when it doesn't load: see the module's doc.
fn configured(home: &Path) -> Vec<ConnectAddress> {
    match radicle::profile::Config::load(&home.join("config.json")) {
        Ok(config) => config
            .preferred_seeds
            .into_iter()
            .chain(config.node.connect)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// The node's repository gate, with every quarantined repository closed
/// for its kind.
fn repository_gate(home: &Path) -> Result<RepoGate, ErrorBody> {
    let path = home.join("node").join(quarantine::QUARANTINE_DB_FILE);
    let record = Quarantine::open(&path).map_err(|e| {
        start_failed(format!(
            "the quarantine record: {}",
            crate::reconcile::record_error(&e)
        ))
    })?;
    let repositories = RepoGate::new();
    for page in 0.. {
        let records = record.page(page, PAGE).map_err(|e| {
            start_failed(format!(
                "the quarantine record: {}",
                crate::reconcile::record_error(&e)
            ))
        })?;
        for entry in &records {
            let kind = match entry.kind {
                quarantine::Kind::Cache => gate::Quarantine::Cache,
                quarantine::Kind::Namespace => gate::Quarantine::Namespace,
            };
            // No node runs yet, so no pass is held, and the close is
            // immediate; either way the repository stays closed.
            let _ = repositories.close(entry.rid, RepoState::Quarantined(kind), Duration::ZERO);
        }
        if records.len() < PAGE {
            break;
        }
    }
    Ok(repositories)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use radicle::storage::git::reconcile::quarantine::Kind;

    fn rid(byte: u8) -> radicle::prelude::RepoId {
        radicle::prelude::RepoId::from(radicle::git::Oid::from_sha1([byte; 20]))
    }

    #[test]
    fn the_gate_closes_every_quarantined_repository_for_its_kind() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("node")).unwrap();
        let path = home
            .path()
            .join("node")
            .join(quarantine::QUARANTINE_DB_FILE);
        let mut record = Quarantine::open(&path).unwrap();
        // More than a page, so that every page is read.
        for byte in 0..(PAGE as u8 + 3) {
            let kind = if byte % 2 == 0 {
                Kind::Cache
            } else {
                Kind::Namespace
            };
            record
                // Any time: the gate reads the kind alone.
                .quarantine(rid(byte), kind, "cache", None, "", Default::default())
                .unwrap();
        }
        drop(record);
        let gate = repository_gate(home.path()).unwrap();
        for byte in 0..(PAGE as u8 + 3) {
            let kind = if byte % 2 == 0 {
                gate::Quarantine::Cache
            } else {
                gate::Quarantine::Namespace
            };
            assert_eq!(gate.state(&rid(byte)), RepoState::Quarantined(kind));
        }
        assert!(gate.state(&rid(200)).is_open());
    }

    /// A stop clears the marker only for a node it alone asked, stopped and
    /// let go of its home in time, at `rad.shutdown`, after a complete
    /// drain. A node found down, asked before, ended before any asked, or
    /// whose thread failed is `node_down`, whatever its home, the stop's end
    /// and the drain; any other stop after an incomplete drain is unproven.
    /// Every `Asked` x `ThreadEnd` x `HomeLock` x end row is checked with
    /// both drain states, watched and not.
    #[test]
    fn only_the_stop_that_alone_asked_a_live_node_after_a_drain_is_clean() {
        use libradicle::{Asked, HomeLock, Shutdown, ThreadEnd};
        let stop = |asked, thread, home| Shutdown {
            asked,
            thread,
            home,
            within: Duration::ZERO,
        };
        let failed = || ThreadEnd::Failed("ended".into());
        let unknown = || HomeLock::Unknown(std::io::Error::other("lock"));
        let homes = || [HomeLock::Released, HomeLock::Held, unknown()];
        let threads = || [ThreadEnd::Running, ThreadEnd::Stopped, failed()];
        let ends = [End::Shutdown, End::Eof];
        let running = "work was still running";

        let clean = || stop(Asked::ThisCall, ThreadEnd::Stopped, HomeLock::Released);
        assert_eq!(ending(false, true, &clean(), End::Shutdown), Ending::Clean);
        assert_eq!(ending(false, true, &clean(), End::Eof), Ending::Stopped);
        for end in ends {
            // Work still running past the drain: nothing is proven.
            assert_eq!(
                ending(false, false, &clean(), end),
                Ending::Unproven(running)
            );
            for home in homes() {
                let late = stop(Asked::ThisCall, ThreadEnd::Running, home);
                assert_eq!(
                    ending(false, true, &late, end),
                    Ending::Unproven("it didn't stop in time")
                );
                assert_eq!(ending(false, false, &late, end), Ending::Unproven(running));
            }
            let held = stop(Asked::ThisCall, ThreadEnd::Stopped, HomeLock::Held);
            assert_eq!(
                ending(false, true, &held, end),
                Ending::Unproven("it didn't let go of its home in time")
            );
            assert_eq!(ending(false, false, &held, end), Ending::Unproven(running));
            let lock = stop(Asked::ThisCall, ThreadEnd::Stopped, unknown());
            assert_eq!(
                ending(false, true, &lock, end),
                Ending::Unproven("its home's lock failed")
            );
            assert_eq!(ending(false, false, &lock, end), Ending::Unproven(running));
            // A thread that failed while a name lookup held the home past
            // the deadline, after this stop asked or before any did, whether
            // or not the drain was complete.
            for asked in [Asked::ThisCall, Asked::Never] {
                for drained in [true, false] {
                    assert_eq!(
                        ending(false, drained, &stop(asked, failed(), HomeLock::Held), end),
                        Ending::Down,
                        "{asked:?} drained {drained}"
                    );
                }
            }
        }
        // Every row, both drain states, watched and not: a failed thread,
        // a node another stop asked or none did, and every node the watch
        // found down, are `Down` before the drain counts; the rest above.
        let mut rows = 0;
        for asked in [Asked::ThisCall, Asked::Earlier, Asked::Never] {
            for thread in threads() {
                let behind = asked != Asked::ThisCall || matches!(thread, ThreadEnd::Failed(_));
                for home in homes() {
                    let stopped = stop(asked, thread.clone(), home);
                    for end in ends {
                        for drained in [true, false] {
                            if behind {
                                assert_eq!(
                                    ending(false, drained, &stopped, end),
                                    Ending::Down,
                                    "{stopped:?} drained {drained}"
                                );
                            } else if !drained {
                                assert_eq!(
                                    ending(false, drained, &stopped, end),
                                    Ending::Unproven(running),
                                    "{stopped:?}"
                                );
                            } else {
                                assert!(
                                    !matches!(ending(false, drained, &stopped, end), Ending::Down),
                                    "{stopped:?}"
                                );
                            }
                            assert_eq!(
                                ending(true, drained, &stopped, end),
                                Ending::Down,
                                "{stopped:?} drained {drained}"
                            );
                            rows += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(rows, 3 * 3 * 3 * 2 * 2);
    }

    #[test]
    fn configured_targets_are_config_jsons_seeds_and_peers() {
        let home = tempfile::tempdir().unwrap();
        assert!(configured(home.path()).is_empty(), "no config.json yet");
        std::fs::write(
            home.path().join("config.json"),
            r#"{"preferredSeeds":["z6MkrLMMsiPWUcNPHcRajuMi9mDfYckSoJyPwwnknocNYPm7@seed.lan:8776"],"node":{"alias":"x","connect":["z6Mkmqogy2qEM2ummccUthFEaaHvyYmYBYh3dbe9W4ebScxo@192.168.1.2:8776"]}}"#,
        )
        .unwrap();
        let hosts: Vec<String> = configured(home.path())
            .iter()
            .map(|c| c.addr.to_string())
            .collect();
        assert_eq!(hosts, ["seed.lan:8776", "192.168.1.2:8776"]);
    }
}
