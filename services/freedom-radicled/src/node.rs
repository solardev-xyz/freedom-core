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
//! **The stop** ([`Node::stop`], at the connection's end): the node is asked
//! to stop and waited for, for at most 3 s ([`SHUTDOWN_WITHIN`]), inside the
//! connection's 5 s exit. **The dirty marker is cleared only after a proven
//! clean stop** ("Reconciliation"): `rad.shutdown` ended the connection, the
//! node was running, not down, and `Embedded::shutdown_within` returned
//! `Ok`, so heartwood's workers have finished their fetches. This build has
//! no writes, so no write is queued, running or uncertain. Anything else
//! leaves the marker, and the next start runs the full repair.

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

use crate::{dial, identity, marker, nat64, testhooks};

/// `rad.start`'s bound (0008, "Bounds").
pub const START_DEADLINE: Duration = Duration::from_secs(30);

/// How long the stop waits for the node: inside the connection's 5 s exit,
/// with room for the marker's removal and the final replies.
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
}

impl Node {
    pub fn new() -> Self {
        Self {
            phase: Mutex::new(Phase::Waiting),
            changed: Condvar::new(),
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
        let _ = conn.reply(
            id,
            &json!({ "did": identity.did, "nid": identity.nid, "alias": identity.alias }),
        );
        testhooks::after_start(&mut running.embedded);
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
                    log::error("the node thread ended", json!({ "reason": "node_down" }));
                    // Nothing else is in flight in this build to answer.
                    conn.fail(Exit::Internal);
                    return;
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

    /// The connection ended with `end`: stops the node, if one runs, and
    /// clears the dirty marker in `home` after a proven clean stop (see the
    /// module's doc). Nothing starts after this.
    pub fn stop(&self, home: &Path, end: End) {
        let previous = std::mem::replace(&mut *self.lock(), Phase::Over);
        self.changed.notify_all();
        let (running, down) = match previous {
            Phase::Running(running) => (running, false),
            Phase::Down(running) => (running, true),
            Phase::Waiting | Phase::Starting | Phase::Over => return,
        };
        let Running {
            mut embedded,
            repositories,
            nat64,
        } = running;
        let stopped = embedded.shutdown_within(testhooks::shutdown_within(SHUTDOWN_WITHIN));
        drop(nat64);
        drop(repositories);
        match stopped {
            Ok(()) if !down && end == End::Shutdown => match marker::remove(home) {
                Ok(()) => log::info(
                    "the node stopped cleanly; the dirty marker is cleared",
                    json!({}),
                ),
                Err(e) => log::error(
                    "the node stopped cleanly, but the dirty marker wasn't cleared",
                    json!({ "error": e.to_string() }),
                ),
            },
            Ok(()) => log::info(
                "the node stopped; the dirty marker stays",
                json!({ "end": end.name(), "down": down }),
            ),
            Err(e) => log::error(
                "the node didn't stop cleanly; the dirty marker stays",
                json!({ "error": stop_error(&e) }),
            ),
        }
        // A node that didn't stop in time is waited for once more as it
        // drops, within the connection's 5 s exit.
        drop(embedded);
    }
}

/// A stop's failure, without its details: a node thread's error can name a
/// path.
fn stop_error(e: &libradicle::Error) -> &'static str {
    match e {
        libradicle::Error::ShutdownTimeout(_) => "it didn't stop in time",
        libradicle::Error::NodeThread(_) => "its thread ended with an error",
        _ => "its home wasn't let go of",
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
