//! The service's side of the connection (design 0008, "The protocol").
//!
//! **This build:** the start, in order: `rad.hello`, `rad.identity` (0008,
//! "Keys"), `rad.reconcile` ([`crate::reconcile`]) and `rad.start`
//! ([`crate::node`]), and the node's life until the connection ends. Every
//! other method 0008 lists comes with later steps:
//! - `rad.reconcile` and `rad.start` before `rad.identity` has succeeded:
//!   `no_identity`, and the process ends;
//! - **the pooled methods** go through their pool's admission, as 0008's
//!   table places them ([`crate::pools`]): `rad.quarantine_list`,
//!   `rad.read` and `rad.blob` on the read pool, `rad.remove_repo`,
//!   `rad.unseed` and `rad.write` on the write queue, each with its 60 s
//!   deadline from admission. Before `RUNNING` and from the stop on they
//!   are `stopped`, and past the pool's bounds `busy`. Quarantine's two,
//!   `rad.quarantine_list` and `rad.remove_repo`, are served
//!   ([`crate::quarantine`]), and so are the writes, `rad.write` and
//!   `rad.unseed`, with the mutation-start boundary ([`crate::writes`]),
//!   and a COB write's online repair on the writer when its outcome is
//!   unknown ([`crate::repair`]). `rad.read`'s pass-through ops are served
//!   within the process's output budget ([`crate::reads`],
//!   [`crate::output`]). `rad.blob` comes with a later step: until then its
//!   work answers `stopped`, as this build answered it before;
//! - **the network operations,** `rad.connect_seeds` and `rad.clone`, go
//!   through the network pool's admission, with the deadline from
//!   admission of the request's own `timeout_ms` plus 30 s, and are served
//!   ([`crate::network`]): a clone's progress goes to main as
//!   `rad.progress` events, bounded per clone, through the progress hub's
//!   thread ([`crate::network::progress`]);
//! - **`rad.stats`** is answered inline, on the reader thread, at once, in
//!   every phase from the handshake on: what the service holds in memory,
//!   never waiting ([`crate::stats`]);
//! - `rad.import_repo` (the import process's) comes with a later step, and
//!   answers `stopped`.
//!
//! **`rad.reconcile`** runs on a thread of its own, never the reader's. It
//! is admitted once, after `rad.identity`; a second is `invalid_argument`,
//! and ends the process. Its failure (`recovery_failed`) and its cutoff
//! (`deadline`) end the process after the reply, as a failed start step
//! does. `rad.shutdown`, or the connection's end, stops it after the unit
//! in progress.
//!
//! **`rad.start`** is admitted once, after `rad.reconcile` has succeeded,
//! with `{ alias }`, an alias heartwood takes. Anything else is
//! `invalid_argument`: before `rad.reconcile` has succeeded, a second
//! `rad.start`, or other params. Like every failed start step, it ends the
//! process after its reply.
//!
//! `rad.shutdown` is the connection's own ([`fc_service::conn`]): its end
//! stops the node ([`crate::node::Node::stop`]). A method 0008 doesn't list
//! is `unknown_method`.

use std::path::PathBuf;
use std::str::FromStr as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::{Connection, End, Hello, Request, Service};
use fc_service::network::NetworkPolicy;
use fc_service::watchdog::Watchdog;
use fc_service::{Exit, log};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::build_info;
use crate::confine::Grant;
use crate::identity::{self, Identity};
use crate::network::{self, progress};
use crate::node::{self, Node};
use crate::output::{self, Budget};
use crate::pools::{self, Mutates, Pool, Pools, Ticket, Work};
use crate::{quarantine, reads, reconcile, repair, stats, writes};
use crate::{testhooks, units};

/// How the process ends after a start step it answered with an error
/// (0008: "the service answers with the error and then exits"). Main read
/// the error; this isn't a crash.
const FAILED_START: Exit = Exit::Ok;

/// The methods 0008 lists beside `rad.hello`, `rad.identity` and
/// `rad.shutdown` that later steps implement, and that take no pool here.
const LATER: &[&str] = &["rad.import_repo"];

/// The methods on the network pool.
const NETWORK: &[&str] = &["rad.connect_seeds", "rad.clone"];

/// The methods on the read pool.
const READS: &[&str] = &["rad.quarantine_list", "rad.read", "rad.blob"];

/// The methods on the write queue.
const WRITES: &[&str] = &["rad.remove_repo", "rad.unseed", "rad.write"];

/// The methods that need the node's identity first.
const NEED_IDENTITY: &[&str] = &["rad.reconcile", "rad.start"];

/// Where `rad.reconcile` stands.
enum Reconciliation {
    /// Not asked for yet.
    Waiting,
    /// Running, or ended in a failure that ends the process.
    Running,
    /// Done: the home is consistent. The repositories whose own namespace
    /// was re-signed are announced once the node runs: heartwood's start
    /// queues a refs announcement for each ([`crate::node`]).
    Done {
        resigned: Vec<radicle::prelude::RepoId>,
    },
}

/// `rad.start`'s params.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartParams {
    alias: String,
}

pub struct RadicleService {
    /// The Radicle home, under the gate.
    home: PathBuf,
    identity: Identity,
    reconciliation: Arc<Mutex<Reconciliation>>,
    /// Stops reconciliation between units: set by the connection's end.
    stopping: Arc<AtomicBool>,
    /// The process's policy (`--network`), which the node runs under.
    policy: NetworkPolicy,
    /// `rad.hello`'s `network`: the policy, as it reports it.
    network: Value,
    /// `rad.hello`'s `confinement`: what `confine` reported (design 0010).
    confinement: Value,
    /// `rad.identity`'s deadline, armed by `rad.hello`'s reply.
    deadline: Mutex<Option<Watchdog>>,
    /// The repair units' watchdog, its thread started with the service:
    /// reconciliation's at a start, and the online repair's while the node
    /// runs.
    units: Arc<units::UnitWatch>,
    /// main's proof that libgit2 reads no git configuration outside a
    /// repository, for reconciliation.
    git_config: libradicle::GitConfigIsolated,
    /// The node, from `rad.start` until the connection ends.
    node: Arc<Node>,
    /// The read pool, the network pool and the write queue, which the node
    /// opens and drains.
    pools: Arc<Pools>,
    /// The output budget, the process's: every read's bytes (0008, "Pools
    /// and budgets").
    budget: Arc<Budget>,
    /// The clones' progress, written to main by its thread.
    progress: Arc<progress::Hub>,
    /// The quarantine record's count, for `rad.stats`.
    quarantined: Arc<stats::Quarantined>,
}

impl RadicleService {
    /// The service for `grant`'s home, with the key for this start, `units`
    /// the repair units' watch, `pools` its pools and `progress` the
    /// clones' progress hub, their threads started; `None` if the OS's
    /// randomness fails.
    pub fn new(
        grant: Grant,
        network: &fc_service::network::NetworkPolicy,
        confinement: Value,
        units: Arc<units::UnitWatch>,
        pools: Arc<Pools>,
        progress: Arc<progress::Hub>,
        git_config: libradicle::GitConfigIsolated,
    ) -> Option<Self> {
        let identity = Identity::new(&grant.home)?;
        let node = Arc::new(Node::new(pools.clone()));
        let quarantined = Arc::new(stats::Quarantined::default());
        // The writer's online repair reaches the node only while it runs.
        pools.repair_with(Arc::new(repair::Online::new(
            Arc::downgrade(&node),
            grant.home.clone(),
            units.clone(),
            quarantined.clone(),
        )));
        Some(Self {
            home: grant.home,
            identity,
            reconciliation: Arc::new(Mutex::new(Reconciliation::Waiting)),
            stopping: Arc::new(AtomicBool::new(false)),
            policy: *network,
            network: network.to_json(),
            confinement,
            deadline: Mutex::new(None),
            units,
            git_config,
            node,
            pools,
            budget: Budget::new(testhooks::budget(output::BUDGET)),
            progress,
            quarantined,
        })
    }

    fn disarm_deadline(&self) {
        if let Some(deadline) = self
            .deadline
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            deadline.disarm();
        }
    }

    /// The pool `method` runs on, with its deadline from admission.
    fn pool(&self, method: &str) -> Option<(&Pool<Connection>, std::time::Duration)> {
        if READS.contains(&method) {
            Some((self.pools.read(), pools::READ_DEADLINE))
        } else if WRITES.contains(&method) {
            Some((self.pools.write(), pools::WRITE_DEADLINE))
        } else {
            None
        }
    }

    /// The work of pooled `request`, and the repository it mutates, if it
    /// names one.
    fn work(&self, conn: &Connection, request: &Request<'_>) -> (Work, Option<Mutates>) {
        match request.method {
            "rad.quarantine_list" => (quarantine::list(conn, &self.home, request.params), None),
            "rad.remove_repo" => quarantine::remove(
                conn,
                &self.node,
                &self.home,
                request.params,
                &self.quarantined,
            ),
            "rad.write" => {
                // Known by now: the pool admits nothing before `RUNNING`.
                let ephemeral = self.identity.with(|i| i.ephemeral).unwrap_or(true);
                writes::write(conn, &self.node, &self.home, request.params, ephemeral)
            }
            "rad.unseed" => writes::unseed(conn, &self.node, request.params),
            "rad.read" => (
                reads::read(
                    conn,
                    &self.node,
                    &self.pools,
                    &self.budget,
                    &self.home,
                    request.params,
                ),
                None,
            ),
            _ => (later_step(conn), None),
        }
    }

    /// Answers `error`, then ends the process (0008: a failed start step).
    fn fail_start(&self, conn: &Connection, id: u64, error: &ErrorBody) {
        fail_start(conn, id, error);
    }

    /// `rad.reconcile`: admitted once, after `rad.identity`, and run on a
    /// thread of its own.
    fn reconcile(&self, conn: &Connection, request: &Request<'_>) {
        let none = request.params.is_none_or(|raw| {
            serde_json::from_str::<Value>(raw.get())
                .is_ok_and(|value| value.is_null() || value.as_object().is_some_and(Map::is_empty))
        });
        if !none {
            return self.fail_start(
                conn,
                request.id,
                &ErrorBody::new(ErrorCode::InvalidArgument, "rad.reconcile takes no params"),
            );
        }
        {
            let mut phase = self
                .reconciliation
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if !matches!(*phase, Reconciliation::Waiting) {
                drop(phase);
                return self.fail_start(
                    conn,
                    request.id,
                    &ErrorBody::new(
                        ErrorCode::InvalidArgument,
                        "rad.reconcile was already called",
                    ),
                );
            }
            *phase = Reconciliation::Running;
        }
        let admitted = Instant::now();
        let Some((own, signer)) = self.identity.with(|i| (i.id, i.signer())) else {
            // `request` checked that the identity is known.
            return self.fail_start(
                conn,
                request.id,
                &ErrorBody::new(ErrorCode::NoIdentity, "rad.identity has not succeeded"),
            );
        };
        let home = self.home.clone();
        let cancel = self.stopping.clone();
        let reconciliation = self.reconciliation.clone();
        let quarantined = self.quarantined.clone();
        let owed = conn.clone();
        let id = request.id;
        // Each unit's time limit, from outside the worker.
        let watch = self.units.clone();
        let git_config = self.git_config;
        let spawned = std::thread::Builder::new()
            .name("reconcile".into())
            .spawn(move || {
                let run = reconcile::Run {
                    home: &home,
                    own,
                    signer: signer.as_ref(),
                    admitted,
                    cutoff: crate::testhooks::reconcile_cutoff(reconcile::CUTOFF),
                    cancel,
                };
                // A panic here ends the process (70): a crash, which main
                // restarts, and whose next start reconciles again.
                let outcome = fc_service::panic::with_kind(
                    fc_service::panic::TaskKind::named("reconcile"),
                    || reconcile::run(&run, &*watch, git_config),
                );
                drop(signer);
                match outcome {
                    Ok(reconcile::Outcome::Done {
                        reply,
                        resigned,
                        quarantined: count,
                    }) => {
                        log::info(
                            "reconciled",
                            json!({
                                "was_dirty": reply["was_dirty"],
                                "repaired": reply["repaired"],
                                "quarantined": reply["quarantined"]["count"],
                            }),
                        );
                        quarantined.set(Some(count));
                        *reconciliation.lock().unwrap_or_else(|p| p.into_inner()) =
                            Reconciliation::Done { resigned };
                        let _ = owed.reply(id, &reply);
                    }
                    Ok(reconcile::Outcome::Deadline(error)) => fail_start(&owed, id, &error),
                    Ok(reconcile::Outcome::Cancelled(error)) => {
                        let _ = owed.reply_error(id, &error);
                    }
                    Err(reconcile::Failure(error)) => fail_start(&owed, id, &error),
                }
            });
        if spawned.is_err() {
            self.fail_start(
                conn,
                id,
                &ErrorBody::new(ErrorCode::Internal, "Internal error"),
            );
        }
    }

    /// `rad.stats`'s snapshot: what the service holds now, each part read
    /// under a lock held only briefly ([`crate::stats`]).
    fn snapshot(&self) -> stats::Snapshot {
        stats::Snapshot {
            node: self.node.view(),
            unit: self.units.current().map(|(kind, elapsed)| stats::Unit {
                kind,
                elapsed,
                limit: self.units.limit(),
            }),
            quarantined: self.quarantined.get(),
            pools: self.pools.usage(),
            output: (self.budget.used(), self.budget.total()),
            mode: match self.policy {
                NetworkPolicy::Direct => "direct",
                NetworkPolicy::Socks5 { .. } => "socks5",
            },
        }
    }

    /// `rad.start`: admitted once, after `rad.reconcile` has succeeded, and
    /// run on a thread of its own ([`crate::node`]).
    fn start(&self, conn: &Connection, request: &Request<'_>) {
        let invalid = |message: &str| {
            fail_start(
                conn,
                request.id,
                &ErrorBody::new(ErrorCode::InvalidArgument, message),
            );
        };
        let resigned = {
            let phase = self
                .reconciliation
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            match &*phase {
                Reconciliation::Done { resigned } => resigned.len(),
                Reconciliation::Waiting | Reconciliation::Running => {
                    drop(phase);
                    return invalid("rad.reconcile has not succeeded");
                }
            }
        };
        let Some(params) = request
            .params
            .and_then(|raw| serde_json::from_str::<StartParams>(raw.get()).ok())
        else {
            return invalid("rad.start takes { alias }");
        };
        if radicle::node::Alias::from_str(&params.alias).is_err() {
            return invalid("the alias isn't one Radicle takes");
        }
        if !self.node.admit() {
            return invalid("rad.start was already called");
        }
        // The start takes the key: the service keeps no copy of it.
        let Some(key) = self.identity.take_key() else {
            return fail_start(
                conn,
                request.id,
                &ErrorBody::new(ErrorCode::Internal, "Internal error"),
            );
        };
        log::info("starting the node", json!({ "resigned": resigned }));
        self.node.start(
            conn,
            request.id,
            node::Start {
                home: self.home.clone(),
                alias: params.alias,
                network: self.policy,
                key,
            },
        );
    }
}

/// The work of a pooled method whose operation comes with a later step: it
/// holds its slot as any work does, then answers `stopped`, as this build
/// answered it before.
fn later_step(conn: &Connection) -> Work {
    let conn = conn.clone();
    Box::new(move |ticket: &Ticket| {
        testhooks::hold_work(&ticket.cancel);
        let _ = conn.reply_error(
            ticket.id,
            &ErrorBody::new(ErrorCode::Stopped, "not served in this build"),
        );
    })
}

/// Answers `error`, then ends the process (0008: a failed start step).
pub(crate) fn fail_start(conn: &Connection, id: u64, error: &ErrorBody) {
    log::error(
        "a start step failed",
        json!({ "code": serde_json::to_value(error.code).unwrap_or(Value::Null) }),
    );
    let _ = conn.reply_error(id, error);
    conn.fail(FAILED_START);
}

impl Service for RadicleService {
    fn hello(&self, _hello: &Hello) -> Result<Map<String, Value>, ErrorBody> {
        let mut members = Map::new();
        members.insert("service_version".into(), env!("CARGO_PKG_VERSION").into());
        members.insert(
            "libradicle".into(),
            json!({
                "version": build_info::LIBRADICLE_VERSION,
                "git_commit": build_info::LIBRADICLE_COMMIT,
            }),
        );
        members.insert("recipient".into(), self.identity.recipient().into());
        members.insert("network".into(), self.network.clone());
        members.insert("confinement".into(), self.confinement.clone());
        // `rad.identity` within 30 s of this reply, or the process ends.
        let deadline = Watchdog::arm(
            "identity_deadline",
            crate::testhooks::identity_deadline(identity::DEADLINE),
            Exit::Protocol,
        );
        *self.deadline.lock().unwrap_or_else(|p| p.into_inner()) = Some(deadline);
        Ok(members)
    }

    fn request(&self, conn: &Connection, request: Request<'_>) {
        let method = request.method;
        if method == "rad.reconcile" && self.identity.known() {
            self.reconcile(conn, &request);
        } else if method == "rad.start" && self.identity.known() {
            self.start(conn, &request);
        } else if method == "rad.stats" {
            stats::answer(conn, &request, || self.snapshot());
        } else if method == "rad.identity" {
            match self
                .identity
                .establish(request.params.map(serde_json::value::RawValue::get))
            {
                Ok(result) => {
                    self.disarm_deadline();
                    let _ = conn.reply(request.id, &result);
                }
                Err(identity::Failure(error)) => self.fail_start(conn, request.id, &error),
            }
        } else if NEED_IDENTITY.contains(&method) && !self.identity.known() {
            self.fail_start(
                conn,
                request.id,
                &ErrorBody::new(ErrorCode::NoIdentity, "rad.identity has not succeeded"),
            );
        } else if let Some((pool, within)) = self.pool(method) {
            let deadline = Instant::now() + testhooks::work_deadline(within);
            let (work, mutates) = self.work(conn, &request);
            pool.submit_mutating(request.id, deadline, conn.clone(), work, mutates);
        } else if NETWORK.contains(&method) {
            let admitted = Instant::now();
            let (work, within) = if method == "rad.clone" {
                network::clone(conn, &self.node, &self.progress, &self.home, request.params)
            } else {
                network::connect_seeds(conn, &self.node, request.params)
            };
            self.pools.network().submit_mutating(
                request.id,
                admitted + within,
                conn.clone(),
                work,
                None,
            );
        } else if LATER.contains(&method) {
            let _ = conn.reply_error(
                request.id,
                &ErrorBody::new(ErrorCode::Stopped, "the Radicle node is not running"),
            );
        } else {
            let _ = conn.reply_error(
                request.id,
                &ErrorBody::new(ErrorCode::UnknownMethod, "unknown method"),
            );
        }
    }

    fn cancel(&self, _conn: &Connection, id: u64) {
        // A pool's request; the others are answered at once, or not
        // cancellable (`rad.reconcile`, `rad.start`).
        self.pools.cancel(id);
    }

    fn end(&self, conn: &Connection, end: End) {
        self.disarm_deadline();
        // Reconciliation stops after the unit in progress.
        self.stopping.store(true, Ordering::Release);
        // The pools drain, then the node stops, within the connection's 5 s
        // exit. The clones' progress stops with the connection: nothing more
        // is written.
        self.node.stop(conn, &self.home, end);
        self.progress.stop();
        log::info("connection ended", json!({ "end": end.name() }));
    }
}
