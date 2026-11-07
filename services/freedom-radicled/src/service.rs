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
//! - `rad.import_repo` answers `stopped`: only the import process serves
//!   it ([`crate::import`]).
//!
//! **`rad.hello`'s members, `rad.identity` and `rad.reconcile`** are the
//! steps both processes answer ([`crate::steps`]).
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

use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Instant;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::{Connection, End, Hello, Request, Service};
use fc_service::log;
use fc_service::network::NetworkPolicy;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::confine::Grant;
use crate::network::{self, progress};
use crate::node::{self, Node};
use crate::output::{self, Budget};
use crate::pools::{self, Mutates, Pool, Pools, Ticket, Work};
use crate::steps::Steps;
use crate::{quarantine, reads, repair, stats, writes};
use crate::{testhooks, units};

pub(crate) use crate::steps::fail_start;

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

/// `rad.start`'s params.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartParams {
    alias: String,
}

pub struct RadicleService {
    /// `rad.hello`, `rad.identity` and `rad.reconcile`, with the home and
    /// the identity. The repair units' watchdog is reconciliation's at a
    /// start, and the online repair's while the node runs.
    steps: Steps,
    /// The process's policy (`--network`), which the node runs under.
    policy: NetworkPolicy,
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
            steps: Steps::new(
                grant.home,
                network.to_json(),
                confinement,
                units,
                quarantined.clone(),
                git_config,
            )?,
            policy: *network,
            node,
            pools,
            budget: Budget::new(testhooks::budget(output::BUDGET)),
            progress,
            quarantined,
        })
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
            "rad.quarantine_list" => (
                quarantine::list(conn, &self.steps.home, request.params),
                None,
            ),
            "rad.remove_repo" => quarantine::remove(
                conn,
                &self.node,
                &self.steps.home,
                request.params,
                &self.quarantined,
            ),
            "rad.write" => {
                // Known by now: the pool admits nothing before `RUNNING`.
                let ephemeral = self.steps.identity.with(|i| i.ephemeral).unwrap_or(true);
                writes::write(
                    conn,
                    &self.node,
                    &self.steps.home,
                    request.params,
                    ephemeral,
                )
            }
            "rad.unseed" => writes::unseed(conn, &self.node, request.params),
            "rad.read" => (
                reads::read(
                    conn,
                    &self.node,
                    &self.pools,
                    &self.budget,
                    &self.steps.home,
                    request.params,
                ),
                None,
            ),
            _ => (later_step(conn), None),
        }
    }

    /// `rad.stats`'s snapshot: what the service holds now, each part read
    /// under a lock held only briefly ([`crate::stats`]).
    fn snapshot(&self) -> stats::Snapshot {
        stats::Snapshot {
            node: self.node.view(),
            unit: self
                .steps
                .units
                .current()
                .map(|(kind, elapsed)| stats::Unit {
                    kind,
                    elapsed,
                    limit: self.steps.units.limit(),
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
        let Some(resigned) = self.steps.reconciled() else {
            return invalid("rad.reconcile has not succeeded");
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
        let Some(key) = self.steps.identity.take_key() else {
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
                home: self.steps.home.clone(),
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

impl Service for RadicleService {
    fn hello(&self, _hello: &Hello) -> Result<Map<String, Value>, ErrorBody> {
        Ok(self.steps.hello())
    }

    fn request(&self, conn: &Connection, request: Request<'_>) {
        let method = request.method;
        if method == "rad.reconcile" && self.steps.identity.known() {
            self.steps.reconcile(conn, &request);
        } else if method == "rad.start" && self.steps.identity.known() {
            self.start(conn, &request);
        } else if method == "rad.stats" {
            stats::answer(conn, &request, || self.snapshot());
        } else if method == "rad.identity" {
            self.steps.identity(conn, &request);
        } else if NEED_IDENTITY.contains(&method) && !self.steps.identity.known() {
            fail_start(
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
                network::clone(
                    conn,
                    &self.node,
                    &self.progress,
                    &self.steps.home,
                    request.params,
                )
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
        // `rad.identity`'s deadline stands down, and reconciliation stops
        // after the unit in progress.
        self.steps.end();
        // The pools drain, then the node stops, within the connection's 5 s
        // exit. The clones' progress stops with the connection: nothing more
        // is written.
        self.node.stop(conn, &self.steps.home, end);
        self.progress.stop();
        log::info("connection ended", json!({ "end": end.name() }));
    }
}
