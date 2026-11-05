//! The service's side of the connection (design 0008, "The protocol").
//!
//! **This build:** the start, in order: `rad.hello`, `rad.identity` (0008,
//! "Keys"), `rad.reconcile` ([`crate::reconcile`]) and `rad.start`
//! ([`crate::node`]), and the node's life until the connection ends. Every
//! other method 0008 lists comes with later steps, and answers `stopped`, as
//! before `RUNNING`:
//! - `rad.reconcile` and `rad.start` before `rad.identity` has succeeded:
//!   `no_identity`, and the process ends;
//! - otherwise `stopped`.
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
use crate::node::{self, Node};
use crate::reconcile;
use crate::units;

/// How the process ends after a start step it answered with an error
/// (0008: "the service answers with the error and then exits"). Main read
/// the error; this isn't a crash.
const FAILED_START: Exit = Exit::Ok;

/// The methods 0008 lists beside `rad.hello`, `rad.identity` and
/// `rad.shutdown`, which later steps implement.
const LATER: &[&str] = &[
    "rad.quarantine_list",
    "rad.remove_repo",
    "rad.stats",
    "rad.read",
    "rad.blob",
    "rad.connect_seeds",
    "rad.clone",
    "rad.unseed",
    "rad.write",
    "rad.import_repo",
];

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
    /// reconciliation's at a start, and the online repair's (a later step).
    units: Arc<units::UnitWatch>,
    /// main's proof that libgit2 reads no git configuration outside a
    /// repository, for reconciliation.
    git_config: libradicle::GitConfigIsolated,
    /// The node, from `rad.start` until the connection ends.
    node: Arc<Node>,
}

impl RadicleService {
    /// The service for `grant`'s home, with the key for this start, and
    /// `units` the repair units' watch; `None` if the OS's randomness fails.
    pub fn new(
        grant: Grant,
        network: &fc_service::network::NetworkPolicy,
        confinement: Value,
        units: Arc<units::UnitWatch>,
        git_config: libradicle::GitConfigIsolated,
    ) -> Option<Self> {
        let identity = Identity::new(&grant.home)?;
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
            node: Arc::new(Node::new()),
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
                    Ok(reconcile::Outcome::Done { reply, resigned }) => {
                        log::info(
                            "reconciled",
                            json!({
                                "was_dirty": reply["was_dirty"],
                                "repaired": reply["repaired"],
                                "quarantined": reply["quarantined"]["count"],
                            }),
                        );
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

    fn cancel(&self, _conn: &Connection, _id: u64) {
        // Every request is answered at once: nothing runs to cancel.
    }

    fn end(&self, _conn: &Connection, end: End) {
        self.disarm_deadline();
        // Reconciliation stops after the unit in progress.
        self.stopping.store(true, Ordering::Release);
        // The node stops, within the connection's 5 s exit.
        self.node.stop(&self.home, end);
        log::info("connection ended", json!({ "end": end.name() }));
    }
}
