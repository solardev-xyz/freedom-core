//! The start steps both processes answer, in order (design 0008, "The
//! protocol"; design 0010, D5): `rad.hello`'s members, `rad.identity`
//! (0008, "Keys") and `rad.reconcile` ([`crate::reconcile`]). The serve
//! process then takes `rad.start` ([`crate::service`]); the import process
//! `rad.import_repo` ([`crate::import`]).
//!
//! **`rad.reconcile`** runs on a thread of its own, never the reader's. It
//! is admitted once, after `rad.identity`; a second is `invalid_argument`,
//! and ends the process. Its failure (`recovery_failed`) and its cutoff
//! (`deadline`) end the process after the reply, as a failed start step
//! does. `rad.shutdown`, or the connection's end, stops it after the unit
//! in progress.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::{Connection, Request};
use fc_service::watchdog::Watchdog;
use fc_service::{Exit, log};
use serde_json::{Map, Value, json};

use crate::build_info;
use crate::identity::{self, Identity};
use crate::{reconcile, testhooks, units};

/// How the process ends after a start step it answered with an error
/// (0008: "the service answers with the error and then exits"). Main read
/// the error; this isn't a crash.
pub const FAILED_START: Exit = Exit::Ok;

/// Where `rad.reconcile` stands.
pub enum Reconciliation {
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

/// What the start steps share.
pub struct Steps {
    /// The Radicle home, under the gate.
    pub home: PathBuf,
    pub identity: Identity,
    reconciliation: Arc<Mutex<Reconciliation>>,
    /// Stops reconciliation between units: set by the connection's end.
    stopping: Arc<AtomicBool>,
    /// `rad.hello`'s `network`: the policy, as it reports it.
    network: Value,
    /// `rad.hello`'s `confinement`: what `confine` reported (design 0010).
    confinement: Value,
    /// `rad.identity`'s deadline, armed by `rad.hello`'s reply.
    deadline: Mutex<Option<Watchdog>>,
    /// The repair units' watchdog, its thread started with the process.
    units: Arc<units::UnitWatch>,
    /// main's proof that libgit2 reads no git configuration outside a
    /// repository, for reconciliation.
    git_config: libradicle::GitConfigIsolated,
}

impl Steps {
    /// The steps for `home`, with the key for this start; `None` if the
    /// OS's randomness fails.
    pub fn new(
        home: PathBuf,
        network: Value,
        confinement: Value,
        units: Arc<units::UnitWatch>,
        git_config: libradicle::GitConfigIsolated,
    ) -> Option<Self> {
        let identity = Identity::new(&home)?;
        Some(Self {
            home,
            identity,
            reconciliation: Arc::new(Mutex::new(Reconciliation::Waiting)),
            stopping: Arc::new(AtomicBool::new(false)),
            network,
            confinement,
            deadline: Mutex::new(None),
            units,
            git_config,
        })
    }

    /// `rad.hello`'s members other than `protocol`; arms `rad.identity`'s
    /// deadline.
    pub fn hello(&self) -> Map<String, Value> {
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
            testhooks::identity_deadline(identity::DEADLINE),
            Exit::Protocol,
        );
        *self.deadline.lock().unwrap_or_else(|p| p.into_inner()) = Some(deadline);
        members
    }

    /// `rad.identity`: once; a failure ends the process after its reply.
    pub fn identity(&self, conn: &Connection, request: &Request<'_>) {
        match self
            .identity
            .establish(request.params.map(serde_json::value::RawValue::get))
        {
            Ok(result) => {
                self.disarm_deadline();
                let _ = conn.reply(request.id, &result);
            }
            Err(identity::Failure(error)) => fail_start(conn, request.id, &error),
        }
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

    /// How many repositories reconciliation re-signed, once it is done.
    pub fn reconciled(&self) -> Option<usize> {
        match &*self
            .reconciliation
            .lock()
            .unwrap_or_else(|p| p.into_inner())
        {
            Reconciliation::Done { resigned } => Some(resigned.len()),
            Reconciliation::Waiting | Reconciliation::Running => None,
        }
    }

    /// `rad.reconcile`: admitted once, after `rad.identity`, and run on a
    /// thread of its own.
    pub fn reconcile(&self, conn: &Connection, request: &Request<'_>) {
        let none = request.params.is_none_or(|raw| {
            serde_json::from_str::<Value>(raw.get())
                .is_ok_and(|value| value.is_null() || value.as_object().is_some_and(Map::is_empty))
        });
        if !none {
            return fail_start(
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
                return fail_start(
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
            // The caller checked that the identity is known.
            return fail_start(
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
                    cutoff: testhooks::reconcile_cutoff(reconcile::CUTOFF),
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
            fail_start(
                conn,
                id,
                &ErrorBody::new(ErrorCode::Internal, "Internal error"),
            );
        }
    }

    /// The connection ended: `rad.identity`'s deadline stands down, and
    /// reconciliation stops after the unit in progress.
    pub fn end(&self) {
        self.disarm_deadline();
        self.stopping.store(true, Ordering::Release);
    }
}

/// Answers `error`, then ends the process (0008: a failed start step).
pub fn fail_start(conn: &Connection, id: u64, error: &ErrorBody) {
    log::error(
        "a start step failed",
        json!({ "code": serde_json::to_value(error.code).unwrap_or(Value::Null) }),
    );
    let _ = conn.reply_error(id, error);
    conn.fail(FAILED_START);
}
