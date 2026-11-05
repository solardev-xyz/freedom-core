//! `rad.reconcile` (design 0008, "Reconciliation"): heartwood's procedure
//! (`radicle::storage::git::reconcile::driver::run`, heartwood item 13),
//! run before the node, with the home's gate held, and the dirty marker
//! around it.
//!
//! **In order:**
//! 1. **The marker** ([`marker`]) is read: whether it was present selects
//!    the full repair, and the identities it names are the namespaces
//!    checked in every repository. A marker that doesn't read is
//!    `recovery_failed`, with nothing touched.
//! 2. **It is written durably** before anything changes, naming the running
//!    identity too, so that every mutation of this run happens while it is
//!    present. A throwaway key isn't named: it owns no namespace and signs
//!    nothing (0008, "Profiles without a vault"), so a check of it would
//!    find nothing.
//! 3. **The repair runs** on the storage (`storage/`), with its progress in
//!    `cobs/cache.db` and the quarantine record in `node/reconcile.db`.
//!    Only the running identity's key signs, and only its own namespace; a
//!    throwaway key signs nothing. No unit starts after the cutoff, 240 s
//!    from admission ([`CUTOFF`]), and none after `rad.shutdown`.
//! 4. **Its ending:**
//!    - **done:** the marker is rewritten durably to name only the running
//!      identity, and the reply gives the counts and the first quarantined
//!      repositories;
//!    - **the cutoff:** `deadline`, with the marker and the progress kept,
//!      for a retry in a new process to continue;
//!    - **`rad.shutdown`:** `stopped`, with the same kept;
//!    - **a failure outside any one repository:** `recovery_failed`, its
//!      message naming the step, and nothing deleted.
//!
//! **Messages and logs** carry counts, repository IDs and the kind of an
//! I/O error, never a path.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use radicle::git::UserInfo;
use radicle::prelude::{NodeId, RepoId};
use radicle::storage::git::Storage;
use radicle::storage::git::reconcile::driver::{self, Context, Ending, Report, Stop, Watch};
use radicle::storage::git::reconcile::quarantine::{self, Quarantine, Record};
use radicle::storage::git::reconcile::state::State;
use serde_json::{Value, json};

use crate::marker::{self, Names};

/// No unit starts after this, from `rad.reconcile`'s admission: it leaves
/// the unit already running and a cut off batch's commit, 30 s each, before
/// the reply's 300 s (0008, "The deadline").
pub const CUTOFF: Duration = Duration::from_secs(240);

/// The alias the storage is opened with. Reconciliation makes no
/// repository and no commit, so it names no one.
const ALIAS: &str = "freedom-radicled";

/// What a run needs.
pub struct Run<'a> {
    /// The Radicle home: its gate is held.
    pub home: &'a Path,
    /// The running identity.
    pub own: NodeId,
    /// Its key, unless it is a throwaway one.
    pub signer: Option<&'a radicle::crypto::SigningKey>,
    /// When `rad.reconcile` was admitted.
    pub admitted: Instant,
    /// How long after admission units may start.
    pub cutoff: Duration,
    /// Set by `rad.shutdown`.
    pub cancel: Arc<AtomicBool>,
}

/// How a run ended, short of a failure.
#[derive(Debug)]
pub enum Outcome {
    /// Every repair is done, or its repository quarantined: the reply, and
    /// the repositories whose own namespace was re-signed, to be announced
    /// once the node runs.
    Done { reply: Value, resigned: Vec<RepoId> },
    /// The cutoff passed: `deadline`.
    Deadline(ErrorBody),
    /// `rad.shutdown` came: `stopped`.
    Cancelled(ErrorBody),
}

/// A failure outside any one repository: `recovery_failed`.
#[derive(Debug)]
pub struct Failure(pub ErrorBody);

fn failed(step: &str, what: impl std::fmt::Display) -> Failure {
    Failure(ErrorBody::new(
        ErrorCode::RecoveryFailed,
        format!("{step}: {what}"),
    ))
}

/// The home's paths, as heartwood lays them out.
struct Paths {
    storage: PathBuf,
    cobs: PathBuf,
    node: PathBuf,
    progress: PathBuf,
    record: PathBuf,
}

impl Paths {
    fn of(home: &Path) -> Self {
        let cobs = home.join("cobs");
        let node = home.join("node");
        Self {
            storage: home.join("storage"),
            progress: cobs.join(radicle::cob::cache::COBS_DB_FILE),
            cobs,
            record: node.join(quarantine::QUARANTINE_DB_FILE),
            node,
        }
    }
}

/// Runs the reconciliation of `run.home`, telling `watch` of each unit.
///
/// Only after `libradicle::isolate_git_config`, which `_git_config` proves.
/// Otherwise libgit2 would look for the system's git configuration with
/// every repository it opens, and confinement leaves an `/etc/gitconfig`
/// unreadable: every open would fail, and every repository would be
/// quarantined at its unit's `begin`.
pub fn run(
    run: &Run<'_>,
    watch: &dyn Watch,
    _git_config: libradicle::GitConfigIsolated,
) -> Result<Outcome, Failure> {
    let found = marker::read(run.home).map_err(|e| failed("the dirty marker", e))?;
    // Named only for an identity that can sign: see the module's doc.
    let named = match (run.signer, found.clone().unwrap_or_default()) {
        (Some(_), names) => names.with(run.own),
        (None, names) => names,
    };
    marker::write(run.home, &named).map_err(|e| failed("the dirty marker", e))?;

    let paths = Paths::of(run.home);
    for dir in [&paths.cobs, &paths.node] {
        std::fs::create_dir_all(dir).map_err(|e| failed("the home's directories", e.kind()))?;
    }
    let info = UserInfo {
        alias: radicle::node::Alias::new(ALIAS),
        key: run.own,
    };
    let storage =
        Storage::open(&paths.storage, info).map_err(|e| failed("the storage", kind_of(&e)))?;
    let mut state =
        State::open(&paths.progress).map_err(|e| failed("the reconcile state", state_error(&e)))?;
    let mut quarantine = Quarantine::open(&paths.record)
        .map_err(|e| failed("the quarantine record", record_error(&e)))?;
    let stop = Stop {
        cancel: run.cancel.clone(),
        cutoff: run.admitted.checked_add(run.cutoff),
    };
    let dirty = found.as_ref().map(Names::node_ids);
    let mut cx = Context {
        storage: &storage,
        state: &mut state,
        quarantine: &mut quarantine,
        signer: run.signer,
        stop: &stop,
        watch,
    };
    let report = driver::run(&mut cx, dirty.as_ref()).map_err(|e| failure(&e))?;
    match report.ending {
        Ending::Done => {
            // Every earlier identity is checked, or its repositories
            // quarantined: the marker names the running identity alone.
            let now = match run.signer {
                Some(_) => Names::of([run.own]),
                None => Names::default(),
            };
            marker::write(run.home, &now).map_err(|e| failed("the dirty marker", e))?;
            Ok(Outcome::Done {
                reply: reply(&report),
                resigned: report.resigned.clone(),
            })
        }
        Ending::Deadline => Ok(Outcome::Deadline(ErrorBody::new(
            ErrorCode::Deadline,
            "reconciliation reached its cutoff; a retry continues from its checkpoints",
        ))),
        Ending::Cancelled => Ok(Outcome::Cancelled(ErrorBody::new(
            ErrorCode::Stopped,
            "the service is shutting down",
        ))),
    }
}

/// A failure's message: its step, never a path.
fn failure(e: &driver::Error) -> Failure {
    match e {
        driver::Error::Io(e) => failed("the storage", e.kind()),
        driver::Error::State(e) => failed("the reconcile state", state_error(e)),
        driver::Error::Quarantine(e) => failed("the quarantine record", record_error(e)),
        driver::Error::Fsync(e) => failed("libgit2's fsync", e),
        driver::Error::Clone { .. } => failed("a temporary clone", "it wasn't removed"),
        // Only a temporary clone's unit fails the run so: any other unit
        // quarantines its repository instead.
        driver::Error::Poison { .. } => failed(
            "a temporary clone",
            "its removal was in progress when two processes ended",
        ),
        driver::Error::NotBegun => failed("a repair", "a step ran before it began"),
        // Every repository would fail alike, so none is quarantined
        // (heartwood#27). libgit2's message can name a path: its class
        // alone.
        driver::Error::Host(e) => failed(
            "the host's environment",
            format_args!(
                "libgit2 refused it ({:?}): its configuration outside any repository, or a repository's ownership",
                e.class()
            ),
        ),
    }
}

/// The kind of a storage error's I/O, or that it wasn't I/O.
fn kind_of(e: &radicle::storage::Error) -> String {
    match e {
        radicle::storage::Error::Io(e) => e.kind().to_string(),
        _ => "it doesn't open".to_owned(),
    }
}

/// What went wrong with the progress state, without its details: libgit2's
/// and SQLite's messages can name a path, and a ref name is inside a
/// repository.
fn state_error(e: &radicle::storage::git::reconcile::state::Error) -> String {
    use radicle::storage::git::reconcile::state::Error;
    match e {
        Error::Sql(_) => "its database doesn't open or answer".to_owned(),
        Error::Git(_) => "a repository's refs don't read".to_owned(),
        Error::Invalid(_) => "it holds what it can't have written".to_owned(),
        Error::Undecodable(_) => "a symbolic ref's target isn't UTF-8".to_owned(),
        Error::Interrupted(n) => format!("{n} units were started and never completed"),
    }
}

/// What went wrong with the quarantine record, without its details.
pub(crate) fn record_error(e: &quarantine::Error) -> String {
    match e {
        quarantine::Error::Sql(_) => "its database doesn't open or answer".to_owned(),
        quarantine::Error::Invalid(_) => "it holds what it can't have written".to_owned(),
        quarantine::Error::Random(_) => "the OS's random generator failed".to_owned(),
        quarantine::Error::Collision(_) => "a new record's ID is another record's".to_owned(),
    }
}

/// `rad.reconcile`'s reply: `{ was_dirty, repaired, quarantined: { count,
/// first } }`.
fn reply(report: &Report) -> Value {
    json!({
        "was_dirty": report.dirty,
        "repaired": {
            "clones": report.clones,
            "left": report.left,
            "locks": report.locks,
            "namespaces": report.namespaces,
            "resigned": report.resigned.len(),
            "caches": report.caches,
            "quarantined": report.newly_quarantined.len(),
        },
        "quarantined": {
            "count": report.quarantined,
            "first": report.first.iter().map(entry).collect::<Vec<_>>(),
        },
    })
}

/// A quarantine entry, as `rad.reconcile` and `rad.quarantine_list` give it:
/// `{ rid, qid, kind, step, unit, since }`. The evidence stays in the
/// record: it may name a ref.
pub fn entry(record: &Record) -> Value {
    json!({
        "rid": record.rid.to_string(),
        "qid": record.qid.to_string(),
        "kind": record.kind.as_str(),
        "step": record.step,
        "unit": record.unit,
        "since": record.since.as_millis(),
    })
}
