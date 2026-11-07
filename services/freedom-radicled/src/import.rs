//! The import process (design 0010, "The Radicle import (D5)"; design
//! 0008, "Writes"): `freedom-radicled import --home … --lock-dir …
//! --source <path>`, which main runs with the service stopped.
//!
//! **Before the connection** ([`crate::main`]), as `serve` does: the gate,
//! then the working copy's roots, found from the source's own files without
//! libgit2 and checked against main's protected roots ([`roots`]), then
//! confinement to them: read only on exactly those roots, read and write on
//! the home and the service's own `HOME`, and no network
//! ([`crate::confine::Grant::import_policy`]). A layout that can't be
//! granted grants no root, and is refused at `rad.import_repo`.
//!
//! **The methods,** in order: `rad.hello`, `rad.identity` and
//! `rad.reconcile`, as at a start ([`crate::steps`]), then
//! `rad.import_repo { path, name, description, default_branch }`, giving
//! `{ rid }`. Anything else is `unknown_method`, and `rad.shutdown` is the
//! connection's own.
//!
//! **Admission:** `rad.import_repo` is admitted only after `rad.reconcile`
//! has succeeded in this process. Before that it is `stopped`, and changes
//! nothing; the process goes on. A second, once one is admitted, is
//! `invalid_argument`. The one admitted has 300 s from its admission
//! ([`LIMIT`]), under a watchdog that ends the process with 70; and once it
//! is answered, whatever the answer, the process ends (0).
//!
//! **Before its start, every refusal is definitive,** in this order:
//! params that don't parse (`invalid_argument`); a throwaway key
//! (`needs_vault`: main refuses it first, by the generation's identity);
//! `path` that isn't `--source`, exactly (`invalid_argument`); a layout
//! that can't be granted (`unsupported_layout`); then, on the import's own
//! thread, what libradicle's `Import::prepare` refuses: an argument
//! Radicle refuses or a branch the working copy lacks (`invalid_argument`),
//! a repository already in storage (`failed`, "… already exists in
//! storage"), and the working copy's open (`not_found` or `failed`, by
//! today's message test, with libgit2's text); then main's cancel
//! (`cancelled`, the connection's) or the connection's end (`stopped`).
//!
//! **The start** is claimed in one step with main's cancel
//! ([`Connection::commit`]) and the connection's end, under the import's
//! lock. Past it, only a success is proven: libradicle's error, a panic,
//! the deadline, a kill or a crash is `outcome_unknown`, the error's text
//! logged with its code. libradicle builds the repository in a temporary
//! clone and moves it into place last, so what a cut-off import leaves is
//! a temporary clone, which reconciliation at the service's next start
//! removes.
//!
//! **The dirty marker** stays from `rad.reconcile` on, and is removed only
//! when no import is uncertain: after a proven import, a refusal before the
//! start, or the connection's end with no import started, each once
//! reconciliation is done. Any other end leaves it, for the service's next
//! start to reconcile again.
//!
//! **No child process:** libradicle's import fetches the working copy with
//! libgit2's local transport, in this process.

pub mod roots;

use std::ffi::OsStr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::{Connection, End, Hello, Request, Service};
use fc_service::watchdog::Watchdog;
use fc_service::{Exit, log};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};

use crate::steps::{Steps, fail_start};
use crate::{marker, reads, testhooks};

/// `rad.import_repo`'s time from its admission (0010, D5): past it, the
/// process ends with 70.
pub const LIMIT: Duration = Duration::from_secs(300);

/// The service's texts (0008, "Errors"), pinned with what main makes of
/// them by `vectors/radicle-import.json`.
const BEFORE_RECONCILE: &str = "rad.import_repo is admitted only after rad.reconcile has succeeded";
const ALREADY_CALLED: &str = "rad.import_repo was already called";
const PARAMS: &str = "rad.import_repo takes { path, name, description, default_branch }";
const NOT_THE_SOURCE: &str = "path isn't the --source this import process was started with";
const ENDING: &str = "the import process is ending";
const NEEDS_VAULT: &str = "the node runs with a throwaway key: publishing needs a vault";
const OUTCOME_UNKNOWN: &str = "the import was cut off past its start: it may have been recorded";

/// `rad.import_repo`'s params: today's `importRepo` arguments, by name.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    pub path: String,
    pub name: String,
    pub description: String,
    pub default_branch: String,
}

/// The working copy main named, and its roots.
pub struct Source {
    /// `--source`, as given, if it is valid Unicode: `path` must be it.
    named: Option<String>,
    /// The roots confinement grants, or why the layout can't be granted.
    roots: Result<Vec<PathBuf>, roots::Unsupported>,
}

impl Source {
    /// Finds `source`'s roots and checks them against `protected`.
    pub fn find(source: &OsStr, protected: &[PathBuf]) -> Self {
        let named = source.to_str().map(str::to_owned);
        let roots = match &named {
            None => Err(roots::Unsupported(
                "the source's path isn't valid Unicode".into(),
            )),
            Some(named) => roots::find(Path::new(named)).and_then(|found| {
                roots::check(&found, protected)?;
                Ok(found)
            }),
        };
        Self { named, roots }
    }

    /// What confinement grants read only: the roots, or nothing.
    pub fn granted(&self) -> &[PathBuf] {
        self.roots.as_deref().unwrap_or(&[])
    }

    /// For the log: how many roots, or why none.
    pub fn summary(&self) -> Value {
        match &self.roots {
            Ok(roots) => json!({ "roots": roots.len() }),
            Err(why) => json!({ "unsupported": why.0 }),
        }
    }
}

/// Where the import stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// None admitted yet.
    Waiting,
    /// Admitted, before its start.
    Admitted,
    /// Past its start: its outcome is unknown until libradicle returns.
    Started,
    /// Over: proven, refused before its start, or ended before one; or
    /// cut off past its start (`uncertain`).
    Over { uncertain: bool },
}

pub struct ImportService {
    steps: Steps,
    source: Source,
    phase: Arc<Mutex<Phase>>,
}

impl ImportService {
    pub fn new(steps: Steps, source: Source) -> Self {
        Self {
            steps,
            source,
            phase: Arc::new(Mutex::new(Phase::Waiting)),
        }
    }

    /// `rad.import_repo`.
    fn import(&self, conn: &Connection, request: &Request<'_>) {
        if self.steps.reconciled().is_none() {
            let _ = conn.reply_error(
                request.id,
                &ErrorBody::new(ErrorCode::Stopped, BEFORE_RECONCILE),
            );
            return;
        }
        {
            let mut phase = lock(&self.phase);
            if *phase != Phase::Waiting {
                drop(phase);
                let _ = conn.reply_error(
                    request.id,
                    &ErrorBody::new(ErrorCode::InvalidArgument, ALREADY_CALLED),
                );
                return;
            }
            *phase = Phase::Admitted;
        }
        let watchdog = Watchdog::arm(
            "import_deadline",
            testhooks::import_limit(LIMIT),
            Exit::Internal,
        );
        let ending = Ending {
            conn: conn.clone(),
            id: request.id,
            home: self.steps.home.clone(),
            phase: self.phase.clone(),
            watchdog,
        };
        log::info("the import is admitted", self.source.summary());
        let params = match request.params.and_then(parse_params) {
            Some(params) => params,
            None => {
                return ending.refused(&ErrorBody::new(ErrorCode::InvalidArgument, PARAMS));
            }
        };
        // Known: reconciliation came after `rad.identity`.
        let key = match self.steps.identity.with(|i| (i.ephemeral, i.signer())) {
            Some((false, Some(key))) => key,
            Some((true, _)) => return ending.refused(&needs_vault()),
            _ => {
                return ending.refused(&ErrorBody::new(ErrorCode::Internal, "Internal error"));
            }
        };
        if self.source.named.as_deref() != Some(params.path.as_str()) {
            return ending.refused(&ErrorBody::new(ErrorCode::InvalidArgument, NOT_THE_SOURCE));
        }
        if let Err(why) = &self.source.roots {
            return ending.refused(&ErrorBody::new(ErrorCode::UnsupportedLayout, why.0.clone()));
        }
        let spawned = std::thread::Builder::new()
            .name("import".into())
            .spawn(move || run(ending, &params, &key));
        if spawned.is_err() {
            // The closure, and `ending` with it, went with the error: the
            // process ends with the connection, answering nothing more. The
            // import never started.
            log::error("cannot start the import's thread", json!({}));
            conn.fail(Exit::Internal);
        }
    }
}

/// What an admitted import's end needs.
struct Ending {
    conn: Connection,
    id: u64,
    home: PathBuf,
    phase: Arc<Mutex<Phase>>,
    watchdog: Watchdog,
}

impl Ending {
    /// A refusal before the start: definitive. The marker goes, then the
    /// answer, then the process ends.
    fn refused(self, error: &ErrorBody) {
        *lock(&self.phase) = Phase::Over { uncertain: false };
        clear_marker(&self.home, "the import was refused before its start");
        self.finish(Err(error));
    }

    /// Answers, then ends the process.
    fn finish(self, answer: Result<Box<RawValue>, &ErrorBody>) {
        self.watchdog.disarm();
        match answer {
            Ok(result) => {
                let _ = self.conn.reply(self.id, &result);
            }
            Err(error) => {
                log::info(
                    "the import is answered",
                    json!({ "code": serde_json::to_value(error.code).unwrap_or(Value::Null) }),
                );
                let _ = self.conn.reply_error(self.id, error);
            }
        }
        self.conn.fail(Exit::Ok);
    }
}

/// The import's own thread: libradicle's checks, the start, the import.
fn run(ending: Ending, params: &Params, key: &radicle::crypto::SigningKey) {
    testhooks::at_import_admission();
    testhooks::at_import_stage("admitted");
    let prepared = libradicle::import::Import::prepare(
        &ending.home,
        key,
        Path::new(&params.path),
        &params.name,
        &params.description,
        &params.default_branch,
    );
    let import = match prepared {
        Ok(import) => import,
        Err(e) => return ending.refused(&refusal(e)),
    };
    // The start: one decision with main's cancel and the connection's end.
    {
        let mut phase = lock(&ending.phase);
        if *phase != Phase::Admitted {
            // The connection ended first, and its end cleared the marker.
            drop(phase);
            return ending.finish(Err(&ErrorBody::new(ErrorCode::Stopped, ENDING)));
        }
        if !ending.conn.commit(ending.id) {
            // Main's cancel came first: its `cancelled` is the answer.
            *phase = Phase::Over { uncertain: false };
            drop(phase);
            clear_marker(&ending.home, "the import was cancelled before its start");
            ending.watchdog.disarm();
            ending.conn.fail(Exit::Ok);
            return;
        }
        *phase = Phase::Started;
    }
    log::info(
        "the import has started",
        json!({ "rid": import.rid().to_string() }),
    );
    testhooks::at_import_stage("start");
    let outcome = fc_service::panic::with_kind(fc_service::panic::TaskKind::REQUEST, || {
        catch_unwind(AssertUnwindSafe(|| {
            import.run(&mut |stage| testhooks::at_import_stage(stage_name(stage)))
        }))
    });
    match outcome {
        Ok(Ok(rid)) => {
            *lock(&ending.phase) = Phase::Over { uncertain: false };
            clear_marker(&ending.home, "the import is proven");
            log::info("the import is proven", json!({ "rid": rid.to_string() }));
            ending.finish(Ok(result(&rid)));
        }
        Ok(Err(e)) => {
            *lock(&ending.phase) = Phase::Over { uncertain: true };
            log::error(
                "the import failed past its start; the dirty marker stays",
                json!({ "error": e.to_string() }),
            );
            ending.finish(Err(&outcome_unknown()));
        }
        Err(_) => {
            *lock(&ending.phase) = Phase::Over { uncertain: true };
            log::error(
                "the import panicked past its start; the dirty marker stays",
                json!({}),
            );
            ending.finish(Err(&outcome_unknown()));
        }
    }
}

/// `rad.import_repo`'s params: an object of the four strings, and nothing
/// else (serde would take a struct from an array too).
fn parse_params(raw: &RawValue) -> Option<Params> {
    match serde_json::from_str::<Value>(raw.get()) {
        Ok(value @ Value::Object(_)) => serde_json::from_value(value).ok(),
        _ => None,
    }
}

/// The result of a proven import, `{ rid }`: the text the add-on's
/// `importRepo` returns, from libradicle's `json::rid`.
pub fn result(rid: &radicle::prelude::RepoId) -> Box<RawValue> {
    let mut text = Vec::new();
    let written = libradicle::json::rid(&mut text, rid).is_ok();
    String::from_utf8(text)
        .ok()
        .filter(|_| written)
        .and_then(|text| RawValue::from_string(text).ok())
        .unwrap_or_else(|| {
            // libradicle's writer into memory doesn't fail; the same bytes.
            serde_json::value::to_raw_value(&json!({ "rid": rid.to_string() }))
                .unwrap_or_else(|_| Box::<RawValue>::default())
        })
}

/// libradicle's refusal before the start, as the service answers it.
pub fn refusal(e: libradicle::Error) -> ErrorBody {
    match e {
        libradicle::Error::InvalidImport(message) => {
            ErrorBody::new(ErrorCode::InvalidArgument, message)
        }
        e @ libradicle::Error::Exists(_) => ErrorBody::new(ErrorCode::Failed, e.to_string()),
        other => reads::radicle_error(other),
    }
}

fn needs_vault() -> ErrorBody {
    ErrorBody::new(ErrorCode::NeedsVault, NEEDS_VAULT)
}

/// 0008's text for a write that may have been recorded.
fn outcome_unknown() -> ErrorBody {
    ErrorBody::new(ErrorCode::OutcomeUnknown, OUTCOME_UNKNOWN)
}

fn stage_name(stage: libradicle::import::Stage) -> &'static str {
    use libradicle::import::Stage;
    match stage {
        Stage::Created => "created",
        Stage::Fetched => "fetched",
        Stage::Signed => "signed",
        Stage::Seeded => "seeded",
        _ => "other",
    }
}

/// Removes the dirty marker: nothing this process did is uncertain, and
/// reconciliation is done.
fn clear_marker(home: &Path, why: &str) {
    match marker::remove(home) {
        Ok(()) => log::info("the dirty marker is cleared", json!({ "why": why })),
        Err(e) => log::error(
            "the dirty marker wasn't cleared",
            json!({ "why": why, "error": e.to_string() }),
        ),
    }
}

fn lock(phase: &Mutex<Phase>) -> std::sync::MutexGuard<'_, Phase> {
    phase.lock().unwrap_or_else(|p| p.into_inner())
}

impl Service for ImportService {
    fn hello(&self, _hello: &Hello) -> Result<Map<String, Value>, ErrorBody> {
        Ok(self.steps.hello())
    }

    fn request(&self, conn: &Connection, request: Request<'_>) {
        match request.method {
            "rad.identity" => self.steps.identity(conn, &request),
            "rad.reconcile" if self.steps.identity.known() => {
                self.steps.reconcile(conn, &request);
            }
            "rad.reconcile" => fail_start(
                conn,
                request.id,
                &ErrorBody::new(ErrorCode::NoIdentity, "rad.identity has not succeeded"),
            ),
            "rad.import_repo" => self.import(conn, &request),
            _ => {
                let _ = conn.reply_error(
                    request.id,
                    &ErrorBody::new(ErrorCode::UnknownMethod, "unknown method"),
                );
            }
        }
    }

    fn cancel(&self, _conn: &Connection, _id: u64) {
        // `rad.import_repo` before its start: its `cancelled` is queued,
        // and the start's commit sees it. Past its start, main's cancel
        // queues nothing, and the import answers its outcome.
    }

    fn end(&self, _conn: &Connection, end: End) {
        self.steps.end();
        let mut phase = lock(&self.phase);
        match *phase {
            // No import started, and none will: the home is as
            // reconciliation left it, if it is done.
            Phase::Waiting | Phase::Admitted => {
                *phase = Phase::Over { uncertain: false };
                drop(phase);
                if self.steps.reconciled().is_some() {
                    clear_marker(&self.steps.home, "no import started");
                }
            }
            // An import past its start: the process ends within the
            // connection's exit, and with it the import, unless it is
            // answered first.
            Phase::Started => log::info(
                "the connection ended during the import; the dirty marker stays",
                json!({}),
            ),
            Phase::Over { .. } => {}
        }
        log::info("connection ended", json!({ "end": end.name() }));
    }
}

#[cfg(test)]
mod tests;
