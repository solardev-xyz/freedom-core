//! `freedom-radicled`: the libradicle service process (design 0008).
//!
//! ```text
//! freedom-radicled serve     --home <dir> --lock-dir <dir> --network <policy> [--parent-pid <pid>]
//! freedom-radicled import    --home <dir> --lock-dir <dir> --source <path> [--protected <dir>]… [--parent-pid <pid>]
//! freedom-radicled hold-lock --home <dir> --lock-dir <dir>
//! ```
//!
//! - **`serve`** is the profile's Radicle node: one node per process, and
//!   the process is its only teardown (0008, "Process model").
//! - **`import`** is the one-shot import process (design 0010, D5;
//!   [`import`]): with the service stopped, it reconciles the home, imports
//!   the working copy at `--source`, and exits. It runs `serve`'s steps 1
//!   to 7, then finds and checks the working copy's roots, and confines
//!   itself to them read only, with no network, before its connection.
//! - **`hold-lock`** holds the home's gate until stdin closes: the alias
//!   rewrite, profile delete and reset, and `radicle:reset` run under it.
//!
//! **`serve`, in order** (0008, "Spawn and lock"; design 0010, "The
//! recommendation", step 1):
//! 1. the panic hook, before any other work, and the entry's one re-exec if
//!    a descriptor is inherited (`fc_service::confine::clean_entry`);
//! 2. hardening;
//! 3. libgit2's configuration search paths emptied
//!    (`libradicle::isolate_git_config`, libradicle item 9), while the
//!    process has one thread: no git configuration outside a repository
//!    applies, and confinement, which leaves `/etc/gitconfig` unreadable,
//!    fails no repository's open;
//! 4. the arguments, `--network` among them;
//! 5. the environment main cleared, checked ([`env`]);
//! 6. the gate, `<lock-dir>/radicle-<sha256(canonical home)>.lock`, before
//!    anything opens the home;
//! 7. the home and the service's own `HOME` directory, opened;
//! 8. **confinement** ([`confine`]), while the process has one thread: the
//!    two directories read-write, with `refer`; the network policy; the lock
//!    as the one descriptor it keeps;
//! 9. only then logging's writer, the connection's threads and the
//!    watchdogs: the handshake, `rad.hello`, and what follows.
//!
//! **This build** answers `rad.hello`, `rad.identity` (0008, "The sealed
//! release" and "Profiles without a vault"), `rad.reconcile` (0008,
//! "Reconciliation") and `rad.start`, which runs the node until the
//! connection ends ([`node`]); then quarantine's methods ([`quarantine`]),
//! the writes ([`writes`]), `rad.read`'s ops ([`reads`]), the network
//! operations, `rad.connect_seeds` and `rad.clone` ([`network`]), and
//! `rad.stats` ([`stats`]). The import process answers `rad.hello`,
//! `rad.identity`, `rad.reconcile` and `rad.import_repo` ([`import`]).
//! The other methods and ops 0008 lists come with later steps; until then
//! each answers `stopped`.
//!
//! **No child processes:** libradicle is built with `no-spawn`, and the
//! service starts none.
//!
//! **Exit codes** (0001's, and 0008's): 0 after `rad.shutdown`, stdin EOF,
//! the parent gone, or a failed start step answered first; 64 for usage,
//! including an environment main should have cleared; 70 for a panic
//! outside a request, a repair unit's overrun (`unit_overrun`), the node
//! thread's end while the node should run (`node_down`), an import past its
//! 300 s (`import_deadline`), or a service that
//! can't start (libgit2's search paths, the OS's randomness,
//! or the unit watchdog's thread); 74 for storage; 75 when the gate is
//! held; 76 for a protocol error, the handshake's deadline, `rad.identity`'s
//! deadline or the writer stall; 77 when confinement refuses the process
//! (`confinement`: a thread or descriptor it didn't expect, or its own rules
//! refused).

mod args;
mod build_info;
mod confine;
mod dial;
mod env;
mod identity;
mod import;
mod marker;
mod nat64;
mod network;
mod node;
mod output;
mod pools;
mod quarantine;
mod reads;
mod reconcile;
mod repair;
mod service;
mod stats;
mod steps;
mod testhooks;
mod units;
mod writes;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fc_service::conn::{self, Options};
use fc_service::network::NetworkPolicy;
use fc_service::{Exit, gate, log};
use serde_json::{Value, json};

use crate::args::Command;
use crate::import::ImportService;
use crate::service::RadicleService;

/// The gate's namespace: `<lock-dir>/radicle-<sha256(home)>.lock` (0008,
/// "Spawn and lock"). The core's identity writes take the same gate.
const NAMESPACE: &str = "radicle";
/// The method prefix: `rad.hello`, `rad.shutdown`, ….
const SERVICE: &str = "rad";
/// The protocol version `rad.hello` must name.
const PROTOCOL: u32 = 1;

fn main() -> ExitCode {
    let started = Instant::now();
    // First, before any other work (0008, "Crashes and restarts").
    fc_service::panic::install();
    // Before anything opens a descriptor (0010, step 1): returns only when
    // nothing needed dropping, or this is the one re-exec, or it failed.
    let entry = fc_service::confine::clean_entry();
    fc_service::hardening::harden();
    // The process's one unsafe call (AGENTS.md rule 6, and Cargo.toml's
    // lints; tests/unsafe_code.rs holds the crate to it). libgit2's search
    // paths are process-wide options with no sound safe setter. After
    // `clean_entry`, not before, so that libgit2's initialization, which can
    // open `/dev/urandom` for its seed, comes after the check for inherited
    // descriptors.
    //
    // `remove_git_config_env`, its companion, isn't needed: `serve` refuses
    // every `GIT_*` variable (`env::check`) before anything opens a
    // repository, and nothing here opens one from the environment.
    #[allow(unsafe_code)]
    // SAFETY: `isolate_git_config` must run before any thread can use
    // libgit2. None can: no other thread of this program exists yet, and
    // nothing has called libgit2. The panic hook, the entry's re-exec and
    // hardening, all that runs before this, start no thread and don't touch
    // libgit2, and every thread the process starts, logging's writer and
    // reconciliation's among them, starts from `serve`, after this returns.
    let isolated = unsafe { libradicle::isolate_git_config() };
    let exit = match isolated {
        Ok(git_config) => run(started, &entry, git_config),
        Err(e) => {
            log::error(
                "cannot isolate libgit2 from git configuration",
                json!({ "error": e.to_string() }),
            );
            Exit::Internal
        }
    };
    // The process's exit is this thread's from here, unless a hook's or a
    // watchdog's has begun: that one ends the process first.
    fc_service::exit::claim();
    log::finish(Duration::from_millis(500));
    ExitCode::from(exit.code())
}

fn run(
    started: Instant,
    entry: &fc_service::confine::Entry,
    git_config: libradicle::GitConfigIsolated,
) -> Exit {
    let Some(command) = args::parse(std::env::args_os().skip(1)) else {
        log::error(args::USAGE, json!({}));
        return Exit::Usage;
    };
    match entry {
        fc_service::confine::Entry::Clean => {}
        fc_service::confine::Entry::Reexeced => log::info(
            "re-executed once at entry: descriptors were inherited",
            json!({}),
        ),
        fc_service::confine::Entry::Replaced => log::error(
            "re-executed at entry, but not from the file that ran: confinement refuses it",
            json!({}),
        ),
        fc_service::confine::Entry::Left { reexeced, error } => log::error(
            "descriptors inherited at entry are left",
            json!({
                "reexeced": reexeced,
                "error": error.as_ref().map(|e| e.kind().to_string()),
            }),
        ),
    }
    match command {
        Command::HoldLock { home, lock_dir } => gate::hold_lock(
            &home,
            &lock_dir,
            NAMESPACE,
            std::io::stdin().lock(),
            std::io::stdout().lock(),
        ),
        Command::Import {
            home,
            lock_dir,
            source,
            protected,
            parent_pid,
        } => {
            let own_home = match env::check(std::env::vars_os()) {
                Ok(own_home) => own_home,
                Err(refusal) => {
                    log::error(
                        "the environment holds what the service must not inherit",
                        json!({ "reason": refusal.reason() }),
                    );
                    return Exit::Usage;
                }
            };
            let gate = match gate::acquire(&home, &lock_dir, NAMESPACE, gate::CONTENTION_RETRY) {
                Ok(gate) => gate,
                Err(e) => {
                    log::error("cannot take the gate", json!({ "error": e.to_string() }));
                    return Exit::from(&e);
                }
            };
            let exit = match confine::Grant::open(&gate.data_dir, &own_home) {
                Ok(grant) => {
                    // The roots, before confinement, and main's check of
                    // them: no root may be, contain, or lie inside the
                    // lock directory, the home, the service's own `HOME`,
                    // or a root main protects.
                    let mut guarded =
                        vec![lock_dir.clone(), grant.home.clone(), grant.own_home.clone()];
                    guarded.extend(protected);
                    let source = import::Source::find(&source, &guarded);
                    let policy = grant.import_policy(source.granted(), gate.descriptors());
                    match confine::apply(&policy) {
                        Ok(report) => serve_import(
                            grant,
                            source,
                            report.to_json(),
                            parent_pid,
                            started,
                            git_config,
                        ),
                        Err(invalid) => {
                            log::error(
                                "confinement refused the process",
                                json!({ "reason": invalid.to_string() }),
                            );
                            Exit::Confinement
                        }
                    }
                }
                Err(e) => {
                    log::error(
                        "cannot open the home",
                        json!({ "error": e.kind().to_string() }),
                    );
                    Exit::Storage
                }
            };
            drop(gate);
            exit
        }
        Command::Serve {
            home,
            lock_dir,
            network,
            parent_pid,
        } => {
            let own_home = match env::check(std::env::vars_os()) {
                Ok(own_home) => own_home,
                Err(refusal) => {
                    log::error(
                        "the environment holds what the service must not inherit",
                        json!({ "reason": refusal.reason() }),
                    );
                    return Exit::Usage;
                }
            };
            // Held until the process exits, and taken before anything opens
            // the home: heartwood's own exclusion comes after its threads.
            let gate = match gate::acquire(&home, &lock_dir, NAMESPACE, gate::CONTENTION_RETRY) {
                Ok(gate) => gate,
                Err(e) => {
                    log::error("cannot take the gate", json!({ "error": e.to_string() }));
                    return Exit::from(&e);
                }
            };
            let exit = match confine::Grant::open(&gate.data_dir, &own_home) {
                Ok(grant) => match confine::confine(&grant, &network, gate.descriptors()) {
                    Ok(report) => serve(
                        grant,
                        network,
                        report.to_json(),
                        parent_pid,
                        started,
                        git_config,
                    ),
                    Err(invalid) => {
                        log::error(
                            "confinement refused the process",
                            json!({ "reason": invalid.to_string() }),
                        );
                        Exit::Confinement
                    }
                },
                Err(e) => {
                    log::error(
                        "cannot open the home",
                        json!({ "error": e.kind().to_string() }),
                    );
                    Exit::Storage
                }
            };
            drop(gate);
            exit
        }
    }
}

/// Runs the connection with main until it ends. Every thread the process
/// starts, logging's writer included, starts here, after confinement.
fn serve(
    grant: confine::Grant,
    network: NetworkPolicy,
    confinement: Value,
    parent_pid: Option<u32>,
    started: Instant,
    git_config: libradicle::GitConfigIsolated,
) -> Exit {
    log::init();
    log::info(
        "serving",
        json!({ "network": network.to_json(), "confinement": confinement }),
    );
    // The repair units' watchdog: one thread for the service's lifetime. One
    // that can't be started fails the start, before any unit runs.
    let units = match units::UnitWatch::start(testhooks::unit_limit(units::UNIT_LIMIT)) {
        Ok(watch) => Arc::new(watch),
        Err(e) => {
            log::error(
                "cannot start the unit watchdog",
                json!({ "error": e.kind().to_string() }),
            );
            return Exit::Internal;
        }
    };
    // The read pool, the network pool and the write queue: their threads
    // wait for `RUNNING`. One that can't be started fails the start too.
    let pools = match pools::Pools::start() {
        Ok(pools) => Arc::new(pools),
        Err(e) => {
            log::error(
                "cannot start the pools",
                json!({ "error": e.kind().to_string() }),
            );
            return Exit::Internal;
        }
    };
    // The clones' progress: one thread, which writes their events to main.
    let progress = match network::progress::Hub::start() {
        Ok(hub) => Arc::new(hub),
        Err(e) => {
            log::error(
                "cannot start the progress hub",
                json!({ "error": e.kind().to_string() }),
            );
            return Exit::Internal;
        }
    };
    let service = match RadicleService::new(
        grant,
        &network,
        confinement,
        units,
        pools,
        progress,
        git_config,
    ) {
        Some(service) => Arc::new(service),
        None => {
            log::error("the OS random number generator failed", json!({}));
            return Exit::Internal;
        }
    };
    let mut options = Options::new(SERVICE, PROTOCOL, started);
    options.parent_pid = parent_pid;
    // One event waits for the writer at most: what a clone hasn't had
    // written waits in its own bounded queue (0008, "Progress").
    options.max_events = network::progress::CONNECTION_EVENTS;
    conn::run(service, options, std::io::stdin(), std::io::stdout())
}

/// The import process's connection with main, until it ends (design 0010,
/// D5). As in [`serve`], every thread starts here, after confinement: no
/// pools, no node and no progress hub, only the unit watchdog, which
/// reconciliation's units need.
fn serve_import(
    grant: confine::Grant,
    source: import::Source,
    confinement: Value,
    parent_pid: Option<u32>,
    started: Instant,
    git_config: libradicle::GitConfigIsolated,
) -> Exit {
    log::init();
    log::info(
        "importing",
        json!({ "source": source.summary(), "confinement": confinement }),
    );
    let units = match units::UnitWatch::start(testhooks::unit_limit(units::UNIT_LIMIT)) {
        Ok(watch) => Arc::new(watch),
        Err(e) => {
            log::error(
                "cannot start the unit watchdog",
                json!({ "error": e.kind().to_string() }),
            );
            return Exit::Internal;
        }
    };
    // The quarantine record's count, which no method of this process
    // reports.
    let quarantined = Arc::new(stats::Quarantined::default());
    let Some(steps) = steps::Steps::new(
        grant.home,
        json!({ "mode": "offline" }),
        confinement,
        units,
        quarantined,
        git_config,
    ) else {
        log::error("the OS random number generator failed", json!({}));
        return Exit::Internal;
    };
    let service = Arc::new(ImportService::new(steps, source));
    let mut options = Options::new(SERVICE, PROTOCOL, started);
    options.parent_pid = parent_pid;
    conn::run(service, options, std::io::stdin(), std::io::stdout())
}
