//! `freedom-ipfsd`: the freedom-ipfs service process (design 0007).
//!
//! ```text
//! freedom-ipfsd serve     --data-dir <dir> --lock-dir <dir> --network <policy> [--parent-pid <pid>]
//! freedom-ipfsd serve     --ephemeral --network <policy> [--parent-pid <pid>]
//! freedom-ipfsd hold-lock --data-dir <dir> --lock-dir <dir>
//! ```
//!
//! - **`serve` with a data directory** is the profile's persistent process.
//!   It takes the data directory's `ipfs` gate for its whole life, and holds
//!   one disk instance at a time, its store at
//!   `<data-dir>/freedom-ipfs.sqlite3`.
//! - **`serve --ephemeral`** is the private windows' process: no data
//!   directory and no lock, and up to 8 memory instances.
//! - **`hold-lock`** holds the gate until stdin closes: profile delete,
//!   reset and `ipfs:reset` run under it.
//!
//! **Every command, first:** SQLite's out-of-memory hook
//! ([`freedom_ipfs_store::fail_stop_on_oom`]; design 0010, "The memory
//! cap"), the process's one unsafe call, before any thread or store. From
//! then on an allocation SQLite can't make ends the process with exit 71
//! (`oom.rs`).
//!
//! **`serve`, in order** (design 0010, "The recommendation", step 1):
//! 1. the panic hook, before any other work, and the entry's one re-exec if
//!    a descriptor is inherited ([`confine::clean_entry`]);
//! 2. hardening, the arguments (`--network` among them) and, for the
//!    persistent process, the gate, which creates the data directory;
//! 3. **confinement** ([`confine::confine`]), while the process has one
//!    thread: its data directory read-write (none for the ephemeral
//!    process), NAT64's resolver files read-only, the network policy, and
//!    the lock as the one descriptor it keeps;
//! 4. only then logging's writer, the runtime and the connection to main on
//!    stdin and stdout, until it ends and every instance is torn down.
//!    Lines before logging's writer are written directly.
//!
//! **Exit codes** (0001's, and 0007's 70, 71 and 77): 0 after
//! `ipfs.shutdown`, stdin EOF or the parent gone; 64 for usage; 70 for a
//! panic outside a request, or a teardown that couldn't prove quiescence; 71
//! for out of memory (`out_of_memory`: SQLite couldn't allocate, under the
//! memory cap); 74 for storage; 75 when the gate is held; 76 for a protocol
//! error, the handshake's deadline or the writer stall; 77 when confinement
//! refuses the process (`confinement`: a thread or descriptor it didn't
//! expect, or its own rules refused), or SQLite's out-of-memory hook is
//! refused (something used SQLite first).

mod args;
mod budget;
mod build_info;
mod confinement;
mod dns;
mod instances;
mod nat64;
mod network;
mod oom;
mod params;
mod progress;
mod requests;
mod service;
mod stats;
mod testhooks;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fc_service::conn::{self, Options};
use fc_service::network::NetworkPolicy;
use fc_service::{Exit, confine, gate, log};
use serde_json::{Value, json};

use crate::args::{Command, Mode};
use crate::budget::Budgets;
use crate::instances::{Instances, Kind, STORE_FILE};
use crate::requests::Requests;
use crate::service::IpfsService;
use crate::stats::{STATS_DEADLINE, Stats};

/// The gate's namespace: `<lock-dir>/ipfs-<sha256(data dir)>.lock`.
const NAMESPACE: &str = "ipfs";
/// The method prefix: `ipfs.hello`, `ipfs.shutdown`, ….
const SERVICE: &str = "ipfs";
/// The protocol version `ipfs.hello` must name.
const PROTOCOL: u32 = 1;
/// The process runtime's workers (0007, "Inside the process").
const PROCESS_WORKERS: usize = 2;
/// Its blocking pool: control jobs (builds and teardowns), at most one per
/// instance and one per stop, so a few.
const PROCESS_BLOCKING: usize = 32;

fn main() -> ExitCode {
    let started = Instant::now();
    // A no-op unless a test asks: SQLite used first, so the hook below is
    // refused (`testhooks.rs`, FREEDOM_IPFSD_TEST_SQLITE_FIRST).
    testhooks::sqlite_first();
    // The process's one unsafe call (AGENTS.md rule 6, and Cargo.toml's
    // lints; tests/unsafe_code.rs holds the crate to it): SQLite's
    // allocator is process-global, and `sqlite3_config`, which sets it, has
    // no sound safe form. With it, an allocation SQLite can't make ends the
    // process with exit 71 at once, before any statement fails with it
    // (design 0010, "The memory cap"; `oom.rs`).
    #[allow(unsafe_code)]
    // SAFETY: `fail_stop_on_oom` must run before any thread starts and
    // before any SQLite use in the process. Both hold. It is the first call
    // in `main`, and Rust's runtime starts no thread before `main`, so this
    // is the only thread. Nothing has used SQLite: the panic hook, the
    // entry's re-exec, hardening and confinement come after this, as does
    // every thread the process starts (logging's writer, the runtimes, the
    // connection's) and every store it opens, all from `run`. The entry's
    // re-exec runs `main` again in a new image, where the same holds. The
    // one exception is the test hook above, in a test build alone and only
    // when a test sets its variable: it opens and closes a store on this
    // thread first, which this call then sees (the store's state lock) and
    // refuses with `TooLate` before any FFI.
    let fail_stop = unsafe { freedom_ipfs_store::fail_stop_on_oom() };
    // First after it, before any other work (0007, "Panics").
    fc_service::panic::install();
    // A refused hook ends the process as a confinement step refused does,
    // with no restart (exit 77): only a fault in this program, something
    // using SQLite first, gets here, and it would again.
    if let Err(refused) = fail_stop {
        log::error(
            "SQLite's out-of-memory hook is refused: the process ends",
            json!({ "reason": refused.to_string() }),
        );
        fc_service::exit::claim();
        log::finish(Duration::from_millis(500));
        return ExitCode::from(Exit::Confinement.code());
    }
    // Before anything opens a descriptor (0010, step 1): returns only when
    // nothing needed dropping, or this is the one re-exec, or it failed.
    let entry = confine::clean_entry();
    fc_service::hardening::harden();
    let exit = run(started, &entry);
    // The process's exit is this thread's from here, unless a hook's or a
    // watchdog's has begun: that one ends the process first.
    fc_service::exit::claim();
    log::finish(Duration::from_millis(500));
    ExitCode::from(exit.code())
}

fn run(started: Instant, entry: &confine::Entry) -> Exit {
    let Some(command) = args::parse(std::env::args_os().skip(1)) else {
        log::error(args::USAGE, json!({}));
        return Exit::Usage;
    };
    match entry {
        confine::Entry::Clean => {}
        confine::Entry::Reexeced => log::info(
            "re-executed once at entry: descriptors were inherited",
            json!({}),
        ),
        confine::Entry::Replaced => log::error(
            "re-executed at entry, but not from the file that ran: confinement refuses it",
            json!({}),
        ),
        confine::Entry::Left { reexeced, error } => log::error(
            "descriptors inherited at entry are left",
            json!({
                "reexeced": reexeced,
                "error": error.as_ref().map(|e| e.kind().to_string()),
            }),
        ),
    }
    match command {
        Command::HoldLock { data_dir, lock_dir } => gate::hold_lock(
            &data_dir,
            &lock_dir,
            NAMESPACE,
            std::io::stdin().lock(),
            std::io::stdout().lock(),
        ),
        Command::Serve {
            mode: Mode::Persistent { data_dir, lock_dir },
            network,
            parent_pid,
        } => {
            // Held until the process exits.
            let gate = match gate::acquire(&data_dir, &lock_dir, NAMESPACE, gate::CONTENTION_RETRY)
            {
                Ok(gate) => gate,
                Err(e) => {
                    log::error("cannot take the gate", json!({ "error": e.to_string() }));
                    return Exit::from(&e);
                }
            };
            let mut policy =
                confinement::policy(vec![gate.data_dir.clone()], &network, gate.descriptors());
            testhooks::memory_cap(&mut policy);
            let (confinement, dns) = match confined(&policy, &network) {
                Ok(confined) => confined,
                Err(exit) => return exit,
            };
            let kind = Kind::Persistent {
                store: gate.data_dir.join(STORE_FILE),
            };
            let exit = serve(kind, network, confinement, dns, parent_pid, started);
            drop(gate);
            exit
        }
        Command::Serve {
            mode: Mode::Ephemeral,
            network,
            parent_pid,
        } => {
            // No lock and no directory: nothing writable, nothing kept.
            let mut policy = confinement::policy(Vec::new(), &network, Vec::new());
            testhooks::memory_cap(&mut policy);
            let (confinement, dns) = match confined(&policy, &network) {
                Ok(confined) => confined,
                Err(exit) => return exit,
            };
            serve(
                Kind::Ephemeral,
                network,
                confinement,
                dns,
                parent_pid,
                started,
            )
        }
    }
}

/// Confines the process to `policy`, on the main thread while it is the
/// only one, then reads its DNS configuration under `network`, confined
/// (`dns.rs`): the report, with what resolves names, and that
/// configuration. A refusal is exit 77, which main doesn't restart.
fn confined(
    policy: &confine::Policy,
    network: &NetworkPolicy,
) -> Result<(Value, Option<dns::Dns>), Exit> {
    testhooks::at_confinement_point();
    match confine::confine(policy) {
        Ok(mut report) => {
            let dns = dns::read(network);
            dns::report(&mut report, dns.as_ref());
            Ok((report.to_json(), dns))
        }
        Err(invalid) => {
            log::error(
                "confinement refused the process",
                json!({ "reason": invalid.to_string() }),
            );
            Err(Exit::Confinement)
        }
    }
}

/// Runs the connection with main until it ends, and every instance with it.
/// Every thread the process starts, logging's writer included, starts here,
/// after confinement.
fn serve(
    kind: Kind,
    network: NetworkPolicy,
    confinement: Value,
    dns: Option<dns::Dns>,
    parent_pid: Option<u32>,
    started: Instant,
) -> Exit {
    log::init();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(PROCESS_WORKERS)
        .max_blocking_threads(PROCESS_BLOCKING)
        .thread_name("ipfsd-process")
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            log::error(
                "cannot start the process runtime",
                json!({ "error": e.kind().to_string() }),
            );
            return Exit::Internal;
        }
    };
    log::info(
        "serving",
        json!({ "kind": kind.name(), "network": network.to_json(), "confinement": confinement }),
    );
    testhooks::after_confinement(runtime.handle());
    // Before anything of freedom-ipfs runs: the persistent process records
    // progress, the ephemeral one never does (0007, "Stats").
    let records_progress = matches!(kind, Kind::Persistent { .. });
    if records_progress {
        progress::install();
    }
    // The process's budgets, the writer's 16 MiB reserved first.
    let budgets = match Budgets::new(&kind) {
        Ok(budgets) => Arc::new(budgets),
        Err(_) => {
            log::error("the memory budget can't hold the writer's queue", json!({}));
            return Exit::Internal;
        }
    };
    let requests = Requests::new(runtime.handle().clone(), budgets.memory.clone());
    // The process's NAT64 discovery: idle until a `direct` instance starts.
    let discovery = nat64::Discovery::new(
        testhooks::nat64_source().unwrap_or_else(nat64::Discovery::os_source),
        nat64::Timing::DESIGN,
    );
    let instances = Instances::new(
        kind,
        network,
        runtime.handle().clone(),
        requests.clone(),
        budgets.clone(),
        discovery,
        dns,
    );
    let stats = Stats::new(
        runtime.handle().clone(),
        budgets,
        STATS_DEADLINE,
        records_progress,
    );
    let service = Arc::new(IpfsService::new(
        instances,
        requests,
        stats,
        &network,
        confinement,
    ));
    let mut options = Options::new(SERVICE, PROTOCOL, started);
    options.parent_pid = parent_pid;
    let exit = conn::run(service, options, std::io::stdin(), std::io::stdout());
    // Every instance has been torn down (`Service::end`); what is left are
    // start deadlines' timers. Joining nothing: the process exits next.
    runtime.shutdown_background();
    exit
}
