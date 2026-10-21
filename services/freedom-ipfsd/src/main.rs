//! `freedom-ipfsd`: the freedom-ipfs service process (design 0007).
//!
//! ```text
//! freedom-ipfsd serve     --data-dir <dir> --lock-dir <dir> [--parent-pid <pid>]
//! freedom-ipfsd serve     --ephemeral [--parent-pid <pid>]
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
//! **`serve`, in order:** the panic hook, before any other work; logging;
//! hardening; the gate (persistent only); then the connection to main on
//! stdin and stdout, until it ends and every instance is torn down.
//!
//! **Exit codes** (0001's, and 0007's 70): 0 after `ipfs.shutdown`, stdin
//! EOF or the parent gone; 64 for usage; 70 for a panic outside a request,
//! or a teardown that couldn't prove quiescence; 74 for storage; 75 when the
//! gate is held; 76 for a protocol error, the handshake's deadline or the
//! writer stall.

mod args;
mod budget;
mod build_info;
mod instances;
mod network;
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
use fc_service::{Exit, gate, log};
use serde_json::json;

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
    // First, before any other work (0007, "Panics").
    fc_service::panic::install();
    log::init();
    fc_service::hardening::harden();
    let exit = run(started);
    // The process's exit is this thread's from here, unless a hook's or a
    // watchdog's has begun: that one ends the process first.
    fc_service::exit::claim();
    log::finish(Duration::from_millis(500));
    ExitCode::from(exit.code())
}

fn run(started: Instant) -> Exit {
    let Some(command) = args::parse(std::env::args_os().skip(1)) else {
        log::error(args::USAGE, json!({}));
        return Exit::Usage;
    };
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
            let kind = Kind::Persistent {
                store: gate.data_dir.join(STORE_FILE),
            };
            let exit = serve(kind, parent_pid, started);
            drop(gate);
            exit
        }
        Command::Serve {
            mode: Mode::Ephemeral,
            parent_pid,
        } => serve(Kind::Ephemeral, parent_pid, started),
    }
}

/// Runs the connection with main until it ends, and every instance with it.
fn serve(kind: Kind, parent_pid: Option<u32>, started: Instant) -> Exit {
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
    log::info("serving", json!({ "kind": kind.name() }));
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
    let instances = Instances::new(
        kind,
        runtime.handle().clone(),
        requests.clone(),
        budgets.clone(),
    );
    let stats = Stats::new(
        runtime.handle().clone(),
        budgets,
        STATS_DEADLINE,
        records_progress,
    );
    let service = Arc::new(IpfsService::new(instances, requests, stats));
    let mut options = Options::new(SERVICE, PROTOCOL, started);
    options.parent_pid = parent_pid;
    let exit = conn::run(service, options, std::io::stdin(), std::io::stdout());
    // Every instance has been torn down (`Service::end`); what is left are
    // start deadlines' timers. Joining nothing: the process exits next.
    runtime.shutdown_background();
    exit
}
