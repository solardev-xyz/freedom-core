//! `freedom-colibrid`: Colibri's verifier as a native, confined process
//! (design 0014). The command line is in [`args`].
//!
//! **`serve`, in order** (design 0010, "The recommendation", step 1):
//! 1. the panic hook, before any other work, and the entry's one re-exec if
//!    a descriptor is inherited ([`confine::clean_entry`]);
//! 2. hardening, the arguments, and for a persistent process the gate,
//!    which creates the chain's directory;
//! 3. **confinement** ([`confine::confine`]), while the process has one
//!    thread: no network, the chain's directory read-write (nothing for a
//!    private process), and the lock as the one descriptor it keeps;
//! 4. logging's writer; the verifier thread, the only one that calls into
//!    the C core, which gives it its store and checks its version before
//!    `hello` can be answered; and the connection to main on stdin and
//!    stdout.
//!
//! **`checkpoint`** runs the same way with no gate and no directory, its
//! store in memory, and ends after its one `colibri.checkpoint`.
//!
//! **Exit codes** (0001's and 0007's): 0 after `colibri.shutdown`, stdin
//! EOF, the parent gone, or a recycle; 64 for usage; 70 for a panic or an
//! internal failure; 74 for storage; 75 when the gate is held; 76 for a
//! protocol error; 77 when confinement refuses the process.

mod args;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fc_service::conn::{self, Options};
use fc_service::{Exit, confine, gate, log};
use freedom_colibrid::service::ColibriService;
use freedom_colibrid::shared::{Mode as Process, Shared};
use freedom_colibrid::store::Store;
use serde_json::json;

use crate::args::{Command, Mode};

/// The gate's namespace: `<lock-dir>/colibri-<sha256(data dir)>.lock`.
const NAMESPACE: &str = "colibri";
/// The method prefix: `colibri.hello`, `colibri.shutdown`, ….
const SERVICE: &str = "colibri";
/// The protocol version `colibri.hello` must name.
const PROTOCOL: u32 = 1;

fn main() -> ExitCode {
    let started = Instant::now();
    // First, before any other work (0007, "Panics").
    fc_service::panic::install();
    // Before anything opens a descriptor (0010, step 1).
    let entry = confine::clean_entry();
    fc_service::hardening::harden();
    let exit = run(started, &entry);
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
    let (chain, mode, parent_pid) = match command {
        Command::Checkpoint { chain, parent_pid } => {
            // No lock, no directory, nothing writable: its store is in
            // memory (0014, "Spawn").
            let report = match confined(Vec::new(), Vec::new()) {
                Ok(report) => report,
                Err(exit) => return exit,
            };
            return serve(
                chain,
                Process::Checkpoint,
                Store::memory(),
                report,
                parent_pid,
                started,
            );
        }
        Command::HoldLock { data_dir, lock_dir } => {
            return gate::hold_lock(
                &data_dir,
                &lock_dir,
                NAMESPACE,
                std::io::stdin().lock(),
                std::io::stdout().lock(),
            );
        }
        Command::Serve {
            chain,
            mode,
            parent_pid,
        } => (chain, mode, parent_pid),
    };
    match mode {
        Mode::Persistent { data_dir, lock_dir } => {
            // Held until the process exits.
            let gate = match gate::acquire(&data_dir, &lock_dir, NAMESPACE, gate::CONTENTION_RETRY)
            {
                Ok(gate) => gate,
                Err(e) => {
                    log::error("cannot take the gate", json!({ "error": e.to_string() }));
                    return Exit::from(&e);
                }
            };
            let report = match confined(vec![gate.data_dir.clone()], gate.descriptors()) {
                Ok(report) => report,
                Err(exit) => return exit,
            };
            let store = match Store::open(&gate.data_dir) {
                Ok(store) => store,
                Err(e) => {
                    log::error(
                        "cannot open the chain's store",
                        json!({ "error": e.kind().to_string() }),
                    );
                    return Exit::Storage;
                }
            };
            let exit = serve(chain, Process::Serve, store, report, parent_pid, started);
            drop(gate);
            exit
        }
        Mode::Private => {
            // No lock and no directory: nothing writable, nothing kept.
            let report = match confined(Vec::new(), Vec::new()) {
                Ok(report) => report,
                Err(exit) => return exit,
            };
            serve(
                chain,
                Process::Serve,
                Store::memory(),
                report,
                parent_pid,
                started,
            )
        }
    }
}

/// Confinement (0014, "Confinement"): no network, `read_write` alone, and
/// `descriptors` the only ones kept.
fn confined(
    read_write: Vec<std::path::PathBuf>,
    descriptors: Vec<i32>,
) -> Result<serde_json::Value, Exit> {
    match confine::confine(&confine::Policy {
        read_write,
        read_only: Vec::new(),
        read_only_dirs: Vec::new(),
        refer: false,
        min_abi: 1,
        network: confine::Network::Offline,
        resolver: confine::Resolver::None,
        descriptors,
        interface_index: false,
        times: false,
        symlinks: false,
        modes: false,
    }) {
        Ok(report) => Ok(report.to_json()),
        Err(invalid) => {
            log::error(
                "confinement refused the process",
                json!({ "invalid": format!("{invalid:?}") }),
            );
            Err(Exit::Confinement)
        }
    }
}

fn serve(
    chain: u64,
    process: Process,
    store: Store,
    confinement: serde_json::Value,
    parent_pid: Option<u32>,
    started: Instant,
) -> Exit {
    freedom_colibrid::testhooks::probe("main");
    // Logging's writer is a thread: after confinement.
    log::init();
    let shared = Arc::new(Shared::new(chain, Arc::new(store), process));
    // The verifier thread gives the C core its store and checks its version
    // (main refuses another than its pin's; so does the service) before
    // anything else reaches the C core, and before `hello`.
    let service = match ColibriService::start(shared, confinement) {
        Ok(service) => Arc::new(service),
        Err(e) => {
            log::error("the C core's setup failed", json!({ "error": e }));
            return Exit::Internal;
        }
    };
    let mut options = Options::new(SERVICE, PROTOCOL, started);
    options.parent_pid = parent_pid;
    // Main's bodies come back as streams (COL-3).
    options.two_way = true;
    conn::run(service, options, std::io::stdin(), std::io::stdout())
}
