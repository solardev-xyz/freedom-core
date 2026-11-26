//! `freedom-cored`: the desktop core process (design 0001).
//!
//! ```text
//! freedom-cored serve     --data-dir <identity dir> --lock-dir <lock dir> [--parent-pid <pid>]
//!                         --grant-root <dir> [--user-data-dir <dir>]
//!                         [--node-root bee=<dir>] [--node-root radicle=<dir>]
//! freedom-cored hold-lock --data-dir <identity dir> --lock-dir <lock dir>
//! freedom-cored recover   --data-dir <identity dir> --lock-dir <lock dir>
//! freedom-cored profile <open|list|create|rename|import|update-nodes|reserved-ports|status|delete|forget-list|forget-done|migrate> …
//! freedom-cored hold-profile --user-data-dir <dir> --lock-dir <dir> [--app-root <dir> --id <id>]
//! freedom-cored keystore --op <op> --policy <policy> --item <id> [--reply-key <base64>] [--reason <kind>]
//! ```
//!
//! `serve`'s `--grant-root`, `--user-data-dir` and `--node-root` are the
//! directories of its grant (design 0017, C1): each absolute and
//! normalized, each node kind at most once. `--grant-root` is required; a
//! `serve` without it is a usage error (64). The hello must name the same
//! `grant_root` and `user_data_dir`, and `nodes.write_identity` the same
//! node directory.
//!
//! `keystore` is the one-shot key-store helper ([`keystore::helper`],
//! design 0013): one call to the OS's key store, one line on stdout.
//!
//! Every other subcommand confines itself: the profile subcommands
//! ([`profile`], design 0013), and `serve`, `hold-lock` and `recover`
//! (design 0017, [`confine`]). Each starts as a service does (0010): before
//! anything opens a descriptor, inherited ones are dropped by one re-exec
//! (`fc_service::confine::clean_entry`), and no thread starts before its
//! confinement, logging's writer included (its lines are written directly).

mod accounts;
mod approvals;
mod chain;
mod clock;
mod confine;
mod delete_journal;
mod dweb;
mod eip1193;
mod exit;
mod gate;
mod grants;
mod hardening;
mod intents;
mod journal;
mod keystore;
mod log;
mod naming;
mod nodes;
mod payments;
mod payments_store;
mod phone;
mod pool;
mod profile;
mod requests;
mod rng;
mod rpc_keys;
mod safe;
mod safe_pending;
mod secrets;
mod serve;
mod signing;
mod sqlite;
mod storage;
mod swarm;
mod testhooks;
// The `testhooks` feature only (build.rs refuses it in a release build):
// otherwise no test method is compiled at all.
#[cfg(feature = "testhooks")]
mod testmethods;
// The `testhooks` feature only: fc-store's journal driven from stdin, for
// the interop harness (design 0013, PRF-5d).
#[cfg(feature = "testhooks")]
mod testjournal;
// The `testhooks` feature only: the payments methods driven from stdin, for
// the interop harness (design 0013, PRF-5g-2).
#[cfg(feature = "testhooks")]
mod testpayments;
mod transport;
mod vault;
mod vault_meta_journal;
mod worker;

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use exit::Exit;

const USAGE: &str = "usage: freedom-cored <serve|hold-lock|recover> --data-dir <dir> --lock-dir <dir> [--parent-pid <pid>]; \
     serve also: --grant-root <dir> [--user-data-dir <dir>] [--node-root bee=<dir>] [--node-root radicle=<dir>]";

struct Args {
    command: String,
    data_dir: Option<PathBuf>,
    lock_dir: Option<PathBuf>,
    parent_pid: Option<u32>,
    hello_timeout_ms: u64,
    /// `serve`'s grant (design 0017, C1).
    grant_root: Option<PathBuf>,
    user_data_dir: Option<PathBuf>,
    node_roots: nodes::NodeRootArgs,
}

impl Args {
    /// Whether any of `serve`'s grant arguments was given.
    fn names_a_grant(&self) -> bool {
        self.grant_root.is_some()
            || self.user_data_dir.is_some()
            || self.node_roots.bee.is_some()
            || self.node_roots.radicle.is_some()
    }
}

fn parse_args() -> Option<Args> {
    let mut args = std::env::args_os().skip(1);
    let command = args.next()?.into_string().ok()?;
    let mut parsed = Args {
        command,
        data_dir: None,
        lock_dir: None,
        parent_pid: None,
        hello_timeout_ms: 10_000,
        grant_root: None,
        user_data_dir: None,
        node_roots: nodes::NodeRootArgs::default(),
    };
    while let Some(flag) = args.next() {
        let value = args.next()?;
        match flag.to_str()? {
            "--data-dir" => parsed.data_dir = Some(PathBuf::from(value)),
            "--lock-dir" => parsed.lock_dir = Some(PathBuf::from(value)),
            "--parent-pid" => parsed.parent_pid = Some(value.to_str()?.parse().ok()?),
            // For tests; main never passes it.
            "--hello-timeout-ms" => parsed.hello_timeout_ms = value.to_str()?.parse().ok()?,
            "--grant-root" => {
                set_once(&mut parsed.grant_root, grant_dir(value.to_str()?)?)?;
            }
            "--user-data-dir" => {
                set_once(&mut parsed.user_data_dir, grant_dir(value.to_str()?)?)?;
            }
            "--node-root" => {
                let (kind, dir) = value.to_str()?.split_once('=')?;
                let slot = match kind {
                    "bee" => &mut parsed.node_roots.bee,
                    "radicle" => &mut parsed.node_roots.radicle,
                    _ => return None,
                };
                set_once(slot, grant_dir(dir)?)?;
            }
            _ => return None,
        }
    }
    Some(parsed)
}

/// A directory of `serve`'s grant (design 0017, C1): absolute and
/// normalized, by the rule the hello's `grant_root` is checked with. UTF-8,
/// since each must equal a string main sends (the hello's, or
/// `nodes.write_identity`'s).
fn grant_dir(value: &str) -> Option<PathBuf> {
    Some(PathBuf::from(value)).filter(|dir| journal::normalized_absolute(dir))
}

/// Sets a grant argument: given twice, it is a usage error.
fn set_once(slot: &mut Option<PathBuf>, dir: PathBuf) -> Option<()> {
    if slot.is_some() {
        return None;
    }
    *slot = Some(dir);
    Some(())
}

fn main() -> ExitCode {
    let started = Instant::now();
    // Every subcommand's durable writes report a failed flush after their
    // commit to the log (fc-store writes none of its own).
    fc_store::fsx::report_flush_failures(|kind| {
        log::error(
            "directory flush failed after commit",
            serde_json::json!({ "kind": kind.to_string() }),
        );
    });
    let command = std::env::args_os()
        .nth(1)
        .and_then(|c| c.into_string().ok());
    if command.as_deref() == Some("keystore") {
        // No logging thread, no gate: one OS call and one line.
        return ExitCode::from(keystore::helper::run(std::env::args_os().skip(2)).code());
    }
    #[cfg(feature = "testhooks")]
    if command.as_deref() == Some("test-journal") && testhooks::test_methods() {
        return ExitCode::from(testjournal::run(std::env::args_os().skip(2)));
    }
    #[cfg(feature = "testhooks")]
    if command.as_deref() == Some("test-payments") && testhooks::test_methods() {
        return ExitCode::from(testpayments::run(std::env::args_os().skip(2)));
    }
    if matches!(command.as_deref(), Some("profile" | "hold-profile")) {
        let entry = fc_service::confine::clean_entry();
        return ExitCode::from(profile::run(std::env::args_os().skip(1), &entry).code());
    }
    // `serve`, `hold-lock` and `recover` (design 0017, "The order in
    // serve", step 1): inherited descriptors dropped, and no logging thread
    // until each has confined itself.
    let entry = fc_service::confine::clean_entry();
    let exit = run(started, &entry);
    log::finish(Duration::from_millis(500));
    ExitCode::from(exit.code())
}

fn run(started: Instant, entry: &fc_service::confine::Entry) -> Exit {
    confine::log_entry(entry);
    // Step 2: the arguments (design 0017, C1).
    let Some(args) = parse_args() else {
        log::error(USAGE, serde_json::json!({}));
        return Exit::Usage;
    };
    // The grant's arguments are `serve`'s alone, and `serve` needs its
    // Freedom root.
    if args.command != "serve" && args.names_a_grant() {
        log::error(USAGE, serde_json::json!({}));
        return Exit::Usage;
    }
    let (Some(data_dir), Some(lock_dir)) = (args.data_dir, args.lock_dir) else {
        log::error(USAGE, serde_json::json!({}));
        return Exit::Usage;
    };
    match args.command.as_str() {
        "serve" => {
            let Some(grant_root) = args.grant_root else {
                log::error(USAGE, serde_json::json!({}));
                return Exit::Usage;
            };
            serve::run(&serve::Options {
                data_dir,
                lock_dir,
                parent_pid: args.parent_pid,
                hello_timeout: Duration::from_millis(args.hello_timeout_ms),
                started,
                grant_root,
                user_data_dir: args.user_data_dir,
                node_roots: args.node_roots,
            })
        }
        "hold-lock" => hold_lock(&data_dir, &lock_dir),
        "recover" => recover(&data_dir, &lock_dir),
        _ => {
            log::error(USAGE, serde_json::json!({}));
            Exit::Usage
        }
    }
}

/// Takes the gate, says `locked`, and holds it until stdin closes. Profile
/// delete, reset and migration run under it. Confined to the identity
/// directory and its gate (design 0017, "Steps", D7-2).
fn hold_lock(data_dir: &std::path::Path, lock_dir: &std::path::Path) -> Exit {
    let gate = match gate::acquire(data_dir, lock_dir) {
        Ok(gate) => gate,
        Err(e) => {
            log::error(
                "cannot take the gate",
                serde_json::json!({ "error": e.to_string() }),
            );
            return Exit::from(&e);
        }
    };
    let policy = confine::policy(vec![gate.identity_dir.clone()], gate.descriptors());
    if let Err(exit) = confine::apply(&policy, "hold-lock confined") {
        return exit;
    }
    log::init();
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(b"locked\n")
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return Exit::Internal;
    }
    let mut sink = [0u8; 4096];
    let mut stdin = std::io::stdin().lock();
    while matches!(stdin.read(&mut sink), Ok(n) if n > 0) {}
    Exit::Ok
}

/// Takes the gate and completes interrupted node-identity journals, for
/// JS-backend builds before they start nodes, and the vault's delete and
/// metadata journals. Confined (design 0017, "Steps", D7-2) to the identity
/// directory, its gate, and what C6's plan names: the roots of a pending
/// record that exist (a committed Radicle journal's home made), with each
/// planned Radicle home's gate file, opened before (C3).
fn recover(data_dir: &std::path::Path, lock_dir: &std::path::Path) -> Exit {
    let gate = match gate::acquire(data_dir, lock_dir) {
        Ok(gate) => gate,
        Err(e) => {
            log::error(
                "cannot take the gate",
                serde_json::json!({ "error": e.to_string() }),
            );
            return Exit::from(&e);
        }
    };
    // The identity directory's entry in its parent, flushed as at `serve`'s
    // start: recovery writes the vault's records in it.
    if let Err(e) = journal::sync_parent(&gate.identity_dir) {
        log::error(
            "cannot flush the identity directory in its parent",
            serde_json::json!({ "error": e.kind().to_string() }),
        );
        return Exit::Storage;
    }
    let prepared = journal::prepare(&gate.identity_dir, lock_dir, None);
    let mut read_write = vec![gate.identity_dir.clone()];
    read_write.extend(prepared.grant.iter().cloned());
    let mut descriptors = gate.descriptors();
    descriptors.extend(prepared.gates.descriptors());
    if let Err(exit) = confine::apply(
        &confine::policy(read_write, descriptors),
        "recover confined",
    ) {
        return exit;
    }
    log::init();
    // A vault delete's journal a core left is finished first, as at the
    // core's own start (design 0013, "Forgetting an item").
    if let Err(e) = delete_journal::startup(data_dir) {
        log::error(
            "vault delete recovery failed",
            serde_json::json!({ "error": e.kind().to_string() }),
        );
        return Exit::Storage;
    }
    // Then a vault write's metadata journal (design 0013, "The vault and
    // its metadata, one write"), as at the core's own start.
    if let Err(e) = vault_meta_journal::startup(data_dir) {
        log::error(
            "vault write recovery failed",
            serde_json::json!({ "error": e.kind().to_string() }),
        );
        return Exit::Storage;
    }
    // Roll any interrupted node identity write forward (design 0001,
    // "Multi-file writes"). JS-backend builds run this at startup. A Radicle
    // journal waits for its home's gate, as long as 0001's retries allow;
    // still held, the journal stays, and the exit is 75 (design 0008).
    let gates = journal::Gates {
        lock_dir: lock_dir.to_owned(),
        retry: fc_service::gate::CONTENTION_RETRY,
        held: None,
        held_identity: None,
        files: prepared.gates,
    };
    let line = match journal::recover(data_dir, &gates) {
        Ok(journal::Recovered::Waiting { node, .. }) => {
            log::error(
                "node identity recovery waits for the node's gate",
                serde_json::json!({ "node": node }),
            );
            return Exit::LockHeld;
        }
        Ok(journal::Recovered::Finished {
            op_id,
            status: journal::OpStatus::Corrupt,
            ..
        }) => format!("corrupt {op_id}\n"),
        Ok(journal::Recovered::Invalid) => "corrupt -\n".to_owned(),
        Ok(_) => "recovered\n".to_owned(),
        Err(e) => {
            log::error(
                "node identity recovery failed",
                serde_json::json!({ "error": e.kind().to_string() }),
            );
            return Exit::Storage;
        }
    };
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(line.as_bytes())
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return Exit::Internal;
    }
    Exit::Ok
}
