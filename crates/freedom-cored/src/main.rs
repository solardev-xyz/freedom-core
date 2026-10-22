//! `freedom-cored`: the desktop core process (design 0001).
//!
//! ```text
//! freedom-cored serve     --data-dir <identity dir> --lock-dir <lock dir> [--parent-pid <pid>]
//! freedom-cored hold-lock --data-dir <identity dir> --lock-dir <lock dir>
//! freedom-cored recover   --data-dir <identity dir> --lock-dir <lock dir>
//! ```

mod chain;
mod clock;
mod exit;
mod fsx;
mod gate;
mod hardening;
mod journal;
mod log;
mod naming;
mod nodes;
mod requests;
mod rng;
mod serve;
mod signing;
mod storage;
mod testhooks;
// Debug builds only: release builds carry no test methods at all.
#[cfg(debug_assertions)]
mod testmethods;
mod transport;
mod vault;
mod worker;

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use exit::Exit;

const USAGE: &str = "usage: freedom-cored <serve|hold-lock|recover> --data-dir <dir> --lock-dir <dir> [--parent-pid <pid>]";

struct Args {
    command: String,
    data_dir: Option<PathBuf>,
    lock_dir: Option<PathBuf>,
    parent_pid: Option<u32>,
    hello_timeout_ms: u64,
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
    };
    while let Some(flag) = args.next() {
        let value = args.next()?;
        match flag.to_str()? {
            "--data-dir" => parsed.data_dir = Some(PathBuf::from(value)),
            "--lock-dir" => parsed.lock_dir = Some(PathBuf::from(value)),
            "--parent-pid" => parsed.parent_pid = Some(value.to_str()?.parse().ok()?),
            // For tests; main never passes it.
            "--hello-timeout-ms" => parsed.hello_timeout_ms = value.to_str()?.parse().ok()?,
            _ => return None,
        }
    }
    Some(parsed)
}

fn main() -> ExitCode {
    let started = Instant::now();
    log::init();
    let exit = run(started);
    log::finish(Duration::from_millis(500));
    ExitCode::from(exit.code())
}

fn run(started: Instant) -> Exit {
    let Some(args) = parse_args() else {
        log::error(USAGE, serde_json::json!({}));
        return Exit::Usage;
    };
    let (Some(data_dir), Some(lock_dir)) = (args.data_dir, args.lock_dir) else {
        log::error(USAGE, serde_json::json!({}));
        return Exit::Usage;
    };
    match args.command.as_str() {
        "serve" => serve::run(&serve::Options {
            data_dir,
            lock_dir,
            parent_pid: args.parent_pid,
            hello_timeout: Duration::from_millis(args.hello_timeout_ms),
            started,
        }),
        "hold-lock" => hold_lock(&data_dir, &lock_dir),
        "recover" => recover(&data_dir, &lock_dir),
        _ => {
            log::error(USAGE, serde_json::json!({}));
            Exit::Usage
        }
    }
}

/// Takes the gate, says `locked`, and holds it until stdin closes. Profile
/// delete, reset and migration run under it.
fn hold_lock(data_dir: &std::path::Path, lock_dir: &std::path::Path) -> Exit {
    let _gate = match gate::acquire(data_dir, lock_dir) {
        Ok(gate) => gate,
        Err(e) => {
            log::error(
                "cannot take the gate",
                serde_json::json!({ "error": e.to_string() }),
            );
            return Exit::from(&e);
        }
    };
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
/// JS-backend builds before they start nodes. Node writes arrive in a later
/// PR, so there is nothing to recover yet.
fn recover(data_dir: &std::path::Path, lock_dir: &std::path::Path) -> Exit {
    let _gate = match gate::acquire(data_dir, lock_dir) {
        Ok(gate) => gate,
        Err(e) => {
            log::error(
                "cannot take the gate",
                serde_json::json!({ "error": e.to_string() }),
            );
            return Exit::from(&e);
        }
    };
    // Roll any interrupted node identity write forward (design 0001,
    // "Multi-file writes"). JS-backend builds run this at startup.
    let line = match journal::recover(data_dir) {
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
