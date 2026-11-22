//! A gate over an open file, confined (design 0017, C3): opened before
//! `confine`, with its lock directory outside every grant, its descriptor
//! registered, then locked through that descriptor alone once confined.
//! Shared by each OS's confined child; the lines are the same `OK`/`FAIL`
//! checks.

#![allow(clippy::print_stdout, clippy::unwrap_used)]

use std::path::Path;
use std::time::{Duration, Instant};

use fc_service::gate::{self, CONTENTION_RETRY, GateError, GateFile};

const NAMESPACE: &str = "radicle";

fn check(name: &str, ok: bool) {
    println!("{} {name}", if ok { "OK" } else { "FAIL" });
}

/// Two gate files on one lock file, each opened on its own (two open files,
/// as two processes would hold), before `confine`: `home` is made in a
/// read-write grant, `locks` outside every grant.
pub fn open(home: &Path, locks: &Path) -> (GateFile, GateFile) {
    let first = GateFile::open(home, locks, NAMESPACE).unwrap();
    let second = GateFile::open_existing(home, locks, NAMESPACE).unwrap();
    (first, second)
}

/// Once confined: a gate taken through the descriptor kept, a second opener
/// held after its retry, the gate let go and taken by the second, then
/// taken again through the first.
pub fn exercise(first: &GateFile, second: &GateFile) {
    let gate = first.lock(CONTENTION_RETRY);
    check(
        "a gate taken through the descriptor kept, confined",
        gate.as_ref().is_ok_and(|gate| {
            gate.data_dir == first.data_dir() && gate.lock_path == first.lock_path()
        }),
    );
    let started = Instant::now();
    let contended = second.lock(Duration::from_millis(300));
    check(
        "a second opener waits its retry, then is held",
        matches!(contended, Err(GateError::Held))
            && started.elapsed() >= Duration::from_millis(300),
    );
    check(
        "the same open file is held too",
        matches!(first.lock(Duration::ZERO), Err(GateError::Held)),
    );
    drop(gate);
    let taken = second.lock(CONTENTION_RETRY);
    check("the second takes it once let go", taken.is_ok());
    check(
        "the first is then held",
        matches!(first.lock(Duration::ZERO), Err(GateError::Held)),
    );
    drop(taken);
    let again = first.lock(CONTENTION_RETRY);
    check("taken again through the first", again.is_ok());
}

/// Linux and macOS: the lock directory stays out of reach by path once
/// confined. Nothing new is made there, the lock file can't be opened or
/// removed by its name, and no gate can be taken by path.
#[cfg_attr(windows, allow(dead_code))]
pub fn lock_dir_refused(home: &Path, locks: &Path, lock_path: &Path) {
    check(
        "a new file in the lock directory refused",
        std::fs::write(locks.join("another.lock"), b"").is_err(),
    );
    check(
        "the lock file by its path refused",
        std::fs::File::open(lock_path).is_err(),
    );
    check(
        "a gate by path refused",
        gate::acquire_existing(home, locks, NAMESPACE, Duration::ZERO).is_err(),
    );
    check(
        "removing the lock file refused",
        std::fs::remove_file(lock_path).is_err(),
    );
}
