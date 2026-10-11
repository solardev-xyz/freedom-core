//! The lifetime lock ("gate") from design 0001.
//!
//! - **Location:** `<lock-dir>/<sha256(canonical identity dir)>.lock`. The
//!   lock directory is a per-user directory every Freedom build shares and
//!   never deletes. It must not be the identity directory or inside it,
//!   because deleting the identity directory would then delete the gate.
//! - **Mechanism:** an OS lock (`flock`, `LockFileEx`) held for the life of
//!   the process. The lock file is never truncated, renamed or unlinked.
//! - **Storage qualification:** independent of locking. Known network
//!   filesystems are refused, and so is storage that can't be inspected.
//! - **One directory:** the core works only in the canonical identity
//!   directory whose gate it holds. The path is resolved again after locking,
//!   and a change (a retargeted symlink) is refused.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::storage::{self, Qualification};

/// How long contention is retried. Windows can release a lock a little
/// after the owning process exits.
const CONTENTION_RETRY: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum GateError {
    /// Another process holds the gate (exit 75).
    Held,
    /// The lock or identity directory is on a network filesystem, or can't
    /// be inspected (exit 74).
    Unqualified(String),
    /// The lock directory is the identity directory or inside it (exit 74).
    LockInsideIdentity,
    /// The identity directory resolved differently after locking (exit 74).
    Moved,
    /// Any other storage failure (exit 74).
    Storage(std::io::Error),
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::Held => f.write_str("another process holds the identity directory's lock"),
            GateError::Unqualified(reason) => write!(f, "refusing storage: {reason}"),
            GateError::LockInsideIdentity => {
                f.write_str("the lock directory must be outside the identity directory")
            }
            GateError::Moved => f.write_str("the identity directory changed while taking its lock"),
            GateError::Storage(e) => write!(f, "storage error: {}", e.kind()),
        }
    }
}

/// A held gate. Dropping it (or exiting) releases the OS lock.
#[derive(Debug)]
pub struct Gate {
    _file: File,
    pub lock_path: PathBuf,
    /// The canonical identity directory. Every operation uses this path.
    pub identity_dir: PathBuf,
}

/// Qualifies storage, then takes the gate for `identity_dir`, retrying on
/// contention for up to 5 s.
pub fn acquire(identity_dir: &Path, lock_dir: &Path) -> Result<Gate, GateError> {
    std::fs::create_dir_all(identity_dir).map_err(GateError::Storage)?;
    std::fs::create_dir_all(lock_dir).map_err(GateError::Storage)?;
    let canonical_identity = std::fs::canonicalize(identity_dir).map_err(GateError::Storage)?;
    let canonical_locks = std::fs::canonicalize(lock_dir).map_err(GateError::Storage)?;
    if canonical_locks.starts_with(&canonical_identity) {
        return Err(GateError::LockInsideIdentity);
    }
    for dir in [&canonical_identity, &canonical_locks] {
        match storage::qualify(dir) {
            Qualification::Local => {}
            Qualification::Network(fs) => {
                return Err(GateError::Unqualified(format!("network filesystem {fs}")));
            }
            Qualification::Unknown(reason) => return Err(GateError::Unqualified(reason)),
        }
    }

    let lock_path = canonical_locks.join(lock_file_name(&canonical_identity));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(GateError::Storage)?;
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(TryLockError::WouldBlock) if started.elapsed() < CONTENTION_RETRY => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(TryLockError::WouldBlock) => return Err(GateError::Held),
            Err(TryLockError::Error(e)) => return Err(GateError::Storage(e)),
        }
    }
    // Resolve again under the lock: if the path now points elsewhere, this
    // gate doesn't protect the directory we would be using.
    if std::fs::canonicalize(identity_dir).map_err(GateError::Storage)? != canonical_identity {
        return Err(GateError::Moved);
    }
    Ok(Gate {
        _file: file,
        lock_path,
        identity_dir: canonical_identity,
    })
}

/// The lock file's name: the SHA-256 of the canonical identity directory, so
/// every path alias of one directory maps to one gate.
pub fn lock_file_name(canonical_identity_dir: &Path) -> String {
    let digest = Sha256::digest(canonical_identity_dir.as_os_str().as_encoded_bytes());
    let mut name = String::with_capacity(69);
    for byte in digest {
        name.push_str(&format!("{byte:02x}"));
    }
    name.push_str(".lock");
    name
}
