//! The lifetime lock ("gate") from design 0001.
//!
//! - **Location:** `<lock-dir>/<sha256(canonical identity dir)>.lock`. The
//!   lock directory is a per-user directory every Freedom build shares and
//!   never deletes, so deleting or recreating the identity directory can't
//!   affect the gate.
//! - **Mechanism:** an OS lock (`flock`, `LockFileEx`) held for the life of
//!   the process. The lock file is never truncated, renamed or unlinked.
//! - **Storage qualification:** independent of locking. Known network
//!   filesystems are refused, because a lock there may not exclude other
//!   hosts.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// How long contention is retried. Windows can release a lock a little
/// after the owning process exits.
const CONTENTION_RETRY: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum GateError {
    /// Another process holds the gate (exit 75).
    Held,
    /// The identity or lock directory is on a network filesystem (exit 74).
    NetworkFilesystem(String),
    /// Any other storage failure (exit 74).
    Storage(std::io::Error),
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::Held => f.write_str("another process holds the identity directory's lock"),
            GateError::NetworkFilesystem(fs) => write!(f, "refusing network filesystem {fs}"),
            GateError::Storage(e) => write!(f, "storage error: {e}"),
        }
    }
}

/// A held gate. Dropping it (or exiting) releases the OS lock.
#[derive(Debug)]
pub struct Gate {
    _file: File,
    pub lock_path: PathBuf,
}

/// Qualifies storage, then takes the gate for `identity_dir`, retrying on
/// contention for up to 5 s.
pub fn acquire(identity_dir: &Path, lock_dir: &Path) -> Result<Gate, GateError> {
    std::fs::create_dir_all(identity_dir).map_err(GateError::Storage)?;
    std::fs::create_dir_all(lock_dir).map_err(GateError::Storage)?;
    let identity_dir = std::fs::canonicalize(identity_dir).map_err(GateError::Storage)?;
    let lock_dir = std::fs::canonicalize(lock_dir).map_err(GateError::Storage)?;
    for dir in [&identity_dir, &lock_dir] {
        if let Some(fs) = crate::storage::network_filesystem(dir) {
            return Err(GateError::NetworkFilesystem(fs));
        }
    }

    let lock_path = lock_dir.join(lock_file_name(&identity_dir));
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
            Ok(()) => {
                return Ok(Gate {
                    _file: file,
                    lock_path,
                });
            }
            Err(TryLockError::WouldBlock) if started.elapsed() < CONTENTION_RETRY => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(TryLockError::WouldBlock) => return Err(GateError::Held),
            Err(TryLockError::Error(e)) => return Err(GateError::Storage(e)),
        }
    }
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
