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
//! - **Private (Unix, #84):** `flock` works on a read-only handle, so anyone
//!   who can open the lock file can hold the gate and keep every core from
//!   starting. The lock and identity directories are created `0700`, and
//!   existing ones lose their group and other bits; the lock file is created
//!   `0600` (never through a symlink), and an existing one is tightened to
//!   it. A directory or lock file that isn't the user's own is refused
//!   (exit 74). Windows: both inherit the per-user `%APPDATA%` ACL, as the
//!   vault does.

use std::fs::{File, TryLockError};
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
    /// The lock or identity directory, or the lock file, isn't the user's
    /// own, or isn't what it should be (exit 74).
    #[cfg_attr(not(unix), allow(dead_code))]
    NotPrivate(&'static str),
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
            GateError::NotPrivate(what) => write!(f, "refusing {what}"),
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
    create_private_dir(identity_dir).map_err(GateError::Storage)?;
    create_private_dir(lock_dir).map_err(GateError::Storage)?;
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
    make_private(
        &canonical_identity,
        "an identity directory that isn't the user's own",
    )?;
    make_private(
        &canonical_locks,
        "a lock directory that isn't the user's own",
    )?;

    let lock_path = canonical_locks.join(lock_file_name(&canonical_identity));
    let file = open_lock_file(&lock_path)?;
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

/// Creates `dir` and its missing ancestors, private to the user on Unix
/// (`0700`, less the umask).
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Unix: `dir` (canonical) must be a directory the user owns; its group and
/// other permission bits are removed (#84).
#[cfg(unix)]
fn make_private(dir: &Path, foreign: &'static str) -> Result<(), GateError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // Judged and changed through one handle, never by path twice.
    let handle = File::open(dir).map_err(GateError::Storage)?;
    let metadata = handle.metadata().map_err(GateError::Storage)?;
    if !metadata.is_dir() {
        return Err(GateError::NotPrivate(
            "a lock or identity path that isn't a directory",
        ));
    }
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(GateError::NotPrivate(foreign));
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o077 != 0 {
        handle
            .set_permissions(std::fs::Permissions::from_mode(mode & 0o7700))
            .map_err(GateError::Storage)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_private(_dir: &Path, _foreign: &'static str) -> Result<(), GateError> {
    Ok(())
}

/// Opens (creating it if needed, never truncating it) the lock file. Unix:
/// created `0600`, never through a symlink, and it must be a regular file the
/// user owns, tightened to `0600` if it is wider (#84).
#[cfg(unix)]
fn open_lock_file(path: &Path) -> Result<File, GateError> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let flags =
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = rustix::fs::open(path, flags, Mode::RUSR | Mode::WUSR)
        .map_err(|e| GateError::Storage(e.into()))?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(GateError::Storage)?;
    if !metadata.is_file() {
        return Err(GateError::NotPrivate(
            "a lock file that isn't a regular file",
        ));
    }
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(GateError::NotPrivate(
            "a lock file that isn't the user's own",
        ));
    }
    if metadata.mode() & 0o777 != 0o600 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(GateError::Storage)?;
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_lock_file(path: &Path) -> Result<File, GateError> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(GateError::Storage)
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
