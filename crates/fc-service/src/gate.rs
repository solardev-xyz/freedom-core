//! The lifetime lock ("gate"), on 0001's rules with a namespace per service
//! (design 0007, "Lifetime lock"; 0008, "Spawn and lock").
//!
//! - **Location:** `<lock-dir>/<namespace>-<sha256(canonical data dir)>.lock`,
//!   for example `ipfs-…` for freedom-ipfsd and `radicle-…` for
//!   freedom-radicled. The namespace keeps each service's gate apart from
//!   the core's (`<sha256>.lock`, no prefix) and from each other's, even if
//!   one directory were given to two of them.
//! - **The lock directory** is the stable one every Freedom build shares. It
//!   must not be the data directory or inside it.
//! - **Mechanism:** an OS lock (`flock`, `LockFileEx`) held for the life of
//!   the process. The lock file is never truncated, renamed or unlinked.
//! - **Storage qualification:** known network filesystems are refused, and
//!   so is storage that can't be inspected (exit 74).
//! - **Contention** is retried for 5 s, then exits 75 (`lock_held`).
//! - **One directory:** the data directory is resolved again after locking,
//!   and a change (a retargeted symlink) is refused.
//! - **Private (Unix; 0001, freedom-core#84):** `flock` works on a read-only
//!   handle, so anyone who can open a lock file can hold the gate. The lock
//!   and data directories are created `0700`, and existing ones lose their
//!   group and other bits; the lock file is created `0600` (never through a
//!   symlink), and an existing one is tightened to it. A directory or lock
//!   file that isn't the user's own is refused (exit 74).

use std::fs::{File, TryLockError};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::exit::Exit;
use crate::storage::{self, Qualification};

/// How long contention is retried. Windows can release a lock a little
/// after the owning process exits.
pub const CONTENTION_RETRY: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum GateError {
    /// Another process holds the gate (exit 75).
    Held,
    /// The lock or data directory is on a network filesystem, or can't be
    /// inspected (exit 74).
    Unqualified(String),
    /// The lock directory is the data directory or inside it (exit 74).
    LockInsideData,
    /// The data directory resolved differently after locking (exit 74).
    Moved,
    /// The lock or data directory, or the lock file, isn't the user's own,
    /// or isn't what it should be (exit 74).
    #[cfg_attr(not(unix), allow(dead_code))]
    NotPrivate(&'static str),
    /// Any other storage failure (exit 74).
    Storage(std::io::Error),
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::Held => f.write_str("another process holds the data directory's lock"),
            GateError::Unqualified(reason) => write!(f, "refusing storage: {reason}"),
            GateError::LockInsideData => {
                f.write_str("the lock directory must be outside the data directory")
            }
            GateError::Moved => f.write_str("the data directory changed while taking its lock"),
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
    /// The canonical data directory. Every operation uses this path.
    pub data_dir: PathBuf,
}

/// Qualifies storage, then takes `namespace`'s gate for `data_dir`,
/// retrying on contention for up to `retry` (0001: 5 s).
pub fn acquire(
    data_dir: &Path,
    lock_dir: &Path,
    namespace: &str,
    retry: Duration,
) -> Result<Gate, GateError> {
    create_private_dir(data_dir).map_err(GateError::Storage)?;
    create_private_dir(lock_dir).map_err(GateError::Storage)?;
    let canonical_data = std::fs::canonicalize(data_dir).map_err(GateError::Storage)?;
    let canonical_locks = std::fs::canonicalize(lock_dir).map_err(GateError::Storage)?;
    if canonical_locks.starts_with(&canonical_data) {
        return Err(GateError::LockInsideData);
    }
    for dir in [&canonical_data, &canonical_locks] {
        match storage::qualify(dir) {
            Qualification::Local => {}
            Qualification::Network(fs) => {
                return Err(GateError::Unqualified(format!("network filesystem {fs}")));
            }
            Qualification::Unknown(reason) => return Err(GateError::Unqualified(reason)),
        }
    }
    make_private(
        &canonical_data,
        "a data directory that isn't the user's own",
    )?;
    make_private(
        &canonical_locks,
        "a lock directory that isn't the user's own",
    )?;

    let lock_path = canonical_locks.join(lock_file_name(namespace, &canonical_data));
    let file = open_lock_file(&lock_path)?;
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(TryLockError::WouldBlock) if started.elapsed() < retry => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(TryLockError::WouldBlock) => return Err(GateError::Held),
            Err(TryLockError::Error(e)) => return Err(GateError::Storage(e)),
        }
    }
    // Resolve again under the lock: if the path now points elsewhere, this
    // gate doesn't protect the directory we would be using.
    if std::fs::canonicalize(data_dir).map_err(GateError::Storage)? != canonical_data {
        return Err(GateError::Moved);
    }
    Ok(Gate {
        _file: file,
        lock_path,
        data_dir: canonical_data,
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
/// other permission bits are removed.
#[cfg(unix)]
fn make_private(dir: &Path, foreign: &'static str) -> Result<(), GateError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // Judged and changed through one handle, never by path twice.
    let handle = File::open(dir).map_err(GateError::Storage)?;
    let metadata = handle.metadata().map_err(GateError::Storage)?;
    if !metadata.is_dir() {
        return Err(GateError::NotPrivate(
            "a lock or data path that isn't a directory",
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
/// user owns, tightened to `0600` if it is wider.
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

/// The lock file's name: the namespace, then the SHA-256 of the canonical
/// data directory, so every path alias of one directory maps to one gate.
pub fn lock_file_name(namespace: &str, canonical_data_dir: &Path) -> String {
    let digest = Sha256::digest(canonical_data_dir.as_os_str().as_encoded_bytes());
    let mut name = String::with_capacity(namespace.len() + 70);
    name.push_str(namespace);
    name.push('-');
    for byte in digest {
        name.push_str(&format!("{byte:02x}"));
    }
    name.push_str(".lock");
    name
}

/// The `hold-lock` subcommand (0001): takes the gate, writes `locked`, and
/// holds it until `input` closes. Profile delete, reset and the services'
/// own resets run under it.
///
/// Only a real EOF releases the gate with exit 0. An interrupted read is
/// retried; any other read error releases it with exit 70, which main
/// treats as a failed hold.
pub fn hold_lock(
    data_dir: &Path,
    lock_dir: &Path,
    namespace: &str,
    mut input: impl Read,
    mut output: impl Write,
) -> Exit {
    let _gate = match acquire(data_dir, lock_dir, namespace, CONTENTION_RETRY) {
        Ok(gate) => gate,
        Err(e) => {
            crate::log::error(
                "cannot take the gate",
                serde_json::json!({ "error": e.to_string() }),
            );
            return Exit::from(&e);
        }
    };
    if output
        .write_all(b"locked\n")
        .and_then(|()| output.flush())
        .is_err()
    {
        return Exit::Internal;
    }
    let mut sink = [0u8; 4096];
    loop {
        match input.read(&mut sink) {
            Ok(0) => return Exit::Ok,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                crate::log::error(
                    "cannot read stdin while holding the gate",
                    serde_json::json!({ "error": e.kind().to_string() }),
                );
                return Exit::Internal;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let locks = root.path().join("locks");
        (root, data, locks)
    }

    #[test]
    fn a_second_owner_is_refused_and_released_on_drop() {
        let (_root, data, locks) = dirs();
        let gate = acquire(&data, &locks, "ipfs", CONTENTION_RETRY).unwrap();
        let name = gate
            .lock_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(
            name.starts_with("ipfs-") && name.ends_with(".lock"),
            "{name}"
        );
        assert_eq!(name.len(), "ipfs-".len() + 64 + ".lock".len());
        assert!(matches!(
            acquire(&data, &locks, "ipfs", Duration::from_millis(200)),
            Err(GateError::Held)
        ));
        // Another namespace is another gate.
        let other = acquire(&data, &locks, "radicle", Duration::ZERO).unwrap();
        assert_ne!(other.lock_path, gate.lock_path);
        drop(gate);
        // Other tests in this binary spawn children: one spawned while the
        // gate was held keeps a copy of its descriptor, and so the lock,
        // until it execs. Released means acquirable within the retry, here
        // and in every other test that reacquires after a release.
        assert!(acquire(&data, &locks, "ipfs", CONTENTION_RETRY).is_ok());
    }

    #[test]
    fn aliases_share_one_gate() {
        let (root, data, locks) = dirs();
        std::fs::create_dir_all(&data).unwrap();
        let alias = root.path().join("data/../data");
        let gate = acquire(&data, &locks, "ipfs", Duration::ZERO).unwrap();
        assert!(matches!(
            acquire(&alias, &locks, "ipfs", Duration::ZERO),
            Err(GateError::Held)
        ));
        assert_eq!(gate.data_dir, std::fs::canonicalize(&data).unwrap());
    }

    #[test]
    fn the_lock_directory_must_be_outside_the_data_directory() {
        let (_root, data, _) = dirs();
        let inside = data.join("locks");
        assert!(matches!(
            acquire(&data, &inside, "ipfs", Duration::ZERO),
            Err(GateError::LockInsideData)
        ));
        assert!(matches!(
            acquire(&data, &data, "ipfs", Duration::ZERO),
            Err(GateError::LockInsideData)
        ));
    }

    /// freedom-core#84: another user who can open the lock file can hold
    /// the gate (`flock` works on a read-only handle). Directories are
    /// private, the lock file `0600`, existing ones tightened.
    #[cfg(unix)]
    #[test]
    fn the_gate_is_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        let (root, data, locks) = dirs();
        let gate = acquire(&data, &locks, "ipfs", Duration::ZERO).unwrap();
        assert_eq!(mode(&data), 0o700);
        assert_eq!(mode(&locks), 0o700);
        assert_eq!(mode(&gate.lock_path), 0o600);
        drop(gate);

        // What an earlier build, or the default umask, left wider.
        let set = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let lock_path = locks.join(lock_file_name(
            "ipfs",
            &std::fs::canonicalize(&data).unwrap(),
        ));
        set(&data, 0o755);
        set(&locks, 0o777);
        set(&lock_path, 0o644);
        // A reacquire after a release retries (see the release test).
        let gate = acquire(&data, &locks, "ipfs", CONTENTION_RETRY).unwrap();
        assert_eq!(mode(&data), 0o700);
        assert_eq!(mode(&locks), 0o700);
        assert_eq!(mode(&gate.lock_path), 0o600);
        drop(gate);

        // A symlink in the lock file's place is never followed.
        std::fs::remove_file(&lock_path).unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::write(&elsewhere, b"").unwrap();
        set(&elsewhere, 0o644);
        std::os::unix::fs::symlink(&elsewhere, &lock_path).unwrap();
        assert!(acquire(&data, &locks, "ipfs", Duration::ZERO).is_err());
        assert_eq!(mode(&elsewhere), 0o644);
    }

    /// Someone else's lock directory is refused. Only root can make one.
    #[cfg(unix)]
    #[test]
    fn a_lock_directory_of_another_user_is_refused() {
        if !rustix::process::getuid().is_root() {
            return;
        }
        let (_root, data, locks) = dirs();
        std::fs::create_dir_all(&locks).unwrap();
        // Some sandboxes map no UID 65534 (EINVAL): nothing to check there.
        if std::os::unix::fs::chown(&locks, Some(65534), None).is_err() {
            return;
        }
        assert!(matches!(
            acquire(&data, &locks, "ipfs", Duration::ZERO),
            Err(GateError::NotPrivate(_))
        ));
    }

    #[test]
    fn hold_lock_says_locked_and_holds_until_eof() {
        let (_root, data, locks) = dirs();
        let (reader, writer) = std::io::pipe().unwrap();
        let (data2, locks2) = (data.clone(), locks.clone());
        let mut said = Vec::new();
        let holder = std::thread::spawn(move || {
            let mut out = Vec::new();
            let exit = hold_lock(&data2, &locks2, "ipfs", reader, &mut out);
            (exit, out)
        });
        // While it holds the gate, nobody else gets it.
        let deadline = Instant::now() + Duration::from_secs(5);
        while acquire(&data, &locks, "ipfs", Duration::ZERO).is_ok() {
            assert!(Instant::now() < deadline, "hold-lock never took the gate");
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(writer);
        let (exit, out) = holder.join().unwrap();
        said.extend(out);
        assert_eq!((exit, said.as_slice()), (Exit::Ok, &b"locked\n"[..]));
        assert!(acquire(&data, &locks, "ipfs", CONTENTION_RETRY).is_ok());
    }

    /// A stdin that fails its first read with `kind`, then reads `inner`.
    struct FailsOnce<R> {
        inner: R,
        kind: Option<std::io::ErrorKind>,
    }

    impl<R: Read> Read for FailsOnce<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.kind.take() {
                Some(kind) => Err(kind.into()),
                None => self.inner.read(buf),
            }
        }
    }

    #[test]
    fn an_interrupted_read_is_not_eof() {
        let (_root, data, locks) = dirs();
        let (reader, writer) = std::io::pipe().unwrap();
        let (data2, locks2) = (data.clone(), locks.clone());
        let (said_tx, said) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let input = FailsOnce {
                inner: reader,
                kind: Some(std::io::ErrorKind::Interrupted),
            };
            struct Said(std::sync::mpsc::Sender<Vec<u8>>);
            impl Write for Said {
                fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                    let _ = self.0.send(buf.to_vec());
                    Ok(buf.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            hold_lock(&data2, &locks2, "ipfs", input, Said(said_tx))
        });
        assert_eq!(said.recv().unwrap(), b"locked\n");
        // Still held after the interruption, while stdin is open.
        std::thread::sleep(Duration::from_millis(200));
        assert!(!holder.is_finished());
        assert!(matches!(
            acquire(&data, &locks, "ipfs", Duration::ZERO),
            Err(GateError::Held)
        ));
        drop(writer);
        assert_eq!(holder.join().unwrap(), Exit::Ok);
    }

    #[test]
    fn a_failed_read_releases_the_gate_with_exit_70() {
        let (_root, data, locks) = dirs();
        let input = FailsOnce {
            inner: std::io::empty(),
            kind: Some(std::io::ErrorKind::BrokenPipe),
        };
        let exit = hold_lock(&data, &locks, "ipfs", input, Vec::new());
        assert_eq!(exit, Exit::Internal);
        assert!(acquire(&data, &locks, "ipfs", CONTENTION_RETRY).is_ok());
    }

    #[test]
    fn a_held_gate_makes_hold_lock_exit_75() {
        let (_root, data, locks) = dirs();
        let _gate = acquire(&data, &locks, "ipfs", Duration::ZERO).unwrap();
        // Held for the whole retry window (5 s): the exit is lock_held.
        let started = Instant::now();
        let exit = hold_lock(&data, &locks, "ipfs", std::io::empty(), Vec::new());
        assert_eq!(exit, Exit::LockHeld);
        assert!(started.elapsed() >= CONTENTION_RETRY);
    }
}
