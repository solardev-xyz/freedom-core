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
//! - **Over an open file (design 0017, C3):** a confined process can't
//!   reach the lock directory, which holds every profile's gates, so it
//!   opens a gate's file before confining itself and locks it later.
//!   [`GateFile::open`] and [`GateFile::open_existing`] do what [`acquire`]
//!   and [`acquire_existing`] do before locking (the directories made, or
//!   required; both resolved; the lock directory outside the data
//!   directory; storage qualified; both the user's own; the lock file
//!   opened, created `0600` or tightened, at `lock_file_name`'s path), and
//!   lock nothing. [`GateFile::lock`] then takes that file's lock with the
//!   same retry and contention, and resolves the data directory again
//!   under it, with nothing opened in the lock directory. The [`Gate`] it
//!   returns unlocks the file when dropped and leaves it open, for the next
//!   lock. The file's descriptor crosses `confine`
//!   ([`GateFile::descriptors`]). Within one process, gates over one file
//!   contend as two processes' do: `flock` alone would let a second lock
//!   through one open file, so the file also records that it is locked.

use std::ffi::OsStr;
use std::fs::{File, TryLockError};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::confine::OpenDir;
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
    holder: Holder,
    pub lock_path: PathBuf,
    /// The canonical data directory. Every operation uses this path.
    pub data_dir: PathBuf,
    /// The data directory's identity once the lock is held: the directory
    /// this gate was taken for. A caller that opens it later can tell it
    /// from another directory moved into its path meanwhile. `None` where
    /// std exposes no file identity (Windows).
    pub identity: Option<DirIdentity>,
}

impl Gate {
    /// The descriptors the gate holds open, which cross `confine`
    /// ([`crate::confine::Policy::descriptors`]): the lock's, on Unix.
    /// Empty elsewhere.
    pub fn descriptors(&self) -> Vec<i32> {
        descriptors(self.holder.file())
    }
}

/// What holds a gate's lock.
#[derive(Debug)]
enum Holder {
    /// The gate's own file: closing it releases the lock.
    Own(File),
    /// A [`GateFile`]'s file, locked for this gate.
    Shared(SharedLock),
}

impl Holder {
    fn file(&self) -> &File {
        match self {
            Holder::Own(file) => file,
            Holder::Shared(lock) => &lock.0.file,
        }
    }
}

/// A [`GateFile`]'s lock, taken: dropping it unlocks the file and keeps it
/// open.
#[derive(Debug)]
struct SharedLock(Arc<Opened>);

impl Drop for SharedLock {
    fn drop(&mut self) {
        // The OS lock first, then the record: a gate of this process that
        // took the record in between would lock the file again through the
        // same open file, and this unlock would release its lock.
        let _ = self.0.file.unlock();
        self.0.locked.store(false, Ordering::Release);
    }
}

/// `file`'s descriptor, which crosses `confine`, on Unix; none elsewhere.
fn descriptors(file: &File) -> Vec<i32> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        vec![file.as_raw_fd()]
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Vec::new()
    }
}

/// A gate's lock file, opened and checked, not locked (design 0017, C3):
/// opened before confinement, while the lock directory can be reached, and
/// locked later through the open file alone ([`GateFile::lock`]).
///
/// Clones share the one open file, and so its lock: the file closes when
/// the last clone and the last [`Gate`] taken through it are dropped.
#[derive(Debug, Clone)]
pub struct GateFile {
    opened: Arc<Opened>,
}

/// An open lock file, and the paths it was opened for.
#[derive(Debug)]
struct Opened {
    file: File,
    /// The data directory as the caller named it, resolved again under each
    /// lock.
    named: PathBuf,
    lock_path: PathBuf,
    /// The canonical data directory.
    data_dir: PathBuf,
    /// Whether a gate of this process holds the file's lock.
    locked: AtomicBool,
}

impl GateFile {
    /// [`acquire`] up to its lock: storage qualified, `data_dir` and the
    /// lock directory made if missing and private, and `namespace`'s lock
    /// file for `data_dir` opened (created `0600`, or tightened to it). No
    /// lock is taken.
    pub fn open(data_dir: &Path, lock_dir: &Path, namespace: &str) -> Result<GateFile, GateError> {
        GateFile::opened(data_dir, lock_dir, namespace, Make::Both)
    }

    /// [`acquire_existing`] up to its lock: for a `data_dir` and a
    /// `lock_dir` that must already exist, creating nothing but the lock
    /// file. No lock is taken.
    pub fn open_existing(
        data_dir: &Path,
        lock_dir: &Path,
        namespace: &str,
    ) -> Result<GateFile, GateError> {
        GateFile::opened(data_dir, lock_dir, namespace, Make::Nothing)
    }

    fn opened(
        data_dir: &Path,
        lock_dir: &Path,
        namespace: &str,
        make: Make,
    ) -> Result<GateFile, GateError> {
        let (file, lock_path, canonical_data) =
            open_with(data_dir, lock_dir, namespace, make, false)?;
        Ok(GateFile {
            opened: Arc::new(Opened {
                file,
                named: data_dir.to_path_buf(),
                lock_path,
                data_dir: canonical_data,
                locked: AtomicBool::new(false),
            }),
        })
    }

    /// Takes the gate through the open file, retrying contention for up to
    /// `retry` as [`acquire`] does (then [`GateError::Held`]). Another
    /// process's lock is contention, and so is a gate this process holds
    /// through this file or a clone of it. Under the lock, the data
    /// directory, as named at the open, is resolved again: one that resolves
    /// elsewhere now is [`GateError::Moved`], and one gone is
    /// [`GateError::Storage`] (`NotFound`); either releases the lock. Nothing
    /// is made, and nothing is opened in the lock directory.
    ///
    /// The returned gate unlocks the file when dropped, and leaves it open.
    pub fn lock(&self, retry: Duration) -> Result<Gate, GateError> {
        let opened = &self.opened;
        retry_contention(retry, || {
            if opened
                .locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                return Err(TryLockError::WouldBlock);
            }
            opened
                .file
                .try_lock()
                .inspect_err(|_| opened.locked.store(false, Ordering::Release))
        })?;
        // Released by its drop, on an error below too.
        let lock = SharedLock(Arc::clone(opened));
        let identity = resolved_under_lock(&opened.named, &opened.data_dir)?;
        Ok(Gate {
            holder: Holder::Shared(lock),
            lock_path: opened.lock_path.clone(),
            data_dir: opened.data_dir.clone(),
            identity,
        })
    }

    /// The lock file's path: `lock_file_name`'s, in the canonical lock
    /// directory.
    pub fn lock_path(&self) -> &Path {
        &self.opened.lock_path
    }

    /// The canonical data directory, as resolved at the open.
    pub fn data_dir(&self) -> &Path {
        &self.opened.data_dir
    }

    /// The descriptor of the open file, which crosses `confine`
    /// ([`crate::confine::Policy::descriptors`]), on Unix: the same one
    /// every gate taken through it holds. Empty elsewhere.
    pub fn descriptors(&self) -> Vec<i32> {
        descriptors(&self.opened.file)
    }
}

/// A directory's identity: its device and inode (Unix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirIdentity {
    pub dev: u64,
    pub ino: u64,
}

impl DirIdentity {
    /// The identity of what `metadata` describes (Unix); `None` elsewhere.
    pub fn of(metadata: &std::fs::Metadata) -> Option<DirIdentity> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Some(DirIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            None
        }
    }
}

/// Qualifies storage, then takes `namespace`'s gate for `data_dir`,
/// retrying on contention for up to `retry` (0001: 5 s). `data_dir` (and the
/// lock directory) are made if missing.
pub fn acquire(
    data_dir: &Path,
    lock_dir: &Path,
    namespace: &str,
    retry: Duration,
) -> Result<Gate, GateError> {
    acquire_with(data_dir, lock_dir, namespace, retry, Make::Both, false)
}

/// [`acquire`], for a `data_dir` and a `lock_dir` that must already exist:
/// it creates nothing. A missing directory is `GateError::Storage`
/// (`NotFound`), before any lock is taken, and neither is made, so a data
/// directory renamed away can't be made again under its old name through
/// its lock directory. The one file it may create is the gate's lock file,
/// in the existing lock directory, outside the data directory. A caller that
/// saw the directory, and must act on that one directory or on nothing,
/// compares the gate's [`Gate::identity`] with what it saw (freedom-cored's
/// intent cleanup, design 0001).
pub fn acquire_existing(
    data_dir: &Path,
    lock_dir: &Path,
    namespace: &str,
    retry: Duration,
) -> Result<Gate, GateError> {
    acquire_with(data_dir, lock_dir, namespace, retry, Make::Nothing, false)
}

/// The profile gate (design 0013, "The lock"):
/// `<lock-dir>/profile-<sha256(canonical userData)>.lock`, for a profile's
/// `userData` that must already exist, as [`acquire_existing`]. Two
/// differences:
///
/// - **The lock directory may lie inside `userData`,** as it does for the
///   packaged default profile on macOS and Windows, whose `userData` is the
///   app root holding `locks/`. That profile's delete spares `locks/` (0013,
///   "The lock directory is kept"), so the gate's file outlives it.
/// - **A missing lock directory is made,** with its missing ancestors, as
///   [`acquire`] makes it (`0700`), once `userData` has resolved: on a
///   machine no new build has run on, nothing else makes it before the first
///   launch's gate. Each missing name is made relative to its parent's
///   handle, never through a link or a replaced parent, and `userData` and
///   its ancestors never are (`create_lock_dir`): a missing `userData`, or
///   one renamed away or replaced by a link after it resolved, makes
///   nothing.
pub fn acquire_profile(
    user_data_dir: &Path,
    lock_dir: &Path,
    retry: Duration,
) -> Result<Gate, GateError> {
    acquire_with(
        user_data_dir,
        lock_dir,
        PROFILE_NAMESPACE,
        retry,
        Make::LockDir,
        true,
    )
}

/// The profile gate's namespace.
pub const PROFILE_NAMESPACE: &str = "profile";

/// Whether another process holds `namespace`'s gate for `data_dir`: its lock
/// tried without waiting and let go at once, so a holder starting meanwhile,
/// which retries contention for [`CONTENTION_RETRY`], never fails for it
/// (design 0013, "Asking the gate"). A directory, lock directory or lock
/// file that isn't there was never gated: `false`. Nothing is made.
pub fn probe(data_dir: &Path, lock_dir: &Path, namespace: &str) -> Result<bool, GateError> {
    let canonical_data = match std::fs::canonicalize(data_dir) {
        Ok(path) => path,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(GateError::Storage(e)),
    };
    let canonical_locks = match std::fs::canonicalize(lock_dir) {
        Ok(path) => path,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(GateError::Storage(e)),
    };
    let lock_path = canonical_locks.join(lock_file_name(namespace, &canonical_data));
    let file = match open_existing_lock_file(&lock_path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(GateError::Storage(e)),
    };
    match file.try_lock() {
        Ok(()) => Ok(false),
        Err(TryLockError::WouldBlock) => Ok(true),
        Err(TryLockError::Error(e)) => Err(GateError::Storage(e)),
    }
}

/// Opens an existing lock file to try its lock, never through a symlink
/// (Unix) and never creating it.
#[cfg(unix)]
fn open_existing_lock_file(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = File::from(rustix::fs::open(path, flags, Mode::empty())?);
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "a lock file that isn't a regular file",
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_existing_lock_file(path: &Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new().read(true).open(path)
}

/// What taking a gate may make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Make {
    /// The data and lock directories, with their missing ancestors
    /// ([`acquire`]).
    Both,
    /// The lock directory alone, once the data directory has resolved, and
    /// never the data directory through it ([`acquire_profile`]).
    LockDir,
    /// Nothing: both must exist ([`acquire_existing`]).
    Nothing,
}

fn acquire_with(
    data_dir: &Path,
    lock_dir: &Path,
    namespace: &str,
    retry: Duration,
    make: Make,
    lock_inside_data: bool,
) -> Result<Gate, GateError> {
    let (file, lock_path, canonical_data) =
        open_with(data_dir, lock_dir, namespace, make, lock_inside_data)?;
    lock_within(&file, retry)?;
    let identity = resolved_under_lock(data_dir, &canonical_data)?;
    Ok(Gate {
        holder: Holder::Own(file),
        lock_path,
        data_dir: canonical_data,
        identity,
    })
}

/// Everything taking a gate does before its lock: the directories made as
/// `make` says, both resolved and checked, and the lock file opened. The
/// open file, its path, and the canonical data directory.
fn open_with(
    data_dir: &Path,
    lock_dir: &Path,
    namespace: &str,
    make: Make,
    lock_inside_data: bool,
) -> Result<(File, PathBuf, PathBuf), GateError> {
    // Without `Make::Both`, the data directory must already exist: it is never
    // made, so it can't be made again in place of one renamed away.
    if make == Make::Both {
        create_private_dir(data_dir).map_err(GateError::Storage)?;
        create_private_dir(lock_dir).map_err(GateError::Storage)?;
    }
    let canonical_data = std::fs::canonicalize(data_dir).map_err(GateError::Storage)?;
    #[cfg(test)]
    tests::after_data_resolved();
    if make == Make::LockDir {
        create_lock_dir(data_dir, &canonical_data, lock_dir)?;
    }
    let canonical_locks = std::fs::canonicalize(lock_dir).map_err(GateError::Storage)?;
    if canonical_locks == canonical_data
        || (!lock_inside_data && canonical_locks.starts_with(&canonical_data))
    {
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
    Ok((file, lock_path, canonical_data))
}

/// Under a gate's lock: `data_dir`, as the caller named it, resolved again,
/// and the identity of what is at `canonical_data` now.
fn resolved_under_lock(
    data_dir: &Path,
    canonical_data: &Path,
) -> Result<Option<DirIdentity>, GateError> {
    // If the path now points elsewhere, this gate doesn't protect the
    // directory we would be using.
    if std::fs::canonicalize(data_dir).map_err(GateError::Storage)? != canonical_data {
        return Err(GateError::Moved);
    }
    // What is at the canonical path now, under the lock: the directory this
    // gate protects (a symlink there resolved differently just above).
    Ok(DirIdentity::of(
        &std::fs::symlink_metadata(canonical_data).map_err(GateError::Storage)?,
    ))
}

/// Takes `file`'s lock, retrying contention for up to `retry` (none at
/// zero).
fn lock_within(file: &File, retry: Duration) -> Result<(), GateError> {
    retry_contention(retry, || file.try_lock())
}

/// Runs `try_lock` until it takes the lock, retrying contention
/// (`WouldBlock`) for up to `retry` (none at zero), then
/// [`GateError::Held`].
fn retry_contention(
    retry: Duration,
    mut try_lock: impl FnMut() -> Result<(), TryLockError>,
) -> Result<(), GateError> {
    let started = Instant::now();
    loop {
        match try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) if started.elapsed() < retry => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(TryLockError::WouldBlock) => return Err(GateError::Held),
            Err(TryLockError::Error(e)) => return Err(GateError::Storage(e)),
        }
    }
}

/// A gate a profile delete takes on a directory it is about to remove
/// (design 0013, "Deletion"): its lock tried for `retry` (the delete's is
/// zero), with nothing made but the lock directory and the lock file, so a
/// refused delete leaves the profile as it was.
///
/// - **A `data_dir` that isn't there** is gated at the path it would have:
///   its nearest existing ancestor's canonical path with the missing names
///   below it. A holder that makes it meanwhile and takes its gate finds
///   this one held.
/// - **A `data_dir` that is a file,** as a moved identity's placeholder
///   (design 0013, "The move"), is gated at its path, and nothing is
///   tightened: no service uses a file as its directory.
/// - **`file_name`** names the lock file from that path: [`lock_file_name`]
///   with a service's namespace, or the core's own name, which has none.
/// - **`lock_inside_data`:** the lock directory may lie inside the data
///   directory, as for [`acquire_profile`].
///
/// Otherwise as [`acquire_existing`]: storage qualified, the directories
/// the user's own, and the path resolved again under the lock.
pub fn acquire_for_delete(
    data_dir: &Path,
    lock_dir: &Path,
    file_name: &dyn Fn(&Path) -> String,
    lock_inside_data: bool,
    retry: Duration,
) -> Result<Gate, GateError> {
    create_private_dir(lock_dir).map_err(GateError::Storage)?;
    let (canonical_data, existing) = planned_canonical(data_dir).map_err(GateError::Storage)?;
    let canonical_locks = std::fs::canonicalize(lock_dir).map_err(GateError::Storage)?;
    if canonical_locks == canonical_data
        || (!lock_inside_data && canonical_locks.starts_with(&canonical_data))
    {
        return Err(GateError::LockInsideData);
    }
    for dir in [&existing, &canonical_locks] {
        match storage::qualify(dir) {
            Qualification::Local => {}
            Qualification::Network(fs) => {
                return Err(GateError::Unqualified(format!("network filesystem {fs}")));
            }
            Qualification::Unknown(reason) => return Err(GateError::Unqualified(reason)),
        }
    }
    if existing == canonical_data
        && std::fs::metadata(&canonical_data).is_ok_and(|metadata| metadata.is_dir())
    {
        make_private(
            &canonical_data,
            "a data directory that isn't the user's own",
        )?;
    }
    make_private(
        &canonical_locks,
        "a lock directory that isn't the user's own",
    )?;
    let lock_path = canonical_locks.join(file_name(&canonical_data));
    let file = open_lock_file(&lock_path)?;
    lock_within(&file, retry)?;
    if planned_canonical(data_dir).map_err(GateError::Storage)?.0 != canonical_data {
        return Err(GateError::Moved);
    }
    let identity = std::fs::symlink_metadata(&canonical_data)
        .ok()
        .and_then(|metadata| DirIdentity::of(&metadata));
    Ok(Gate {
        holder: Holder::Own(file),
        lock_path,
        data_dir: canonical_data,
        identity,
    })
}

/// `dir`'s canonical path, or, while it isn't there, the path it would
/// have: its nearest existing ancestor's canonical path with the missing
/// names below it. Second, that ancestor's canonical path (the first, when
/// `dir` is there).
fn planned_canonical(dir: &Path) -> std::io::Result<(PathBuf, PathBuf)> {
    let mut missing = Vec::new();
    let mut current = dir;
    loop {
        match std::fs::canonicalize(current) {
            Ok(found) => {
                let mut planned = found.clone();
                for name in missing.iter().rev() {
                    planned.push(name);
                }
                return Ok((planned, found));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let (Some(name), Some(parent)) = (current.file_name(), current.parent()) else {
                    return Err(e);
                };
                missing.push(name);
                current = parent;
            }
            Err(e) => return Err(e),
        }
    }
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

/// Makes a missing lock directory and its missing ancestors, private to the
/// user on Unix (`0700`, less the umask) as [`create_private_dir`] does, but
/// anchored: nothing is made through a link, nothing through a parent
/// renamed or replaced once the anchor is open, and never the data directory
/// (`data_dir`, resolved to `canonical_data`) or one of its ancestors.
///
/// - **Never the data directory:** a missing name at the data directory's
///   path or above it is refused (`NotFound`) before anything is opened, so
///   a missing data directory, or one renamed away after it resolved, isn't
///   made again through a lock directory inside it.
/// - **The anchor** is the lock directory's nearest existing ancestor at its
///   canonical path, so an ordinary alias (macOS's `/var`, for
///   `/private/var`) is followed there, opened without following a link at
///   it ([`OpenDir`]; on Linux, at any component). Then, before anything is
///   made, it must still be what the paths name: the data directory resolves
///   as it did (else [`GateError::Moved`]: one replaced by a link since it
///   resolved makes nothing at the link's target through a lock directory
///   inside it); the lock directory's path still leads where it did; and the
///   anchor's canonical path still names the directory opened. A plain
///   directory put at the anchor's path before it is opened is the one
///   that path names, so it is anchored as such: the lock directory is
///   made at its planned path, as if the swap had come before the plan,
///   never through a link and never at the data directory or above.
/// - **One name at a time, relative to its parent's handle:** each missing
///   name is made (`mkdirat`; on Windows `NtCreateFile`) and opened, without
///   following a link at it, in the directory opened before it, never by a
///   path. A parent renamed or replaced meanwhile can't redirect it: the
///   name goes into the directory that was checked, wherever it now is, and
///   the gate's own checks then refuse a path that no longer leads there.
/// - **Race-safe:** a name another process makes meanwhile (another holder,
///   `hold-lock`) is taken if it is a directory; a link (on Windows, any
///   reparse point) or anything else there is refused (`AlreadyExists`), and
///   nothing is made through it.
/// - **An existing lock directory** is left to the gate's own checks, as
///   [`acquire`] leaves it: resolved, then a directory the user owns, with
///   its group and other bits removed (`make_private`).
fn create_lock_dir(
    data_dir: &Path,
    canonical_data: &Path,
    lock_dir: &Path,
) -> Result<(), GateError> {
    let (planned, existing) = planned_canonical(lock_dir).map_err(GateError::Storage)?;
    let missing = planned
        .strip_prefix(&existing)
        .map_err(|e| GateError::Storage(std::io::Error::other(e)))?;
    let mut names = Vec::new();
    let mut dir = existing.clone();
    for component in missing.components() {
        let Component::Normal(name) = component else {
            return Err(GateError::Storage(std::io::Error::other(
                "a lock directory path that isn't plain",
            )));
        };
        dir.push(name);
        if canonical_data.starts_with(&dir) {
            return Err(GateError::Storage(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "the data directory would be made through its lock directory",
            )));
        }
        names.push(name);
    }
    if names.is_empty() {
        return Ok(());
    }
    let anchor = OpenDir::open(&existing).map_err(GateError::Storage)?;
    if std::fs::canonicalize(data_dir).map_err(GateError::Storage)? != canonical_data {
        return Err(GateError::Moved);
    }
    if planned_canonical(lock_dir).map_err(GateError::Storage)?.0 != planned
        || OpenDir::open(&existing)
            .map_err(GateError::Storage)?
            .identity()
            != anchor.identity()
    {
        return Err(GateError::Storage(std::io::Error::other(
            "the lock directory's path changed while it was made",
        )));
    }
    #[cfg(test)]
    tests::lock_dir_anchored();
    let mut parent: Option<File> = None;
    for name in names {
        parent = Some(open_dir_at(parent.as_ref().unwrap_or(anchor.file()), name)?);
    }
    Ok(())
}

/// A link (on Windows, any reparse point), a file or anything else where a
/// lock directory's missing name is made.
fn not_a_lock_directory() -> GateError {
    GateError::Storage(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "something that isn't a directory where the lock directory goes",
    ))
}

/// The directory `name` in the one `parent` is open on, made first if it is
/// missing (`0700`, less the umask), and opened without following a link at
/// it, never by a path.
#[cfg(unix)]
fn open_dir_at(parent: &File, name: &OsStr) -> Result<File, GateError> {
    use rustix::fs::{Mode, OFlags};
    use rustix::io::Errno;
    match rustix::fs::mkdirat(parent, name, Mode::from_bits_truncate(0o700)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(e) => return Err(GateError::Storage(e.into())),
    }
    let flags =
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    match rustix::fs::openat(parent, name, flags, Mode::empty()) {
        Ok(fd) => Ok(File::from(fd)),
        Err(Errno::LOOP | Errno::NOTDIR) => Err(not_a_lock_directory()),
        Err(e) => Err(GateError::Storage(e.into())),
    }
}

/// `FILE_ATTRIBUTE_REPARSE_POINT`: a symlink, a junction or another reparse
/// point.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

/// The directory `name` in the one `parent` is open on, made first if it is
/// missing (inheriting its parent's ACL, as `hold-lock`'s does), relative
/// to that handle, never by a path (`fc_sys::windows::open_dir_at`). A
/// reparse point there is opened itself, never followed, and refused.
#[cfg(windows)]
fn open_dir_at(parent: &File, name: &OsStr) -> Result<File, GateError> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::AsHandle;
    let dir = match fc_sys::windows::open_dir_at(parent.as_handle(), name) {
        Ok(handle) => File::from(handle),
        Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => {
            return Err(not_a_lock_directory());
        }
        Err(e) => return Err(GateError::Storage(e)),
    };
    let metadata = dir.metadata().map_err(GateError::Storage)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir() {
        return Err(not_a_lock_directory());
    }
    Ok(dir)
}

#[cfg(not(any(unix, windows)))]
fn open_dir_at(_parent: &File, _name: &OsStr) -> Result<File, GateError> {
    Err(GateError::Storage(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no directory handles on this OS",
    )))
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

    /// A delete's gate: tried once, nothing made but the lock file, and a
    /// missing directory gated at the path it would have, so whoever makes
    /// it and takes its gate finds it held.
    #[test]
    fn a_deletes_gate_makes_nothing_and_covers_a_missing_directory() {
        let (_root, data, locks) = dirs();
        let name = |dir: &Path| lock_file_name("ipfs", dir);
        let inner = data.join("ipfs-data").join("freedom-ipfs");
        let gate = acquire_for_delete(&inner, &locks, &name, false, Duration::ZERO).unwrap();
        assert!(!data.exists());
        assert!(gate.identity.is_none());
        assert!(
            gate.data_dir
                .ends_with(Path::new("data/ipfs-data/freedom-ipfs"))
        );
        // A holder that makes it now waits on this gate.
        assert!(matches!(
            acquire(&inner, &locks, "ipfs", Duration::ZERO),
            Err(GateError::Held)
        ));
        drop(gate);
        let holder = acquire(&inner, &locks, "ipfs", CONTENTION_RETRY).unwrap();
        assert!(matches!(
            acquire_for_delete(&inner, &locks, &name, false, Duration::ZERO),
            Err(GateError::Held)
        ));
        drop(holder);
        let gate = acquire_for_delete(&inner, &locks, &name, false, CONTENTION_RETRY).unwrap();
        assert!(gate.identity.is_some() || cfg!(windows));
        // The lock directory inside the data directory is refused unless
        // allowed, as for the profile gate.
        let nested = inner.join("locks");
        assert!(matches!(
            acquire_for_delete(&inner, &nested, &name, false, Duration::ZERO),
            Err(GateError::LockInsideData)
        ));
        assert!(
            acquire_for_delete(&data, &data.join("locks"), &name, true, Duration::ZERO).is_ok()
        );
        // A file in the directory's place (a moved identity's placeholder)
        // is gated at its path.
        let placeholder = data.join("identity");
        std::fs::write(&placeholder, "moved").unwrap();
        let gate = acquire_for_delete(&placeholder, &locks, &name, false, Duration::ZERO).unwrap();
        assert_eq!(gate.data_dir, std::fs::canonicalize(&placeholder).unwrap());
        assert!(matches!(
            acquire_for_delete(&placeholder, &locks, &name, false, Duration::ZERO),
            Err(GateError::Held)
        ));
    }

    /// `acquire_existing` never makes the data directory: a missing one is
    /// `NotFound`, and nothing is made; an existing one is gated as by
    /// `acquire`, which still makes a missing one.
    #[test]
    fn acquire_existing_never_makes_the_data_directory() {
        let (_root, data, locks) = dirs();
        match acquire_existing(&data, &locks, "radicle", Duration::ZERO) {
            Err(GateError::Storage(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("{other:?}"),
        }
        assert!(!data.exists());
        let made = acquire(&data, &locks, "radicle", Duration::ZERO).unwrap();
        assert!(data.is_dir());
        assert!(matches!(
            acquire_existing(&data, &locks, "radicle", Duration::ZERO),
            Err(GateError::Held)
        ));
        drop(made);
        let gate = acquire_existing(&data, &locks, "radicle", CONTENTION_RETRY).unwrap();
        assert_eq!(gate.data_dir, std::fs::canonicalize(&data).unwrap());
        #[cfg(unix)]
        assert_eq!(
            gate.identity,
            DirIdentity::of(&std::fs::metadata(&data).unwrap())
        );
    }

    std::thread_local! {
        /// Run once, on this thread, right after `acquire_with` resolves the
        /// data directory.
        static AFTER_DATA_RESOLVED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn after_data_resolved() {
        if let Some(hook) = AFTER_DATA_RESOLVED.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }

    std::thread_local! {
        /// Run once, on this thread, right after `create_lock_dir` has
        /// checked its anchor, before it makes the first missing name.
        static AFTER_LOCK_ANCHORED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn lock_dir_anchored() {
        if let Some(hook) = AFTER_LOCK_ANCHORED.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }

    // Review of #177, round 6: a lock directory at or under the missing data
    // directory doesn't make it either.
    #[test]
    fn acquire_existing_never_makes_the_data_directory_through_its_locks() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("missing-data");
        for locks in [data.clone(), data.join("lock-parent")] {
            let result = acquire_existing(&data, &locks, "radicle", Duration::ZERO);
            assert!(!data.exists(), "recreated through {locks:?}: {result:?}");
            assert!(!locks.exists());
            assert!(matches!(result, Err(GateError::Storage(ref e))
                if e.kind() == std::io::ErrorKind::NotFound));
        }
    }

    // Review of #177, round 7: a missing lock directory isn't made either.
    #[test]
    fn acquire_existing_needs_an_existing_lock_directory() {
        let (_root, data, locks) = dirs();
        std::fs::create_dir_all(&data).unwrap();
        let result = acquire_existing(&data, &locks, "radicle", Duration::ZERO);
        assert!(matches!(result, Err(GateError::Storage(ref e))
            if e.kind() == std::io::ErrorKind::NotFound));
        assert!(!locks.exists());
    }

    // Review of #177, round 7: a data directory renamed away right after it
    // is resolved isn't made again through a lock directory at or under it.
    #[test]
    fn acquire_existing_makes_nothing_when_the_data_directory_moves_after_it_is_resolved() {
        for (layout, inside, made) in [
            ("the data directory itself", "", false),
            ("a missing lock directory under it", "locks", false),
            ("an existing lock directory under it", "locks", true),
        ] {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("data");
            let moved = root.path().join("moved");
            let locks = if inside.is_empty() {
                data.clone()
            } else {
                data.join(inside)
            };
            std::fs::create_dir(&data).unwrap();
            if made {
                std::fs::create_dir(&locks).unwrap();
            }
            let (from, to) = (data.clone(), moved.clone());
            AFTER_DATA_RESOLVED.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || std::fs::rename(from, to).unwrap()));
            });
            let result = acquire_existing(&data, &locks, "radicle", Duration::ZERO);
            assert!(!data.exists(), "{layout}: made again: {result:?}");
            assert!(
                matches!(result, Err(GateError::Storage(ref e))
                if e.kind() == std::io::ErrorKind::NotFound),
                "{layout}: {result:?}"
            );
            // The moved directory is as it was: nothing added.
            let entries = std::fs::read_dir(&moved).unwrap().count();
            assert_eq!(entries, usize::from(made), "{layout}");
        }
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

    /// The profile gate (design 0013): the lock directory may lie inside the
    /// profile's `userData` (the packaged default profile's app root holds
    /// `locks/`), never be it; the directory must exist; and it is its own
    /// gate, apart from every service's on the same directory.
    #[test]
    fn the_profile_gate_allows_the_app_roots_own_lock_directory() {
        let (_root, data, _) = dirs();
        assert!(matches!(
            acquire_profile(&data, &data.join("locks"), Duration::ZERO),
            Err(GateError::Storage(e)) if e.kind() == std::io::ErrorKind::NotFound
        ));
        assert!(!data.exists(), "the profile gate makes no directory");
        std::fs::create_dir_all(data.join("locks")).unwrap();
        let gate = acquire_profile(&data, &data.join("locks"), Duration::ZERO).unwrap();
        let name = gate
            .lock_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            name,
            lock_file_name(PROFILE_NAMESPACE, &std::fs::canonicalize(&data).unwrap())
        );
        assert!(name.starts_with("profile-"));
        assert!(matches!(
            acquire_profile(&data, &data.join("locks"), Duration::ZERO),
            Err(GateError::Held)
        ));
        assert!(matches!(
            acquire_profile(&data, &data, Duration::ZERO),
            Err(GateError::LockInsideData)
        ));
        // Another namespace on the same directory is another gate.
        let locks = data.join("locks");
        let ipfs = acquire_existing(&data, &locks, "ipfs", Duration::ZERO);
        assert!(matches!(ipfs, Err(GateError::LockInsideData)));
    }

    /// On a machine no new build has run on, the profile gate makes its
    /// missing lock directory and missing ancestors, private to the user, as
    /// `acquire` does; inside `userData` too (the packaged default profile).
    #[test]
    fn the_profile_gate_makes_its_lock_directory() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("profile");
        std::fs::create_dir(&data).unwrap();
        let parent = root.path().join("Freedom");
        let locks = parent.join("locks");
        let gate = acquire_profile(&data, &locks, Duration::ZERO).unwrap();
        assert!(locks.is_dir());
        assert_eq!(
            gate.lock_path.parent().unwrap(),
            std::fs::canonicalize(&locks).unwrap()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for dir in [&parent, &locks] {
                let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o7777;
                assert_eq!(mode & 0o077, 0, "{dir:?}: {mode:o}");
            }
        }
        // Taken again with the directory there.
        drop(gate);
        acquire_profile(&data, &locks, CONTENTION_RETRY).unwrap();
        let inner = data.join("locks");
        acquire_profile(&data, &inner, Duration::ZERO).unwrap();
        assert!(inner.is_dir());
    }

    /// A missing `userData`, or one renamed away right after it resolves,
    /// makes nothing through a lock directory under it or beside it.
    #[test]
    fn the_profile_gate_never_makes_user_data_through_its_lock_directory() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("missing");
        for locks in [
            data.join("locks"),
            data.join("a").join("locks"),
            root.path().join("locks"),
        ] {
            let result = acquire_profile(&data, &locks, Duration::ZERO);
            assert!(
                matches!(result, Err(GateError::Storage(ref e))
                    if e.kind() == std::io::ErrorKind::NotFound),
                "{locks:?}: {result:?}"
            );
            assert!(!data.exists() && !locks.exists(), "{locks:?}");
        }
        for inside in ["locks", "a/locks"] {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("data");
            let moved = root.path().join("moved");
            std::fs::create_dir(&data).unwrap();
            let locks = data.join(inside);
            let (from, to) = (data.clone(), moved.clone());
            AFTER_DATA_RESOLVED.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || std::fs::rename(from, to).unwrap()));
            });
            let result = acquire_profile(&data, &locks, Duration::ZERO);
            assert!(
                matches!(result, Err(GateError::Storage(ref e))
                    if e.kind() == std::io::ErrorKind::NotFound),
                "{inside}: {result:?}"
            );
            assert!(!data.exists(), "{inside}: made again");
            assert_eq!(std::fs::read_dir(&moved).unwrap().count(), 0, "{inside}");
        }
    }

    /// A directory symlink at `link` to `target`; on Windows a junction,
    /// which needs no privilege.
    fn dir_link(target: &Path, link: &Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        {
            let status = std::process::Command::new("cmd")
                .arg("/C")
                .arg("mklink")
                .arg("/J")
                .arg(link)
                .arg(target)
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "mklink /J");
        }
    }

    /// Review of #351, round 1: a `userData` replaced by a link (on
    /// Windows, a junction) right after it resolves makes nothing through a
    /// lock directory inside it, at the link's target or anywhere: the gate
    /// is refused before anything is made.
    #[test]
    fn the_profile_gate_makes_nothing_through_a_user_data_replaced_by_a_link() {
        for inside in ["locks", "a/locks"] {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("data");
            let moved = root.path().join("moved");
            let target = root.path().join("target");
            std::fs::create_dir(&data).unwrap();
            std::fs::create_dir(&target).unwrap();
            let locks = data.join(inside);
            let (from, to, link_target) = (data.clone(), moved.clone(), target.clone());
            AFTER_DATA_RESOLVED.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    std::fs::rename(&from, to).unwrap();
                    dir_link(&link_target, &from);
                }));
            });
            let result = acquire_profile(&data, &locks, Duration::ZERO);
            assert!(
                matches!(result, Err(GateError::Moved)),
                "{inside}: {result:?}"
            );
            assert_eq!(
                std::fs::read_dir(&target).unwrap().count(),
                0,
                "{inside}: made through the link"
            );
            assert_eq!(std::fs::read_dir(&moved).unwrap().count(), 0, "{inside}");
        }
    }

    /// Review of #351, round 1: once the lock directory's existing parent is
    /// checked, each missing name is made in that very directory, by its
    /// handle: a parent replaced by a link (on Windows, a junction) then
    /// can't redirect it, and a link that appears at a missing name is
    /// refused, with nothing made through either.
    #[test]
    fn the_profile_gate_makes_its_lock_directory_in_the_parent_it_checked() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let parent = root.path().join("parent");
        let moved = root.path().join("moved");
        let target = root.path().join("target");
        for dir in [&data, &parent, &target] {
            std::fs::create_dir(dir).unwrap();
        }
        let locks = parent.join("a").join("locks");
        let (from, to, link_target) = (parent.clone(), moved.clone(), target.clone());
        AFTER_LOCK_ANCHORED.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(&from, to).unwrap();
                dir_link(&link_target, &from);
            }));
        });
        let result = acquire_profile(&data, &locks, Duration::ZERO);
        // Made in the parent checked, now at `moved`; the path leads through
        // the link to no lock directory, so the gate is refused.
        assert!(
            matches!(result, Err(GateError::Storage(ref e))
                if e.kind() == std::io::ErrorKind::NotFound),
            "{result:?}"
        );
        assert!(moved.join("a").join("locks").is_dir());
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);

        // A link at a missing name, made after the check.
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let target = root.path().join("target");
        std::fs::create_dir(&data).unwrap();
        std::fs::create_dir(&target).unwrap();
        let link = root.path().join("a");
        let locks = link.join("locks");
        let (at, link_target) = (link.clone(), target.clone());
        AFTER_LOCK_ANCHORED.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || dir_link(&link_target, &at)));
        });
        let result = acquire_profile(&data, &locks, Duration::ZERO);
        assert!(
            matches!(result, Err(GateError::Storage(ref e))
                if e.kind() == std::io::ErrorKind::AlreadyExists),
            "{result:?}"
        );
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
    }

    /// A file where the lock directory goes is refused, and so is a link
    /// that leads nowhere (Unix), with nothing made through it.
    #[test]
    fn the_profile_gate_refuses_a_lock_directory_that_isnt_one() {
        let (root, data, locks) = dirs();
        std::fs::create_dir(&data).unwrap();
        std::fs::write(&locks, b"file").unwrap();
        let result = acquire_profile(&data, &locks, Duration::ZERO);
        #[cfg(unix)]
        assert!(
            matches!(result, Err(GateError::NotPrivate(_))),
            "{result:?}"
        );
        #[cfg(not(unix))]
        assert!(result.is_err());
        assert_eq!(std::fs::read(&locks).unwrap(), b"file");
        #[cfg(unix)]
        {
            let target = root.path().join("target");
            let link = root.path().join("link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            for lock_dir in [link.clone(), link.join("locks")] {
                let result = acquire_profile(&data, &lock_dir, Duration::ZERO);
                assert!(
                    matches!(result, Err(GateError::Storage(ref e))
                        if e.kind() == std::io::ErrorKind::AlreadyExists),
                    "{lock_dir:?}: {result:?}"
                );
                assert!(!target.exists(), "made through {lock_dir:?}");
            }
        }
        #[cfg(not(unix))]
        let _ = root;
    }

    /// Holders racing to make one lock directory all take their gates.
    #[test]
    fn profile_gates_racing_to_make_one_lock_directory() {
        const HOLDERS: usize = 8;
        let root = tempfile::tempdir().unwrap();
        let locks = root.path().join("a").join("b").join("locks");
        let start = std::sync::Arc::new(std::sync::Barrier::new(HOLDERS));
        let holders: Vec<_> = (0..HOLDERS)
            .map(|i| {
                let data = root.path().join(format!("profile-{i}"));
                std::fs::create_dir(&data).unwrap();
                let (locks, start) = (locks.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    acquire_profile(&data, &locks, Duration::ZERO).map(|_| ())
                })
            })
            .collect();
        for holder in holders {
            let result = holder.join().unwrap();
            assert!(result.is_ok(), "{result:?}");
        }
        assert_eq!(std::fs::read_dir(&locks).unwrap().count(), HOLDERS);
    }

    /// `probe` reports a held gate and leaves a free one free; it makes
    /// nothing, and a directory never gated reads free.
    #[test]
    fn probe_tries_without_holding() {
        let (_root, data, locks) = dirs();
        assert!(!probe(&data, &locks, "profile").unwrap());
        assert!(!locks.exists() && !data.exists());
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&locks).unwrap();
        assert!(!probe(&data, &locks, "profile").unwrap());
        assert_eq!(std::fs::read_dir(&locks).unwrap().count(), 0);
        let gate = acquire_profile(&data, &locks, Duration::ZERO).unwrap();
        assert!(probe(&data, &locks, "profile").unwrap());
        assert!(!probe(&data, &locks, "ipfs").unwrap());
        drop(gate);
        // Free after the probe: taken within the retry (a child spawned by
        // another test may hold a copy of the descriptor until it execs).
        assert!(acquire_profile(&data, &locks, CONTENTION_RETRY).is_ok());
    }

    /// Design 0017, C3: a gate file is opened once, at `acquire`'s path and
    /// with its checks, without locking it; then locked and unlocked through
    /// that one open file, as often as needed, each lock a gate `acquire`
    /// contends with, and each unlock leaving the file open.
    #[test]
    fn a_gate_file_opens_once_and_locks_repeatedly() {
        let (_root, data, locks) = dirs();
        let file = GateFile::open(&data, &locks, "radicle").unwrap();
        // Made as `acquire` makes them, at its path, and nothing locked.
        assert!(data.is_dir() && locks.is_dir());
        let canonical_data = std::fs::canonicalize(&data).unwrap();
        let canonical_locks = std::fs::canonicalize(&locks).unwrap();
        assert_eq!(file.data_dir(), canonical_data);
        assert_eq!(
            file.lock_path(),
            canonical_locks.join(lock_file_name("radicle", &canonical_data))
        );
        assert_eq!(
            file.lock_path().file_name().unwrap().to_str().unwrap(),
            lock_file_name("radicle", &canonical_data)
        );
        let taken = acquire(&data, &locks, "radicle", Duration::ZERO).unwrap();
        assert_eq!(taken.lock_path, file.lock_path());
        assert!(matches!(file.lock(Duration::ZERO), Err(GateError::Held)));
        drop(taken);
        #[cfg(unix)]
        let descriptor = {
            assert_eq!(file.descriptors().len(), 1);
            file.descriptors()[0]
        };
        for _ in 0..5 {
            // Within the retry: a child another test forks may hold a copy
            // of a released descriptor until it execs.
            let gate = file.lock(CONTENTION_RETRY).unwrap();
            assert_eq!(gate.data_dir, canonical_data);
            assert_eq!(gate.lock_path, file.lock_path());
            assert_eq!(gate.descriptors(), file.descriptors());
            #[cfg(unix)]
            assert_eq!(
                gate.identity,
                DirIdentity::of(&std::fs::metadata(&data).unwrap())
            );
            assert!(matches!(
                acquire(&data, &locks, "radicle", Duration::ZERO),
                Err(GateError::Held)
            ));
            assert!(probe(&data, &locks, "radicle").unwrap());
            drop(gate);
            // Unlocked, and the file still open on the same descriptor.
            assert!(!probe(&data, &locks, "radicle").unwrap());
            #[cfg(unix)]
            {
                assert_eq!(file.descriptors(), [descriptor]);
                assert_eq!(
                    open_descriptor_identity(descriptor),
                    file_identity(file.lock_path())
                );
            }
        }
        // A gate `acquire` holds is waited on, as `acquire` waits.
        let taken = acquire(&data, &locks, "radicle", CONTENTION_RETRY).unwrap();
        let started = Instant::now();
        assert!(matches!(
            file.lock(Duration::from_millis(300)),
            Err(GateError::Held)
        ));
        assert!(started.elapsed() >= Duration::from_millis(300));
        drop(taken);
        assert!(file.lock(CONTENTION_RETRY).is_ok());
    }

    /// The file's identity, as `open_descriptor_identity` gives it.
    #[cfg(unix)]
    fn file_identity(path: &Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(path).unwrap();
        (metadata.dev(), metadata.ino())
    }

    /// What the open descriptor `fd` names, through `/dev/fd`: it fails if
    /// the descriptor is closed.
    #[cfg(unix)]
    fn open_descriptor_identity(fd: i32) -> (u64, u64) {
        file_identity(Path::new(&format!("/dev/fd/{fd}")))
    }

    /// Two gate files opened on one lock file contend as two processes'
    /// gates do: the second waits for the retry, then is `Held`, and takes
    /// the gate once the first lets go within it. Gates through one file, or
    /// through its clones, contend too.
    #[test]
    fn gate_files_on_one_lock_file_contend() {
        let (_root, data, locks) = dirs();
        let first = GateFile::open(&data, &locks, "radicle").unwrap();
        let second = GateFile::open_existing(&data, &locks, "radicle").unwrap();
        assert_eq!(first.lock_path(), second.lock_path());
        #[cfg(unix)]
        assert_ne!(first.descriptors(), second.descriptors());
        let held = first.lock(CONTENTION_RETRY).unwrap();
        let started = Instant::now();
        assert!(matches!(
            second.lock(Duration::from_millis(300)),
            Err(GateError::Held)
        ));
        assert!(started.elapsed() >= Duration::from_millis(300));
        // Through the same file and a clone of it: held in this process.
        assert!(matches!(first.lock(Duration::ZERO), Err(GateError::Held)));
        let clone = first.clone();
        assert!(matches!(clone.lock(Duration::ZERO), Err(GateError::Held)));
        // Let go within the second's retry: it takes the gate.
        let waiter = std::thread::spawn(move || second.lock(CONTENTION_RETRY).map(|_| ()));
        std::thread::sleep(Duration::from_millis(300));
        drop(held);
        assert!(waiter.join().unwrap().is_ok());
        // A clone locks the shared file, and the original then waits on it;
        // the clone's gate keeps the file open once every handle is gone.
        let gate = clone.lock(CONTENTION_RETRY).unwrap();
        assert!(matches!(first.lock(Duration::ZERO), Err(GateError::Held)));
        drop((first, clone));
        assert!(probe(&data, &locks, "radicle").unwrap());
        drop(gate);
        assert!(acquire(&data, &locks, "radicle", CONTENTION_RETRY).is_ok());
    }

    /// Threads racing through one gate file: one gate at a time.
    #[test]
    fn one_gate_at_a_time_through_one_gate_file() {
        let (_root, data, locks) = dirs();
        let file = GateFile::open(&data, &locks, "radicle").unwrap();
        let inside = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let (file, inside) = (file.clone(), Arc::clone(&inside));
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        let gate = file.lock(Duration::from_secs(30)).unwrap();
                        assert_eq!(inside.fetch_add(1, Ordering::SeqCst), 0);
                        std::thread::sleep(Duration::from_millis(5));
                        assert_eq!(inside.fetch_sub(1, Ordering::SeqCst), 1);
                        drop(gate);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    /// The open is `acquire`'s and `acquire_existing`'s, up to the lock:
    /// `open_existing` makes no directory, both refuse a lock directory in
    /// the data directory, and the lock file is private (Unix).
    #[test]
    fn a_gate_file_opens_as_its_gate_does() {
        let (_root, data, locks) = dirs();
        match GateFile::open_existing(&data, &locks, "radicle") {
            Err(GateError::Storage(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("{other:?}"),
        }
        assert!(!data.exists() && !locks.exists());
        std::fs::create_dir(&data).unwrap();
        assert!(matches!(
            GateFile::open_existing(&data, &locks, "radicle"),
            Err(GateError::Storage(ref e)) if e.kind() == std::io::ErrorKind::NotFound
        ));
        assert!(!locks.exists());
        assert!(matches!(
            GateFile::open(&data, &data.join("locks"), "radicle"),
            Err(GateError::LockInsideData)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
            std::fs::create_dir(&locks).unwrap();
            let lock_path = locks.join(lock_file_name(
                "radicle",
                &std::fs::canonicalize(&data).unwrap(),
            ));
            std::fs::write(&lock_path, b"").unwrap();
            for (path, wide) in [(&data, 0o755), (&locks, 0o777), (&lock_path, 0o644)] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(wide)).unwrap();
            }
            let file = GateFile::open_existing(&data, &locks, "radicle").unwrap();
            assert_eq!(mode(&data), 0o700);
            assert_eq!(mode(&locks), 0o700);
            assert_eq!(mode(file.lock_path()), 0o600);
        }
    }

    /// Under each lock, the data directory is resolved again: a link
    /// retargeted since the open is `Moved`, a directory gone is
    /// `NotFound`, and either lets the lock go.
    #[test]
    fn a_gate_file_resolves_its_directory_again_under_each_lock() {
        let root = tempfile::tempdir().unwrap();
        let (data, other, link) = (
            root.path().join("data"),
            root.path().join("other"),
            root.path().join("link"),
        );
        let locks = root.path().join("locks");
        std::fs::create_dir(&data).unwrap();
        std::fs::create_dir(&other).unwrap();
        dir_link(&data, &link);
        let file = GateFile::open(&link, &locks, "radicle").unwrap();
        assert_eq!(file.data_dir(), std::fs::canonicalize(&data).unwrap());
        drop(file.lock(CONTENTION_RETRY).unwrap());
        remove_dir_link(&link);
        dir_link(&other, &link);
        assert!(matches!(file.lock(Duration::ZERO), Err(GateError::Moved)));
        // Let go: neither this process nor another finds it held.
        assert!(!probe(&data, &locks, "radicle").unwrap());
        remove_dir_link(&link);
        dir_link(&data, &link);
        let gate = file.lock(Duration::ZERO).unwrap();
        assert_eq!(gate.data_dir, std::fs::canonicalize(&data).unwrap());
        drop(gate);
        // A directory gone since the open isn't made again.
        remove_dir_link(&link);
        std::fs::remove_dir(&data).unwrap();
        assert!(matches!(
            file.lock(Duration::ZERO),
            Err(GateError::Storage(ref e)) if e.kind() == std::io::ErrorKind::NotFound
        ));
        assert!(!data.exists() && !link.exists());
        std::fs::create_dir(&data).unwrap();
        dir_link(&data, &link);
        assert!(file.lock(Duration::ZERO).is_ok());
    }

    /// Removes a link `dir_link` made.
    fn remove_dir_link(link: &Path) {
        #[cfg(unix)]
        std::fs::remove_file(link).unwrap();
        #[cfg(windows)]
        std::fs::remove_dir(link).unwrap();
    }
}
