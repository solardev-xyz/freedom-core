//! A starting move's preconditions (design 0013, "The move", 2; step
//! PRF-9b): what `profile migrate` without `--finish-only` observes under
//! the move's exclusion and before its confinement, and whether it starts.
//!
//! - **A journal or the marker** in `freedom/`: nothing starts; the run
//!   settles the journal as `--finish-only` does, or finds the move done.
//! - **Otherwise `fc_profile::layout::plan_start` decides,** from what is
//!   observed here: each of the list's entries at the root (as `lstat`
//!   finds it) and whether it is a mount point (MD6), what `freedom/` is
//!   and holds, and whether a node identity journal or staging file is in
//!   `identity/` (MG3).
//! - **Then the nodes' own OS locks** (MD7), each tried and let go at
//!   once, as the PRF-9b spike found them in freedom-browser's
//!   integration branch:
//!   - **arti** (pinned 2.7.0) holds `tor-data/state/state/state.lock`
//!     (tor-persist's `FsStateMgr` under the `state_dir` main writes into
//!     `arti.toml`) and `tor-data/cache/dir.lock` (tor-dirmgr's store
//!     under `cache_dir`), each through fslock-guard, which is std's
//!     `File::try_lock`: `flock` on Unix, `LockFileEx` on Windows. The
//!     core tries the same lock.
//!   - **Myotis's supervisor** holds `.freedom-myotis-owner`, and it and
//!     its execution child (which inherits it, so an orphan keeps it) the
//!     lifetime lease `.freedom-myotis-lifetime`, in each network's data
//!     directory (`myotis/` for mainnet, `myotis/gnosis/`): `flock` on
//!     Unix; on Windows a handle that shares reading only. The core tries
//!     `flock` on Unix, and on Windows opens each for `DELETE` while
//!     sharing everything, which only a handle sharing less refuses.
//!
//!   A lock held, or one that can't be tried (an error other than a
//!   missing file), defers. antd holds no OS lock the core can try: main
//!   checks `ant-process.json`'s pid (B3).
//!
//! Any of them ends the run with `deferred` (exit 0) and nothing changed:
//! the profile opens in the old layout, and the move is tried at the next
//! start.

use std::ffi::OsStr;
use std::io;
use std::path::Path;

use fc_profile::layout::{
    self, AtRoot, Deferral, FREEDOM_DIR, FreedomDir, LAYOUT_MARKER, MOVE_JOURNAL, MOVED_ENTRIES,
    StartState,
};
use fc_store::anchor::{Dir, Kind};

/// What a starting run does.
#[derive(Debug, PartialEq, Eq)]
pub enum Check {
    /// A journal or the marker is there: settled as `--finish-only`
    /// settles it.
    Settle,
    /// The move starts, on these entries, in the list's order: none for a
    /// new profile's empty move (MD5).
    Start(Vec<&'static str>),
    /// It doesn't start: the reason's word, and what was found.
    Defer { why: &'static str, detail: String },
}

/// The preconditions, on the profile's root opened from its gate's
/// canonical path (`root`, at `canonical`).
pub fn check(root: &Dir, canonical: &Path) -> io::Result<Check> {
    let freedom_names;
    let freedom = match root.kind(OsStr::new(FREEDOM_DIR))? {
        Kind::Missing => FreedomDir::Missing,
        Kind::Dir => {
            let dir = root
                .child(OsStr::new(FREEDOM_DIR), false)?
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            if dir.kind(OsStr::new(MOVE_JOURNAL))? != Kind::Missing
                || dir.kind(OsStr::new(LAYOUT_MARKER))? != Kind::Missing
            {
                return Ok(Check::Settle);
            }
            freedom_names = dir
                .names()?
                .into_iter()
                .map(|name| name.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            FreedomDir::Dir(&freedom_names)
        }
        Kind::File | Kind::Other => FreedomDir::Other,
    };
    let mut at_root = Vec::new();
    for name in MOVED_ENTRIES {
        let found = match root.kind(OsStr::new(name))? {
            Kind::Missing => continue,
            Kind::File => layout::Found::File,
            Kind::Dir => layout::Found::Dir,
            Kind::Other => layout::Found::Other,
        };
        let mount_point = mount_point(canonical, name)?;
        at_root.push((*name, AtRoot { found, mount_point }));
    }
    let state = StartState {
        root: &at_root,
        freedom,
        node_identity_journal: node_identity_journal(canonical)?,
    };
    let entries = match layout::plan_start(&state) {
        Ok(entries) => entries,
        Err(deferral) => {
            let detail = match &deferral {
                Deferral::NodeIdentityJournal | Deferral::FreedomNotDir => String::new(),
                Deferral::FreedomHolds(name) => name.clone(),
                Deferral::MountPoint(name) => (*name).to_owned(),
            };
            return Ok(Check::Defer {
                why: deferral.word(),
                detail,
            });
        }
    };
    for lock in NODE_LOCKS {
        if !entries.contains(&lock.entry) {
            continue;
        }
        let mut path = canonical.join(lock.entry);
        path.extend(lock.path);
        match try_lock(&path, lock.probe) {
            Tried::Free => {}
            Tried::Held => {
                return Ok(Check::Defer {
                    why: "node_running",
                    detail: relative(lock),
                });
            }
            Tried::Unknown(kind) => {
                return Ok(Check::Defer {
                    why: "node_lock_unknown",
                    detail: format!("{}: {kind}", relative(lock)),
                });
            }
        }
    }
    Ok(Check::Start(entries))
}

/// A node identity journal or its staging file in the root's `identity/`,
/// through a symlink there too: its recovery would write at the absolute
/// root it records.
fn node_identity_journal(canonical: &Path) -> io::Result<bool> {
    let identity = canonical.join("identity");
    for name in [crate::journal::JOURNAL, crate::journal::STAGING] {
        match std::fs::symlink_metadata(identity.join(name)) {
            Ok(_) => return Ok(true),
            // Missing, or `identity` isn't a directory (a file there).
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    || e.kind() == io::ErrorKind::NotADirectory => {}
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

/// Whether the root's `name` is a mount point, not following a symlink at
/// it (a symlink is moved as the link): on another device than the root,
/// or, on Linux, on another mount (a bind mount of the same file system).
#[cfg(unix)]
fn mount_point(canonical: &Path, name: &str) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let path = canonical.join(name);
    let entry = std::fs::symlink_metadata(&path)?;
    if entry.file_type().is_symlink() {
        return Ok(false);
    }
    if entry.dev() != std::fs::symlink_metadata(canonical)?.dev() {
        return Ok(true);
    }
    #[cfg(target_os = "linux")]
    {
        // `STATX_MNT_ID` (Linux 5.8): an older kernel that doesn't give it
        // leaves the device check alone.
        if let (Some(entry), Some(root)) = (mount_id(&path), mount_id(canonical)) {
            return Ok(entry != root);
        }
    }
    Ok(false)
}

#[cfg(target_os = "linux")]
fn mount_id(path: &Path) -> Option<u64> {
    use rustix::fs::{AtFlags, CWD, StatxFlags, statx};
    let stat = statx(CWD, path, AtFlags::SYMLINK_NOFOLLOW, StatxFlags::MNT_ID).ok()?;
    (StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID))
        .then_some(stat.stx_mnt_id)
}

/// Whether the root's `name` is a volume mount point: a reparse point whose
/// target is a volume (`\\?\Volume{…}\`). A directory that is no reparse
/// point is on its parent's volume; a junction or a symlink to a path is a
/// link, moved as itself.
#[cfg(windows)]
fn mount_point(canonical: &Path, name: &str) -> io::Result<bool> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let path = canonical.join(name);
    let meta = std::fs::symlink_metadata(&path)?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return Ok(false);
    }
    // A reparse point std can't read (neither a symlink nor a junction)
    // isn't a mount point either.
    Ok(std::fs::read_link(&path).is_ok_and(|target| volume_target(&target)))
}

/// A reparse target naming a volume rather than a path.
#[cfg(any(windows, test))]
fn volume_target(target: &Path) -> bool {
    let text = target.to_string_lossy().to_ascii_lowercase();
    text.starts_with(r"\\?\volume{") || text.starts_with(r"\??\volume{")
}

#[cfg(not(any(unix, windows)))]
fn mount_point(_canonical: &Path, _name: &str) -> io::Result<bool> {
    Ok(false)
}

/// How a node's lock is tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// std's `File::try_lock`, as fslock-guard takes it: `flock` on Unix,
    /// `LockFileEx` on Windows.
    FileLock,
    /// Myotis's lease: `flock` on Unix; on Windows a handle that shares
    /// reading only, which an open for `DELETE` sharing everything finds.
    Lease,
}

/// A lock a node holds while it runs, under one of the moved entries.
struct NodeLock {
    entry: &'static str,
    path: &'static [&'static str],
    probe: Probe,
}

/// The locks the spike found (the module's comment).
const NODE_LOCKS: &[NodeLock] = &[
    NodeLock {
        entry: "tor-data",
        path: &["state", "state", "state.lock"],
        probe: Probe::FileLock,
    },
    NodeLock {
        entry: "tor-data",
        path: &["cache", "dir.lock"],
        probe: Probe::FileLock,
    },
    NodeLock {
        entry: "myotis",
        path: &[".freedom-myotis-lifetime"],
        probe: Probe::Lease,
    },
    NodeLock {
        entry: "myotis",
        path: &[".freedom-myotis-owner"],
        probe: Probe::Lease,
    },
    NodeLock {
        entry: "myotis",
        path: &["gnosis", ".freedom-myotis-lifetime"],
        probe: Probe::Lease,
    },
    NodeLock {
        entry: "myotis",
        path: &["gnosis", ".freedom-myotis-owner"],
        probe: Probe::Lease,
    },
];

/// A lock's path under the root, for the log.
fn relative(lock: &NodeLock) -> String {
    let mut parts = vec![lock.entry];
    parts.extend(lock.path);
    parts.join("/")
}

#[derive(Debug, PartialEq, Eq)]
enum Tried {
    Free,
    Held,
    Unknown(io::ErrorKind),
}

/// Tries `path`'s lock and lets it go at once. Nothing there, or no
/// regular file (so no lock a node takes), is free. Only a regular file is
/// opened: a FIFO's open would wait for a writer.
fn try_lock(path: &Path, probe: Probe) -> Tried {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => return Tried::Free,
        Err(e) if gone(&e) => return Tried::Free,
        Err(e) => return Tried::Unknown(e.kind()),
    }
    #[cfg(windows)]
    if probe == Probe::Lease {
        return share_probe(path);
    }
    let _ = probe;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if gone(&e) => return Tried::Free,
        Err(e) => return Tried::Unknown(e.kind()),
    };
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            Tried::Free
        }
        Err(std::fs::TryLockError::WouldBlock) => Tried::Held,
        Err(std::fs::TryLockError::Error(e)) => Tried::Unknown(e.kind()),
    }
}

/// Missing, or a parent on the way that isn't a directory.
fn gone(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// Opens `path` for `DELETE`, sharing reading, writing and deleting, and
/// lets it go: refused with a sharing violation only while another handle
/// shares less (Myotis's share reading only).
#[cfg(windows)]
fn share_probe(path: &Path) -> Tried {
    use std::os::windows::fs::OpenOptionsExt;
    const DELETE: u32 = 0x0001_0000;
    const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    match std::fs::OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(_) => Tried::Free,
        Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Tried::Held,
        Err(e) if gone(&e) => Tried::Free,
        Err(e) => Tried::Unknown(e.kind()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_volume_target_is_a_mount_point_and_a_path_is_a_link() {
        assert!(volume_target(Path::new(
            r"\\?\Volume{0b3c1f2e-0000-0000-0000-100000000000}\"
        )));
        assert!(volume_target(Path::new(
            r"\??\VOLUME{0b3c1f2e-0000-0000-0000-100000000000}\"
        )));
        assert!(!volume_target(Path::new(r"\\?\D:\data\ant-data")));
        assert!(!volume_target(Path::new(r"D:\Volume{x}")));
    }

    /// The system's own mount points, where the test can see one: `/proc`
    /// on Linux, `/dev` on macOS. A directory beside them isn't one, and a
    /// symlink never is.
    #[cfg(unix)]
    #[test]
    fn a_mount_point_is_found_and_a_plain_directory_or_link_isnt() {
        let root = Path::new("/");
        #[cfg(target_os = "linux")]
        if Path::new("/proc/self").exists() {
            assert!(mount_point(root, "proc").unwrap());
        }
        #[cfg(target_os = "macos")]
        assert!(mount_point(root, "dev").unwrap());
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir(base.join("ant-data")).unwrap();
        std::os::unix::fs::symlink("/", base.join("ipfs-data")).unwrap();
        assert!(!mount_point(&base, "ant-data").unwrap());
        assert!(!mount_point(&base, "ipfs-data").unwrap());
    }

    #[test]
    fn a_lock_held_is_found_and_let_go_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.lock");
        assert_eq!(try_lock(&path, Probe::FileLock), Tried::Free, "missing");
        std::fs::write(&path, "").unwrap();
        assert_eq!(try_lock(&path, Probe::FileLock), Tried::Free);
        // Let go: another takes it after the try.
        let other = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        other.try_lock().unwrap();
        // flock and LockFileEx exclude another open of the same file, even
        // in this process.
        assert_eq!(try_lock(&path, Probe::FileLock), Tried::Held);
        other.unlock().unwrap();
        assert_eq!(try_lock(&path, Probe::FileLock), Tried::Free);
        // A directory at the name holds no lock.
        let sub = dir.path().join("dir.lock");
        std::fs::create_dir(&sub).unwrap();
        assert_eq!(try_lock(&sub, Probe::FileLock), Tried::Free);
        // A file on the way: nothing below it.
        assert_eq!(try_lock(&path.join("below"), Probe::FileLock), Tried::Free);
    }
}
