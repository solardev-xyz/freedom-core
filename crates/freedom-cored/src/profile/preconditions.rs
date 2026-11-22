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
//! - **Then each entry that is a link** (a symlink, or on Windows a
//!   junction): one whose target is relative, or absolute and inside the
//!   profile by name, defers (`link_inside_profile`). Moved one directory
//!   deeper, a relative link names another place, and one into the profile
//!   may name an entry the move takes elsewhere. A link to an absolute path
//!   outside moves as the link.
//! - **Then the nodes' own OS locks** (MD7), each tried and let go at
//!   once, as the PRF-9b spike found them in freedom-browser's
//!   integration branch. The lock's own name is opened without following
//!   a link and without waiting (a FIFO's open would wait for a writer),
//!   and the handle checked to be a regular file:
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
    for name in &entries {
        if let Some(why) = link_inside(canonical, name)? {
            return Ok(Check::Defer {
                why: "link_inside_profile",
                detail: format!("{name}: {why}"),
            });
        }
    }
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
            Tried::Unknown(why) => {
                return Ok(Check::Defer {
                    why: "node_lock_unknown",
                    detail: format!("{}: {why}", relative(lock)),
                });
            }
        }
    }
    Ok(Check::Start(entries))
}

/// Why the root's `name`, a link (a symlink, or on Windows a junction),
/// can't move as the link: its target is relative, so it would name
/// another place one directory deeper; or it is absolute and inside the
/// profile's directory, by name or once resolved, so it may name another
/// entry, which the move takes elsewhere. `None` for anything else: a link to an absolute
/// path outside the profile moves as itself. The move doesn't rewrite a
/// link: a new link isn't one rename, and its rollback would have to undo
/// it.
fn link_inside(canonical: &Path, name: &str) -> io::Result<Option<&'static str>> {
    let path = canonical.join(name);
    let meta = std::fs::symlink_metadata(&path)?;
    if !is_link(&meta) {
        return Ok(None);
    }
    let target = match std::fs::read_link(&path) {
        Ok(target) => target,
        // A reparse point std can't read is no link it would follow either
        // (a volume mount point is deferred before this, as one).
        Err(_) if cfg!(windows) => return Ok(None),
        Err(e) => return Err(e),
    };
    if !target.is_absolute() {
        return Ok(Some("a relative link"));
    }
    // By name, and resolved where it resolves (a short 8.3 name or a link on
    // its way naming the profile too): either inside defers.
    let inside = lexically_inside(&target, canonical)
        || std::fs::canonicalize(&path)
            .is_ok_and(|resolved| lexically_inside(&resolved, canonical));
    Ok(inside.then_some("a link into the profile"))
}

/// A symlink, or on Windows any reparse point (a junction too).
pub fn is_link(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        meta.file_type().is_symlink() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

/// Whether the absolute `target`, its `.` and `..` resolved by name alone
/// (no link followed), is `root` or below it. Compared folded
/// (`fc_profile::delete::fold`, without Windows's verbatim prefix) on every
/// OS: a fold wider than a volume's only defers more.
fn lexically_inside(target: &Path, root: &Path) -> bool {
    use std::path::Component;
    let parts = |path: &Path| -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => out.push(prefix_key(prefix.kind())),
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir => {
                    if out.len() > 1 || (out.len() == 1 && !cfg!(windows)) {
                        out.pop();
                    }
                }
                Component::Normal(name) => {
                    out.push(fc_profile::delete::fold(&name.to_string_lossy()));
                }
            }
        }
        out
    };
    let (target, root) = (parts(target), parts(root));
    target.len() >= root.len() && target[..root.len()] == root[..]
}

/// A Windows path prefix as one key: `C:` and `\\?\C:` alike, a share by
/// its server and name.
fn prefix_key(prefix: std::path::Prefix<'_>) -> String {
    use std::path::Prefix;
    let fold = |text: &OsStr| fc_profile::delete::fold(&text.to_string_lossy());
    match prefix {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
            format!("{}:", char::from(letter).to_ascii_lowercase())
        }
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
            format!("//{}/{}", fold(server), fold(share))
        }
        Prefix::Verbatim(name) | Prefix::DeviceNS(name) => format!("//?/{}", fold(name)),
    }
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
    /// Why it couldn't be tried.
    Unknown(String),
}

/// Tries `path`'s lock and lets it go at once. The last component is
/// opened without following a link and without waiting (a FIFO's open
/// doesn't wait for a writer), and the handle checked: a link there is
/// `Unknown` (the core doesn't follow it, and a node that did would lock
/// what it names), anything but a regular file is free (no node's lock is
/// one), and so is nothing there. A link above it (a symlinked `tor-data/`)
/// is followed, as the node follows it.
fn try_lock(path: &Path, probe: Probe) -> Tried {
    let file = match open_lock(path, probe) {
        Opened::File(file) => file,
        #[cfg(windows)]
        Opened::Held => return Tried::Held,
        Opened::Free => return Tried::Free,
        Opened::Unknown(kind) => return Tried::Unknown(kind),
    };
    #[cfg(windows)]
    if probe == Probe::Lease {
        // The open was the try.
        return Tried::Free;
    }
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            Tried::Free
        }
        Err(std::fs::TryLockError::WouldBlock) => Tried::Held,
        Err(std::fs::TryLockError::Error(e)) => Tried::Unknown(e.kind().to_string()),
    }
}

/// What opening a lock's path found.
enum Opened {
    /// A regular file, open: its lock is tried next.
    File(std::fs::File),
    /// Windows, Myotis's lease: another handle shares less than the open.
    #[cfg(windows)]
    Held,
    Free,
    Unknown(String),
}

/// Missing, or a parent on the way that isn't a directory.
fn gone(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// `open(O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)`, then `fstat`.
#[cfg(unix)]
fn open_lock(path: &Path, _probe: Probe) -> Opened {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => std::fs::File::from(fd),
        // A symlink at the name (`ELOOP`; `EMLINK` on some BSDs).
        Err(e) if e == rustix::io::Errno::LOOP || e == rustix::io::Errno::MLINK => {
            return Opened::Unknown("a link at the lock's name".to_owned());
        }
        Err(e) => {
            let e = io::Error::from(e);
            return if gone(&e) {
                Opened::Free
            } else {
                Opened::Unknown(e.kind().to_string())
            };
        }
    };
    match file.metadata() {
        Ok(meta) if meta.is_file() => Opened::File(file),
        Ok(_) => Opened::Free,
        Err(e) => Opened::Unknown(e.kind().to_string()),
    }
}

/// Opened itself if it is a reparse point (`FILE_FLAG_OPEN_REPARSE_POINT`),
/// a directory too (`FILE_FLAG_BACKUP_SEMANTICS`), then its attributes read
/// from the handle. For Myotis's lease, the open is the try: for `DELETE`,
/// sharing reading, writing and deleting, which only another handle sharing
/// less (Myotis's share reading only) refuses, with a sharing violation.
#[cfg(windows)]
fn open_lock(path: &Path, probe: Probe) -> Opened {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const DELETE: u32 = 0x0001_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    let mut options = std::fs::OpenOptions::new();
    options
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
    match probe {
        Probe::FileLock => options.read(true),
        Probe::Lease => options.access_mode(DELETE | FILE_READ_ATTRIBUTES),
    };
    let file = match options.open(path) {
        Ok(file) => file,
        Err(e) if probe == Probe::Lease && e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => {
            return Opened::Held;
        }
        Err(e) if gone(&e) => return Opened::Free,
        Err(e) => return Opened::Unknown(e.kind().to_string()),
    };
    match file.metadata() {
        Ok(meta) if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
            Opened::Unknown("a link at the lock's name".to_owned())
        }
        Ok(meta) if meta.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0 => Opened::Free,
        Ok(_) => Opened::File(file),
        Err(e) => Opened::Unknown(e.kind().to_string()),
    }
}

#[cfg(not(any(unix, windows)))]
fn open_lock(_path: &Path, _probe: Probe) -> Opened {
    Opened::Free
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

    /// The lock's own name is never followed: a symlink there, even to a
    /// regular file held, is `Unknown`, and the file it names is neither
    /// opened nor locked. A FIFO there (or a link to one) doesn't wait for
    /// a writer, and no node's lock is a FIFO. A symlinked parent is
    /// followed, as the node follows it.
    #[cfg(unix)]
    #[test]
    fn a_lock_name_is_opened_without_following_or_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::write(&outside, "").unwrap();
        let held = std::fs::File::open(&outside).unwrap();
        held.lock().unwrap();
        let link = dir.path().join("state.lock");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(matches!(
            try_lock(&link, Probe::FileLock),
            Tried::Unknown(_)
        ));
        assert!(matches!(try_lock(&link, Probe::Lease), Tried::Unknown(_)));
        // Through a symlinked parent: followed, and the lock found held.
        let parent = dir.path().join("tor-data");
        std::fs::create_dir(&parent).unwrap();
        std::fs::rename(&outside, parent.join("dir.lock")).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&parent, &alias).unwrap();
        assert_eq!(
            try_lock(&alias.join("dir.lock"), Probe::FileLock),
            Tried::Held
        );
        drop(held);

        let fifo = dir.path().join("fifo.lock");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let started = std::time::Instant::now();
        assert_eq!(try_lock(&fifo, Probe::FileLock), Tried::Free);
        assert_eq!(try_lock(&fifo, Probe::Lease), Tried::Free);
        // A FIFO swapped in behind a link at the name: still not followed.
        let swapped = dir.path().join("swapped.lock");
        std::os::unix::fs::symlink(&fifo, &swapped).unwrap();
        assert!(matches!(
            try_lock(&swapped, Probe::FileLock),
            Tried::Unknown(_)
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn a_target_inside_the_profile_is_found_by_name_alone() {
        #[cfg(unix)]
        {
            let root = Path::new("/home/u/.config/Freedom/Profiles/work");
            assert!(lexically_inside(root, root));
            assert!(lexically_inside(&root.join("wallet"), root));
            assert!(lexically_inside(
                Path::new("/home/u/.config/Freedom/Profiles/work/x/../ipfs-data"),
                root
            ));
            assert!(lexically_inside(
                Path::new("/home/u/.config/Freedom/Profiles/other/../work/ant-data"),
                root
            ));
            assert!(lexically_inside(
                Path::new("/home/u/.config/Freedom/Profiles/WORK/identity"),
                root
            ));
            assert!(!lexically_inside(
                Path::new("/home/u/.config/Freedom/Profiles/work/../other"),
                root
            ));
            assert!(!lexically_inside(
                Path::new("/home/u/.config/Freedom/Profiles/workshop"),
                root
            ));
            assert!(!lexically_inside(Path::new("/mnt/big/ant-data"), root));
            assert!(!lexically_inside(Path::new("/../.."), root));
        }
        #[cfg(windows)]
        {
            let root = Path::new(r"\\?\C:\Users\u\AppData\Roaming\Freedom");
            assert!(lexically_inside(
                Path::new(r"C:\Users\U\AppData\Roaming\Freedom\ipfs-data"),
                root
            ));
            assert!(lexically_inside(
                Path::new(r"\\?\c:\users\u\appdata\roaming\freedom\x\..\identity"),
                root
            ));
            assert!(!lexically_inside(Path::new(r"D:\Freedom"), root));
            assert!(!lexically_inside(
                Path::new(r"C:\Users\u\AppData\Roaming\Freedom\..\Other"),
                root
            ));
        }
    }

    /// Relative links, and absolute ones into the profile, are found; one
    /// to an absolute path outside isn't.
    #[cfg(unix)]
    #[test]
    fn a_link_inside_the_profile_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let profile = base.join("profile");
        std::fs::create_dir_all(profile.join("wallet")).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        let link = |name: &str, target: &Path| {
            std::os::unix::fs::symlink(target, profile.join(name)).unwrap();
        };
        link("identity", Path::new("../wallet"));
        link("ant-data", &profile.join("wallet"));
        link("ipfs-data", &base.join("outside"));
        link("tor-data", Path::new("wallet"));
        std::fs::create_dir(profile.join("myotis")).unwrap();
        assert_eq!(
            link_inside(&profile, "identity").unwrap(),
            Some("a relative link")
        );
        assert_eq!(
            link_inside(&profile, "tor-data").unwrap(),
            Some("a relative link")
        );
        assert_eq!(
            link_inside(&profile, "ant-data").unwrap(),
            Some("a link into the profile")
        );
        assert_eq!(link_inside(&profile, "ipfs-data").unwrap(), None);
        assert_eq!(link_inside(&profile, "myotis").unwrap(), None);
    }
}
