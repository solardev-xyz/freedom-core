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
//!   integration branch. Each is looked up from the profile's root handle
//!   without following any link or crossing a mount, the entry itself
//!   included (`openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//!   RESOLVE_NO_XDEV` on Linux; elsewhere, or without it, a walk from
//!   handle to handle), its last component opened without waiting (a
//!   FIFO's open would wait for a writer), and the handle checked to be a
//!   regular file:
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
//!   - **antd** (pinned v0.5.77) holds `ant-data/antd.lock` for its whole
//!     life, taken before it opens its data (`acquire_instance_lock`),
//!     through fs4's `try_lock`: `flock` on Unix, `LockFileEx` on Windows,
//!     as arti's. An orphaned antd keeps it, so this covers the gap before
//!     main writes `ant-process.json`, and a marker lost in a crash. An
//!     `ant-data/` that is itself a link (a user's data on another disk)
//!     isn't followed to try it: that case is left to main's
//!     `ant-process.json` check, and the link moves.
//!
//!   A lock held, a link or a mount on the way (so a `tor-data/` or
//!   `myotis/` that is a link, which then doesn't move; `ant-data/` aside,
//!   as above), anything at the
//!   lock's name but a regular file or a directory, or an error other than
//!   a missing file, defers. Main also checks `ant-process.json`'s pid
//!   (B3), a second layer.
//! - **Then the copies** (PRF-9c, `copy.rs`): when `freedom/` is already
//!   on another mount than the profile's directory (a volume mounted there:
//!   its device differs, or on Linux its mount ID), every entry's rename
//!   into it would fail with `EXDEV`, so every entry will be copied. Each
//!   is surveyed (a mount point inside it, a special file, a file or
//!   directory this process can't use, a tree too deep, on Windows a
//!   reparse point), their total size must be within the 2 GiB a move
//!   copies (`copy_too_large`), and with the margin it must fit in the
//!   space free on `freedom/`'s volume. A `freedom/` on the profile's own mount (or none yet, which
//!   the move makes there) needs no copy, so nothing is walked: a renamed
//!   entry carries whatever is mounted inside it along, removes nothing,
//!   and a rollback renames it back.
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
use fc_store::fsx::Regular;

use super::copy::{self, Unfit};

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
    let mut freedom_dir = None;
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
            freedom_dir = Some(dir);
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
        let mount_point = mount_point(root, canonical, name)?;
        at_root.push((*name, AtRoot { found, mount_point }));
    }
    let state = StartState {
        root: &at_root,
        freedom,
        // Not looked for in an `identity` that is a mount: plan_start
        // defers on the mount, and nothing is read inside it.
        node_identity_journal: !identity_is_a_mount(&at_root) && node_identity_journal(root)?,
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
        if lock.linked_left_to_main && root.kind(OsStr::new(lock.entry))? != Kind::Dir {
            continue;
        }
        let mut parts = vec![lock.entry];
        parts.extend(lock.path);
        match try_lock(root, canonical, &parts, lock.probe) {
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
    if let Some(Unfit { why, detail }) = copies(root, freedom_dir.as_ref(), &entries)? {
        return Ok(Check::Defer { why, detail });
    }
    Ok(Check::Start(entries))
}

/// The entries a copy will move (all of them, when `freedom/` is on
/// another mount than the profile's directory; those
/// `FREEDOM_CORED_TEST_PROFILE_MIGRATE_EXDEV` lists), each surveyed, and
/// their total size checked against the space free on `freedom/`'s volume
/// (the profile's, where the move will make `freedom/`): the first reason
/// one can't be copied, or none.
fn copies(
    root: &Dir,
    freedom: Option<&Dir>,
    entries: &[&'static str],
) -> io::Result<Option<Unfit>> {
    let elsewhere = match freedom {
        Some(dir) => !dir.mount()?.same(root.mount()?),
        None => false,
    };
    let copied: Vec<&str> = entries
        .iter()
        .copied()
        .filter(|name| elsewhere || crate::testhooks::profile_migrate_exdev(name))
        .collect();
    if copied.is_empty() {
        return Ok(None);
    }
    let space = copy::space(freedom.unwrap_or(root))?;
    let mut size = 0u64;
    for name in copied {
        match copy::survey(root, name, space.block)? {
            Ok(bytes) => size = size.saturating_add(bytes),
            Err(unfit) => return Ok(Some(unfit)),
        }
    }
    if let Err(unfit) = copy::within_cap(size) {
        return Ok(Some(unfit));
    }
    Ok(copy::room(space, size).err())
}

/// Why the root's `name`, a link (a symlink, or on Windows a junction),
/// can't move as the link: its target is relative, so it would name
/// another place one directory deeper; or it is absolute and inside the
/// profile's directory ([`inside`]), so it may name another entry, which
/// the move takes elsewhere. `None` for anything else: a link to an absolute
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
    Ok(inside(&target, canonical).then_some("a link into the profile"))
}

/// Whether the absolute `target` names `root` or a path below it, by the
/// volume's own relation for names, following nothing:
/// - **Linux:** exact names.
/// - **macOS:** folded where the profile's volume ignores case
///   ([`case_insensitive`]), exact where it doesn't.
/// - **Windows:** folded, and for a target on a local drive letter (never a
///   share, so no lookup reaches the network) also once resolved, which
///   finds a short 8.3 alias of the profile's path.
#[cfg(target_os = "linux")]
fn inside(target: &Path, root: &Path) -> bool {
    named_inside(target, root, false)
}

#[cfg(target_os = "macos")]
fn inside(target: &Path, root: &Path) -> bool {
    named_inside(target, root, case_insensitive(root))
}

#[cfg(windows)]
fn inside(target: &Path, root: &Path) -> bool {
    use std::path::{Component, Prefix};
    let local = matches!(
        target.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    );
    named_inside(target, root, true)
        || (local
            && std::fs::canonicalize(target)
                .is_ok_and(|resolved| named_inside(&resolved, root, true)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn inside(target: &Path, root: &Path) -> bool {
    named_inside(target, root, true)
}

/// Whether the volume holding `root` ignores case: the last of its names
/// with a cased letter, its case flipped, names the same directory (device
/// and inode). In doubt (no such name, or a lookup failing), it is taken to
/// ignore case, macOS's default: a wider fold only defers more.
#[cfg(target_os = "macos")]
fn case_insensitive(root: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let same =
        |a: &Path, b: &Path| match (std::fs::symlink_metadata(a), std::fs::symlink_metadata(b)) {
            (Ok(a), Ok(b)) => Some(a.dev() == b.dev() && a.ino() == b.ino()),
            (Ok(_), Err(e)) if e.kind() == io::ErrorKind::NotFound => Some(false),
            _ => None,
        };
    for dir in root.ancestors() {
        let (Some(name), Some(parent)) = (dir.file_name(), dir.parent()) else {
            continue;
        };
        let name = name.to_string_lossy();
        let flipped: String = name
            .chars()
            .flat_map(|c| -> Vec<char> {
                if c.is_lowercase() {
                    c.to_uppercase().collect()
                } else {
                    c.to_lowercase().collect()
                }
            })
            .collect();
        if flipped == name {
            continue;
        }
        return same(dir, &parent.join(flipped)).unwrap_or(true);
    }
    true
}

/// Whether the absolute `target`, its `.` and `..` resolved by name alone
/// (no link followed), is `root` or below it, its names compared exactly or
/// folded (`fc_profile::delete::fold`); a Windows prefix compares without
/// its verbatim form, the drive letter ignoring case.
fn named_inside(target: &Path, root: &Path, fold: bool) -> bool {
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
                    let name = name.to_string_lossy();
                    out.push(if fold {
                        fc_profile::delete::fold(&name)
                    } else {
                        name.into_owned()
                    });
                }
            }
        }
        out
    };
    let (target, root) = (parts(target), parts(root));
    target.len() >= root.len() && target[..root.len()] == root[..]
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

/// Whether the root's `identity`, as observed, is a mount point.
fn identity_is_a_mount(at_root: &[(&str, AtRoot)]) -> bool {
    at_root
        .iter()
        .any(|(name, seen)| *name == "identity" && seen.mount_point)
}

/// A node identity journal or its staging file in the root's `identity/`,
/// read through the root's handle, following nothing: its recovery would
/// write at the absolute root it records. An `identity` that is a link
/// (or anything but a directory) holds no journal of this profile's: it
/// moves as the link, or defers as one into the profile.
fn node_identity_journal(root: &Dir) -> io::Result<bool> {
    if root.kind(OsStr::new("identity"))? != Kind::Dir {
        return Ok(false);
    }
    let Some(identity) = root.child(OsStr::new("identity"), false)? else {
        return Ok(false);
    };
    for name in [crate::journal::JOURNAL, crate::journal::STAGING] {
        if identity.kind(OsStr::new(name))? != Kind::Missing {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the root's `name` is a mount point, not following a symlink at
/// it (a symlink is moved as the link): on another device than the root,
/// or, on Linux, on another mount (a bind mount of the same file system).
#[cfg(unix)]
fn mount_point(root: &Dir, _canonical: &Path, name: &str) -> io::Result<bool> {
    use rustix::fs::FileType;
    let stat = rustix::fs::statat(root.as_fd(), name, no_follow())?;
    if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink {
        return Ok(false);
    }
    #[allow(clippy::unnecessary_cast)]
    let here = stat.st_dev as u64;
    if here != root.identity()?.0 {
        return Ok(true);
    }
    #[cfg(target_os = "linux")]
    {
        // `STATX_MNT_ID` (Linux 5.8): an older kernel that doesn't give it
        // leaves the device check alone.
        if let (Some(entry), Some(root)) = (mount_id(root, name), mount_id(root, "")) {
            return Ok(entry != root);
        }
    }
    Ok(false)
}

/// A lookup's flags: no link followed, and on Linux no automount
/// triggered: what is at a name is classified, never entered.
#[cfg(unix)]
fn no_follow() -> rustix::fs::AtFlags {
    #[cfg(target_os = "linux")]
    {
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW | rustix::fs::AtFlags::NO_AUTOMOUNT
    }
    #[cfg(not(target_os = "linux"))]
    {
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW
    }
}

/// The mount ID of `name` in `root` (of `root` itself for an empty name).
#[cfg(target_os = "linux")]
fn mount_id(root: &Dir, name: &str) -> Option<u64> {
    use rustix::fs::{AtFlags, StatxFlags, statx};
    let flags = if name.is_empty() {
        AtFlags::EMPTY_PATH
    } else {
        no_follow()
    };
    let stat = statx(root.as_fd(), name, flags, StatxFlags::MNT_ID).ok()?;
    (StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID))
        .then_some(stat.stx_mnt_id)
}

/// Whether the root's `name` is a volume mount point: a reparse point whose
/// target is a volume (`\\?\Volume{…}\`). A directory that is no reparse
/// point is on its parent's volume; a junction or a symlink to a path is a
/// link, moved as itself.
#[cfg(windows)]
fn mount_point(_root: &Dir, canonical: &Path, name: &str) -> io::Result<bool> {
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
fn mount_point(_root: &Dir, _canonical: &Path, _name: &str) -> io::Result<bool> {
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
    /// When the entry itself is a link (or anything but a directory), the
    /// core doesn't follow it to try the lock, and leaves that case to
    /// main's own check instead of deferring: antd's `ant-process.json`
    /// (B3). An `ant-data/` linked to another disk is a user's ordinary
    /// choice, and moves as the link. arti and Myotis have no such check,
    /// so theirs defers.
    linked_left_to_main: bool,
}

/// The locks the spike found (the module's comment).
const NODE_LOCKS: &[NodeLock] = &[
    NodeLock {
        entry: "tor-data",
        path: &["state", "state", "state.lock"],
        probe: Probe::FileLock,
        linked_left_to_main: false,
    },
    NodeLock {
        entry: "tor-data",
        path: &["cache", "dir.lock"],
        probe: Probe::FileLock,
        linked_left_to_main: false,
    },
    NodeLock {
        entry: "ant-data",
        path: &["antd.lock"],
        probe: Probe::FileLock,
        linked_left_to_main: true,
    },
    NodeLock {
        entry: "myotis",
        path: &[".freedom-myotis-lifetime"],
        probe: Probe::Lease,
        linked_left_to_main: false,
    },
    NodeLock {
        entry: "myotis",
        path: &[".freedom-myotis-owner"],
        probe: Probe::Lease,
        linked_left_to_main: false,
    },
    NodeLock {
        entry: "myotis",
        path: &["gnosis", ".freedom-myotis-lifetime"],
        probe: Probe::Lease,
        linked_left_to_main: false,
    },
    NodeLock {
        entry: "myotis",
        path: &["gnosis", ".freedom-myotis-owner"],
        probe: Probe::Lease,
        linked_left_to_main: false,
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

/// Tries the lock at `parts` below the profile's root and lets it go at
/// once. The whole path is looked up from the root's handle without
/// following any link and without crossing a mount, the entry itself
/// included, and the last component opened without waiting (a FIFO's open
/// would wait for a writer):
/// - **a link or a mount on the way,** or anything but a directory or a
///   regular file at the lock's name, is `Unknown`: the core doesn't follow
///   it to storage it hasn't qualified, and can't tell whether a node holds
///   what it names. So a profile whose `tor-data/` or `myotis/` is a link
///   doesn't move: its old layout keeps working;
/// - **nothing there** (or a file on the way, with nothing below it), or a
///   directory at the lock's name, is free: no node's lock is one;
/// - **a regular file:** its lock tried.
fn try_lock(root: &Dir, canonical: &Path, parts: &[&str], probe: Probe) -> Tried {
    let file = match open_beneath(root, parts) {
        Opened::File(file) => file,
        Opened::Free => return Tried::Free,
        Opened::Unknown(why) => return Tried::Unknown(why),
    };
    #[cfg(windows)]
    if probe == Probe::Lease {
        drop(file);
        let mut path = canonical.to_path_buf();
        path.extend(parts);
        return share_probe(&path);
    }
    let _ = (canonical, probe);
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            Tried::Free
        }
        Err(std::fs::TryLockError::WouldBlock) => Tried::Held,
        Err(std::fs::TryLockError::Error(e)) => Tried::Unknown(e.kind().to_string()),
    }
}

/// What looking a lock up found.
enum Opened {
    /// A regular file, open for reading: its lock is tried next.
    File(std::fs::File),
    Free,
    Unknown(String),
}

const ON_THE_WAY: &str = "a link or a mount on the way to the lock";

/// Linux: `openat2` from the root's handle with `RESOLVE_BENEATH`,
/// `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_XDEV` and `RESOLVE_NO_MAGICLINKS`,
/// and `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`: one lookup that refuses a
/// link, a mount (a bind mount of the same file system too) and a way out.
/// A kernel without it (before 5.6, or a filter refusing it) takes the
/// walk.
#[cfg(target_os = "linux")]
fn open_beneath(root: &Dir, parts: &[&str]) -> Opened {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    use rustix::io::Errno;
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let resolve = ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_XDEV
        | ResolveFlags::NO_MAGICLINKS;
    match rustix::fs::openat2(root.as_fd(), parts.join("/"), flags, Mode::empty(), resolve) {
        Ok(fd) => classify(std::fs::File::from(fd), None),
        Err(Errno::NOSYS | Errno::PERM) => walk(root, parts),
        Err(Errno::LOOP | Errno::XDEV) => Opened::Unknown(ON_THE_WAY.to_owned()),
        Err(Errno::NOENT | Errno::NOTDIR) => Opened::Free,
        Err(e) => Opened::Unknown(io::Error::from(e).kind().to_string()),
    }
}

#[cfg(not(target_os = "linux"))]
fn open_beneath(root: &Dir, parts: &[&str]) -> Opened {
    walk(root, parts)
}

/// Component by component from the root's handle (`fc_store`'s `Dir`):
/// each name classified first by one lookup that follows nothing and
/// enters nothing ([`classify_at`]: its kind and device), before any open
/// or answer; each directory then opened through its parent refusing a
/// link (a Windows reparse point too); and the lock's name opened without
/// following or waiting. A name on another device than the root's, the
/// lock's own included (a directory mounted at it), is a mount.
fn walk(root: &Dir, parts: &[&str]) -> Opened {
    let unknown = |e: io::Error| Opened::Unknown(e.kind().to_string());
    let Some((last, parents)) = parts.split_last() else {
        return Opened::Free;
    };
    let device = match root.identity() {
        Ok((device, _)) => device,
        Err(e) => return unknown(e),
    };
    let mut dir = match root.try_clone() {
        Ok(dir) => dir,
        Err(e) => return unknown(e),
    };
    for part in parents {
        match classify_at(&dir, part, device) {
            Ok(Seen::Missing | Seen::File) => return Opened::Free,
            Ok(Seen::Other | Seen::Mount) => return Opened::Unknown(ON_THE_WAY.to_owned()),
            Ok(Seen::Dir) => {}
            Err(e) => return unknown(e),
        }
        dir = match dir.child(OsStr::new(part), false) {
            Ok(Some(child)) => child,
            Ok(None) => return Opened::Free,
            // Swapped for a link since: refused.
            Err(_) => return Opened::Unknown(ON_THE_WAY.to_owned()),
        };
        match dir.identity() {
            Ok((here, _)) if here == device => {}
            Ok(_) => return Opened::Unknown(ON_THE_WAY.to_owned()),
            Err(e) => return unknown(e),
        }
    }
    match classify_at(&dir, last, device) {
        Ok(Seen::Missing | Seen::Dir) => return Opened::Free,
        Ok(Seen::Mount) => return Opened::Unknown(ON_THE_WAY.to_owned()),
        Ok(Seen::Other) => return Opened::Unknown(OTHER.to_owned()),
        Ok(Seen::File) => {}
        Err(e) => return unknown(e),
    }
    match dir.open_regular(OsStr::new(last), false) {
        Ok(Regular::File(file)) => classify(file, Some(device)),
        Ok(Regular::Missing) => Opened::Free,
        Ok(Regular::Other) => Opened::Unknown(OTHER.to_owned()),
        Err(e) => unknown(e),
    }
}

/// What one anchored lookup found at a name.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Missing,
    File,
    Dir,
    /// A link, a reparse point, or a special file.
    Other,
    /// On another device than the root's: a mount point.
    Mount,
}

/// `name` in `dir`, by one `fstatat` from the handle that follows no link
/// and (Linux) triggers no automount: its kind and its device together,
/// before anything opens it.
#[cfg(unix)]
fn classify_at(dir: &Dir, name: &str, device: u64) -> io::Result<Seen> {
    use rustix::fs::FileType;
    let stat = match rustix::fs::statat(dir.as_fd(), name, no_follow()) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(Seen::Missing),
        Err(e) => return Err(e.into()),
    };
    let kind = FileType::from_raw_mode(stat.st_mode);
    #[allow(clippy::unnecessary_cast)]
    let here = stat.st_dev as u64;
    Ok(match kind {
        FileType::Symlink => Seen::Other,
        _ if here != device => Seen::Mount,
        FileType::RegularFile => Seen::File,
        FileType::Directory => Seen::Dir,
        _ => Seen::Other,
    })
}

/// On Windows a volume is reached only through a reparse point, which
/// `Dir::kind` reports as `Other`.
#[cfg(not(unix))]
fn classify_at(dir: &Dir, name: &str, _device: u64) -> io::Result<Seen> {
    Ok(match dir.kind(OsStr::new(name))? {
        Kind::Missing => Seen::Missing,
        Kind::File => Seen::File,
        Kind::Dir => Seen::Dir,
        Kind::Other => Seen::Other,
    })
}

const OTHER: &str = "a link or a special file at the lock's name";

/// The opened lock's handle: a regular file (on the root's device, where
/// the walk checks it), a directory, or anything else.
fn classify(file: std::fs::File, device: Option<u64>) -> Opened {
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(e) => return Opened::Unknown(e.kind().to_string()),
    };
    if meta.is_dir() {
        return Opened::Free;
    }
    if !meta.is_file() {
        return Opened::Unknown(OTHER.to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if device.is_some_and(|device| meta.dev() != device) {
            return Opened::Unknown(ON_THE_WAY.to_owned());
        }
    }
    let _ = device;
    Opened::File(file)
}

/// Windows, Myotis's lease, once the walk found a regular file there: opens
/// it for `DELETE` (and its attributes), sharing reading, writing and
/// deleting, not following a reparse point, and lets it go. Refused with a
/// sharing violation only while another handle shares less (Myotis's share
/// reading only). Its parents were checked from the root's handle just
/// before; this open goes by path, so a parent swapped for a junction in
/// between (by the same user) isn't seen here.
#[cfg(windows)]
fn share_probe(path: &Path) -> Tried {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const DELETE: u32 = 0x0001_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    match std::fs::OpenOptions::new()
        .access_mode(DELETE | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => match file.metadata() {
            Ok(meta) if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                Tried::Unknown(OTHER.to_owned())
            }
            Ok(_) => Tried::Free,
            Err(e) => Tried::Unknown(e.kind().to_string()),
        },
        Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Tried::Held,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Tried::Free,
        Err(e) => Tried::Unknown(e.kind().to_string()),
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
        let open = |path: &Path| {
            Dir::open_root(path, fc_store::anchor::Resolve::Follow)
                .unwrap()
                .unwrap()
        };
        let slash = open(Path::new("/"));
        #[cfg(target_os = "linux")]
        if Path::new("/proc/self").exists() {
            assert!(mount_point(&slash, Path::new("/"), "proc").unwrap());
        }
        #[cfg(target_os = "macos")]
        assert!(mount_point(&slash, Path::new("/"), "dev").unwrap());
        let _ = &slash;
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir(base.join("ant-data")).unwrap();
        std::os::unix::fs::symlink("/", base.join("ipfs-data")).unwrap();
        let root = open(&base);
        assert!(!mount_point(&root, &base, "ant-data").unwrap());
        assert!(!mount_point(&root, &base, "ipfs-data").unwrap());
    }

    /// A profile root as the move opens it, and a probe of `parts` below it
    /// by both lookups (the Linux one and the walk).
    struct Root {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
    }

    fn root() -> Root {
        let dir = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(dir.path()).unwrap();
        Root { _dir: dir, path }
    }

    fn probe(root: &Root, parts: &[&str], probe: Probe) -> Tried {
        let dir = Dir::open_root(&root.path, fc_store::anchor::Resolve::Follow)
            .unwrap()
            .unwrap();
        let tried = try_lock(&dir, &root.path, parts, probe);
        // The walk alone (the fallback where `openat2` is missing) agrees.
        let walked = match walk(&dir, parts) {
            Opened::File(_) => None,
            Opened::Free => Some(Tried::Free),
            Opened::Unknown(why) => Some(Tried::Unknown(why)),
        };
        match (&tried, walked) {
            (Tried::Free, Some(Tried::Free)) | (Tried::Held, None) => {}
            (Tried::Free, None) => {}
            (Tried::Unknown(_), Some(Tried::Unknown(_))) => {}
            (tried, walked) => panic!("{parts:?}: {tried:?} but the walk found {walked:?}"),
        }
        tried
    }

    #[test]
    fn a_lock_held_is_found_and_let_go_otherwise() {
        let r = root();
        let lock = ["tor-data", "state", "state", "state.lock"];
        assert_eq!(probe(&r, &lock, Probe::FileLock), Tried::Free, "missing");
        let path = r.path.join("tor-data/state/state/state.lock");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "").unwrap();
        assert_eq!(probe(&r, &lock, Probe::FileLock), Tried::Free);
        // Let go: another takes it after the try.
        let other = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        other.try_lock().unwrap();
        // flock and LockFileEx exclude another open of the same file, even
        // in this process.
        assert_eq!(probe(&r, &lock, Probe::FileLock), Tried::Held);
        other.unlock().unwrap();
        assert_eq!(probe(&r, &lock, Probe::FileLock), Tried::Free);
        // A directory at the name holds no lock.
        std::fs::create_dir_all(r.path.join("tor-data/cache/dir.lock")).unwrap();
        assert_eq!(
            probe(&r, &["tor-data", "cache", "dir.lock"], Probe::FileLock),
            Tried::Free
        );
        // A file on the way: nothing below it.
        std::fs::create_dir_all(r.path.join("myotis")).unwrap();
        std::fs::write(r.path.join("myotis/gnosis"), "").unwrap();
        assert_eq!(
            probe(
                &r,
                &["myotis", "gnosis", ".freedom-myotis-lifetime"],
                Probe::Lease
            ),
            Tried::Free
        );
    }

    /// Nothing on the way to a lock is followed, the entry itself included,
    /// nor the lock's own name: a symlink anywhere is `Unknown`, and what it
    /// names (here a regular file held) is neither opened nor locked. A FIFO
    /// at the name doesn't wait for a writer, and is `Unknown` too: no
    /// node's lock is one.
    #[cfg(unix)]
    #[test]
    fn a_lock_is_looked_up_without_following_or_waiting() {
        use std::os::unix::fs::symlink;
        let r = root();
        let outside = root();
        let held_path = outside.path.join("state/state/state.lock");
        std::fs::create_dir_all(held_path.parent().unwrap()).unwrap();
        std::fs::write(&held_path, "").unwrap();
        let held = std::fs::File::open(&held_path).unwrap();
        held.lock().unwrap();
        let lock = ["tor-data", "state", "state", "state.lock"];
        // The entry a link to another place (another disk, say).
        symlink(&outside.path, r.path.join("tor-data")).unwrap();
        assert!(matches!(
            probe(&r, &lock, Probe::FileLock),
            Tried::Unknown(_)
        ));
        // A link in the middle.
        std::fs::remove_file(r.path.join("tor-data")).unwrap();
        std::fs::create_dir(r.path.join("tor-data")).unwrap();
        symlink(outside.path.join("state"), r.path.join("tor-data/state")).unwrap();
        assert!(matches!(
            probe(&r, &lock, Probe::FileLock),
            Tried::Unknown(_)
        ));
        // At the lock's name.
        std::fs::remove_file(r.path.join("tor-data/state")).unwrap();
        std::fs::create_dir_all(r.path.join("tor-data/state/state")).unwrap();
        symlink(&held_path, r.path.join("tor-data/state/state/state.lock")).unwrap();
        assert!(matches!(
            probe(&r, &lock, Probe::FileLock),
            Tried::Unknown(_)
        ));
        assert!(matches!(probe(&r, &lock, Probe::Lease), Tried::Unknown(_)));
        drop(held);

        let fifo = r.path.join("myotis");
        std::fs::create_dir(&fifo).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(fifo.join(".freedom-myotis-lifetime"))
            .status()
            .unwrap();
        assert!(made.success());
        let started = std::time::Instant::now();
        let lease = ["myotis", ".freedom-myotis-lifetime"];
        assert!(matches!(probe(&r, &lease, Probe::Lease), Tried::Unknown(_)));
        assert!(matches!(
            probe(&r, &lease, Probe::FileLock),
            Tried::Unknown(_)
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    /// Mounts in a test profile (CI's tmpfs: `FREEDOM_TEST_TMPFS` names a
    /// profile with one mounted at `tor-data/state`, one at
    /// `myotis/.freedom-myotis-lifetime` and one at `identity`), each
    /// refused before it is entered:
    /// - on the way to a lock, by `openat2`'s `RESOLVE_NO_XDEV` and by the
    ///   fallback walk's lookup before it opens anything;
    /// - a directory mounted at a lock's own name, the same, not free;
    /// - an `identity` that is a mount, holding a node identity journal:
    ///   deferred as a mount, the journal never looked for.
    ///
    /// Skipped where the variable isn't set, but not under CI, whose Linux
    /// test job mounts them.
    #[cfg(target_os = "linux")]
    #[test]
    fn mounts_in_the_profile_are_refused_before_they_are_entered() {
        let Some(profile) = std::env::var_os("FREEDOM_TEST_TMPFS") else {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI's Linux test job mounts FREEDOM_TEST_TMPFS"
            );
            return;
        };
        let profile = std::path::PathBuf::from(profile);
        let state = profile.join("tor-data").join("state");
        std::fs::create_dir_all(state.join("state")).unwrap();
        std::fs::write(state.join("state").join("state.lock"), "").unwrap();
        let root = Dir::open_root(&profile, fc_store::anchor::Resolve::Follow)
            .unwrap()
            .unwrap();
        let (device, _) = root.identity().unwrap();
        let tor = root.child(OsStr::new("tor-data"), false).unwrap().unwrap();
        assert_eq!(classify_at(&tor, "state", device).unwrap(), Seen::Mount);
        for parts in [
            &["tor-data", "state", "state", "state.lock"][..],
            &["myotis", ".freedom-myotis-lifetime"][..],
        ] {
            assert!(
                matches!(walk(&root, parts), Opened::Unknown(_)),
                "{parts:?}: the walk"
            );
            assert!(
                matches!(
                    try_lock(&root, &profile, parts, Probe::Lease),
                    Tried::Unknown(_)
                ),
                "{parts:?}"
            );
        }
        std::fs::write(
            profile.join("identity").join("node-identity-journal.json"),
            "{}",
        )
        .unwrap();
        match check(&root, &profile).unwrap() {
            Check::Defer { why, detail } => {
                assert_eq!((why, detail.as_str()), ("mount_point", "identity"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_target_inside_the_profile_is_found_by_name_alone() {
        #[cfg(unix)]
        {
            let root = Path::new("/home/u/.config/Freedom/Profiles/work");
            let inside = |target: &str| named_inside(Path::new(target), root, false);
            assert!(named_inside(root, root, false));
            assert!(inside("/home/u/.config/Freedom/Profiles/work/wallet"));
            assert!(inside(
                "/home/u/.config/Freedom/Profiles/work/x/../ipfs-data"
            ));
            assert!(inside(
                "/home/u/.config/Freedom/Profiles/other/../work/ant-data"
            ));
            assert!(!inside("/home/u/.config/Freedom/Profiles/work/../other"));
            assert!(!inside("/home/u/.config/Freedom/Profiles/workshop"));
            assert!(!inside("/mnt/big/ant-data"));
            assert!(!inside("/../.."));
            // Case: exact unless folded.
            let shouted = Path::new("/home/u/.config/Freedom/Profiles/WORK/identity");
            assert!(!named_inside(shouted, root, false));
            assert!(named_inside(shouted, root, true));
            #[cfg(target_os = "linux")]
            assert!(!super::inside(shouted, root), "Linux names are exact");
        }
        #[cfg(windows)]
        {
            let root = Path::new(r"\\?\C:\Users\u\AppData\Roaming\Freedom");
            let inside = |target: &str| named_inside(Path::new(target), root, true);
            assert!(inside(r"C:\Users\U\AppData\Roaming\Freedom\ipfs-data"));
            assert!(inside(
                r"\\?\c:\users\u\appdata\roaming\freedom\x\..\identity"
            ));
            assert!(!inside(r"D:\Freedom"));
            assert!(!inside(r"C:\Users\u\AppData\Roaming\Freedom\..\Other"));
            // A share is compared by name and never resolved.
            assert!(!super::inside(Path::new(r"\\server\share\Freedom"), root));
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
