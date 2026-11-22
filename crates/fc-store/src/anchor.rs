//! Files under a node's root, reached through no symlink below it (review
//! of #177; design 0008, "Spawn and lock": every operation under a Radicle
//! home uses the gate's canonical path).
//!
//! A journal names its targets under its root. A symlinked directory below
//! the root (`keys`, `node`) would otherwise take a removal, a rename or a
//! read out of the home: into another home's `keys`, or anywhere. So every
//! operation on a node identity file goes through [`Dir`]:
//!
//! - **The root is opened once,** by the caller, and held for the whole
//!   operation ([`Dir::open_root`]): planning, staging, install and cleanup
//!   all reach what is below it from that handle, never by its path again
//!   (review of #177, round 2). A Radicle home is opened after its gate is
//!   taken, as the gate's canonical path ([`Resolve::Canonical`]): no
//!   symlink is followed at it; the directory at that path, resolved again,
//!   must be the one opened; and on Unix it must be the very directory the
//!   gate was taken for, by the device and inode the gate recorded once its
//!   lock was held (review of #177, round 3). So a home replaced since the
//!   gate was taken, by a symlink or by another real directory, is refused,
//!   and one moved after the open keeps receiving its operation. On
//!   Windows the directory at the path must have the handle's file ID; the
//!   gate's recorded identity, a Unix device and inode, isn't compared
//!   there. Bee's
//!   root is the data directory main names, which may itself be a symlink
//!   ([`Resolve::Follow`]). A root that doesn't exist is no target
//!   (`None`): nothing under it exists.
//! - **Each directory below it** is opened through its parent, refusing a
//!   symlink (`O_NOFOLLOW`, `O_DIRECTORY`; on Windows a reparse point, a
//!   symlink or a junction, opened itself and refused), and created
//!   (`0700`; on Windows inheriting its parent's ACL) when a write needs
//!   it.
//! - **On Unix** the final operation is relative to that directory's handle
//!   (`openat`, `unlinkat`, `renameat`, `fstatat` without following), so a
//!   directory swapped for a symlink after it was opened can't redirect it.
//!   A tree's removal ([`Dir::remove_tree`]) walks it the same way, from
//!   handle to handle, and unlinks each entry relative to its directory's,
//!   holding a bounded number of handles however deep the tree is.
//! - **On Windows** the same holds through `fc-sys`'s handle-relative calls
//!   (design 0013, "Windows handle I/O (#963)"): each file is opened or
//!   made by `NtCreateFile` relative to its directory's handle, never
//!   following a reparse point at its name (one is refused, or removed
//!   itself), and renamed (`FileRenameInformationEx`, with
//!   `RootDirectory`) and deleted (`FileDispositionInfoEx`) through its own
//!   handle, POSIX semantics where the system serves them (Windows 10 1607
//!   and NTFS) and the older classes, still by handle, where it doesn't. A
//!   directory swapped for a junction after it was opened can't redirect
//!   anything: the operation stays in the directory the handle holds. A
//!   tree is walked by handle too. Only the root is opened by its path.
//! - **A tree within one mount** (design 0013, "The move": PRF-9c's
//!   cross-device copy): [`Dir::walk`], [`Dir::copy_tree`] and
//!   [`Dir::remove_tree_within`] never enter a directory on another mount
//!   than the directory they start from ([`Mount`]): a walk reports it, a
//!   copy or a removal stops with an error. Removing through a mount point
//!   would empty the mounted volume, and copying through it would pull the
//!   whole volume across.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::fsx::Regular;

mod tree;

pub use tree::MAX_DEPTH;

/// A directory's identity: its device and inode (Unix), as a gate records
/// it once its lock is held ([`Resolve::Canonical`]). The caller builds it
/// from its gate's (fc-service's `gate::DirIdentity`, the same two fields),
/// so this crate stays free of the service skeleton, which is empty on
/// iOS and Android.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirIdentity {
    pub dev: u64,
    pub ino: u64,
}

/// What is at a name, not following a symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Missing,
    File,
    Dir,
    /// A symlink, a reparse point, or anything else that isn't a regular
    /// file or a directory.
    Other,
}

/// The mount a directory is on: its device and, on Linux 5.8 and later,
/// its mount's ID (`STATX_MNT_ID`), which tells a bind mount of the same
/// file system from its parent; on Windows, its volume's serial number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mount {
    device: u64,
    id: Option<u64>,
}

impl Mount {
    /// Whether both are the same mount: the same device, and the same mount
    /// ID where both are known.
    pub fn same(self, other: Mount) -> bool {
        self.device == other.device
            && match (self.id, other.id) {
                (Some(one), Some(two)) => one == two,
                _ => true,
            }
    }
}

/// A volume's free space ([`Dir::space`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Space {
    /// The bytes this process's user may still write (`f_bavail`; on
    /// Windows the caller's available allocation units, under any quota).
    pub available: u64,
    /// The volume's allocation unit, in bytes, at least 1: a file takes a
    /// whole number of them.
    pub block: u64,
}

/// What a walk ([`Dir::walk`]) meets, not following a symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Node {
    /// A regular file, its length, and whether this process may read it.
    File { len: u64, readable: bool },
    /// A directory on the walk's mount, and whether this process may list
    /// it and add and remove entries in it (read, write and search). One it
    /// may not use isn't entered.
    Dir { usable: bool },
    /// A symlink (on Windows any reparse point: a symlink or a junction),
    /// never followed.
    Link,
    /// A FIFO, a socket or a device: never opened.
    Special,
    /// A directory on another mount than the walk's: not entered.
    Mount,
    /// A directory [`MAX_DEPTH`] levels below the walk's top: not entered.
    Deep,
}

/// How a node's root is opened ([`Dir::open_root`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolve {
    /// As named, following symlinks: Bee's data directory, which main names.
    Follow,
    /// A gate's canonical path (a Radicle home's): no symlink is followed at
    /// it, and the directory at that path now, resolved again, must be the
    /// one opened. With the identity the gate recorded (`Some`, Unix), it
    /// must also be the directory the gate was taken for: one moved into its
    /// path since, a real directory as much as a symlink, is refused.
    Canonical(Option<DirIdentity>),
}

/// A node's root, or a directory under it, opened through no symlink.
pub struct Dir {
    path: PathBuf,
    #[cfg(unix)]
    fd: rustix::fd::OwnedFd,
    #[cfg(windows)]
    handle: std::os::windows::io::OwnedHandle,
}

impl Dir {
    /// The root, opened once: `None` if it doesn't exist. A root that isn't
    /// a directory, or (`Canonical`) isn't where its path says or isn't its
    /// gate's directory, is an error.
    pub fn open_root(root: &Path, resolve: Resolve) -> io::Result<Option<Dir>> {
        imp::open_root(root, resolve)
    }

    /// This directory's path: for building targets, logs and test hooks,
    /// never to reach it again.
    pub fn location(&self) -> &Path {
        &self.path
    }

    /// The directory holding `target` under this one, reached from this
    /// handle, and `target`'s name. Every directory on the way is opened
    /// without following a symlink; with `create`, missing ones are made
    /// (`0700`, their parents flushed). `None` when one is missing and
    /// `create` is off: nothing under it exists. A target that isn't under
    /// this directory in plain components is an error.
    pub fn under(&self, target: &Path, create: bool) -> io::Result<Option<(Dir, OsString)>> {
        let relative = target
            .strip_prefix(&self.path)
            .map_err(|_| io::Error::other("a node identity file outside its root"))?;
        let mut names: Vec<&OsStr> = Vec::new();
        for component in relative.components() {
            match component {
                Component::Normal(name) => names.push(name),
                _ => return Err(io::Error::other("a node identity path that isn't plain")),
            }
        }
        let Some((file, parents)) = names.split_last() else {
            return Err(io::Error::other("a node identity path names no file"));
        };
        let mut dir = imp::try_clone(self)?;
        for name in parents {
            match dir.child(name, create)? {
                Some(child) => dir = child,
                None => return Ok(None),
            }
        }
        Ok(Some((dir, (*file).to_owned())))
    }

    /// The path of `name` in this directory: for logs and test hooks only.
    pub fn path(&self, name: &OsStr) -> PathBuf {
        self.path.join(name)
    }

    /// The directory `name` in this one, through no symlink.
    pub fn child(&self, name: &OsStr, create: bool) -> io::Result<Option<Dir>> {
        imp::child(self, name, create)
    }

    /// What is at `name`, not following a symlink (nor, on Linux,
    /// triggering an automount there).
    pub fn kind(&self, name: &OsStr) -> io::Result<Kind> {
        imp::kind(self, name)
    }

    /// `name`, opened for reading (or writing too) only if it is a regular
    /// file, judged on the open handle, through no symlink, and without
    /// waiting (non-blocking).
    pub fn open_regular(&self, name: &OsStr, write: bool) -> io::Result<Regular> {
        imp::open_regular(self, name, write)
    }

    /// `name`, opened for reading only if it is a regular file, judged on
    /// the open handle, without waiting; a symlink at `name` is followed,
    /// as JS's `readFileSync` follows Radicle's `config.json`.
    pub fn open_following(&self, name: &OsStr) -> io::Result<Regular> {
        imp::open_following(self, name)
    }

    /// A new file `name` (`0600` on Unix), which must not exist.
    pub fn create_new(&self, name: &OsStr) -> io::Result<File> {
        imp::create_new(self, name)
    }

    /// Removes `name` if it is there, following no symlink (a symlink is
    /// removed itself); a directory there is an error. Whether anything
    /// was removed.
    pub fn unlink(&self, name: &OsStr) -> io::Result<bool> {
        match self.kind(name)? {
            Kind::Missing => Ok(false),
            Kind::Dir => Err(io::Error::other(
                "a directory where a node identity file was to be removed",
            )),
            Kind::File | Kind::Other => imp::unlink(self, name),
        }
    }

    /// Removes `name` and everything under it, following no symlink (a
    /// symlink in its place is removed itself). Whether anything was there.
    /// The tree is walked from this directory's handle, each entry removed
    /// relative to its own directory's (review of #177, round 2).
    pub fn remove_tree(&self, name: &OsStr) -> io::Result<bool> {
        imp::remove_tree(self, name, None, &mut || Ok(()))
    }

    /// As [`Dir::remove_tree`], but never past this directory's mount:
    /// `name`, if it is a directory, and every directory under it must be
    /// on the mount this directory is on ([`Mount::same`]), or the removal
    /// stops with an error at the first that isn't, the rest left as it
    /// is. A symlink or anything else that isn't a directory is unlinked
    /// itself, as `remove_tree` does. `each` runs after each entry is
    /// removed, and an error from it stops the removal. Whether anything
    /// was there.
    pub fn remove_tree_within(
        &self,
        name: &OsStr,
        each: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<bool> {
        let bound = self.mount()?;
        imp::remove_tree(self, name, Some(bound), each)
    }

    /// The mount this directory is on.
    pub fn mount(&self) -> io::Result<Mount> {
        imp::mount_of(self)
    }

    /// Whether this process may add and remove entries here: on Unix, write
    /// and search permission on the directory (`faccessat` on its handle),
    /// which removing an entry of it takes. On Windows a removal takes each
    /// entry's own `DELETE` right, which [`Dir::walk`] probes, so this is
    /// always true there.
    pub fn may_change(&self) -> bool {
        imp::may_change(self)
    }

    /// Renames `from` over `to`, both in this directory, replacing whatever
    /// `to` is without following it.
    pub fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        imp::rename(self, from, to)
    }

    /// Renames `from` in this directory to `to` in `target`, both reached
    /// through their handles (`renameat`; Windows: `FileRenameInformationEx`
    /// with `RootDirectory`), replacing whatever `to` is without following
    /// it. A profile's move recovery puts an entry
    /// back from `freedom/` (design 0013).
    pub fn rename_into(&self, from: &OsStr, target: &Dir, to: &OsStr) -> io::Result<()> {
        imp::rename_into(self, from, target, to)
    }

    /// Whether `name` is the file `handle` holds (Unix: the same device and
    /// inode; Windows: the same volume serial number and file ID); `false`
    /// if nothing is there.
    pub fn same_file(&self, handle: &File, name: &OsStr) -> io::Result<bool> {
        imp::same_file(self, handle, name)
    }

    /// Flushes this directory's entries (Unix; nothing on Windows, where
    /// `fsx::sync_rename`'s flush of the renamed file serves).
    pub fn sync(&self) -> io::Result<()> {
        imp::sync(self)
    }

    /// This directory again, as a handle of its own (the descriptor or
    /// handle duplicated).
    pub fn try_clone(&self) -> io::Result<Dir> {
        imp::try_clone(self)
    }

    /// The handle's descriptor (Unix), for confinement's list of those that
    /// cross it; `None` elsewhere.
    pub fn descriptor(&self) -> Option<i32> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            Some(self.fd.as_raw_fd())
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    /// The handle, borrowed (Unix): for a lookup the type has no method for
    /// that must still start from this directory, such as `openat2` with
    /// `RESOLVE_BENEATH` (a profile move's node-lock probe, design 0013).
    #[cfg(unix)]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.fd.as_fd()
    }

    /// The names of the directories in this one, not following a symlink
    /// (one is no directory), read from its handle.
    pub fn subdirs(&self) -> io::Result<Vec<OsString>> {
        imp::subdirs(self)
    }

    /// The names of everything in this one, read from its handle.
    pub fn names(&self) -> io::Result<Vec<OsString>> {
        imp::names(self)
    }

    /// This directory's identity, from its handle: on Unix its device and
    /// inode; on Windows its volume's serial number and file ID.
    pub fn identity(&self) -> io::Result<(u64, u128)> {
        imp::identity_of(self)
    }

    /// Removes the directory `name` in this one if it is empty, following
    /// no symlink. Whether it went: not there, or not empty, is `false`.
    pub fn remove_empty(&self, name: &OsStr) -> io::Result<bool> {
        imp::remove_empty(self, name)
    }
}

#[cfg(unix)]
mod imp {
    use super::{Dir, DirIdentity, Kind, Mount, Resolve};
    use crate::fsx::Regular;
    use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use rustix::io::Errno;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io;
    use std::path::Path;

    pub(super) const DIR_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    /// A directory of a tree being removed: never through a symlink, and
    /// never waiting on whatever else is there.
    pub(super) const TREE_FLAGS: OFlags = DIR_FLAGS.union(OFlags::NONBLOCK);

    pub(super) fn refused(errno: Errno) -> io::Error {
        if errno == Errno::LOOP || errno == Errno::NOTDIR {
            io::Error::other("a symlink or a file where a node directory should be")
        } else {
            io::Error::from(errno)
        }
    }

    pub fn open_root(root: &Path, resolve: Resolve) -> io::Result<Option<Dir>> {
        let mut flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        if let Resolve::Canonical(_) = resolve {
            flags |= OFlags::NOFOLLOW;
        }
        let fd = match rustix::fs::open(root, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(refused(e)),
        };
        if let Resolve::Canonical(gated) = resolve {
            // The directory at the canonical path now, resolved again, must
            // be the one opened: a symlink above it, or a directory swapped
            // in and out, is refused. And it must be the one the gate was
            // taken for: another directory moved into its path is too.
            let held = rustix::fs::fstat(&fd)?;
            let resolved = std::fs::canonicalize(root)?;
            let now = rustix::fs::lstat(root)?;
            if resolved != root || held.st_dev != now.st_dev || held.st_ino != now.st_ino {
                return Err(io::Error::other(
                    "a node's root that isn't the directory at its canonical path",
                ));
            }
            // st_dev and st_ino are u64 on Linux, but not on every Unix.
            #[allow(clippy::unnecessary_cast)]
            let identity = DirIdentity {
                dev: held.st_dev as u64,
                ino: held.st_ino as u64,
            };
            if gated.is_some_and(|gated| gated != identity) {
                return Err(io::Error::other(
                    "a node's root that isn't the directory its gate was taken for",
                ));
            }
        }
        Ok(Some(Dir {
            path: root.to_owned(),
            fd,
        }))
    }

    pub fn try_clone(dir: &Dir) -> io::Result<Dir> {
        Ok(Dir {
            path: dir.path.clone(),
            fd: rustix::io::fcntl_dupfd_cloexec(&dir.fd, 0)?,
        })
    }

    pub fn child(dir: &Dir, name: &OsStr, create: bool) -> io::Result<Option<Dir>> {
        match rustix::fs::openat(&dir.fd, name, DIR_FLAGS, Mode::empty()) {
            Ok(fd) => Ok(Some(Dir {
                path: dir.path.join(name),
                fd,
            })),
            Err(Errno::NOENT) if create => {
                match rustix::fs::mkdirat(&dir.fd, name, Mode::from_bits_truncate(0o700)) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(e) => return Err(e.into()),
                }
                rustix::fs::fsync(&dir.fd)?;
                let fd =
                    rustix::fs::openat(&dir.fd, name, DIR_FLAGS, Mode::empty()).map_err(refused)?;
                Ok(Some(Dir {
                    path: dir.path.join(name),
                    fd,
                }))
            }
            Err(Errno::NOENT) => Ok(None),
            Err(e) => Err(refused(e)),
        }
    }

    pub fn kind(dir: &Dir, name: &OsStr) -> io::Result<Kind> {
        // No automount is triggered at the name, on Linux: what is there is
        // classified, not entered.
        #[cfg(target_os = "linux")]
        let flags = AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT;
        #[cfg(not(target_os = "linux"))]
        let flags = AtFlags::SYMLINK_NOFOLLOW;
        match rustix::fs::statat(&dir.fd, name, flags) {
            Ok(stat) => Ok(match FileType::from_raw_mode(stat.st_mode) {
                FileType::RegularFile => Kind::File,
                FileType::Directory => Kind::Dir,
                _ => Kind::Other,
            }),
            Err(Errno::NOENT) => Ok(Kind::Missing),
            Err(e) => Err(e.into()),
        }
    }

    pub fn open_regular(dir: &Dir, name: &OsStr, write: bool) -> io::Result<Regular> {
        let access = if write { OFlags::RDWR } else { OFlags::RDONLY };
        let flags = access | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        match rustix::fs::openat(&dir.fd, name, flags, Mode::empty()) {
            Ok(fd) => {
                let file = File::from(fd);
                let metadata = file.metadata()?;
                if metadata.is_file() {
                    Ok(Regular::File(file))
                } else {
                    Ok(Regular::Other)
                }
            }
            Err(Errno::NOENT) => Ok(Regular::Missing),
            // A symlink refused by O_NOFOLLOW, or a directory or other file
            // that won't open for writing: something other than a regular
            // file, not read.
            Err(Errno::LOOP | Errno::ISDIR | Errno::NXIO) => Ok(Regular::Other),
            Err(e) => Err(e.into()),
        }
    }

    pub fn open_following(dir: &Dir, name: &OsStr) -> io::Result<Regular> {
        let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC;
        match rustix::fs::openat(&dir.fd, name, flags, Mode::empty()) {
            Ok(fd) => {
                let file = File::from(fd);
                if file.metadata()?.is_file() {
                    Ok(Regular::File(file))
                } else {
                    Ok(Regular::Other)
                }
            }
            Err(Errno::NOENT) => Ok(Regular::Missing),
            Err(Errno::LOOP | Errno::NXIO) => Ok(Regular::Other),
            Err(e) => Err(e.into()),
        }
    }

    pub fn create_new(dir: &Dir, name: &OsStr) -> io::Result<File> {
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = rustix::fs::openat(&dir.fd, name, flags, Mode::from_bits_truncate(0o600))?;
        Ok(File::from(fd))
    }

    pub fn unlink(dir: &Dir, name: &OsStr) -> io::Result<bool> {
        match rustix::fs::unlinkat(&dir.fd, name, AtFlags::empty()) {
            Ok(()) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub fn rename(dir: &Dir, from: &OsStr, to: &OsStr) -> io::Result<()> {
        rustix::fs::renameat(&dir.fd, from, &dir.fd, to)?;
        Ok(())
    }

    pub fn rename_into(dir: &Dir, from: &OsStr, target: &Dir, to: &OsStr) -> io::Result<()> {
        rustix::fs::renameat(&dir.fd, from, &target.fd, to)?;
        Ok(())
    }

    /// A directory of the tree being removed: its name in its parent, its
    /// identity (to know it again when it is reopened), and the entries in
    /// it still to remove. No handle: the walk holds only the deepest one.
    struct Level {
        name: std::ffi::OsString,
        identity: (u64, u64),
        left: Vec<std::ffi::OsString>,
    }

    fn identity(fd: &OwnedFd) -> io::Result<(u64, u64)> {
        let stat = rustix::fs::fstat(fd)?;
        // st_dev and st_ino are u64 on Linux, but not on every Unix.
        #[allow(clippy::unnecessary_cast)]
        Ok((stat.st_dev as u64, stat.st_ino as u64))
    }

    /// The names in the directory `fd`, but `.` and `..`, read whole before
    /// any is removed.
    pub(super) fn entries(fd: &OwnedFd) -> io::Result<Vec<std::ffi::OsString>> {
        use std::os::unix::ffi::OsStrExt;
        let mut names = Vec::new();
        for entry in rustix::fs::Dir::read_from(fd)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(OsStr::from_bytes(name).to_owned());
            }
        }
        Ok(names)
    }

    /// The directory `levels` lead to, reopened from `top` down: each
    /// through its parent's handle without following a symlink, and each
    /// the very directory it was when the walk first opened it. One swapped
    /// since is an error, and the walk stops. Two handles at a time.
    fn reopen(top: &OwnedFd, levels: &[Level]) -> io::Result<OwnedFd> {
        use rustix::fd::AsFd;
        let mut fd: Option<OwnedFd> = None;
        for level in levels {
            let parent = fd.as_ref().map_or(top.as_fd(), |fd| fd.as_fd());
            let next = rustix::fs::openat(parent, &level.name, TREE_FLAGS, Mode::empty())
                .map_err(refused)?;
            if identity(&next)? != level.identity {
                return Err(changed());
            }
            fd = Some(next);
        }
        fd.ok_or_else(|| io::Error::other("no directory to reopen"))
    }

    /// Depth first, holding at most a few handles however deep the tree is
    /// (review of #177, round 3): the directory being emptied, and while one
    /// is reopened, two more. Each directory is opened through its parent's
    /// handle without following a symlink, and each entry is unlinked, or
    /// removed once empty, relative to its directory's handle. Anything
    /// that isn't a directory (a symlink included) is unlinked itself. A
    /// parent is reopened from the held directory, level by level, and must
    /// be the directory it was ([`reopen`]). So nothing outside the tree is
    /// reached, whatever is renamed or swapped above or inside it meanwhile.
    ///
    /// With `bound`, each directory opened (the top's included) must be on
    /// that mount, or the removal stops there with an error ([`within`]).
    /// `each` runs after each entry is removed.
    pub fn remove_tree(
        dir: &Dir,
        name: &OsStr,
        bound: Option<Mount>,
        each: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<bool> {
        let looked = before_open(bound, dir.fd.as_fd(), name)?;
        let first = match rustix::fs::openat(&dir.fd, name, TREE_FLAGS, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(false),
            // Not a directory, or a symlink: removed itself.
            Err(Errno::LOOP | Errno::NOTDIR) => {
                let removed = unlink(dir, name)?;
                if removed {
                    each()?;
                }
                return Ok(removed);
            }
            Err(e) => return Err(e.into()),
        };
        opened_as(&first, looked)?;
        within(bound, first.as_fd())?;
        super::tree::pause::at("opened", name);
        let mut levels = vec![Level {
            name: name.to_owned(),
            identity: identity(&first)?,
            left: entries(&first)?,
        }];
        // The handle of the deepest level, the one being emptied.
        let mut current = first;
        loop {
            let Some(level) = levels.last_mut() else {
                return Ok(true);
            };
            if let Some(entry) = level.left.pop() {
                let looked = before_open(bound, current.as_fd(), &entry)?;
                match rustix::fs::openat(&current, &entry, TREE_FLAGS, Mode::empty()) {
                    Ok(child) => {
                        opened_as(&child, looked)?;
                        within(bound, child.as_fd())?;
                        super::tree::pause::at("opened", &entry);
                        levels.push(Level {
                            name: entry,
                            identity: identity(&child)?,
                            left: entries(&child)?,
                        });
                        // The parent's handle closes; it is reopened once
                        // this child is gone.
                        current = child;
                    }
                    Err(Errno::NOENT) => {}
                    Err(Errno::LOOP | Errno::NOTDIR) => {
                        match rustix::fs::unlinkat(&current, &entry, AtFlags::empty()) {
                            Ok(()) => each()?,
                            Err(Errno::NOENT) => {}
                            Err(e) => return Err(e.into()),
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
                continue;
            }
            // Empty now: removed from its parent, through the parent's handle.
            let Some(done) = levels.pop() else {
                return Ok(true);
            };
            drop(current);
            if levels.is_empty() {
                return match rustix::fs::unlinkat(&dir.fd, &done.name, AtFlags::REMOVEDIR) {
                    Ok(()) => each().map(|()| true),
                    Err(Errno::NOENT) => Ok(true),
                    Err(e) => Err(e.into()),
                };
            }
            current = reopen(&dir.fd, &levels)?;
            match rustix::fs::unlinkat(&current, &done.name, AtFlags::REMOVEDIR) {
                Ok(()) => each()?,
                Err(Errno::NOENT) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// With a bound, the directory `fd` must be on that mount: a mount
    /// point inside a tree stops its removal or its copy.
    pub(super) fn within(bound: Option<Mount>, fd: BorrowedFd<'_>) -> io::Result<()> {
        match bound {
            Some(bound) if !mount_of_fd(fd)?.same(bound) => Err(super::tree::crossing()),
            _ => Ok(()),
        }
    }

    pub fn mount_of(dir: &Dir) -> io::Result<Mount> {
        mount_of_fd(dir.fd.as_fd())
    }

    /// The mount `fd` is on: its device, and on Linux its mount's ID where
    /// the kernel gives one (`STATX_MNT_ID`, Linux 5.8).
    pub(super) fn mount_of_fd(fd: BorrowedFd<'_>) -> io::Result<Mount> {
        let stat = rustix::fs::fstat(fd)?;
        // st_dev is u64 on Linux, but not on every Unix.
        #[allow(clippy::unnecessary_cast)]
        let device = stat.st_dev as u64;
        #[cfg(target_os = "linux")]
        let id = mount_id(fd, c"", AtFlags::EMPTY_PATH);
        #[cfg(not(target_os = "linux"))]
        let id = None;
        Ok(Mount { device, id })
    }

    /// The mount `name` in `parent` is on, not following a symlink at it,
    /// from its `lstat` (`stat`, read by the caller).
    pub(super) fn mount_at(parent: BorrowedFd<'_>, name: &OsStr, stat: &rustix::fs::Stat) -> Mount {
        // st_dev is u64 on Linux, but not on every Unix.
        #[allow(clippy::unnecessary_cast)]
        let device = stat.st_dev as u64;
        #[cfg(target_os = "linux")]
        let id = mount_id(parent, name, LOOK);
        #[cfg(not(target_os = "linux"))]
        let id = {
            let _ = (parent, name);
            None
        };
        Mount { device, id }
    }

    /// How a name is looked at before it is opened: never following a
    /// symlink, and on Linux never triggering an automount at it.
    #[cfg(target_os = "linux")]
    const LOOK: AtFlags = AtFlags::SYMLINK_NOFOLLOW.union(AtFlags::NO_AUTOMOUNT);
    #[cfg(not(target_os = "linux"))]
    const LOOK: AtFlags = AtFlags::SYMLINK_NOFOLLOW;

    /// `name` in `parent`, looked at as [`LOOK`] says (`fstatat`).
    pub(super) fn stat_at(parent: BorrowedFd<'_>, name: &OsStr) -> Result<rustix::fs::Stat, Errno> {
        rustix::fs::statat(parent, name, LOOK)
    }

    /// A stat's device and inode, as [`identity`] reads them from a handle.
    pub(super) fn stat_identity(stat: &rustix::fs::Stat) -> (u64, u64) {
        // st_dev and st_ino are u64 on Linux, but not on every Unix.
        #[allow(clippy::unnecessary_cast)]
        (stat.st_dev as u64, stat.st_ino as u64)
    }

    /// With a bound, `name` in `parent` looked at before it is opened: a
    /// directory there must be on the bound's mount, or the removal stops
    /// before the open (which could trigger an automount, or wait on a
    /// mounted volume). Its identity, which the open must then find.
    fn before_open(
        bound: Option<Mount>,
        parent: BorrowedFd<'_>,
        name: &OsStr,
    ) -> io::Result<Option<(u64, u64)>> {
        let Some(bound) = bound else {
            return Ok(None);
        };
        let stat = match stat_at(parent, name) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Ok(None);
        }
        if !mount_at(parent, name, &stat).same(bound) {
            return Err(super::tree::crossing());
        }
        super::tree::pause::at("classified", name);
        Ok(Some(stat_identity(&stat)))
    }

    /// The directory opened must be the one looked at before.
    fn opened_as(fd: &OwnedFd, looked: Option<(u64, u64)>) -> io::Result<()> {
        match looked {
            Some(looked) if identity(fd)? != looked => Err(changed()),
            _ => Ok(()),
        }
    }

    fn changed() -> io::Error {
        io::Error::other("a directory of a tree changed during its removal")
    }

    pub fn may_change(dir: &Dir) -> bool {
        use rustix::fs::Access;
        rustix::fs::accessat(
            &dir.fd,
            c".",
            Access::WRITE_OK | Access::EXEC_OK,
            AtFlags::empty(),
        )
        .is_ok()
    }

    /// `STATX_MNT_ID`, or `None` where the kernel doesn't give it.
    #[cfg(target_os = "linux")]
    fn mount_id<P: rustix::path::Arg>(fd: BorrowedFd<'_>, path: P, flags: AtFlags) -> Option<u64> {
        use rustix::fs::StatxFlags;
        let stat = rustix::fs::statx(fd, path, flags, StatxFlags::MNT_ID).ok()?;
        StatxFlags::from_bits_retain(stat.stx_mask)
            .contains(StatxFlags::MNT_ID)
            .then_some(stat.stx_mnt_id)
    }

    pub fn same_file(dir: &Dir, handle: &File, name: &OsStr) -> io::Result<bool> {
        use std::os::unix::fs::MetadataExt;
        let held = handle.metadata()?;
        match rustix::fs::statat(&dir.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            // st_dev and st_ino are u64 on Linux, but not on every Unix.
            #[allow(clippy::unnecessary_cast)]
            Ok(stat) => Ok(held.dev() == stat.st_dev as u64 && held.ino() == stat.st_ino as u64),
            Err(Errno::NOENT) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub fn sync(dir: &Dir) -> io::Result<()> {
        rustix::fs::fsync(&dir.fd)?;
        Ok(())
    }

    pub fn subdirs(dir: &Dir) -> io::Result<Vec<std::ffi::OsString>> {
        let mut names = Vec::new();
        for name in entries(&dir.fd)? {
            if kind(dir, &name)? == Kind::Dir {
                names.push(name);
            }
        }
        Ok(names)
    }

    pub fn names(dir: &Dir) -> io::Result<Vec<std::ffi::OsString>> {
        entries(&dir.fd)
    }

    pub fn identity_of(dir: &Dir) -> io::Result<(u64, u128)> {
        let (dev, ino) = identity(&dir.fd)?;
        Ok((dev, u128::from(ino)))
    }

    pub fn remove_empty(dir: &Dir, name: &OsStr) -> io::Result<bool> {
        match rustix::fs::unlinkat(&dir.fd, name, AtFlags::REMOVEDIR) {
            Ok(()) => Ok(true),
            Err(Errno::NOENT | Errno::NOTEMPTY | Errno::EXIST) => Ok(false),
            Err(e) => Err(refused(e)),
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::{Dir, Kind, Mount, Resolve};
    use crate::fsx::{Regular, file_identity};
    use fc_sys::windows::{self as win, Create, Expect, OpenAt, access};
    use std::ffi::{OsStr, OsString};
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::io::{AsHandle as _, BorrowedHandle, OwnedHandle};
    use std::path::Path;

    fn refused() -> io::Error {
        io::Error::other("a symlink or a file where a node directory should be")
    }

    /// `name` in `dir`, opened relative to its handle as `how` says, a
    /// reparse point never followed unless `how` says so: `None` if nothing
    /// is there.
    fn open(dir: &Dir, name: &OsStr, how: OpenAt) -> io::Result<Option<OwnedHandle>> {
        match win::open_at(dir.handle.as_handle(), name, how) {
            Ok(handle) => Ok(Some(handle)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(super) fn how(access: u32, create: Create, expect: Expect) -> OpenAt {
        OpenAt {
            access,
            create,
            expect,
            follow: false,
        }
    }

    /// A directory, and not a reparse point: a junction or a directory
    /// symlink opened itself is neither followed nor taken for one.
    pub(super) fn plain_dir(handle: &OwnedHandle) -> io::Result<bool> {
        let attributes = win::attribute_tag(handle.as_handle())?;
        Ok(attributes.directory() && !attributes.reparse_point())
    }

    /// The directory at `path`, by path: a reparse point there followed
    /// or opened itself. `None` if nothing is there.
    fn open_path(path: &Path, follow: bool) -> io::Result<Option<OwnedHandle>> {
        use std::os::windows::fs::OpenOptionsExt as _;
        let mut custom = win::flags::BACKUP_SEMANTICS;
        if !follow {
            custom |= win::flags::OPEN_REPARSE_POINT;
        }
        match OpenOptions::new()
            .access_mode(access::LIST | access::ATTRIBUTES)
            .custom_flags(custom)
            .open(path)
        {
            Ok(file) => Ok(Some(file.into())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The root is opened by its path, once; everything below it is
    /// reached from that handle. Canonical: not a reparse point, still its
    /// own canonical path, and the directory at that path now has the
    /// handle's file ID. The gate's identity is a Unix device and inode, so
    /// it isn't compared here.
    pub fn open_root(root: &Path, resolve: Resolve) -> io::Result<Option<Dir>> {
        let follow = resolve == Resolve::Follow;
        let Some(handle) = open_path(root, follow)? else {
            return Ok(None);
        };
        let attributes = win::attribute_tag(handle.as_handle())?;
        if !attributes.directory() || (!follow && attributes.reparse_point()) {
            return Err(refused());
        }
        if let Resolve::Canonical(_) = resolve {
            let resolved = std::fs::canonicalize(root)?;
            let now =
                open_path(root, false)?.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            if resolved != root
                || file_identity(handle.as_handle())? != file_identity(now.as_handle())?
            {
                return Err(io::Error::other(
                    "a node's root that isn't the directory at its canonical path",
                ));
            }
        }
        Ok(Some(Dir {
            path: root.to_owned(),
            handle,
        }))
    }

    pub fn try_clone(dir: &Dir) -> io::Result<Dir> {
        Ok(Dir {
            path: dir.path.clone(),
            handle: dir.handle.try_clone()?,
        })
    }

    /// Opened, or made (inheriting its parent's ACL), relative to `dir`'s
    /// handle; a reparse point there is opened itself and refused, and
    /// nothing is made through it.
    pub fn child(dir: &Dir, name: &OsStr, create: bool) -> io::Result<Option<Dir>> {
        let create = if create {
            Create::IfMissing
        } else {
            Create::No
        };
        let opened = match open(dir, name, how(access::LIST, create, Expect::Directory)) {
            Ok(opened) => opened,
            Err(e) if e.kind() == io::ErrorKind::NotADirectory => return Err(refused()),
            Err(e) => return Err(e),
        };
        let Some(handle) = opened else {
            return Ok(None);
        };
        if !plain_dir(&handle)? {
            return Err(refused());
        }
        Ok(Some(Dir {
            path: dir.path.join(name),
            handle,
        }))
    }

    pub fn kind(dir: &Dir, name: &OsStr) -> io::Result<Kind> {
        let Some(handle) = open(dir, name, how(access::ATTRIBUTES, Create::No, Expect::Any))?
        else {
            return Ok(Kind::Missing);
        };
        let attributes = win::attribute_tag(handle.as_handle())?;
        Ok(if attributes.reparse_point() {
            Kind::Other
        } else if attributes.directory() {
            Kind::Dir
        } else {
            Kind::File
        })
    }

    /// Opened as a file relative to `dir`'s handle and judged on the
    /// handle: a directory (a junction included) or a reparse point is
    /// something other than a regular file, not read.
    fn open_file(dir: &Dir, name: &OsStr, how: OpenAt) -> io::Result<Regular> {
        match open(dir, name, how) {
            Ok(Some(handle)) => {
                let attributes = win::attribute_tag(handle.as_handle())?;
                if attributes.directory() || attributes.reparse_point() {
                    Ok(Regular::Other)
                } else {
                    Ok(Regular::File(File::from(handle)))
                }
            }
            Ok(None) => Ok(Regular::Missing),
            Err(e) if e.kind() == io::ErrorKind::IsADirectory => Ok(Regular::Other),
            Err(e) => Err(e),
        }
    }

    pub fn open_regular(dir: &Dir, name: &OsStr, write: bool) -> io::Result<Regular> {
        let access = if write {
            access::READ | access::WRITE
        } else {
            access::READ
        };
        open_file(dir, name, how(access, Create::No, Expect::File))
    }

    pub fn open_following(dir: &Dir, name: &OsStr) -> io::Result<Regular> {
        let how = OpenAt {
            follow: true,
            ..how(access::READ, Create::No, Expect::File)
        };
        open_file(dir, name, how)
    }

    pub fn create_new(dir: &Dir, name: &OsStr) -> io::Result<File> {
        let handle = win::open_at(
            dir.handle.as_handle(),
            name,
            how(access::WRITE, Create::New, Expect::File),
        )?;
        Ok(File::from(handle))
    }

    /// By handle: the entry opened itself (a reparse point included), then
    /// deleted through that handle. A directory there now is refused.
    pub fn unlink(dir: &Dir, name: &OsStr) -> io::Result<bool> {
        let Some(handle) = open(dir, name, how(access::DELETE, Create::No, Expect::Any))? else {
            return Ok(false);
        };
        if plain_dir(&handle)? {
            return Err(io::Error::other(
                "a directory where a node identity file was to be removed",
            ));
        }
        win::delete(handle.as_handle())?;
        Ok(true)
    }

    pub fn rename(dir: &Dir, from: &OsStr, to: &OsStr) -> io::Result<()> {
        rename_into(dir, from, dir, to)
    }

    /// By handle: `from` opened itself relative to `dir`'s handle (a
    /// reparse point is moved itself), then renamed relative to `target`'s.
    pub fn rename_into(dir: &Dir, from: &OsStr, target: &Dir, to: &OsStr) -> io::Result<()> {
        let handle = win::open_at(
            dir.handle.as_handle(),
            from,
            how(access::DELETE, Create::No, Expect::Any),
        )?;
        win::rename_at(handle.as_handle(), target.handle.as_handle(), to)
    }

    /// `name` in the directory `parent` is open on, opened itself for its
    /// removal: `None` if nothing is there.
    fn open_entry(parent: &OwnedHandle, name: &OsStr) -> io::Result<Option<OwnedHandle>> {
        match win::open_at(
            parent.as_handle(),
            name,
            how(access::DELETE, Create::No, Expect::Any),
        ) {
            Ok(handle) => Ok(Some(handle)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn names_in(handle: &OwnedHandle) -> io::Result<Vec<OsString>> {
        Ok(win::list_dir(handle.as_handle())?
            .into_iter()
            .map(|(name, _)| name)
            .collect())
    }

    /// Depth first, from handle to handle: each entry is opened relative to
    /// its directory's handle without following a reparse point, and
    /// deleted through its own handle once empty. A reparse point (a
    /// symlink or a junction) is deleted itself, never walked into. Each
    /// level's handle is held until it is deleted, so nothing outside the
    /// tree is reached, whatever is renamed or swapped above or inside it
    /// meanwhile. Windows bounds a process's handles in the millions, not
    /// the thousands: a handle per level is held, where Unix reopens them.
    ///
    /// With `bound`, each directory opened (the top's included) must be on
    /// that volume, or the removal stops there with an error. A volume
    /// mounted in a folder is a reparse point, deleted itself and never
    /// walked, so a removal never reaches into one. `each` runs after each
    /// entry is deleted (its handle closed).
    pub fn remove_tree(
        dir: &Dir,
        name: &OsStr,
        bound: Option<Mount>,
        each: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<bool> {
        let Some(top) = open_entry(&dir.handle, name)? else {
            return Ok(false);
        };
        if !plain_dir(&top)? {
            win::delete(top.as_handle())?;
            drop(top);
            each()?;
            return Ok(true);
        }
        within(bound, top.as_handle())?;
        super::tree::pause::at("opened", name);
        let left = names_in(&top)?;
        let mut levels = vec![(top, left)];
        loop {
            let Some((handle, left)) = levels.last_mut() else {
                return Ok(true);
            };
            if let Some(entry) = left.pop() {
                match open_entry(handle, &entry)? {
                    None => {}
                    Some(child) if plain_dir(&child)? => {
                        within(bound, child.as_handle())?;
                        super::tree::pause::at("opened", &entry);
                        let left = names_in(&child)?;
                        levels.push((child, left));
                    }
                    Some(child) => {
                        win::delete(child.as_handle())?;
                        drop(child);
                        each()?;
                    }
                }
                continue;
            }
            if let Some((done, _)) = levels.pop() {
                win::delete(done.as_handle())?;
                drop(done);
                each()?;
            }
        }
    }

    /// With a bound, the directory `handle` is open on must be on that
    /// volume.
    pub(super) fn within(bound: Option<Mount>, handle: BorrowedHandle<'_>) -> io::Result<()> {
        match bound {
            Some(bound) if !mount_of_handle(handle)?.same(bound) => Err(super::tree::crossing()),
            _ => Ok(()),
        }
    }

    pub fn mount_of(dir: &Dir) -> io::Result<Mount> {
        mount_of_handle(dir.handle.as_handle())
    }

    pub fn may_change(_dir: &Dir) -> bool {
        true
    }

    /// The volume `handle` is open on, by its serial number.
    pub(super) fn mount_of_handle(handle: BorrowedHandle<'_>) -> io::Result<Mount> {
        Ok(Mount {
            device: file_identity(handle)?.0,
            id: None,
        })
    }

    /// The file IDs of `handle` and of `name`, opened itself relative to
    /// `dir`'s handle.
    pub fn same_file(dir: &Dir, handle: &File, name: &OsStr) -> io::Result<bool> {
        let Some(named) = open(dir, name, how(access::ATTRIBUTES, Create::No, Expect::Any))? else {
            return Ok(false);
        };
        Ok(file_identity(handle.as_handle())? == file_identity(named.as_handle())?)
    }

    /// Nothing: a directory handle can't be flushed without write access
    /// to the directory, and Windows documents no durability for it. The
    /// renamed file's flush commits NTFS's log through the rename
    /// (`fsx::sync_rename`); power loss is best effort here (design 0001).
    pub fn sync(_dir: &Dir) -> io::Result<()> {
        Ok(())
    }

    /// From the handle's listing: a junction or a directory symlink is no
    /// directory here, as `kind` says.
    pub fn subdirs(dir: &Dir) -> io::Result<Vec<OsString>> {
        Ok(win::list_dir(dir.handle.as_handle())?
            .into_iter()
            .filter(|(_, attributes)| attributes.directory() && !attributes.reparse_point())
            .map(|(name, _)| name)
            .collect())
    }

    pub fn names(dir: &Dir) -> io::Result<Vec<OsString>> {
        names_in(&dir.handle)
    }

    pub fn identity_of(dir: &Dir) -> io::Result<(u64, u128)> {
        file_identity(dir.handle.as_handle())
    }

    /// By handle, as a directory and not a reparse point: anything else at
    /// `name`, or a directory that isn't empty, is `false`.
    pub fn remove_empty(dir: &Dir, name: &OsStr) -> io::Result<bool> {
        let handle = match open(
            dir,
            name,
            how(access::DELETE, Create::No, Expect::Directory),
        ) {
            Ok(Some(handle)) => handle,
            Ok(None) => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::NotADirectory => return Ok(false),
            Err(e) => return Err(e),
        };
        if !plain_dir(&handle)? {
            return Ok(false);
        }
        match win::delete(handle.as_handle()) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests;
