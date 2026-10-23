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
//!   and one moved after the open keeps receiving its operation. Windows
//!   exposes no file identity: there the check is the path's alone. Bee's
//!   root is the data directory main names, which may itself be a symlink
//!   ([`Resolve::Follow`]). A root that doesn't exist is no target
//!   (`None`): nothing under it exists.
//! - **Each directory below it** is opened through its parent, refusing a
//!   symlink (`O_NOFOLLOW`, `O_DIRECTORY`), and created (`0700`) when a
//!   write needs it.
//! - **On Unix** the final operation is relative to that directory's handle
//!   (`openat`, `unlinkat`, `renameat`, `fstatat` without following), so a
//!   directory swapped for a symlink after it was opened can't redirect it.
//!   A tree's removal ([`Dir::remove_tree`]) walks it the same way, from
//!   handle to handle, and unlinks each entry relative to its directory's,
//!   holding a bounded number of handles however deep the tree is.
//! - **On Windows** the root and each directory below it are checked to be
//!   directories, not reparse points (a symlink or a junction), then used by
//!   path: std exposes no handle-relative calls, so a same-user process
//!   swapping a directory between that check and the operation is outside
//!   what the core guarantees there, as design 0001 says of its other
//!   identity checks. A tree is removed by std's `remove_dir_all`, which
//!   removes a reparse point itself and walks the tree by handle, but
//!   reaches its top by path, under the same limit.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::fsx::Regular;
pub use fc_service::gate::DirIdentity;

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

    /// What is at `name`, not following a symlink.
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
    /// On Unix the tree is walked from this directory's handle, each entry
    /// removed relative to its own directory's (review of #177, round 2).
    pub fn remove_tree(&self, name: &OsStr) -> io::Result<bool> {
        imp::remove_tree(self, name)
    }

    /// Renames `from` over `to`, both in this directory, replacing whatever
    /// `to` is without following it.
    pub fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        imp::rename(self, from, to)
    }

    /// Whether `name` is the file `handle` holds (Unix: the same device and
    /// inode); `false` if nothing is there. Elsewhere, `true`: no file
    /// identity is exposed (design 0001).
    pub fn same_file(&self, handle: &File, name: &OsStr) -> io::Result<bool> {
        imp::same_file(self, handle, name)
    }

    /// Flushes this directory's entries (Unix).
    pub fn sync(&self) -> io::Result<()> {
        imp::sync(self)
    }
}

#[cfg(unix)]
mod imp {
    use super::{Dir, DirIdentity, Kind, Resolve};
    use crate::fsx::Regular;
    use rustix::fd::OwnedFd;
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use rustix::io::Errno;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io;
    use std::path::Path;

    const DIR_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    /// A directory of a tree being removed: never through a symlink, and
    /// never waiting on whatever else is there.
    const TREE_FLAGS: OFlags = DIR_FLAGS.union(OFlags::NONBLOCK);

    fn refused(errno: Errno) -> io::Error {
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
        match rustix::fs::statat(&dir.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
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
    fn entries(fd: &OwnedFd) -> io::Result<Vec<std::ffi::OsString>> {
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
                return Err(io::Error::other(
                    "a directory of a tree changed during its removal",
                ));
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
    pub fn remove_tree(dir: &Dir, name: &OsStr) -> io::Result<bool> {
        let first = match rustix::fs::openat(&dir.fd, name, TREE_FLAGS, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(false),
            // Not a directory, or a symlink: removed itself.
            Err(Errno::LOOP | Errno::NOTDIR) => return unlink(dir, name),
            Err(e) => return Err(e.into()),
        };
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
                match rustix::fs::openat(&current, &entry, TREE_FLAGS, Mode::empty()) {
                    Ok(child) => {
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
                            Ok(()) | Err(Errno::NOENT) => {}
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
                    Ok(()) | Err(Errno::NOENT) => Ok(true),
                    Err(e) => Err(e.into()),
                };
            }
            current = reopen(&dir.fd, &levels)?;
            match rustix::fs::unlinkat(&current, &done.name, AtFlags::REMOVEDIR) {
                Ok(()) | Err(Errno::NOENT) => {}
                Err(e) => return Err(e.into()),
            }
        }
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
}

#[cfg(not(unix))]
mod imp {
    use super::{Dir, Kind, Resolve};
    use crate::fsx::Regular;
    use std::ffi::OsStr;
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::path::Path;

    /// `FILE_ATTRIBUTE_REPARSE_POINT`: a symlink, a junction or another
    /// reparse point.
    #[cfg(windows)]
    const REPARSE_POINT: u32 = 0x0400;

    fn plain_dir(path: &Path) -> io::Result<Option<bool>> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                #[cfg(windows)]
                let reparse = {
                    use std::os::windows::fs::MetadataExt;
                    metadata.file_attributes() & REPARSE_POINT != 0
                };
                #[cfg(not(windows))]
                let reparse = metadata.file_type().is_symlink();
                Ok(Some(metadata.is_dir() && !reparse))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn refused() -> io::Error {
        io::Error::other("a symlink or a file where a node directory should be")
    }

    pub fn open_root(root: &Path, resolve: Resolve) -> io::Result<Option<Dir>> {
        let plain = match resolve {
            Resolve::Follow => match std::fs::metadata(root) {
                Ok(metadata) => Some(metadata.is_dir()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                Err(e) => return Err(e),
            },
            // Not a reparse point, and still its own canonical path. No file
            // identity is exposed here, so the gate's isn't compared.
            Resolve::Canonical(_) => match plain_dir(root)? {
                Some(true) => Some(std::fs::canonicalize(root)? == root),
                other => other,
            },
        };
        match plain {
            Some(true) => Ok(Some(Dir {
                path: root.to_owned(),
            })),
            Some(false) => Err(refused()),
            None => Ok(None),
        }
    }

    pub fn try_clone(dir: &Dir) -> io::Result<Dir> {
        Ok(Dir {
            path: dir.path.clone(),
        })
    }

    pub fn child(dir: &Dir, name: &OsStr, create: bool) -> io::Result<Option<Dir>> {
        let path = dir.path.join(name);
        match plain_dir(&path)? {
            Some(true) => Ok(Some(Dir { path })),
            Some(false) => Err(refused()),
            None if create => {
                match std::fs::create_dir(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
                match plain_dir(&path)? {
                    Some(true) => Ok(Some(Dir { path })),
                    _ => Err(refused()),
                }
            }
            None => Ok(None),
        }
    }

    pub fn kind(dir: &Dir, name: &OsStr) -> io::Result<Kind> {
        let path = dir.path.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                #[cfg(windows)]
                let reparse = {
                    use std::os::windows::fs::MetadataExt;
                    metadata.file_attributes() & REPARSE_POINT != 0
                };
                #[cfg(not(windows))]
                let reparse = metadata.file_type().is_symlink();
                Ok(if reparse {
                    Kind::Other
                } else if metadata.is_dir() {
                    Kind::Dir
                } else if metadata.is_file() {
                    Kind::File
                } else {
                    Kind::Other
                })
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Kind::Missing),
            Err(e) => Err(e),
        }
    }

    pub fn open_regular(dir: &Dir, name: &OsStr, write: bool) -> io::Result<Regular> {
        let path = dir.path.join(name);
        if write {
            crate::fsx::open_regular_rw(&path)
        } else {
            crate::fsx::open_regular(&path, false)
        }
    }

    pub fn open_following(dir: &Dir, name: &OsStr) -> io::Result<Regular> {
        crate::fsx::open_regular(&dir.path.join(name), true)
    }

    pub fn create_new(dir: &Dir, name: &OsStr) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.path.join(name))
    }

    pub fn unlink(dir: &Dir, name: &OsStr) -> io::Result<bool> {
        match std::fs::remove_file(dir.path.join(name)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn rename(dir: &Dir, from: &OsStr, to: &OsStr) -> io::Result<()> {
        std::fs::rename(dir.path.join(from), dir.path.join(to))
    }

    /// std's `remove_dir_all`: a reparse point in the tree's place, or in
    /// it, is removed itself, and the tree is walked by handle; its top is
    /// reached by path (the module's Windows limit).
    pub fn remove_tree(dir: &Dir, name: &OsStr) -> io::Result<bool> {
        match kind(dir, name)? {
            Kind::Missing => Ok(false),
            Kind::Dir => match std::fs::remove_dir_all(dir.path.join(name)) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(e),
            },
            Kind::File | Kind::Other => unlink(dir, name),
        }
    }

    pub fn same_file(dir: &Dir, handle: &File, name: &OsStr) -> io::Result<bool> {
        crate::fsx::same_file(handle, &dir.path.join(name))
    }

    pub fn sync(_dir: &Dir) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
