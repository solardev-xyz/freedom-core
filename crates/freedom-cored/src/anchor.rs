//! Files under a node's root, reached through no symlink below it (review
//! of #177; design 0008, "Spawn and lock": every operation under a Radicle
//! home uses the gate's canonical path).
//!
//! A journal names its targets under its root. A symlinked directory below
//! the root (`keys`, `node`) would otherwise take a removal, a rename or a
//! read out of the home: into another home's `keys`, or anywhere. So every
//! operation on a node identity file goes through [`Dir`]:
//!
//! - **The root** is the caller's: a Radicle home's is the gate's canonical
//!   path, which recovery checks is exactly the journal's root (a root
//!   retargeted since is refused there); Bee's is the data directory main
//!   names, which may itself be a symlink. It is opened as a directory.
//! - **Each directory below it** is opened through its parent, refusing a
//!   symlink (`O_NOFOLLOW`, `O_DIRECTORY`), and created (`0700`) when a
//!   write needs it.
//! - **On Unix** the final operation is relative to that directory's handle
//!   (`openat`, `unlinkat`, `renameat`, `fstatat` without following), so a
//!   directory swapped for a symlink after it was opened can't redirect it.
//! - **On Windows** each directory below the root is checked to be one, not
//!   a reparse point (a symlink or a junction), then used by path: std
//!   exposes no handle-relative calls, so a same-user process swapping a
//!   directory between that check and the operation is outside what the
//!   core guarantees there, as design 0001 says of its other identity checks.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::fsx::Regular;

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

/// A directory under a node's root, opened through no symlink.
pub struct Dir {
    path: PathBuf,
    #[cfg(unix)]
    fd: rustix::fd::OwnedFd,
}

impl Dir {
    /// The root itself: a directory.
    pub fn root(root: &Path) -> io::Result<Dir> {
        imp::root(root)
    }

    /// The directory holding `target` under `root`, and `target`'s name.
    /// Every directory below the root is opened without following a
    /// symlink; with `create`, missing ones are made (`0700`, their parents
    /// flushed). `None` when one is missing and `create` is off: nothing
    /// under it exists. A target that isn't under `root` in plain
    /// components is an error.
    pub fn under(root: &Path, target: &Path, create: bool) -> io::Result<Option<(Dir, OsString)>> {
        let relative = target
            .strip_prefix(root)
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
        let mut dir = Dir::root(root)?;
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
    pub fn remove_tree(&self, name: &OsStr) -> io::Result<bool> {
        match self.kind(name)? {
            Kind::Missing => Ok(false),
            Kind::Dir => {
                // std's remove_dir_all doesn't follow symlinks inside the
                // tree, and this directory was reached through none.
                match std::fs::remove_dir_all(self.path(name)) {
                    Ok(()) => Ok(true),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
                    Err(e) => Err(e),
                }
            }
            Kind::File | Kind::Other => imp::unlink(self, name),
        }
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
    use super::{Dir, Kind};
    use crate::fsx::Regular;
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

    fn refused(errno: Errno) -> io::Error {
        if errno == Errno::LOOP || errno == Errno::NOTDIR {
            io::Error::other("a symlink or a file where a node directory should be")
        } else {
            io::Error::from(errno)
        }
    }

    pub fn root(root: &Path) -> io::Result<Dir> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let fd = rustix::fs::open(root, flags, Mode::empty())?;
        Ok(Dir {
            path: root.to_owned(),
            fd,
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
    use super::{Dir, Kind};
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

    pub fn root(root: &Path) -> io::Result<Dir> {
        if std::fs::metadata(root)?.is_dir() {
            Ok(Dir {
                path: root.to_owned(),
            })
        } else {
            Err(refused())
        }
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

    pub fn same_file(dir: &Dir, handle: &File, name: &OsStr) -> io::Result<bool> {
        crate::fsx::same_file(handle, &dir.path.join(name))
    }

    pub fn sync(_dir: &Dir) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
