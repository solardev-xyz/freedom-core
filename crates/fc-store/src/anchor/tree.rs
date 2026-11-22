//! A tree walked and copied within one mount, and a volume's free space
//! (design 0013, "The move": PRF-9c's cross-device copy of an entry into a
//! `freedom/` on another volume).
//!
//! - **[`Dir::walk`]** visits `name` and everything under it, never
//!   following a symlink, never opening anything but a directory, and never
//!   entering a directory on another mount than the directory it starts
//!   from ([`Node::Mount`]), one this process may not use, or one
//!   [`MAX_DEPTH`] levels down. So the caller can size a copy and find what
//!   it couldn't copy before anything changes.
//! - **[`Dir::copy_tree`]** copies `name` to a new name in another
//!   directory: a regular file's bytes, synced, made with its permission
//!   bits (the umask applied; a directory keeps its owner's too, so its
//!   copy can be filled); a directory's entries, the copy flushed once they
//!   are made; a symlink as the link. A directory on another mount, a FIFO,
//!   a socket or a device (on Windows any reparse point) stops it with an
//!   error before anything is opened at that name. Timestamps, owners and
//!   extended attributes aren't copied: confinement forbids changing them
//!   (design 0010), and nothing a profile's nodes keep reads them.
//! - **[`Dir::space`]**: the bytes free to this process's user on a
//!   directory's volume, and its allocation unit.
//!
//! Both hold a handle per level they are in (a copy, two), so neither goes
//! deeper than [`MAX_DEPTH`]: the nodes' data is a few levels deep.

use std::ffi::OsStr;
use std::io;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use super::{Dir, Node, Space};

/// How many levels below its top a walk or a copy enters: a directory this
/// deep is [`Node::Deep`] to a walk, and an error to a copy.
pub const MAX_DEPTH: usize = 64;

/// A visitor's call for each node, with its path from the walk's directory
/// (the top's name first).
type Visit<'a> = dyn FnMut(&Path, Node) -> ControlFlow<()> + 'a;
/// What a copy calls after each entry it makes.
type Each<'a> = dyn FnMut() -> io::Result<()> + 'a;

/// A mount point met inside a tree being copied or removed.
pub(super) fn crossing() -> io::Error {
    io::Error::other("a mount point inside the tree: it isn't crossed")
}

fn too_deep() -> io::Error {
    io::Error::other("a tree deeper than a copy goes")
}

fn special() -> io::Error {
    io::Error::other("a FIFO, a socket, a device or a link a copy doesn't make")
}

fn changed() -> io::Error {
    io::Error::other("a file changed during its copy")
}

impl Dir {
    /// The bytes free to this process's user on this directory's volume,
    /// and its allocation unit (`fstatvfs`; on Windows
    /// `NtQueryVolumeInformationFile`), from its handle.
    pub fn space(&self) -> io::Result<Space> {
        imp::space(self)
    }

    /// Visits `name` and, if it is a directory this process may use on this
    /// directory's mount, everything under it, depth first ([`Node`]). The
    /// visitor gets each node's path from this directory, `name` first, and
    /// stops the walk with `Break`. Nothing is opened but directories, and
    /// a symlink is never followed. A name missing (the top, or one removed
    /// meanwhile) is skipped.
    pub fn walk(&self, name: &OsStr, visit: &mut Visit<'_>) -> io::Result<()> {
        let mut path = PathBuf::from(name);
        imp::walk(self, name, &mut path, visit).map(|_| ())
    }

    /// Copies `name` in this directory to `to` in `target`, which must not
    /// exist, never past this directory's mount (the module's comment).
    /// `each` runs after each entry is made (a directory once it is, a file
    /// once it is synced), and an error from it stops the copy. A copy
    /// stopped leaves what it made for the caller to remove.
    pub fn copy_tree(
        &self,
        name: &OsStr,
        target: &Dir,
        to: &OsStr,
        each: &mut Each<'_>,
    ) -> io::Result<()> {
        imp::copy_tree(self, name, target, to, each)
    }
}

#[cfg(unix)]
mod imp {
    use super::{Each, MAX_DEPTH, Visit, changed, special, too_deep};
    use crate::anchor::imp::{
        DIR_FLAGS, TREE_FLAGS, entries, mount_at, mount_of_fd, refused, within,
    };
    use crate::anchor::{Dir, Mount, Node, Space};
    use rustix::fd::{AsFd, BorrowedFd};
    use rustix::fs::{Access, AtFlags, FileType, Mode, OFlags};
    use rustix::io::Errno;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io;
    use std::ops::ControlFlow;
    use std::path::PathBuf;

    pub fn space(dir: &Dir) -> io::Result<Space> {
        let stat = rustix::fs::fstatvfs(&dir.fd)?;
        let block = if stat.f_frsize > 0 {
            stat.f_frsize
        } else {
            stat.f_bsize
        };
        Ok(Space {
            available: stat.f_bavail.saturating_mul(block),
            block: block.max(1),
        })
    }

    pub fn walk(
        dir: &Dir,
        name: &OsStr,
        path: &mut PathBuf,
        visit: &mut Visit<'_>,
    ) -> io::Result<ControlFlow<()>> {
        let bound = mount_of_fd(dir.fd.as_fd())?;
        walk_at(dir.fd.as_fd(), name, path, bound, 0, visit)
    }

    /// Whether this process may use `name` in `parent` as `access` says
    /// (`faccessat`, its real IDs, which are its effective ones).
    fn may(parent: BorrowedFd<'_>, name: &OsStr, access: Access) -> bool {
        rustix::fs::accessat(parent, name, access, AtFlags::empty()).is_ok()
    }

    fn walk_at(
        parent: BorrowedFd<'_>,
        name: &OsStr,
        path: &mut PathBuf,
        bound: Mount,
        depth: usize,
        visit: &mut Visit<'_>,
    ) -> io::Result<ControlFlow<()>> {
        let stat = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(ControlFlow::Continue(())),
            Err(e) => return Err(e.into()),
        };
        let node = match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => Node::File {
                len: u64::try_from(stat.st_size).unwrap_or(0),
                readable: may(parent, name, Access::READ_OK),
            },
            FileType::Symlink => Node::Link,
            FileType::Directory if !mount_at(parent, name, &stat).same(bound) => Node::Mount,
            FileType::Directory if depth >= MAX_DEPTH => Node::Deep,
            FileType::Directory => {
                let usable = may(
                    parent,
                    name,
                    Access::READ_OK | Access::WRITE_OK | Access::EXEC_OK,
                );
                if visit(path, Node::Dir { usable }).is_break() {
                    return Ok(ControlFlow::Break(()));
                }
                if !usable {
                    return Ok(ControlFlow::Continue(()));
                }
                let fd = match rustix::fs::openat(parent, name, TREE_FLAGS, Mode::empty()) {
                    Ok(fd) => fd,
                    Err(Errno::NOENT) => return Ok(ControlFlow::Continue(())),
                    Err(e) => return Err(refused(e)),
                };
                // What was opened, judged again on its handle: a mount made
                // at the name since its `lstat` isn't entered either.
                within(Some(bound), fd.as_fd())?;
                for entry in entries(&fd)? {
                    path.push(&entry);
                    let flow = walk_at(fd.as_fd(), &entry, path, bound, depth + 1, visit)?;
                    path.pop();
                    if flow.is_break() {
                        return Ok(flow);
                    }
                }
                return Ok(ControlFlow::Continue(()));
            }
            _ => Node::Special,
        };
        Ok(visit(path, node))
    }

    pub fn copy_tree(
        dir: &Dir,
        name: &OsStr,
        target: &Dir,
        to: &OsStr,
        each: &mut Each<'_>,
    ) -> io::Result<()> {
        let bound = mount_of_fd(dir.fd.as_fd())?;
        copy_at(dir.fd.as_fd(), name, target.fd.as_fd(), to, bound, 0, each)
    }

    fn copy_at(
        from_dir: BorrowedFd<'_>,
        name: &OsStr,
        into_dir: BorrowedFd<'_>,
        to: &OsStr,
        bound: Mount,
        depth: usize,
        each: &mut Each<'_>,
    ) -> io::Result<()> {
        let stat = rustix::fs::statat(from_dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
        let mode = Mode::from_raw_mode(stat.st_mode) & (Mode::RWXU | Mode::RWXG | Mode::RWXO);
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => copy_file(from_dir, name, into_dir, to, mode)?,
            FileType::Symlink => {
                let target = rustix::fs::readlinkat(from_dir, name, Vec::new())?;
                rustix::fs::symlinkat(target.as_c_str(), into_dir, to)?;
            }
            FileType::Directory => {
                let from = rustix::fs::openat(from_dir, name, TREE_FLAGS, Mode::empty())
                    .map_err(refused)?;
                within(Some(bound), from.as_fd())?;
                if depth >= MAX_DEPTH {
                    return Err(too_deep());
                }
                rustix::fs::mkdirat(into_dir, to, mode | Mode::RWXU)?;
                let into =
                    rustix::fs::openat(into_dir, to, DIR_FLAGS, Mode::empty()).map_err(refused)?;
                each()?;
                for entry in entries(&from)? {
                    copy_at(
                        from.as_fd(),
                        &entry,
                        into.as_fd(),
                        &entry,
                        bound,
                        depth + 1,
                        each,
                    )?;
                }
                rustix::fs::fsync(&into)?;
                return Ok(());
            }
            _ => return Err(special()),
        }
        each()
    }

    /// The file's bytes into a new file made with `mode`, synced. Opened
    /// without following a symlink and without waiting, then judged on the
    /// handle, so a name swapped for a FIFO since its `lstat` is refused,
    /// never waited on. The bytes copied must be its length.
    fn copy_file(
        from_dir: BorrowedFd<'_>,
        name: &OsStr,
        into_dir: BorrowedFd<'_>,
        to: &OsStr,
        mode: Mode,
    ) -> io::Result<()> {
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let mut from = File::from(rustix::fs::openat(from_dir, name, flags, Mode::empty())?);
        let meta = from.metadata()?;
        if !meta.is_file() {
            return Err(changed());
        }
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut into = File::from(rustix::fs::openat(into_dir, to, flags, mode)?);
        if std::io::copy(&mut from, &mut into)? != meta.len() {
            return Err(changed());
        }
        into.sync_all()
    }
}

#[cfg(windows)]
mod imp {
    use super::{Each, MAX_DEPTH, Visit, changed, special, too_deep};
    use crate::anchor::imp::{how, mount_of_handle, plain_dir, within};
    use crate::anchor::{Dir, Mount, Node, Space};
    use fc_sys::windows::{self as win, Create, Expect, access};
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io;
    use std::ops::ControlFlow;
    use std::os::windows::io::{AsHandle as _, BorrowedHandle, OwnedHandle};
    use std::path::PathBuf;

    pub fn space(dir: &Dir) -> io::Result<Space> {
        let (available, block) = win::volume_space(dir.handle.as_handle())?;
        Ok(Space {
            available,
            block: block.max(1),
        })
    }

    /// `name` in the directory `parent` is open on, opened itself (a
    /// reparse point never followed): `None` if nothing is there.
    fn open_at(
        parent: BorrowedHandle<'_>,
        name: &OsStr,
        access: u32,
        expect: Expect,
    ) -> io::Result<Option<OwnedHandle>> {
        match win::open_at(parent, name, how(access, Create::No, expect)) {
            Ok(handle) => Ok(Some(handle)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn walk(
        dir: &Dir,
        name: &OsStr,
        path: &mut PathBuf,
        visit: &mut Visit<'_>,
    ) -> io::Result<ControlFlow<()>> {
        let bound = mount_of_handle(dir.handle.as_handle())?;
        walk_at(dir.handle.as_handle(), name, path, bound, 0, visit)
    }

    /// Windows checks no permission here: a file or directory this process
    /// may not use fails the copy, which rolls back.
    fn walk_at(
        parent: BorrowedHandle<'_>,
        name: &OsStr,
        path: &mut PathBuf,
        bound: Mount,
        depth: usize,
        visit: &mut Visit<'_>,
    ) -> io::Result<ControlFlow<()>> {
        let Some(handle) = open_at(parent, name, access::ATTRIBUTES, Expect::Any)? else {
            return Ok(ControlFlow::Continue(()));
        };
        let attributes = win::attribute_tag(handle.as_handle())?;
        let node = if attributes.reparse_point() {
            Node::Link
        } else if !attributes.directory() {
            Node::File {
                len: File::from(handle).metadata()?.len(),
                readable: true,
            }
        } else if !mount_of_handle(handle.as_handle())?.same(bound) {
            Node::Mount
        } else if depth >= MAX_DEPTH {
            Node::Deep
        } else {
            drop(handle);
            if visit(path, Node::Dir { usable: true }).is_break() {
                return Ok(ControlFlow::Break(()));
            }
            let Some(dir) = open_at(parent, name, access::LIST, Expect::Directory)? else {
                return Ok(ControlFlow::Continue(()));
            };
            if !plain_dir(&dir)? {
                return Err(changed());
            }
            within(Some(bound), dir.as_handle())?;
            for (entry, _) in win::list_dir(dir.as_handle())? {
                path.push(&entry);
                let flow = walk_at(dir.as_handle(), &entry, path, bound, depth + 1, visit)?;
                path.pop();
                if flow.is_break() {
                    return Ok(flow);
                }
            }
            return Ok(ControlFlow::Continue(()));
        };
        Ok(visit(path, node))
    }

    pub fn copy_tree(
        dir: &Dir,
        name: &OsStr,
        target: &Dir,
        to: &OsStr,
        each: &mut Each<'_>,
    ) -> io::Result<()> {
        let bound = mount_of_handle(dir.handle.as_handle())?;
        copy_at(
            dir.handle.as_handle(),
            name,
            target.handle.as_handle(),
            to,
            bound,
            0,
            each,
        )
    }

    /// A reparse point (a symlink or a junction) isn't copied: making one
    /// takes `FSCTL_SET_REPARSE_POINT`, and a symlink a privilege a user
    /// lacks. A walk finds it first ([`Node::Link`]).
    fn copy_at(
        from_dir: BorrowedHandle<'_>,
        name: &OsStr,
        into_dir: BorrowedHandle<'_>,
        to: &OsStr,
        bound: Mount,
        depth: usize,
        each: &mut Each<'_>,
    ) -> io::Result<()> {
        let handle = win::open_at(
            from_dir,
            name,
            how(access::ATTRIBUTES, Create::No, Expect::Any),
        )?;
        let attributes = win::attribute_tag(handle.as_handle())?;
        if attributes.reparse_point() {
            return Err(special());
        }
        drop(handle);
        if !attributes.directory() {
            copy_file(from_dir, name, into_dir, to)?;
            return each();
        }
        let from = win::open_at(
            from_dir,
            name,
            how(access::LIST, Create::No, Expect::Directory),
        )?;
        if !plain_dir(&from)? {
            return Err(changed());
        }
        within(Some(bound), from.as_handle())?;
        if depth >= MAX_DEPTH {
            return Err(too_deep());
        }
        let into = win::open_at(
            into_dir,
            to,
            how(access::LIST, Create::New, Expect::Directory),
        )?;
        each()?;
        for (entry, _) in win::list_dir(from.as_handle())? {
            copy_at(
                from.as_handle(),
                &entry,
                into.as_handle(),
                &entry,
                bound,
                depth + 1,
                each,
            )?;
        }
        Ok(())
    }

    /// The file's bytes into a new file, flushed. Judged on the handle: a
    /// directory or a reparse point there now is refused. The bytes copied
    /// must be its length.
    fn copy_file(
        from_dir: BorrowedHandle<'_>,
        name: &OsStr,
        into_dir: BorrowedHandle<'_>,
        to: &OsStr,
    ) -> io::Result<()> {
        let from = win::open_at(from_dir, name, how(access::READ, Create::No, Expect::File))?;
        let attributes = win::attribute_tag(from.as_handle())?;
        if attributes.reparse_point() || attributes.directory() {
            return Err(changed());
        }
        let mut from = File::from(from);
        let len = from.metadata()?.len();
        let mut into = File::from(win::open_at(
            into_dir,
            to,
            how(access::WRITE, Create::New, Expect::File),
        )?);
        if std::io::copy(&mut from, &mut into)? != len {
            return Err(changed());
        }
        into.sync_all()
    }
}
