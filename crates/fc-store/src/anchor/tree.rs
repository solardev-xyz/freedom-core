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
//!   error before anything is opened at that name. It copies at most a
//!   budget of file bytes, files found after any survey included: a file
//!   longer than what is left is refused before its copy is made, and at
//!   most what is left and one byte more is read from each, so a file that
//!   grows during its read can't run it past the budget either. Timestamps, owners and
//!   extended attributes aren't copied: confinement forbids changing them
//!   (design 0010), and nothing a profile's nodes keep reads them.
//! - **[`Dir::space`]**: the bytes free to this process's user on a
//!   directory's volume, and its allocation unit.
//!
//! Both go from handle to handle, as `remove_tree` does: each name is
//! looked at first (`lstat`, never triggering an automount on Linux), a
//! directory on another mount refused before it is opened, then opened
//! through its parent's handle without following a symlink and checked to
//! be the very directory looked at (its device and inode; on Windows its
//! volume and file ID) and on the walk's mount. So a directory swapped for a
//! link or for another directory between the look and the open is refused,
//! and one renamed out of its path once opened is still the one read. Both
//! hold a handle per level they are in (a copy, two), so neither goes
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
    io::Error::other("an entry of the tree changed during its walk or copy")
}

fn over_budget() -> io::Error {
    io::Error::new(io::ErrorKind::FileTooLarge, "the copy is past its budget")
}

/// `from`'s bytes into `into`, charged to `left`, the copy's budget: at most
/// `left` and one byte more are read, so a file growing during its read
/// stops the copy just past the budget rather than anywhere. Then the
/// bytes copied must be `len`, the length its open handle gave.
fn charge(
    from: &mut std::fs::File,
    into: &mut std::fs::File,
    len: u64,
    left: &mut u64,
    name: &OsStr,
) -> io::Result<()> {
    pause::at("file-opened", name);
    let mut bounded = std::io::Read::take(&mut *from, left.saturating_add(1));
    let copied = std::io::copy(&mut bounded, into)?;
    if copied > *left {
        return Err(over_budget());
    }
    if copied != len {
        return Err(changed());
    }
    *left -= copied;
    Ok(())
}

/// Test-only pause points (fc-store's own unit tests): `classified`, once a
/// name is looked at and before it is opened; `opened`, once a directory is
/// opened and before its entries are read; and `file-opened`, once a file
/// a copy reads is opened and before its bytes are read. So a test can
/// swap, rename or grow what the walk, the copy or a bounded removal is
/// about to reach. Outside this crate's tests each is a no-op that compiles away.
pub(super) mod pause {
    #[cfg(test)]
    type Hook = Box<dyn FnMut(&'static str, &std::ffi::OsStr)>;

    #[cfg(test)]
    std::thread_local! {
        static HOOK: std::cell::RefCell<Option<Hook>> = const { std::cell::RefCell::new(None) };
    }

    /// Sets this thread's hook, or clears it with `None`.
    #[cfg(test)]
    pub fn set(hook: Option<Hook>) {
        HOOK.with(|slot| *slot.borrow_mut() = hook);
    }

    #[cfg(test)]
    pub fn at(point: &'static str, name: &std::ffi::OsStr) {
        let hook = HOOK.with(|slot| slot.borrow_mut().take());
        if let Some(mut hook) = hook {
            hook(point, name);
            HOOK.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot.is_none() {
                    *slot = Some(hook);
                }
            });
        }
    }

    #[cfg(not(test))]
    #[inline(always)]
    pub fn at(_point: &'static str, _name: &std::ffi::OsStr) {}
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
    /// exist, never past this directory's mount (the module's comment), and
    /// at most `budget` bytes of files' data: past it the copy stops with
    /// `FileTooLarge`. `each` runs after each entry is made (a directory
    /// once it is, a file once it is synced), and an error from it stops
    /// the copy. A copy stopped leaves what it made for the caller to
    /// remove. The bytes of files' data it copied.
    pub fn copy_tree(
        &self,
        name: &OsStr,
        target: &Dir,
        to: &OsStr,
        budget: u64,
        each: &mut Each<'_>,
    ) -> io::Result<u64> {
        let mut left = budget;
        imp::copy_tree(self, name, target, to, &mut left, each)?;
        Ok(budget - left)
    }
}

#[cfg(unix)]
mod imp {
    use super::{Each, MAX_DEPTH, Visit, changed, charge, over_budget, pause, special, too_deep};
    use crate::anchor::imp::{
        DIR_FLAGS, TREE_FLAGS, entries, mount_at, mount_of_fd, refused, stat_at, stat_identity,
        within,
    };
    use crate::anchor::{Dir, Mount, Node, Space};
    use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
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

    /// The directory `name` in `parent`, looked at as `stat`, opened through
    /// `parent`'s handle without following a symlink: it must be the one
    /// looked at, on the walk's mount. `None` if it is gone.
    fn open_dir(
        parent: BorrowedFd<'_>,
        name: &OsStr,
        stat: &rustix::fs::Stat,
        bound: Mount,
    ) -> io::Result<Option<OwnedFd>> {
        let fd = match rustix::fs::openat(parent, name, TREE_FLAGS, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(refused(e)),
        };
        if stat_identity(&rustix::fs::fstat(&fd)?) != stat_identity(stat) {
            return Err(changed());
        }
        within(Some(bound), fd.as_fd())?;
        pause::at("opened", name);
        Ok(Some(fd))
    }

    fn walk_at(
        parent: BorrowedFd<'_>,
        name: &OsStr,
        path: &mut PathBuf,
        bound: Mount,
        depth: usize,
        visit: &mut Visit<'_>,
    ) -> io::Result<ControlFlow<()>> {
        let stat = match stat_at(parent, name) {
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
                pause::at("classified", name);
                let Some(fd) = open_dir(parent, name, &stat, bound)? else {
                    return Ok(ControlFlow::Continue(()));
                };
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
        left: &mut u64,
        each: &mut Each<'_>,
    ) -> io::Result<()> {
        let bound = mount_of_fd(dir.fd.as_fd())?;
        let into = target.fd.as_fd();
        copy_at(dir.fd.as_fd(), name, into, to, bound, 0, left, each)
    }

    #[allow(clippy::too_many_arguments)]
    fn copy_at(
        from_dir: BorrowedFd<'_>,
        name: &OsStr,
        into_dir: BorrowedFd<'_>,
        to: &OsStr,
        bound: Mount,
        depth: usize,
        left: &mut u64,
        each: &mut Each<'_>,
    ) -> io::Result<()> {
        let stat = stat_at(from_dir, name)?;
        let mode = Mode::from_raw_mode(stat.st_mode) & (Mode::RWXU | Mode::RWXG | Mode::RWXO);
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => copy_file(from_dir, name, &stat, into_dir, to, mode, left)?,
            FileType::Symlink => {
                let target = rustix::fs::readlinkat(from_dir, name, Vec::new())?;
                rustix::fs::symlinkat(target.as_c_str(), into_dir, to)?;
            }
            FileType::Directory => {
                if !mount_at(from_dir, name, &stat).same(bound) {
                    return Err(super::crossing());
                }
                if depth >= MAX_DEPTH {
                    return Err(too_deep());
                }
                pause::at("classified", name);
                let from = open_dir(from_dir, name, &stat, bound)?
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
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
                        left,
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
    /// handle: it must be the regular file looked at (`stat`), so a name
    /// swapped for a FIFO or another file since is refused, never waited
    /// on. Longer than what is `left` of the budget, it is refused before
    /// its copy is made; its read is bounded by it too ([`charge`]).
    fn copy_file(
        from_dir: BorrowedFd<'_>,
        name: &OsStr,
        stat: &rustix::fs::Stat,
        into_dir: BorrowedFd<'_>,
        to: &OsStr,
        mode: Mode,
        left: &mut u64,
    ) -> io::Result<()> {
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let from = rustix::fs::openat(from_dir, name, flags, Mode::empty())?;
        let held = rustix::fs::fstat(&from)?;
        if FileType::from_raw_mode(held.st_mode) != FileType::RegularFile
            || stat_identity(&held) != stat_identity(stat)
        {
            return Err(changed());
        }
        let mut from = File::from(from);
        let len = u64::try_from(held.st_size).unwrap_or(0);
        if len > *left {
            return Err(over_budget());
        }
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut into = File::from(rustix::fs::openat(into_dir, to, flags, mode)?);
        charge(&mut from, &mut into, len, left, name)?;
        into.sync_all()
    }
}

#[cfg(windows)]
mod imp {
    use super::{Each, MAX_DEPTH, Visit, changed, charge, over_budget, pause, special, too_deep};
    use crate::anchor::imp::{how, mount_of_handle, plain_dir, within};
    use crate::anchor::{Dir, Mount, Node, Space};
    use crate::fsx::file_identity;
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
    /// reparse point never followed) with `access`: `None` if nothing is
    /// there.
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

    /// Refused for want of a right, or by another handle that shares less
    /// (a sharing or lock violation).
    fn refused_access(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::PermissionDenied
            || matches!(error.raw_os_error(), Some(32 | 33))
    }

    /// The same file or directory: its volume and file ID.
    fn same(one: &OwnedHandle, two: &OwnedHandle) -> io::Result<bool> {
        Ok(file_identity(one.as_handle())? == file_identity(two.as_handle())?)
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

    /// The rights a copy and its source's removal take, probed by opening
    /// with them: a file's data (`FILE_READ_DATA`, as the copy opens it) and
    /// `DELETE`; a directory's listing and `DELETE`. (Deleting an entry takes its own `DELETE`, or the parent's
    /// `FILE_DELETE_CHILD`, which the system grants `DELETE` on.) A refusal
    /// is a node this process can't use.
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
            let len = File::from(handle.try_clone()?).metadata()?.len();
            let readable = match open_at(
                parent,
                name,
                access::READ_DATA | access::DELETE,
                Expect::File,
            ) {
                Ok(Some(probe)) => same(&probe, &handle)?,
                Ok(None) => return Ok(ControlFlow::Continue(())),
                Err(e) if refused_access(&e) => false,
                Err(e) => return Err(e),
            };
            Node::File { len, readable }
        } else if !mount_of_handle(handle.as_handle())?.same(bound) {
            Node::Mount
        } else if depth >= MAX_DEPTH {
            Node::Deep
        } else {
            pause::at("classified", name);
            let dir = match open_at(
                parent,
                name,
                access::LIST | access::DELETE,
                Expect::Directory,
            ) {
                Ok(Some(dir)) => dir,
                Ok(None) => return Ok(ControlFlow::Continue(())),
                Err(e) if refused_access(&e) => {
                    return Ok(visit(path, Node::Dir { usable: false }));
                }
                Err(e) => return Err(e),
            };
            if !plain_dir(&dir)? || !same(&dir, &handle)? {
                return Err(changed());
            }
            drop(handle);
            within(Some(bound), dir.as_handle())?;
            if visit(path, Node::Dir { usable: true }).is_break() {
                return Ok(ControlFlow::Break(()));
            }
            pause::at("opened", name);
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
        left: &mut u64,
        each: &mut Each<'_>,
    ) -> io::Result<()> {
        let bound = mount_of_handle(dir.handle.as_handle())?;
        let into = target.handle.as_handle();
        copy_at(dir.handle.as_handle(), name, into, to, bound, 0, left, each)
    }

    /// A reparse point (a symlink or a junction) isn't copied: making one
    /// takes `FSCTL_SET_REPARSE_POINT`, and a symlink a privilege a user
    /// lacks. A walk finds it first ([`Node::Link`]).
    #[allow(clippy::too_many_arguments)]
    fn copy_at(
        from_dir: BorrowedHandle<'_>,
        name: &OsStr,
        into_dir: BorrowedHandle<'_>,
        to: &OsStr,
        bound: Mount,
        depth: usize,
        left: &mut u64,
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
        if !attributes.directory() {
            copy_file(from_dir, name, &handle, into_dir, to, left)?;
            return each();
        }
        if !mount_of_handle(handle.as_handle())?.same(bound) {
            return Err(super::crossing());
        }
        if depth >= MAX_DEPTH {
            return Err(too_deep());
        }
        pause::at("classified", name);
        let from = win::open_at(
            from_dir,
            name,
            how(access::LIST, Create::No, Expect::Directory),
        )?;
        if !plain_dir(&from)? || !same(&from, &handle)? {
            return Err(changed());
        }
        drop(handle);
        within(Some(bound), from.as_handle())?;
        pause::at("opened", name);
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
                left,
                each,
            )?;
        }
        Ok(())
    }

    /// The file's bytes into a new file, flushed. Opened for its data alone
    /// (`FILE_READ_DATA`, and the attributes every open adds), as the walk
    /// probes it, and judged on the handle: it must be the file looked at
    /// (`looked`), not a directory or a reparse point. Longer than what is
    /// `left` of the budget, it is refused before its copy is made; its
    /// read is bounded by it too ([`charge`]).
    fn copy_file(
        from_dir: BorrowedHandle<'_>,
        name: &OsStr,
        looked: &OwnedHandle,
        into_dir: BorrowedHandle<'_>,
        to: &OsStr,
        left: &mut u64,
    ) -> io::Result<()> {
        let from = win::open_at(
            from_dir,
            name,
            how(access::READ_DATA, Create::No, Expect::File),
        )?;
        let attributes = win::attribute_tag(from.as_handle())?;
        if attributes.reparse_point() || attributes.directory() || !same(&from, looked)? {
            return Err(changed());
        }
        let mut from = File::from(from);
        let len = from.metadata()?.len();
        if len > *left {
            return Err(over_budget());
        }
        let mut into = File::from(win::open_at(
            into_dir,
            to,
            how(access::WRITE, Create::New, Expect::File),
        )?);
        charge(&mut from, &mut into, len, left, name)?;
        into.sync_all()
    }
}
