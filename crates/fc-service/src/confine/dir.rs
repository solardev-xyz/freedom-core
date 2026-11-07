//! A directory a service opens before confinement and then only reads, held
//! open with its identity (design 0010, D5: the import's roots), so that
//! what was decided about it is bound to the directory itself, not to its
//! name.
//!
//! - **The open** never follows a symlink at the path's last component, and
//!   never waits:
//!   - on Linux, one component at a time from `/`, each `O_PATH |
//!     O_DIRECTORY | O_NOFOLLOW`: no component is followed as a symlink, so
//!     the directory held is the one the canonical path named when it was
//!     opened. `O_PATH` reads nothing and Landlock doesn't check it, so the
//!     same open works once confined;
//!   - on macOS and other Unix, one open, `O_RDONLY | O_DIRECTORY |
//!     O_NOFOLLOW | O_NONBLOCK`: the last component isn't followed, and the
//!     ones before it are resolved by name;
//!   - on Windows, `FILE_FLAG_BACKUP_SEMANTICS` (which a directory needs)
//!     and `FILE_FLAG_OPEN_REPARSE_POINT`: a reparse point at the last
//!     component is opened itself, then refused.
//!
//!   Anything but a directory is refused, as the handle opened shows it.
//! - **Its identity** ([`Identity`]): on Unix its device and inode numbers;
//!   on Windows its volume's serial number and its file ID (`FileIdInfo`,
//!   or the file index where the file system lacks it).
//! - **Landlock's rule** for a [`super::Policy::read_only_dirs`] entry is
//!   made from this handle, never by opening its path again. Seatbelt's
//!   rules are by path, so a service that must know the directory is still
//!   the one it checked opens it again once confined and compares its path
//!   and identity (the import does).

use std::fs::{File, Metadata};
use std::io;
#[cfg(target_os = "linux")]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A file's identity: on Unix its device and inode numbers; on Windows its
/// volume's serial number and its file ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identity {
    pub volume: u64,
    pub file: u128,
}

/// A directory opened by [`OpenDir::open`], held open, with its path and
/// identity.
#[derive(Debug, Clone)]
pub struct OpenDir {
    path: PathBuf,
    dir: Arc<File>,
    identity: Identity,
}

/// The same directory: the same path and the same identity.
impl PartialEq for OpenDir {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.identity == other.identity
    }
}

impl Eq for OpenDir {}

impl OpenDir {
    /// Opens the directory at `path`, which must be absolute and should be
    /// canonical (on Linux, a `.` or `..` component is refused), never
    /// following a symlink at its last component (on Linux, at any), and
    /// never waiting. Anything but a directory is refused
    /// (`NotADirectory`).
    pub fn open(path: &Path) -> io::Result<Self> {
        let dir = open(path)?;
        let metadata = dir.metadata()?;
        if !is_dir(&metadata) {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "not a directory",
            ));
        }
        let identity = identity(&dir, &metadata)?;
        Ok(Self {
            path: path.to_path_buf(),
            dir: Arc::new(dir),
            identity,
        })
    }

    /// The path it was opened at.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The directory's identity, from the handle.
    pub fn identity(&self) -> Identity {
        self.identity
    }

    /// The open directory: Landlock's rule is made from it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) fn file(&self) -> &File {
        &self.dir
    }

    /// Its descriptor, for [`super::Policy::descriptors`].
    #[cfg(unix)]
    pub fn descriptor(&self) -> i32 {
        use std::os::fd::AsRawFd as _;
        self.dir.as_raw_fd()
    }
}

/// A path the open can't take as it is.
#[cfg(unix)]
fn not_canonical() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "not an absolute, canonical path",
    )
}

/// One component at a time from `/`, none followed as a symlink.
#[cfg(target_os = "linux")]
fn open(path: &Path) -> io::Result<File> {
    use rustix::fs::{CWD, Mode, OFlags};

    let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(not_canonical());
    }
    let mut dir = rustix::fs::openat(CWD, "/", flags, Mode::empty())?;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(not_canonical());
        };
        dir = rustix::fs::openat(&dir, name, flags, Mode::empty())?;
    }
    Ok(File::from(dir))
}

/// One open, its last component not followed as a symlink.
#[cfg(all(unix, not(target_os = "linux")))]
fn open(path: &Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};

    if !path.is_absolute() {
        return Err(not_canonical());
    }
    let flags =
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    Ok(File::from(rustix::fs::open(path, flags, Mode::empty())?))
}

/// `FILE_FLAG_BACKUP_SEMANTICS`: a directory can be opened.
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// `FILE_FLAG_OPEN_REPARSE_POINT`: a symlink, junction or other reparse
/// point is opened itself, never its target.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// `FILE_ATTRIBUTE_REPARSE_POINT`.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

#[cfg(windows)]
fn open(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no directory handles on this OS",
    ))
}

/// Whether `metadata`, the handle's, is a directory's: on Windows, not a
/// reparse point.
fn is_dir(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return false;
        }
    }
    metadata.is_dir()
}

#[cfg(unix)]
fn identity(_dir: &File, metadata: &Metadata) -> io::Result<Identity> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(Identity {
        volume: metadata.dev(),
        file: u128::from(metadata.ino()),
    })
}

#[cfg(windows)]
fn identity(dir: &File, _metadata: &Metadata) -> io::Result<Identity> {
    use std::os::windows::io::AsHandle as _;
    let (volume, file) = fc_sys::windows::file_id(dir.as_handle())
        .or_else(|_| fc_sys::windows::file_index(dir.as_handle()))?;
    Ok(Identity { volume, file })
}

#[cfg(not(any(unix, windows)))]
fn identity(_dir: &File, _metadata: &Metadata) -> io::Result<Identity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no file identity on this OS",
    ))
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn root() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(dir.path()).unwrap();
        (dir, path)
    }

    #[test]
    fn a_directory_is_held_with_its_identity_through_a_rename() {
        let (_t, root) = root();
        let one = root.join("one");
        let two = root.join("two");
        std::fs::create_dir(&one).unwrap();
        std::fs::create_dir(&two).unwrap();
        let held = OpenDir::open(&one).unwrap();
        assert_eq!(held.path(), one);
        assert_eq!(OpenDir::open(&one).unwrap(), held);
        assert_ne!(OpenDir::open(&two).unwrap().identity(), held.identity());
        // Renamed, it is the same directory; another made at its name isn't.
        let moved = root.join("moved");
        std::fs::rename(&one, &moved).unwrap();
        std::fs::create_dir(&one).unwrap();
        assert_eq!(OpenDir::open(&moved).unwrap().identity(), held.identity());
        assert_ne!(OpenDir::open(&one).unwrap().identity(), held.identity());
        assert_ne!(OpenDir::open(&one).unwrap(), held);
    }

    #[test]
    fn anything_but_a_directory_is_refused() {
        let (_t, root) = root();
        let file = root.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(OpenDir::open(&file).is_err());
        assert!(OpenDir::open(&root.join("missing")).is_err());
        #[cfg(unix)]
        {
            let dir = root.join("dir");
            std::fs::create_dir(&dir).unwrap();
            // A symlink to a directory, at the last component.
            std::os::unix::fs::symlink(&dir, root.join("link")).unwrap();
            assert!(OpenDir::open(&root.join("link")).is_err());
            // A FIFO: refused at once, never waited on.
            let fifo = root.join("fifo");
            assert!(
                std::process::Command::new("mkfifo")
                    .arg(&fifo)
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(OpenDir::open(&fifo).is_err());
            assert!(OpenDir::open(Path::new("relative")).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_no_component_is_followed() {
        let (_t, root) = root();
        let dir = root.join("real").join("inner");
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        assert!(OpenDir::open(&root.join("link").join("inner")).is_err());
        assert!(OpenDir::open(&dir.join("..").join("inner")).is_err());
        assert!(OpenDir::open(&dir).is_ok());
    }
}
