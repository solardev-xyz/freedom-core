//! A starting move's cross-device copy (design 0013, "The move", step 4;
//! PRF-9c): an entry whose rename into `freedom/` fails because `freedom/`
//! is on another volume (`EXDEV`; Windows's `ERROR_NOT_SAME_DEVICE`; both
//! std's `CrossesDevices`) is copied there instead. `migrate.rs` copies;
//! this sizes an entry, finds what a copy couldn't move, and checks the
//! room for it.
//!
//! - **The survey** ([`survey`]) walks the entry without following a
//!   symlink and without opening anything but a directory (fc-store's
//!   `Dir::walk`), and never past the profile directory's mount:
//!   - **its size:** each file's length rounded up to the target volume's
//!     allocation unit, and one unit for each directory and symlink;
//!   - **what the copy couldn't move, or the cleanup couldn't remove,**
//!     each a reason with the path where it was found: a mount point inside
//!     the entry (`nested_mount`: the copy would pull the mounted volume
//!     across, and the source's removal would empty it); a FIFO, a socket
//!     or a device (`special_file`: never opened, so never waited on; the
//!     copy doesn't make one); a file this process can't read, or a
//!     directory it can't list, write and search, or a profile directory
//!     it can't remove the entry from (`no_access`: the copy or the
//!     removal would fail halfway; on Windows each file's reading and
//!     `DELETE`, and each directory's listing and `DELETE`, probed by
//!     opening with them); a directory deeper than fc-store's `MAX_DEPTH`
//!     (`too_deep`); on Windows, a reparse point (`reparse_point`: making
//!     one takes a privilege a user lacks).
//! - **The cap** ([`within_cap`]): a starting move copies at most 2 GiB in
//!   all (`copy_too_large` past it), so it ends well inside main's
//!   ten-minute bound even on slow media. A copy killed at the bound rolls
//!   back and starts over at the next start, so a larger one would never
//!   finish; past the cap the move defers, and the old layout keeps
//!   working.
//! - **The room** ([`room`]): the survey's size plus a margin, 5% of it and
//!   at least 64 MiB, must fit in the space free to this process's user on
//!   `freedom/`'s volume, so a copy never leaves it nearly full for the
//!   nodes that start on it next.
//!
//! Both run in the preconditions, before anything changes, for every entry
//! when `freedom/` is already on another mount than the profile's
//! directory: a failure there is `deferred` with nothing changed. They run
//! again for each entry at its copy, where a failure rolls the move back.

use std::ffi::OsStr;
use std::io;
use std::ops::ControlFlow;

use fc_store::anchor::{Dir, Node, Space};

/// The least room a copy leaves on `freedom/`'s volume beyond its own size.
const MARGIN_MIN: u64 = 64 * 1024 * 1024;

/// The most a starting move copies across devices, in all, by the survey's
/// size (the coordinator's call of 2026-11-22; the module's comment).
pub const COPY_CAP: u64 = 2 * 1024 * 1024 * 1024;

/// Whether copying `total` in all stays within [`COPY_CAP`].
pub fn within_cap(total: u64) -> Result<(), Unfit> {
    if total <= COPY_CAP {
        return Ok(());
    }
    Err(Unfit {
        why: "copy_too_large",
        detail: format!("{total} bytes to copy, past the {COPY_CAP} a move copies"),
    })
}

/// The bytes a copy of `size` needs free: its size, and the margin.
pub fn needed(size: u64) -> u64 {
    size.saturating_add((size / 20).max(MARGIN_MIN))
}

/// Why an entry isn't copied, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unfit {
    /// The reason's word, for the log (the module's comment).
    pub why: &'static str,
    /// The path found, from the profile's directory, or the sizes compared.
    pub detail: String,
}

impl Unfit {
    /// As the copy's failure, which rolls the move back: no room is a full
    /// volume's error.
    pub fn error(&self) -> io::Error {
        let kind = if self.why == "no_space" {
            io::ErrorKind::StorageFull
        } else {
            io::ErrorKind::Other
        };
        io::Error::new(kind, format!("{}: {}", self.why, self.detail))
    }
}

/// Whether a rename failed because its target is on another volume.
pub fn crosses_devices(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::CrossesDevices
}

/// The free space on `dir`'s volume, as the move reads it
/// (`FREEDOM_CORED_TEST_PROFILE_MIGRATE_FREE` replaces the bytes free).
pub fn space(dir: &Dir) -> io::Result<Space> {
    let mut space = dir.space()?;
    if let Some(free) = crate::testhooks::profile_migrate_free() {
        space.available = free;
    }
    Ok(space)
}

/// What copying the root's `name` to a volume whose allocation unit is
/// `block` takes, or why it can't be copied (the module's comment).
pub fn survey(root: &Dir, name: &str, block: u64) -> io::Result<Result<u64, Unfit>> {
    // The source's removal takes the right to change the profile's
    // directory itself (on Unix its write and search permission).
    if !root.may_change() {
        return Ok(Err(Unfit {
            why: "no_access",
            detail: "the profile's directory".to_owned(),
        }));
    }
    let block = block.max(1);
    let mut size = 0u64;
    let mut unfit = None;
    root.walk(OsStr::new(name), &mut |path, node| {
        let why = match node {
            Node::File {
                len,
                readable: true,
            } => {
                size = size.saturating_add(len.div_ceil(block).saturating_mul(block));
                return ControlFlow::Continue(());
            }
            Node::Dir { usable: true } => {
                size = size.saturating_add(block);
                return ControlFlow::Continue(());
            }
            Node::Link if cfg!(unix) => {
                size = size.saturating_add(block);
                return ControlFlow::Continue(());
            }
            Node::Link => "reparse_point",
            Node::File {
                readable: false, ..
            }
            | Node::Dir { usable: false } => "no_access",
            Node::Special => "special_file",
            Node::Mount => "nested_mount",
            Node::Deep => "too_deep",
        };
        unfit = Some(Unfit {
            why,
            detail: path.to_string_lossy().replace('\\', "/"),
        });
        ControlFlow::Break(())
    })?;
    Ok(match unfit {
        Some(unfit) => Err(unfit),
        None => Ok(size),
    })
}

/// Whether a copy of `size` fits in `space` with its margin.
pub fn room(space: Space, size: u64) -> Result<(), Unfit> {
    let needed = needed(size);
    if space.available >= needed {
        return Ok(());
    }
    Err(Unfit {
        why: "no_space",
        detail: format!(
            "{needed} bytes needed with the margin, {} free",
            space.available
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_move_copies_at_most_2_gib() {
        assert_eq!(within_cap(0), Ok(()));
        assert_eq!(within_cap(COPY_CAP), Ok(()));
        let over = within_cap(COPY_CAP + 1).unwrap_err();
        assert_eq!(over.why, "copy_too_large");
        assert_eq!(over.error().kind(), io::ErrorKind::Other);
    }

    /// A profile directory this process can't change: no source could be
    /// removed from it. Root may change anything, so this checks only where
    /// the modes bind.
    #[cfg(unix)]
    #[test]
    fn a_survey_needs_the_right_to_remove_from_the_profile_directory() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("profile");
        std::fs::create_dir_all(base.join("run")).unwrap();
        let dir = root(&base);
        assert_eq!(survey(&dir, "run", 512).unwrap(), Ok(512));
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o500)).unwrap();
        if std::fs::write(base.join("probe"), b"x").is_err() {
            let unfit = survey(&dir, "run", 512).unwrap().unwrap_err();
            assert_eq!(unfit.why, "no_access");
        }
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn the_margin_is_five_percent_and_at_least_64_mib() {
        assert_eq!(needed(0), MARGIN_MIN);
        assert_eq!(needed(1000), 1000 + MARGIN_MIN);
        let large = 10 * 1024 * 1024 * 1024u64;
        assert_eq!(needed(large), large + large / 20);
        assert_eq!(needed(u64::MAX), u64::MAX);
        let space = |available| Space {
            available,
            block: 4096,
        };
        assert_eq!(room(space(1000 + MARGIN_MIN), 1000), Ok(()));
        let short = room(space(999 + MARGIN_MIN), 1000).unwrap_err();
        assert_eq!(short.why, "no_space");
        assert_eq!(short.error().kind(), io::ErrorKind::StorageFull);
    }

    /// `EXDEV` (Linux and macOS) and `ERROR_NOT_SAME_DEVICE` (Windows, 17)
    /// both read as crossing devices, as the rename's failure does; other
    /// failures don't take the copy path.
    #[test]
    fn crossing_devices_is_exdev_or_error_not_same_device() {
        #[cfg(unix)]
        let code = rustix::io::Errno::XDEV.raw_os_error();
        #[cfg(windows)]
        let code = 17;
        assert!(crosses_devices(&io::Error::from_raw_os_error(code)));
        assert!(crosses_devices(&io::Error::from(
            io::ErrorKind::CrossesDevices
        )));
        assert!(!crosses_devices(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
        assert!(!crosses_devices(&io::Error::from(
            io::ErrorKind::StorageFull
        )));
    }

    fn root(path: &std::path::Path) -> Dir {
        Dir::open_root(path, fc_store::anchor::Resolve::Follow)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn a_survey_sizes_by_the_block_and_finds_what_isnt_copied() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        std::fs::create_dir_all(base.join("ant-data").join("sub")).unwrap();
        std::fs::write(base.join("ant-data").join("one"), [0u8; 1]).unwrap();
        std::fs::write(base.join("ant-data").join("sub").join("two"), [0u8; 4097]).unwrap();
        std::fs::write(base.join("settings.json"), b"{}").unwrap();
        let dir = root(base);
        // Two directories, a block for the one-byte file, two for the other.
        assert_eq!(survey(&dir, "ant-data", 4096).unwrap(), Ok(5 * 4096));
        assert_eq!(survey(&dir, "settings.json", 4096).unwrap(), Ok(4096));
        assert_eq!(survey(&dir, "missing", 4096).unwrap(), Ok(0));
        // Too deep: a directory MAX_DEPTH levels below the top.
        let mut deep = base.join("ipfs-data");
        for _ in 0..fc_store::anchor::MAX_DEPTH {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        let unfit = survey(&dir, "ipfs-data", 4096).unwrap().unwrap_err();
        assert_eq!(unfit.why, "too_deep");
        assert!(unfit.detail.starts_with("ipfs-data/d/d/"), "{unfit:?}");
        std::fs::remove_dir(&deep).unwrap();
        assert!(survey(&dir, "ipfs-data", 4096).unwrap().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_survey_refuses_special_files_and_counts_links() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        std::fs::create_dir_all(base.join("run")).unwrap();
        std::os::unix::fs::symlink("/nowhere", base.join("run").join("link")).unwrap();
        let dir = root(base);
        assert_eq!(survey(&dir, "run", 512).unwrap(), Ok(2 * 512));
        let _socket =
            std::os::unix::net::UnixListener::bind(base.join("run").join("sock")).unwrap();
        let unfit = survey(&dir, "run", 512).unwrap().unwrap_err();
        assert_eq!(
            unfit,
            Unfit {
                why: "special_file",
                detail: "run/sock".into()
            }
        );
    }
}
