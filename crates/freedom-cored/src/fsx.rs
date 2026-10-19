//! Durable file operations (design 0001, "Writes and durability").
//!
//! **Replacing a file:**
//! 1. Create a temp file in the same directory with an exclusive create. On
//!    Unix its mode is `0600` from creation.
//! 2. Write it, then `fsync` it.
//! 3. Run the caller's check against the temp file (for the vault: decrypt it
//!    and compare the mnemonic). If the check fails, the temp file is
//!    removed and the target is untouched.
//! 4. Ask the caller's commit gate. It answers false when the operation was
//!    abandoned (cancelled, revoked or out of time) before this point; the
//!    temp file is then removed and the target is untouched.
//! 5. Rename it over the target.
//! 6. On Unix, `fsync` the directory.
//!
//! Errors from every flush are reported, never ignored. A failure before the
//! rename is an error and leaves the target untouched. Once the rename (or
//! unlink) has happened the change is committed, so a failed directory flush
//! after it is reported as [`Done::NotDurable`] rather than as an error:
//! callers must never report a committed change as failed.
//!
//! **Guarantee:** the target survives a process crash on every OS, and power
//! loss on local Unix filesystems. Windows rename is best-effort under power
//! loss.
//!
//! **Leftover temp files.** A process killed between steps 1 and 5 leaves its
//! temp file behind; for the vault that is an encrypted copy of the
//! mnemonic. [`remove_temps`] removes them: at startup, under the gate, and
//! on `vault.delete` (#81).
//!
//! **Reading a file** ([`open_regular`], [`read_at_most`]) opens it once and
//! judges the open handle: anything but a regular file is refused before a
//! byte is read, and no more than a bound is read, so nothing swapped in
//! between a check and the read (a FIFO, a symlink, a growing file) can
//! block a thread or be read whole (#83).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Why a write failed. In every case the target is untouched: `Check` means
/// the staged file didn't verify, `Abandoned` that the commit gate refused.
#[derive(Debug)]
pub enum WriteError {
    Io(std::io::Error),
    Check(String),
    Abandoned,
}

/// A change that has taken effect. `NotDurable`: the directory flush after
/// the rename or unlink failed, so the change is visible but may not survive
/// power loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Done {
    Durable,
    NotDurable,
}

impl From<std::io::Error> for WriteError {
    fn from(error: std::io::Error) -> Self {
        WriteError::Io(error)
    }
}

/// Atomically and durably replaces `target` with `contents`, after `check`
/// accepts the staged file and `commit` allows the rename.
pub fn replace(
    target: &Path,
    contents: &[u8],
    check: impl FnOnce(&Path) -> Result<(), String>,
    commit: impl FnOnce() -> bool,
) -> Result<Done, WriteError> {
    let dir = target
        .parent()
        .ok_or_else(|| std::io::Error::other("target has no parent directory"))?;
    let (temp_path, mut temp) = create_temp(dir, target)?;
    let staged = (|| -> Result<(), WriteError> {
        temp.write_all(contents)?;
        temp.sync_all()?;
        drop(temp);
        check(&temp_path).map_err(WriteError::Check)?;
        if !commit() {
            return Err(WriteError::Abandoned);
        }
        std::fs::rename(&temp_path, target)?;
        Ok(())
    })();
    if let Err(error) = staged {
        let _ = std::fs::remove_file(&temp_path);
        return Err(error);
    }
    Ok(flushed(sync_dir(dir)))
}

/// Removes `target` durably, if `commit` allows it: unlink, then `fsync` the
/// directory. A missing file is not an error. `Ok(None)`: the gate refused,
/// and the file is untouched.
pub fn remove(target: &Path, commit: impl FnOnce() -> bool) -> std::io::Result<Option<Done>> {
    if !commit() {
        return Ok(None);
    }
    match std::fs::remove_file(target) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Some(Done::Durable)),
        Err(e) => return Err(e),
    }
    Ok(Some(match target.parent() {
        Some(dir) => flushed(sync_dir(dir)),
        None => Done::Durable,
    }))
}

/// The outcome of the directory flush after a commit; a failure is logged.
fn flushed(sync: std::io::Result<()>) -> Done {
    match sync {
        Ok(()) => Done::Durable,
        Err(e) => {
            crate::log::error(
                "directory flush failed after commit",
                serde_json::json!({ "kind": e.kind().to_string() }),
            );
            Done::NotDurable
        }
    }
}

/// Tightens an existing secret file to mode `0600` in place. This changes
/// metadata, not content, so quick unlock's fingerprint is unaffected. Only
/// regular files owned by the current user are touched; symlinks and
/// foreign files are left alone. Returns whether the mode was changed.
#[cfg(unix)]
pub fn tighten(path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if !metadata.is_file() || metadata.uid() != rustix::process::getuid().as_raw() {
        return Ok(false);
    }
    if metadata.mode() & 0o777 == 0o600 {
        return Ok(false);
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(true)
}

/// Windows has no POSIX modes: files inherit their directory's ACL.
#[cfg(not(unix))]
pub fn tighten(_path: &Path) -> std::io::Result<bool> {
    Ok(false)
}

/// What [`open_regular`] found at a path.
#[derive(Debug)]
pub enum Regular {
    /// Nothing is there.
    Missing,
    /// Something other than a regular file: a directory, a FIFO, a socket, a
    /// device, or a symlink when not following them. Nothing was read.
    Other,
    /// A regular file, open for reading.
    File(File),
}

/// Opens `path` for reading if it is a regular file, judged on the opened
/// handle, so nothing can be swapped in between the check and the read
/// (#83). The open itself can't wait: on Unix it is non-blocking (a FIFO
/// opens at once, and is then refused), and without `follow` a symlink is
/// refused (`O_NOFOLLOW`). Windows has no FIFOs among files, and opening a
/// named pipe doesn't wait; without `follow`, a symlink is refused by its own
/// metadata first, and whatever the handle then turns out to be, anything
/// but a regular file is refused before a byte is read.
pub fn open_regular(path: &Path, follow: bool) -> std::io::Result<Regular> {
    #[cfg(not(unix))]
    if !follow {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.is_file() => return Ok(Regular::Other),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Regular::Missing),
            Err(e) => return Err(e),
        }
    }
    match open_nonblocking(path, follow) {
        Ok(file) => {
            if file.metadata()?.is_file() {
                Ok(Regular::File(file))
            } else {
                Ok(Regular::Other)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Regular::Missing),
        Err(e) => {
            // A symlink refused by O_NOFOLLOW (ELOOP), or a directory Windows
            // won't open as a file: say what is there, without reading it.
            let found = if follow {
                std::fs::metadata(path)
            } else {
                std::fs::symlink_metadata(path)
            };
            match found {
                Ok(metadata) if !metadata.is_file() => Ok(Regular::Other),
                _ => Err(e),
            }
        }
    }
}

#[cfg(unix)]
fn open_nonblocking(path: &Path, follow: bool) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags};
    let mut flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC;
    if !follow {
        flags |= OFlags::NOFOLLOW;
    }
    Ok(File::from(rustix::fs::open(path, flags, Mode::empty())?))
}

#[cfg(not(unix))]
fn open_nonblocking(path: &Path, _follow: bool) -> std::io::Result<File> {
    File::open(path)
}

/// Reads `file` to its end, but never more than `max` bytes: `None` if it
/// holds more (it may have grown since it was opened).
pub fn read_at_most(file: File, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    Ok((bytes.len() as u64 <= max).then_some(bytes))
}

/// Removes the temp files [`replace`] left in `dir` for its target `name`
/// (`.<name>.<pid>.<n>.tmp`), then flushes the directory if it removed any.
/// Only call it while nothing can be writing `name`: under the gate, with
/// no job running. Returns how many it removed.
pub fn remove_temps(dir: &Path, name: &str) -> std::io::Result<usize> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut removed = 0;
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        if !file_name.to_str().is_some_and(|n| is_temp_of(n, name)) {
            continue;
        }
        // A directory or anything else under that name isn't ours: left.
        if !entry.file_type()?.is_file() {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    if removed > 0 {
        sync_dir(dir)?;
    }
    Ok(removed)
}

/// Whether `file_name` is a temp file [`create_temp`] makes for `name`:
/// `.<name>.<digits>.<digits>.tmp`, exactly.
fn is_temp_of(file_name: &str, name: &str) -> bool {
    let Some(rest) = file_name
        .strip_prefix('.')
        .and_then(|r| r.strip_prefix(name))
        .and_then(|r| r.strip_prefix('.'))
        .and_then(|r| r.strip_suffix(".tmp"))
    else {
        return false;
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    matches!(rest.split_once('.'), Some((pid, n)) if digits(pid) && digits(n))
}

/// Creates `<target>.<pid>.<n>.tmp` exclusively in `dir`.
fn create_temp(dir: &Path, target: &Path) -> std::io::Result<(PathBuf, File)> {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    for attempt in 0u32..100 {
        let path = dir.join(format!(".{name}.{}.{attempt}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("no free temp file name"))
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_files(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn replaces_atomically_with_private_mode() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("identity-vault.json");
        std::fs::write(&target, b"old").unwrap();
        let done = replace(
            &target,
            b"new",
            |staged| {
                assert_eq!(std::fs::read(staged).unwrap(), b"new");
                Ok(())
            },
            || true,
        )
        .unwrap();
        assert_eq!(done, Done::Durable);
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert!(temp_files(dir.path()).is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn a_failed_check_leaves_the_target_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("identity-vault.json");
        std::fs::write(&target, b"old").unwrap();
        let result = replace(
            &target,
            b"broken",
            |_| Err("does not decrypt".into()),
            || true,
        );
        assert!(matches!(result, Err(WriteError::Check(_))));
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
        assert!(temp_files(dir.path()).is_empty());
    }

    #[test]
    fn a_refused_commit_leaves_the_target_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("identity-vault.json");
        std::fs::write(&target, b"old").unwrap();
        let result = replace(&target, b"new", |_| Ok(()), || false);
        assert!(matches!(result, Err(WriteError::Abandoned)));
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
        assert!(temp_files(dir.path()).is_empty());
        assert_eq!(remove(&target, || false).unwrap(), None);
        assert!(target.exists());
    }

    #[test]
    fn remove_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("identity-vault.json");
        std::fs::write(&target, b"x").unwrap();
        assert_eq!(remove(&target, || true).unwrap(), Some(Done::Durable));
        assert!(!target.exists());
        assert_eq!(remove(&target, || true).unwrap(), Some(Done::Durable));
    }

    #[test]
    fn leftover_temps_are_removed_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("identity-vault.json");
        std::fs::write(&target, b"vault").unwrap();
        // What a write killed before its rename leaves.
        let (left, file) = create_temp(dir.path(), &target).unwrap();
        drop(file);
        std::fs::write(&left, b"an encrypted copy").unwrap();
        std::fs::write(dir.path().join(".identity-vault.json.1.2.tmp"), b"x").unwrap();
        // Not ours: another target's, other shapes, a directory.
        let keep = [
            ".node-identity-journal.json.1.0.tmp",
            ".identity-vault.json.1.tmp",
            ".identity-vault.json.a.0.tmp",
            ".identity-vault.json.1.0.tmp.bak",
            "identity-vault.json.1.0.tmp",
            ".identity-vault.json..0.tmp",
        ];
        for name in keep {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        std::fs::create_dir(dir.path().join(".identity-vault.json.3.0.tmp")).unwrap();
        assert_eq!(remove_temps(dir.path(), "identity-vault.json").unwrap(), 2);
        assert!(!left.exists());
        assert_eq!(std::fs::read(&target).unwrap(), b"vault");
        for name in keep {
            assert!(dir.path().join(name).exists(), "{name}");
        }
        assert!(dir.path().join(".identity-vault.json.3.0.tmp").is_dir());
        assert_eq!(remove_temps(dir.path(), "identity-vault.json").unwrap(), 0);
        assert_eq!(
            remove_temps(&dir.path().join("missing"), "identity-vault.json").unwrap(),
            0
        );
    }

    #[test]
    fn reads_only_regular_files_and_at_most_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"12345").unwrap();
        let read = |follow| match open_regular(&file, follow).unwrap() {
            Regular::File(f) => read_at_most(f, 5).unwrap(),
            other => panic!("{other:?}"),
        };
        assert_eq!(read(false).as_deref(), Some(&b"12345"[..]));
        assert_eq!(read(true).as_deref(), Some(&b"12345"[..]));
        // One byte over the bound: refused, however it got there.
        let Regular::File(f) = open_regular(&file, false).unwrap() else {
            panic!("not a file");
        };
        assert_eq!(read_at_most(f, 4).unwrap(), None);
        assert!(matches!(
            open_regular(&dir.path().join("missing"), false).unwrap(),
            Regular::Missing
        ));
        assert!(matches!(
            open_regular(dir.path(), false).unwrap(),
            Regular::Other
        ));
    }

    /// #83: a FIFO (or a symlink) where a file should be is refused at
    /// once. A blocking open of a FIFO with no writer would wait forever.
    #[cfg(unix)]
    #[test]
    fn a_fifo_or_a_symlink_is_refused_without_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("identity-vault.json");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let (done, finished) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let _ = done.send(matches!(open_regular(&path, false), Ok(Regular::Other)));
        });
        assert!(
            finished
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("open_regular blocked on a FIFO"),
        );
        // Followed or not, a FIFO is no regular file.
        assert!(matches!(open_regular(&fifo, true).unwrap(), Regular::Other));

        let target = dir.path().join("target");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            open_regular(&link, false).unwrap(),
            Regular::Other
        ));
        // Followed (Radicle's config, as JS reads it): the file it names.
        assert!(matches!(
            open_regular(&link, true).unwrap(),
            Regular::File(_)
        ));
        // Judged on the handle: once a regular file is open, whatever is
        // put at its path (here a FIFO) no longer matters.
        let vault = dir.path().join("vault");
        std::fs::write(&vault, b"contents").unwrap();
        let Regular::File(handle) = open_regular(&vault, false).unwrap() else {
            panic!("not a file");
        };
        std::fs::remove_file(&vault).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(&vault)
            .status()
            .unwrap();
        assert!(made.success());
        assert_eq!(
            read_at_most(handle, 100).unwrap().as_deref(),
            Some(&b"contents"[..])
        );

        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("nothing"), &dangling).unwrap();
        assert!(matches!(
            open_regular(&dangling, false).unwrap(),
            Regular::Other
        ));
        assert!(matches!(
            open_regular(&dangling, true).unwrap(),
            Regular::Missing
        ));
    }

    #[cfg(unix)]
    #[test]
    fn tighten_changes_mode_not_content() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("identity-vault.json");
        std::fs::write(&file, b"content").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(tighten(&file).unwrap());
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"content");
        assert!(!tighten(&file).unwrap(), "already 0600");

        // A symlink is left alone, and so is its target.
        let other = dir.path().join("other");
        std::fs::write(&other, b"x").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&other, &link).unwrap();
        assert!(!tighten(&link).unwrap());
        assert_eq!(
            std::fs::metadata(&other).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(!tighten(&dir.path().join("missing")).unwrap());
    }
}
