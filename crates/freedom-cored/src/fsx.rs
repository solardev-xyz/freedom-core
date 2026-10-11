//! Durable file operations (design 0001, "Writes and durability").
//!
//! **Replacing a file:**
//! 1. Create a temp file in the same directory with an exclusive create. On
//!    Unix its mode is `0600` from creation.
//! 2. Write it, then `fsync` it.
//! 3. Run the caller's check against the temp file (for the vault: decrypt it
//!    and compare the mnemonic). If the check fails, the temp file is
//!    removed and the target is untouched.
//! 4. Rename it over the target.
//! 5. On Unix, `fsync` the directory.
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

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Why a write failed. `Check` means the staged file didn't verify; the
/// target is untouched in that case.
#[derive(Debug)]
pub enum WriteError {
    Io(std::io::Error),
    Check(String),
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
/// accepts the staged file.
pub fn replace(
    target: &Path,
    contents: &[u8],
    check: impl FnOnce(&Path) -> Result<(), String>,
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
        std::fs::rename(&temp_path, target)?;
        Ok(())
    })();
    if let Err(error) = staged {
        let _ = std::fs::remove_file(&temp_path);
        return Err(error);
    }
    Ok(flushed(sync_dir(dir)))
}

/// Removes `target` durably: unlink, then `fsync` the directory. A missing
/// file is not an error.
pub fn remove(target: &Path) -> std::io::Result<Done> {
    match std::fs::remove_file(target) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Done::Durable),
        Err(e) => return Err(e),
    }
    Ok(match target.parent() {
        Some(dir) => flushed(sync_dir(dir)),
        None => Done::Durable,
    })
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
        let done = replace(&target, b"new", |staged| {
            assert_eq!(std::fs::read(staged).unwrap(), b"new");
            Ok(())
        })
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
        let result = replace(&target, b"broken", |_| Err("does not decrypt".into()));
        assert!(matches!(result, Err(WriteError::Check(_))));
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
        assert!(temp_files(dir.path()).is_empty());
    }

    #[test]
    fn remove_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("identity-vault.json");
        std::fs::write(&target, b"x").unwrap();
        assert_eq!(remove(&target).unwrap(), Done::Durable);
        assert!(!target.exists());
        assert_eq!(remove(&target).unwrap(), Done::Durable);
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
