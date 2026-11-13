//! The catalog's files on disk (design 0013, 5.1, "Writes"): fc-profile's
//! [`Store`] over 0001's rules.
//!
//! - **Reads:** a regular file the user owns, never through a symlink at
//!   the file's own name, and at most [`MAX_FILE`] bytes.
//! - **Writes:** 0001's durable atomic write (temp file, fsync, rename,
//!   directory flushed), mode `0600`, committed only while the catalog's
//!   write lock is still this process's. The temp file is
//!   `<name>.<pid>.<n>.tmp`, so the catalog's keep `profile-registry.json.`
//!   as their prefix, which every build's delete of the packaged default
//!   profile spares.
//! - **Directories** are made `0700`.

use std::path::{Path, PathBuf};

use fc_profile::{Store, StoreError, Style};

use crate::fsx;

/// The largest catalog or `profile.json` read: far past any real one.
pub const MAX_FILE: u64 = 4 << 20;

pub struct DiskStore<'a> {
    /// Whether a write may still commit: the catalog lock isn't lost.
    pub commit: &'a dyn Fn() -> bool,
}

fn error(path: &str, message: impl Into<String>) -> StoreError {
    StoreError {
        path: path.to_owned(),
        message: message.into(),
    }
}

fn io(path: &str, e: &std::io::Error) -> StoreError {
    error(path, e.kind().to_string())
}

/// Unix: the file must be the user's own.
#[cfg(unix)]
fn owned(path: &str, file: &std::fs::File) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().map_err(|e| io(path, &e))?;
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(error(path, "a file that isn't the user's own"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn owned(_path: &str, _file: &std::fs::File) -> Result<(), StoreError> {
    Ok(())
}

/// Makes `dir` and its missing parents, `0700` on Unix.
pub fn make_dirs(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

impl Store for DiskStore<'_> {
    fn read(&mut self, path: &str) -> Result<Option<String>, StoreError> {
        let file = match fsx::open_regular(Path::new(path), false) {
            Ok(fsx::Regular::Missing) => return Ok(None),
            Ok(fsx::Regular::Other) => return Err(error(path, "not a regular file")),
            Ok(fsx::Regular::File(file)) => file,
            // A missing directory on the way: nothing is there.
            Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => return Ok(None),
            Err(e) => return Err(io(path, &e)),
        };
        owned(path, &file)?;
        let bytes = fsx::read_at_most(&file, MAX_FILE)
            .map_err(|e| io(path, &e))?
            .ok_or_else(|| error(path, "past its size bound"))?;
        // As Node's `readFileSync(path, 'utf-8')`: each invalid sequence
        // is U+FFFD.
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    fn is_dir(&mut self, path: &str) -> Result<bool, StoreError> {
        Ok(std::fs::metadata(path).is_ok_and(|m| m.is_dir()))
    }

    fn list_dirs(&mut self, path: &str) -> Result<Vec<String>, StoreError> {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io(path, &e)),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| io(path, &e))?;
            if !entry.file_type().map_err(|e| io(path, &e))?.is_dir() {
                continue;
            }
            // A name that isn't Unicode is no profile id.
            if let Ok(name) = entry.file_name().into_string() {
                names.push(name);
            }
        }
        // libuv's scandir order, which Node's readdirSync gives.
        names.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        Ok(names)
    }

    fn ensure_dir(&mut self, path: &str) -> Result<(), StoreError> {
        make_dirs(Path::new(path)).map_err(|e| io(path, &e))
    }

    fn write(&mut self, path: &str, text: &str) -> Result<(), StoreError> {
        let target = PathBuf::from(path);
        if let Some(dir) = target.parent() {
            make_dirs(dir).map_err(|e| io(path, &e))?;
        }
        let stem = target
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| error(path, "no file name"))?
            .to_owned();
        let commit = self.commit;
        match fsx::replace_as(&target, &stem, text.as_bytes(), |_| Ok(()), commit) {
            Ok(_) => Ok(()),
            Err(fsx::WriteError::Io(e)) => Err(io(path, &e)),
            Err(fsx::WriteError::Check(reason)) => Err(error(path, reason)),
            Err(fsx::WriteError::Abandoned) => Err(error(path, "lock_lost")),
        }
    }

    fn resolve(&self, path: &str) -> String {
        let absolute = std::path::absolute(path).unwrap_or_else(|_| PathBuf::from(path));
        Style::native().normalize(&absolute.to_string_lossy())
    }
}

/// Removes the catalog's temp files a writer killed before its rename left
/// at the app root: the core's `profile-registry.json.<pid>.<n>.tmp` and an
/// older build's `profile-registry.json.<pid>.tmp`. Run under the catalog's
/// write lock, which every writer of the catalog holds while its temp file
/// exists, so each one found is a leftover.
pub fn remove_catalog_temps(app_root: &Path) -> std::io::Result<()> {
    let entries = match std::fs::read_dir(app_root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if is_catalog_temp(&name) && entry.file_type()?.is_file() {
            match std::fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

/// `profile-registry.json.<digits>[.<digits>].tmp`, exactly.
fn is_catalog_temp(name: &str) -> bool {
    let Some(middle) = name
        .strip_prefix("profile-registry.json.")
        .and_then(|rest| rest.strip_suffix(".tmp"))
    else {
        return false;
    };
    let parts: Vec<&str> = middle.split('.').collect();
    (1..=2).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_temps_are_exactly_the_writers() {
        assert!(is_catalog_temp("profile-registry.json.123.tmp"));
        assert!(is_catalog_temp("profile-registry.json.123.0.tmp"));
        assert!(!is_catalog_temp("profile-registry.json.forget"));
        assert!(!is_catalog_temp("profile-registry.json.1.2.3.tmp"));
        assert!(!is_catalog_temp("profile-registry.json..tmp"));
        assert!(!is_catalog_temp("profile-registry.json.x.tmp"));
    }
}
