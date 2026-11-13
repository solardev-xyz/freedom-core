//! The catalog's files on disk (design 0013, 5.1, "Writes"): fc-profile's
//! [`Store`] over 0001's rules.
//!
//! - **Below the app root,** every path is reached from the app root's
//!   handle, opened once per run, through no symlink below it
//!   ([`crate::anchor::Dir`]; review of #336): `Profiles`, a profile's
//!   directory and every directory on the way are opened without following
//!   a symlink (or, on Windows, a junction), and on Unix each file's final
//!   operation is relative to its directory's handle (`openat`,
//!   `renameat`). A symlink on the way is refused ([`SYMLINK`]), so a
//!   symlinked `Profiles` or `Profiles/<id>` can't take a read or a write
//!   to another directory. Windows has no handle-relative calls: each
//!   directory is checked to be no reparse point, then used by path (the
//!   anchor module's limit there). The app root itself is main's argument,
//!   and may be a symlink.
//! - **Elsewhere** (a default profile directory or a `--user-data-dir` main
//!   names outside the app root), by path, as main names it.
//! - **Reads:** a regular file the user owns, never through a symlink at
//!   the file's own name, and at most [`MAX_FILE`] bytes.
//! - **Writes:** 0001's durable atomic write (temp file, fsync, rename,
//!   directory flushed), mode `0600`, committed only while the catalog's
//!   write lock is still this process's. The temp file is
//!   `<name>.<pid>.<n>.tmp`, so the catalog's keep `profile-registry.json.`
//!   as their prefix, which every build's delete of the packaged default
//!   profile spares.
//! - **Directories** are made `0700`, and only while the catalog's write
//!   lock is still this process's: a run that lost it makes none (review of
//!   #336).

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::path::{Component, Path, PathBuf};

use fc_profile::{Store, StoreError, Style};

use crate::anchor::{Dir, Kind, Resolve};
use crate::fsx::{self, Regular, WriteError};

/// The largest catalog or `profile.json` read: far past any real one.
pub const MAX_FILE: u64 = 4 << 20;

/// A store error's message when the catalog's write lock was lost before a
/// change: nothing was changed.
pub const LOCK_LOST: &str = "lock_lost";

/// A store error's message when a symlink (on Windows, a junction or
/// another reparse point), or another file that isn't a directory, stands
/// where a directory below the app root should be: nothing was read or
/// changed through it.
pub const SYMLINK: &str = "symlink";

pub struct DiskStore<'a> {
    /// Whether a write may still commit: the catalog lock isn't lost.
    commit: &'a dyn Fn() -> bool,
    /// The app root, resolved (`path.resolve`).
    root_path: PathBuf,
    /// The app root's handle; `None` when nothing is there yet (a read-only
    /// run before any write).
    root: Option<Dir>,
}

impl<'a> DiskStore<'a> {
    /// The store of a run on `app_root`, whose handle is opened now.
    pub fn open(app_root: &str, commit: &'a dyn Fn() -> bool) -> std::io::Result<DiskStore<'a>> {
        let root_path = PathBuf::from(resolved(app_root));
        let root = Dir::open_root(&root_path, Resolve::Follow)?;
        Ok(DiskStore {
            commit,
            root_path,
            root,
        })
    }
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

/// `path.resolve(path)`, natively.
fn resolved(path: &str) -> String {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| PathBuf::from(path));
    Style::native().normalize(&absolute.to_string_lossy())
}

/// The names from `root` down to `path`, both resolved (none: `path` is
/// `root`); `None` when `path` isn't at or below `root`. Windows compares
/// names without regard to ASCII case, as its filesystems do.
fn below(root: &Path, path: &Path) -> Option<Vec<OsString>> {
    let mut parts = path.components();
    for want in root.components() {
        let got = parts.next()?;
        let same = if cfg!(windows) {
            want.as_os_str().eq_ignore_ascii_case(got.as_os_str())
        } else {
            want == got
        };
        if !same {
            return None;
        }
    }
    parts
        .map(|part| match part {
            Component::Normal(name) => Some(name.to_owned()),
            _ => None,
        })
        .collect()
}

/// Where a path lies.
enum Place {
    /// Below the app root: the names from it down.
    Under(Vec<OsString>),
    /// Elsewhere: used by its path.
    Outside(PathBuf),
}

/// What a walk down from the app root found.
enum Walked {
    Dir(Dir),
    Missing,
    /// A regular file where a directory should be: nothing is below it.
    File,
}

/// Unix: the file must be the user's own.
#[cfg(unix)]
fn owned(path: &str, file: &File) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().map_err(|e| io(path, &e))?;
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(error(path, "a file that isn't the user's own"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn owned(_path: &str, _file: &File) -> Result<(), StoreError> {
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

impl DiskStore<'_> {
    fn place(&self, path: &str) -> Place {
        match below(&self.root_path, Path::new(&resolved(path))) {
            Some(names) => Place::Under(names),
            None => Place::Outside(PathBuf::from(path)),
        }
    }

    /// Walks `names` down from the app root, each directory opened through
    /// its parent's handle without following a symlink. With `create`, a
    /// missing one is made, if the lock is still held.
    fn walk(&self, names: &[OsString], path: &str, create: bool) -> Result<Walked, StoreError> {
        let Some(root) = &self.root else {
            // Only a read-only run has no app root: nothing is below it.
            return if create {
                Err(error(path, "no app root"))
            } else {
                Ok(Walked::Missing)
            };
        };
        let mut dir = root.try_clone().map_err(|e| io(path, &e))?;
        for name in names {
            match dir.kind(name).map_err(|e| io(path, &e))? {
                Kind::Dir => {}
                Kind::Missing if create => {
                    if !(self.commit)() {
                        return Err(error(path, LOCK_LOST));
                    }
                }
                Kind::Missing => return Ok(Walked::Missing),
                Kind::File => return Ok(Walked::File),
                Kind::Other => return Err(error(path, SYMLINK)),
            }
            dir = match dir.child(name, create) {
                Ok(Some(child)) => child,
                Ok(None) => return Ok(Walked::Missing),
                // Swapped since it was looked at: a symlink now is refused
                // as one.
                Err(e) => {
                    return Err(match dir.kind(name) {
                        Ok(Kind::Other) => error(path, SYMLINK),
                        _ => io(path, &e),
                    });
                }
            };
        }
        Ok(Walked::Dir(dir))
    }

    /// Makes `dir`, outside the app root, if it isn't a directory, and only
    /// while the lock is held.
    fn make_outside(&self, dir: &Path, path: &str) -> Result<(), StoreError> {
        if std::fs::metadata(dir).is_ok_and(|m| m.is_dir()) {
            return Ok(());
        }
        if !(self.commit)() {
            return Err(error(path, LOCK_LOST));
        }
        make_dirs(dir).map_err(|e| io(path, &e))
    }
}

impl Store for DiskStore<'_> {
    fn read(&mut self, path: &str) -> Result<Option<String>, StoreError> {
        let opened = match self.place(path) {
            Place::Outside(target) => match fsx::open_regular(&target, false) {
                // A missing directory on the way: nothing is there.
                Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => return Ok(None),
                opened => opened.map_err(|e| io(path, &e))?,
            },
            Place::Under(names) => {
                let Some((name, parents)) = names.split_last() else {
                    return Err(error(path, "not a regular file"));
                };
                match self.walk(parents, path, false)? {
                    Walked::Dir(dir) => dir.open_regular(name, false).map_err(|e| io(path, &e))?,
                    Walked::Missing | Walked::File => return Ok(None),
                }
            }
        };
        let file = match opened {
            Regular::Missing => return Ok(None),
            Regular::Other => return Err(error(path, "not a regular file")),
            Regular::File(file) => file,
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
        match self.place(path) {
            Place::Outside(target) => Ok(std::fs::metadata(target).is_ok_and(|m| m.is_dir())),
            Place::Under(names) => Ok(matches!(self.walk(&names, path, false)?, Walked::Dir(_))),
        }
    }

    fn list_dirs(&mut self, path: &str) -> Result<Vec<String>, StoreError> {
        let found = match self.place(path) {
            Place::Outside(target) => {
                let entries = match std::fs::read_dir(target) {
                    Ok(entries) => entries,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                    Err(e) => return Err(io(path, &e)),
                };
                let mut found = Vec::new();
                for entry in entries {
                    let entry = entry.map_err(|e| io(path, &e))?;
                    if entry.file_type().map_err(|e| io(path, &e))?.is_dir() {
                        found.push(entry.file_name());
                    }
                }
                found
            }
            Place::Under(names) => match self.walk(&names, path, false)? {
                Walked::Dir(dir) => dir.subdirs().map_err(|e| io(path, &e))?,
                Walked::Missing => return Ok(Vec::new()),
                Walked::File => return Err(error(path, "not a directory")),
            },
        };
        // A name that isn't Unicode is no profile id.
        let mut names: Vec<String> = found
            .into_iter()
            .filter_map(|name| name.into_string().ok())
            .collect();
        // libuv's scandir order, which Node's readdirSync gives.
        names.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        Ok(names)
    }

    fn ensure_dir(&mut self, path: &str) -> Result<(), StoreError> {
        match self.place(path) {
            Place::Outside(target) => self.make_outside(&target, path),
            Place::Under(names) => match self.walk(&names, path, true)? {
                Walked::Dir(_) => Ok(()),
                Walked::Missing | Walked::File => Err(error(path, "not a directory")),
            },
        }
    }

    fn write(&mut self, path: &str, text: &str) -> Result<(), StoreError> {
        let written = match self.place(path) {
            Place::Outside(target) => {
                if let Some(dir) = target.parent() {
                    self.make_outside(dir, path)?;
                }
                let stem = target
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| error(path, "no file name"))?
                    .to_owned();
                let commit = self.commit;
                fsx::replace_as(&target, &stem, text.as_bytes(), |_| Ok(()), commit).map(|_| ())
            }
            Place::Under(names) => {
                let Some((name, parents)) = names.split_last() else {
                    return Err(error(path, "no file name"));
                };
                let Walked::Dir(dir) = self.walk(parents, path, true)? else {
                    return Err(error(path, "not a directory"));
                };
                replace_in(&dir, name, text.as_bytes(), self.commit).map(|_| ())
            }
        };
        match written {
            Ok(()) => Ok(()),
            Err(WriteError::Io(e)) => Err(io(path, &e)),
            Err(WriteError::Check(reason)) => Err(error(path, reason)),
            Err(WriteError::Abandoned) => Err(error(path, LOCK_LOST)),
        }
    }

    fn resolve(&self, path: &str) -> String {
        resolved(path)
    }
}

/// [`fsx::replace_as`] from a directory's handle: the temp file
/// `<name>.<pid>.<n>.tmp` (`0600`) made in `dir`, written and flushed; the
/// rename over `name` made only if `commit` allows it and the temp file is
/// still the one written; then `dir` flushed. A failed flush after the
/// rename leaves the change made and is reported as `replace_as` reports it:
/// logged, and [`fsx::Done::NotDurable`].
fn replace_in(
    dir: &Dir,
    name: &OsStr,
    contents: &[u8],
    commit: &dyn Fn() -> bool,
) -> Result<fsx::Done, WriteError> {
    use std::io::Write as _;
    let (temp_name, mut temp) = create_temp_in(dir, name)?;
    let staged = (|| -> Result<(), WriteError> {
        temp.write_all(contents)?;
        temp.sync_all()?;
        if !commit() {
            return Err(WriteError::Abandoned);
        }
        if !dir.same_file(&temp, &temp_name)? {
            return Err(WriteError::Io(std::io::Error::other(
                "the temp file was replaced before its rename",
            )));
        }
        drop(temp);
        dir.rename(&temp_name, name)?;
        Ok(())
    })();
    if let Err(error) = staged {
        let _ = dir.unlink(&temp_name);
        return Err(error);
    }
    #[cfg(unix)]
    let synced = dir.sync();
    #[cfg(not(unix))]
    let synced = fsx::sync_rename(dir.location(), &dir.path(name));
    Ok(fsx::flushed(synced))
}

/// Creates `<name>.<pid>.<n>.tmp` exclusively in `dir`.
fn create_temp_in(dir: &Dir, name: &OsStr) -> std::io::Result<(OsString, File)> {
    for attempt in 0u32..100 {
        let mut temp = name.to_owned();
        temp.push(format!(".{}.{attempt}.tmp", std::process::id()));
        match dir.create_new(&temp) {
            Ok(file) => return Ok((temp, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("no free temp file name"))
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
    fn paths_below_the_app_root() {
        let root = Path::new(if cfg!(windows) { r"C:\app" } else { "/app" });
        let names = |rest: &[&str]| -> Option<Vec<OsString>> {
            Some(rest.iter().map(OsString::from).collect())
        };
        assert_eq!(below(root, root), names(&[]));
        assert_eq!(
            below(root, &root.join("Profiles").join("a")),
            names(&["Profiles", "a"])
        );
        assert_eq!(
            below(root, &root.join("profile-registry.json")),
            names(&["profile-registry.json"])
        );
        let sibling = if cfg!(windows) {
            r"C:\application"
        } else {
            "/application"
        };
        assert_eq!(below(root, Path::new(sibling)), None);
        assert_eq!(below(&root.join("Profiles"), root), None);
        if cfg!(windows) {
            assert_eq!(
                below(root, Path::new(r"c:\APP\Profiles")),
                names(&["Profiles"])
            );
        }
    }

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
