//! A profile's removal under its gates, as the reference's `deleteProfile`
//! does it (`profile-catalog.js`: `gatedPlace`, `radicleHomeFence`,
//! `fenceAndCommit`, `removeSparing`, `removeDefaultProfileDataFromAppRoot`,
//! `removeEmptyRemade` and the Radicle staging siblings; design 0013,
//! "Deletion").
//!
//! What differs: the gates are this process's own, held for the whole run,
//! so none is lost meanwhile and the reference's lost-gate checks and
//! reports have nothing to report. And every change (a fence's rename, each
//! removal, each `rmdir`) is made only while the catalog's write lock is
//! still this process's: a lost lock stops the delete there
//! ([`Failure::LockLost`]). A fence put back after a failed step is the one
//! change made without it, since it undoes one.
//!
//! Links: the layout must be the app's own, as `gatedPlace` requires, and,
//! beyond the reference, every step from the app root down to the profile's
//! directory must be a directory too ([`refuse_links_below`]), so the
//! removal can't be carried through a link out of the app's tree.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A directory's identity: on Unix its device and inode; on Windows its
/// volume's serial number and file ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    volume: u64,
    file: u128,
}

/// Why a delete stopped.
#[derive(Debug)]
pub enum Failure {
    /// The reference's refusal, with its message (exit 65). Before the
    /// catalog changes, nothing has.
    Refused(String),
    /// The catalog's write lock was lost: nothing more was changed.
    LockLost,
    Io(std::io::Error),
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Failure::Io(error)
    }
}

/// What is at a path, not following a link there.
struct Entry {
    /// A directory, not a link or another reparse point.
    dir: bool,
    /// A directory's identity.
    id: Option<Identity>,
}

#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
#[cfg(windows)]
const FILE_READ_ATTRIBUTES: u32 = 0x0080;

/// A directory, not a link (nor, on Windows, a junction or another reparse
/// point), from `symlink_metadata`.
fn is_real_dir(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return false;
        }
    }
    metadata.is_dir() && !metadata.file_type().is_symlink()
}

#[cfg(unix)]
fn identity_of(
    _path: &Path,
    metadata: &std::fs::Metadata,
    _follow: bool,
) -> std::io::Result<Identity> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(Identity {
        volume: metadata.dev(),
        file: u128::from(metadata.ino()),
    })
}

#[cfg(windows)]
fn identity_of(
    path: &Path,
    _metadata: &std::fs::Metadata,
    follow: bool,
) -> std::io::Result<Identity> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsHandle as _;
    let flags = if follow {
        FILE_FLAG_BACKUP_SEMANTICS
    } else {
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    };
    let handle = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(flags)
        .open(path)?;
    let (volume, file) = fc_sys::windows::file_id(handle.as_handle())
        .or_else(|_| fc_sys::windows::file_index(handle.as_handle()))?;
    Ok(Identity { volume, file })
}

#[cfg(not(any(unix, windows)))]
fn identity_of(
    _path: &Path,
    _metadata: &std::fs::Metadata,
    _follow: bool,
) -> std::io::Result<Identity> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no file identity on this OS",
    ))
}

/// `lstatIfThere`: what is at `path`, without following a link there, or
/// `None` if nothing is.
fn lstat_if_there(path: &Path) -> std::io::Result<Option<Entry>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let dir = is_real_dir(&metadata);
    let id = if dir {
        Some(identity_of(path, &metadata, false)?)
    } else {
        None
    };
    Ok(Some(Entry { dir, id }))
}

/// `identitiesUp(target)`: the identities of `target` and of every
/// directory above it, following links; missing ones skipped.
fn identities_up(target: &Path) -> std::io::Result<Vec<Identity>> {
    let mut ids = Vec::new();
    let mut current = Some(target);
    while let Some(dir) = current {
        match std::fs::metadata(dir) {
            Ok(metadata) => ids.push(identity_of(dir, &metadata, true)?),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) => {}
            Err(e) => return Err(e),
        }
        current = dir.parent();
    }
    Ok(ids)
}

/// `layoutRefused(what, detail)`.
fn layout_refused(what: &str, detail: &str) -> Failure {
    Failure::Refused(format!(
        "The profile's {what} {detail}, so it can't be deleted safely while its lock is held. \
         Nothing was deleted: replace the link with the directory itself, or remove it, and \
         delete the profile again."
    ))
}

/// `radicleLayoutRefused(link)`.
fn radicle_layout_refused(link: &Path) -> Failure {
    Failure::Refused(format!(
        "The profile's Radicle data is reached through a link ({}), so the profile can't be \
         deleted safely while its locks are held. Nothing was deleted: replace the link with \
         the directory itself, or remove it, and delete the profile again.",
        link.display()
    ))
}

/// The profile's directory reached through a link below the app root (not
/// in the reference, whose removal would follow it).
fn data_layout_refused(link: &Path) -> Failure {
    Failure::Refused(format!(
        "The profile's data is reached through a link ({}), so the profile can't be deleted \
         safely. Nothing was deleted: replace the link with the directory itself, or remove \
         it, and delete the profile again.",
        link.display()
    ))
}

/// The names from `base` down to `target`, which is below it.
fn names_below<'a>(base: &Path, target: &'a Path) -> Option<Vec<&'a OsStr>> {
    let rest = target.strip_prefix(base).ok()?;
    rest.components()
        .map(|component| match component {
            std::path::Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect()
}

/// `refuseLinksBelow(base, target)`: every step below `base` down to
/// `target`, as far as it exists, a real directory. `refused` makes the
/// refusal for the step found.
fn steps_are_dirs(
    base: &Path,
    target: &Path,
    refused: fn(&Path) -> Failure,
) -> Result<(), Failure> {
    let Some(names) = names_below(base, target) else {
        return Err(refused(target));
    };
    let mut current = base.to_path_buf();
    for name in names {
        current.push(name);
        match lstat_if_there(&current)? {
            None => return Ok(()),
            Some(entry) if !entry.dir => return Err(refused(&current)),
            Some(_) => {}
        }
    }
    Ok(())
}

/// The Radicle home's path (`base`, its app-owned directory, down to the
/// home) free of links, as `refuseLinksBelow` requires.
pub fn refuse_radicle_links(base: &Path, home: &Path) -> Result<(), Failure> {
    steps_are_dirs(base, home, radicle_layout_refused)
}

/// Every step from the app root down to the profile's data root a real
/// directory, as far as it exists.
pub fn refuse_links_below(app_root: &Path, data_root: &Path) -> Result<(), Failure> {
    if app_root == data_root {
        return Ok(());
    }
    steps_are_dirs(app_root, data_root, data_layout_refused)
}

/// One directory on the way from the data root to a gated one.
#[derive(Debug)]
struct Node {
    name: Option<OsString>,
    id: Option<Identity>,
    parent: Option<usize>,
    gated: bool,
}

/// A gated directory, by its canonical path.
#[derive(Debug)]
pub struct Fence {
    pub dir: PathBuf,
    pub what: &'static str,
    id: Option<Identity>,
}

/// `gatedPlace`'s result: the data root's canonical path, the directories
/// on the way to each gated one, and the gated ones.
#[derive(Debug)]
pub struct Place {
    pub root: PathBuf,
    nodes: Vec<Node>,
    pub fences: Vec<Fence>,
}

/// A gated directory to check: its path below the data root, and what it
/// holds (`identity data`, `IPFS data`).
pub struct Gated<'a> {
    pub dir: &'a Path,
    pub what: &'static str,
}

/// `gatedPlace(dataRoot, gatedDirs, { otherRoots, radicle })`: where the
/// gated directories are, or the reference's refusal, before anything
/// changes. `None` when the data root isn't there.
pub fn gated_place(
    data_root: &Path,
    gated: &[Gated<'_>],
    other_roots: &[PathBuf],
    radicle: Option<(&Path, &Path)>,
) -> Result<Option<Place>, Failure> {
    let Some(first) = gated.first() else {
        return Ok(None);
    };
    let Some(root_entry) = lstat_if_there(data_root)? else {
        return Ok(None);
    };
    if !root_entry.dir {
        return Err(layout_refused(
            first.what,
            &format!("is reached through a link ({})", data_root.display()),
        ));
    }
    let root = std::fs::canonicalize(data_root)?;
    let mut nodes = vec![Node {
        name: None,
        id: root_entry.id,
        parent: None,
        gated: false,
    }];
    let mut fences = Vec::new();
    for Gated { dir, what } in gated {
        let Some(names) = names_below(data_root, dir) else {
            return Err(layout_refused(
                what,
                &format!("is reached under another name ({})", dir.display()),
            ));
        };
        let mut current = data_root.to_path_buf();
        let mut parent = 0;
        let mut entry = None;
        for (i, name) in names.iter().enumerate() {
            current.push(name);
            entry = lstat_if_there(&current)?;
            if entry.as_ref().is_some_and(|e| !e.dir) {
                return Err(layout_refused(
                    what,
                    &format!("is reached through a link ({})", current.display()),
                ));
            }
            let found = nodes.iter().position(|node| {
                node.parent == Some(parent) && node.name.as_deref() == Some(*name)
            });
            parent = match found {
                Some(index) => index,
                None => {
                    nodes.push(Node {
                        name: Some((*name).to_owned()),
                        id: entry.as_ref().and_then(|e| e.id),
                        parent: Some(parent),
                        gated: i + 1 == names.len(),
                    });
                    nodes.len() - 1
                }
            };
        }
        let mut gated_path = root.clone();
        for name in &names {
            gated_path.push(name);
        }
        if entry.is_some() && std::fs::canonicalize(dir)? != gated_path {
            return Err(layout_refused(
                what,
                &format!("is reached under another name ({})", dir.display()),
            ));
        }
        fences.push(Fence {
            dir: gated_path,
            what,
            id: entry.and_then(|e| e.id),
        });
    }
    if let Some((base, home)) = radicle {
        refuse_radicle_links(base, home)?;
    }
    for fence in &fences {
        let around = identities_up(&fence.dir)?;
        for other in other_roots {
            // Not there; or a link, which is removed as a link, its target
            // untouched.
            let Some(Entry { dir: true, id }) = lstat_if_there(other)? else {
                continue;
            };
            let within = match fence.id {
                Some(fence_id) => {
                    identities_up(&std::fs::canonicalize(other)?)?.contains(&fence_id)
                }
                None => false,
            };
            if id.is_some_and(|id| around.contains(&id)) || within {
                return Err(layout_refused(
                    fence.what,
                    &format!(
                        "overlaps other data this delete removes ({})",
                        other.display()
                    ),
                ));
            }
        }
    }
    Ok(Some(Place {
        root,
        nodes,
        fences,
    }))
}

/// Windows refuses a rename while a scanner or indexer has a file open;
/// those clear in a moment (`FENCE_RETRY_CODES`).
fn retryable(failure: &Failure) -> bool {
    let Failure::Io(e) = failure else {
        return false;
    };
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        return true;
    }
    match e.raw_os_error() {
        // EBUSY.
        #[cfg(unix)]
        Some(16) => true,
        // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION.
        #[cfg(windows)]
        Some(32 | 33) => true,
        _ => false,
    }
}

const FENCE_ATTEMPTS: u32 = 10;
const FENCE_RETRY: Duration = Duration::from_millis(100);

/// A gated directory the fence moved aside.
#[derive(Debug)]
pub struct Move {
    pub dir: PathBuf,
    pub tombstone: PathBuf,
    pub what: &'static str,
}

/// `tombstoneOf(dir)`: `.<name>.deleting-<pid>-<ms>` beside it, a name no
/// core or service opens.
fn tombstone_of(dir: &Path, now_ms: i64) -> PathBuf {
    let mut name = OsString::from(".");
    name.push(dir.file_name().unwrap_or_default());
    name.push(format!(".deleting-{}-{now_ms}", std::process::id()));
    dir.with_file_name(name)
}

/// `moveBack(moved, cause)`: what one attempt moved, put back last first.
/// One that can't be is named, with where it is.
fn move_back(moves: &[Move], moved: &[usize]) -> Result<(), Failure> {
    let mut stuck = Vec::new();
    for &index in moved.iter().rev() {
        let m = &moves[index];
        if std::fs::rename(&m.tombstone, &m.dir).is_err() {
            stuck.push(m);
        }
    }
    if stuck.is_empty() {
        return Ok(());
    }
    let where_ = stuck
        .iter()
        .map(|m| format!("its {} is at {}", m.what, m.tombstone.display()))
        .collect::<Vec<_>>()
        .join(", and ");
    Err(Failure::Refused(format!(
        "The profile couldn't be deleted, and not all of its data could be put back: {where_}. \
         Move it back to its name without the leading dot and the \".deleting-…\" suffix."
    )))
}

/// `fenceAndCommit(fences, gates, commit)`: each gated directory (`fences`,
/// in order: the identity directory, the IPFS directory, the Radicle home)
/// moved aside to its tombstone, then `commit`, the catalog's change. A
/// move or `commit` that fails has the moves before it put back; a
/// Windows refusal is waited out and the whole step tried again. Each move
/// only while `held` (the catalog's write lock still this process's).
pub fn fence_and_commit(
    fences: &[(&Path, &'static str)],
    now_ms: i64,
    held: &dyn Fn() -> bool,
    commit: &mut dyn FnMut() -> Result<(), Failure>,
) -> Result<Vec<Move>, Failure> {
    let moves: Vec<Move> = fences
        .iter()
        .map(|(dir, what)| Move {
            dir: dir.to_path_buf(),
            tombstone: tombstone_of(dir, now_ms),
            what,
        })
        .collect();
    let mut attempt = 1;
    loop {
        let mut moved = Vec::new();
        let mut result = Ok(());
        for (index, m) in moves.iter().enumerate() {
            if !held() {
                result = Err(Failure::LockLost);
                break;
            }
            match std::fs::rename(&m.dir, &m.tombstone) {
                Ok(()) => moved.push(index),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    result = Err(Failure::Io(e));
                    break;
                }
            }
        }
        if result.is_ok() {
            result = commit();
        }
        let Err(failure) = result else {
            return Ok(moves);
        };
        move_back(&moves, &moved)?;
        if !retryable(&failure) || attempt >= FENCE_ATTEMPTS {
            return Err(failure);
        }
        attempt += 1;
        std::thread::sleep(FENCE_RETRY);
    }
}

/// The removal's state: the lock it runs under, and its test hook.
pub struct Removal<'a> {
    pub held: &'a dyn Fn() -> bool,
    /// Whether anything has been removed yet (the `mid-removal` hook runs
    /// after the first).
    removed: bool,
}

impl<'a> Removal<'a> {
    pub fn new(held: &'a dyn Fn() -> bool) -> Removal<'a> {
        Removal {
            held,
            removed: false,
        }
    }

    fn check(&self) -> Result<(), Failure> {
        if (self.held)() {
            Ok(())
        } else {
            Err(Failure::LockLost)
        }
    }

    /// `fsOffload.removePath(target, { recursive: true, force: true })`:
    /// a directory and all below it, never through a link; a link or file
    /// itself; nothing if nothing is there.
    pub fn remove_path(&mut self, target: &Path) -> Result<(), Failure> {
        self.check()?;
        let metadata = match std::fs::symlink_metadata(target) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let removed = if is_real_dir(&metadata) {
            std::fs::remove_dir_all(target)
        } else {
            // On Windows a directory link or junction goes by remove_dir.
            std::fs::remove_file(target).or_else(|e| {
                if cfg!(windows) {
                    std::fs::remove_dir(target)
                } else {
                    Err(e)
                }
            })
        };
        match removed {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        if !self.removed {
            self.removed = true;
            crate::testhooks::profile_delete_step("mid-removal");
        }
        Ok(())
    }

    /// `rmdir`, only while the lock is held; `false` when it didn't go (not
    /// there, not empty, or any other failure), as the reference ignores
    /// those.
    fn rmdir(&self, dir: &Path) -> Result<bool, Failure> {
        self.check()?;
        Ok(std::fs::remove_dir(dir).is_ok())
    }

    /// `removeSparing(dir, place, index, { skip, keepRoot })`: removes
    /// `dir`, `place`'s directory `index` on the way to the gated
    /// directories, sparing them: it walks only into the directories on the
    /// way (by identity, under any name), never through a link, and removes
    /// everything else. A directory named as one of the next steps, but not
    /// that directory, is spared. Directories on the way go only if empty.
    pub fn remove_sparing(
        &mut self,
        dir: &Path,
        place: &Place,
        index: usize,
        skip: Option<&dyn Fn(&OsStr) -> bool>,
        keep_root: bool,
    ) -> Result<(), Failure> {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let mut names = Vec::new();
        for entry in entries {
            names.push(entry?.file_name());
        }
        for name in names {
            if skip.is_some_and(|skip| skip(&name)) {
                continue;
            }
            let target = dir.join(&name);
            let Some(entry) = lstat_if_there(&target)? else {
                continue;
            };
            let step = if entry.dir {
                step_of(place, entry.id)
            } else {
                None
            };
            let next_named = entry.dir
                && place.nodes.iter().any(|node| {
                    node.parent == Some(index)
                        && node
                            .name
                            .as_deref()
                            .is_some_and(|n| same_entry_name(&name, n))
                });
            match step {
                Some(step) if step > index => {
                    self.remove_sparing(&target, place, step, None, false)?
                }
                // A directory on the way met again (a mount that loops
                // back), or one named as a next step but not that
                // directory: spared.
                Some(_) => {}
                None if next_named => {}
                None => self.remove_path(&target)?,
            }
        }
        if keep_root {
            return Ok(());
        }
        self.rmdir(dir)?;
        Ok(())
    }

    /// `removeDefaultProfileDataFromAppRoot(appRoot, { place })`: every
    /// entry of the app root but the shared ones, the root itself kept.
    pub fn remove_default_from_app_root(
        &mut self,
        app_root: &Path,
        place: Option<&Place>,
    ) -> Result<(), Failure> {
        let shared = |name: &OsStr| {
            name.to_str()
                .is_some_and(fc_profile::delete::is_app_root_shared_entry)
        };
        if let Some(place) = place {
            return self.remove_sparing(app_root, place, 0, Some(&shared), true);
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(app_root)? {
            names.push(entry?.file_name());
        }
        for name in names {
            if !shared(&name) {
                self.remove_path(&app_root.join(name))?;
            }
        }
        Ok(())
    }

    /// `removeEmptyRemade(place, { keepRoot })`: each gated directory made
    /// again since the fence, empty, and each directory above it that this
    /// leaves empty, up to the data root (never the packaged app root).
    /// The gates are this process's, still held.
    pub fn remove_empty_remade(&self, place: &Place, keep_root: bool) -> Result<(), Failure> {
        for fence in &place.fences {
            let mut dir = fence.dir.clone();
            loop {
                if keep_root && dir == place.root {
                    break;
                }
                if !self.rmdir(&dir)? || dir == place.root {
                    break;
                }
                match dir.parent() {
                    Some(parent) => dir = parent.to_path_buf(),
                    None => break,
                }
            }
        }
        Ok(())
    }

    /// The Radicle home made again since its fence, if empty.
    pub fn remove_empty_home(&self, home: &Path) -> Result<(), Failure> {
        self.rmdir(home).map(|_| ())
    }
}

/// `stepOf(place, stat)`: which directory on the way to a gated one this
/// is, by identity; never a gated one.
fn step_of(place: &Place, id: Option<Identity>) -> Option<usize> {
    let id = id?;
    place
        .nodes
        .iter()
        .position(|node| !node.gated && node.id == Some(id))
}

/// `sameEntryName(entry, name)`: compared without case. The reference also
/// compares in NFC; for the names compared here (`identity`, `ipfs-data`,
/// `freedom-ipfs`), which hold no `k`, `;` or `` ` ``, the only ASCII
/// letters a canonical singleton reaches, NFC changes nothing.
fn same_entry_name(entry: &OsStr, name: &OsStr) -> bool {
    match (entry.to_str(), name.to_str()) {
        (Some(entry), Some(name)) => entry.to_lowercase() == name.to_lowercase(),
        _ => entry == name,
    }
}

/// The staging copies an interrupted legacy `radicle-data/` carry-over
/// left beside a Radicle home (`<slot>.migrating-<pid>-<ts>`), each inside
/// `root` (`radicleStagingSiblings`).
pub fn radicle_staging_siblings(home: &Path, root: &Path) -> Result<Vec<PathBuf>, Failure> {
    let Some(parent) = home.parent() else {
        return Ok(Vec::new());
    };
    let mut prefix = home.file_name().unwrap_or_default().to_owned();
    prefix.push(".migrating-");
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        if name
            .as_encoded_bytes()
            .starts_with(prefix.as_encoded_bytes())
        {
            let target = parent.join(&name);
            if target == root || !target.starts_with(root) {
                return Err(Failure::Refused(
                    "Refusing to delete Radicle data outside its root".into(),
                ));
            }
            out.push(target);
        }
    }
    Ok(out)
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn always() -> bool {
        true
    }

    /// The removal spares a gated directory under another name, and walks
    /// only the steps on the way.
    #[test]
    fn spares_the_gated_directories() {
        let root = tempfile::tempdir().unwrap();
        let data = std::fs::canonicalize(root.path()).unwrap().join("p");
        std::fs::create_dir_all(data.join("identity")).unwrap();
        std::fs::create_dir_all(data.join("ipfs-data/freedom-ipfs")).unwrap();
        std::fs::write(data.join("ipfs-data/other"), "x").unwrap();
        std::fs::write(data.join("Cookies"), "x").unwrap();
        std::fs::write(data.join("identity/vault.json"), "x").unwrap();
        let identity = data.join("identity");
        let ipfs = data.join("ipfs-data/freedom-ipfs");
        let place = gated_place(
            &data,
            &[
                Gated {
                    dir: &identity,
                    what: "identity data",
                },
                Gated {
                    dir: &ipfs,
                    what: "IPFS data",
                },
            ],
            &[],
            None,
        )
        .unwrap()
        .unwrap();
        // A link to a gated directory goes as a link.
        std::os::unix::fs::symlink(&identity, data.join("link")).unwrap();
        let held = always;
        let mut removal = Removal::new(&held);
        removal
            .remove_sparing(&data, &place, 0, None, false)
            .unwrap();
        // The identity and IPFS directories are spared (not moved here), and
        // so the root and `ipfs-data` stay; everything else went.
        assert!(identity.join("vault.json").exists());
        assert!(ipfs.exists());
        assert!(!data.join("ipfs-data/other").exists());
        assert!(!data.join("Cookies").exists());
        assert!(!data.join("link").exists());
    }

    #[test]
    fn links_are_refused_before_anything_changes() {
        let root = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(root.path()).unwrap();
        let elsewhere = base.join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("identity")).unwrap();
        let app = base.join("app");
        std::fs::create_dir_all(&app).unwrap();
        std::os::unix::fs::symlink(&elsewhere, app.join("Profiles")).unwrap();
        let data = app.join("Profiles");
        match refuse_links_below(&app, &data.join("work")) {
            Err(Failure::Refused(message)) => assert!(message.contains("reached through a link")),
            other => panic!("{other:?}"),
        }
        let identity = elsewhere.join("identity");
        std::fs::create_dir_all(base.join("p")).unwrap();
        std::os::unix::fs::symlink(&identity, base.join("p/identity")).unwrap();
        let link = base.join("p/identity");
        match gated_place(
            &base.join("p"),
            &[Gated {
                dir: &link,
                what: "identity data",
            }],
            &[],
            None,
        ) {
            Err(Failure::Refused(message)) => assert!(
                message.starts_with("The profile's identity data is reached through a link"),
                "{message}"
            ),
            other => panic!("{other:?}"),
        }
        assert!(identity.exists());
    }

    #[test]
    fn a_lost_lock_stops_the_removal() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("x");
        std::fs::create_dir_all(&dir).unwrap();
        let held = || false;
        let mut removal = Removal::new(&held);
        assert!(matches!(removal.remove_path(&dir), Err(Failure::LockLost)));
        assert!(dir.exists());
        let mut commit = || Ok(());
        let moved = fence_and_commit(&[(&dir, "identity data")], 1, &held, &mut commit);
        assert!(matches!(moved, Err(Failure::LockLost)));
        assert!(dir.exists());
    }

    #[test]
    fn a_failed_commit_puts_the_fences_back() {
        let root = tempfile::tempdir().unwrap();
        let a = root.path().join("a");
        let b = root.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let held = always;
        let mut commit = || Err(Failure::Io(std::io::Error::other("no")));
        let result = fence_and_commit(
            &[(&a, "identity data"), (&b, "IPFS data")],
            7,
            &held,
            &mut commit,
        );
        assert!(matches!(result, Err(Failure::Io(_))));
        assert!(a.is_dir() && b.is_dir());
        let names: Vec<_> = std::fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
        let mut commit = || Ok(());
        let moves = fence_and_commit(&[(&a, "identity data")], 7, &held, &mut commit).unwrap();
        assert!(!a.exists());
        assert_eq!(
            moves[0].tombstone.file_name().unwrap().to_str().unwrap(),
            format!(".a.deleting-{}-7", std::process::id())
        );
        assert!(moves[0].tombstone.is_dir());
    }
}
