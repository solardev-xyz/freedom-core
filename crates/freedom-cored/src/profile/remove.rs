//! A profile's removal under its gates, as the reference's `deleteProfile`
//! does it (`profile-catalog.js`: `gatedPlace`, `radicleHomeFence`,
//! `fenceAndCommit`, `removeSparing`, `removeDefaultProfileDataFromAppRoot`,
//! `removeEmptyRemade` and the Radicle staging siblings; design 0013,
//! "Deletion").
//!
//! - **Through no symlink** ([`crate::anchor::Dir`], as the catalog's store
//!   reaches its files; review of #336): the profile's data and its Radicle
//!   home are reached from the app root's handle (a dev build's homes from
//!   the handle of the directory above it), each step opened without
//!   following a symlink. A link or a file at any step from there down to
//!   the data, a gated directory or the home is refused before anything
//!   changes. Every change is made through a directory's handle (on Unix
//!   `renameat`, `unlinkat`; a tree removed handle to handle), so a link
//!   met inside is removed itself, never followed. Windows has no
//!   handle-relative calls: there each directory is checked to be no
//!   reparse point, then used by path (the anchor module's limit).
//! - **Under the catalog's write lock:** every change (a fence's rename,
//!   each removal, each `rmdir`) is made only while the lock is still this
//!   process's; a lost lock stops the delete there ([`Failure::LockLost`]).
//!   A fence put back after a failed step is the one change made without
//!   it, since it undoes one.
//! - **The gates** are this process's own, held for the whole run, so none
//!   is lost meanwhile: the reference's lost-gate checks and reports have
//!   nothing to report, and a directory made again since the fence is
//!   always under a held gate.
//! - **Read-only checks by path:** whether a gated directory is reached
//!   under another name, and whether the Radicle home overlaps one by
//!   identity (`identitiesUp`), stat paths as the reference does; they only
//!   refuse.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::anchor::{Dir, Kind};

/// A directory's identity: on Unix its device and inode; on Windows its
/// volume's serial number and file ID.
pub type Identity = (u64, u128);

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

/// `layoutRefused(what, detail)`.
fn layout_refused(what: &str, detail: &str) -> Failure {
    Failure::Refused(format!(
        "The profile's {what} {detail}, so it can't be deleted safely while its lock is held. \
         Nothing was deleted: replace the link with the directory itself, or remove it, and \
         delete the profile again."
    ))
}

/// `radicleLayoutRefused(link)`.
pub fn radicle_layout_refused(link: &Path) -> Failure {
    Failure::Refused(format!(
        "The profile's Radicle data is reached through a link ({}), so the profile can't be \
         deleted safely while its locks are held. Nothing was deleted: replace the link with \
         the directory itself, or remove it, and delete the profile again.",
        link.display()
    ))
}

/// The profile's directory reached through a link below the app root (not
/// in the reference, whose removal would follow it).
pub fn data_layout_refused(link: &Path) -> Failure {
    Failure::Refused(format!(
        "The profile's data is reached through a link ({}), so the profile can't be deleted \
         safely. Nothing was deleted: replace the link with the directory itself, or remove \
         it, and delete the profile again.",
        link.display()
    ))
}

/// The names from `base` down to `target`, which is below it.
fn names_below(base: &Path, target: &Path) -> Option<Vec<OsString>> {
    let rest = target.strip_prefix(base).ok()?;
    rest.components()
        .map(|component| match component {
            std::path::Component::Normal(name) => Some(name.to_owned()),
            _ => None,
        })
        .collect()
}

/// The directory `name` in `dir`, if it is a real one there: `None` when
/// nothing is there; a link or anything else is `refused` with its path.
fn real_child(
    dir: &Dir,
    name: &OsStr,
    refused: &dyn Fn(&Path) -> Failure,
) -> Result<Option<Dir>, Failure> {
    match dir.kind(name)? {
        Kind::Missing => Ok(None),
        Kind::Dir => Ok(dir.child(name, false)?),
        Kind::File | Kind::Other => Err(refused(&dir.path(name))),
    }
}

/// A directory the delete acts on, reached from a handle: the handle of
/// the directory holding it (`None` when that is missing: nothing below it
/// exists), its name there, and its own handle if it is there. Where a
/// step on the way was missing, the last directory that was there, and the
/// names from it down to the one holding it, so what is made there later
/// can still be reached from it ([`Located::parent_now`]).
pub struct Located {
    pub parent: Option<Dir>,
    pub name: OsString,
    pub dir: Option<Dir>,
    pub path: PathBuf,
    anchor: Option<(Dir, Vec<OsString>)>,
}

impl Located {
    /// The handle of the directory holding it, now: the one the layout
    /// check found or, where a step on the way was missing then, reached
    /// again from the last directory that was there, step by step through
    /// real directories only. A start makes its missing directories before
    /// it waits on the gate the delete holds (`gate::acquire`), so they
    /// may be there by now (review of #337). `None` while a step is still
    /// missing, or isn't a real directory: nothing below it is the
    /// profile's.
    pub fn parent_now(&self) -> Result<Option<Dir>, Failure> {
        if let Some(parent) = &self.parent {
            return Ok(Some(parent.try_clone()?));
        }
        let Some((anchor, names)) = &self.anchor else {
            return Ok(None);
        };
        let mut dir = anchor.try_clone()?;
        for name in names {
            if dir.kind(name)? != Kind::Dir {
                return Ok(None);
            }
            match dir.child(name, false)? {
                Some(child) => dir = child,
                None => return Ok(None),
            }
        }
        Ok(Some(dir))
    }
}

/// `target`, below `base` (whose handle is `base_dir`), reached step by
/// step through no symlink: every step down to it, and it, a real
/// directory as far as they exist, or `refused` with the first that isn't
/// (`refuseLinksBelow`, as the reference has it for the Radicle home).
pub fn locate(
    base_dir: &Dir,
    base: &Path,
    target: &Path,
    refused: &dyn Fn(&Path) -> Failure,
) -> Result<Located, Failure> {
    let names = names_below(base, target).ok_or_else(|| refused(target))?;
    let Some((name, parents)) = names.split_last() else {
        return Err(refused(target));
    };
    let mut parent = Some(base_dir.try_clone()?);
    let mut anchor = None;
    for (at, step) in parents.iter().enumerate() {
        let Some(dir) = parent.take() else {
            break;
        };
        match real_child(&dir, step, refused)? {
            Some(child) => parent = Some(child),
            None => {
                anchor = Some((dir, parents[at..].to_vec()));
                break;
            }
        }
    }
    let dir = match &parent {
        Some(parent) => real_child(parent, name, refused)?,
        None => None,
    };
    Ok(Located {
        parent,
        name: name.clone(),
        dir,
        path: target.to_owned(),
        anchor,
    })
}

/// One directory on the way from the data root to a gated one.
#[derive(Debug)]
struct Node {
    name: Option<OsString>,
    id: Option<Identity>,
    parent: Option<usize>,
    gated: bool,
}

/// A gated directory: the handle of the directory holding it (if that is
/// there), its name, its names below the data root, its canonical path,
/// and its identity if it is there.
pub struct Fence {
    pub parent: Option<Dir>,
    pub name: OsString,
    pub names: Vec<OsString>,
    pub what: &'static str,
    canonical: PathBuf,
    id: Option<Identity>,
}

/// `gatedPlace`'s result: the directories on the way to each gated one,
/// and the gated ones.
pub struct Place {
    nodes: Vec<Node>,
    pub fences: Vec<Fence>,
}

/// A gated directory to check: its names below the data root, what it
/// holds (`identity data`, `IPFS data`), and whether a regular file at its
/// name is the move's placeholder (design 0013, "The move", step 4: the
/// root's `identity` while a move's journal is pending), which is gated at
/// its path and goes as a file. Anything else that isn't a directory there
/// is refused.
pub struct Gated<'a> {
    pub names: &'a [&'a str],
    pub what: &'static str,
    pub placeholder: bool,
}

/// `identitiesUp(target)`: the identities of `target` and of every
/// directory above it, by path, following links; one that isn't there, or
/// can't be opened as a directory, skipped.
fn identities_up(target: &Path) -> std::io::Result<Vec<Identity>> {
    let mut ids = Vec::new();
    let mut current = Some(target);
    while let Some(dir) = current {
        // One that isn't there, or isn't a directory, is skipped.
        if let Ok(Some(opened)) = Dir::open_root(dir, crate::anchor::Resolve::Follow) {
            ids.push(opened.identity()?);
        }
        current = dir.parent();
    }
    Ok(ids)
}

/// `gatedPlace(dataRoot, gatedDirs, { otherRoots })`: where the gated
/// directories are, from the data root's handle, or the reference's
/// refusal, before anything changes. `None` when the data root isn't there.
/// `other_roots` are the Radicle home and its staging siblings, by path.
pub fn gated_place(
    data_root: Option<&Dir>,
    data_path: &Path,
    gated: &[Gated<'_>],
    other_roots: &[PathBuf],
) -> Result<Option<Place>, Failure> {
    let Some(root) = data_root else {
        return Ok(None);
    };
    let canonical_root = std::fs::canonicalize(data_path)?;
    let mut nodes = vec![Node {
        name: None,
        id: Some(root.identity()?),
        parent: None,
        gated: false,
    }];
    let mut fences = Vec::new();
    for Gated {
        names,
        what,
        placeholder,
    } in gated
    {
        let names: Vec<OsString> = names.iter().map(OsString::from).collect();
        let Some((last, _)) = names.split_last() else {
            continue;
        };
        let mut current = Some(root.try_clone()?);
        let mut holder = None;
        let mut id = None;
        let mut parent = 0;
        let mut path = data_path.to_path_buf();
        for (i, name) in names.iter().enumerate() {
            path.push(name);
            let here = current.take();
            let last = i + 1 == names.len();
            let next = match &here {
                // The placeholder: no directory there, so nothing below it
                // to spare; the fence moves it aside as a file.
                Some(dir) if *placeholder && last && dir.kind(name)? == Kind::File => None,
                Some(dir) => real_child(dir, name, &|link| {
                    layout_refused(
                        what,
                        &format!("is reached through a link ({})", link.display()),
                    )
                })?,
                None => None,
            };
            id = next.as_ref().map(Dir::identity).transpose()?;
            let found = nodes.iter().position(|node| {
                node.parent == Some(parent) && node.name.as_deref() == Some(name.as_os_str())
            });
            parent = match found {
                Some(index) => index,
                None => {
                    nodes.push(Node {
                        name: Some(name.clone()),
                        id,
                        parent: Some(parent),
                        gated: last,
                    });
                    nodes.len() - 1
                }
            };
            if last {
                holder = here;
            }
            current = next;
        }
        let mut canonical = canonical_root.clone();
        for name in &names {
            canonical.push(name);
        }
        if id.is_some() && std::fs::canonicalize(&path)? != canonical {
            return Err(layout_refused(
                what,
                &format!("is reached under another name ({})", path.display()),
            ));
        }
        fences.push(Fence {
            parent: holder,
            name: last.clone(),
            names: names.clone(),
            what,
            canonical,
            id,
        });
    }
    for fence in &fences {
        let around = identities_up(&fence.canonical)?;
        for other in other_roots {
            // Not there, or not a directory (a link goes as a link).
            let Ok(metadata) = std::fs::symlink_metadata(other) else {
                continue;
            };
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                continue;
            }
            let Some(opened) = Dir::open_root(other, crate::anchor::Resolve::Follow)? else {
                continue;
            };
            let other_id = opened.identity()?;
            let within = match fence.id {
                Some(fence_id) => {
                    identities_up(&std::fs::canonicalize(other)?)?.contains(&fence_id)
                }
                None => false,
            };
            if around.contains(&other_id) || within {
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
    Ok(Some(Place { nodes, fences }))
}

/// Windows refuses a rename while a scanner or indexer has a file open;
/// those clear in a moment (`FENCE_RETRY_CODES`).
fn retryable(failure: &Failure) -> bool {
    let Failure::Io(e) = failure else {
        return false;
    };
    if matches!(
        e.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ResourceBusy
    ) {
        return true;
    }
    // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION.
    cfg!(windows) && matches!(e.raw_os_error(), Some(32 | 33))
}

const FENCE_ATTEMPTS: u32 = 10;
const FENCE_RETRY: Duration = Duration::from_millis(100);

/// A directory the fence moves aside: its parent's handle and its name.
pub struct ToFence<'a> {
    pub parent: &'a Dir,
    pub name: &'a OsStr,
    pub what: &'static str,
}

/// `tombstoneOf(dir)`: `.<name>.deleting-<pid>-<ms>` beside it, a name no
/// core or service opens.
fn tombstone_of(name: &OsStr, now_ms: i64) -> OsString {
    let mut tombstone = OsString::from(".");
    tombstone.push(name);
    tombstone.push(format!(".deleting-{}-{now_ms}", std::process::id()));
    tombstone
}

/// `moveBack(moved, cause)`: what one attempt moved, put back last first.
/// One that can't be is named, with where it is.
fn move_back(
    fences: &[ToFence<'_>],
    tombstones: &[OsString],
    moved: &[usize],
) -> Result<(), Failure> {
    let mut stuck = Vec::new();
    for &index in moved.iter().rev() {
        let fence = &fences[index];
        if fence.parent.rename(&tombstones[index], fence.name).is_err() {
            stuck.push(index);
        }
    }
    if stuck.is_empty() {
        return Ok(());
    }
    let where_ = stuck
        .iter()
        .map(|&i| {
            format!(
                "its {} is at {}",
                fences[i].what,
                fences[i].parent.path(&tombstones[i]).display()
            )
        })
        .collect::<Vec<_>>()
        .join(", and ");
    Err(Failure::Refused(format!(
        "The profile couldn't be deleted, and not all of its data could be put back: {where_}. \
         Move it back to its name without the leading dot and the \".deleting-…\" suffix."
    )))
}

/// `fenceAndCommit(fences, gates, commit)`: each gated directory (in
/// order: the identity directory, the IPFS directory, the Radicle home)
/// renamed aside to its tombstone through its parent's handle, then
/// `commit`, the catalog's change. A move or `commit` that fails has the
/// moves before it put back; a Windows refusal is waited out and the whole
/// step tried again. Each move only while `held`. Returns each fence's
/// tombstone, `None` where nothing was there to move.
pub fn fence_and_commit(
    fences: &[ToFence<'_>],
    now_ms: i64,
    held: &dyn Fn() -> bool,
    commit: &mut dyn FnMut() -> Result<(), Failure>,
) -> Result<Vec<Option<OsString>>, Failure> {
    let tombstones: Vec<OsString> = fences
        .iter()
        .map(|fence| tombstone_of(fence.name, now_ms))
        .collect();
    let mut attempt = 1;
    loop {
        let mut moved = Vec::new();
        let mut result = Ok(());
        for (index, fence) in fences.iter().enumerate() {
            if !held() {
                result = Err(Failure::LockLost);
                break;
            }
            match fence.parent.rename(fence.name, &tombstones[index]) {
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
            return Ok((0..fences.len())
                .map(|i| moved.contains(&i).then(|| tombstones[i].clone()))
                .collect());
        };
        move_back(fences, &tombstones, &moved)?;
        if !retryable(&failure) || attempt >= FENCE_ATTEMPTS {
            return Err(failure);
        }
        attempt += 1;
        std::thread::sleep(FENCE_RETRY);
    }
}

/// The removal's state: the lock it runs under, and its test hook.
pub struct Removal<'a> {
    held: &'a dyn Fn() -> bool,
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

    /// `fsOffload.removePath(…, { recursive: true, force: true })` of
    /// `name` in `dir`: a directory and all below it, walked handle to
    /// handle; a link or file itself; nothing if nothing is there.
    pub fn remove_tree(&mut self, dir: &Dir, name: &OsStr) -> Result<(), Failure> {
        self.check()?;
        dir.remove_tree(name)?;
        if !self.removed {
            self.removed = true;
            crate::testhooks::profile_delete_step("mid-removal");
        }
        Ok(())
    }

    /// `rmdir` of `name` in `dir`, only while the lock is held: whether it
    /// went (not there, or not empty, is `false`).
    pub fn remove_empty(&self, dir: &Dir, name: &OsStr) -> Result<bool, Failure> {
        self.check()?;
        Ok(dir.remove_empty(name)?)
    }

    /// `removeSparing(dir, place, index, { skip })`: empties `dir`,
    /// `place`'s directory `index` on the way to the gated directories,
    /// sparing them: it walks only into the directories on the way (by
    /// identity, under any name), and removes everything else. A directory
    /// named as one of the next steps, but not that directory, is spared.
    /// A directory on the way goes once empty; `dir` itself is the
    /// caller's.
    pub fn remove_sparing(
        &mut self,
        dir: &Dir,
        place: &Place,
        index: usize,
        skip: Option<&dyn Fn(&OsStr) -> bool>,
    ) -> Result<(), Failure> {
        for name in dir.names()? {
            if skip.is_some_and(|skip| skip(&name)) {
                continue;
            }
            match dir.kind(&name)? {
                Kind::Missing => {}
                Kind::Dir => {
                    let Some(child) = dir.child(&name, false)? else {
                        continue;
                    };
                    let step = step_of(place, child.identity()?);
                    let next_named = place.nodes.iter().any(|node| {
                        node.parent == Some(index)
                            && node
                                .name
                                .as_deref()
                                .is_some_and(|n| same_entry_name(&name, n))
                    });
                    match step {
                        Some(step) if step > index => {
                            self.remove_sparing(&child, place, step, None)?;
                            drop(child);
                            self.remove_empty(dir, &name)?;
                        }
                        // A directory on the way met again (a mount that
                        // loops back), or one named as a next step but not
                        // that directory: spared.
                        Some(_) => {}
                        None if next_named => {}
                        None => {
                            drop(child);
                            self.remove_tree(dir, &name)?;
                        }
                    }
                }
                Kind::File | Kind::Other => self.remove_tree(dir, &name)?,
            }
        }
        Ok(())
    }

    /// `removeEmptyRemade`, for one gated directory: reached again from
    /// `base` along `names` (the data root's name first, unless the data
    /// root is `base` itself, the packaged app root that stays), it and
    /// each directory above it that this leaves empty go, up to `base`'s
    /// child. A directory made again there since the fence is under a gate
    /// this process still holds.
    pub fn remove_empty_chain(&self, base: &Dir, names: &[OsString]) -> Result<(), Failure> {
        let Some((_, parents)) = names.split_last() else {
            return Ok(());
        };
        let mut dirs = vec![base.try_clone()?];
        for name in parents {
            let Some(last) = dirs.last() else {
                return Ok(());
            };
            if last.kind(name)? != Kind::Dir {
                return Ok(());
            }
            match last.child(name, false)? {
                Some(child) => dirs.push(child),
                None => return Ok(()),
            }
        }
        for (dir, name) in dirs.iter().zip(names).rev() {
            if !self.remove_empty(dir, name)? {
                break;
            }
        }
        Ok(())
    }
}

/// `stepOf(place, stat)`: which directory on the way to a gated one this
/// is, by identity; never a gated one.
fn step_of(place: &Place, id: Identity) -> Option<usize> {
    place
        .nodes
        .iter()
        .position(|node| !node.gated && node.id == Some(id))
}

/// `sameEntryName(entry, name)`: compared without case. The reference also
/// compares in NFC; for the names compared here (`identity`, `ipfs-data`,
/// `freedom-ipfs`), which hold no `k`, `;` or `` ` ``, the only ASCII
/// characters a canonical singleton reaches, NFC changes nothing.
fn same_entry_name(entry: &OsStr, name: &OsStr) -> bool {
    match (entry.to_str(), name.to_str()) {
        (Some(entry), Some(name)) => entry.to_lowercase() == name.to_lowercase(),
        _ => entry == name,
    }
}

/// The staging copies an interrupted legacy `radicle-data/` carry-over
/// left beside a Radicle home (`<slot>.migrating-<pid>-<ts>`,
/// `radicleStagingSiblings`): their names in the home's directory.
pub fn radicle_staging_siblings(parent: &Dir, home: &OsStr) -> Result<Vec<OsString>, Failure> {
    let mut prefix = home.to_owned();
    prefix.push(".migrating-");
    Ok(parent
        .names()?
        .into_iter()
        .filter(|name| {
            name.as_encoded_bytes()
                .starts_with(prefix.as_encoded_bytes())
        })
        .collect())
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::anchor::Resolve;

    fn always() -> bool {
        true
    }

    fn open(path: &Path) -> Dir {
        Dir::open_root(path, Resolve::Follow).unwrap().unwrap()
    }

    const GATED: [Gated<'static>; 2] = [
        Gated {
            names: &["identity"],
            what: "identity data",
            placeholder: false,
        },
        Gated {
            names: &["ipfs-data", "freedom-ipfs"],
            what: "IPFS data",
            placeholder: false,
        },
    ];

    /// The removal spares the gated directories and walks only the steps
    /// on the way; a link to a gated directory goes as a link.
    #[test]
    fn spares_the_gated_directories() {
        let root = tempfile::tempdir().unwrap();
        let data = std::fs::canonicalize(root.path()).unwrap().join("p");
        std::fs::create_dir_all(data.join("identity")).unwrap();
        std::fs::create_dir_all(data.join("ipfs-data/freedom-ipfs")).unwrap();
        std::fs::write(data.join("ipfs-data/other"), "x").unwrap();
        std::fs::write(data.join("Cookies"), "x").unwrap();
        std::fs::write(data.join("identity/vault.json"), "x").unwrap();
        let dir = open(&data);
        let place = gated_place(Some(&dir), &data, &GATED, &[])
            .unwrap()
            .unwrap();
        std::os::unix::fs::symlink(data.join("identity"), data.join("link")).unwrap();
        let held = always;
        let mut removal = Removal::new(&held);
        removal.remove_sparing(&dir, &place, 0, None).unwrap();
        assert!(data.join("identity/vault.json").exists());
        assert!(data.join("ipfs-data/freedom-ipfs").exists());
        assert!(!data.join("ipfs-data/other").exists());
        assert!(!data.join("Cookies").exists());
        assert!(std::fs::symlink_metadata(data.join("link")).is_err());
    }

    /// A regular file at a gated name is refused, but where it is the
    /// move's placeholder: then it is no directory to spare and goes as a
    /// file, while the moved directory beside it is spared. A link there is
    /// refused either way.
    #[test]
    fn the_placeholder_goes_as_a_file() {
        let pending: [Gated<'static>; 2] = [
            Gated {
                names: &["identity"],
                what: "identity data",
                placeholder: true,
            },
            Gated {
                names: &["freedom", "identity"],
                what: "identity data",
                placeholder: false,
            },
        ];
        let root = tempfile::tempdir().unwrap();
        let data = std::fs::canonicalize(root.path()).unwrap().join("p");
        std::fs::create_dir_all(data.join("freedom/identity")).unwrap();
        std::fs::write(data.join("freedom/identity/vault.json"), "x").unwrap();
        std::fs::write(data.join("freedom/settings.json"), "x").unwrap();
        std::fs::write(data.join("identity"), "moved to freedom/identity").unwrap();
        let dir = open(&data);
        match gated_place(Some(&dir), &data, &GATED, &[]) {
            Err(Failure::Refused(message)) => assert!(
                message.starts_with("The profile's identity data is reached through a link"),
                "{message}"
            ),
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("a file at a gated directory's name"),
        }
        let place = gated_place(Some(&dir), &data, &pending, &[])
            .unwrap()
            .unwrap();
        assert!(place.fences[0].parent.is_some() && place.fences[0].id.is_none());
        let held = always;
        let mut removal = Removal::new(&held);
        removal.remove_sparing(&dir, &place, 0, None).unwrap();
        assert!(std::fs::symlink_metadata(data.join("identity")).is_err());
        assert!(data.join("freedom/identity/vault.json").exists());
        assert!(!data.join("freedom/settings.json").exists());

        std::os::unix::fs::symlink(data.join("freedom/identity"), data.join("identity")).unwrap();
        assert!(matches!(
            gated_place(Some(&dir), &data, &pending, &[]),
            Err(Failure::Refused(_))
        ));
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
        match locate(
            &open(&app),
            &app,
            &app.join("Profiles/work"),
            &data_layout_refused,
        ) {
            Err(Failure::Refused(message)) => assert!(message.contains("reached through a link")),
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("located through a link"),
        }
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        std::os::unix::fs::symlink(elsewhere.join("identity"), p.join("identity")).unwrap();
        match gated_place(Some(&open(&p)), &p, &GATED, &[]) {
            Err(Failure::Refused(message)) => assert!(
                message.starts_with("The profile's identity data is reached through a link"),
                "{message}"
            ),
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("a place through a link"),
        }
        assert!(elsewhere.join("identity").exists());
    }

    #[test]
    fn a_lost_lock_stops_the_removal() {
        let root = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir_all(base.join("x")).unwrap();
        let dir = open(&base);
        let held = || false;
        let mut removal = Removal::new(&held);
        assert!(matches!(
            removal.remove_tree(&dir, OsStr::new("x")),
            Err(Failure::LockLost)
        ));
        assert!(matches!(
            removal.remove_empty(&dir, OsStr::new("x")),
            Err(Failure::LockLost)
        ));
        let mut commit = || Ok(());
        let fences = [ToFence {
            parent: &dir,
            name: OsStr::new("x"),
            what: "identity data",
        }];
        let moved = fence_and_commit(&fences, 1, &held, &mut commit);
        assert!(matches!(moved, Err(Failure::LockLost)));
        assert!(base.join("x").exists());
    }

    #[test]
    fn a_failed_commit_puts_the_fences_back() {
        let root = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir_all(base.join("a")).unwrap();
        std::fs::create_dir_all(base.join("b")).unwrap();
        let dir = open(&base);
        let held = always;
        let fences = [
            ToFence {
                parent: &dir,
                name: OsStr::new("a"),
                what: "identity data",
            },
            ToFence {
                parent: &dir,
                name: OsStr::new("b"),
                what: "IPFS data",
            },
            ToFence {
                parent: &dir,
                name: OsStr::new("missing"),
                what: "Radicle data",
            },
        ];
        let mut commit = || Err(Failure::Io(std::io::Error::other("no")));
        let result = fence_and_commit(&fences, 7, &held, &mut commit);
        assert!(matches!(result, Err(Failure::Io(_))));
        assert!(base.join("a").is_dir() && base.join("b").is_dir());
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 2);
        let mut commit = || Ok(());
        let moved = fence_and_commit(&fences[..1], 7, &held, &mut commit).unwrap();
        assert!(!base.join("a").exists());
        let tombstone = moved[0].clone().unwrap();
        assert_eq!(
            tombstone.to_str().unwrap(),
            format!(".a.deleting-{}-7", std::process::id())
        );
        assert!(base.join(tombstone).is_dir());
    }
}
