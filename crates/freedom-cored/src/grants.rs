//! The four permission files on disk (design 0012, "The files (Q10)"):
//! `dapp-permissions.json`, `swarm-permissions.json`,
//! `radicle-permissions.json` and `x402-permissions.json` in the profile's
//! `userData`, which `core.hello` names as `grant_root`. Their codecs and
//! every decision are `fc-approval`'s; this module reads and writes the
//! bytes.
//!
//! - **One writer per file.** A file not in `core.hello`'s `grant_moved` is
//!   main's: the core reads it at each check, as main last renamed it into
//!   place, and changes nothing in it: no write, rename or removal, its
//!   temp files included. A write method answers `not_moved`.
//! - **A moved file** is the core's: read once at the hello, kept in
//!   memory, and written by 0001's single-file write (a temp file of mode
//!   `0600`, its fsync, the rename, the directory's flush). The core's own
//!   temp files left by a crash are removed at the hello, and a file that
//!   can't be read is renamed aside once (`<name>.unreadable`), the store
//!   starting empty.
//! - **Reading** follows 0001's rules: a regular file the user owns, never
//!   through a symlink, and at most 4 MiB. Anything else, like a file that
//!   doesn't parse, is an unreadable file, read as an empty store; a missing
//!   file is an empty store.
//! - **A failed write** leaves the file as it was. A widening isn't applied
//!   in memory either; a narrowing (or a neutral change: a last use, a
//!   chain) is, and is reported as not saved. A failed directory flush
//!   after the rename is reported as `durable: false`, the change in place.
//!
//! Every write runs inline on the event loop, as the approval methods do,
//! so two writes to one store never overlap.

use std::borrow::Cow;
use std::io::Write;
use std::path::{Path, PathBuf};

use fc_approval::stores::{
    Applied, CapStore, DappStore, Effect, MAX_FILE_BYTES, RadicleStore, Refused, StoreKind,
    SwarmStore, Unreadable,
};

use crate::fsx::{self, Done};

/// A store kept in one of the four files.
pub trait StoreFile: Clone + Default {
    const KIND: StoreKind;
    /// The store as its file's bytes give it (`wall_s`: x402's caps expire
    /// on the wall clock as they load).
    fn from_bytes(bytes: &[u8], wall_s: u64) -> Result<Self, Unreadable>;
    fn file_text(&self) -> Result<String, Refused>;
    fn slot(grants: &Grants) -> &Self;
    fn slot_mut(grants: &mut Grants) -> &mut Self;
}

impl StoreFile for DappStore {
    const KIND: StoreKind = StoreKind::Dapp;
    fn from_bytes(bytes: &[u8], _wall_s: u64) -> Result<Self, Unreadable> {
        DappStore::load(bytes)
    }
    fn file_text(&self) -> Result<String, Refused> {
        self.text()
    }
    fn slot(grants: &Grants) -> &Self {
        &grants.dapp
    }
    fn slot_mut(grants: &mut Grants) -> &mut Self {
        &mut grants.dapp
    }
}

impl StoreFile for SwarmStore {
    const KIND: StoreKind = StoreKind::Swarm;
    fn from_bytes(bytes: &[u8], _wall_s: u64) -> Result<Self, Unreadable> {
        SwarmStore::load(bytes)
    }
    fn file_text(&self) -> Result<String, Refused> {
        self.text()
    }
    fn slot(grants: &Grants) -> &Self {
        &grants.swarm
    }
    fn slot_mut(grants: &mut Grants) -> &mut Self {
        &mut grants.swarm
    }
}

impl StoreFile for RadicleStore {
    const KIND: StoreKind = StoreKind::Radicle;
    fn from_bytes(bytes: &[u8], _wall_s: u64) -> Result<Self, Unreadable> {
        RadicleStore::load(bytes)
    }
    fn file_text(&self) -> Result<String, Refused> {
        self.text()
    }
    fn slot(grants: &Grants) -> &Self {
        &grants.radicle
    }
    fn slot_mut(grants: &mut Grants) -> &mut Self {
        &mut grants.radicle
    }
}

impl StoreFile for CapStore {
    const KIND: StoreKind = StoreKind::X402;
    fn from_bytes(bytes: &[u8], wall_s: u64) -> Result<Self, Unreadable> {
        CapStore::load(bytes, wall_s)
    }
    fn file_text(&self) -> Result<String, Refused> {
        self.text()
    }
    fn slot(grants: &Grants) -> &Self {
        &grants.x402
    }
    fn slot_mut(grants: &mut Grants) -> &mut Self {
        &mut grants.x402
    }
}

/// What reading a file found.
enum Read {
    Missing,
    /// Not a regular file the user owns, past the bound, or an I/O error.
    Unreadable,
    Bytes(Vec<u8>),
}

/// Reads `path` under 0001's rules: a regular file, opened without
/// following a symlink and judged on the open handle, owned by the user,
/// and no more than [`MAX_FILE_BYTES`]. On Windows ownership is 0001's:
/// the default root's per-user `%APPDATA%` ACL, with no owner check here;
/// an alternate root waits for 0001's owner-only DACL follow-up, as the
/// vault does.
fn read_file(path: &Path) -> Read {
    let file = match fsx::open_regular(path, false) {
        Ok(fsx::Regular::File(file)) => file,
        Ok(fsx::Regular::Missing) => return Read::Missing,
        Ok(fsx::Regular::Other) | Err(_) => return Read::Unreadable,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match file.metadata() {
            Ok(metadata) if metadata.uid() == rustix::process::getuid().as_raw() => {}
            _ => return Read::Unreadable,
        }
    }
    match fsx::read_at_most(&file, MAX_FILE_BYTES as u64) {
        Ok(Some(bytes)) => Read::Bytes(bytes),
        Ok(None) | Err(_) => Read::Unreadable,
    }
}

/// Why a write changed nothing on disk.
#[derive(Debug)]
pub enum WriteFailure {
    /// The file hasn't moved: main writes it (`not_moved`).
    NotMoved,
    /// The change would pass a bound (`invalid_argument`); the store is
    /// unchanged.
    Bounds(Refused),
    /// The temp file's write, its fsync or the rename failed: the file is
    /// as it was. `applied`: the change is active in memory all the same
    /// (a narrowing), and the store's next write carries it.
    Io { applied: bool },
}

/// A change made.
#[derive(Debug)]
pub struct Written<T> {
    pub value: T,
    pub effect: Effect,
    /// `false` when the directory flush after the rename failed: the change
    /// is in place, and may not survive power loss.
    pub durable: bool,
}

/// The four stores and where they live.
#[derive(Default)]
pub struct Grants {
    root: Option<PathBuf>,
    moved: Vec<StoreKind>,
    dapp: DappStore,
    swarm: SwarmStore,
    radicle: RadicleStore,
    x402: CapStore,
}

impl Grants {
    pub fn new() -> Self {
        Grants::default()
    }

    /// The hello's `grant_root` and `grant_moved`: each moved file's leftover
    /// temp files removed and the file loaded, renamed aside if it can't be
    /// read. Files that haven't moved are left as they are.
    pub fn configure(&mut self, root: PathBuf, moved: Vec<StoreKind>, wall_s: u64) {
        self.root = Some(root);
        self.moved = moved;
        if self.moved(StoreKind::Dapp) {
            self.dapp = self.load_moved::<DappStore>(wall_s);
        }
        if self.moved(StoreKind::Swarm) {
            self.swarm = self.load_moved::<SwarmStore>(wall_s);
        }
        if self.moved(StoreKind::Radicle) {
            self.radicle = self.load_moved::<RadicleStore>(wall_s);
        }
        if self.moved(StoreKind::X402) {
            self.x402 = self.load_moved::<CapStore>(wall_s);
        }
    }

    /// Whether the core writes `kind`'s file (it is in `grant_moved`).
    pub fn moved(&self, kind: StoreKind) -> bool {
        self.moved.contains(&kind)
    }

    fn path(&self, kind: StoreKind) -> Option<PathBuf> {
        self.root.as_ref().map(|root| root.join(kind.file_name()))
    }

    fn load_moved<S: StoreFile>(&self, wall_s: u64) -> S {
        let (Some(root), Some(path)) = (self.root.as_ref(), self.path(S::KIND)) else {
            return S::default();
        };
        if let Err(e) = fsx::remove_temps(root, S::KIND.file_name()) {
            crate::log::warn(
                "cannot remove a permission file's temp files",
                serde_json::json!({ "store": S::KIND.name(), "kind": e.kind().to_string() }),
            );
        }
        let loaded = match read_file(&path) {
            Read::Missing => return S::default(),
            Read::Bytes(bytes) => S::from_bytes(&bytes, wall_s).ok(),
            Read::Unreadable => None,
        };
        if let Some(store) = loaded {
            return store;
        }
        // Renamed aside once, and every site asks again (`file-unreadable`).
        let aside = root.join(format!("{}.unreadable", S::KIND.file_name()));
        let renamed = std::fs::rename(&path, &aside)
            .map(|()| fsx::flushed(fsx::sync_rename(root, &aside)) == Done::Durable);
        crate::log::warn(
            "a permission file can't be read: renamed aside, the store starts empty",
            serde_json::json!({ "store": S::KIND.name(), "renamed": renamed.is_ok() }),
        );
        S::default()
    }

    /// The store as it stands: the core's own once moved, otherwise the
    /// file main last renamed into place, read now (missing or unreadable:
    /// empty, and left where it is).
    pub fn view<S: StoreFile>(&self, wall_s: u64) -> Cow<'_, S> {
        if self.moved(S::KIND) {
            return Cow::Borrowed(S::slot(self));
        }
        let Some(path) = self.path(S::KIND) else {
            return Cow::Owned(S::default());
        };
        let store = match read_file(&path) {
            Read::Bytes(bytes) => S::from_bytes(&bytes, wall_s).unwrap_or_default(),
            Read::Missing | Read::Unreadable => S::default(),
        };
        Cow::Owned(store)
    }

    /// Changes a moved store and writes its file. A change that leaves the
    /// store as it was writes nothing. See [`WriteFailure`] for what a
    /// failure leaves.
    pub fn write<S: StoreFile, T>(
        &mut self,
        change: impl FnOnce(&mut S) -> Applied<T>,
    ) -> Result<Written<T>, WriteFailure> {
        if !self.moved(S::KIND) {
            return Err(WriteFailure::NotMoved);
        }
        let Some(path) = self.path(S::KIND) else {
            return Err(WriteFailure::NotMoved);
        };
        let mut next = S::slot(self).clone();
        let applied = change(&mut next);
        if applied.effect == Effect::Unchanged {
            return Ok(Written {
                value: applied.value,
                effect: applied.effect,
                durable: true,
            });
        }
        let text = next.file_text().map_err(WriteFailure::Bounds)?;
        match write_file(&path, S::KIND.name(), text.as_bytes()) {
            Ok(done) => {
                *S::slot_mut(self) = next;
                Ok(Written {
                    value: applied.value,
                    effect: applied.effect,
                    durable: done == Done::Durable,
                })
            }
            Err(e) => {
                let applied = applied.effect != Effect::Widening;
                crate::log::error(
                    "a permission file's write failed",
                    serde_json::json!({
                        "store": S::KIND.name(),
                        "kind": e.kind().to_string(),
                        "applied": applied,
                    }),
                );
                if applied {
                    *S::slot_mut(self) = next;
                }
                Err(WriteFailure::Io { applied })
            }
        }
    }
}

/// 0001's single-file write of `target`, with the test hooks' failures at
/// each step (`write`, `fsync`, `rename`, `flush`). Before the rename an
/// error leaves the target untouched and the temp file removed; after it,
/// a failed flush is [`Done::NotDurable`].
fn write_file(target: &Path, store: &str, contents: &[u8]) -> std::io::Result<Done> {
    let fails = |step: &str| crate::testhooks::grant_write_fails(store, step);
    let dir = target
        .parent()
        .ok_or_else(|| std::io::Error::other("target has no parent directory"))?;
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (temp_path, temp) = fsx::create_temp(dir, &format!(".{name}"))?;
    if let Err(error) = stage(temp, &temp_path, target, contents, &fails) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(error);
    }
    if fails("flush") {
        return Ok(fsx::flushed(Err(std::io::Error::other(
            "test hook: flush fails",
        ))));
    }
    Ok(fsx::flushed(fsx::sync_rename(dir, target)))
}

/// Writes and flushes the temp file, then renames it over `target` if its
/// name still names the file written. The handle is closed before the
/// rename, which Windows needs.
fn stage(
    mut temp: std::fs::File,
    temp_path: &Path,
    target: &Path,
    contents: &[u8],
    fails: &dyn Fn(&str) -> bool,
) -> std::io::Result<()> {
    let injected = |step: &str| std::io::Error::other(format!("test hook: {step} fails"));
    if fails("write") {
        return Err(injected("write"));
    }
    temp.write_all(contents)?;
    if fails("fsync") {
        return Err(injected("fsync"));
    }
    temp.sync_all()?;
    if fails("rename") {
        return Err(injected("rename"));
    }
    if !fsx::same_file(&temp, temp_path)? {
        return Err(std::io::Error::other(
            "the temp file was replaced before its rename",
        ));
    }
    drop(temp);
    std::fs::rename(temp_path, target)
}
