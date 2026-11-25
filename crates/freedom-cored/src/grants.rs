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
//!
//! **The Swarm grants are shared** (design 0015, SWM-4's D2): the swarm
//! thread's method machines read a site's connection, messaging grant and
//! rules synchronously, between two answers, so the Swarm store sits
//! behind a handle ([`Grants::swarm_handle`]) that the event loop and the
//! swarm thread both lock, each for a short section: the thread for one
//! step of a request, the loop to read the store. Both write it: the loop
//! main's approvals, the swarm thread a permission manifest's projections
//! (`swarm.manifest`). Each write holds the lock from the copy it changes
//! to the change put in place, its file written between ([`write_swarm`]),
//! so the two writers' changes are serialised and neither loses the
//! other's.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use fc_approval::stores::{
    Applied, CapStore, DappStore, Effect, MAX_FILE_BYTES, RadicleStore, Refused, StoreKind,
    SwarmStore, Unreadable,
};

use fc_store::file::{Read, read_file, set_aside, write_file};
use fc_store::fsx::{self, Done};

use crate::testhooks::GrantWrite;

/// A store kept in one of the four files.
pub trait StoreFile: Clone + Default {
    const KIND: StoreKind;
    /// The store as its file's bytes give it (`wall_s`: x402's caps expire
    /// on the wall clock as they load).
    fn from_bytes(bytes: &[u8], wall_s: u64) -> Result<Self, Unreadable>;
    fn file_text(&self) -> Result<String, Refused>;
    /// The store in memory: borrowed, or a copy taken under the shared
    /// Swarm store's lock.
    fn slot(grants: &Grants) -> Cow<'_, Self>;
    /// Runs `f` on the store in memory, nothing else changing it
    /// meanwhile: the shared Swarm store's lock held throughout (D2).
    fn locked<R>(grants: &mut Grants, f: impl FnOnce(&mut Self) -> R) -> R;
}

impl StoreFile for DappStore {
    const KIND: StoreKind = StoreKind::Dapp;
    fn from_bytes(bytes: &[u8], _wall_s: u64) -> Result<Self, Unreadable> {
        DappStore::load(bytes)
    }
    fn file_text(&self) -> Result<String, Refused> {
        self.text()
    }
    fn slot(grants: &Grants) -> Cow<'_, Self> {
        Cow::Borrowed(&grants.dapp)
    }
    fn locked<R>(grants: &mut Grants, f: impl FnOnce(&mut Self) -> R) -> R {
        f(&mut grants.dapp)
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
    fn slot(grants: &Grants) -> Cow<'_, Self> {
        Cow::Owned(grants.swarm().clone())
    }
    fn locked<R>(grants: &mut Grants, f: impl FnOnce(&mut Self) -> R) -> R {
        f(&mut grants.swarm())
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
    fn slot(grants: &Grants) -> Cow<'_, Self> {
        Cow::Borrowed(&grants.radicle)
    }
    fn locked<R>(grants: &mut Grants, f: impl FnOnce(&mut Self) -> R) -> R {
        f(&mut grants.radicle)
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
    fn slot(grants: &Grants) -> Cow<'_, Self> {
        Cow::Borrowed(&grants.x402)
    }
    fn locked<R>(grants: &mut Grants, f: impl FnOnce(&mut Self) -> R) -> R {
        f(&mut grants.x402)
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
    /// The stores whose file is behind memory: a narrowing applied in
    /// memory whose write failed, and no write of that store since.
    behind: Vec<StoreKind>,
    dapp: DappStore,
    /// Shared with the swarm thread (D2).
    swarm: Arc<Mutex<SwarmStore>>,
    radicle: RadicleStore,
    x402: CapStore,
}

impl Grants {
    pub fn new() -> Self {
        Grants::default()
    }

    /// The Swarm store's handle, which the swarm thread reads its grants
    /// through (design 0015's D2): the same store the loop's approvals
    /// read and write once `swarm` is in `grant_moved`, its file loaded
    /// into it at the hello.
    pub fn swarm_handle(&self) -> Arc<Mutex<SwarmStore>> {
        Arc::clone(&self.swarm)
    }

    /// `swarm-permissions.json`'s path once the core writes it (`swarm` in
    /// `grant_moved`), for the swarm thread's writes ([`write_swarm`]).
    pub fn swarm_path(&self) -> Option<PathBuf> {
        if !self.moved(StoreKind::Swarm) {
            return None;
        }
        self.path(StoreKind::Swarm)
    }

    /// The shared Swarm store, locked. A poisoned lock still holds a whole
    /// store: every change is put in place in one assignment.
    fn swarm(&self) -> MutexGuard<'_, SwarmStore> {
        self.swarm
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
            let store = self.load_moved::<SwarmStore>(wall_s);
            *self.swarm() = store;
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
        let loaded = match read_file(&path, MAX_FILE_BYTES) {
            Read::Missing => return S::default(),
            Read::Bytes(bytes) => S::from_bytes(&bytes, wall_s).ok(),
            Read::Unreadable => None,
        };
        if let Some(store) = loaded {
            return store;
        }
        // Renamed aside once, and every site asks again (`file-unreadable`).
        let renamed = set_aside(root, S::KIND.file_name());
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
            return S::slot(self);
        }
        let Some(path) = self.path(S::KIND) else {
            return Cow::Owned(S::default());
        };
        let store = match read_file(&path, MAX_FILE_BYTES) {
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
        self.write_change(change, false)
    }

    /// As [`Grants::write`], except that a change that leaves the store as
    /// it is still writes the file when a narrowing's failed write left the
    /// file behind memory. `accounts.remove` needs the file itself not to
    /// name the account (design 0013, `accounts-remove-forget-first`): a
    /// removed index is handed out again, and the file is what a restart
    /// loads.
    pub fn write_through<S: StoreFile, T>(
        &mut self,
        change: impl FnOnce(&mut S) -> Applied<T>,
    ) -> Result<Written<T>, WriteFailure> {
        self.write_change(change, true)
    }

    fn write_change<S: StoreFile, T>(
        &mut self,
        change: impl FnOnce(&mut S) -> Applied<T>,
        through: bool,
    ) -> Result<Written<T>, WriteFailure> {
        if !self.moved(S::KIND) {
            return Err(WriteFailure::NotMoved);
        }
        let Some(path) = self.path(S::KIND) else {
            return Err(WriteFailure::NotMoved);
        };
        let behind = through && self.behind.contains(&S::KIND);
        // The copy, its file and the change put in place under one lock,
        // so another writer of the shared Swarm store waits (D2).
        let (result, file) = S::locked(self, |slot| write_slot(slot, &path, change, behind));
        match file {
            File::Current => self.behind.retain(|kind| *kind != S::KIND),
            File::Behind if !self.behind.contains(&S::KIND) => self.behind.push(S::KIND),
            File::Behind | File::Unchanged => {}
        }
        result
    }
}

/// Where a write left the file against memory.
enum File {
    /// Written: the file holds memory's store.
    Current,
    /// Its write failed with the change applied in memory (a narrowing).
    Behind,
    /// Not written, and memory as it was.
    Unchanged,
}

/// `change` on a copy of `slot`, the copy's text written to `path`, and the
/// copy put in `slot`'s place once written; a narrowing (or a neutral
/// change) whose write fails is put in place all the same, a widening
/// isn't. `behind`: write even a change that leaves the store as it is
/// ([`Grants::write_through`]).
fn write_slot<S: StoreFile, T>(
    slot: &mut S,
    path: &Path,
    change: impl FnOnce(&mut S) -> Applied<T>,
    behind: bool,
) -> (Result<Written<T>, WriteFailure>, File) {
    let mut next = slot.clone();
    let applied = change(&mut next);
    if applied.effect == Effect::Unchanged && !behind {
        let written = Written {
            value: applied.value,
            effect: applied.effect,
            durable: true,
        };
        return (Ok(written), File::Unchanged);
    }
    let text = match next.file_text() {
        Ok(text) => text,
        Err(refused) => return (Err(WriteFailure::Bounds(refused)), File::Unchanged),
    };
    match write_file(path, text.as_bytes(), &GrantWrite(S::KIND.name())) {
        Ok(done) => {
            *slot = next;
            let written = Written {
                value: applied.value,
                effect: applied.effect,
                durable: done == Done::Durable,
            };
            (Ok(written), File::Current)
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
            let file = if applied {
                *slot = next;
                File::Behind
            } else {
                File::Unchanged
            };
            (Err(WriteFailure::Io { applied }), file)
        }
    }
}

/// The swarm thread's write of the shared Swarm store (design 0015's D2:
/// a permission manifest's projection): as the loop's
/// ([`Grants::write`]), `change` on a copy, `swarm-permissions.json` at
/// `path` written, and the copy put in place, all under the store's lock,
/// so the loop's writes and the thread's are serialised. A narrowing whose
/// write fails is in place all the same, as the loop's is; the loop's next
/// write of the store carries it.
pub fn write_swarm<T>(
    handle: &Mutex<SwarmStore>,
    path: &Path,
    change: impl FnOnce(&mut SwarmStore) -> Applied<T>,
) -> Result<Written<T>, WriteFailure> {
    let mut store = handle
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    write_slot(&mut *store, path, change, false).0
}
