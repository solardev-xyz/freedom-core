//! The profile's secrets file on disk, and quick unlock over it (design
//! 0013, "The trait", "Forgetting an item" and "The re-wrap"; PRF-1c).
//!
//! - **The file** is `secrets.json` in the identity directory, beside the
//!   vault, in fc-keystore's text. It is read as 0001 reads the vault (judged
//!   on the open handle, never through a symlink, bounded), and replaced as
//!   0001 replaces it (a temp file of mode 0600, flushed, renamed, the
//!   directory flushed). The staged file must read back as exactly the file
//!   meant before it is renamed into place.
//! - **One writer at a time:** each change reads the file, applies one of
//!   fc-keystore's changes, and writes the result, under one lock. The
//!   vault worker's jobs (enroll, disable, a vault delete) and the drain
//!   share it. A file that doesn't read, or doesn't parse, is never
//!   written over: nothing it names is acted on.
//! - **Quick unlock** is the entry `quick-unlock`: the vault password,
//!   bound to the vault file's SHA-256 (`vault_fingerprint`), under the
//!   `UserPresence` key where the device offers it and `Unattended`
//!   otherwise. An entry bound to another digest is quick unlock off.
//! - **At start** ([`Secrets::startup`]), before `core.hello` is answered
//!   and before any job runs: temp files a killed write left are removed;
//!   each `pending` item moves into `forget`, since its `create` never
//!   committed; `forget` records of a backend this OS doesn't have are
//!   dropped, since their items aren't here; and a `quick-unlock` entry
//!   naming no vault (none there, or another vault's digest) is removed,
//!   its key moving into `forget` if nothing else is under it. One write,
//!   if anything changed. Nothing here asks the key store.
//! - **The drain** ([`Secrets::drain`]) asks the key store to forget each
//!   `forget` record, and drops the record once the answer is done (`ok`,
//!   or `not_found`, which the key store counts as done). It runs on its own
//!   thread, after the hello and after each write that moves an item into
//!   `forget`, and inline before a `create` that needs room. A failed
//!   `forget` keeps its record, for the next start or that `create`.
//!   Nothing retries on a timer.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use fc_keystore::{
    Binding, EntryName, ItemId, KeyStore, KeyStoreError, Label, MAX_FILE_BYTES, MAX_SECRET_BYTES,
    OpenError, Policy, Put, Reason, Refused, Secret, SecretsFile,
};

use crate::fsx::{self, Done};
use crate::rng::OsRng;

/// The secrets file inside the identity directory.
pub const SECRETS_FILE: &str = "secrets.json";
/// Quick unlock's entry.
pub const QUICK_UNLOCK: &str = "quick-unlock";
/// The binding member that holds the vault file's SHA-256.
pub const FINGERPRINT: &str = "vault_fingerprint";

/// Why a secrets operation failed. Nothing committed changed, except where
/// a write's own commit is the one that failed after its rename (which
/// [`fsx::replace`] reports as done, not as an error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The file can't be read (a storage error's kind), or doesn't parse
    /// (`malformed`): it isn't written over.
    Unreadable(&'static str),
    /// A write failed before its rename: the file is as it was.
    Write(&'static str),
    /// The key store refused or didn't answer.
    KeyStore(KeyStoreError),
    /// A `create` would name a fifth item, even after the `forget` list was
    /// tried again (0013, "The bounds").
    ForgetBacklog,
    /// No `quick-unlock` entry for this vault.
    NotEnabled,
    /// A password quick unlock can't hold: over fc-keystore's 1 KiB.
    TooLong,
    /// The entry doesn't open under its key (changed, or another key's).
    EntryRefused,
    /// The job was abandoned (cancelled, revoked, out of time) before its
    /// commit.
    Abandoned,
    Internal,
}

/// What the event loop knows of the file, for `quick_unlock.status`: kept
/// by every write, so the loop never reads storage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct View {
    /// The `quick-unlock` entry's policy, and the vault digest it is bound
    /// to.
    pub quick_unlock: Option<(Policy, String)>,
    /// The file didn't read or parse at its last read.
    pub unreadable: bool,
    /// The file holds `forget` records.
    pub records: bool,
}

/// What a job hands a change that has a commit point: whether it was
/// abandoned, and the claim of its commit (the vault's `JobControl`), asked
/// once, right before the one write that commits.
pub struct Gate<'a> {
    pub abandoned: &'a dyn Fn() -> bool,
    pub claim: &'a dyn Fn() -> bool,
}

/// See the module documentation.
pub struct Secrets {
    dir: PathBuf,
    store: Arc<dyn KeyStore + Send + Sync>,
    /// Held across each read-change-write, never across a `forget`.
    file: Mutex<()>,
    view: Mutex<View>,
    /// Wakes the drain thread, once it runs.
    drain: Mutex<Option<SyncSender<()>>>,
}

fn quick_unlock() -> Result<EntryName, Error> {
    EntryName::new(QUICK_UNLOCK).ok_or(Error::Internal)
}

fn io_kind(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => "permission",
        std::io::ErrorKind::StorageFull => "no_space",
        _ => "other",
    }
}

fn refused(refused: Refused) -> Error {
    match refused {
        Refused::ForgetBacklog => Error::ForgetBacklog,
        Refused::SecretSize => Error::TooLong,
        Refused::EntryRefused => Error::EntryRefused,
        _ => Error::Internal,
    }
}

impl Secrets {
    pub fn new(dir: PathBuf, store: Arc<dyn KeyStore + Send + Sync>) -> Arc<Secrets> {
        Arc::new(Secrets {
            dir,
            store,
            file: Mutex::new(()),
            view: Mutex::new(View::default()),
            drain: Mutex::new(None),
        })
    }

    /// What the device offers, as the key store says.
    pub fn capabilities(&self) -> fc_keystore::Capabilities {
        self.store.capabilities()
    }

    /// The file as last read or written.
    pub fn view(&self) -> View {
        self.view
            .lock()
            .map(|view| view.clone())
            .unwrap_or_default()
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>, Error> {
        self.file.lock().map_err(|_| Error::Internal)
    }

    fn set_view(&self, view: View) {
        if let Ok(mut current) = self.view.lock() {
            *current = view;
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.join(SECRETS_FILE)
    }

    /// The file as it stands: empty if there is none.
    fn load(&self) -> Result<SecretsFile, Error> {
        let loaded = read(&self.path());
        if loaded.is_err() {
            self.set_view(View {
                unreadable: true,
                ..View::default()
            });
        }
        loaded
    }

    /// Writes `next` durably, if `commit` allows its rename, and keeps the
    /// view. `step` names the crash hooks before and after it.
    fn write(
        &self,
        next: &SecretsFile,
        step: &str,
        commit: &dyn Fn() -> bool,
    ) -> Result<(), Error> {
        crate::testhooks::secrets_step(&format!("before-{step}"));
        std::fs::create_dir_all(&self.dir).map_err(|e| Error::Write(io_kind(&e)))?;
        let text = next.text();
        let written = fsx::replace(
            &self.path(),
            text.as_bytes(),
            |staged| {
                let bytes = fsx::read_at_most(staged, MAX_FILE_BYTES as u64)
                    .map_err(|e| e.to_string())?
                    .ok_or("the staged secrets file grew")?;
                match SecretsFile::parse(&bytes) {
                    Ok(read) if read == *next => Ok(()),
                    _ => Err("the staged secrets file doesn't read back".into()),
                }
            },
            commit,
        );
        match written {
            Ok(done) => {
                if done == Done::NotDurable {
                    crate::log::warn(
                        "the secrets file's directory flush failed",
                        serde_json::json!({}),
                    );
                }
                self.set_view(view_of(next));
                crate::testhooks::secrets_step(&format!("after-{step}"));
                Ok(())
            }
            Err(fsx::WriteError::Abandoned) => Err(Error::Abandoned),
            Err(fsx::WriteError::Io(e)) => Err(Error::Write(io_kind(&e))),
            Err(fsx::WriteError::Check(reason)) => {
                crate::log::error(
                    "the staged secrets file failed its check",
                    serde_json::json!({ "reason": reason }),
                );
                Err(Error::Internal)
            }
        }
    }

    /// At start, before `core.hello` is answered and before any job runs
    /// (see the module documentation). `vault` is the vault file's digest as
    /// the startup snapshot read it: the entry naming no vault is removed
    /// only on a definite answer.
    pub fn startup(&self, vault: Result<Option<&str>, ()>) {
        let Ok(_held) = self.lock() else {
            return;
        };
        match fsx::remove_temps(&self.dir, SECRETS_FILE) {
            Ok(0) => {}
            Ok(count) => crate::log::info(
                "removed temp files a killed secrets write left",
                serde_json::json!({ "count": count }),
            ),
            Err(e) => crate::log::warn(
                "could not remove temp files a killed secrets write left",
                serde_json::json!({ "error": e.kind().to_string() }),
            ),
        }
        let file = match self.load() {
            Ok(file) => file,
            Err(error) => {
                crate::log::error(
                    "the secrets file can't be read; nothing it names is touched",
                    serde_json::json!({ "error": format!("{error:?}") }),
                );
                return;
            }
        };
        let mut next = file
            .settle()
            .drop_foreign(self.store.capabilities().backend);
        if let Ok(fingerprint) = vault
            && let Ok(name) = quick_unlock()
            && next
                .binding(&name)
                .is_some_and(|binding| binding.get(FINGERPRINT) != fingerprint)
            && let Ok(without) = next.remove(&name)
        {
            crate::log::info(
                "removed a quick-unlock entry that names no vault",
                serde_json::json!({}),
            );
            next = without;
        }
        if next == file {
            self.set_view(view_of(&file));
            return;
        }
        if let Err(error) = self.write(&next, "startup", &|| true) {
            crate::log::error(
                "could not settle the secrets file",
                serde_json::json!({ "error": format!("{error:?}") }),
            );
            self.set_view(view_of(&file));
        }
    }

    /// Starts the drain's thread, and drains once if the file holds
    /// records. After `core.hello`'s reply: main runs `shell.keystore` from
    /// then on.
    pub fn start_drain(self: &Arc<Self>) -> std::io::Result<()> {
        if self.drain.lock().is_ok_and(|drain| drain.is_some()) {
            self.poke();
            return Ok(());
        }
        let (wake, woken) = mpsc::sync_channel::<()>(1);
        let secrets: Weak<Secrets> = Arc::downgrade(self);
        std::thread::Builder::new()
            .name("secrets".into())
            .spawn(move || {
                while woken.recv().is_ok() {
                    let Some(secrets) = secrets.upgrade() else {
                        return;
                    };
                    secrets.drain();
                }
            })?;
        if let Ok(mut drain) = self.drain.lock() {
            *drain = Some(wake);
        }
        if self.view().records {
            self.poke();
        }
        Ok(())
    }

    /// Wakes the drain, if it runs. A wake already waiting covers this one.
    fn poke(&self) {
        if let Ok(drain) = self.drain.lock()
            && let Some(wake) = drain.as_ref()
        {
            let _ = wake.try_send(());
        }
    }

    /// One pass over the `forget` list: each record forgotten through the
    /// key store, without the file's lock, and dropped under it once done.
    pub fn drain(&self) {
        let records = match self.lock().and_then(|_held| self.load()) {
            Ok(file) => file.forget_list(),
            Err(_) => return,
        };
        for sealed in records {
            match self.store.forget(&sealed) {
                Ok(()) => {
                    let dropped = self.lock().and_then(|_held| {
                        let file = self.load()?;
                        let next = file.forgotten(sealed.item());
                        if next == file {
                            return Ok(());
                        }
                        self.write(&next, "forgotten", &|| true)
                    });
                    if let Err(error) = dropped {
                        crate::log::warn(
                            "could not drop a forgotten key-store record",
                            serde_json::json!({ "error": format!("{error:?}") }),
                        );
                    }
                }
                Err(error) => crate::log::warn(
                    "a key-store forget failed; its record stays",
                    serde_json::json!({ "error": error.code() }),
                ),
            }
        }
    }

    /// [`Secrets::drain`] with the file's lock held, before a `create` that
    /// needs room: `file` is the file as it stands, and the result is the
    /// file as it then stands.
    fn drain_held(&self, mut file: SecretsFile) -> Result<SecretsFile, Error> {
        for sealed in file.forget_list() {
            if self.store.forget(&sealed).is_ok() {
                let next = file.forgotten(sealed.item());
                self.write(&next, "forgotten", &|| true)?;
                file = next;
            }
        }
        Ok(file)
    }

    /// `quick_unlock.enroll`: writes `password` as the `quick-unlock`
    /// entry, bound to `fingerprint`, once the caller has checked it against
    /// the vault with that digest.
    ///
    /// - Under the policy's committed key, if it opens: one write, the
    ///   entry put (replaced) under it.
    /// - Otherwise a new key: the `pending` write, `create`, then the commit
    ///   that makes the key the policy's and writes the entry under it. A
    ///   committed key whose item is gone (`not_found`, `invalidated`) is
    ///   replaced so: its entry, which can't be re-wrapped, leaves in the
    ///   `pending` write, which moves the key into `forget`.
    /// - An entry under the other policy leaves in the first write.
    ///
    /// Only the last write is the commit, claimed through `gate`.
    pub fn enroll(&self, password: &[u8], fingerprint: &str, gate: &Gate<'_>) -> Result<(), Error> {
        if !(1..=MAX_SECRET_BYTES).contains(&password.len()) {
            return Err(Error::TooLong);
        }
        let caps = self.store.capabilities();
        let policy = if caps.offers(Policy::UserPresence) {
            Policy::UserPresence
        } else if caps.offers(Policy::Unattended) {
            Policy::Unattended
        } else {
            return Err(Error::KeyStore(crate::keystore::unavailable("unsupported")));
        };
        let backend = caps.backend.ok_or(Error::Internal)?;
        let name = quick_unlock()?;
        let binding = Binding::new([(FINGERPRINT, fingerprint)]).ok_or(Error::Internal)?;
        let put = || Put {
            name: name.clone(),
            binding: binding.clone(),
            secret: password,
        };
        let _held = self.lock()?;
        let file = self.load()?;
        // What the first write takes off: the entry under the other
        // policy's key, and, once known, the entry under a dead key.
        let mut drop_entry = file.entry_key(&name).is_some_and(|key| key != policy);
        let base = |file: &SecretsFile, drop_entry: bool| -> Result<SecretsFile, Error> {
            if drop_entry && file.entry_key(&name).is_some() {
                file.remove(&name).map_err(refused)
            } else {
                Ok(file.clone())
            }
        };
        let mut start = base(&file, drop_entry)?;
        if let Some(sealed) = start.key(policy) {
            match self.store.open(&sealed, Some(Reason::QuickUnlock)) {
                Ok(key) => {
                    let next = start
                        .put(policy, &key, put(), &mut OsRng)
                        .map_err(refused)?;
                    if (gate.abandoned)() {
                        return Err(Error::Abandoned);
                    }
                    self.write(&next, "commit", gate.claim)?;
                    if !next.forget_list().is_empty() {
                        self.poke();
                    }
                    return Ok(());
                }
                Err(error @ (KeyStoreError::NotFound | KeyStoreError::Invalidated)) => {
                    drop_entry = true;
                    start = base(&file, drop_entry)?;
                    // Other secrets still under the dead key can't be
                    // re-wrapped; quick unlock doesn't take them down.
                    if start.key(policy).is_some() {
                        return Err(Error::KeyStore(error));
                    }
                }
                Err(error) => return Err(Error::KeyStore(error)),
            }
        }
        let item = ItemId::random(&mut OsRng).map_err(|_| Error::Internal)?;
        let pending = match start.begin_create(policy, backend, item) {
            Ok(pending) => pending,
            Err(Refused::ForgetBacklog) => {
                // The `forget` list is tried again first (0013, "The
                // bounds").
                let drained = self.drain_held(file)?;
                base(&drained, drop_entry)?
                    .begin_create(policy, backend, item)
                    .map_err(refused)?
            }
            Err(other) => return Err(refused(other)),
        };
        if (gate.abandoned)() {
            return Err(Error::Abandoned);
        }
        self.write(&pending, "pending", &|| true)?;
        if !pending.forget_list().is_empty() {
            self.poke();
        }
        let (key, sealed) = self
            .store
            .create(policy, &Label::new(item))
            .map_err(Error::KeyStore)?;
        if sealed.item() != item || sealed.policy() != policy || sealed.backend() != backend {
            return Err(Error::Internal);
        }
        let next = pending
            .commit(&sealed, &key, None, Some(put()), &mut OsRng)
            .map_err(refused)?;
        self.write(&next, "commit", gate.claim)?;
        if !next.forget_list().is_empty() {
            self.poke();
        }
        Ok(())
    }

    /// The password quick unlock holds for the vault with digest
    /// `fingerprint`, opened under its key with `reason`. Nothing is
    /// changed or deleted on a failure.
    pub fn password(&self, fingerprint: &str, reason: Reason) -> Result<Secret, Error> {
        let name = quick_unlock()?;
        let file = {
            let _held = self.lock()?;
            self.load()?
        };
        let binding = file.binding(&name).ok_or(Error::NotEnabled)?.clone();
        if binding.get(FINGERPRINT) != Some(fingerprint) {
            return Err(Error::NotEnabled);
        }
        let policy = file.entry_key(&name).ok_or(Error::NotEnabled)?;
        let sealed = file.key(policy).ok_or(Error::NotEnabled)?;
        let key = self
            .store
            .open(&sealed, Some(reason))
            .map_err(Error::KeyStore)?;
        file.open(&name, &binding, &key)
            .map_err(|error| match error {
                OpenError::NoEntry | OpenError::OtherBinding => Error::NotEnabled,
                OpenError::Refused => Error::EntryRefused,
            })
    }

    /// `quick_unlock.disable`: the entry removed, and its key moved into
    /// `forget` if nothing else is under it, in one write, claimed through
    /// `gate`. No entry: nothing to do.
    pub fn disable(&self, gate: &Gate<'_>) -> Result<(), Error> {
        let name = quick_unlock()?;
        let _held = self.lock()?;
        let file = self.load()?;
        if file.entry_key(&name).is_none() {
            return Ok(());
        }
        let next = file.remove(&name).map_err(refused)?;
        if (gate.abandoned)() {
            return Err(Error::Abandoned);
        }
        self.write(&next, "remove", gate.claim)?;
        self.poke();
        Ok(())
    }

    /// After a vault delete has committed: the entry goes as for a disable.
    /// A failure is only logged, since the delete has happened; the entry
    /// then names no vault, and the next start removes it.
    pub fn vault_deleted(&self) {
        let removed = quick_unlock().and_then(|name| {
            let _held = self.lock()?;
            let file = self.load()?;
            if file.entry_key(&name).is_none() {
                return Ok(false);
            }
            let next = file.remove(&name).map_err(refused)?;
            self.write(&next, "remove", &|| true)?;
            Ok(true)
        });
        match removed {
            Ok(true) => self.poke(),
            Ok(false) => {}
            Err(error) => crate::log::warn(
                "could not remove quick unlock's entry after a vault delete",
                serde_json::json!({ "error": format!("{error:?}") }),
            ),
        }
    }
}

/// Reads the file at `path`: empty if there is none.
fn read(path: &Path) -> Result<SecretsFile, Error> {
    let file = match fsx::open_regular(path, false) {
        Ok(fsx::Regular::Missing) => return Ok(SecretsFile::new()),
        Ok(fsx::Regular::Other) => return Err(Error::Unreadable("not_regular")),
        Ok(fsx::Regular::File(file)) => file,
        Err(e) => return Err(Error::Unreadable(io_kind(&e))),
    };
    let bytes = fsx::read_at_most(&file, MAX_FILE_BYTES as u64)
        .map_err(|e| Error::Unreadable(io_kind(&e)))?
        .ok_or(Error::Unreadable("malformed"))?;
    SecretsFile::parse(&bytes).map_err(|_| Error::Unreadable("malformed"))
}

fn view_of(file: &SecretsFile) -> View {
    let quick_unlock = quick_unlock().ok().and_then(|name| {
        let policy = file.entry_key(&name)?;
        let bound = file.binding(&name)?.get(FINGERPRINT)?.to_owned();
        Some((policy, bound))
    });
    View {
        quick_unlock,
        unreadable: false,
        records: !file.forget_list().is_empty(),
    }
}
