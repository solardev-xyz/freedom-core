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
//! - **A vault delete** ([`Secrets::delete_vault`]) with quick unlock's
//!   entry is one journaled operation over the vault and this file
//!   ([`crate::delete_journal`]): a crash leaves the vault, the entry and
//!   its key in use, or none of them and the key in `forget`. A file that
//!   can't be read, or a write that fails, refuses the delete with the vault
//!   intact. Every read of the file first finishes a delete whose journal
//!   committed.
//! - **Quick unlock** is the entry `quick-unlock`: the vault password,
//!   bound to the vault file's SHA-256 (`vault_fingerprint`), under the
//!   `UserPresence` key where the device offers it and `Unattended`
//!   otherwise. An entry bound to another digest is quick unlock off.
//! - **The re-wrap** ([`Secrets::stage`]): `vault.create` and `vault.import`
//!   with `quick_unlock: true`, and `vault.change_password` on a vault with
//!   quick unlock, write the new vault's credential, bound to the new
//!   vault's digest, before the vault commits: as `quick-unlock`, or as
//!   `quick-unlock.next` while `quick-unlock` still holds the credential of
//!   the vault being replaced. The vault's rename is the commit point. After
//!   it, one write leaves only `quick-unlock`, bound to the new vault
//!   ([`Staged::committed`]); a failure before it takes the new entry off
//!   again ([`Staged::rolled_back`]). The credential for a vault is
//!   whichever of the two names is bound to its digest, so at every point
//!   the vault on disk has its own (design 0013, "The re-wrap").
//! - **At start** ([`Secrets::startup`]), before `core.hello` is answered
//!   and before any job runs: temp files a killed write left are removed;
//!   each `pending` item moves into `forget`, since its `create` never
//!   committed; `forget` records of a backend this OS doesn't have are
//!   dropped, since their items aren't here; and each quick-unlock entry
//!   (either name) naming no vault (none there, or another vault's digest)
//!   is removed, its key moving into `forget` if nothing else is under it.
//!   One write, if anything changed. Nothing here asks the key store.
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
    Backend, Binding, EntryName, ItemId, KeyStore, KeyStoreError, Label, MAX_FILE_BYTES,
    MAX_SECRET_BYTES, OpenError, Policy, Put, Reason, Refused, Secret, SecretsFile, WrapKey,
};

use crate::fsx::{self, Done};
use crate::rng::OsRng;

/// The secrets file inside the identity directory.
pub const SECRETS_FILE: &str = "secrets.json";
/// Quick unlock's entry.
pub const QUICK_UNLOCK: &str = "quick-unlock";
/// Where a re-wrap writes the next vault's credential while `quick-unlock`
/// still holds the credential of the vault it replaces (design 0013, "The
/// re-wrap").
pub const QUICK_UNLOCK_NEXT: &str = "quick-unlock.next";
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
    /// A vault delete without quick unlock's entry: the vault's own unlink
    /// failed (a storage error's kind), and nothing changed.
    VaultStorage(&'static str),
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
    /// Each quick-unlock entry's policy, and the vault digest it is bound
    /// to: `quick-unlock`'s, then `quick-unlock.next`'s.
    pub quick_unlock: Vec<(Policy, String)>,
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

/// Quick unlock's two names: `quick-unlock`, then `quick-unlock.next`.
fn names() -> Result<[EntryName; 2], Error> {
    match (
        EntryName::new(QUICK_UNLOCK),
        EntryName::new(QUICK_UNLOCK_NEXT),
    ) {
        (Some(main), Some(next)) => Ok([main, next]),
        _ => Err(Error::Internal),
    }
}

/// The quick-unlock entry bound to the vault file with digest
/// `fingerprint`: `quick-unlock` if it is, else `quick-unlock.next` if it
/// is.
fn credential(file: &SecretsFile, fingerprint: &str) -> Option<EntryName> {
    names().ok()?.into_iter().find(|name| {
        file.binding(name)
            .is_some_and(|binding| binding.get(FINGERPRINT) == Some(fingerprint))
    })
}

/// How a quick-unlock entry is written ([`Secrets::write_entry`]): its
/// name, binding and secret, the entries the write that puts it also takes
/// off, and the step names of its `pending` write and of the write that
/// puts it.
struct Writing<'a> {
    name: EntryName,
    binding: Binding,
    secret: &'a [u8],
    drop: Vec<EntryName>,
    steps: [&'static str; 2],
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

    /// The file as it stands: empty if there is none. A vault delete whose
    /// journal committed is finished first ([`crate::delete_journal`]):
    /// while it can't be, the file is neither read nor written.
    fn load(&self) -> Result<SecretsFile, Error> {
        let loaded = crate::delete_journal::settle(&self.dir)
            .map_err(|e| Error::Unreadable(io_kind(&e)))
            .and_then(|_| read(&self.path()));
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
        if crate::testhooks::secrets_fails(step) {
            // As if the OS had failed the write before its rename.
            return Err(Error::Write("other"));
        }
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
        // Either name: a re-wrap killed before its vault's rename leaves the
        // new vault's entry naming no vault, and one killed after it the old
        // vault's (design 0013, "The re-wrap").
        if let Ok(fingerprint) = vault
            && let Ok(names) = names()
        {
            for name in names {
                if next
                    .binding(&name)
                    .is_some_and(|binding| binding.get(FINGERPRINT) != fingerprint)
                    && let Ok(without) = next.remove(&name)
                {
                    crate::log::info(
                        "removed a quick-unlock entry that names no vault",
                        serde_json::json!({ "entry": name.as_str() }),
                    );
                    next = without;
                }
            }
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

    /// The policy quick unlock's entries go under, and the backend its keys
    /// are made in: `UserPresence` where the device offers it, `Unattended`
    /// otherwise.
    fn policy(&self) -> Result<(Policy, Backend), Error> {
        let caps = self.store.capabilities();
        let policy = if caps.offers(Policy::UserPresence) {
            Policy::UserPresence
        } else if caps.offers(Policy::Unattended) {
            Policy::Unattended
        } else {
            return Err(Error::KeyStore(crate::keystore::unavailable("unsupported")));
        };
        Ok((policy, caps.backend.ok_or(Error::Internal)?))
    }

    /// Writes a quick-unlock entry under `policy`'s key, with the file's
    /// lock held. `file` is the file as it stands.
    ///
    /// - Under the policy's committed key, if it opens: one write, the
    ///   entry put (replaced) under it.
    /// - Otherwise a new key: the `pending` write, `create`, then the commit
    ///   that makes the key the policy's and writes the entry under it. A
    ///   committed key whose item is gone (`not_found`, `invalidated`) is
    ///   replaced so: the quick-unlock entries under it, which can't be
    ///   re-wrapped, leave in the `pending` write, which moves the key into
    ///   `forget`.
    /// - The first write takes off an entry of the same name under the
    ///   other policy's key; the write that puts the entry also takes off
    ///   `writing.drop`, after the put, so that a key it shares stays.
    ///
    /// Only the last write is claimed through `gate`. The result is the
    /// file as written, with the key the entry is under.
    fn write_entry(
        &self,
        file: SecretsFile,
        writing: &Writing<'_>,
        (policy, backend): (Policy, Backend),
        gate: &Gate<'_>,
    ) -> Result<(SecretsFile, WrapKey), Error> {
        let [main, next_name] = names()?;
        let put = || Put {
            name: writing.name.clone(),
            binding: writing.binding.clone(),
            secret: writing.secret,
        };
        // What the first write takes off: an entry of the same name under
        // the other policy's key, which `put` can't replace; once the key
        // is known dead, every quick-unlock entry under it too.
        let base = |file: &SecretsFile, dead: bool| -> Result<SecretsFile, Error> {
            let mut out = file.clone();
            for name in [&main, &next_name] {
                let Some(key) = out.entry_key(name) else {
                    continue;
                };
                if (*name == writing.name && key != policy) || (dead && key == policy) {
                    out = out.remove(name).map_err(refused)?;
                }
            }
            Ok(out)
        };
        // `writing.drop` leaves in the write that puts the entry, after it,
        // so that a key it shares stays.
        let finish = |file: SecretsFile| -> Result<SecretsFile, Error> {
            let mut out = file;
            for name in &writing.drop {
                if out.entry_key(name).is_some() {
                    out = out.remove(name).map_err(refused)?;
                }
            }
            Ok(out)
        };
        let mut dead = false;
        let mut start = base(&file, dead)?;
        if let Some(sealed) = start.key(policy) {
            match self.store.open(&sealed, Some(Reason::QuickUnlock)) {
                Ok(key) => {
                    let next = finish(
                        start
                            .put(policy, &key, put(), &mut OsRng)
                            .map_err(refused)?,
                    )?;
                    if (gate.abandoned)() {
                        return Err(Error::Abandoned);
                    }
                    self.write(&next, writing.steps[1], gate.claim)?;
                    if !next.forget_list().is_empty() {
                        self.poke();
                    }
                    return Ok((next, key));
                }
                Err(error @ (KeyStoreError::NotFound | KeyStoreError::Invalidated)) => {
                    dead = true;
                    start = base(&file, dead)?;
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
                base(&drained, dead)?
                    .begin_create(policy, backend, item)
                    .map_err(refused)?
            }
            Err(other) => return Err(refused(other)),
        };
        if (gate.abandoned)() {
            return Err(Error::Abandoned);
        }
        self.write(&pending, writing.steps[0], &|| true)?;
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
        let next = finish(
            pending
                .commit(&sealed, &key, None, Some(put()), &mut OsRng)
                .map_err(refused)?,
        )?;
        self.write(&next, writing.steps[1], gate.claim)?;
        if !next.forget_list().is_empty() {
            self.poke();
        }
        Ok((next, key))
    }

    /// `quick_unlock.enroll`: writes `password` as the `quick-unlock`
    /// entry, bound to `fingerprint`, once the caller has checked it against
    /// the vault with that digest ([`Secrets::write_entry`]: under the
    /// policy's key if it opens, a new key otherwise). A `quick-unlock.next`
    /// leaves in the write that puts the entry: it is this vault's
    /// credential, which the entry replaces, or names no vault. Only the
    /// last write is the commit, claimed through `gate`.
    pub fn enroll(&self, password: &[u8], fingerprint: &str, gate: &Gate<'_>) -> Result<(), Error> {
        if !(1..=MAX_SECRET_BYTES).contains(&password.len()) {
            return Err(Error::TooLong);
        }
        let policy = self.policy()?;
        let [main, next] = names()?;
        let binding = Binding::new([(FINGERPRINT, fingerprint)]).ok_or(Error::Internal)?;
        let _held = self.lock()?;
        let file = self.load()?;
        self.write_entry(
            file,
            &Writing {
                name: main,
                binding,
                secret: password,
                drop: vec![next],
                steps: ["pending", "commit"],
            },
            policy,
            gate,
        )?;
        Ok(())
    }

    /// A re-wrap's first half (design 0013, "The re-wrap"): the new vault's
    /// credential, `password` bound to `after` (the digest of the vault file
    /// about to be written), written before that vault commits. `before` is
    /// the digest of the vault file it replaces, if there is one.
    ///
    /// - **Where:** as `quick-unlock`, unless `quick-unlock` holds the
    ///   credential for `before`; then as `quick-unlock.next`, so the vault
    ///   on disk keeps its own until the new one's rename. The other name, if
    ///   it isn't that credential, names no vault, and leaves in the write
    ///   that puts the new entry.
    /// - **How:** as enroll writes ([`Secrets::write_entry`]), with the step
    ///   names `stage-pending` and `stage`. None of these writes is the
    ///   commit: the vault's rename is, so each is refused once the job is
    ///   `abandoned`.
    /// - **When:** `required` (create and import with `quick_unlock: true`)
    ///   always; otherwise (a password change) only when there is a
    ///   credential for `before`: `Ok(None)` then means the vault is written
    ///   alone, and the file is unchanged.
    ///
    /// The result holds the file's lock until [`Staged::committed`] or
    /// [`Staged::rolled_back`]. A file that doesn't read, a key-store
    /// refusal, or a write that fails refuses the operation before its
    /// vault is written; a `pending` item it leaves is settled at the next
    /// start, as enroll's.
    pub fn stage<'a>(
        &'a self,
        password: &[u8],
        before: Option<&str>,
        after: &str,
        required: bool,
        abandoned: &dyn Fn() -> bool,
    ) -> Result<Option<Staged<'a>>, Error> {
        let [main, next] = names()?;
        let held = self.lock()?;
        let file = self.load()?;
        let current = before.and_then(|digest| credential(&file, digest));
        if !required && current.is_none() {
            return Ok(None);
        }
        if !(1..=MAX_SECRET_BYTES).contains(&password.len()) {
            return Err(Error::TooLong);
        }
        let policy = self.policy()?;
        if before == Some(after) {
            // A vault written again has a fresh salt and nonce: never the
            // digest it replaces.
            return Err(Error::Internal);
        }
        let name = if current.as_ref() == Some(&main) {
            next.clone()
        } else {
            main.clone()
        };
        let drop = [main, next]
            .into_iter()
            .filter(|other| *other != name && Some(other) != current.as_ref())
            .collect();
        let binding = Binding::new([(FINGERPRINT, after)]).ok_or(Error::Internal)?;
        let not_abandoned = || !abandoned();
        let (file, key) = self.write_entry(
            file,
            &Writing {
                name: name.clone(),
                binding: binding.clone(),
                secret: password,
                drop,
                steps: ["stage-pending", "stage"],
            },
            policy,
            &Gate {
                abandoned,
                claim: &not_abandoned,
            },
        )?;
        Ok(Some(Staged {
            secrets: self,
            _held: held,
            file,
            name,
            binding,
            key,
            policy: policy.0,
        }))
    }

    /// The password quick unlock holds for the vault with digest
    /// `fingerprint` (in whichever of its two names is bound to it), opened
    /// under its key with `reason`. Nothing is changed or deleted on a
    /// failure.
    pub fn password(&self, fingerprint: &str, reason: Reason) -> Result<Secret, Error> {
        let file = {
            let _held = self.lock()?;
            self.load()?
        };
        let name = credential(&file, fingerprint).ok_or(Error::NotEnabled)?;
        let binding = file.binding(&name).ok_or(Error::NotEnabled)?.clone();
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

    /// `quick_unlock.disable`: the entry removed (both names), and its key
    /// moved into `forget` if nothing else is under it, in one write,
    /// claimed through `gate`. No entry: nothing to do.
    pub fn disable(&self, gate: &Gate<'_>) -> Result<(), Error> {
        let _held = self.lock()?;
        let file = self.load()?;
        let next = without_quick_unlock(&file)?;
        if next == file {
            return Ok(());
        }
        if (gate.abandoned)() {
            return Err(Error::Abandoned);
        }
        self.write(&next, "remove", gate.claim)?;
        self.poke();
        Ok(())
    }

    /// `vault.delete`, once the password opened the vault file, whose
    /// digest is `vault` (design 0013, "Forgetting an item"). `claim` is the
    /// vault's commit claim.
    ///
    /// - **With quick unlock's entry** (under either name): the entries'
    ///   removal (their key moved into `forget` if nothing else is under
    ///   it) and the vault's are one journaled operation
    ///   ([`crate::delete_journal`]), committed by the journal's write. Then
    ///   the drain forgets the key.
    /// - **Without it:** the file doesn't change, and the vault is removed
    ///   as 0001 removes it, committed at the unlink.
    ///
    /// A file that can't be read (missing is empty, and has no entry), or
    /// a staged write or journal write that fails, refuses the delete: the
    /// vault, the entry and its key stay as they were, so nothing the file
    /// names is ever left unnamed.
    pub fn delete_vault(&self, vault: &str, claim: &dyn Fn() -> bool) -> Result<Done, Error> {
        let _held = self.lock()?;
        let file = self.load()?;
        // Quick unlock's entry under either name (design 0013, "The
        // re-wrap"): both leave with the vault.
        let next = without_quick_unlock(&file)?;
        if next == file {
            return match fsx::remove(&self.dir.join(crate::vault::VAULT_FILE), claim) {
                Ok(Some(done)) => Ok(done),
                Ok(None) => Err(Error::Abandoned),
                Err(e) => Err(Error::VaultStorage(io_kind(&e))),
            };
        }
        let text = next.text();
        let check = |bytes: &[u8]| SecretsFile::parse(bytes).is_ok_and(|read| read == next);
        match crate::delete_journal::delete(&self.dir, text.as_bytes(), vault, &check, claim) {
            Ok(done) => {
                self.set_view(view_of(&next));
                self.poke();
                Ok(done)
            }
            Err(crate::delete_journal::Error::Abandoned) => Err(Error::Abandoned),
            Err(crate::delete_journal::Error::Io(e)) => Err(Error::Write(io_kind(&e))),
            Err(crate::delete_journal::Error::Check) => {
                crate::log::error(
                    "the staged secrets file of a vault delete failed its check",
                    serde_json::json!({}),
                );
                Err(Error::Internal)
            }
        }
    }
}

/// A re-wrap's credential, written before its vault commits
/// ([`Secrets::stage`]). It holds the secrets file's lock, the file as
/// written, and the key the entry is under, until the vault's write ends:
/// then [`Staged::committed`] or [`Staged::rolled_back`].
pub struct Staged<'a> {
    secrets: &'a Secrets,
    _held: MutexGuard<'a, ()>,
    file: SecretsFile,
    name: EntryName,
    binding: Binding,
    key: WrapKey,
    policy: Policy,
}

impl Staged<'_> {
    /// The vault committed: one write leaves only `quick-unlock`, the new
    /// vault's credential. Staged as `quick-unlock.next`, the entry is
    /// sealed again under `quick-unlock` with the key this holds, so no
    /// key-store call follows the commit; staged as `quick-unlock`, the old
    /// vault's `quick-unlock.next` leaves. A failure is logged, not
    /// answered: the commit has happened, and the entry staged is the new
    /// vault's credential under either name until the next start removes
    /// the other.
    pub fn committed(self, password: &[u8]) {
        let folded = (|| -> Result<SecretsFile, Error> {
            let [main, next] = names()?;
            let mut out = self.file.clone();
            if self.name == next {
                if out.entry_key(&main).is_some() {
                    out = out.remove(&main).map_err(refused)?;
                }
                out = out
                    .put(
                        self.policy,
                        &self.key,
                        Put {
                            name: main,
                            binding: self.binding.clone(),
                            secret: password,
                        },
                        &mut OsRng,
                    )
                    .map_err(refused)?;
                out = out.remove(&next).map_err(refused)?;
            } else if out.entry_key(&next).is_some() {
                out = out.remove(&next).map_err(refused)?;
            }
            Ok(out)
        })();
        let written = folded.and_then(|out| {
            if out != self.file {
                self.secrets.write(&out, "fold", &|| true)?;
                if !out.forget_list().is_empty() {
                    self.secrets.poke();
                }
            }
            Ok(())
        });
        if let Err(error) = written {
            crate::log::warn(
                "could not fold a re-wrapped quick-unlock entry; the next start settles it",
                serde_json::json!({ "error": format!("{error:?}") }),
            );
        }
    }

    /// The vault didn't commit: the entry staged leaves again, its key into
    /// `forget` if nothing else is under it. A failure is logged: the entry
    /// names no vault, and the next start removes it.
    pub fn rolled_back(self) {
        let written = (|| -> Result<(), Error> {
            if self.file.entry_key(&self.name).is_none() {
                return Ok(());
            }
            let out = self.file.remove(&self.name).map_err(refused)?;
            self.secrets.write(&out, "rollback", &|| true)?;
            if !out.forget_list().is_empty() {
                self.secrets.poke();
            }
            Ok(())
        })();
        if let Err(error) = written {
            crate::log::warn(
                "could not take back a re-wrap's quick-unlock entry; the next start removes it",
                serde_json::json!({ "error": format!("{error:?}") }),
            );
        }
    }
}

/// A change to entries outside quick unlock's (design 0013, "RPC API
/// keys"): what [`Secrets::change_entries`] puts, under the `Unattended`
/// key, and takes off.
#[derive(Default)]
pub struct Change {
    pub put: Vec<(EntryName, zeroize::Zeroizing<Vec<u8>>)>,
    pub remove: Vec<EntryName>,
}

impl Change {
    pub fn is_empty(&self) -> bool {
        self.put.is_empty() && self.remove.is_empty()
    }
}

impl Secrets {
    /// The entries' names whose name starts with `prefix`, from the file as
    /// it stands. No key is opened and the key store isn't asked.
    pub fn entry_names(&self, prefix: &str) -> Result<Vec<EntryName>, Error> {
        let file = {
            let _held = self.lock()?;
            self.load()?
        };
        Ok(file
            .entry_names()
            .filter(|name| name.as_str().starts_with(prefix))
            .cloned()
            .collect())
    }

    /// Each entry whose name starts with `prefix`, bound to `{}`, opened
    /// under its key (no reason: these are `Unattended`).
    pub fn open_entries(&self, prefix: &str) -> Result<Vec<(EntryName, Secret)>, Error> {
        let file = {
            let _held = self.lock()?;
            self.load()?
        };
        let mut keys: Vec<(Policy, WrapKey)> = Vec::new();
        let mut out = Vec::new();
        for name in file
            .entry_names()
            .filter(|n| n.as_str().starts_with(prefix))
        {
            let policy = file.entry_key(name).ok_or(Error::Internal)?;
            if !keys.iter().any(|(p, _)| *p == policy) {
                let sealed = file.key(policy).ok_or(Error::Internal)?;
                let key = self.store.open(&sealed, None).map_err(Error::KeyStore)?;
                keys.push((policy, key));
            }
            let key = keys
                .iter()
                .find(|(p, _)| *p == policy)
                .map(|(_, k)| k)
                .ok_or(Error::Internal)?;
            let secret = file
                .open(name, &Binding::empty(), key)
                .map_err(|_| Error::EntryRefused)?;
            out.push((name.clone(), secret));
        }
        Ok(out)
    }

    /// One change to entries outside quick unlock's, planned by `plan` from
    /// the file as it stands, under the file's lock: each put under the
    /// `Unattended` key (bound to `{}`, replacing an entry of the name), each
    /// removal after the puts. Under the committed key if there is one, in
    /// one write named `step`; otherwise a new key (the `pending` write
    /// `<step>-pending`, `create`, then the commit, which carries every put).
    /// A plan with nothing to do writes nothing. The result is the plan's.
    pub fn change_entries<T>(
        &self,
        step: &str,
        plan: impl FnOnce(&SecretsFile) -> Result<(Change, T), Error>,
    ) -> Result<T, Error> {
        let policy = Policy::Unattended;
        let caps = self.store.capabilities();
        let _held = self.lock()?;
        let file = self.load()?;
        let (change, planned) = plan(&file)?;
        if change.is_empty() {
            return Ok(planned);
        }
        // An entry of a put's name under the other key leaves first: `put`
        // can't replace it.
        let mut base = file.clone();
        for (name, _) in &change.put {
            if base.entry_key(name).is_some_and(|key| key != policy) {
                base = base.remove(name).map_err(refused)?;
            }
        }
        let puts = |mut next: SecretsFile, key: &WrapKey, from: usize| {
            for (name, secret) in &change.put[from..] {
                let put = Put {
                    name: name.clone(),
                    binding: Binding::empty(),
                    secret,
                };
                next = next.put(policy, key, put, &mut OsRng).map_err(refused)?;
            }
            Ok::<_, Error>(next)
        };
        let put = match base.key(policy) {
            _ if change.put.is_empty() => base,
            Some(sealed) => {
                let key = self.store.open(&sealed, None).map_err(Error::KeyStore)?;
                puts(base, &key, 0)?
            }
            None => {
                if !caps.offers(policy) {
                    return Err(Error::KeyStore(crate::keystore::unavailable("unsupported")));
                }
                let backend = caps.backend.ok_or(Error::Internal)?;
                let item = ItemId::random(&mut OsRng).map_err(|_| Error::Internal)?;
                let pending = match base.begin_create(policy, backend, item) {
                    Ok(pending) => pending,
                    Err(Refused::ForgetBacklog) => self
                        .drain_held(base.clone())?
                        .begin_create(policy, backend, item)
                        .map_err(refused)?,
                    Err(other) => return Err(refused(other)),
                };
                self.write(&pending, &format!("{step}-pending"), &|| true)?;
                if !pending.forget_list().is_empty() {
                    self.poke();
                }
                let (key, sealed) = self
                    .store
                    .create(policy, &Label::new(item))
                    .map_err(Error::KeyStore)?;
                if sealed.item() != item || sealed.policy() != policy || sealed.backend() != backend
                {
                    return Err(Error::Internal);
                }
                let (name, secret) = &change.put[0];
                let first = Put {
                    name: name.clone(),
                    binding: Binding::empty(),
                    secret,
                };
                let committed = pending
                    .commit(&sealed, &key, None, Some(first), &mut OsRng)
                    .map_err(refused)?;
                puts(committed, &key, 1)?
            }
        };
        let mut next = put;
        for name in &change.remove {
            if next.entry_key(name).is_some() {
                next = next.remove(name).map_err(refused)?;
            }
        }
        self.write(&next, step, &|| true)?;
        if !next.forget_list().is_empty() {
            self.poke();
        }
        Ok(planned)
    }
}

/// `file` without quick unlock's entries, under either name, each key left
/// with nothing under it moved into `forget`.
fn without_quick_unlock(file: &SecretsFile) -> Result<SecretsFile, Error> {
    let mut out = file.clone();
    for name in names()? {
        if out.entry_key(&name).is_some() {
            out = out.remove(&name).map_err(refused)?;
        }
    }
    Ok(out)
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
    let quick_unlock = names()
        .map(|names| {
            names
                .iter()
                .filter_map(|name| {
                    let policy = file.entry_key(name)?;
                    let bound = file.binding(name)?.get(FINGERPRINT)?.to_owned();
                    Some((policy, bound))
                })
                .collect()
        })
        .unwrap_or_default();
    View {
        quick_unlock,
        unreadable: false,
        records: !file.forget_list().is_empty(),
    }
}
