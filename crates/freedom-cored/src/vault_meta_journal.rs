//! `vault.create` and `vault.import` with `vault_meta` moved: the vault and
//! `vault-meta.json` installed as one journaled operation (design 0013,
//! "The vault and its metadata, one write"; PRF-5c-2), modelled on the
//! vault delete's ([`crate::delete_journal`]).
//!
//! 1. **Stage.** `identity-vault.json.freedom-new` and
//!    `vault-meta.json.freedom-new`: exclusive create, mode 0600, fsync,
//!    read back through the handle that wrote each, then a directory flush.
//!    The digest of each file they replace is taken (`before`, null where
//!    there is none).
//! 2. **Commit.** `vault-meta-journal.json`, by 0001's single-file write.
//!    The vault's commit claim comes right before its rename (0001: "before
//!    the journal write of a multi-file operation"): the journal's write is
//!    the commit point.
//! 3. **Install.** Every file is checked before either is renamed: a file
//!    is done if it has the journaled digest; otherwise it can be installed
//!    if its staged file has that digest and the target is still `before`.
//!    Only when both are done or can be installed is each staged file not
//!    yet done renamed over its target, the vault's first, with a directory
//!    flush after each.
//! 4. **Finish.** The journal is unlinked, then the directory flushed.
//!
//! **Before the commit** a failure or a crash changes nothing: the staged
//! files are removed (after a crash, at the next start). **After it**, a
//! failure the install or the finish returns answers the committed result
//! with `durable: false`, and the journal stays: [`settle`] finishes it at
//! start, before `core.hello` is answered, in `freedom-cored recover`, and
//! first in every read of the vault, every `accounts.*` call and every
//! secrets-file operation, which fail with `storage` while it can't.
//!
//! **A record with `quick_unlock`** whose vault isn't installed yet installs
//! it only while the secrets file has an entry bound to the staged vault's
//! digest: an older core removes that entry at its start, and a Quick Setup
//! vault installed without it would open only with the recovery phrase.
//!
//! **Recovery trusts nothing it reads:** a record that isn't exactly a
//! writer's, a file that has neither its digest nor a staged file with it
//! over its `before`, or a quick-unlock record without its credential is
//! renamed to `vault-meta-journal.json.corrupt`, its staged files removed,
//! and nothing else changed. One lock, the delete journal's, serializes the
//! write, both journals' recovery and the delete.

use std::cell::Cell;
use std::fs::OpenOptions;
use std::io::{Seek, Write as _};
use std::path::Path;

use fc_store::fsx::{self, Done};
use fc_wallet_state::vault_meta;
use serde::{Deserialize, Serialize};

use crate::delete_journal::{lock, sha256_hex};
use crate::secrets::Secrets;
use crate::vault::{MAX_VAULT_BYTES, VAULT_FILE};

/// The journal, in the identity directory.
pub const JOURNAL: &str = "vault-meta-journal.json";
/// The new vault, staged beside it.
pub const VAULT_STAGED: &str = "identity-vault.json.freedom-new";
/// The new metadata, staged beside it.
pub const META_STAGED: &str = "vault-meta.json.freedom-new";
/// Where a record recovery can't act on is set aside.
pub const CORRUPT: &str = "vault-meta-journal.json.corrupt";
/// Two entries of fixed names and digests.
const MAX_JOURNAL: u64 = 4096;
const META_MAX: u64 = vault_meta::MAX_FILE_BYTES as u64;

/// The operation a record is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Create,
    Import,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::Create => "vault.create",
            Op::Import => "vault.import",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    op: String,
    quick_unlock: bool,
    files: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    target: String,
    staged: String,
    before: Option<String>,
    sha256: String,
}

/// One file of a record: the digest it replaces and the digest it installs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    before: Option<String>,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Plan {
    op: Op,
    quick_unlock: bool,
    vault: Target,
    meta: Target,
}

const FILES: [(&str, &str); 2] = [
    (VAULT_FILE, VAULT_STAGED),
    (vault_meta::FILE_NAME, META_STAGED),
];

impl Plan {
    fn journal(&self) -> Journal {
        let entry = |(target, staged): (&str, &str), t: &Target| Entry {
            target: target.to_owned(),
            staged: staged.to_owned(),
            before: t.before.clone(),
            sha256: t.sha256.clone(),
        };
        Journal {
            op: self.op.name().to_owned(),
            quick_unlock: self.quick_unlock,
            files: vec![entry(FILES[0], &self.vault), entry(FILES[1], &self.meta)],
        }
    }

    fn of(journal: &Journal) -> Option<Plan> {
        let op = [Op::Create, Op::Import]
            .into_iter()
            .find(|op| op.name() == journal.op)?;
        let [vault, meta] = journal.files.as_slice() else {
            return None;
        };
        let target = |entry: &Entry, (name, staged): (&str, &str)| {
            let shaped = entry.target == name
                && entry.staged == staged
                && entry.before.as_deref().is_none_or(is_digest)
                && is_digest(&entry.sha256);
            shaped.then(|| Target {
                before: entry.before.clone(),
                sha256: entry.sha256.clone(),
            })
        };
        Some(Plan {
            op,
            quick_unlock: journal.quick_unlock,
            vault: target(vault, FILES[0])?,
            meta: target(meta, FILES[1])?,
        })
    }
}

/// The plan of a record that is exactly what [`write`] writes: its shape
/// and its very members, each once (as the delete journal's).
fn plan_of_record(bytes: &[u8]) -> Option<Plan> {
    let journal = serde_json::from_slice::<Journal>(bytes).ok()?;
    let record = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    let plan = Plan::of(&journal)?;
    (serde_json::to_value(plan.journal()).ok()? == record).then_some(plan)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A test build's returned failure at `step` of the install or the finish
/// (`vault_meta_journal:<step>` in `FREEDOM_CORED_TEST_GRANT_WRITE_FAIL`,
/// read at each step, so a test turns it on and off while the core runs).
fn fails(step: &str) -> bool {
    crate::testhooks::grant_write_fails("vault_meta_journal", step)
}

fn hook_error(step: &str) -> std::io::Error {
    std::io::Error::other(format!("{step} failed (test hook)"))
}

/// Why [`write`] didn't commit. Nothing changed in every case.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// A staged file didn't read back as the file meant.
    Check,
    /// The commit claim was refused (cancelled, revoked, out of time).
    Abandoned,
    /// The claim was taken, then the journal's rename failed.
    NotWritten,
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

/// A committed write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Written {
    /// Both files installed and the journal gone.
    Finished(Done),
    /// An install or the finish failed: the journal stays for [`settle`].
    Pending,
}

/// What [`write`] installs.
pub struct Pair<'a> {
    pub op: Op,
    /// A credential bound to the new vault was staged before this.
    pub quick_unlock: bool,
    pub vault: &'a [u8],
    /// The staged vault, read back, must pass it (it decrypts to the
    /// mnemonic meant).
    pub check: &'a dyn Fn(&[u8]) -> bool,
    pub meta: &'a [u8],
}

/// The journaled write (see the module documentation). `claim` is the
/// vault's commit claim. The caller has settled any earlier journal
/// (reading the vault does).
pub fn write(dir: &Path, pair: &Pair<'_>, claim: &dyn Fn() -> bool) -> Result<Written, Error> {
    let _held = lock()?;
    crate::testhooks::secrets_step("before-meta-stage");
    let staged = (|| -> Result<Plan, Error> {
        let vault_before = before(dir, VAULT_FILE, MAX_VAULT_BYTES, false)?;
        let meta_before = before(dir, vault_meta::FILE_NAME, META_MAX, true)?;
        stage(dir, VAULT_STAGED, pair.vault, MAX_VAULT_BYTES, pair.check)?;
        stage(dir, META_STAGED, pair.meta, META_MAX, &|_| true)?;
        // The staged names are durable before the journal names them.
        fsx::sync_dir(dir)?;
        Ok(Plan {
            op: pair.op,
            quick_unlock: pair.quick_unlock,
            vault: Target {
                before: vault_before,
                sha256: sha256_hex(pair.vault),
            },
            meta: Target {
                before: meta_before,
                sha256: sha256_hex(pair.meta),
            },
        })
    })();
    let plan = match staged {
        Ok(plan) => plan,
        Err(error) => {
            let _ = remove_staged(dir);
            return Err(error);
        }
    };
    crate::testhooks::secrets_step("before-meta-journal");
    let text = serde_json::to_vec(&plan.journal())
        .map_err(|_| Error::Io(std::io::Error::other("the journal doesn't serialize")))?;
    let claimed = Cell::new(false);
    let written = fsx::replace(
        &dir.join(JOURNAL),
        &text,
        |file| match fsx::read_at_most(file, MAX_JOURNAL) {
            Ok(Some(back)) if back == text => Ok(()),
            _ => Err("the staged journal doesn't read back".to_owned()),
        },
        || {
            claimed.set(claim());
            if claimed.get() {
                crate::testhooks::secrets_step("before-meta-journal-rename");
            }
            claimed.get() && !crate::testhooks::secrets_fails("meta-journal")
        },
        &crate::testhooks::Swap,
    );
    let journaled = match written {
        Ok(done) => done,
        Err(error) => {
            let _ = remove_staged(dir);
            return Err(match error {
                fsx::WriteError::Abandoned if claimed.get() => Error::NotWritten,
                fsx::WriteError::Abandoned => Error::Abandoned,
                fsx::WriteError::Io(e) => Error::Io(e),
                fsx::WriteError::Check(_) => Error::Check,
            });
        }
    };
    crate::testhooks::secrets_step("after-meta-journal");
    // Committed: what follows is the install, which [`settle`] repeats.
    let finished = match install(dir, &plan) {
        Ok(Installed::Done) => finish(dir),
        Ok(other) => Err(std::io::Error::other(format!(
            "the install can't proceed: {other:?}"
        ))),
        Err(e) => Err(e),
    };
    match finished {
        Ok(done) if journaled == Done::Durable => Ok(Written::Finished(done)),
        Ok(_) => Ok(Written::Finished(Done::NotDurable)),
        Err(e) => {
            crate::log::error(
                "a committed vault write's install failed; its journal stays",
                serde_json::json!({ "error": e.to_string() }),
            );
            Ok(Written::Pending)
        }
    }
}

/// The digest of the file at `name` the write replaces, `None` if there is
/// none. Metadata that can't be read (not a regular file, or past its
/// bound) is set aside first, as `accounts.*` sets it aside; a vault that
/// can't be read refuses the write.
fn before(dir: &Path, name: &str, max: u64, aside: bool) -> Result<Option<String>, Error> {
    match state_of(&dir.join(name), max)? {
        State::Missing => Ok(None),
        State::File(digest, _) => Ok(Some(digest)),
        State::Other if aside => {
            let _ = fc_store::file::set_aside(dir, name)?;
            crate::log::warn(
                "vault-meta.json can't be read: renamed aside before the vault's write",
                serde_json::json!({}),
            );
            Ok(None)
        }
        State::Other => Err(Error::Io(std::io::Error::other(
            "the vault file isn't a regular file within its bound",
        ))),
    }
}

/// Step 1 for one file.
fn stage(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    max: u64,
    check: &dyn Fn(&[u8]) -> bool,
) -> Result<(), Error> {
    let staged = dir.join(name);
    // A leftover of a write that never committed: no journal names it.
    remove(&staged)?;
    if crate::testhooks::secrets_fails("meta-stage") {
        return Err(Error::Io(hook_error("the staged file's write")));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&staged)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.rewind()?;
    match fsx::read_at_most(&file, max)? {
        Some(back) if back == bytes && check(&back) => Ok(()),
        _ => Err(Error::Check),
    }
}

fn remove(path: &Path) -> std::io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn remove_staged(dir: &Path) -> std::io::Result<bool> {
    let vault = remove(&dir.join(VAULT_STAGED))?;
    let meta = remove(&dir.join(META_STAGED))?;
    Ok(vault || meta)
}

enum State {
    Missing,
    File(String, std::fs::File),
    /// Not a regular file, or past the bound: no record names it.
    Other,
}

/// The file at `path`, judged on the handle (never through a symlink, at
/// most `max` bytes), with its digest.
fn state_of(path: &Path, max: u64) -> std::io::Result<State> {
    let file = match fsx::open_regular(path, false)? {
        fsx::Regular::Missing => return Ok(State::Missing),
        fsx::Regular::Other => return Ok(State::Other),
        fsx::Regular::File(file) => file,
    };
    Ok(match fsx::read_at_most(&file, max)? {
        Some(bytes) => State::File(sha256_hex(&bytes), file),
        None => State::Other,
    })
}

/// One file at the install's check.
enum Look {
    Done,
    /// The staged file, with the journaled digest, and the target its
    /// `before`.
    Install(std::fs::File),
}

#[derive(Debug)]
enum Installed {
    Done,
    /// A file has neither its digest nor a staged file with it over its
    /// `before`.
    Corrupt,
    /// A quick-unlock record whose vault isn't installed, and whose
    /// credential is gone.
    NoCredential,
}

fn look(
    dir: &Path,
    (name, staged): (&str, &str),
    t: &Target,
    max: u64,
) -> std::io::Result<Option<Look>> {
    let now = state_of(&dir.join(name), max)?;
    let replaceable = match (&now, &t.before) {
        (State::File(digest, _), _) if *digest == t.sha256 => return Ok(Some(Look::Done)),
        (State::Missing, None) => true,
        (State::File(digest, _), Some(before)) => digest == before,
        _ => false,
    };
    if !replaceable {
        return Ok(None);
    }
    Ok(match state_of(&dir.join(staged), max)? {
        State::File(digest, file) if digest == t.sha256 => Some(Look::Install(file)),
        _ => None,
    })
}

/// Step 3, for [`write`] and [`settle`] alike.
fn install(dir: &Path, plan: &Plan) -> std::io::Result<Installed> {
    let vault = look(dir, FILES[0], &plan.vault, MAX_VAULT_BYTES)?;
    let meta = look(dir, FILES[1], &plan.meta, META_MAX)?;
    let (Some(vault), Some(meta)) = (vault, meta) else {
        return Ok(Installed::Corrupt);
    };
    if plan.quick_unlock
        && matches!(vault, Look::Install(_))
        && !crate::secrets::has_credential(dir, &plan.vault.sha256)?
    {
        return Ok(Installed::NoCredential);
    }
    rename(dir, vault, FILES[0], "vault")?;
    crate::testhooks::secrets_step("after-meta-install-vault");
    rename(dir, meta, FILES[1], "meta")?;
    crate::testhooks::secrets_step("after-meta-install-meta");
    Ok(Installed::Done)
}

/// Installs one file, then flushes the directory. A file already done is
/// flushed again: an earlier rename whose flush failed is made durable
/// before the journal goes.
fn rename(dir: &Path, look: Look, (name, staged): (&str, &str), step: &str) -> std::io::Result<()> {
    let (target, staged) = (dir.join(name), dir.join(staged));
    let Look::Install(file) = look else {
        if fails(&format!("{step}-flush")) {
            return Err(hook_error(&format!("the {step}'s flush")));
        }
        return fsx::sync_dir(dir);
    };
    if fails(&format!("{step}-rename")) {
        return Err(hook_error(&format!("the {step}'s rename")));
    }
    // The rename moves whatever the name holds: it must still be the file
    // hashed (as 0001's install checks).
    if !fsx::same_file(&file, &staged)? {
        return Err(std::io::Error::other(
            "a staged file was replaced before its rename",
        ));
    }
    drop(file);
    std::fs::rename(&staged, &target)?;
    if fails(&format!("{step}-flush")) {
        return Err(hook_error(&format!("the {step}'s flush")));
    }
    fsx::sync_rename(dir, &target)
}

/// Step 4: the journal unlinked, then the directory flushed (0001's durable
/// remove). A failed flush is past the unlink: not durable, not an error.
fn finish(dir: &Path) -> std::io::Result<Done> {
    if fails("unlink") {
        return Err(hook_error("the journal's unlink"));
    }
    remove(&dir.join(JOURNAL))?;
    let done = if fails("finish-flush") {
        Done::NotDurable
    } else {
        fsx::flushed(fsx::sync_dir(dir))
    };
    crate::testhooks::secrets_step("after-meta-done");
    Ok(done)
}

/// What [`settle`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settled {
    /// No journal.
    Nothing,
    /// A committed write finished. `vault` is the installed vault's digest,
    /// whose credential the secrets file keeps when `quick_unlock`.
    Finished { quick_unlock: bool, vault: String },
    /// Set aside, nothing else changed.
    SetAside,
}

/// Whether a journal is there (a cheap look before taking any lock: only
/// the vault worker writes one, and it serializes with every caller).
pub fn exists(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir.join(JOURNAL)).is_ok()
}

/// Finishes a committed write whose journal is still there. `Err`: the
/// journal stays, and the caller must not act on the vault, the metadata
/// or the secrets file.
pub fn settle(dir: &Path) -> std::io::Result<Settled> {
    if !exists(dir) {
        return Ok(Settled::Nothing);
    }
    let _held = lock()?;
    let plan = match fsx::open_regular(&dir.join(JOURNAL), false)? {
        fsx::Regular::Missing => return Ok(Settled::Nothing),
        fsx::Regular::Other => None,
        fsx::Regular::File(file) => fsx::read_at_most(&file, MAX_JOURNAL)?
            .as_deref()
            .and_then(plan_of_record),
    };
    let Some(plan) = plan else {
        set_aside(dir, "not a writer's record")?;
        return Ok(Settled::SetAside);
    };
    match install(dir, &plan)? {
        Installed::Done => {
            // Past the unlink, a failed flush leaves nothing to redo.
            let _ = finish(dir)?;
            Ok(Settled::Finished {
                quick_unlock: plan.quick_unlock,
                vault: plan.vault.sha256,
            })
        }
        other => {
            set_aside(dir, &format!("{other:?}"))?;
            Ok(Settled::SetAside)
        }
    }
}

fn set_aside(dir: &Path, why: &str) -> std::io::Result<()> {
    crate::log::error(
        "a vault write's journal can't be finished; set aside, nothing changed",
        serde_json::json!({ "why": why }),
    );
    std::fs::rename(dir.join(JOURNAL), dir.join(CORRUPT))?;
    remove_staged(dir)?;
    fsx::sync_dir(dir)
}

/// Recovery first, for a job or an `accounts.*` call: with `secrets`, under
/// its lock, so a finished quick-unlock record leaves only the new vault's
/// credential ([`Secrets::recover`]). `Err`: the journal stays.
pub fn recover(dir: &Path, secrets: Option<&Secrets>) -> std::io::Result<()> {
    if !exists(dir) {
        return Ok(());
    }
    if let Some(secrets) = secrets {
        let _ = secrets.recover();
    }
    settle(dir).map(|_| ())
}

/// The journaled vault of a writer's record still there, read as the vault
/// is read: the target once installed, else its staged file. For
/// `vault.reconcile` while the install can't finish.
pub fn journaled_vault(dir: &Path) -> std::io::Result<Option<String>> {
    let Some(plan) = plan_in(dir)? else {
        return Ok(None);
    };
    for name in [VAULT_FILE, VAULT_STAGED] {
        let fsx::Regular::File(file) = fsx::open_regular(&dir.join(name), false)? else {
            continue;
        };
        if let Some(bytes) = fsx::read_at_most(&file, MAX_VAULT_BYTES)?
            && sha256_hex(&bytes) == plan.vault.sha256
        {
            return Ok(String::from_utf8(bytes).ok());
        }
    }
    Ok(None)
}

fn plan_in(dir: &Path) -> std::io::Result<Option<Plan>> {
    Ok(match fsx::open_regular(&dir.join(JOURNAL), false)? {
        fsx::Regular::File(file) => fsx::read_at_most(&file, MAX_JOURNAL)?
            .as_deref()
            .and_then(plan_of_record),
        _ => None,
    })
}

/// At start, under the gate, before any job runs: a committed write is
/// finished, and staged files no journal names (a write that never
/// committed) are removed. `Err`: the journal stays, and so do they.
pub fn startup(dir: &Path) -> std::io::Result<Settled> {
    let settled = settle(dir)?;
    if remove_staged(dir)? {
        crate::log::info(
            "removed the staged files of a vault write that never committed",
            serde_json::json!({}),
        );
    }
    Ok(settled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn plan(before: Option<String>) -> Plan {
        Plan {
            op: Op::Import,
            quick_unlock: true,
            vault: Target {
                before: before.clone(),
                sha256: digest('a'),
            },
            meta: Target {
                before,
                sha256: digest('b'),
            },
        }
    }

    #[test]
    fn only_a_writers_record_has_a_plan() {
        for before in [None, Some(digest('c'))] {
            let plan = plan(before);
            let text = serde_json::to_vec(&plan.journal()).unwrap();
            assert_eq!(plan_of_record(&text), Some(plan.clone()));
            let mut value = serde_json::to_value(plan.journal()).unwrap();
            value["files"][0].as_object_mut().unwrap().remove("before");
            let missing = serde_json::to_vec(&value).unwrap();
            assert_eq!(plan_of_record(&missing), None, "a member left out");
        }
        let good = serde_json::to_value(plan(None).journal()).unwrap();
        let mut cases = Vec::new();
        for (path, bad) in [
            ("/op", serde_json::json!("vault.delete")),
            ("/quick_unlock", serde_json::json!(1)),
            ("/files/0/target", serde_json::json!("vault-meta.json")),
            ("/files/1/staged", serde_json::json!("../x")),
            ("/files/0/sha256", serde_json::json!(digest('A'))),
            ("/files/1/before", serde_json::json!("ab")),
        ] {
            let mut value = good.clone();
            *value.pointer_mut(path).unwrap() = bad;
            cases.push(serde_json::to_vec(&value).unwrap());
        }
        let mut swapped = good.clone();
        swapped["files"].as_array_mut().unwrap().reverse();
        cases.push(serde_json::to_vec(&swapped).unwrap());
        let mut extra = good.clone();
        extra["files"][0]["remove"] = serde_json::json!(false);
        cases.push(serde_json::to_vec(&extra).unwrap());
        let text = String::from_utf8(serde_json::to_vec(&good).unwrap()).unwrap();
        cases.push(
            text.replacen("{\"op\"", "{\"op\":\"vault.create\",\"op\"", 1)
                .into_bytes(),
        );
        for case in cases {
            assert_eq!(
                plan_of_record(&case),
                None,
                "{}",
                String::from_utf8_lossy(&case)
            );
        }
    }

    fn write_plan(dir: &Path, plan: &Plan) {
        std::fs::write(
            dir.join(JOURNAL),
            serde_json::to_vec(&plan.journal()).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn nothing_is_renamed_before_both_files_are_checked() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        std::fs::write(p.join(VAULT_FILE), b"old vault").unwrap();
        std::fs::write(p.join(vault_meta::FILE_NAME), b"changed meta").unwrap();
        std::fs::write(p.join(VAULT_STAGED), b"new vault").unwrap();
        std::fs::write(p.join(META_STAGED), b"new meta").unwrap();
        let plan = Plan {
            op: Op::Import,
            quick_unlock: false,
            vault: Target {
                before: Some(sha256_hex(b"old vault")),
                sha256: sha256_hex(b"new vault"),
            },
            meta: Target {
                before: Some(sha256_hex(b"old meta")),
                sha256: sha256_hex(b"new meta"),
            },
        };
        write_plan(p, &plan);
        assert_eq!(settle(p).unwrap(), Settled::SetAside);
        assert_eq!(std::fs::read(p.join(VAULT_FILE)).unwrap(), b"old vault");
        assert_eq!(
            std::fs::read(p.join(vault_meta::FILE_NAME)).unwrap(),
            b"changed meta"
        );
        assert!(p.join(CORRUPT).exists() && !p.join(JOURNAL).exists());
        assert!(!p.join(VAULT_STAGED).exists() && !p.join(META_STAGED).exists());
        // Its `before` again: both install, the vault's first.
        std::fs::write(p.join(vault_meta::FILE_NAME), b"old meta").unwrap();
        std::fs::write(p.join(VAULT_STAGED), b"new vault").unwrap();
        std::fs::write(p.join(META_STAGED), b"new meta").unwrap();
        write_plan(p, &plan);
        assert!(matches!(settle(p).unwrap(), Settled::Finished { .. }));
        assert_eq!(std::fs::read(p.join(VAULT_FILE)).unwrap(), b"new vault");
        assert_eq!(
            std::fs::read(p.join(vault_meta::FILE_NAME)).unwrap(),
            b"new meta"
        );
        assert!(!p.join(JOURNAL).exists());
        // Both done, the journal put back: only removed.
        write_plan(p, &plan);
        assert!(matches!(settle(p).unwrap(), Settled::Finished { .. }));
        assert!(!p.join(JOURNAL).exists());
        assert_eq!(std::fs::read(p.join(VAULT_FILE)).unwrap(), b"new vault");
    }

    #[test]
    fn a_missing_target_matches_only_a_null_before() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        std::fs::write(p.join(VAULT_STAGED), b"new vault").unwrap();
        std::fs::write(p.join(META_STAGED), b"new meta").unwrap();
        let mut plan = Plan {
            op: Op::Create,
            quick_unlock: false,
            vault: Target {
                before: Some(sha256_hex(b"old")),
                sha256: sha256_hex(b"new vault"),
            },
            meta: Target {
                before: None,
                sha256: sha256_hex(b"new meta"),
            },
        };
        write_plan(p, &plan);
        assert_eq!(settle(p).unwrap(), Settled::SetAside);
        assert!(!p.join(VAULT_FILE).exists());
        plan.vault.before = None;
        std::fs::write(p.join(VAULT_STAGED), b"new vault").unwrap();
        std::fs::write(p.join(META_STAGED), b"new meta").unwrap();
        std::fs::write(p.join(vault_meta::FILE_NAME), b"there").unwrap();
        write_plan(p, &plan);
        assert_eq!(
            settle(p).unwrap(),
            Settled::SetAside,
            "a file where none was"
        );
        assert!(!p.join(VAULT_FILE).exists());
    }

    #[test]
    fn a_quick_unlock_record_needs_its_credential_until_its_vault_is_in() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        std::fs::write(p.join(VAULT_STAGED), b"new vault").unwrap();
        std::fs::write(p.join(META_STAGED), b"new meta").unwrap();
        let plan = Plan {
            op: Op::Create,
            quick_unlock: true,
            vault: Target {
                before: None,
                sha256: sha256_hex(b"new vault"),
            },
            meta: Target {
                before: None,
                sha256: sha256_hex(b"new meta"),
            },
        };
        write_plan(p, &plan);
        // No secrets file: no credential.
        assert_eq!(settle(p).unwrap(), Settled::SetAside);
        assert!(!p.join(VAULT_FILE).exists() && !p.join(vault_meta::FILE_NAME).exists());
        // The vault already in: the metadata follows, credential or not.
        std::fs::write(p.join(VAULT_FILE), b"new vault").unwrap();
        std::fs::write(p.join(META_STAGED), b"new meta").unwrap();
        write_plan(p, &plan);
        assert!(matches!(
            settle(p).unwrap(),
            Settled::Finished {
                quick_unlock: true,
                ..
            }
        ));
        assert_eq!(
            std::fs::read(p.join(vault_meta::FILE_NAME)).unwrap(),
            b"new meta"
        );
    }
}
