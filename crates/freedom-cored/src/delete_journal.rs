//! `vault.delete` with quick unlock's entry: one journaled operation over
//! the vault and the secrets file (design 0013, "Forgetting an item": the
//! secrets file joins the delete's journaled operation, in 0001's
//! multi-file form).
//!
//! 1. **Stage.** The secrets file as the delete leaves it (the entry
//!    removed, its key moved into `forget`) is written as
//!    `secrets.json.freedom-new`: exclusive create, mode 0600, fsync, read
//!    back through the handle that wrote it, directory flush. Its SHA-256
//!    is taken.
//! 2. **Commit.** `vault-delete-journal.json` names the staged file with
//!    that digest, and the vault to remove with the digest of the file the
//!    password opened. It is written durably (0001's single-file write),
//!    and the vault's commit claim comes right before its rename: that claim
//!    is the delete's commit point (0001, "Deadlines, cancellation and
//!    commit": "before the journal write of a multi-file operation").
//! 3. **Install.** The secrets file is done if it already has the journaled
//!    digest; otherwise the staged file, with that digest, is renamed over
//!    it. Then the vault: done if it is gone, removed if it has the
//!    journaled digest, and left if it is another file, which only a later
//!    write can have put there. The directory is flushed after each.
//! 4. **Finish.** The journal is removed, and the directory flushed.
//!
//! A failure or a crash before the commit leaves the vault, the entry and
//! its key in use: the staged file is removed, or, after a crash, at the
//! next start. After the commit, [`settle`] finishes the install at the next
//! start, before `core.hello` is answered: no vault, no entry, and the key
//! in `forget`.
//!
//! **While a journal is pending** (an install that failed after the commit
//! keeps it), [`settle`] runs first in every read of the vault and every
//! secrets operation, and they fail with a storage error while it can't
//! finish. So nothing reads the vault the delete committed to remove, and
//! nothing writes the secrets file over the staged one.
//!
//! **Recovery trusts nothing it reads:** a journal is acted on only if it is
//! exactly what [`delete`] writes (its fixed names, two valid digests).
//! Anything else is set aside as `vault-delete-journal.json.corrupt`, and
//! nothing is changed. So is a journal whose secrets file has neither the
//! journaled digest nor a staged file with it: the vault then stays, as do
//! the entry and its key, since the two can't change together.

use std::cell::Cell;
use std::fs::OpenOptions;
use std::io::{Seek, Write};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fsx::{self, Done};
use crate::secrets::SECRETS_FILE;
use crate::vault::{MAX_VAULT_BYTES, VAULT_FILE};

/// The delete's journal, in the identity directory.
pub const JOURNAL: &str = "vault-delete-journal.json";
/// The secrets file as the delete leaves it, staged beside it.
pub const STAGED: &str = "secrets.json.freedom-new";
/// Where a journal no writer wrote is set aside.
const CORRUPT: &str = "vault-delete-journal.json.corrupt";
const OP: &str = "vault.delete";
/// The journal is two names and two digests.
const MAX_JOURNAL: u64 = 4096;

/// Serializes [`delete`] and [`settle`]: the vault worker and the secrets
/// drain may both settle. Taken after the secrets file's lock where both
/// are held, never the other way round.
static LOCK: Mutex<()> = Mutex::new(());

fn lock() -> std::io::Result<MutexGuard<'static, ()>> {
    LOCK.lock()
        .map_err(|_| std::io::Error::other("the delete journal's lock is poisoned"))
}

/// The journal as [`delete`] writes it: 0001's record shape, `{ op, files:
/// [{ target, staged, sha256 }, { target, remove, sha256 }] }`. A member it
/// doesn't write makes it no writer's.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    op: String,
    files: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    staged: Option<String>,
    sha256: String,
    #[serde(default, skip_serializing_if = "is_false")]
    remove: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// What a journal commits to: the staged secrets file's digest, and the
/// digest of the vault to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Plan {
    secrets: String,
    vault: String,
}

impl Plan {
    fn journal(&self) -> Journal {
        Journal {
            op: OP.to_owned(),
            files: vec![
                Entry {
                    target: SECRETS_FILE.to_owned(),
                    staged: Some(STAGED.to_owned()),
                    sha256: self.secrets.clone(),
                    remove: false,
                },
                Entry {
                    target: VAULT_FILE.to_owned(),
                    staged: None,
                    sha256: self.vault.clone(),
                    remove: true,
                },
            ],
        }
    }

    /// The plan of a journal that is exactly a writer's, else `None`.
    fn of(journal: &Journal) -> Option<Plan> {
        let [secrets, vault] = journal.files.as_slice() else {
            return None;
        };
        let shaped = journal.op == OP
            && secrets.target == SECRETS_FILE
            && secrets.staged.as_deref() == Some(STAGED)
            && !secrets.remove
            && is_digest(&secrets.sha256)
            && vault.target == VAULT_FILE
            && vault.staged.is_none()
            && vault.remove
            && is_digest(&vault.sha256);
        shaped.then(|| Plan {
            secrets: secrets.sha256.clone(),
            vault: vault.sha256.clone(),
        })
    }
}

/// The plan of a record that is exactly what [`delete`] writes for it: its
/// shape ([`Plan::of`]) and its very members, so a member the writer omits
/// (`"staged": null` on the vault, `"remove": false` on the secrets file)
/// makes it no writer's, as does any other (0013, "The vault delete's
/// journal").
fn plan_of_record(record: &serde_json::Value) -> Option<Plan> {
    let journal = serde_json::from_value::<Journal>(record.clone()).ok()?;
    let plan = Plan::of(&journal)?;
    (serde_json::to_value(plan.journal()).ok()? == *record).then_some(plan)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Why [`delete`] didn't commit. Nothing changed in every case.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The staged file didn't read back as the file meant.
    Check,
    /// The commit claim was refused (cancelled, revoked, out of time).
    Abandoned,
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

/// The journaled delete (see the module documentation). `secrets` is the
/// secrets file as the delete leaves it, which `check` must accept when
/// read back; `vault` is the digest of the vault file the password opened;
/// `claim` is the vault's commit claim. The caller holds the secrets file's
/// lock, and has settled any earlier journal (reading the file does).
///
/// `Ok`: committed, and the reply is success. An install that fails after
/// the commit is logged and answered as not durable: the journal stays, and
/// [`settle`] finishes it before anything reads the vault or the secrets
/// file again.
pub fn delete(
    dir: &Path,
    secrets: &[u8],
    vault: &str,
    check: &dyn Fn(&[u8]) -> bool,
    claim: &dyn Fn() -> bool,
) -> Result<Done, Error> {
    let _held = lock()?;
    crate::testhooks::secrets_step("before-delete-stage");
    let staged = dir.join(STAGED);
    let digest = match stage(dir, secrets, check) {
        Ok(digest) => digest,
        Err(error) => {
            let _ = std::fs::remove_file(&staged);
            return Err(error);
        }
    };
    crate::testhooks::secrets_step("before-delete-journal");
    let plan = Plan {
        secrets: digest,
        vault: vault.to_owned(),
    };
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
                // Its temp file written and flushed, not yet renamed.
                crate::testhooks::secrets_step("before-delete-journal-rename");
            }
            // As if the journal's rename failed, after the claim.
            claimed.get() && !crate::testhooks::secrets_fails("delete-journal")
        },
    );
    let journaled = match written {
        Ok(done) => done,
        Err(error) => {
            let _ = std::fs::remove_file(&staged);
            return Err(match error {
                fsx::WriteError::Abandoned if claimed.get() => Error::Io(std::io::Error::other(
                    "the journal's rename failed (test hook)",
                )),
                fsx::WriteError::Abandoned => Error::Abandoned,
                fsx::WriteError::Io(e) => Error::Io(e),
                fsx::WriteError::Check(_) => Error::Check,
            });
        }
    };
    crate::testhooks::secrets_step("after-delete-journal");
    // Committed: what follows is the install, which [`settle`] repeats.
    let finished = match install(dir, &plan) {
        Ok(Installed::Done) => finish(dir),
        Ok(Installed::Corrupt) => Err(std::io::Error::other(
            "the staged secrets file is gone before its install",
        )),
        Err(e) => Err(e),
    };
    match finished {
        Ok(done) if journaled == Done::Durable => Ok(done),
        Ok(_) => Ok(Done::NotDurable),
        Err(e) => {
            crate::log::error(
                "a committed vault delete's install failed; its journal stays",
                serde_json::json!({ "error": e.kind().to_string() }),
            );
            Ok(Done::NotDurable)
        }
    }
}

/// Step 1: writes the staged secrets file, and returns its digest.
fn stage(dir: &Path, secrets: &[u8], check: &dyn Fn(&[u8]) -> bool) -> Result<String, Error> {
    let staged = dir.join(STAGED);
    // A leftover of a delete that never committed: no journal names it.
    match std::fs::remove_file(&staged) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::Io(e)),
    }
    if crate::testhooks::secrets_fails("delete-stage") {
        return Err(Error::Io(std::io::Error::other(
            "the staged secrets file's write failed (test hook)",
        )));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&staged)?;
    file.write_all(secrets)?;
    file.sync_all()?;
    file.rewind()?;
    match fsx::read_at_most(&file, fc_keystore::MAX_FILE_BYTES as u64)? {
        Some(back) if back == secrets && check(&back) => {}
        _ => return Err(Error::Check),
    }
    // The staged name is durable before the journal names it.
    fsx::sync_dir(dir)?;
    Ok(sha256_hex(secrets))
}

enum Installed {
    Done,
    /// The secrets file has neither the journaled digest nor a staged file
    /// with it: the two files can't change together.
    Corrupt,
}

/// Step 3, for [`delete`] and [`settle`] alike.
fn install(dir: &Path, plan: &Plan) -> std::io::Result<Installed> {
    let target = dir.join(SECRETS_FILE);
    let staged = dir.join(STAGED);
    let max = fc_keystore::MAX_FILE_BYTES as u64;
    let installed = digest_of(&target, max)?.is_some_and(|(digest, _)| digest == plan.secrets);
    if !installed {
        let Some((digest, file)) = digest_of(&staged, max)? else {
            return Ok(Installed::Corrupt);
        };
        if digest != plan.secrets {
            return Ok(Installed::Corrupt);
        }
        if crate::testhooks::secrets_fails("delete-install") {
            return Err(std::io::Error::other(
                "the staged secrets file's rename failed (test hook)",
            ));
        }
        // The rename moves whatever the name holds: it must still be the
        // file hashed (as 0001's install checks).
        if !fsx::same_file(&file, &staged)? {
            return Err(std::io::Error::other(
                "the staged secrets file was replaced before its rename",
            ));
        }
        drop(file);
        std::fs::rename(&staged, &target)?;
        fsx::sync_rename(dir, &target)?;
    }
    crate::testhooks::secrets_step("after-delete-secrets");
    let vault = dir.join(VAULT_FILE);
    match digest_of(&vault, MAX_VAULT_BYTES)? {
        None => {}
        Some((digest, file)) if digest == plan.vault => {
            if !fsx::same_file(&file, &vault)? {
                return Err(std::io::Error::other(
                    "the vault file was replaced before its removal",
                ));
            }
            drop(file);
            match std::fs::remove_file(&vault) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            fsx::sync_dir(dir)?;
        }
        Some(_) => crate::log::warn(
            "a vault delete's journal names another vault file; it stays",
            serde_json::json!({}),
        ),
    }
    crate::testhooks::secrets_step("after-delete-vault");
    Ok(Installed::Done)
}

/// The SHA-256 of the regular file at `path` (never through a symlink, at
/// most `max` bytes), with its open handle. `None`: nothing there, or
/// something else (not a regular file, or past the bound), which no journal
/// names.
fn digest_of(path: &Path, max: u64) -> std::io::Result<Option<(String, std::fs::File)>> {
    let file = match fsx::open_regular(path, false)? {
        fsx::Regular::File(file) => file,
        fsx::Regular::Missing | fsx::Regular::Other => return Ok(None),
    };
    Ok(fsx::read_at_most(&file, max)?.map(|bytes| (sha256_hex(&bytes), file)))
}

/// Step 4: the journal removed, and the directory flushed.
fn finish(dir: &Path) -> std::io::Result<Done> {
    match std::fs::remove_file(dir.join(JOURNAL)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let done = fsx::flushed(fsx::sync_dir(dir));
    crate::testhooks::secrets_step("after-delete-done");
    Ok(done)
}

/// What [`settle`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    /// No journal.
    Nothing,
    /// A committed delete, finished.
    Finished,
    /// A journal no writer wrote, or one whose secrets file can't be
    /// installed: set aside, nothing changed.
    SetAside,
}

/// Finishes a committed delete whose journal is still there: at start,
/// and first in every read of the vault and every secrets operation. `Err`:
/// the journal stays, and the caller must not act on the vault or the
/// secrets file.
pub fn settle(dir: &Path) -> std::io::Result<Settled> {
    let _held = lock()?;
    let path = dir.join(JOURNAL);
    let plan = match fsx::open_regular(&path, false)? {
        fsx::Regular::Missing => return Ok(Settled::Nothing),
        fsx::Regular::Other => None,
        fsx::Regular::File(file) => fsx::read_at_most(&file, MAX_JOURNAL)?
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .as_ref()
            .and_then(plan_of_record),
    };
    let Some(plan) = plan else {
        set_aside(dir)?;
        return Ok(Settled::SetAside);
    };
    match install(dir, &plan)? {
        Installed::Done => {
            let _ = finish(dir)?;
            Ok(Settled::Finished)
        }
        Installed::Corrupt => {
            set_aside(dir)?;
            Ok(Settled::SetAside)
        }
    }
}

/// Renames the journal aside, so that nothing acts on it again, and removes
/// the staged file it may have named.
fn set_aside(dir: &Path) -> std::io::Result<()> {
    crate::log::error(
        "a vault delete's journal can't be finished; set aside, nothing changed",
        serde_json::json!({}),
    );
    std::fs::rename(dir.join(JOURNAL), dir.join(CORRUPT))?;
    match std::fs::remove_file(dir.join(STAGED)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    fsx::sync_dir(dir)
}

/// At start, under the gate, before any job runs: a committed delete is
/// finished, and a staged secrets file that no journal names (a delete that
/// never committed) removed. `Err`: the journal stays.
pub fn startup(dir: &Path) -> std::io::Result<Settled> {
    let settled = settle(dir)?;
    match std::fs::remove_file(dir.join(STAGED)) {
        Ok(()) => crate::log::info(
            "removed the staged secrets file of a vault delete that never committed",
            serde_json::json!({}),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(settled)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn plan() -> Plan {
        Plan {
            secrets: digest('a'),
            vault: digest('b'),
        }
    }

    #[test]
    fn only_a_writers_journal_has_a_plan() {
        let journal = plan().journal();
        assert_eq!(Plan::of(&journal), Some(plan()));
        let text = serde_json::to_value(&journal).unwrap();
        assert_eq!(
            text,
            serde_json::json!({ "op": "vault.delete", "files": [
                { "target": "secrets.json", "staged": "secrets.json.freedom-new", "sha256": digest('a') },
                { "target": "identity-vault.json", "sha256": digest('b'), "remove": true },
            ] })
        );
        let changed = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut value = text.clone();
            change(&mut value);
            plan_of_record(&value)
        };
        assert_eq!(changed(&|_| {}), Some(plan()));
        let refused: [&dyn Fn(&mut serde_json::Value); 13] = [
            // A member the writer omits, present with its default.
            &|v| v["files"][1]["staged"] = serde_json::Value::Null,
            &|v| v["files"][0]["remove"] = false.into(),
            // Or present with any value, or one it never writes.
            &|v| v["files"][1]["staged"] = STAGED.into(),
            &|v| v["files"][0]["extra"] = 1.into(),
            &|v| v["op"] = "nodes.write_identity".into(),
            &|v| v["files"][0]["target"] = "../secrets.json".into(),
            &|v| v["files"][0]["staged"] = "other".into(),
            &|v| v["files"][0]["sha256"] = digest('A').into(),
            &|v| v["files"][1]["target"] = "secrets.json".into(),
            &|v| v["files"][1]["remove"] = false.into(),
            &|v| v["files"][1]["sha256"] = "ab".into(),
            &|v| v["extra"] = 1.into(),
            &|v| {
                let files = v["files"].as_array_mut().unwrap();
                files.swap(0, 1);
            },
        ];
        for change in refused {
            assert_eq!(changed(change), None);
        }
        assert_eq!(
            changed(&|v| {
                v["files"].as_array_mut().unwrap().pop();
            }),
            None
        );
    }

    #[test]
    fn a_journal_no_writer_wrote_is_set_aside_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(VAULT_FILE), b"vault").unwrap();
        std::fs::write(dir.path().join(SECRETS_FILE), b"secrets").unwrap();
        std::fs::write(dir.path().join(JOURNAL), b"{\"op\":\"vault.delete\"}").unwrap();
        assert_eq!(settle(dir.path()).unwrap(), Settled::SetAside);
        assert!(!dir.path().join(JOURNAL).exists());
        assert!(dir.path().join(CORRUPT).exists());
        assert_eq!(
            std::fs::read(dir.path().join(VAULT_FILE)).unwrap(),
            b"vault"
        );
        assert_eq!(
            std::fs::read(dir.path().join(SECRETS_FILE)).unwrap(),
            b"secrets"
        );
        assert_eq!(settle(dir.path()).unwrap(), Settled::Nothing);
    }

    /// A journal that would install, with a member the writer omits
    /// present at its default: set aside, nothing changed (review of #381,
    /// round 3).
    #[test]
    fn an_omitted_member_present_at_its_default_is_set_aside() {
        let aliases: [(usize, &str, serde_json::Value); 2] = [
            (1, "staged", serde_json::Value::Null),
            (0, "remove", false.into()),
        ];
        for (entry, member, value) in aliases {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(VAULT_FILE), b"vault").unwrap();
            std::fs::write(dir.path().join(SECRETS_FILE), b"before").unwrap();
            std::fs::write(dir.path().join(STAGED), b"next").unwrap();
            let plan = Plan {
                secrets: sha256_hex(b"next"),
                vault: sha256_hex(b"vault"),
            };
            let mut record = serde_json::to_value(plan.journal()).unwrap();
            record["files"][entry][member] = value;
            std::fs::write(dir.path().join(JOURNAL), record.to_string()).unwrap();
            assert_eq!(settle(dir.path()).unwrap(), Settled::SetAside, "{member}");
            assert_eq!(
                std::fs::read(dir.path().join(VAULT_FILE)).unwrap(),
                b"vault"
            );
            assert_eq!(
                std::fs::read(dir.path().join(SECRETS_FILE)).unwrap(),
                b"before"
            );
            assert!(dir.path().join(CORRUPT).exists());
        }
    }

    #[test]
    fn settle_installs_once_and_leaves_another_vault() {
        let dir = tempfile::tempdir().unwrap();
        let journal = |vault: &[u8]| {
            let plan = Plan {
                secrets: sha256_hex(b"next"),
                vault: sha256_hex(vault),
            };
            serde_json::to_vec(&plan.journal()).unwrap()
        };
        // The vault the journal names goes; the staged file is installed.
        std::fs::write(dir.path().join(VAULT_FILE), b"vault").unwrap();
        std::fs::write(dir.path().join(SECRETS_FILE), b"before").unwrap();
        std::fs::write(dir.path().join(STAGED), b"next").unwrap();
        std::fs::write(dir.path().join(JOURNAL), journal(b"vault")).unwrap();
        assert_eq!(settle(dir.path()).unwrap(), Settled::Finished);
        assert!(!dir.path().join(VAULT_FILE).exists());
        assert!(!dir.path().join(STAGED).exists());
        assert!(!dir.path().join(JOURNAL).exists());
        assert_eq!(
            std::fs::read(dir.path().join(SECRETS_FILE)).unwrap(),
            b"next"
        );
        // Again, the secrets file already installed: another vault, written
        // since, stays.
        std::fs::write(dir.path().join(VAULT_FILE), b"another").unwrap();
        std::fs::write(dir.path().join(JOURNAL), journal(b"vault")).unwrap();
        assert_eq!(settle(dir.path()).unwrap(), Settled::Finished);
        assert_eq!(
            std::fs::read(dir.path().join(VAULT_FILE)).unwrap(),
            b"another"
        );
        // The staged file gone and the secrets file not installed: set
        // aside, and the vault stays.
        std::fs::write(dir.path().join(SECRETS_FILE), b"before").unwrap();
        std::fs::write(dir.path().join(JOURNAL), journal(b"another")).unwrap();
        assert_eq!(settle(dir.path()).unwrap(), Settled::SetAside);
        assert_eq!(
            std::fs::read(dir.path().join(VAULT_FILE)).unwrap(),
            b"another"
        );
        assert_eq!(
            std::fs::read(dir.path().join(SECRETS_FILE)).unwrap(),
            b"before"
        );
    }
}
