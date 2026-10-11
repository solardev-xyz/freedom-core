//! Multi-file node-identity writes (design 0001, "Multi-file writes").
//!
//! A node identity is several files that must change together (Bee: the
//! keystore and the config holding its password; Radicle: the key pair and
//! the config). Node directories can be outside the profile, so the journal
//! lives in the identity directory, where startup recovery always finds it.
//!
//! 1. **Stage.** Each target gets `<target>.freedom-new` (exclusive create,
//!    `0600`, fsync, directory fsync) and its SHA-256.
//! 2. **Commit.** `<identityDir>/node-identity-journal.json` is written
//!    atomically and durably, if the caller's commit gate allows it. It holds
//!    `{ op_id, node, files: [{ target, staged, sha256 }] }` (absolute paths,
//!    no key material).
//! 3. **Install.** A target that already has its journaled digest is done;
//!    otherwise its staged file is renamed over it. Then every affected
//!    directory is fsynced.
//! 4. **Finish.** `op_id` is added to `<identityDir>/node-identity-done.json`
//!    (the last 32 operations), then the journal is removed.
//!
//! A failure before the commit removes the staged files: nothing changed. A
//! failure after it keeps the journal: the result is `pending_recovery`, and
//! [`recover`] (at startup, and in `freedom-cored recover`) finishes it.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fsx;

pub const JOURNAL: &str = "node-identity-journal.json";
pub const DONE: &str = "node-identity-done.json";
const STAGED_SUFFIX: &str = ".freedom-new";
const MAX_DONE: usize = 32;
/// Node identity files are small; anything larger can't be ours.
const MAX_FILE: u64 = 1 << 20;

#[derive(Debug, Serialize, Deserialize)]
struct Journal {
    op_id: String,
    node: String,
    files: Vec<JournalFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JournalFile {
    target: PathBuf,
    staged: PathBuf,
    sha256: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct DoneList {
    ops: Vec<DoneOp>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoneOp {
    op_id: String,
    status: OpStatus,
}

/// `nodes.op_status` (design 0001, "Reconciliation").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpStatus {
    Installed,
    PendingRecovery,
    NotCommitted,
    Corrupt,
}

/// One file of an operation. The caller owns (and wipes) the contents.
pub struct FileSpec<'a> {
    pub target: PathBuf,
    pub contents: &'a [u8],
}

/// How a write ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// All four steps completed.
    Installed,
    /// Committed, but installing or finishing failed; the journal is kept.
    PendingRecovery,
    /// The commit gate refused: nothing changed.
    Abandoned,
}

/// What [`recover`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovered {
    Nothing,
    /// A leftover journal was finished with this status.
    Finished {
        op_id: String,
        status: OpStatus,
    },
}

/// Runs the four steps for one operation. An error means nothing was
/// committed (the staged files are removed).
pub fn write(
    identity_dir: &Path,
    op_id: &str,
    node: &str,
    files: &[FileSpec<'_>],
    commit: impl FnOnce() -> bool,
) -> std::io::Result<Outcome> {
    // 1. Stage.
    let mut journal = Journal {
        op_id: op_id.to_owned(),
        node: node.to_owned(),
        files: Vec::with_capacity(files.len()),
    };
    for file in files {
        match stage(file) {
            Ok(staged) => journal.files.push(staged),
            Err(e) => {
                discard(&journal);
                return Err(e);
            }
        }
    }
    // 2. Commit.
    let encoded = serde_json::to_vec(&journal).map_err(std::io::Error::other)?;
    std::fs::create_dir_all(identity_dir)?;
    match fsx::replace(&identity_dir.join(JOURNAL), &encoded, |_| Ok(()), commit) {
        Ok(_) => {}
        Err(fsx::WriteError::Abandoned) => {
            discard(&journal);
            return Ok(Outcome::Abandoned);
        }
        Err(fsx::WriteError::Io(e)) => {
            discard(&journal);
            return Err(e);
        }
        Err(fsx::WriteError::Check(reason)) => {
            discard(&journal);
            return Err(std::io::Error::other(reason));
        }
    }
    // 3 and 4. After the commit, a failure leaves the journal for recovery.
    match install(&journal).and_then(|corrupt| {
        let status = if corrupt {
            OpStatus::Corrupt
        } else {
            OpStatus::Installed
        };
        finish(identity_dir, &journal.op_id, status).map(|()| status)
    }) {
        Ok(OpStatus::Installed) => Ok(Outcome::Installed),
        // Our own staged files vanished between staging and install.
        Ok(_) => Ok(Outcome::PendingRecovery),
        Err(e) => {
            crate::log::error(
                "node identity install failed after commit",
                serde_json::json!({ "error": e.kind().to_string() }),
            );
            Ok(Outcome::PendingRecovery)
        }
    }
}

/// Finishes a leftover journal (step 3 with recovery rules, then step 4).
/// A target with the right digest is done; otherwise a staged file with the
/// right digest is renamed into place; if neither exists, the operation is
/// `corrupt` and needs a fresh write while unlocked.
pub fn recover(identity_dir: &Path) -> std::io::Result<Recovered> {
    let path = identity_dir.join(JOURNAL);
    let bytes = match read_bounded(&path)? {
        Some(bytes) => bytes,
        None => return Ok(Recovered::Nothing),
    };
    let Ok(journal) = serde_json::from_slice::<Journal>(&bytes) else {
        // Unreadable: keep it aside for inspection, never act on it.
        let aside = identity_dir.join(format!("{JOURNAL}.corrupt"));
        std::fs::rename(&path, aside)?;
        crate::log::error(
            "unreadable node identity journal set aside",
            serde_json::json!({}),
        );
        return Ok(Recovered::Nothing);
    };
    let corrupt = install(&journal)?;
    let status = if corrupt {
        OpStatus::Corrupt
    } else {
        OpStatus::Installed
    };
    finish(identity_dir, &journal.op_id, status)?;
    Ok(Recovered::Finished {
        op_id: journal.op_id,
        status,
    })
}

/// `nodes.op_status`: from the done list and the journal. A consistent node
/// directory alone doesn't count: it could still hold the old identity.
pub fn op_status(identity_dir: &Path, op_id: &str) -> std::io::Result<OpStatus> {
    let done = read_done(identity_dir)?;
    if let Some(op) = done.ops.iter().rev().find(|op| op.op_id == op_id) {
        return Ok(op.status);
    }
    if let Some(bytes) = read_bounded(&identity_dir.join(JOURNAL))?
        && serde_json::from_slice::<Journal>(&bytes).is_ok_and(|j| j.op_id == op_id)
    {
        return Ok(OpStatus::PendingRecovery);
    }
    Ok(OpStatus::NotCommitted)
}

/// Step 1 for one file. A staged file left by an earlier crashed write
/// (before its commit, so no journal names it) is replaced.
fn stage(file: &FileSpec<'_>) -> std::io::Result<JournalFile> {
    if !file.target.is_absolute() {
        return Err(std::io::Error::other(
            "node identity targets must be absolute",
        ));
    }
    let dir = file
        .target
        .parent()
        .ok_or_else(|| std::io::Error::other("target has no parent directory"))?;
    std::fs::create_dir_all(dir)?;
    let mut name = file.target.as_os_str().to_owned();
    name.push(STAGED_SUFFIX);
    let staged = PathBuf::from(name);
    match std::fs::remove_file(&staged) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut out = options.open(&staged)?;
        out.write_all(file.contents)?;
        out.sync_all()?;
        sync_dir(dir)
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&staged);
        return Err(e);
    }
    Ok(JournalFile {
        target: file.target.clone(),
        staged,
        sha256: hex_digest(file.contents),
    })
}

/// Step 3. Returns whether any file could not be installed (corrupt).
fn install(journal: &Journal) -> std::io::Result<bool> {
    let mut corrupt = false;
    let mut dirs: Vec<&Path> = Vec::new();
    for file in &journal.files {
        if digest_of(&file.target)?.as_deref() == Some(file.sha256.as_str()) {
            // Already in place; a duplicate staged copy is no longer needed.
            let _ = std::fs::remove_file(&file.staged);
        } else if digest_of(&file.staged)?.as_deref() == Some(file.sha256.as_str()) {
            std::fs::rename(&file.staged, &file.target)?;
        } else {
            corrupt = true;
            continue;
        }
        if let Some(dir) = file.target.parent()
            && !dirs.contains(&dir)
        {
            dirs.push(dir);
        }
    }
    for dir in dirs {
        sync_dir(dir)?;
    }
    Ok(corrupt)
}

/// Step 4: record the outcome, then remove the journal.
fn finish(identity_dir: &Path, op_id: &str, status: OpStatus) -> std::io::Result<()> {
    let mut done = read_done(identity_dir)?;
    done.ops.retain(|op| op.op_id != op_id);
    done.ops.push(DoneOp {
        op_id: op_id.to_owned(),
        status,
    });
    let excess = done.ops.len().saturating_sub(MAX_DONE);
    done.ops.drain(..excess);
    let encoded = serde_json::to_vec(&done).map_err(std::io::Error::other)?;
    // The done list is bookkeeping: a failed directory flush after its
    // rename doesn't matter here (the journal is removed after it anyway).
    let _flushed = fsx::replace(&identity_dir.join(DONE), &encoded, |_| Ok(()), || true).map_err(
        |e| match e {
            fsx::WriteError::Io(e) => e,
            other => std::io::Error::other(format!("{other:?}")),
        },
    )?;
    fsx::remove(&identity_dir.join(JOURNAL), || true)?;
    Ok(())
}

fn read_done(identity_dir: &Path) -> std::io::Result<DoneList> {
    match read_bounded(&identity_dir.join(DONE))? {
        // An unreadable done list is treated as empty: op_status then falls
        // back to the journal, and the next finish rewrites it.
        Some(bytes) => Ok(serde_json::from_slice(&bytes).unwrap_or_default()),
        None => Ok(DoneList::default()),
    }
}

/// Removes the staged files of an operation that didn't commit.
fn discard(journal: &Journal) {
    for file in &journal.files {
        let _ = std::fs::remove_file(&file.staged);
    }
}

/// A regular file's contents, if it exists and is at most [`MAX_FILE`].
fn read_bounded(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !metadata.is_file() || metadata.len() > MAX_FILE {
        return Ok(None);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    File::open(path)?
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

/// The SHA-256 of a file, if it exists (and could be ours).
fn digest_of(path: &Path) -> std::io::Result<Option<String>> {
    Ok(read_bounded(path)?.map(|bytes| hex_digest(&bytes)))
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn specs<'a>(dir: &Path, contents: &[&'a [u8]]) -> Vec<FileSpec<'a>> {
        contents
            .iter()
            .enumerate()
            .map(|(i, c)| FileSpec {
                target: dir.join(format!("node/f{i}")),
                contents: c,
            })
            .collect()
    }

    fn staged_left(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir.join("node"))
            .map(|entries| {
                entries
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .filter(|n| n.ends_with(STAGED_SUFFIX))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn installs_all_files_and_records_the_op() {
        let root = tempfile::tempdir().unwrap();
        let identity = root.path().join("identity");
        let files = specs(root.path(), &[b"key", b"config"]);
        let outcome = write(&identity, "op-1", "bee", &files, || true).unwrap();
        assert_eq!(outcome, Outcome::Installed);
        assert_eq!(std::fs::read(root.path().join("node/f0")).unwrap(), b"key");
        assert_eq!(
            std::fs::read(root.path().join("node/f1")).unwrap(),
            b"config"
        );
        assert!(staged_left(root.path()).is_empty());
        assert!(!identity.join(JOURNAL).exists());
        assert_eq!(op_status(&identity, "op-1").unwrap(), OpStatus::Installed);
        assert_eq!(
            op_status(&identity, "op-2").unwrap(),
            OpStatus::NotCommitted
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(root.path().join("node/f0"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn an_abandoned_write_changes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let identity = root.path().join("identity");
        std::fs::create_dir_all(root.path().join("node")).unwrap();
        std::fs::write(root.path().join("node/f0"), b"old").unwrap();
        let files = specs(root.path(), &[b"new", b"config"]);
        let outcome = write(&identity, "op-1", "bee", &files, || false).unwrap();
        assert_eq!(outcome, Outcome::Abandoned);
        assert_eq!(std::fs::read(root.path().join("node/f0")).unwrap(), b"old");
        assert!(!root.path().join("node/f1").exists());
        assert!(staged_left(root.path()).is_empty());
        assert_eq!(
            op_status(&identity, "op-1").unwrap(),
            OpStatus::NotCommitted
        );
    }

    #[test]
    fn recovery_rolls_a_committed_journal_forward() {
        let root = tempfile::tempdir().unwrap();
        let identity = root.path().join("identity");
        std::fs::create_dir_all(root.path().join("node")).unwrap();
        std::fs::write(root.path().join("node/f0"), b"old key").unwrap();
        std::fs::write(root.path().join("node/f1"), b"old config").unwrap();
        // Simulate a crash after the commit with one file installed.
        let files = specs(root.path(), &[b"new key", b"new config"]);
        let journal = Journal {
            op_id: "op-7".into(),
            node: "bee".into(),
            files: files.iter().map(|f| stage(f).unwrap()).collect(),
        };
        std::fs::rename(&journal.files[0].staged, &journal.files[0].target).unwrap();
        std::fs::create_dir_all(&identity).unwrap();
        std::fs::write(
            identity.join(JOURNAL),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        assert_eq!(
            op_status(&identity, "op-7").unwrap(),
            OpStatus::PendingRecovery
        );

        let recovered = recover(&identity).unwrap();
        assert_eq!(
            recovered,
            Recovered::Finished {
                op_id: "op-7".into(),
                status: OpStatus::Installed
            }
        );
        assert_eq!(
            std::fs::read(root.path().join("node/f0")).unwrap(),
            b"new key"
        );
        assert_eq!(
            std::fs::read(root.path().join("node/f1")).unwrap(),
            b"new config"
        );
        assert!(!identity.join(JOURNAL).exists());
        assert_eq!(op_status(&identity, "op-7").unwrap(), OpStatus::Installed);
        assert_eq!(recover(&identity).unwrap(), Recovered::Nothing);
    }

    #[test]
    fn a_journal_whose_files_are_gone_is_corrupt() {
        let root = tempfile::tempdir().unwrap();
        let identity = root.path().join("identity");
        let files = specs(root.path(), &[b"new key"]);
        let journal = Journal {
            op_id: "op-9".into(),
            node: "radicle".into(),
            files: files.iter().map(|f| stage(f).unwrap()).collect(),
        };
        std::fs::remove_file(&journal.files[0].staged).unwrap();
        std::fs::create_dir_all(&identity).unwrap();
        std::fs::write(
            identity.join(JOURNAL),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        let recovered = recover(&identity).unwrap();
        assert_eq!(
            recovered,
            Recovered::Finished {
                op_id: "op-9".into(),
                status: OpStatus::Corrupt
            }
        );
        assert_eq!(op_status(&identity, "op-9").unwrap(), OpStatus::Corrupt);
    }

    #[test]
    fn an_unreadable_journal_is_set_aside() {
        let root = tempfile::tempdir().unwrap();
        let identity = root.path().join("identity");
        std::fs::create_dir_all(&identity).unwrap();
        std::fs::write(identity.join(JOURNAL), b"{not json").unwrap();
        assert_eq!(recover(&identity).unwrap(), Recovered::Nothing);
        assert!(!identity.join(JOURNAL).exists());
        assert!(identity.join(format!("{JOURNAL}.corrupt")).exists());
    }

    #[test]
    fn stale_staged_files_are_replaced_and_the_done_list_is_bounded() {
        let root = tempfile::tempdir().unwrap();
        let identity = root.path().join("identity");
        std::fs::create_dir_all(root.path().join("node")).unwrap();
        std::fs::write(
            root.path().join(format!("node/f0{STAGED_SUFFIX}")),
            b"stale",
        )
        .unwrap();
        for i in 0..40 {
            let files = specs(root.path(), &[b"x"]);
            assert_eq!(
                write(&identity, &format!("op-{i}"), "bee", &files, || true).unwrap(),
                Outcome::Installed
            );
        }
        let done = read_done(&identity).unwrap();
        assert_eq!(done.ops.len(), MAX_DONE);
        assert_eq!(done.ops[0].op_id, "op-8");
        assert_eq!(
            op_status(&identity, "op-0").unwrap(),
            OpStatus::NotCommitted
        );
        assert_eq!(op_status(&identity, "op-39").unwrap(), OpStatus::Installed);
    }

    #[test]
    fn relative_targets_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let files = [FileSpec {
            target: PathBuf::from("relative/f0"),
            contents: b"x",
        }];
        assert!(write(root.path(), "op", "bee", &files, || true).is_err());
    }
}
