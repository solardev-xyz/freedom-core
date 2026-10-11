//! Multi-file node-identity writes (design 0001, "Multi-file writes").
//!
//! A node identity is several files that must change together (Bee: the
//! keystore and the config holding its password; Radicle: the key pair and
//! the config). Node directories can be outside the profile, so all records
//! live in the identity directory, where startup recovery always finds them.
//!
//! 0. **Intent.** `node-identity-staging.json` (`{ op_id, node, root }`) is
//!    written durably first, so the staged files of an operation that dies
//!    before its commit can be found and removed.
//! 1. **Stage.** Each file of the node's fixed [`layout`] gets
//!    `<target>.freedom-new` (exclusive create, `0600`, fsync, directory
//!    fsync, new directories persisted) and its SHA-256.
//! 2. **Commit.** `node-identity-journal.json` (`{ op_id, node, root, files:
//!    [{ target, staged, sha256 }] }`, no key material) is written through the
//!    caller's commit gate, and must be durable before anything is installed.
//! 3. **Install.** A target that already is a regular file with its digest is
//!    done; otherwise its staged file is renamed over it. Then every affected
//!    directory is fsynced.
//! 4. **Finish.** The op is added to `node-identity-done.json` (the last 32
//!    operations), durably; then the journal is removed.
//!
//! A failure before the commit removes the staged files: nothing changed. A
//! failure after it keeps the journal (`pending_recovery`); [`recover`] runs
//! at startup, in `freedom-cored recover`, and before every new write.
//!
//! **Recovery trusts nothing it reads.** A journal is acted on only if it is
//! exactly what [`write`] produces: a supported node, a normalized absolute
//! root, the node's exact file layout under it with sibling staged names, and
//! valid digests. Anything else is set aside as `….corrupt` and reported. Only
//! regular files are hashed or installed; symlinks are never followed.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::fsx::{self, Done};

pub const JOURNAL: &str = "node-identity-journal.json";
pub const DONE: &str = "node-identity-done.json";
pub const STAGING: &str = "node-identity-staging.json";
/// Nodes whose identity is known to be broken (a corrupt operation, or an
/// untrusted journal), until a later write installs them. Persisted so every
/// startup reports them, not only the one that found them.
pub const UNRESOLVED: &str = "node-identity-unresolved.json";
const NODES: [&str; 2] = ["bee", "radicle"];
const STAGED_SUFFIX: &str = ".freedom-new";
const MAX_DONE: usize = 32;
/// The largest node identity file (and record) handled. Node configs and
/// keys are a few KiB.
pub const MAX_FILE: u64 = 1 << 20;

/// The files of a node identity, in order, under its root (`data_dir` for
/// Bee, `home` for Radicle). The single source of truth for writers and for
/// recovery's validation.
pub fn layout(node: &str, root: &Path) -> Option<Vec<PathBuf>> {
    match node {
        "bee" => Some(vec![
            root.join("keys").join("swarm.key"),
            root.join("config.yaml"),
        ]),
        "radicle" => Some(vec![
            root.join("keys").join("radicle"),
            root.join("keys").join("radicle.pub"),
            root.join("config.json"),
        ]),
        _ => None,
    }
}

/// Operation IDs come from main: 1 to 64 of `[A-Za-z0-9._-]`.
pub fn valid_op_id(op_id: &str) -> bool {
    (1..=64).contains(&op_id.len())
        && op_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[derive(Debug, Serialize, Deserialize)]
struct Journal {
    op_id: String,
    node: String,
    root: PathBuf,
    files: Vec<JournalFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JournalFile {
    target: PathBuf,
    staged: PathBuf,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Intent {
    op_id: String,
    node: String,
    root: PathBuf,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Unresolved {
    nodes: Vec<String>,
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

/// How a committed (or abandoned) write ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// All four steps completed durably.
    Installed,
    /// Committed, but not (durably) installed or finished yet; the journal is
    /// kept for recovery.
    PendingRecovery,
    /// Committed, but its own staged files were gone at install: needs a
    /// fresh write while unlocked.
    Corrupt,
    /// The commit gate refused: nothing changed.
    Abandoned,
}

/// Why a write didn't commit. Nothing changed in any of these cases.
#[derive(Debug)]
pub enum WriteError {
    Io(std::io::Error),
    /// The op ID is already in the done list or the live journal.
    DuplicateOpId,
    /// Not a node layout this writer produces (a bug in the caller).
    Layout,
    /// A file is larger than [`MAX_FILE`].
    TooLarge,
}

impl From<std::io::Error> for WriteError {
    fn from(error: std::io::Error) -> Self {
        WriteError::Io(error)
    }
}

/// What [`recover`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovered {
    Nothing,
    /// A leftover journal was finished with this status.
    Finished {
        op_id: String,
        node: String,
        status: OpStatus,
    },
    /// A journal that isn't exactly what [`write`] produces was set aside
    /// (`….corrupt`) without acting on it.
    Invalid,
    /// The staged files of an operation that died before its commit were
    /// removed.
    Discarded,
    /// A journal left behind by an operation the done list already records
    /// as finished (its removal didn't persist) was removed.
    Cleaned,
}

/// Runs the four steps for one operation. `Err` means nothing was committed.
/// An outstanding journal is recovered first; if that fails, nothing is
/// written.
pub fn write(
    identity_dir: &Path,
    op_id: &str,
    node: &str,
    root: &Path,
    files: &[FileSpec<'_>],
    commit: impl FnOnce() -> bool,
) -> Result<Outcome, WriteError> {
    let expected = layout(node, root).ok_or(WriteError::Layout)?;
    if !valid_op_id(op_id)
        || !normalized_absolute(root)
        || root == identity_dir
        || files.len() != expected.len()
        || files.iter().zip(&expected).any(|(f, e)| &f.target != e)
    {
        return Err(WriteError::Layout);
    }
    if files.iter().any(|f| f.contents.len() as u64 > MAX_FILE) {
        return Err(WriteError::TooLarge);
    }
    // Design 0001: recovery runs before any node write. An unresolved
    // committed operation must never be replaced.
    recover(identity_dir)?;
    if op_seen(identity_dir, op_id)? {
        return Err(WriteError::DuplicateOpId);
    }
    ensure_dir(identity_dir)?;

    // 0. Intent, durably, before any staged file exists.
    let intent = Intent {
        op_id: op_id.to_owned(),
        node: node.to_owned(),
        root: root.to_owned(),
    };
    put_record(identity_dir, STAGING, &intent)?;

    // 1. Stage.
    let mut journal = Journal {
        op_id: op_id.to_owned(),
        node: node.to_owned(),
        root: root.to_owned(),
        files: Vec::with_capacity(files.len()),
    };
    for file in files {
        match stage(file) {
            Ok(staged) => journal.files.push(staged),
            Err(e) => {
                discard(identity_dir, node, root);
                return Err(e.into());
            }
        }
    }

    // 2. Commit.
    let encoded = serde_json::to_vec(&journal).map_err(std::io::Error::other)?;
    match fsx::replace(&identity_dir.join(JOURNAL), &encoded, |_| Ok(()), commit) {
        Ok(Done::Durable) => {}
        // Committed but not durable: install nothing; recovery finishes it
        // once the journal is known to persist.
        Ok(Done::NotDurable) => {
            let _ = fsx::remove(&identity_dir.join(STAGING), || true);
            return Ok(Outcome::PendingRecovery);
        }
        Err(fsx::WriteError::Abandoned) => {
            discard(identity_dir, node, root);
            return Ok(Outcome::Abandoned);
        }
        Err(fsx::WriteError::Io(e)) => {
            discard(identity_dir, node, root);
            return Err(e.into());
        }
        Err(fsx::WriteError::Check(reason)) => {
            discard(identity_dir, node, root);
            return Err(std::io::Error::other(reason).into());
        }
    }
    // The journal supersedes the intent.
    let _ = fsx::remove(&identity_dir.join(STAGING), || true);

    // 3 and 4. After the commit, a failure leaves the journal for recovery.
    let result = install(&journal).and_then(|corrupt| {
        let status = if corrupt {
            OpStatus::Corrupt
        } else {
            OpStatus::Installed
        };
        finish(identity_dir, &journal.op_id, status).map(|()| status)
    });
    Ok(match result {
        Ok(OpStatus::Installed) => {
            // This node's identity is whole again.
            if let Err(e) = mark_unresolved(identity_dir, &[node], false) {
                crate::log::warn(
                    "could not clear the node's unresolved mark",
                    serde_json::json!({ "error": e.kind().to_string() }),
                );
            }
            Outcome::Installed
        }
        Ok(_) => {
            let _ = mark_unresolved(identity_dir, &[node], true);
            Outcome::Corrupt
        }
        Err(e) => {
            crate::log::error(
                "node identity install did not finish after commit",
                serde_json::json!({ "error": e.kind().to_string() }),
            );
            Outcome::PendingRecovery
        }
    })
}

/// Finishes a leftover journal, or removes the staged files of an operation
/// that died before its commit.
pub fn recover(identity_dir: &Path) -> std::io::Result<Recovered> {
    let path = identity_dir.join(JOURNAL);
    let Some(bytes) = read_record(&path)? else {
        return discard_intent(identity_dir);
    };
    let journal = match serde_json::from_slice::<Journal>(&bytes) {
        Ok(journal) if valid_journal(&journal, identity_dir) => journal,
        _ => {
            // Never act on it: keep it aside for inspection. Which node it
            // concerned is unknown, so both stay unresolved until rewritten.
            mark_unresolved(identity_dir, &NODES, true)?;
            std::fs::rename(&path, identity_dir.join(format!("{JOURNAL}.corrupt")))?;
            sync_dir(identity_dir)?;
            crate::log::error(
                "invalid node identity journal set aside",
                serde_json::json!({}),
            );
            return Ok(Recovered::Invalid);
        }
    };
    // A journal whose operation the done list already records finished: only
    // its removal didn't persist. Never replay it (its targets may have
    // changed since); just remove it.
    if read_done(identity_dir)?
        .ops
        .iter()
        .any(|op| op.op_id == journal.op_id)
    {
        fsx::remove(&path, || true)?;
        return Ok(Recovered::Cleaned);
    }
    // Durability barrier: the journal and its directory entry must persist
    // before any member is installed from it.
    File::open(&path)?.sync_all()?;
    sync_dir(identity_dir)?;
    let corrupt = install(&journal)?;
    let status = if corrupt {
        mark_unresolved(identity_dir, &[journal.node.as_str()], true)?;
        OpStatus::Corrupt
    } else {
        OpStatus::Installed
    };
    finish(identity_dir, &journal.op_id, status)?;
    let _ = fsx::remove(&identity_dir.join(STAGING), || true);
    Ok(Recovered::Finished {
        op_id: journal.op_id,
        node: journal.node,
        status,
    })
}

/// The op ID and node of a valid outstanding journal, if one is there (for
/// reporting a failed recovery).
pub fn pending(identity_dir: &Path) -> Option<(String, String)> {
    let bytes = read_record(&identity_dir.join(JOURNAL)).ok()??;
    let journal: Journal = serde_json::from_slice(&bytes).ok()?;
    valid_journal(&journal, identity_dir).then_some((journal.op_id, journal.node))
}

/// `nodes.op_status`. The live journal wins over the done list, so an old
/// record can't mask a current transaction. A consistent node directory
/// alone doesn't count: it could still hold the old identity.
pub fn op_status(identity_dir: &Path, op_id: &str) -> std::io::Result<OpStatus> {
    let done = read_done(identity_dir)?;
    // Op IDs are single-use, so a done record is final; a live journal with
    // the same ID is then only a leftover whose removal didn't persist.
    if let Some(op) = done.ops.iter().rev().find(|op| op.op_id == op_id) {
        return Ok(op.status);
    }
    if let Some(bytes) = read_record(&identity_dir.join(JOURNAL))?
        && serde_json::from_slice::<Journal>(&bytes).is_ok_and(|j| j.op_id == op_id)
    {
        return Ok(OpStatus::PendingRecovery);
    }
    Ok(OpStatus::NotCommitted)
}

/// The nodes recorded as unresolved (see [`UNRESOLVED`]).
pub fn unresolved(identity_dir: &Path) -> std::io::Result<Vec<String>> {
    Ok(match read_record(&identity_dir.join(UNRESOLVED))? {
        Some(bytes) => serde_json::from_slice::<Unresolved>(&bytes)
            .map(|u| u.nodes)
            // Unreadable: assume the worst.
            .unwrap_or_else(|_| NODES.iter().map(|n| (*n).to_owned()).collect()),
        None => Vec::new(),
    })
}

/// Adds (`broken`) or removes nodes from the unresolved set, durably.
fn mark_unresolved(identity_dir: &Path, nodes: &[&str], broken: bool) -> std::io::Result<()> {
    let mut set = unresolved(identity_dir)?;
    let before = set.clone();
    for node in nodes {
        set.retain(|n| n != node);
        if broken {
            set.push((*node).to_owned());
        }
    }
    set.sort();
    set.dedup();
    if set == before {
        return Ok(());
    }
    if set.is_empty() {
        fsx::remove(&identity_dir.join(UNRESOLVED), || true)?;
        return Ok(());
    }
    ensure_dir(identity_dir)?;
    put_record(identity_dir, UNRESOLVED, &Unresolved { nodes: set })
}

fn op_seen(identity_dir: &Path, op_id: &str) -> std::io::Result<bool> {
    Ok(op_status(identity_dir, op_id)? != OpStatus::NotCommitted)
}

/// A journal exactly as [`write`] produces it.
fn valid_journal(journal: &Journal, identity_dir: &Path) -> bool {
    let Some(expected) = layout(&journal.node, &journal.root) else {
        return false;
    };
    valid_op_id(&journal.op_id)
        && normalized_absolute(&journal.root)
        && journal.root != identity_dir
        && journal.files.len() == expected.len()
        && journal.files.iter().zip(&expected).all(|(file, target)| {
            &file.target == target
                && file.staged == staged_path(target)
                && file.sha256.len() == 64
                && file
                    .sha256
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// Absolute, with no `.` or `..` components.
fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|c| {
            matches!(
                c,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

fn staged_path(target: &Path) -> PathBuf {
    let mut name = target.as_os_str().to_owned();
    name.push(STAGED_SUFFIX);
    PathBuf::from(name)
}

/// Step 1 for one file. A staged file left by an earlier operation that died
/// before its commit is replaced (recovery has run, so no journal needs it).
fn stage(file: &FileSpec<'_>) -> std::io::Result<JournalFile> {
    let dir = file
        .target
        .parent()
        .ok_or_else(|| std::io::Error::other("target has no parent directory"))?;
    ensure_dir(dir)?;
    let staged = staged_path(&file.target);
    remove_if_present(&staged)?;
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
        sha256: hex(&Sha256::digest(file.contents)),
    })
}

/// Step 3. Returns whether any file could not be installed (corrupt).
fn install(journal: &Journal) -> std::io::Result<bool> {
    let mut corrupt = false;
    let mut dirs: Vec<&Path> = Vec::new();
    for file in &journal.files {
        if regular_digest(&file.target)?.as_deref() == Some(file.sha256.as_str()) {
            // Already in place; a leftover staged copy is not needed.
            remove_if_present(&file.staged)?;
        } else if regular_digest(&file.staged)?.as_deref() == Some(file.sha256.as_str()) {
            // Replaces whatever is at the target, a symlink included, without
            // following it.
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

/// Step 4: record the outcome durably, then remove the journal. If the
/// removal isn't durable, a journal that reappears after a crash is finished
/// again (idempotently); the durable done record already holds the outcome.
fn finish(identity_dir: &Path, op_id: &str, status: OpStatus) -> std::io::Result<()> {
    let mut done = read_done(identity_dir)?;
    done.ops.retain(|op| op.op_id != op_id);
    done.ops.push(DoneOp {
        op_id: op_id.to_owned(),
        status,
    });
    let excess = done.ops.len().saturating_sub(MAX_DONE);
    done.ops.drain(..excess);
    put_record(identity_dir, DONE, &done)?;
    if fsx::remove(&identity_dir.join(JOURNAL), || true)? == Some(Done::NotDurable) {
        crate::log::warn(
            "node identity journal removal not flushed",
            serde_json::json!({}),
        );
    }
    Ok(())
}

/// Writes a bookkeeping record durably; a failed directory flush is an error.
fn put_record<T: Serialize>(identity_dir: &Path, name: &str, record: &T) -> std::io::Result<()> {
    let encoded = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    match fsx::replace(&identity_dir.join(name), &encoded, |_| Ok(()), || true) {
        Ok(Done::Durable) => Ok(()),
        Ok(Done::NotDurable) => Err(std::io::Error::other("record not flushed")),
        Err(fsx::WriteError::Io(e)) => Err(e),
        Err(other) => Err(std::io::Error::other(format!("{other:?}"))),
    }
}

fn read_done(identity_dir: &Path) -> std::io::Result<DoneList> {
    match read_record(&identity_dir.join(DONE))? {
        // An unreadable done list is treated as empty: op_status then falls
        // back to the journal, and the next finish rewrites it.
        Some(bytes) => Ok(serde_json::from_slice(&bytes).unwrap_or_default()),
        None => Ok(DoneList::default()),
    }
}

/// Before the commit: removes this operation's staged files, then its
/// intent record.
fn discard(identity_dir: &Path, node: &str, root: &Path) {
    for target in layout(node, root).unwrap_or_default() {
        let _ = std::fs::remove_file(staged_path(&target));
    }
    let _ = fsx::remove(&identity_dir.join(STAGING), || true);
}

/// No journal: an intent left by an operation that died before its commit
/// names staged files to remove (only the node layout's own).
fn discard_intent(identity_dir: &Path) -> std::io::Result<Recovered> {
    let path = identity_dir.join(STAGING);
    let Some(bytes) = read_record(&path)? else {
        return Ok(Recovered::Nothing);
    };
    if let Ok(intent) = serde_json::from_slice::<Intent>(&bytes)
        && valid_op_id(&intent.op_id)
        && normalized_absolute(&intent.root)
        && intent.root != identity_dir
        && let Some(targets) = layout(&intent.node, &intent.root)
    {
        for target in targets {
            remove_if_present(&staged_path(&target))?;
        }
    }
    fsx::remove(&path, || true)?;
    Ok(Recovered::Discarded)
}

/// A bookkeeping record (journal, done list, intent): regular file, bounded.
fn read_record(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !metadata.is_file() || metadata.len() > MAX_FILE {
        return Err(std::io::Error::other("unexpected node identity record"));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

/// The SHA-256 of a regular file (never through a symlink), hashed through a
/// wiped buffer: node files hold private keys and passwords.
fn regular_digest(path: &Path) -> std::io::Result<Option<String>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !metadata.is_file() || metadata.len() > MAX_FILE {
        return Ok(None);
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = Zeroizing::new([0u8; 4096]);
    loop {
        let read = file.read(buffer.as_mut_slice())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Some(hex(&hasher.finalize())))
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Creates `dir` and any missing ancestors, then persists each new entry in
/// its parent, so a crash can't lose a directory that staged files are in.
fn ensure_dir(dir: &Path) -> std::io::Result<()> {
    let mut missing = Vec::new();
    let mut current = Some(dir);
    while let Some(path) = current {
        if path.exists() {
            break;
        }
        missing.push(path);
        current = path.parent();
    }
    std::fs::create_dir_all(dir)?;
    for created in missing.iter().rev() {
        if let Some(parent) = created.parent() {
            sync_dir(parent)?;
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

    fn bee_files<'a>(root: &Path, key: &'a [u8], config: &'a [u8]) -> Vec<FileSpec<'a>> {
        let targets = layout("bee", root).unwrap();
        vec![
            FileSpec {
                target: targets[0].clone(),
                contents: key,
            },
            FileSpec {
                target: targets[1].clone(),
                contents: config,
            },
        ]
    }

    fn staged_left(root: &Path) -> Vec<PathBuf> {
        layout("bee", root)
            .unwrap()
            .iter()
            .map(|t| staged_path(t))
            .filter(|p| p.exists())
            .collect()
    }

    fn made(dir: &Path) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        dir.to_owned()
    }

    fn committed_journal(
        identity: &Path,
        root: &Path,
        op_id: &str,
        key: &[u8],
        config: &[u8],
    ) -> Journal {
        let files = bee_files(root, key, config);
        let journal = Journal {
            op_id: op_id.into(),
            node: "bee".into(),
            root: root.to_owned(),
            files: files.iter().map(|f| stage(f).unwrap()).collect(),
        };
        made(identity);
        std::fs::write(
            identity.join(JOURNAL),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        journal
    }

    #[test]
    fn installs_all_files_and_records_the_op() {
        let tmp = tempfile::tempdir().unwrap();
        let (identity, root) = (tmp.path().join("identity"), tmp.path().join("bee"));
        let files = bee_files(&root, b"key", b"config");
        assert_eq!(
            write(&identity, "op-1", "bee", &root, &files, || true).unwrap(),
            Outcome::Installed
        );
        assert_eq!(std::fs::read(root.join("keys/swarm.key")).unwrap(), b"key");
        assert_eq!(std::fs::read(root.join("config.yaml")).unwrap(), b"config");
        assert!(staged_left(&root).is_empty());
        assert!(!identity.join(JOURNAL).exists());
        assert!(!identity.join(STAGING).exists());
        assert_eq!(op_status(&identity, "op-1").unwrap(), OpStatus::Installed);
        assert_eq!(
            op_status(&identity, "op-2").unwrap(),
            OpStatus::NotCommitted
        );
        // Op IDs are single-use.
        assert!(matches!(
            write(&identity, "op-1", "bee", &root, &files, || true),
            Err(WriteError::DuplicateOpId)
        ));
    }

    #[test]
    fn an_abandoned_write_changes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (identity, root) = (tmp.path().join("identity"), tmp.path().join("bee"));
        made(&root.join("keys"));
        std::fs::write(root.join("keys/swarm.key"), b"old").unwrap();
        let files = bee_files(&root, b"new", b"config");
        assert_eq!(
            write(&identity, "op-1", "bee", &root, &files, || false).unwrap(),
            Outcome::Abandoned
        );
        assert_eq!(std::fs::read(root.join("keys/swarm.key")).unwrap(), b"old");
        assert!(!root.join("config.yaml").exists());
        assert!(staged_left(&root).is_empty());
        assert!(!identity.join(STAGING).exists());
        assert_eq!(
            op_status(&identity, "op-1").unwrap(),
            OpStatus::NotCommitted
        );
    }

    #[test]
    fn recovery_rolls_a_committed_journal_forward() {
        let tmp = tempfile::tempdir().unwrap();
        let (identity, root) = (tmp.path().join("identity"), tmp.path().join("bee"));
        made(&root.join("keys"));
        std::fs::write(root.join("keys/swarm.key"), b"old key").unwrap();
        std::fs::write(root.join("config.yaml"), b"old config").unwrap();
        let journal = committed_journal(&identity, &root, "op-7", b"new key", b"new config");
        // A crash after one file was installed.
        std::fs::rename(&journal.files[0].staged, &journal.files[0].target).unwrap();
        assert_eq!(
            op_status(&identity, "op-7").unwrap(),
            OpStatus::PendingRecovery
        );
        assert_eq!(
            recover(&identity).unwrap(),
            Recovered::Finished {
                op_id: "op-7".into(),
                node: "bee".into(),
                status: OpStatus::Installed
            }
        );
        assert_eq!(
            std::fs::read(root.join("keys/swarm.key")).unwrap(),
            b"new key"
        );
        assert_eq!(
            std::fs::read(root.join("config.yaml")).unwrap(),
            b"new config"
        );
        assert_eq!(op_status(&identity, "op-7").unwrap(), OpStatus::Installed);
        assert_eq!(recover(&identity).unwrap(), Recovered::Nothing);
    }

    #[test]
    fn a_new_write_finishes_the_outstanding_journal_first() {
        let tmp = tempfile::tempdir().unwrap();
        let (identity, root) = (tmp.path().join("identity"), tmp.path().join("bee"));
        committed_journal(&identity, &root, "op-old", b"old-op key", b"old-op config");
        let other = tmp.path().join("bee2");
        let files = bee_files(&other, b"k2", b"c2");
        assert_eq!(
            write(&identity, "op-new", "bee", &other, &files, || true).unwrap(),
            Outcome::Installed
        );
        assert_eq!(op_status(&identity, "op-old").unwrap(), OpStatus::Installed);
        assert_eq!(
            std::fs::read(root.join("config.yaml")).unwrap(),
            b"old-op config"
        );
    }

    #[test]
    fn a_completed_journal_left_behind_is_removed_not_replayed() {
        let tmp = tempfile::tempdir().unwrap();
        let (identity, root) = (tmp.path().join("identity"), tmp.path().join("bee"));
        let journal = committed_journal(&identity, &root, "op-1", b"k", b"c");
        // The op finished (done record), but the journal's removal didn't
        // persist; since then the node rewrote its config.
        std::fs::rename(&journal.files[0].staged, &journal.files[0].target).unwrap();
        std::fs::rename(&journal.files[1].staged, &journal.files[1].target).unwrap();
        finish(&identity, "op-1", OpStatus::Installed).unwrap();
        std::fs::write(
            identity.join(JOURNAL),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        std::fs::write(root.join("config.yaml"), b"changed by the node").unwrap();
        assert_eq!(op_status(&identity, "op-1").unwrap(), OpStatus::Installed);
        assert_eq!(recover(&identity).unwrap(), Recovered::Cleaned);
        assert!(!identity.join(JOURNAL).exists());
        assert_eq!(
            std::fs::read(root.join("config.yaml")).unwrap(),
            b"changed by the node"
        );
        assert_eq!(op_status(&identity, "op-1").unwrap(), OpStatus::Installed);
        assert!(unresolved(&identity).unwrap().is_empty());
    }

    #[test]
    fn broken_nodes_stay_unresolved_until_rewritten() {
        let tmp = tempfile::tempdir().unwrap();
        let (identity, root) = (tmp.path().join("identity"), tmp.path().join("bee"));
        // An untrusted journal: both nodes unresolved, across restarts.
        made(&identity);
        std::fs::write(identity.join(JOURNAL), b"{}").unwrap();
        assert_eq!(recover(&identity).unwrap(), Recovered::Invalid);
        assert_eq!(unresolved(&identity).unwrap(), ["bee", "radicle"]);
        assert_eq!(recover(&identity).unwrap(), Recovered::Nothing);
        assert_eq!(unresolved(&identity).unwrap(), ["bee", "radicle"]);
        // Rewriting Bee resolves Bee only.
        let files = bee_files(&root, b"k", b"c");
        assert_eq!(
            write(&identity, "op-b", "bee", &root, &files, || true).unwrap(),
            Outcome::Installed
        );
        assert_eq!(unresolved(&identity).unwrap(), ["radicle"]);
        // A corrupt operation marks its node.
        let other = tmp.path().join("bee2");
        let journal = committed_journal(&identity, &other, "op-c", b"k", b"c");
        std::fs::remove_file(&journal.files[1].staged).unwrap();
        assert!(matches!(
            recover(&identity).unwrap(),
            Recovered::Finished {
                status: OpStatus::Corrupt,
                ..
            }
        ));
        assert_eq!(unresolved(&identity).unwrap(), ["bee", "radicle"]);
    }

    #[test]
    fn journals_that_writers_never_produce_are_set_aside() {
        let tmp = tempfile::tempdir().unwrap();
        let identity = made(&tmp.path().join("identity"));
        let vault = identity.join("identity-vault.json");
        std::fs::write(&vault, b"the vault").unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::write(&elsewhere, b"other bytes").unwrap();
        let digest = hex(&Sha256::digest(b"other bytes"));
        let bad = [
            // A target outside the node layout (the vault itself).
            serde_json::json!({ "op_id": "x", "node": "bee", "root": identity,
                "files": [{ "target": vault, "staged": elsewhere, "sha256": digest }] }),
            // An unknown node with no files.
            serde_json::json!({ "op_id": "x", "node": "ipfs", "root": tmp.path(), "files": [] }),
            // A relative root.
            serde_json::json!({ "op_id": "x", "node": "bee", "root": "rel", "files": [] }),
        ];
        for journal in bad {
            std::fs::write(identity.join(JOURNAL), journal.to_string()).unwrap();
            assert_eq!(recover(&identity).unwrap(), Recovered::Invalid);
            assert!(!identity.join(JOURNAL).exists());
            assert!(identity.join(format!("{JOURNAL}.corrupt")).exists());
            assert_eq!(std::fs::read(&vault).unwrap(), b"the vault");
            assert_eq!(std::fs::read(&elsewhere).unwrap(), b"other bytes");
        }
    }

    #[test]
    fn a_journal_whose_files_are_gone_is_corrupt() {
        let tmp = tempfile::tempdir().unwrap();
        let (identity, root) = (tmp.path().join("identity"), tmp.path().join("bee"));
        let journal = committed_journal(&identity, &root, "op-9", b"k", b"c");
        std::fs::remove_file(&journal.files[0].staged).unwrap();
        assert_eq!(
            recover(&identity).unwrap(),
            Recovered::Finished {
                op_id: "op-9".into(),
                node: "bee".into(),
                status: OpStatus::Corrupt
            }
        );
        assert_eq!(op_status(&identity, "op-9").unwrap(), OpStatus::Corrupt);
    }

    #[test]
    fn staged_files_of_a_pre_commit_crash_are_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let (identity, root) = (tmp.path().join("identity"), tmp.path().join("bee"));
        made(&identity);
        put_record(
            &identity,
            STAGING,
            &Intent {
                op_id: "op-3".into(),
                node: "bee".into(),
                root: root.clone(),
            },
        )
        .unwrap();
        for file in bee_files(&root, b"k", b"c") {
            stage(&file).unwrap();
        }
        assert_eq!(staged_left(&root).len(), 2);
        assert_eq!(recover(&identity).unwrap(), Recovered::Discarded);
        assert!(staged_left(&root).is_empty());
        assert!(!identity.join(STAGING).exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_never_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let (identity, root) = (tmp.path().join("identity"), tmp.path().join("bee"));
        let journal = committed_journal(&identity, &root, "op-5", b"new key", b"new config");
        // A target that is a symlink to a file with the right bytes is still
        // replaced by the real file, and the referent is untouched.
        let referent = tmp.path().join("referent");
        std::fs::write(&referent, b"new key").unwrap();
        std::os::unix::fs::symlink(&referent, &journal.files[0].target).unwrap();
        assert!(matches!(
            recover(&identity).unwrap(),
            Recovered::Finished {
                status: OpStatus::Installed,
                ..
            }
        ));
        let target = std::fs::symlink_metadata(&journal.files[0].target).unwrap();
        assert!(target.is_file());
        assert_eq!(std::fs::read(&referent).unwrap(), b"new key");
    }

    #[test]
    fn layouts_and_sizes_are_enforced() {
        let tmp = tempfile::tempdir().unwrap();
        let (identity, root) = (tmp.path().join("identity"), tmp.path().join("bee"));
        let wrong = [FileSpec {
            target: root.join("other"),
            contents: b"x",
        }];
        assert!(matches!(
            write(&identity, "op", "bee", &root, &wrong, || true),
            Err(WriteError::Layout)
        ));
        assert!(matches!(
            write(&identity, "op", "bee", Path::new("relative"), &[], || true),
            Err(WriteError::Layout)
        ));
        let big = vec![0u8; MAX_FILE as usize + 1];
        let files = bee_files(&root, &big, b"c");
        assert!(matches!(
            write(&identity, "op", "bee", &root, &files, || true),
            Err(WriteError::TooLarge)
        ));
        assert!(staged_left(&root).is_empty());
    }

    #[test]
    fn the_done_list_is_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        let (identity, root) = (tmp.path().join("identity"), tmp.path().join("bee"));
        for i in 0..40 {
            let files = bee_files(&root, b"x", b"y");
            assert_eq!(
                write(&identity, &format!("op-{i}"), "bee", &root, &files, || true).unwrap(),
                Outcome::Installed
            );
        }
        let done = read_done(&identity).unwrap();
        assert_eq!(done.ops.len(), MAX_DONE);
        assert_eq!(done.ops[0].op_id, "op-8");
    }
}
