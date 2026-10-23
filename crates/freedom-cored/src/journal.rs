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
//! root, one of the node's [`shapes`] under it with sibling staged names, and
//! valid digests. Anything else is set aside as `….corrupt` and reported. Only
//! regular files are hashed or installed; symlinks are never followed.
//!
//! **Removals and the wipe** (design 0008, "The switch" and "Identity
//! changes"): an entry can name a target to remove instead of a staged file,
//! and a journal can name directories to wipe before its entries. Install
//! unlinks such a target, following no symlink, and flushes its directory;
//! a target already gone is done. So recovery repeats them as it repeats an
//! install.
//!
//! **The Radicle home's gate** (0008, "Spawn and lock"): every write and every
//! recovery of a Radicle journal holds `radicle-<sha256(home)>.lock`, the gate
//! the Radicle service holds for its whole life ([`Gates`]). A recovery that
//! finds it held leaves the journal in place ([`Recovered::Waiting`]): the
//! node stays `pending_recovery` until the service has stopped.

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
    /// Directories wiped before any entry (0008, "Identity changes").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    wipe: Vec<PathBuf>,
}

/// One entry: a staged file to install, with its digest, or a target to
/// remove.
#[derive(Debug, Serialize, Deserialize)]
struct JournalFile {
    target: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    staged: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    remove: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// What an entry does to its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Install,
    Remove,
}

/// One shape a node's journal can take: its entries, in order, and the
/// directories it wipes first.
#[derive(Debug, PartialEq, Eq)]
struct Shape {
    entries: Vec<(PathBuf, Action)>,
    wipe: Vec<PathBuf>,
}

/// Every shape a writer produces for `node` under `root`: the single source
/// of truth for writers and for recovery's validation.
///
/// - **Bee:** its [`layout`], installed.
/// - **Radicle, today's form:** its [`layout`], installed: the key pair and
///   the config.
/// - **Radicle, 0008's form** (`custody: "sealed"`), with no key file
///   written: the removal of `keys/radicle` and `keys/radicle.pub`, then the
///   config. **The switch** installs the dirty marker, `node/dirty`, first,
///   naming the identity whose key file it removes. **With `wipe`,**
///   `node/`, `cobs/` and `storage/` are wiped first, and no marker is
///   written: nothing is left to check.
fn shapes(node: &str, root: &Path) -> Vec<Shape> {
    let installed = |files: Vec<PathBuf>| -> Vec<(PathBuf, Action)> {
        files.into_iter().map(|f| (f, Action::Install)).collect()
    };
    match node {
        "bee" => vec![Shape {
            entries: installed(layout(node, root).unwrap_or_default()),
            wipe: Vec::new(),
        }],
        "radicle" => {
            let removals = [
                (root.join("keys").join("radicle"), Action::Remove),
                (root.join("keys").join("radicle.pub"), Action::Remove),
            ];
            let config = (root.join("config.json"), Action::Install);
            let marker = (radicle_marker(root), Action::Install);
            let sealed: Vec<_> = removals.iter().cloned().chain([config.clone()]).collect();
            let switch: Vec<_> = [marker].into_iter().chain(sealed.iter().cloned()).collect();
            vec![
                Shape {
                    entries: installed(layout(node, root).unwrap_or_default()),
                    wipe: Vec::new(),
                },
                Shape {
                    entries: sealed.clone(),
                    wipe: Vec::new(),
                },
                Shape {
                    entries: switch,
                    wipe: Vec::new(),
                },
                Shape {
                    entries: sealed,
                    wipe: radicle_wipe(root),
                },
            ]
        }
        _ => Vec::new(),
    }
}

/// 0008's dirty marker in a Radicle home.
pub fn radicle_marker(root: &Path) -> PathBuf {
    root.join("node").join("dirty")
}

/// The directories an identity change with `wipe` removes (0008).
pub fn radicle_wipe(root: &Path) -> Vec<PathBuf> {
    vec![root.join("node"), root.join("cobs"), root.join("storage")]
}

/// Every target any of `node`'s shapes installs: the staged files an
/// operation that died before its commit may have left.
fn staged_targets(node: &str, root: &Path) -> Vec<PathBuf> {
    let mut targets: Vec<PathBuf> = Vec::new();
    for shape in shapes(node, root) {
        for (target, action) in shape.entries {
            if action == Action::Install && !targets.contains(&target) {
                targets.push(target);
            }
        }
    }
    targets
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
#[derive(Clone)]
pub struct FileSpec<'a> {
    pub target: PathBuf,
    pub contents: &'a [u8],
}

/// One entry of an operation, in the order it is applied.
#[derive(Clone)]
pub enum Entry<'a> {
    Install(FileSpec<'a>),
    Remove(PathBuf),
}

/// An operation: its entries, and the directories it wipes first. It must
/// be one of the node's [`shapes`].
pub struct Plan<'a> {
    pub entries: Vec<Entry<'a>>,
    pub wipe: Vec<PathBuf>,
}

impl<'a> Plan<'a> {
    /// Files to install: the only form before design 0008.
    pub fn install(files: &[FileSpec<'a>]) -> Self {
        Plan {
            entries: files.iter().cloned().map(Entry::Install).collect(),
            wipe: Vec::new(),
        }
    }

    fn shape(&self) -> Shape {
        Shape {
            entries: self
                .entries
                .iter()
                .map(|entry| match entry {
                    Entry::Install(file) => (file.target.clone(), Action::Install),
                    Entry::Remove(target) => (target.clone(), Action::Remove),
                })
                .collect(),
            wipe: self.wipe.clone(),
        }
    }
}

/// How recovery takes a Radicle home's gate (design 0008, "Identity
/// changes"): under the lock directory main and the Radicle service share,
/// retrying for `retry`. `held` is the canonical home whose gate the caller
/// already holds: a write recovers a journal of its own home under its own
/// gate.
#[derive(Debug, Clone)]
pub struct Gates {
    pub lock_dir: PathBuf,
    pub retry: std::time::Duration,
    pub held: Option<PathBuf>,
}

/// The Radicle home gate's namespace: the Radicle service's own.
pub const RADICLE_GATE: &str = "radicle";

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
    /// An outstanding Radicle journal waits for its home's gate, which
    /// another process holds: it can't be finished, so nothing new is
    /// written (0008, "Identity changes").
    LockHeld,
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
    /// A Radicle journal was left in place: its home's gate is held, by the
    /// Radicle service or a `hold-lock` (0008, "Identity changes").
    Waiting {
        op_id: String,
        node: String,
    },
}

/// Runs the four steps for one operation. `Err` means nothing was committed.
/// An outstanding journal is recovered first; if that fails, or waits for a
/// Radicle home's gate, nothing is written. For a Radicle operation the
/// caller holds the home's gate throughout (`gates.held`).
pub fn write(
    identity_dir: &Path,
    op_id: &str,
    node: &str,
    root: &Path,
    plan: &Plan<'_>,
    gates: &Gates,
    commit: impl FnOnce() -> bool,
) -> Result<Outcome, WriteError> {
    if !valid_op_id(op_id)
        || !normalized_absolute(root)
        || root == identity_dir
        || !shapes(node, root).contains(&plan.shape())
    {
        return Err(WriteError::Layout);
    }
    if plan
        .entries
        .iter()
        .any(|e| matches!(e, Entry::Install(f) if f.contents.len() as u64 > MAX_FILE))
    {
        return Err(WriteError::TooLarge);
    }
    // Design 0001: recovery runs before any node write. An unresolved
    // committed operation must never be replaced.
    if let Recovered::Waiting { .. } = recover(identity_dir, gates)? {
        return Err(WriteError::LockHeld);
    }
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
        files: Vec::with_capacity(plan.entries.len()),
        wipe: plan.wipe.clone(),
    };
    for entry in &plan.entries {
        match entry {
            Entry::Install(file) => match stage(file) {
                Ok(staged) => journal.files.push(staged),
                Err(e) => {
                    discard(identity_dir, node, root);
                    return Err(e.into());
                }
            },
            Entry::Remove(target) => journal.files.push(JournalFile {
                target: target.clone(),
                staged: None,
                sha256: None,
                remove: true,
            }),
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
    Ok(match conclude(identity_dir, &journal) {
        Ok(OpStatus::Installed) => Outcome::Installed,
        Ok(_) => Outcome::Corrupt,
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
/// that died before its commit. A Radicle journal is finished only under its
/// home's gate ([`Gates`]); held, it is left in place
/// ([`Recovered::Waiting`]).
pub fn recover(identity_dir: &Path, gates: &Gates) -> std::io::Result<Recovered> {
    let path = identity_dir.join(JOURNAL);
    // Read, judged and later flushed through one handle, never opened again
    // by name: what is flushed is what was checked (review of #114).
    let Some((bytes, handle)) = read_journal(&path)? else {
        return discard_intent(identity_dir);
    };
    crate::testhooks::swap("journal", &path);
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
    // A Radicle journal is finished only under its home's gate, which the
    // Radicle service holds while it runs (0008).
    let _home_gate = if journal.node == "radicle" {
        match radicle_gate(&journal.root, gates)? {
            HomeGate::Held => {
                return Ok(Recovered::Waiting {
                    op_id: journal.op_id,
                    node: journal.node,
                });
            }
            HomeGate::Taken(gate) => gate,
        }
    } else {
        None
    };
    // Durability barrier: the journal and its directory entry must persist
    // before any member is installed from it. The handle has write access:
    // Windows refuses to flush a read-only one.
    handle.sync_all()?;
    drop(handle);
    sync_dir(identity_dir)?;
    let status = conclude(identity_dir, &journal)?;
    let _ = fsx::remove(&identity_dir.join(STAGING), || true);
    Ok(Recovered::Finished {
        op_id: journal.op_id,
        node: journal.node,
        status,
    })
}

enum HomeGate {
    /// Another process holds it.
    Held,
    /// Taken now (`Some`), or already the caller's (`None`).
    Taken(Option<fc_service::gate::Gate>),
}

/// The gate of the Radicle home `root`, unless the caller holds it already.
fn radicle_gate(root: &Path, gates: &Gates) -> std::io::Result<HomeGate> {
    if let Some(held) = &gates.held
        && std::fs::canonicalize(root).is_ok_and(|root| &root == held)
    {
        return Ok(HomeGate::Taken(None));
    }
    match fc_service::gate::acquire(root, &gates.lock_dir, RADICLE_GATE, gates.retry) {
        Ok(gate) => Ok(HomeGate::Taken(Some(gate))),
        Err(fc_service::gate::GateError::Held) => Ok(HomeGate::Held),
        Err(fc_service::gate::GateError::Storage(e)) => Err(e),
        Err(other) => Err(std::io::Error::other(other.to_string())),
    }
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

/// A journal exactly as [`write`] produces it: one of its node's
/// [`shapes`], each install with its sibling staged name and a digest, each
/// removal with neither.
fn valid_journal(journal: &Journal, identity_dir: &Path) -> bool {
    let shape = Shape {
        entries: journal
            .files
            .iter()
            .map(|file| {
                let action = if file.remove {
                    Action::Remove
                } else {
                    Action::Install
                };
                (file.target.clone(), action)
            })
            .collect(),
        wipe: journal.wipe.clone(),
    };
    valid_op_id(&journal.op_id)
        && normalized_absolute(&journal.root)
        && journal.root != identity_dir
        && shapes(&journal.node, &journal.root).contains(&shape)
        && journal.files.iter().all(|file| {
            if file.remove {
                file.staged.is_none() && file.sha256.is_none()
            } else {
                file.staged.as_deref() == Some(staged_path(&file.target).as_path())
                    && file.sha256.as_deref().is_some_and(|sha256| {
                        sha256.len() == 64
                            && sha256
                                .bytes()
                                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                    })
            }
        })
}

/// Absolute, with no `.` or `..` components.
pub fn normalized_absolute(path: &Path) -> bool {
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
        staged: Some(staged),
        sha256: Some(hex(&Sha256::digest(file.contents))),
        remove: false,
    })
}

/// Step 3: the wipe, then each entry in order. Returns whether any file
/// could not be installed (corrupt).
fn install(journal: &Journal) -> std::io::Result<bool> {
    let mut corrupt = false;
    let mut dirs: Vec<&Path> = Vec::new();
    let mut installed: Vec<&Path> = Vec::new();
    for dir in &journal.wipe {
        wipe(dir)?;
    }
    for file in &journal.files {
        let (staged, sha256) = match (&file.staged, &file.sha256) {
            _ if file.remove => {
                // Its directory is flushed only if something was removed:
                // a target already gone may have no directory either.
                if remove_target(&file.target)?
                    && let Some(dir) = file.target.parent()
                    && !dirs.contains(&dir)
                {
                    dirs.push(dir);
                }
                continue;
            }
            (Some(staged), Some(sha256)) => (staged, sha256),
            // valid_journal admits no other entry.
            _ => {
                return Err(std::io::Error::other(
                    "an install entry without its staged file",
                ));
            }
        };
        if regular_digest(&file.target)?.as_deref() == Some(sha256.as_str()) {
            // Already in place; a leftover staged copy is not needed.
            remove_if_present(staged)?;
        } else if let Some((_, checked)) =
            digest_and_handle(staged)?.filter(|(digest, _)| digest == sha256)
        {
            // The rename moves whatever the staged name holds: it must still
            // be the file just hashed (review of #114). If not, nothing is
            // renamed, and the journal stays for recovery to judge again.
            crate::testhooks::swap("checked", staged);
            if !fsx::same_file(&checked, staged)? {
                return Err(std::io::Error::other(
                    "a staged node identity file changed after its check",
                ));
            }
            crate::testhooks::swap("renaming", staged);
            // Replaces whatever is at the target, a symlink included, without
            // following it.
            std::fs::rename(staged, &file.target)?;
            // A file that won the race between that check and the rename is
            // never left installed: the target must be the file checked, with
            // the journaled digest. Otherwise it is removed, and the node is
            // corrupt until a fresh write.
            let ours = fsx::same_file(&checked, &file.target)?
                && regular_digest(&file.target)?.as_deref() == Some(sha256.as_str());
            drop(checked);
            if !ours {
                crate::log::error(
                    "a node identity file was swapped during its install",
                    serde_json::json!({}),
                );
                remove_if_present(&file.target)?;
                corrupt = true;
                continue;
            }
        } else {
            corrupt = true;
            continue;
        }
        installed.push(&file.target);
        if let Some(dir) = file.target.parent()
            && !dirs.contains(&dir)
        {
            dirs.push(dir);
        }
    }
    for dir in dirs {
        sync_dir(dir)?;
    }
    flush_installed(&installed);
    Ok(corrupt)
}

/// Wipes `dir` (0008, "Identity changes"): removes it and everything under
/// it, following no symlink (a symlink in its place is removed itself), then
/// flushes its parent. Already gone is done.
fn wipe(dir: &Path) -> std::io::Result<()> {
    let removed = match std::fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(dir),
        Ok(_) => std::fs::remove_file(dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    match removed {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Some(parent) = dir.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

/// A removal entry (0008, "The switch"): unlinks the target, following no
/// symlink, and says whether anything was there. Already gone is done. A
/// directory in its place is an error: the journal stays, and the node
/// `pending_recovery`.
fn remove_target(target: &Path) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(target) {
        Ok(metadata) if metadata.is_dir() => Err(std::io::Error::other(
            "a directory where a node identity file was to be removed",
        )),
        Ok(_) => remove_if_present(target).map(|()| true),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Windows: flushes each installed file, which commits NTFS's journal
/// through its rename (`fsx::sync_rename`; #85). Durability under power
/// loss is best effort there (design 0001), so a failure is logged, never
/// turned into `pending_recovery`. Unix flushed the directories instead.
fn flush_installed(installed: &[&Path]) {
    #[cfg(windows)]
    for target in installed {
        let parent = target.parent().unwrap_or(target);
        if let Err(e) = fsx::sync_rename(parent, target) {
            crate::log::warn(
                "could not flush an installed node identity file",
                serde_json::json!({ "error": e.kind().to_string() }),
            );
        }
    }
    #[cfg(not(windows))]
    let _ = installed;
}

/// Steps 3 and 4, in the order that keeps every crash recoverable: install,
/// then update the node's health durably (marked unresolved if corrupt,
/// cleared if installed), then record the outcome and remove the journal.
/// Any failure keeps the journal, so recovery repeats the whole sequence.
fn conclude(identity_dir: &Path, journal: &Journal) -> std::io::Result<OpStatus> {
    let corrupt = install(journal)?;
    mark_unresolved(identity_dir, &[journal.node.as_str()], corrupt)?;
    let status = if corrupt {
        OpStatus::Corrupt
    } else {
        OpStatus::Installed
    };
    finish(identity_dir, &journal.op_id, status)?;
    Ok(status)
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
    for target in staged_targets(node, root) {
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
        && NODES.contains(&intent.node.as_str())
    {
        // The core's own staged files, never a node's: no gate is needed.
        for target in staged_targets(&intent.node, &intent.root) {
            remove_if_present(&staged_path(&target))?;
        }
    }
    fsx::remove(&path, || true)?;
    Ok(Recovered::Discarded)
}

/// A bookkeeping record (journal, done list, intent): a regular file, never
/// through a symlink, of at most [`MAX_FILE`], judged on the open handle
/// (`fsx::open_regular`, #83).
fn read_record(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let unexpected = || std::io::Error::other("unexpected node identity record");
    match fsx::open_regular(path, false)? {
        fsx::Regular::Missing => Ok(None),
        fsx::Regular::Other => Err(unexpected()),
        fsx::Regular::File(file) => fsx::read_at_most(&file, MAX_FILE)?
            .map(Some)
            .ok_or_else(unexpected),
    }
}

/// [`read_record`] for the journal, with its handle kept open for writing,
/// so recovery flushes the very file it checked.
fn read_journal(path: &Path) -> std::io::Result<Option<(Vec<u8>, File)>> {
    let unexpected = || std::io::Error::other("unexpected node identity record");
    match fsx::open_regular_rw(path)? {
        fsx::Regular::Missing => Ok(None),
        fsx::Regular::Other => Err(unexpected()),
        fsx::Regular::File(file) => {
            let bytes = fsx::read_at_most(&file, MAX_FILE)?.ok_or_else(unexpected)?;
            Ok(Some((bytes, file)))
        }
    }
}

/// The SHA-256 of a regular file of at most [`MAX_FILE`] (never through a
/// symlink, judged on the open handle), hashed through a wiped buffer: node
/// files hold private keys and passwords. `None` for anything else.
fn regular_digest(path: &Path) -> std::io::Result<Option<String>> {
    Ok(digest_and_handle(path)?.map(|(digest, _)| digest))
}

/// [`regular_digest`], with the handle the digest was taken through.
fn digest_and_handle(path: &Path) -> std::io::Result<Option<(String, File)>> {
    let file = match fsx::open_regular(path, false)? {
        fsx::Regular::File(file) => file,
        fsx::Regular::Missing | fsx::Regular::Other => return Ok(None),
    };
    let digest = {
        let reader: &File = &file;
        let mut reader = reader.take(MAX_FILE + 1);
        let mut hasher = Sha256::new();
        let mut buffer = Zeroizing::new([0u8; 4096]);
        let mut total = 0u64;
        loop {
            let read = reader.read(buffer.as_mut_slice())?;
            if read == 0 {
                break;
            }
            total += read as u64;
            hasher.update(&buffer[..read]);
        }
        if total > MAX_FILE {
            return Ok(None);
        }
        hex(&hasher.finalize())
    };
    Ok(Some((digest, file)))
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
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gates a test's recovery takes: a lock directory beside the
    /// identity directory, no waiting.
    fn gates(identity: &Path) -> Gates {
        Gates {
            lock_dir: identity.parent().unwrap().join("locks"),
            retry: std::time::Duration::ZERO,
            held: None,
        }
    }

    /// [`super::write`] for files to install, under [`gates`].
    fn write(
        identity: &Path,
        op_id: &str,
        node: &str,
        root: &Path,
        files: &[FileSpec<'_>],
        commit: impl FnOnce() -> bool,
    ) -> Result<Outcome, WriteError> {
        super::write(
            identity,
            op_id,
            node,
            root,
            &Plan::install(files),
            &gates(identity),
            commit,
        )
    }

    /// [`super::recover`] under [`gates`].
    fn recover(identity: &Path) -> std::io::Result<Recovered> {
        super::recover(identity, &gates(identity))
    }

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
            wipe: Vec::new(),
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
        std::fs::rename(
            journal.files[0].staged.as_ref().unwrap(),
            &journal.files[0].target,
        )
        .unwrap();
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
        std::fs::rename(
            journal.files[0].staged.as_ref().unwrap(),
            &journal.files[0].target,
        )
        .unwrap();
        std::fs::rename(
            journal.files[1].staged.as_ref().unwrap(),
            &journal.files[1].target,
        )
        .unwrap();
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
    fn recovering_a_repair_clears_its_node() {
        let tmp = tempfile::tempdir().unwrap();
        let (identity, root) = (tmp.path().join("identity"), tmp.path().join("bee"));
        made(&identity);
        mark_unresolved(&identity, &NODES, true).unwrap();
        // A repair of Bee committed, then the process died before install.
        committed_journal(&identity, &root, "op-repair", b"k", b"c");
        assert!(matches!(
            recover(&identity).unwrap(),
            Recovered::Finished {
                status: OpStatus::Installed,
                ..
            }
        ));
        assert_eq!(unresolved(&identity).unwrap(), ["radicle"]);
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
        std::fs::remove_file(journal.files[1].staged.as_ref().unwrap()).unwrap();
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
        std::fs::remove_file(journal.files[0].staged.as_ref().unwrap()).unwrap();
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
