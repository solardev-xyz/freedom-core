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

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::anchor::{Dir, DirIdentity, Resolve};
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

/// A journal as a writer produces it: a member it doesn't write makes the
/// record no writer's, so recovery sets it aside (review of #177).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
/// already holds, and `held_identity` the directory identity that gate
/// recorded: a write recovers a journal of its own home under its own gate.
#[derive(Debug, Clone)]
pub struct Gates {
    pub lock_dir: PathBuf,
    pub retry: std::time::Duration,
    pub held: Option<PathBuf>,
    pub held_identity: Option<DirIdentity>,
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
    /// A Radicle journal, or the intent of a Radicle operation that died
    /// before its commit, was left in place: its home's gate is held, by the
    /// Radicle service, a `hold-lock`, or another core writing that home
    /// (0008, "Identity changes").
    Waiting {
        op_id: String,
        node: String,
    },
}

/// Runs the four steps for one operation. `Err` means nothing was committed.
/// An outstanding journal is recovered first; if that fails, or waits for a
/// Radicle home's gate, nothing is written. For a Radicle operation the
/// caller holds the home's gate throughout (`gates.held`).
///
/// `top` is the node's root, opened once by the caller ([`write_root`]):
/// a Radicle home after its gate was taken, before anything of it was read.
/// Staging, install and cleanup reach everything below it from that handle,
/// never by its path again (review of #177, round 2).
pub fn write(
    identity_dir: &Path,
    op_id: &str,
    node: &str,
    top: &Dir,
    plan: &Plan<'_>,
    gates: &Gates,
    commit: impl FnOnce() -> bool,
) -> Result<Outcome, WriteError> {
    let root = top.location();
    if !valid_op_id(op_id)
        || !normalized_absolute(root)
        || root == identity_dir
        || !shapes(node, root).contains(&plan.shape())
        // A Radicle home is written only under its gate, as its canonical
        // path.
        || (node == "radicle" && gates.held.as_deref() != Some(root))
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

    // 1. Stage, below the held root, and nothing below it reached through a
    // symlink.
    let mut journal = Journal {
        op_id: op_id.to_owned(),
        node: node.to_owned(),
        root: root.to_owned(),
        files: Vec::with_capacity(plan.entries.len()),
        wipe: plan.wipe.clone(),
    };
    for entry in &plan.entries {
        match entry {
            Entry::Install(file) => match stage(top, file) {
                Ok(staged) => journal.files.push(staged),
                Err(e) => {
                    discard(identity_dir, node, top);
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
            discard(identity_dir, node, top);
            return Ok(Outcome::Abandoned);
        }
        Err(fsx::WriteError::Io(e)) => {
            discard(identity_dir, node, top);
            return Err(e.into());
        }
        Err(fsx::WriteError::Check(reason)) => {
            discard(identity_dir, node, top);
            return Err(std::io::Error::other(reason).into());
        }
    }
    // The journal supersedes the intent.
    let _ = fsx::remove(&identity_dir.join(STAGING), || true);

    // 3 and 4. After the commit, a failure leaves the journal for recovery.
    Ok(match conclude(identity_dir, &journal, Some(top)) {
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
        return discard_intent(identity_dir, gates);
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
        match radicle_gate(&journal.root, gates, true)? {
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
    // The root, opened once, after the gate: everything below it is reached
    // from this handle. Gone, nothing under it exists. A Radicle home must
    // be the directory its gate was taken for.
    let identity = match &_home_gate {
        Some(gate) => gate.identity,
        None if gates.held.as_deref() == Some(journal.root.as_path()) => gates.held_identity,
        None => None,
    };
    let top = open_root(&journal.node, &journal.root, identity)?;
    let status = conclude(identity_dir, &journal, top.as_ref())?;
    let _ = fsx::remove(&identity_dir.join(STAGING), || true);
    Ok(Recovered::Finished {
        op_id: journal.op_id,
        node: journal.node,
        status,
    })
}

/// How a node's root is opened: a Radicle home as its gate's canonical
/// path, through no symlink, still where that path says, and (with the
/// gate's `identity`) the directory the gate was taken for; Bee's data
/// directory as main names it ([`Resolve`]).
fn resolve(node: &str, identity: Option<DirIdentity>) -> Resolve {
    if node == "radicle" {
        Resolve::Canonical(identity)
    } else {
        Resolve::Follow
    }
}

/// A journal's or an intent's root, opened once: `None` if it is gone.
fn open_root(
    node: &str,
    root: &Path,
    identity: Option<DirIdentity>,
) -> std::io::Result<Option<Dir>> {
    Dir::open_root(root, resolve(node, identity))
}

/// A writer's root, opened once before anything under it is read: a
/// Radicle home after its gate is taken (the gate made it), which must be
/// the directory that gate recorded (`identity`); Bee's data directory,
/// made if missing.
pub fn write_root(node: &str, root: &Path, identity: Option<DirIdentity>) -> std::io::Result<Dir> {
    if !normalized_absolute(root) {
        return Err(std::io::Error::other("a node's root that isn't absolute"));
    }
    if node != "radicle" {
        ensure_dir(root)?;
    }
    open_root(node, root, identity)?.ok_or_else(|| std::io::Error::other("a node's root is gone"))
}

enum HomeGate {
    /// Another process holds it.
    Held,
    /// Taken now (`Some`), or already the caller's (`None`).
    Taken(Option<fc_service::gate::Gate>),
}

/// The gate of the Radicle home `root`, unless the caller holds it already.
/// A Radicle journal's root is the gate's canonical path when it was
/// written: a root that no longer is (retargeted to a symlink since, or
/// renamed) is refused, and the journal stays (review of #177).
fn radicle_gate(root: &Path, gates: &Gates, create: bool) -> std::io::Result<HomeGate> {
    if gates.held.as_deref() == Some(root) {
        return Ok(HomeGate::Taken(None));
    }
    let acquired = if create {
        fc_service::gate::acquire(root, &gates.lock_dir, RADICLE_GATE, gates.retry)
    } else {
        fc_service::gate::acquire_existing(root, &gates.lock_dir, RADICLE_GATE, gates.retry)
    };
    match acquired {
        Ok(gate) if gate.data_dir == root => Ok(HomeGate::Taken(Some(gate))),
        Ok(_) => Err(std::io::Error::other(
            "a Radicle home that isn't its journal's canonical root",
        )),
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

/// The staged file's name beside its target's.
fn staged_name(name: &std::ffi::OsStr) -> std::ffi::OsString {
    let mut staged = name.to_owned();
    staged.push(STAGED_SUFFIX);
    staged
}

fn staged_path(target: &Path) -> PathBuf {
    let mut name = target.as_os_str().to_owned();
    name.push(STAGED_SUFFIX);
    PathBuf::from(name)
}

/// Step 1 for one file, below the held root ([`Dir`]: no symlink below it
/// is followed, and missing directories are made). A staged file left by an
/// earlier operation that died before its commit is replaced (recovery has
/// run, so no journal needs it).
fn stage(top: &Dir, file: &FileSpec<'_>) -> std::io::Result<JournalFile> {
    let (dir, name) = top
        .under(&file.target, true)?
        .ok_or_else(|| std::io::Error::other("a node identity directory can't be made"))?;
    let staged = staged_name(&name);
    dir.unlink(&staged)?;
    let result = (|| {
        let mut out = dir.create_new(&staged)?;
        out.write_all(file.contents)?;
        out.sync_all()?;
        dir.sync()
    })();
    if let Err(e) = result {
        let _ = dir.unlink(&staged);
        return Err(e);
    }
    Ok(JournalFile {
        target: file.target.clone(),
        staged: Some(staged_path(&file.target)),
        sha256: Some(hex(&Sha256::digest(file.contents))),
        remove: false,
    })
}

/// Step 3: the wipe, then each entry in order, all below the journal's
/// root, held open (`top`), and through no symlink below it ([`Dir`]). A
/// root that is gone (`None`) has nothing under it: removals are done, and
/// installs corrupt. Returns whether any file could not be installed
/// (corrupt).
fn install(journal: &Journal, top: Option<&Dir>) -> std::io::Result<bool> {
    let mut corrupt = false;
    let mut installed: Vec<PathBuf> = Vec::new();
    let under = |target: &Path| match top {
        Some(top) => top.under(target, false),
        None => Ok(None),
    };
    if let Some(top) = top {
        // Each is a directory right under the root (the journal's shapes).
        for dir in &journal.wipe {
            let name = dir
                .file_name()
                .ok_or_else(|| std::io::Error::other("a wipe that names no directory"))?;
            if top.remove_tree(name)? {
                top.sync()?;
            }
        }
    }
    for file in &journal.files {
        if file.remove {
            // A target already gone, or under a directory already gone, is
            // done; its directory is flushed only if something was removed.
            if let Some((dir, name)) = under(&file.target)?
                && dir.unlink(&name)?
            {
                dir.sync()?;
            }
            continue;
        }
        let Some(sha256) = &file.sha256 else {
            // valid_journal admits no other entry.
            return Err(std::io::Error::other("an install entry without its digest"));
        };
        let Some((dir, name)) = under(&file.target)? else {
            // Its directory is gone, its staged file with it.
            corrupt = true;
            continue;
        };
        let staged = staged_name(&name);
        if digest_at(&dir, &name)?.as_deref() == Some(sha256.as_str()) {
            // Already in place; a leftover staged copy is not needed.
            dir.unlink(&staged)?;
        } else if let Some((_, checked)) =
            digest_and_handle_at(&dir, &staged)?.filter(|(digest, _)| digest == sha256)
        {
            // The rename moves whatever the staged name holds: it must still
            // be the file just hashed (review of #114). If not, nothing is
            // renamed, and the journal stays for recovery to judge again.
            crate::testhooks::swap("checked", &dir.path(&staged));
            if !dir.same_file(&checked, &staged)? {
                return Err(std::io::Error::other(
                    "a staged node identity file changed after its check",
                ));
            }
            crate::testhooks::swap("renaming", &dir.path(&staged));
            // Replaces whatever is at the target, a symlink included, without
            // following it.
            dir.rename(&staged, &name)?;
            // A file that won the race between that check and the rename is
            // never left installed: the target must be the file checked, with
            // the journaled digest. Otherwise it is removed, and the node is
            // corrupt until a fresh write.
            let ours = dir.same_file(&checked, &name)?
                && digest_at(&dir, &name)?.as_deref() == Some(sha256.as_str());
            drop(checked);
            if !ours {
                crate::log::error(
                    "a node identity file was swapped during its install",
                    serde_json::json!({}),
                );
                dir.unlink(&name)?;
                corrupt = true;
                continue;
            }
        } else {
            corrupt = true;
            continue;
        }
        dir.sync()?;
        installed.push(dir.path(&name));
    }
    flush_installed(&installed);
    Ok(corrupt)
}

/// Windows: flushes each installed file, which commits NTFS's journal
/// through its rename (`fsx::sync_rename`; #85). Durability under power
/// loss is best effort there (design 0001), so a failure is logged, never
/// turned into `pending_recovery`. Unix flushed the directories instead.
fn flush_installed(installed: &[PathBuf]) {
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
fn conclude(
    identity_dir: &Path,
    journal: &Journal,
    top: Option<&Dir>,
) -> std::io::Result<OpStatus> {
    let corrupt = install(journal, top)?;
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

/// Before the commit: removes this operation's staged files, below the held
/// root, then its intent record.
fn discard(identity_dir: &Path, node: &str, top: &Dir) {
    for target in staged_targets(node, top.location()) {
        if let Ok(Some((dir, name))) = top.under(&target, false) {
            let _ = dir.unlink(&staged_name(&name));
        }
    }
    let _ = fsx::remove(&identity_dir.join(STAGING), || true);
}

/// No journal: an intent left by an operation that died before its commit
/// names staged files to remove (only the node layout's own).
fn discard_intent(identity_dir: &Path, gates: &Gates) -> std::io::Result<Recovered> {
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
        // The core's own staged names, through no symlink below the root, as
        // every node file is. A Radicle home's are fixed names that another
        // core writing the same home, under its gate, may be using now: so
        // they are removed only under that gate too, the caller's or taken
        // here (review of #177, round 4). Held, the intent stays. A root
        // that is gone holds none of this operation's (it died before it
        // made it, review of #177, round 2, or the root was removed since):
        // its intent goes without the gate, which would make the home, and
        // without looking under the root, which another writer may be making
        // meanwhile.
        //
        // A home that is there is gated without being made, and must be the
        // directory seen (review of #177, round 5): if it is gone or another
        // directory by the time the gate is taken, the intent stays and the
        // recovery fails (`pending_recovery`), so nothing is made and the
        // moved home's staged files aren't forgotten.
        let seen = match std::fs::symlink_metadata(&intent.root) {
            Ok(metadata) => Some(DirIdentity::of(&metadata)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        #[cfg(test)]
        tests::INTENT_SEEN.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook(&intent.root, seen.is_some());
            }
        });
        if let Some(seen) = seen {
            let changed = || {
                std::io::Error::other("a Radicle home that changed while its intent was cleaned up")
            };
            let mut identity = None;
            let _home_gate = if intent.node == "radicle" {
                match radicle_gate(&intent.root, gates, false) {
                    Ok(HomeGate::Held) => {
                        return Ok(Recovered::Waiting {
                            op_id: intent.op_id,
                            node: intent.node,
                        });
                    }
                    Ok(HomeGate::Taken(gate)) => {
                        identity = match &gate {
                            Some(gate) => gate.identity,
                            None => gates.held_identity,
                        };
                        if seen.is_some() && identity.is_some() && identity != seen {
                            return Err(changed());
                        }
                        gate
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(changed()),
                    Err(e) => return Err(e),
                }
            } else {
                None
            };
            if let Some(top) = open_root(&intent.node, &intent.root, identity)? {
                for target in staged_targets(&intent.node, &intent.root) {
                    if let Some((dir, name)) = top.under(&target, false)? {
                        dir.unlink(&staged_name(&name))?;
                    }
                }
            }
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

/// The SHA-256 of the regular file `name` in `dir` (of at most
/// [`MAX_FILE`], through no symlink, judged on the open handle), hashed
/// through a wiped buffer: node files hold private keys and passwords.
/// `None` for anything else.
fn digest_at(dir: &Dir, name: &std::ffi::OsStr) -> std::io::Result<Option<String>> {
    Ok(digest_and_handle_at(dir, name)?.map(|(digest, _)| digest))
}

/// [`digest_at`], with the handle the digest was taken through.
fn digest_and_handle_at(
    dir: &Dir,
    name: &std::ffi::OsStr,
) -> std::io::Result<Option<(String, File)>> {
    let file = match dir.open_regular(name, false)? {
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

    /// What runs between the intent cleanup's look at its home and the gate.
    type Seen = Option<Box<dyn FnMut(&Path, bool)>>;

    std::thread_local! {
        /// Runs between the intent cleanup's look at its home (whether it is
        /// there) and the gate, so a test can move the home in between.
        pub(super) static INTENT_SEEN: std::cell::RefCell<Seen> = std::cell::RefCell::new(None);
    }

    /// The gates a test's recovery takes: a lock directory beside the
    /// identity directory, no waiting.
    fn gates(identity: &Path) -> Gates {
        Gates {
            lock_dir: identity.parent().unwrap().join("locks"),
            retry: std::time::Duration::ZERO,
            held: None,
            held_identity: None,
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
        // As the writer does: the root opened once, then written below.
        if !normalized_absolute(root) {
            return Err(WriteError::Layout);
        }
        let top = super::write_root(node, root, None)?;
        super::write(
            identity,
            op_id,
            node,
            &top,
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
            files: {
                let top = write_root("bee", root, None).unwrap();
                files.iter().map(|f| stage(&top, f).unwrap()).collect()
            },
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
            stage(&write_root("bee", &root, None).unwrap(), &file).unwrap();
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

    /// Review of #177, round 2 (M3): an operation that died after its intent
    /// and before it made its root (Bee's data directory, made at staging)
    /// leaves an intent whose root isn't there. Recovery discards it, makes
    /// nothing, and so never blocks the next write. A root that is there but
    /// isn't a directory is still refused, and the intent stays.
    #[test]
    fn an_intent_from_before_its_root_was_made_is_discarded() {
        for node in ["bee", "radicle"] {
            let tmp = tempfile::tempdir().unwrap();
            let identity = made(&tmp.path().join("identity"));
            let root = tmp.path().join("not-made-yet");
            let intent = Intent {
                op_id: "before-stage".into(),
                node: node.into(),
                root: root.clone(),
            };
            put_record(&identity, STAGING, &intent).unwrap();
            assert_eq!(recover(&identity).unwrap(), Recovered::Discarded, "{node}");
            assert!(!identity.join(STAGING).exists(), "{node}");
            assert!(!root.exists(), "{node}");

            std::fs::write(&root, b"not a directory").unwrap();
            put_record(&identity, STAGING, &intent).unwrap();
            assert!(recover(&identity).is_err(), "{node}");
            assert!(identity.join(STAGING).exists(), "{node}");
        }
    }

    /// Review of #177, round 2 (M1): the home is opened once, after its gate,
    /// and held. Renamed after staging, with a symlink to another home (whose
    /// gate its service holds) in its place, the commit's removals and
    /// install still land in the home that was planned and staged in; the
    /// other home is untouched.
    #[cfg(unix)]
    #[test]
    fn a_committed_switch_stays_in_the_home_it_staged_in() {
        let tmp = tempfile::tempdir().unwrap();
        let identity = tmp.path().join("identity");
        let locks = tmp.path().join("locks");
        for (dir, key) in [("home", "own"), ("other-home", "other")] {
            let keys = tmp.path().join(dir).join("keys");
            std::fs::create_dir_all(&keys).unwrap();
            std::fs::write(keys.join("radicle"), format!("{key} private key")).unwrap();
            std::fs::write(keys.join("radicle.pub"), format!("{key} public key")).unwrap();
        }
        let zero = std::time::Duration::ZERO;
        let gate = fc_service::gate::acquire(&tmp.path().join("home"), &locks, RADICLE_GATE, zero)
            .unwrap();
        let other_gate =
            fc_service::gate::acquire(&tmp.path().join("other-home"), &locks, RADICLE_GATE, zero)
                .unwrap();
        let (home, other) = (gate.data_dir.clone(), other_gate.data_dir.clone());
        let moved = home.with_file_name("moved-home");
        let gates = Gates {
            lock_dir: locks,
            retry: zero,
            held: Some(home.clone()),
            held_identity: gate.identity,
        };
        let plan = Plan {
            entries: vec![
                Entry::Remove(home.join("keys/radicle")),
                Entry::Remove(home.join("keys/radicle.pub")),
                Entry::Install(FileSpec {
                    target: home.join("config.json"),
                    contents: b"{}",
                }),
            ],
            wipe: Vec::new(),
        };
        let top = write_root("radicle", &home, gate.identity).unwrap();
        let outcome = super::write(
            &identity,
            "root-swap",
            "radicle",
            &top,
            &plan,
            &gates,
            || {
                std::fs::rename(&home, &moved).unwrap();
                std::os::unix::fs::symlink(&other, &home).unwrap();
                true
            },
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Installed);
        assert_eq!(
            std::fs::read(other.join("keys/radicle")).unwrap(),
            b"other private key"
        );
        assert_eq!(
            std::fs::read(other.join("keys/radicle.pub")).unwrap(),
            b"other public key"
        );
        assert!(!other.join("config.json").exists());
        assert!(!moved.join("keys/radicle").exists());
        assert!(!moved.join("keys/radicle.pub").exists());
        assert_eq!(std::fs::read(moved.join("config.json")).unwrap(), b"{}");
        // And a write that finds the home replaced before it opens it is
        // refused: the canonical home isn't where its gate is.
        assert!(write_root("radicle", &home, gate.identity).is_err());
    }

    /// Review of #177, round 3 (m1): a home replaced after its gate was
    /// taken by another real directory, no symlink anywhere, is refused
    /// where the gate recorded the directory's identity (Unix), and nothing
    /// of either directory is touched. Without that identity (Windows has
    /// none), the open checks the path alone, and takes what is there: the
    /// limit design 0001 states.
    #[cfg(unix)]
    #[test]
    fn a_home_replaced_by_another_directory_after_its_gate_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let locks = tmp.path().join("locks");
        for dir in ["home", "elsewhere"] {
            let keys = tmp.path().join(dir).join("keys");
            std::fs::create_dir_all(&keys).unwrap();
            std::fs::write(keys.join("radicle"), dir).unwrap();
        }
        let zero = std::time::Duration::ZERO;
        let gate = fc_service::gate::acquire(&tmp.path().join("home"), &locks, RADICLE_GATE, zero)
            .unwrap();
        assert!(gate.identity.is_some());
        let home = gate.data_dir.clone();
        std::fs::rename(&home, home.with_file_name("away")).unwrap();
        std::fs::rename(home.with_file_name("elsewhere"), &home).unwrap();
        let refused = write_root("radicle", &home, gate.identity);
        assert!(refused.is_err());
        assert_eq!(
            std::fs::read(home.join("keys/radicle")).unwrap(),
            b"elsewhere"
        );
        assert_eq!(
            std::fs::read(home.with_file_name("away").join("keys/radicle")).unwrap(),
            b"home"
        );
        // The path's checks alone pass: a real directory is at the
        // canonical path.
        assert!(write_root("radicle", &home, None).is_ok());
    }

    /// Review of #177, round 4: another core writing the same Radicle home
    /// holds its gate and has staged its config. This core's recovery of an
    /// intent of its own for that home waits for the gate rather than
    /// remove those fixed staged names: the other write installs. Once the
    /// gate is free, the intent goes.
    #[test]
    fn an_intent_waits_for_its_homes_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let home = base.join("home");
        let locks = base.join("locks");
        let (first, second) = (made(&base.join("identity-a")), base.join("identity-b"));
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join("config.json"), b"{\"old\":true}").unwrap();
        let intent = Intent {
            op_id: "earlier".into(),
            node: "radicle".into(),
            root: home.clone(),
        };
        put_record(&first, STAGING, &intent).unwrap();
        let zero = std::time::Duration::ZERO;
        let gate = fc_service::gate::acquire(&home, &locks, RADICLE_GATE, zero).unwrap();
        let writing = Gates {
            lock_dir: locks.clone(),
            retry: zero,
            held: Some(home.clone()),
            held_identity: gate.identity,
        };
        let recovering = Gates {
            lock_dir: locks,
            retry: zero,
            held: None,
            held_identity: None,
        };
        let plan = Plan {
            entries: vec![
                Entry::Remove(home.join("keys/radicle")),
                Entry::Remove(home.join("keys/radicle.pub")),
                Entry::Install(FileSpec {
                    target: home.join("config.json"),
                    contents: b"{\"new\":true}",
                }),
            ],
            wipe: Vec::new(),
        };
        let top = write_root("radicle", &home, gate.identity).unwrap();
        let outcome = super::write(&second, "live", "radicle", &top, &plan, &writing, || {
            assert!(home.join("config.json.freedom-new").exists());
            assert_eq!(
                super::recover(&first, &recovering).unwrap(),
                Recovered::Waiting {
                    op_id: "earlier".into(),
                    node: "radicle".into(),
                }
            );
            assert!(home.join("config.json.freedom-new").exists());
            true
        })
        .unwrap();
        assert_eq!(outcome, Outcome::Installed);
        assert_eq!(
            std::fs::read(home.join("config.json")).unwrap(),
            b"{\"new\":true}"
        );
        assert!(first.join(STAGING).exists());
        drop(top);
        drop(gate);
        assert_eq!(
            super::recover(&first, &recovering).unwrap(),
            Recovered::Discarded
        );
        assert!(!first.join(STAGING).exists());
    }

    /// Review of #177, round 5: a home moved away between the intent
    /// cleanup's look at it and the gate isn't made again at its path, and
    /// its intent isn't dropped (its staged files are in the moved home):
    /// the recovery fails, closed. The same when another owner holds the
    /// gate of the home it moves.
    #[cfg(unix)]
    #[test]
    fn a_home_moved_before_its_cleanup_gate_is_neither_made_nor_forgotten() {
        for held_by_another in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let base = std::fs::canonicalize(tmp.path()).unwrap();
            let (home, moved) = (base.join("home"), base.join("moved"));
            let identity = made(&base.join("identity"));
            let locks = base.join("locks");
            std::fs::create_dir(&home).unwrap();
            std::fs::write(home.join("config.json.freedom-new"), b"staged").unwrap();
            let intent = Intent {
                op_id: "earlier".into(),
                node: "radicle".into(),
                root: home.clone(),
            };
            put_record(&identity, STAGING, &intent).unwrap();
            let owner = std::rc::Rc::new(std::cell::RefCell::new(None));
            let (held, other_locks, to) = (owner.clone(), locks.clone(), moved.clone());
            INTENT_SEEN.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |root, present| {
                    assert!(present);
                    if held_by_another {
                        *held.borrow_mut() = Some(
                            fc_service::gate::acquire(
                                root,
                                &other_locks,
                                RADICLE_GATE,
                                std::time::Duration::ZERO,
                            )
                            .unwrap(),
                        );
                    }
                    std::fs::rename(root, &to).unwrap();
                }));
            });
            let gates = Gates {
                lock_dir: locks,
                retry: std::time::Duration::ZERO,
                held: None,
                held_identity: None,
            };
            let recovered = super::recover(&identity, &gates);
            INTENT_SEEN.with(|hook| *hook.borrow_mut() = None);
            assert!(
                !matches!(recovered, Ok(Recovered::Discarded)),
                "{held_by_another}: {recovered:?}"
            );
            assert!(!home.exists(), "{held_by_another}: the home was made again");
            assert!(identity.join(STAGING).exists(), "{held_by_another}");
            assert!(moved.join("config.json.freedom-new").exists());
        }
    }

    /// Review of #177, round 5: a home replaced by another directory between
    /// the cleanup's look and the gate is refused: nothing of the other
    /// directory is removed, and the intent stays.
    #[cfg(unix)]
    #[test]
    fn a_home_replaced_before_its_cleanup_gate_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let (home, other) = (base.join("home"), base.join("other"));
        let identity = made(&base.join("identity"));
        for dir in [&home, &other] {
            std::fs::create_dir(dir).unwrap();
            std::fs::write(dir.join("config.json.freedom-new"), b"staged").unwrap();
        }
        let intent = Intent {
            op_id: "earlier".into(),
            node: "radicle".into(),
            root: home.clone(),
        };
        put_record(&identity, STAGING, &intent).unwrap();
        let (from, away) = (other.clone(), base.join("away"));
        INTENT_SEEN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |root, _| {
                std::fs::rename(root, &away).unwrap();
                std::fs::rename(&from, root).unwrap();
            }));
        });
        let gates = Gates {
            lock_dir: base.join("locks"),
            retry: std::time::Duration::ZERO,
            held: None,
            held_identity: None,
        };
        let recovered = super::recover(&identity, &gates);
        INTENT_SEEN.with(|hook| *hook.borrow_mut() = None);
        assert!(recovered.is_err(), "{recovered:?}");
        assert!(home.join("config.json.freedom-new").exists());
        assert!(identity.join(STAGING).exists());
    }
}
