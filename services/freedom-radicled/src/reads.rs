//! `rad.read` (design 0008, "Methods", "Deadlines", "Errors", "Pools and
//! budgets" and "JSON results"), on the read pool with its 60 s deadline to
//! the head ([`crate::pools`]): the pass-through ops here, and the composed
//! ops and those of main's serialization in [`composed`].
//!
//! **`rad.read { op, args }`** answers a head, `{ content_type:
//! "application/json", bytes }`, then the JSON as a body stream: the exact
//! text the add-on returns for that export, with today's arguments, by
//! name. Each op is libradicle's bounded read, and libradicle's own
//! serializer (`libradicle::json`), unchanged:
//! - `repo_info { rid }`;
//! - `tree { rid, path }` and `tree_at { rid, revision, path }`;
//! - `blob { rid, path }` and `blob_at { rid, revision, path }`;
//! - `commits { rid, parent, page, per_page }`, `per_page` cut to
//!   libradicle's `BINDING_MAX_PER_PAGE` (100), as the add-on cuts it; and
//!   `commit { rid, revision }`, whose diff libradicle decodes lossily
//!   where it isn't UTF-8;
//! - `issues { rid }` and `patches { rid }`, the COB ops;
//! - `list_repos` and `list_seeded_repos`;
//! - `seeders { rid }`, with the node held exclusively, as libradicle's
//!   `seeders` takes `&mut self`; `identity` and `status`.
//!
//! The other ops 0008 lists ([`composed`]): of main's serialization,
//! `issue { rid, issue_id }`, `patch { rid, patch_id }`, `remotes { rid }`
//! and `repo_stats { rid, revision }`; composed, `readme_at { rid,
//! revision }`, `repo_meta { rid }`, `repos_meta`, `issues_page` and
//! `patches_page { rid, status, page, per_page }`, and `node_info`.
//!
//! The ops without args take none, null or `{}`. A revision is 40
//! lowercase hex digits, as main checks it; a COB ID 6 to 40, as
//! libradicle checks it, refused with its text. A page's `status`, `page`
//! and `per_page` are strings or null.
//!
//! **Before the build, in this order:**
//! 1. the pool's own refusals: `stopped` before `RUNNING` and from the stop
//!    on, `busy` past its bounds;
//! 2. params that don't parse, read at admission and answered by the work:
//!    `invalid_argument`. That is an op 0008 doesn't list, args it doesn't
//!    take, a RID, or a revision or `parent` that isn't 40 lowercase hex,
//!    and a path (`tree`, `tree_at`, `blob`, `blob_at`) of more than
//!    libradicle's `MAX_TREE_DEPTH` components, 4096 ([`path`]): each is a
//!    tree its walk would load;
//! 3. **the fence** ([`fence`]), for an op that names a repository:
//!    - quarantined at the gate: `quarantined`, with `data.kind` and
//!      `data.step` from the record ([`crate::quarantine::refusal`]), for
//!      the COB ops (`issues`, `issue`, `patches`, `patch`, `issues_page`,
//!      `patches_page`), and for every op of a `namespace` quarantine that
//!      names the repository (the listings, `repos_meta` among them, list
//!      it as they do any);
//!    - the COB ops answer `stopped` while the repository is being
//!      repaired, and while a COB write to it is past its mutation start
//!      and not proven, or its online repair is queued
//!      ([`crate::pools::Pools::writing`]): what such a write leaves may be
//!      partial until its repair publishes;
//!
//!    The fence is looked at once, here: a read already building when a
//!    write starts, or a repair closes its repository, finishes on what it
//!    read, as a read just before them would have.
//!
//! **The build and its JSON** ([`crate::output::json_read`]) reserve from
//! the process's output budget before they allocate, inside the read's
//! deadline and its token: the walk's whole 32 MiB first, then the JSON in
//! 64 KiB steps, at most 32 MiB of it. The walk gets half of those 32 MiB
//! for the items it builds and half for the objects it loads, the add-on's
//! 16 MiB of each, as a walk can hold both at once. libradicle charges
//! each commit and tree a walk loads what libgit2 holds of it once parsed,
//! from its header (`libradicle::commit_held`, `libradicle::tree_held`),
//! and libgit2's object cache, which would keep them past the walk, is off
//! ([`uncache`]). A read past a cap is `too_large`; one whose deadline
//! ends a wait is `deadline`. One whose token is cancelled,
//! in a wait or in its walk, is answered by whoever cancelled it: main's
//! cancel `cancelled`, the timer `deadline`, the stop `stopped`. The
//! node is held for the build alone, never while the body waits for credit.
//! Two results are copied as libradicle writes them, with a `json!` value,
//! so their build is bounded for the copy too:
//! - **`repo_info`'s** walk takes half its items' 16 MiB, so the value's
//!   copy, about the result's size, fits beside it;
//! - **a blob** is loaded only up to half the built budget, 16 MiB (the
//!   add-on's cap too, `libradicle::BINDING_READ_BUDGET`), its size read
//!   from its header first ([`bounded_blob`]), as libgit2's buffer and
//!   libradicle's copy of it are both held while it loads; libgit2's NUL
//!   and structs beside them, 257 bytes, are reserved with the build
//!   ([`BESIDE`]). Its walk is libradicle's, within the add-on's 16 MiB of
//!   loads, and dropped before the blob loads. Then what its JSON's writing
//!   holds beside the JSON ([`blob_held`]): its content, and for text the
//!   value's copy of it, and before that the lossy copy of one that isn't
//!   UTF-8, three bytes for each invalid sequence. Past the built budget it
//!   is `too_large`.
//!
//! **libradicle's errors:** `not_found` when the message matches today's
//! test (`not found`, `does not exist` or `NotFound`, in any case),
//! otherwise `failed` ([`radicle_error`]). The message is libradicle's, as
//! today, only where it can't name a filesystem path ([`pathless`]); main
//! sends it on to pages. A repository the node doesn't have, whose
//! libradicle text names its storage path under the home, is `not_found`
//! with `repository not found`, the text main's public route gives it; any
//! other error that could name a path is `not found` or `the read failed`,
//! by its code (0008's deviation `pathless-errors`). Neither is logged.
//!
//! **The head** is queued only before the deadline, with its bytes reserved
//! until it is written; from the deadline on the reply is `deadline`. Then
//! the body, one data frame per chunk, each chunk's reservation released
//! once it is queued, waiting for main's credit as long as main takes: no
//! service deadline after the head. Main's cancel and the stop end the wait
//! and the stream; the stop's is then aborted `stopped`
//! ([`crate::pools`]), and a panic's `internal`.

use std::path::Path;
use std::str::FromStr as _;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::{Connection, Headed};
use libradicle::{BINDING_MAX_PER_PAGE, Blob, Bounds, MAX_TREE_DEPTH, json};
use radicle::git::raw::{ErrorClass as GitClass, ErrorCode as GitCode};
use radicle::node::gate::{self, RepoGate, RepoState};
use radicle::prelude::RepoId;
use radicle::storage::RepositoryError;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;
use serde_json::{Value, json};

use crate::node::{Handle, Node};
use crate::output::{BUILT, Body, Budget, Failure, Refused, Until, json_read, json_read_beside};
use crate::pools::{Pools, Ticket, Work};
use crate::{quarantine, testhooks};
use composed::Cobs;

mod blob;
mod composed;
mod js;

pub use blob::blob;

/// How often a body waiting for credit looks at its token.
const POLL: Duration = Duration::from_millis(10);

/// Turns libgit2's object cache off, for the whole process (0008, "Pools
/// and budgets"). With it on, every commit and tree under 4 KiB that a
/// repository handle loads stays parsed in its cache until the handle
/// closes, against a limit of 256 MiB counted in the objects' bytes, not in
/// what their parse holds: past any read's reservation. With it off, what a
/// walk loads is freed once the walk drops it, so a walk holds at most what
/// libradicle has charged it.
///
/// Nothing in the service needs the cache: heartwood's node, its fetches,
/// the reconciliation, the repairs, the writes and the reads all read
/// objects through libgit2 the same way with it off, each object read from
/// the object database again where it would have been found in the cache.
/// The packs' own delta-base caches aren't this option's, and stay.
///
/// libgit2 keeps the option in a global it reads unlocked, as it does its
/// search paths: `main` sets it once, before any thread can use libgit2.
pub fn uncache() {
    git2::opts::enable_caching(false);
}

/// Whether libgit2's object cache keeps what a repository loads: whether a
/// tree looked up twice, in a repository held in memory, is one object.
#[cfg(any(test, feature = "testhooks"))]
pub fn object_cache_on() -> Result<bool, git2::Error> {
    use git2::{Binding as _, ObjectType, Odb, Repository};
    let odb = Odb::new()?;
    odb.add_new_mempack_backend(1)?;
    let repo = Repository::from_odb(odb)?;
    let tree = repo.odb()?.write(ObjectType::Tree, &[])?;
    let first = repo.find_tree(tree)?;
    let second = repo.find_tree(tree)?;
    Ok(first.raw() == second.raw())
}

/// `rad.read`'s params.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadParams {
    op: String,
    #[serde(default)]
    args: Value,
}

/// `{ rid }`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RidArgs {
    rid: String,
}

/// `{ rid, path }`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathArgs {
    rid: String,
    path: String,
}

/// `{ rid, revision }`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionArgs {
    rid: String,
    revision: String,
}

/// `{ rid, revision, path }`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AtArgs {
    rid: String,
    revision: String,
    path: String,
}

/// `commits`' args: the add-on's, `page` and `per_page` as its `u32`s.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitsArgs {
    rid: String,
    parent: String,
    page: u32,
    per_page: u32,
}

/// `{ rid, issue_id }`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueArgs {
    rid: String,
    issue_id: String,
}

/// `{ rid, patch_id }`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchArgs {
    rid: String,
    patch_id: String,
}

/// A page's args: its query's raw `status`, `page` and `perPage`, each a
/// string or null.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageArgs {
    rid: String,
    status: Option<String>,
    page: Option<String>,
    per_page: Option<String>,
}

/// An op, its args checked.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    RepoInfo {
        rid: RepoId,
    },
    Tree {
        rid: RepoId,
        path: String,
    },
    TreeAt {
        rid: RepoId,
        revision: String,
        path: String,
    },
    Blob {
        rid: RepoId,
        path: String,
    },
    BlobAt {
        rid: RepoId,
        revision: String,
        path: String,
    },
    Commits {
        rid: RepoId,
        parent: String,
        page: usize,
        per_page: usize,
    },
    Commit {
        rid: RepoId,
        revision: String,
    },
    Issues {
        rid: RepoId,
    },
    Patches {
        rid: RepoId,
    },
    ListRepos,
    ListSeededRepos,
    Seeders {
        rid: RepoId,
    },
    Identity,
    Status,
    Issue {
        rid: RepoId,
        id: String,
    },
    Patch {
        rid: RepoId,
        id: String,
    },
    Remotes {
        rid: RepoId,
    },
    RepoStats {
        rid: RepoId,
        revision: String,
    },
    ReadmeAt {
        rid: RepoId,
        revision: String,
    },
    RepoMeta {
        rid: RepoId,
    },
    ReposMeta,
    Page {
        rid: RepoId,
        cobs: Cobs,
        status: Option<String>,
        page: Option<String>,
        per_page: Option<String>,
    },
    NodeInfo,
}

impl Op {
    /// The repository it reads, if it names one.
    fn rid(&self) -> Option<RepoId> {
        match self {
            Op::RepoInfo { rid }
            | Op::Tree { rid, .. }
            | Op::TreeAt { rid, .. }
            | Op::Blob { rid, .. }
            | Op::BlobAt { rid, .. }
            | Op::Commits { rid, .. }
            | Op::Commit { rid, .. }
            | Op::Issues { rid }
            | Op::Patches { rid }
            | Op::Seeders { rid }
            | Op::Issue { rid, .. }
            | Op::Patch { rid, .. }
            | Op::Remotes { rid }
            | Op::RepoStats { rid, .. }
            | Op::ReadmeAt { rid, .. }
            | Op::RepoMeta { rid }
            | Op::Page { rid, .. } => Some(*rid),
            Op::ListRepos
            | Op::ListSeededRepos
            | Op::Identity
            | Op::Status
            | Op::ReposMeta
            | Op::NodeInfo => None,
        }
    }

    /// Whether it is a COB op, which the repair fences.
    fn cob(&self) -> bool {
        matches!(
            self,
            Op::Issues { .. }
                | Op::Patches { .. }
                | Op::Issue { .. }
                | Op::Patch { .. }
                | Op::Page { .. }
        )
    }
}

fn invalid(message: &str) -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, message)
}

fn parse<T: DeserializeOwned>(params: Option<&RawValue>) -> Option<T> {
    params.and_then(|raw| serde_json::from_str(raw.get()).ok())
}

fn args<T: DeserializeOwned>(args: Value, takes: &str) -> Result<T, ErrorBody> {
    serde_json::from_value(args).map_err(|_| invalid(takes))
}

/// No args: none, null or `{}`.
fn none(args: &Value, takes: &str) -> Result<(), ErrorBody> {
    if args.is_null() || args.as_object().is_some_and(serde_json::Map::is_empty) {
        Ok(())
    } else {
        Err(invalid(takes))
    }
}

fn rid(rid: &str) -> Result<RepoId, ErrorBody> {
    RepoId::from_str(rid).map_err(|_| invalid("rid isn't a repository ID"))
}

/// A path of at most libradicle's `MAX_TREE_DEPTH` components (4096, git's
/// own default `core.maxTreeDepth`), as libradicle walks a path: `/` its
/// separator, empty components skipped. Each component is a tree the walk
/// loads, so a longer one is refused here, before the repository is opened
/// (0008, "Pools and budgets"; deviation `path-depth`).
fn path(path: String) -> Result<String, ErrorBody> {
    if path.split('/').filter(|c| !c.is_empty()).count() > MAX_TREE_DEPTH {
        return Err(invalid(&format!(
            "path has more than {MAX_TREE_DEPTH} components"
        )));
    }
    Ok(path)
}

/// A full commit ID, as main checks it: 40 lowercase hex digits.
fn revision(revision: String, what: &str) -> Result<String, ErrorBody> {
    let hex = revision
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if revision.len() == 40 && hex {
        Ok(revision)
    } else {
        Err(invalid(&format!(
            "{what} isn't a commit ID (40 lowercase hex digits)"
        )))
    }
}

/// A COB ID, as libradicle checks it: 6 to 40 lowercase hex digits,
/// refused with its text.
fn cob_id(id: String) -> Result<String, ErrorBody> {
    let hex = id
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if (6..=40).contains(&id.len()) && hex {
        Ok(id)
    } else {
        Err(invalid(&libradicle::Error::InvalidCobId(id).to_string()))
    }
}

/// A page's args.
fn page(given: Value, op: &str, cobs: Cobs) -> Result<Op, ErrorBody> {
    let a: PageArgs = args(
        given,
        &format!("{op} takes {{ rid, status, page, per_page }}"),
    )?;
    Ok(Op::Page {
        rid: rid(&a.rid)?,
        cobs,
        status: a.status,
        page: a.page,
        per_page: a.per_page,
    })
}

/// `rad.read`'s params, checked (see the module's doc).
fn op(params: Option<&RawValue>) -> Result<Op, ErrorBody> {
    let ReadParams { op, args: given } =
        parse(params).ok_or_else(|| invalid("rad.read takes { op, args }"))?;
    match op.as_str() {
        "repo_info" => {
            let a: RidArgs = args(given, "repo_info takes { rid }")?;
            Ok(Op::RepoInfo { rid: rid(&a.rid)? })
        }
        "tree" => {
            let a: PathArgs = args(given, "tree takes { rid, path }")?;
            Ok(Op::Tree {
                rid: rid(&a.rid)?,
                path: path(a.path)?,
            })
        }
        "tree_at" => {
            let a: AtArgs = args(given, "tree_at takes { rid, revision, path }")?;
            Ok(Op::TreeAt {
                rid: rid(&a.rid)?,
                revision: revision(a.revision, "revision")?,
                path: path(a.path)?,
            })
        }
        "blob" => {
            let a: PathArgs = args(given, "blob takes { rid, path }")?;
            Ok(Op::Blob {
                rid: rid(&a.rid)?,
                path: path(a.path)?,
            })
        }
        "blob_at" => {
            let a: AtArgs = args(given, "blob_at takes { rid, revision, path }")?;
            Ok(Op::BlobAt {
                rid: rid(&a.rid)?,
                revision: revision(a.revision, "revision")?,
                path: path(a.path)?,
            })
        }
        "commits" => {
            let a: CommitsArgs = args(given, "commits takes { rid, parent, page, per_page }")?;
            Ok(Op::Commits {
                rid: rid(&a.rid)?,
                parent: revision(a.parent, "parent")?,
                page: a.page as usize,
                per_page: (a.per_page as usize).min(BINDING_MAX_PER_PAGE),
            })
        }
        "commit" => {
            let a: RevisionArgs = args(given, "commit takes { rid, revision }")?;
            Ok(Op::Commit {
                rid: rid(&a.rid)?,
                revision: revision(a.revision, "revision")?,
            })
        }
        "issues" => {
            let a: RidArgs = args(given, "issues takes { rid }")?;
            Ok(Op::Issues { rid: rid(&a.rid)? })
        }
        "patches" => {
            let a: RidArgs = args(given, "patches takes { rid }")?;
            Ok(Op::Patches { rid: rid(&a.rid)? })
        }
        "list_repos" => none(&given, "list_repos takes no args").map(|()| Op::ListRepos),
        "list_seeded_repos" => {
            none(&given, "list_seeded_repos takes no args").map(|()| Op::ListSeededRepos)
        }
        "seeders" => {
            let a: RidArgs = args(given, "seeders takes { rid }")?;
            Ok(Op::Seeders { rid: rid(&a.rid)? })
        }
        "identity" => none(&given, "identity takes no args").map(|()| Op::Identity),
        "status" => none(&given, "status takes no args").map(|()| Op::Status),
        "issue" => {
            let a: IssueArgs = args(given, "issue takes { rid, issue_id }")?;
            Ok(Op::Issue {
                rid: rid(&a.rid)?,
                id: cob_id(a.issue_id)?,
            })
        }
        "patch" => {
            let a: PatchArgs = args(given, "patch takes { rid, patch_id }")?;
            Ok(Op::Patch {
                rid: rid(&a.rid)?,
                id: cob_id(a.patch_id)?,
            })
        }
        "remotes" => {
            let a: RidArgs = args(given, "remotes takes { rid }")?;
            Ok(Op::Remotes { rid: rid(&a.rid)? })
        }
        "repo_stats" => {
            let a: RevisionArgs = args(given, "repo_stats takes { rid, revision }")?;
            Ok(Op::RepoStats {
                rid: rid(&a.rid)?,
                revision: revision(a.revision, "revision")?,
            })
        }
        "readme_at" => {
            let a: RevisionArgs = args(given, "readme_at takes { rid, revision }")?;
            Ok(Op::ReadmeAt {
                rid: rid(&a.rid)?,
                revision: revision(a.revision, "revision")?,
            })
        }
        "repo_meta" => {
            let a: RidArgs = args(given, "repo_meta takes { rid }")?;
            Ok(Op::RepoMeta { rid: rid(&a.rid)? })
        }
        "repos_meta" => none(&given, "repos_meta takes no args").map(|()| Op::ReposMeta),
        "issues_page" => page(given, "issues_page", Cobs::Issues),
        "patches_page" => page(given, "patches_page", Cobs::Patches),
        "node_info" => none(&given, "node_info takes no args").map(|()| Op::NodeInfo),
        _ => Err(invalid(
            "op is one of repo_info, tree, tree_at, blob, blob_at, commits, commit, issues, \
             patches, list_repos, list_seeded_repos, seeders, identity, status, issue, patch, \
             remotes, repo_stats, readme_at, repo_meta, repos_meta, issues_page, patches_page \
             and node_info",
        )),
    }
}

/// Why `op` can't read its repository now, if it can't (see the module's
/// doc): `gate` says where the repository stands, and `writing` whether a
/// COB write to it is past its start and unproven, or its repair queued.
fn fence(
    home: &Path,
    gate: &RepoGate,
    writing: impl Fn(&RepoId) -> bool,
    op: &Op,
) -> Option<ErrorBody> {
    fenced(home, gate, writing, op.rid()?, op.cob())
}

/// Why a read of `rid` can't read it now, if it can't: [`fence`]'s, for a
/// COB op when `cob` says so (`rad.blob` isn't one).
fn fenced(
    home: &Path,
    gate: &RepoGate,
    writing: impl Fn(&RepoId) -> bool,
    rid: RepoId,
    cob: bool,
) -> Option<ErrorBody> {
    match gate.state(&rid) {
        RepoState::Quarantined(kind) if cob || kind == gate::Quarantine::Namespace => {
            Some(quarantine::refusal(home, rid, kind))
        }
        RepoState::Repairing if cob => Some(ErrorBody::new(
            ErrorCode::Stopped,
            "the repository is being repaired",
        )),
        _ if cob && writing(&rid) => Some(ErrorBody::new(
            ErrorCode::Stopped,
            "a write to the repository is under way, and its outcome isn't proven yet",
        )),
        RepoState::Open | RepoState::Repairing | RepoState::Quarantined(_) => None,
    }
}

/// A repository the node doesn't have: the text main's public route gives
/// one, never libradicle's, which names its storage path.
const MISSING: &str = "repository not found";

/// A not-found error of libradicle's whose text could name a path.
const NOT_FOUND: &str = "not found";

/// Any other error of libradicle's whose text could name a path.
const FAILED: &str = "the read failed";

/// libradicle's error, answered (see the module's doc): `not_found` or
/// `failed` by today's message test, with libradicle's message only when it
/// can't name a filesystem path ([`pathless`]). A repository the node
/// doesn't have is [`MISSING`]; any other error that could name a path is
/// [`NOT_FOUND`] or [`FAILED`], by its code, so main's 404 and 500 stay
/// what they are today.
fn radicle_error(e: libradicle::Error) -> ErrorBody {
    if missing(&e) {
        return ErrorBody::new(ErrorCode::NotFound, MISSING);
    }
    let message = e.to_string();
    let code = if not_found(&message) {
        ErrorCode::NotFound
    } else {
        ErrorCode::Failed
    };
    if pathless(&e, &message) {
        return ErrorBody::new(code, message);
    }
    let fixed = match code {
        ErrorCode::NotFound => NOT_FOUND,
        _ => FAILED,
    };
    ErrorBody::new(code, fixed)
}

/// Whether `e` is heartwood's for a repository that isn't in storage: its
/// open fails with libgit2's `NotFound`, for a directory that isn't there
/// (`Os`: "failed to resolve path '<home>/storage/<rid>'") or isn't a
/// repository (`Repository`: "could not find repository at '…'").
fn missing(e: &libradicle::Error) -> bool {
    matches!(
        e,
        libradicle::Error::Repository(RepositoryError::Git(git))
            if git.code() == GitCode::NotFound
                && matches!(git.class(), GitClass::Os | GitClass::Repository)
    )
}

/// Whether libradicle's text for `e`, `message`, can't name a filesystem
/// path, so that it goes to main as today:
/// - libradicle's own errors whose texts hold only what the request named
///   (a path in the tree, a revision, a COB ID, a RID) or a bound;
/// - libgit2's errors of a tree (a path in it), of an object (its ID), and
///   its object database's not-found (`Odb`, the ID): classes that never
///   wrap the OS's errors or name a file;
/// - any text with no path separator in it, `/` or `\`.
///
/// Every other text can: libgit2's other classes (`Os`, `Filesystem`,
/// `Repository`, `Config`, `Index`, `Odb` past a not-found, `Reference` and
/// the rest) name files under the home, and heartwood's storage, identity,
/// COB, cache and node errors, SQLite's, and libradicle's `NodeThread`,
/// `FetchFailed`, `Announce` and `GitConfig`, can carry them.
fn pathless(e: &libradicle::Error, message: &str) -> bool {
    use libradicle::Error as E;
    let own = match e {
        E::NotABlob(_)
        | E::NotATree(_)
        | E::InvalidCobId(_)
        | E::InvalidRevision(_)
        | E::TooLarge { .. }
        | E::TooDeep { .. }
        | E::Cancelled
        | E::NoIdentityHead(_)
        | E::NoCanonicalHead(_)
        | E::NoSeeds(_)
        | E::Timeout(_)
        | E::Gated { .. }
        | E::Open(_)
        | E::ShutdownTimeout(_) => true,
        E::Git(git) => {
            matches!(git.class(), GitClass::Tree | GitClass::Object)
                || (git.class() == GitClass::Odb && git.code() == GitCode::NotFound)
        }
        _ => false,
    };
    own || !message.contains(['/', '\\'])
}

/// Today's test of a libradicle message: `/not found|does not exist|NotFound/i`.
fn not_found(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("not found") || lower.contains("does not exist") || lower.contains("notfound")
}

/// What libradicle's `json::blob` holds beside the JSON as it writes
/// `blob` (see the module's doc): its content; for text, the `json!`
/// value's copy of it; and before that, for text that isn't UTF-8, the
/// lossy copy, each invalid sequence three bytes.
fn blob_held(blob: &Blob) -> u64 {
    let content = blob.content.len() as u64;
    if blob.binary {
        return content;
    }
    match lossy_len(&blob.content) {
        None => 2 * content,
        Some(lossy) => content + 2 * lossy,
    }
}

/// The length of `String::from_utf8_lossy(bytes)`, if it copies: `None`
/// for valid UTF-8, which it borrows.
fn lossy_len(bytes: &[u8]) -> Option<u64> {
    if std::str::from_utf8(bytes).is_ok() {
        return None;
    }
    Some(
        bytes
            .utf8_chunks()
            .map(|chunk| {
                let replaced = if chunk.invalid().is_empty() { 0 } else { 3 };
                chunk.valid().len() as u64 + replaced
            })
            .sum(),
    )
}

/// What libgit2 holds of a blob beside its bytes while it loads it: their
/// NUL and its structs (`libradicle::raw_held` of none). A blob read as
/// JSON is loaded up to half of its build's reservation, and libradicle
/// copies it while libgit2's buffer lives: twice the blob is that
/// reservation, and these bytes are past it, reserved with it
/// ([`blob_read`], and `readme_at`'s).
const BESIDE: u64 = libradicle::raw_held(0);

/// A blob, loaded up to half of `built`, the reservation of what its read
/// builds (see the module's doc), then refused `too_large` if its JSON's
/// writing would hold more than `built`.
fn bounded_blob(
    built: u64,
    load: impl FnOnce(u64) -> Result<Blob, libradicle::Error>,
) -> Result<Blob, libradicle::Error> {
    let blob = load(built / 2)?;
    let held = blob_held(&blob);
    if held > built {
        return Err(libradicle::Error::TooLarge {
            size: held,
            limit: built,
        });
    }
    Ok(blob)
}

/// `blob` or `blob_at`: the blob `load` loads, as JSON, within the build's
/// reservation and libgit2's bytes beside it ([`BESIDE`]).
fn blob_read(
    budget: &Arc<Budget>,
    until: &Until,
    path: &str,
    load: impl FnOnce(u64) -> Result<Blob, libradicle::Error>,
) -> Result<Body, Failure> {
    json_read_beside(
        BESIDE,
        budget,
        until,
        |_| bounded_blob(BUILT, load),
        |w, blob| json::blob(w, path, blob),
    )
}

/// `bounds` with half its JSON budget: for a result libradicle copies as it
/// writes it.
fn halved(bounds: &Bounds) -> Bounds {
    Bounds {
        budget: bounds.budget / 2,
        ..bounds.clone()
    }
}

/// `op`'s JSON, built and written within the budget (see the module's doc).
fn body(handle: &Handle, budget: &Arc<Budget>, until: &Until, op: Op) -> Result<Body, Failure> {
    match op {
        Op::RepoInfo { rid } => json_read(
            budget,
            until,
            |bounds| handle.node().repo_info_bounded(rid, &halved(bounds)),
            json::repo_info,
        ),
        Op::Tree { rid, path } => json_read(
            budget,
            until,
            |bounds| handle.node().tree_bounded(rid, &path, bounds),
            |w, entries| json::tree(w, entries),
        ),
        Op::TreeAt {
            rid,
            revision,
            path,
        } => json_read(
            budget,
            until,
            |bounds| handle.node().tree_at_bounded(rid, &revision, &path, bounds),
            |w, (entries, commit)| json::tree_at(w, entries, commit),
        ),
        Op::Blob { rid, path } => blob_read(budget, until, &path, |limit| {
            handle.node().read_blob_capped(rid, &path, limit)
        }),
        Op::BlobAt {
            rid,
            revision,
            path,
        } => blob_read(budget, until, &path, |limit| {
            handle
                .node()
                .read_blob_at_capped(rid, &revision, &path, limit)
        }),
        Op::Commits {
            rid,
            parent,
            page,
            per_page,
        } => json_read(
            budget,
            until,
            |bounds| {
                handle
                    .node()
                    .commits_bounded(rid, &parent, page, per_page, bounds)
            },
            |w, commits| json::commits(w, commits),
        ),
        Op::Commit { rid, revision } => json_read(
            budget,
            until,
            |bounds| handle.node().commit_bounded(rid, &revision, bounds),
            json::commit,
        ),
        Op::Issues { rid } => json_read(
            budget,
            until,
            |bounds| handle.node().issues_bounded(rid, bounds),
            |w, issues| json::issues(w, issues),
        ),
        Op::Patches { rid } => json_read(
            budget,
            until,
            |bounds| handle.node().patches_bounded(rid, bounds),
            |w, patches| json::patches(w, patches),
        ),
        Op::ListRepos => json_read(
            budget,
            until,
            |bounds| handle.node().list_repos_bounded(bounds),
            |w, repos| json::repos(w, repos),
        ),
        Op::ListSeededRepos => json_read(
            budget,
            until,
            |bounds| handle.node().list_seeded_repos_bounded(bounds),
            |w, repos| json::seeded_repos(w, repos),
        ),
        Op::Seeders { rid } => json_read(
            budget,
            until,
            |_| handle.node_mut().seeders(rid),
            |w, seeders| json::seeding(w, *seeders),
        ),
        Op::Identity => json_read(
            budget,
            until,
            |_| Ok(handle.node().identity()),
            json::identity,
        ),
        Op::Status => json_read(
            budget,
            until,
            |_| handle.node().connected_peers(),
            |w, peers| json::connected_peers(w, *peers),
        ),
        Op::Issue { rid, id } => composed::issue(handle, budget, until, rid, &id),
        Op::Patch { rid, id } => composed::patch(handle, budget, until, rid, &id),
        Op::Remotes { rid } => composed::remotes(handle, budget, until, rid),
        Op::RepoStats { rid, revision } => {
            composed::repo_stats(handle, budget, until, rid, &revision)
        }
        Op::ReadmeAt { rid, revision } => {
            composed::readme_at(handle, budget, until, rid, &revision)
        }
        Op::RepoMeta { rid } => composed::repo_meta(handle, budget, until, rid),
        Op::ReposMeta => composed::repos_meta(handle, budget, until),
        Op::Page {
            rid,
            cobs,
            status,
            page,
            per_page,
        } => composed::page(
            handle,
            budget,
            until,
            rid,
            cobs,
            (status.as_deref(), page.as_deref(), per_page.as_deref()),
        ),
        Op::NodeInfo => composed::node_info(handle, budget, until),
    }
}

/// What a read's answer before its head is from its deadline on.
fn late() -> ErrorBody {
    ErrorBody::new(ErrorCode::Deadline, "past its deadline")
}

/// Answers `error` before the head, if that is queued before the read's
/// deadline: `deadline` from then on.
fn refuse(conn: &Connection, ticket: &Ticket, error: &ErrorBody) {
    let _ = conn.reply_error_by(ticket.id, error, ticket.deadline, &late(), None);
}

/// `rad.read`'s work, for its request's `params`, on `node`, whose home is
/// `home`, within `budget`; `pools` says which repositories a write fences.
pub fn read(
    conn: &Connection,
    node: &Arc<Node>,
    pools: &Arc<Pools>,
    budget: &Arc<Budget>,
    home: &Path,
    params: Option<&RawValue>,
) -> Work {
    let op = op(params);
    let (conn, node, pools, budget, home) = (
        conn.clone(),
        node.clone(),
        pools.clone(),
        budget.clone(),
        home.to_path_buf(),
    );
    Box::new(move |ticket: &Ticket| {
        let op = match op {
            Ok(op) => op,
            Err(error) => return refuse(&conn, ticket, &error),
        };
        let Some(handle) = node.handle() else {
            return refuse(
                &conn,
                ticket,
                &ErrorBody::new(ErrorCode::Stopped, "the Radicle node is not running"),
            );
        };
        if let Some(error) = fence(&home, &handle.repositories, |rid| pools.writing(rid), &op) {
            return refuse(&conn, ticket, &error);
        }
        testhooks::hold_work(&ticket.cancel);
        let until = Until::new(ticket.deadline, ticket.cancel.clone());
        let built = body(&handle, &budget, &until, op);
        drop(handle);
        match built {
            Ok(body) => {
                let head = json!({ "content_type": "application/json", "bytes": body.bytes() });
                stream(&conn, ticket, &budget, &until, &head, Some(body));
            }
            // Whoever cancelled its token answers it: main's cancel, the
            // deadline's timer, or the stop.
            Err(Failure::Refused(Refused::Cancelled)) => {}
            Err(failure) => refuse(&conn, ticket, &failure.error(radicle_error)),
        }
    })
}

/// `head`, then `body` and its end, if it has one (see the module's doc):
/// without one, the head opens no stream.
fn stream(
    conn: &Connection,
    ticket: &Ticket,
    budget: &Arc<Budget>,
    until: &Until,
    head: &Value,
    body: Option<Body>,
) {
    // What the pending head holds, reserved until the writer has written it.
    let charge = match fc_service::conn::head_len(ticket.id, head) {
        Ok(size) => budget.reserve(size as u64, until),
        Err(_) => {
            return refuse(
                conn,
                ticket,
                &ErrorBody::new(ErrorCode::Internal, "Internal error"),
            );
        }
    };
    let charge = match charge {
        Ok(charge) => charge,
        Err(Refused::Cancelled) => return,
        Err(refused) => return refuse(conn, ticket, &refused.error()),
    };
    match conn.head_by(
        ticket.id,
        head,
        body.is_some(),
        ticket.deadline,
        &late(),
        Some(Box::new(charge)),
    ) {
        Ok(Headed::Queued) => {}
        // `deadline` is its reply; or it is settled already, or closing.
        Ok(Headed::Late) | Err(_) => return,
    }
    let Some(body) = body else {
        return;
    };
    for chunk in body {
        if !send(conn, ticket, chunk.as_slice()) {
            // Cancelled, aborted or closing: the rest is dropped, and its
            // reservations released.
            return;
        }
    }
    let _ = conn.finish(ticket.id);
}

/// Wakes the thread that waits for credit.
struct Unpark(std::thread::Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Queues all of `bytes` on the read's stream, waiting for main's credit as
/// long as it takes: whether it did. It stops waiting once the read's token
/// is cancelled (main's cancel, the stop), or the stream or the connection
/// has ended.
fn send(conn: &Connection, ticket: &Ticket, bytes: &[u8]) -> bool {
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut sending = std::pin::pin!(conn.send(ticket.id, bytes));
    loop {
        if let Poll::Ready(sent) = sending.as_mut().poll(&mut cx) {
            return sent.is_ok();
        }
        if ticket.cancel.is_cancelled() {
            return false;
        }
        std::thread::park_timeout(POLL);
    }
}

#[cfg(test)]
mod tests;
