//! `rad.read`'s pass-through ops (design 0008, "Methods", "Deadlines",
//! "Errors", "Pools and budgets" and "JSON results"), on the read pool with
//! its 60 s deadline to the head ([`crate::pools`]).
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
//! The ops without args take none, null or `{}`. A revision is 40
//! lowercase hex digits, as main checks it. The other ops 0008 lists, of
//! main's serialization (`issue`, `patch`, `remotes`, `repo_stats`) and
//! composed (`readme_at`, `repo_meta`, `repos_meta`, `issues_page`,
//! `patches_page`, `node_info`), come with a later step: until then each
//! answers `stopped`, "not served in this build".
//!
//! **Before the build, in this order:**
//! 1. the pool's own refusals: `stopped` before `RUNNING` and from the stop
//!    on, `busy` past its bounds;
//! 2. params that don't parse, read at admission and answered by the work:
//!    `invalid_argument`. That is an op 0008 doesn't list, args it doesn't
//!    take, a RID, or a revision or `parent` that isn't 40 lowercase hex;
//! 3. **the fence** ([`fence`]), for an op that names a repository:
//!    - quarantined at the gate: `quarantined`, with `data.kind` and
//!      `data.step` from the record ([`crate::quarantine::refusal`]), for
//!      the COB ops, and for every op of a `namespace` quarantine;
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
//! 64 KiB steps, at most 32 MiB of it. A read past a cap is `too_large`; one
//! whose deadline ends a wait is `deadline`. One whose token is cancelled,
//! in a wait or in its walk, is answered by whoever cancelled it: main's
//! cancel `cancelled`, the timer `deadline`, the stop `stopped`. The
//! node is held for the build alone, never while the body waits for credit.
//! Two results are copied as libradicle writes them, with a `json!` value,
//! so their build is bounded for the copy too:
//! - **`repo_info`'s** walk takes half the built budget, so the value's
//!   copy, about the result's size, fits in the other half;
//! - **a blob** is loaded only up to half the built budget, 16 MiB (the
//!   add-on's cap too, `libradicle::BINDING_READ_BUDGET`), its size read
//!   from its header first ([`bounded_blob`]), as libgit2's buffer and
//!   libradicle's copy of it are both held while it loads. Then what its
//!   JSON's writing holds beside the JSON ([`blob_held`]): its content,
//!   and for text the value's copy of it, and before that the lossy copy of
//!   one that isn't UTF-8, three bytes for each invalid sequence. Past the
//!   built budget it is `too_large`.
//!
//! **libradicle's errors:** `not_found` when the message matches today's
//! test (`not found`, `does not exist` or `NotFound`, in any case),
//! otherwise `failed`, with libradicle's message as today. Neither is
//! logged.
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
use libradicle::{BINDING_MAX_PER_PAGE, Blob, Bounds, json};
use radicle::node::gate::{self, RepoGate, RepoState};
use radicle::prelude::RepoId;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;
use serde_json::{Value, json};

use crate::node::{Handle, Node};
use crate::output::{Body, Budget, Failure, Refused, Until, json_read};
use crate::pools::{Pools, Ticket, Work};
use crate::{quarantine, testhooks};

/// How often a body waiting for credit looks at its token.
const POLL: Duration = Duration::from_millis(10);

/// The ops 0008 lists that a later step serves.
const LATER: &[&str] = &[
    "issue",
    "patch",
    "remotes",
    "repo_stats",
    "readme_at",
    "repo_meta",
    "repos_meta",
    "issues_page",
    "patches_page",
    "node_info",
];

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

/// A pass-through op, its args checked.
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
            | Op::Seeders { rid } => Some(*rid),
            Op::ListRepos | Op::ListSeededRepos | Op::Identity | Op::Status => None,
        }
    }

    /// Whether it is a COB op, which the repair fences.
    fn cob(&self) -> bool {
        matches!(self, Op::Issues { .. } | Op::Patches { .. })
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
                path: a.path,
            })
        }
        "tree_at" => {
            let a: AtArgs = args(given, "tree_at takes { rid, revision, path }")?;
            Ok(Op::TreeAt {
                rid: rid(&a.rid)?,
                revision: revision(a.revision, "revision")?,
                path: a.path,
            })
        }
        "blob" => {
            let a: PathArgs = args(given, "blob takes { rid, path }")?;
            Ok(Op::Blob {
                rid: rid(&a.rid)?,
                path: a.path,
            })
        }
        "blob_at" => {
            let a: AtArgs = args(given, "blob_at takes { rid, revision, path }")?;
            Ok(Op::BlobAt {
                rid: rid(&a.rid)?,
                revision: revision(a.revision, "revision")?,
                path: a.path,
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
        later if LATER.contains(&later) => Err(ErrorBody::new(
            ErrorCode::Stopped,
            "not served in this build",
        )),
        _ => Err(invalid(
            "op is one of repo_info, tree, tree_at, blob, blob_at, commits, commit, issues, \
             patches, list_repos, list_seeded_repos, seeders, identity and status",
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
    let rid = op.rid()?;
    match gate.state(&rid) {
        RepoState::Quarantined(kind) if op.cob() || kind == gate::Quarantine::Namespace => {
            Some(quarantine::refusal(home, rid, kind))
        }
        RepoState::Repairing if op.cob() => Some(ErrorBody::new(
            ErrorCode::Stopped,
            "the repository is being repaired",
        )),
        _ if op.cob() && writing(&rid) => Some(ErrorBody::new(
            ErrorCode::Stopped,
            "a write to the repository is under way, and its outcome isn't proven yet",
        )),
        RepoState::Open | RepoState::Repairing | RepoState::Quarantined(_) => None,
    }
}

/// libradicle's error, answered (see the module's doc).
fn radicle_error(e: libradicle::Error) -> ErrorBody {
    let message = e.to_string();
    let code = if not_found(&message) {
        ErrorCode::NotFound
    } else {
        ErrorCode::Failed
    };
    ErrorBody::new(code, message)
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

/// A blob, loaded within `bounds` (see the module's doc), then refused
/// `too_large` if its JSON's writing would hold more than the built budget.
fn bounded_blob(
    bounds: &Bounds,
    load: impl FnOnce(u64) -> Result<Blob, libradicle::Error>,
) -> Result<Blob, libradicle::Error> {
    let blob = load(bounds.budget / 2)?;
    let held = blob_held(&blob);
    if held > bounds.budget {
        return Err(libradicle::Error::TooLarge {
            size: held,
            limit: bounds.budget,
        });
    }
    Ok(blob)
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
        Op::Blob { rid, path } => json_read(
            budget,
            until,
            |bounds| {
                bounded_blob(bounds, |limit| {
                    handle.node().read_blob_capped(rid, &path, limit)
                })
            },
            |w, blob| json::blob(w, &path, blob),
        ),
        Op::BlobAt {
            rid,
            revision,
            path,
        } => json_read(
            budget,
            until,
            |bounds| {
                bounded_blob(bounds, |limit| {
                    handle
                        .node()
                        .read_blob_at_capped(rid, &revision, &path, limit)
                })
            },
            |w, blob| json::blob(w, &path, blob),
        ),
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
            Ok(body) => stream(&conn, ticket, &budget, &until, body),
            // Whoever cancelled its token answers it: main's cancel, the
            // deadline's timer, or the stop.
            Err(Failure::Refused(Refused::Cancelled)) => {}
            Err(failure) => refuse(&conn, ticket, &failure.error(radicle_error)),
        }
    })
}

/// The head, then `body`, then its end (see the module's doc).
fn stream(conn: &Connection, ticket: &Ticket, budget: &Arc<Budget>, until: &Until, body: Body) {
    let head = json!({ "content_type": "application/json", "bytes": body.bytes() });
    // What the pending head holds, reserved until the writer has written it.
    let charge = match fc_service::conn::head_len(ticket.id, &head) {
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
        &head,
        true,
        ticket.deadline,
        &late(),
        Some(Box::new(charge)),
    ) {
        Ok(Headed::Queued) => {}
        // `deadline` is its reply; or it is settled already, or closing.
        Ok(Headed::Late) | Err(_) => return,
    }
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
