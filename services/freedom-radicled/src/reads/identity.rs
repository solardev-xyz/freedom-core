//! The identity document's cap (design 0008's deviation `identity-cap`): a
//! read that would parse a repository's identity document refuses one
//! whose blob is over [`DOCUMENT`], 1 MiB, from the blob's header, before
//! anything parses it. It answers `too_large` with a fixed text, [`OVER`].
//!
//! **Why:** the document is `embeds/radicle.json` in the tree of the commit
//! `refs/rad/id` names, and heartwood parses all of it with `serde_json`
//! (`Doc::load_at`). libradicle sizes the blob from its header before that
//! and charges its bytes, but not what the parse holds: a document's
//! payloads are any JSON, and a dense one holds many times its size once
//! parsed. Real documents are a few KB; 1 MiB holds thousands of delegates
//! or allowed DIDs. Main reads it today with no cap (the add-on's
//! `repo_info` and the rest), as heartwood does.
//!
//! **The reads that parse it,** each through libradicle, and the check
//! each makes first, within the read's own bounds and token:
//! - `repo_info`, `remotes`, `repo_stats`, and `repo_meta` (each of
//!   `repos_meta`'s too): the repository's document ([`check`]);
//! - `tree` and `blob` without a revision: the document only when the
//!   repository's `HEAD` doesn't resolve, as libradicle then computes the
//!   canonical head from it ([`check_headless`]);
//! - the listings, `list_repos`, `list_seeded_repos`, and `repos_meta`'s
//!   and `node_info`'s: the document of every repository they would list,
//!   each one in storage the node seeds ([`check_listed`]). One over the
//!   cap refuses the listing, as a repository whose objects don't fit
//!   libradicle's bounds refuses it.
//!
//! The check sizes the blob as libradicle's `blob_header_bounded` does: the
//! commit and trees on the way charged within the read's loads, the blob's
//! size from its header, nothing of it loaded. It answers only the cap: a
//! repository that doesn't open, has no `refs/rad/id` or no document, or
//! whose walk is past the read's bounds, is left to libradicle's read,
//! which answers it as today. Only the read's cancel ends the check.
//!
//! **What it can't close:** the check resolves `refs/rad/id`, and then
//! libradicle's read resolves it again. A fetch that moves it in between
//! has the read parse a document the check didn't size, once. That fetch
//! has parsed the document already, through heartwood's own verification,
//! which no cap reaches (0008, "What the service can't bound").

use std::ffi::OsStr;
use std::path::Path;

use fc_protocol::error::{ErrorBody, ErrorCode};
use libradicle::{Bounds, Embedded};
use radicle::git::raw::Oid;
use radicle::node::policy;
use radicle::prelude::RepoId;
use radicle::storage::git::Repository;

use crate::node::SEEDING;
use crate::output::{Failure, Refused};

/// The largest identity document a read parses: 1 MiB, its blob's size.
pub const DOCUMENT: u64 = 1 << 20;

/// What a read answers for a repository whose identity document is over
/// [`DOCUMENT`]: `too_large`, with this text, whatever its size.
pub const OVER: &str = "the repository's identity document is over 1 MiB";

/// The document's path in the tree of the commit `refs/rad/id` names, as
/// heartwood reads it (`Doc::blob_at`).
const PATH: &str = "embeds/radicle.json";

/// The ref naming the identity's head, as libradicle reads it.
const HEAD: &str = "refs/rad/id";

/// The answer for a document over [`DOCUMENT`].
pub fn over() -> ErrorBody {
    ErrorBody::new(ErrorCode::TooLarge, OVER)
}

/// Refuses `rid`'s identity document if its blob is over [`DOCUMENT`]
/// (see the module's doc): for a read that parses it.
pub fn check(node: &Embedded, home: &Path, rid: RepoId, bounds: &Bounds) -> Result<(), Failure> {
    let Some(head) = open(home, rid).and_then(|repo| identity_head(&repo)) else {
        return Ok(());
    };
    sized(node, rid, head, bounds)
}

/// [`check`], for a read without a revision: only when `rid`'s `HEAD`
/// doesn't resolve, as libradicle then reads the document for the
/// canonical head. One whose `HEAD` resolves parses none.
pub fn check_headless(
    node: &Embedded,
    home: &Path,
    rid: RepoId,
    bounds: &Bounds,
) -> Result<(), Failure> {
    let Some(repo) = open(home, rid) else {
        return Ok(());
    };
    // libradicle's own test (`head_bounded`): the local `HEAD`, when it
    // resolves to a qualified ref.
    let resolves = repo
        .backend
        .head()
        .is_ok_and(|head| radicle::git::refs::qualified_from(&head).is_ok());
    if resolves {
        return Ok(());
    }
    let Some(head) = identity_head(&repo) else {
        return Ok(());
    };
    drop(repo);
    sized(node, rid, head, bounds)
}

/// [`check`], for a listing: every repository in `home`'s storage that
/// libradicle's listing would read, each one it would open, whose name is a
/// RID and that the node seeds. The read's token is looked at before each.
pub fn check_listed(node: &Embedded, home: &Path, bounds: &Bounds) -> Result<(), Failure> {
    let Ok(entries) = std::fs::read_dir(home.join("storage")) else {
        return Ok(());
    };
    let Ok(store) =
        policy::store::StoreReader::reader(home.join("node").join(radicle::node::POLICIES_DB_FILE))
    else {
        return Ok(());
    };
    let policies = policy::config::Config::new(SEEDING.into(), store);
    for entry in entries {
        if bounds.cancel.is_cancelled() {
            return Err(Refused::Cancelled.into());
        }
        let Some(rid) = entry.ok().and_then(|entry| stored(&entry)) else {
            continue;
        };
        if !policies.is_seeding(&rid).unwrap_or(false) {
            continue;
        }
        check(node, home, rid, bounds)?;
    }
    Ok(())
}

/// The RID of a storage entry libradicle's listing opens: a directory, not
/// hidden, not a `.tmp` or `.lock`, named by a RID.
fn stored(entry: &std::fs::DirEntry) -> Option<RepoId> {
    if !entry.file_type().ok()?.is_dir() {
        return None;
    }
    let name = entry.file_name();
    if name.to_string_lossy().starts_with('.') {
        return None;
    }
    let path = entry.path();
    if matches!(
        path.extension().and_then(OsStr::to_str),
        Some("tmp" | "lock")
    ) {
        return None;
    }
    RepoId::try_from(name).ok()
}

/// `rid`'s repository in `home`'s storage, opened as heartwood opens it.
fn open(home: &Path, rid: RepoId) -> Option<Repository> {
    Repository::open(home.join("storage").join(rid.canonical()), rid).ok()
}

/// The commit `repo`'s `refs/rad/id` names.
fn identity_head(repo: &Repository) -> Option<Oid> {
    repo.backend.refname_to_id(HEAD).ok()
}

/// Refuses the document in the tree of `head` if its blob is over
/// [`DOCUMENT`], from its header, the walk to it within `bounds`.
fn sized(node: &Embedded, rid: RepoId, head: Oid, bounds: &Bounds) -> Result<(), Failure> {
    match node.blob_header_bounded(rid, &head.to_string(), PATH, bounds) {
        Ok(header) if header.size > DOCUMENT => Err(Failure::Answered(over())),
        Ok(_) => Ok(()),
        Err(libradicle::Error::Cancelled) => Err(Refused::Cancelled.into()),
        // libradicle's read meets it again, and answers it as today.
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cap_is_1_mib_and_its_answer_is_fixed() {
        assert_eq!(DOCUMENT, 1_048_576);
        let answer = over();
        assert_eq!(answer.code, ErrorCode::TooLarge);
        assert_eq!(answer.message, OVER);
        assert!(answer.data.is_none());
    }
}
