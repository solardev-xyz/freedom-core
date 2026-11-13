//! `rad.read`'s composed ops, and the ops whose answer main parses and
//! writes again (design 0008, "Methods", "JSON results" and "Parity"). Each
//! writes the bytes main writes today for what it makes of the add-on's
//! results: libradicle's bounded reads, its own serializers' text, then
//! main's composition of that text, done on the text itself
//! ([`super::js`]). `vectors/radicle-reads.json`, recorded from main's own
//! code at the reference, pins what each composition writes.
//! - **Main's serialization:** `issue { rid, issue_id }`, `patch { rid,
//!   patch_id }`, `remotes { rid }` and `repo_stats { rid, revision }`: the
//!   add-on's text as `JSON.parse`, then `JSON.stringify`, make it again.
//! - **`readme_at { rid, revision }`:** main's `readmeAtRaw`: the first
//!   README candidate among the blobs of the root tree at the revision,
//!   then that blob's text with `"path"` spliced in before its closing
//!   brace. None is `not_found`, "no readme", main's 404.
//! - **`repo_meta { rid }`:** main's `buildRepoMeta` of `repo_info` and
//!   `seeders`. A `seeders` failure is `seeding: 0`, logged without the RID
//!   or libradicle's message, which may quote it.
//! - **`repos_meta`:** an array of `repo_meta`, one per `list_repos` entry,
//!   in its order, each read again as main reads it: the first failure, in
//!   that order, fails the whole.
//! - **`issues_page`, `patches_page { rid, status, page, per_page }`:**
//!   main's `paginate` of `issues` and `patches`, each of `status`, `page`
//!   and `per_page` as its query's raw string, or null.
//! - **`node_info`:** `{ connected_peers, repos_total, repos_error }`, for
//!   main's two callers that need the count: `status`, then `list_repos`'s
//!   length. A `status` failure fails the call. A listing failure, a
//!   listing past its bound too, is `repos_error`, libradicle's message,
//!   with `repos_total` null, as main reads such a failure today; a
//!   message that could name a filesystem path is the fixed text the reads'
//!   errors give it (`super::read_error`).
//!
//! **Bounds** (0008, "Pools and budgets"): a composed read holds what any
//! JSON read may, 64 MiB: its JSON, at most 32 MiB, in a
//! [`crate::output::Json`] writer; and everything it builds, within one
//! reservation of the built budget, 32 MiB, taken before it reads
//! anything ([`composed_read`]):
//! - **each walk** gets the add-on's bounds, with the read's token: 16 MiB
//!   of JSON, which libradicle charges as each item is built, and as many
//!   of loaded objects (`Bounds::for_binding`'s, [`TODAYS`]). So a
//!   composed read is refused past the figures the add-on is today, with
//!   libradicle's message: `too_large`;
//! - **the text it composes from** is libradicle's serializer's, counted
//!   first and then written into a buffer of exactly that size, never past
//!   the walk's budget ([`capture`]): the walk's data and its text are held
//!   together, 16 MiB each at most, then the data is dropped;
//! - **the composition's working set** (what the objects it writes hold,
//!   [`super::js::Work`]) then gets the other 16 MiB, beside the text;
//! - **`repo_info`,** which libradicle copies into a `json!` value as it
//!   writes it, gets a quarter, 8 MiB, of each instead: its data, the copy
//!   and its text, then its text and the working set. `repos_meta`'s
//!   listing takes the walk's 16 MiB; then only its RIDs are kept (20 bytes
//!   each, for a listed repository whose JSON took 62 at least: under 5.2
//!   MiB), beside one repository's `repo_meta` at a time;
//! - **`readme_at`'s blob** is read as `blob_at`'s, once the tree is
//!   dropped: loaded up to 16 MiB, with libgit2's 257 bytes beside it
//!   reserved with the build ([`super::BESIDE`]), and refused if what its
//!   JSON's writing holds passes the built budget ([`super::bounded_blob`]);
//!   its JSON goes through [`super::js::Spliced`] into the reply's.
//!
//! `repos_meta` looks at the read's token before each repository; a walk
//! looks at it as it goes.
//!
//! **An identity document over 64 KiB** ([`super::identity`]): `remotes`,
//! `repo_stats` and each `repo_meta` check the repository's before their
//! walk, within its bounds, and the listings of `repos_meta` and
//! `node_info` every seeded repository's; one over the cap is `too_large`
//! with a fixed text, and `node_info`'s `repos_error`.

use std::io;
use std::path::Path;
use std::sync::Arc;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::log;
use libradicle::{Bounds, json};
use radicle::prelude::RepoId;
use serde::Serialize;
use serde_json::json;

use super::js::{self, Seeding, Work};
use super::{BESIDE, bounded_blob, identity};
use crate::node::Handle;
use crate::output::{
    BUILT, Body, Budget, Failure, Json, Refused, Until, composed_read, composed_read_beside,
};
use crate::testhooks;

/// The add-on's bounds of a walk: libradicle's `BINDING_READ_BUDGET`, half
/// the built budget.
pub const TODAYS: u64 = BUILT / 2;

/// What `repo_info` gets of each: a quarter of the built budget.
pub const REPO_INFO: u64 = BUILT / 4;

impl From<js::Error> for Failure {
    fn from(error: js::Error) -> Self {
        match error {
            js::Error::TooLarge { size, limit } => {
                Failure::Refused(Refused::TooLarge { size, limit })
            }
            js::Error::Malformed(what) => Failure::Internal(what),
            // The reply's writer refused, which its `end` answers first.
            js::Error::Write(error) => Failure::Json(serde_json::Error::io(error)),
        }
    }
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Failure::Json(serde_json::Error::io(error))
    }
}

/// A walk's bounds of `bytes`, of JSON and of loads, with the read's token.
fn bounds(until: &Until, bytes: u64) -> Bounds {
    Bounds::new(until.cancel.clone(), bytes).with_loads(bytes)
}

/// Counts what is written, and refuses past its limit.
struct Count {
    bytes: u64,
    limit: u64,
}

impl io::Write for Count {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes = self.bytes.saturating_add(buf.len() as u64);
        if self.bytes > self.limit {
            return Err(io::Error::other("past its limit"));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What `write`, a libradicle serializer, writes, held: counted first, then
/// written into a buffer of exactly that size, so it never holds more than
/// `limit`; past it, `too_large`.
pub(super) fn capture(
    limit: u64,
    write: impl Fn(&mut dyn io::Write) -> json::Written,
) -> Result<Vec<u8>, Failure> {
    let mut count = Count { bytes: 0, limit };
    if let Err(error) = write(&mut count) {
        return Err(if count.bytes > limit {
            Failure::Refused(Refused::TooLarge {
                size: count.bytes,
                limit,
            })
        } else {
            Failure::Json(error)
        });
    }
    let len = usize::try_from(count.bytes).map_err(|_| Failure::Internal("a text's length"))?;
    let mut text = Vec::new();
    text.try_reserve_exact(len)
        .map_err(|_| Failure::Internal("a text, unallocated"))?;
    write(&mut text).map_err(Failure::Json)?;
    if text.len() != len {
        return Err(Failure::Internal("a text written twice, not the same"));
    }
    Ok(text)
}

/// Main's serialization of `text`: `JSON.stringify(JSON.parse(text))`.
fn again(out: &mut Json, text: &[u8]) -> Result<(), Failure> {
    js::write(js::parse(text)?, out, &mut Work::new(TODAYS))?;
    Ok(())
}

/// `issue { rid, issue_id }`.
pub fn issue(
    handle: &Handle,
    budget: &Arc<Budget>,
    until: &Until,
    rid: RepoId,
    issue_id: &str,
) -> Result<Body, Failure> {
    composed_read(budget, until, |out| {
        let text = {
            let (id, issue) = handle
                .node()
                .issue_bounded(rid, issue_id, &bounds(until, TODAYS))?;
            capture(TODAYS, |mut w| json::issue(&mut w, &id, &issue))?
        };
        again(out, &text)
    })
}

/// `patch { rid, patch_id }`.
pub fn patch(
    handle: &Handle,
    budget: &Arc<Budget>,
    until: &Until,
    rid: RepoId,
    patch_id: &str,
) -> Result<Body, Failure> {
    composed_read(budget, until, |out| {
        let text = {
            let (id, patch) = handle
                .node()
                .patch_bounded(rid, patch_id, &bounds(until, TODAYS))?;
            capture(TODAYS, |mut w| json::patch(&mut w, &id, &patch))?
        };
        again(out, &text)
    })
}

/// `remotes { rid }`, on the node whose home is `home`.
pub fn remotes(
    handle: &Handle,
    home: &Path,
    budget: &Arc<Budget>,
    until: &Until,
    rid: RepoId,
) -> Result<Body, Failure> {
    composed_read(budget, until, |out| {
        identity::check(&handle.node(), home, rid, &bounds(until, TODAYS))?;
        let text = {
            let remotes = handle.node().remotes_bounded(rid, &bounds(until, TODAYS))?;
            capture(TODAYS, |mut w| json::remotes(&mut w, &remotes))?
        };
        again(out, &text)
    })
}

/// `repo_stats { rid, revision }`, on the node whose home is `home`.
pub fn repo_stats(
    handle: &Handle,
    home: &Path,
    budget: &Arc<Budget>,
    until: &Until,
    rid: RepoId,
    revision: &str,
) -> Result<Body, Failure> {
    composed_read(budget, until, |out| {
        identity::check(&handle.node(), home, rid, &bounds(until, TODAYS))?;
        let text = {
            let stats = handle
                .node()
                .repo_stats_bounded(rid, revision, &bounds(until, TODAYS))?;
            capture(TODAYS, |mut w| json::repo_stats(&mut w, &stats))?
        };
        again(out, &text)
    })
}

/// Which COBs a page reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cobs {
    Issues,
    Patches,
}

/// `issues_page` and `patches_page { rid, status, page, per_page }`.
pub fn page(
    handle: &Handle,
    budget: &Arc<Budget>,
    until: &Until,
    rid: RepoId,
    cobs: Cobs,
    query: (Option<&str>, Option<&str>, Option<&str>),
) -> Result<Body, Failure> {
    let (status, page, per_page) = query;
    composed_read(budget, until, |out| {
        let text = match cobs {
            Cobs::Issues => {
                let issues = handle.node().issues_bounded(rid, &bounds(until, TODAYS))?;
                capture(TODAYS, |mut w| json::issues(&mut w, &issues))?
            }
            Cobs::Patches => {
                let patches = handle.node().patches_bounded(rid, &bounds(until, TODAYS))?;
                capture(TODAYS, |mut w| json::patches(&mut w, &patches))?
            }
        };
        js::page(
            js::parse(&text)?,
            status,
            js::window(page, per_page),
            out,
            &mut Work::new(TODAYS),
        )?;
        Ok(())
    })
}

/// `readme_at { rid, revision }`.
pub fn readme_at(
    handle: &Handle,
    budget: &Arc<Budget>,
    until: &Until,
    rid: RepoId,
    revision: &str,
) -> Result<Body, Failure> {
    // libgit2's bytes beside the blob while it loads, with the build.
    composed_read_beside(BESIDE, budget, until, |out| {
        let path = {
            let (entries, _) =
                handle
                    .node()
                    .tree_at_bounded(rid, revision, "", &bounds(until, TODAYS))?;
            js::readme(
                entries
                    .iter()
                    .filter(|entry| entry.kind == "blob")
                    .map(|entry| entry.name.as_str()),
            )
        };
        let Some(path) = path else {
            return Err(Failure::Answered(ErrorBody::new(
                ErrorCode::NotFound,
                "no readme",
            )));
        };
        let blob = bounded_blob(BUILT, |limit| {
            handle
                .node()
                .read_blob_at_capped(rid, revision, path, limit)
        })?;
        let mut spliced = js::Spliced::new(out, path);
        json::blob(&mut spliced, path, &blob).map_err(Failure::Json)?;
        spliced.finish()?;
        Ok(())
    })
}

/// One repository's `repo_meta`, written into `out`, on the node whose
/// home is `home`.
fn meta_into(
    handle: &Handle,
    home: &Path,
    until: &Until,
    rid: RepoId,
    out: &mut Json,
) -> Result<(), Failure> {
    identity::check(&handle.node(), home, rid, &bounds(until, REPO_INFO))?;
    let info = {
        let info = handle
            .node()
            .repo_info_bounded(rid, &bounds(until, REPO_INFO))?;
        capture(REPO_INFO, |mut w| json::repo_info(&mut w, &info))?
    };
    let seeders = handle.node_mut().seeders(rid);
    let seeders = match seeders {
        Ok(n) => Some(capture(REPO_INFO, |mut w| json::seeding(&mut w, n))?),
        Err(_) => {
            // Its message may quote the RID.
            log::warn(
                "a repository's seeders could not be read: its seeding is 0",
                json!({}),
            );
            None
        }
    };
    let seeding = match &seeders {
        Some(text) => Seeding::Answered(js::parse(text)?),
        None => Seeding::Failed,
    };
    js::repo_meta(js::parse(&info)?, seeding, out, &mut Work::new(REPO_INFO))?;
    Ok(())
}

/// `repo_meta { rid }`, on the node whose home is `home`.
pub fn repo_meta(
    handle: &Handle,
    home: &Path,
    budget: &Arc<Budget>,
    until: &Until,
    rid: RepoId,
) -> Result<Body, Failure> {
    composed_read(budget, until, |out| {
        meta_into(handle, home, until, rid, out)
    })
}

/// `repos_meta`, on the node whose home is `home`.
pub fn repos_meta(
    handle: &Handle,
    home: &Path,
    budget: &Arc<Budget>,
    until: &Until,
) -> Result<Body, Failure> {
    composed_read(budget, until, |out| {
        identity::check_listed(&handle.node(), home, &bounds(until, TODAYS))?;
        let rids = {
            let repos = handle.node().list_repos_bounded(&bounds(until, TODAYS))?;
            let mut rids: Vec<RepoId> = Vec::new();
            rids.try_reserve_exact(repos.len())
                .map_err(|_| Failure::Internal("the listing's RIDs, unallocated"))?;
            rids.extend(repos.iter().map(|repo| repo.rid));
            rids
        };
        io::Write::write_all(out, b"[")?;
        for (n, rid) in rids.into_iter().enumerate() {
            if until.cancel.is_cancelled() {
                return Err(Failure::Refused(Refused::Cancelled));
            }
            if n > 0 {
                io::Write::write_all(out, b",")?;
            }
            meta_into(handle, home, until, rid, out)?;
        }
        io::Write::write_all(out, b"]")?;
        Ok(())
    })
}

/// `node_info`'s body (0008, "Methods").
#[derive(Serialize)]
struct NodeInfo<'a> {
    connected_peers: usize,
    repos_total: Option<usize>,
    repos_error: Option<&'a str>,
}

/// `node_info`'s JSON, of `status`'s connected peers and the listing's
/// length, or its error's message.
pub(super) fn write_node_info(
    out: &mut impl io::Write,
    connected_peers: usize,
    listed: Result<usize, &str>,
) -> serde_json::Result<()> {
    serde_json::to_writer(
        out,
        &NodeInfo {
            connected_peers,
            repos_total: listed.ok(),
            repos_error: listed.err(),
        },
    )
}

/// `node_info`, on the node whose home is `home`.
pub fn node_info(
    handle: &Handle,
    home: &Path,
    budget: &Arc<Budget>,
    until: &Until,
) -> Result<Body, Failure> {
    composed_read(budget, until, |out| {
        let connected_peers = handle.node().connected_peers()?;
        let error;
        // Two statements, so the check's hold on the node ends before the
        // listing takes it: a second shared hold under the first waits
        // behind `rad.unseed` waiting to hold it exclusively, which waits
        // for the first (#338; `crate::node`: a thread holds the node at
        // most once).
        let checked = identity::check_listed(&handle.node(), home, &bounds(until, TODAYS));
        let listing = checked.and_then(|()| {
            testhooks::hold_read("node_info");
            Ok(handle.node().list_repos_bounded(&bounds(until, TODAYS))?)
        });
        let listed = match listing {
            Ok(repos) => Ok(repos.len()),
            Err(Failure::Refused(Refused::Cancelled)) => {
                return Err(Failure::Refused(Refused::Cancelled));
            }
            // libradicle's message, as main reads it today, where it can't
            // name a filesystem path: as the reads' errors give it. An
            // identity document over its cap is its fixed text.
            Err(failure) => {
                error = failure.error(super::read_error).message;
                Err(error.as_str())
            }
        };
        write_node_info(out, connected_peers, listed).map_err(Failure::Json)
    })
}

#[cfg(test)]
mod tests;
