//! Quarantine's methods (design 0008, "The escape" and "Methods"):
//! `rad.quarantine_list` on the read pool and `rad.remove_repo` on the
//! write queue, each with its 60 s deadline from admission
//! ([`crate::pools`]).
//!
//! **`rad.quarantine_list`** takes `{ page }`, a page number from 0, and
//! answers `{ entries, next_page }`: up to 64 entries ([`PAGE`]) of the
//! quarantine record, `node/reconcile.db`, in the order of their
//! repositories' IDs, each `{ rid, qid, kind, step, unit, since }` as
//! `rad.reconcile` gives them ([`crate::reconcile::entry`]), and the next
//! page's number, or null after the last. A page past the last is empty. It
//! reads the record alone, not the node.
//!
//! **`rad.remove_repo`** takes `{ rid, qid }`, the entry main showed, and
//! removes that repository: the only way out of quarantine. It runs on the
//! writer, with the node held shared ([`crate::node::Handle`]):
//! 1. **the precondition:** the record of `rid` must have `qid`. With no
//!    record of `rid`, or one with another `qid`, nothing is touched, and
//!    the answer is `not_quarantined`. So a delayed or repeated removal never
//!    acts on the repository once it has come back, quarantined anew or not;
//! 2. **libradicle's `Embedded::remove_quarantined`,** with the repository
//!    shut at the node's gate, as every repository in the record is from
//!    `rad.start` on ([`crate::node`]). The node unseeds it. Then heartwood's
//!    `remove_repo` stops seeding it, whatever the default, deletes
//!    `storage/<rid>` and flushes the storage directory, deletes its COB
//!    cache rows, and clears the record last;
//! 3. **the gate opens it** once its record is cleared, so that a later
//!    seed or clone seeds it anew.
//!
//! The answer is `{ removed: true }`. A failure part way is `failed`, naming
//! the step. The record, its `qid` and the gate's close all stay, and a retry
//! with the same `qid` runs the steps again, each of them idempotent.
//!
//! **A removal starts only while its token holds.** One cancelled first, by
//! main's cancel, its deadline or the stop, removes nothing, and its request
//! has its answer already. Once started, libradicle's call runs to its end,
//! and the record is what a retry relies on.
//!
//! **Params** are read as each request is admitted. A bad one is answered
//! `invalid_argument` by its work, after the pool's own refusals (`stopped`,
//! `busy`).
//!
//! **Messages and logs** carry repository IDs and the step, never a path.

use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::Arc;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::Connection;
use fc_service::log;
use radicle::node::gate::RepoGate;
use radicle::prelude::RepoId;
use radicle::storage::git::reconcile::quarantine::{self, Qid, Quarantine, Removal, RemoveError};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;
use serde_json::{Value, json};

use crate::node::Node;
use crate::pools::{Ticket, Work};
use crate::reconcile::{entry, record_error};
use crate::testhooks;

/// The most entries a page of `rad.quarantine_list` holds (0008, "Bounds").
pub const PAGE: usize = 64;

/// `rad.quarantine_list`'s params.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListParams {
    page: u64,
}

/// `rad.remove_repo`'s params.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveParams {
    rid: String,
    qid: String,
}

/// A removal's params, checked.
#[derive(Clone, Copy)]
struct Removing {
    rid: RepoId,
    qid: Qid,
}

fn invalid(message: &str) -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, message)
}

fn parse<T: DeserializeOwned>(params: Option<&RawValue>) -> Option<T> {
    params.and_then(|raw| serde_json::from_str(raw.get()).ok())
}

/// The quarantine record of the home at `home`.
fn record_path(home: &Path) -> PathBuf {
    home.join("node").join(quarantine::QUARANTINE_DB_FILE)
}

fn record_failed(e: &quarantine::Error) -> ErrorBody {
    ErrorBody::new(
        ErrorCode::Failed,
        format!("the quarantine record: {}", record_error(e)),
    )
}

fn answer(conn: &Connection, id: u64, answer: Result<Value, ErrorBody>) {
    let _ = match answer {
        Ok(result) => conn.reply(id, &result),
        Err(error) => conn.reply_error(id, &error),
    };
}

/// `rad.quarantine_list`'s work, for its request's `params`, over `home`'s
/// record.
pub fn list(conn: &Connection, home: &Path, params: Option<&RawValue>) -> Work {
    let page = parse::<ListParams>(params)
        .map(|params| params.page)
        .ok_or_else(|| invalid("rad.quarantine_list takes { page }, a page number from 0"));
    let (conn, home) = (conn.clone(), home.to_path_buf());
    Box::new(move |ticket: &Ticket| {
        answer(
            &conn,
            ticket.id,
            page.and_then(|page| list_page(&home, page)),
        );
    })
}

/// Page `page` of `home`'s quarantine record: `{ entries, next_page }`.
fn list_page(home: &Path, page: u64) -> Result<Value, ErrorBody> {
    let record = Quarantine::open(record_path(home)).map_err(|e| record_failed(&e))?;
    let count = record.count().map_err(|e| record_failed(&e))?;
    let index = usize::try_from(page).ok();
    // A page past the last is empty, and never asked of the record: its
    // query's offset, the page times its size, would overflow for a page
    // number this large, and wrap to the first page.
    let (Some(index), Some(first)) = (index, index.and_then(|i| i.checked_mul(PAGE))) else {
        return Ok(json!({ "entries": [], "next_page": null }));
    };
    if first >= count {
        return Ok(json!({ "entries": [], "next_page": null }));
    }
    let entries = record.page(index, PAGE).map_err(|e| record_failed(&e))?;
    let next = (count - first > PAGE).then(|| page + 1);
    Ok(json!({
        "entries": entries.iter().map(entry).collect::<Vec<_>>(),
        "next_page": next,
    }))
}

/// `rad.remove_repo`'s work, for its request's `params`, on `node`, whose
/// home is `home`.
pub fn remove(conn: &Connection, node: &Arc<Node>, home: &Path, params: Option<&RawValue>) -> Work {
    let removing = parse::<RemoveParams>(params)
        .ok_or_else(|| invalid("rad.remove_repo takes { rid, qid }"))
        .and_then(|params| {
            Ok(Removing {
                rid: RepoId::from_str(&params.rid)
                    .map_err(|_| invalid("rid isn't a repository ID"))?,
                qid: Qid::from_str(&params.qid)
                    .map_err(|_| invalid("qid isn't a quarantine record's ID"))?,
            })
        });
    let (conn, node, home) = (conn.clone(), node.clone(), home.to_path_buf());
    Box::new(move |ticket: &Ticket| {
        let removing = match removing {
            Ok(removing) => removing,
            Err(error) => return answer(&conn, ticket.id, Err(error)),
        };
        let Some(handle) = node.handle() else {
            return answer(
                &conn,
                ticket.id,
                Err(ErrorBody::new(
                    ErrorCode::Stopped,
                    "the Radicle node is not running",
                )),
            );
        };
        let embedded = handle.node();
        testhooks::hold_work(&ticket.cancel);
        if ticket.cancel.is_cancelled() {
            // Before the removal started: nothing is removed, and the
            // request has its answer, or the stop gives it one.
            return;
        }
        answer(
            &conn,
            ticket.id,
            removal(&embedded, &handle.repositories, &home, removing),
        );
    })
}

/// The removal, steps 1 to 3 of the module's doc, on `node`, whose gate's
/// host half is `gate`.
fn removal(
    node: &libradicle::Embedded,
    gate: &RepoGate,
    home: &Path,
    removing: Removing,
) -> Result<Value, ErrorBody> {
    let Removing { rid, qid } = removing;
    let mut record = Quarantine::open(record_path(home)).map_err(|e| record_failed(&e))?;
    let held = record.get(&rid).map_err(|e| record_failed(&e))?;
    if held.is_none_or(|held| held.qid != qid) {
        return Err(not_quarantined(rid));
    }
    match node.remove_quarantined(rid, qid, &mut record) {
        Ok(Removal::Removed) => {
            gate.open(rid);
            log::info(
                "a quarantined repository was removed",
                json!({ "rid": rid.to_string() }),
            );
            Ok(json!({ "removed": true }))
        }
        Ok(Removal::NotQuarantined) => Err(not_quarantined(rid)),
        Err(e) => {
            let error = removal_failed(&e);
            log::error(
                "a quarantined repository's removal failed; its record stays",
                json!({ "rid": rid.to_string(), "error": error.message }),
            );
            Err(error)
        }
    }
}

fn not_quarantined(rid: RepoId) -> ErrorBody {
    ErrorBody::new(
        ErrorCode::NotQuarantined,
        format!("no quarantine record of {rid} has that qid: nothing was removed"),
    )
}

/// A removal's failure, naming its step: never a path. libradicle's own
/// message otherwise, as 0008's `failed` says.
fn removal_failed(e: &libradicle::Error) -> ErrorBody {
    let message = match e {
        libradicle::Error::Remove(e) => match &**e {
            RemoveError::Quarantine(e) => format!("the quarantine record: {}", record_error(e)),
            RemoveError::Policy(_) => {
                "the seeding policy: its database doesn't open or answer".to_owned()
            }
            RemoveError::Io(e) => format!("the repository's storage: {}", e.kind()),
            RemoveError::Cache(_) => {
                "the COB cache: its database doesn't open or answer".to_owned()
            }
        },
        libradicle::Error::Quarantine(e) => format!("the quarantine record: {}", record_error(e)),
        libradicle::Error::Open(_) => {
            "the repository is open at the node's gate, so it isn't quarantined there".to_owned()
        }
        other => other.to_string(),
    };
    ErrorBody::new(ErrorCode::Failed, message)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use radicle::storage::git::reconcile::quarantine::Kind;

    fn rid(n: u16) -> RepoId {
        let mut bytes = [0u8; 20];
        bytes[..2].copy_from_slice(&n.to_be_bytes());
        RepoId::from(radicle::git::Oid::from_sha1(bytes))
    }

    /// A home whose record holds `n` repositories.
    fn home_with(n: u16) -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("node")).unwrap();
        let mut record = Quarantine::open(record_path(home.path())).unwrap();
        for i in 0..n {
            record
                .quarantine(rid(i), Kind::Cache, "cache", None, "", Default::default())
                .unwrap();
        }
        home
    }

    fn rids(page: &Value) -> Vec<String> {
        page["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["rid"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn an_empty_record_lists_an_empty_last_page() {
        let home = tempfile::tempdir().unwrap();
        // No record yet: it is made, empty.
        std::fs::create_dir_all(home.path().join("node")).unwrap();
        assert_eq!(
            list_page(home.path(), 0).unwrap(),
            json!({ "entries": [], "next_page": null })
        );
    }

    /// 0008, "Tests first": `rad.quarantine_list` pages through 100
    /// quarantined repositories, 64 at a time, each once, in the order of
    /// their IDs.
    #[test]
    fn a_hundred_entries_page_64_at_a_time() {
        let home = home_with(100);
        let first = list_page(home.path(), 0).unwrap();
        assert_eq!(rids(&first).len(), PAGE);
        assert_eq!(first["next_page"], 1);
        let second = list_page(home.path(), 1).unwrap();
        assert_eq!(rids(&second).len(), 100 - PAGE);
        assert_eq!(second["next_page"], Value::Null);
        let mut all = rids(&first);
        all.extend(rids(&second));
        let mut expected: Vec<String> = (0..100).map(|i| rid(i).to_string()).collect();
        expected.sort();
        assert_eq!(all, expected);
        let entry = &first["entries"][0];
        assert_eq!(entry["kind"], "cache");
        assert_eq!(entry["step"], "cache");
        assert_eq!(entry["unit"], Value::Null);
        assert_eq!(entry["qid"].as_str().unwrap().len(), 32);
        assert!(entry.get("evidence").is_none(), "{entry}");
    }

    /// Exactly a page: no next one.
    #[test]
    fn a_full_last_page_has_no_next() {
        let home = home_with(PAGE as u16);
        let page = list_page(home.path(), 0).unwrap();
        assert_eq!(rids(&page).len(), PAGE);
        assert_eq!(page["next_page"], Value::Null);
        assert_eq!(
            list_page(home.path(), 1).unwrap(),
            json!({ "entries": [], "next_page": null })
        );
    }

    /// A page number so large that its offset overflows is past the last
    /// page, not the first.
    #[test]
    fn a_page_far_past_the_last_is_empty() {
        let home = home_with(3);
        for page in [
            2,
            u64::MAX / PAGE as u64,
            u64::MAX / PAGE as u64 + 1,
            u64::MAX,
        ] {
            assert_eq!(
                list_page(home.path(), page).unwrap(),
                json!({ "entries": [], "next_page": null }),
                "page {page}"
            );
        }
    }
}
