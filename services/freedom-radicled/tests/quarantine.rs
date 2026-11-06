//! Quarantine's methods through the real binary (design 0008, "The escape",
//! "Methods" and "Tests first": "removal bound to its record",
//! "Diagnostics"): `rad.quarantine_list` pages through the record, and
//! `rad.remove_repo` removes only the repository whose record has the
//! `qid` main passes back, then lets it go: unseeded, its storage and COB
//! cache rows deleted, its record cleared.
//!
//! Every node here reaches no one, as in tests/start.rs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::fixture;
use common::*;
use radicle::node::config::DefaultSeedingPolicy;
use radicle::prelude::RepoId;
use radicle::storage::git::reconcile::quarantine::Kind;
use serde_json::{Value, json};

/// A third identity, who makes the repositories the node seeds.
const CREATOR: [u8; 32] = [9; 32];

fn code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or_default()
}

/// Every entry `rad.quarantine_list` gives, page by page.
fn listed(radicled: &mut Radicled) -> Vec<Value> {
    let mut entries = Vec::new();
    let mut page = json!(0);
    while !page.is_null() {
        let reply = radicled.call("rad.quarantine_list", json!({ "page": page }));
        let result = &reply["result"];
        assert!(result.is_object(), "{reply}");
        entries.extend(result["entries"].as_array().unwrap().iter().cloned());
        page = result["next_page"].clone();
    }
    entries
}

/// The `qid` `rad.quarantine_list` gives `rid`, if it lists it.
fn qid_of(radicled: &mut Radicled, rid: RepoId) -> Option<String> {
    listed(radicled)
        .iter()
        .find(|entry| entry["rid"] == rid.to_string())
        .map(|entry| entry["qid"].as_str().unwrap().to_owned())
}

/// Whether the node's policies, read under its `block` default, seed `rid`.
fn seeding(home: &Path, rid: RepoId) -> bool {
    let store = radicle::node::policy::store::Store::reader(
        home.join("node").join(radicle::node::POLICIES_DB_FILE),
    )
    .unwrap();
    radicle::node::policy::config::Config::new(DefaultSeedingPolicy::Block.into(), store)
        .is_seeding(&rid)
        .unwrap()
}

/// How many issues of `rid` `home`'s COB cache holds.
fn cached_issues(home: &Path, rid: RepoId) -> i64 {
    let db = sqlite::open(home.join("cobs").join("cache.db")).unwrap();
    let mut stmt = db
        .prepare("SELECT COUNT(*) FROM issues WHERE repo = ?1")
        .unwrap();
    stmt.bind((1, rid.to_string().as_str())).unwrap();
    stmt.next().unwrap();
    stmt.read::<i64, _>(0).unwrap()
}

/// The `qid` of `home`'s record of `rid`, if it has one, read once the
/// process has exited.
fn recorded(home: &Path, rid: RepoId) -> Option<String> {
    use radicle::storage::git::reconcile::quarantine::{QUARANTINE_DB_FILE, Quarantine};
    Quarantine::open(home.join("node").join(QUARANTINE_DB_FILE))
        .unwrap()
        .get(&rid)
        .unwrap()
        .map(|record| record.qid.to_string())
}

fn removal(rid: RepoId, qid: &str) -> Value {
    json!({ "rid": rid.to_string(), "qid": qid })
}

/// A record with nothing in it lists one empty page; the params are
/// checked.
#[test]
fn an_empty_quarantine_lists_nothing() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(&dirs, &[]);
    assert!(radicled.start()["result"].is_object());
    let reply = radicled.call("rad.quarantine_list", json!({ "page": 0 }));
    assert_eq!(
        reply["result"],
        json!({ "entries": [], "next_page": null }),
        "{reply}"
    );
    for params in [
        json!({}),
        json!({ "page": -1 }),
        json!({ "page": 1.5 }),
        json!({ "page": "0" }),
        json!({ "page": 0, "size": 64 }),
    ] {
        let reply = radicled.call("rad.quarantine_list", params.clone());
        assert_eq!(code(&reply), "invalid_argument", "{params}: {reply}");
    }
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

/// The record's entries, with the kind and step reconciliation left; then
/// the removal of one with its `qid`: it stops being seeded, its storage
/// and COB cache rows are deleted, and it is gone from the list. A second
/// removal with the same `qid`, one with another record's `qid`, and one of
/// a repository that isn't quarantined are each `not_quarantined`, and
/// touch nothing.
#[test]
fn a_removal_with_its_qid_deletes_the_repository_and_nothing_else() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let removed = fixture::repository(&dirs.home, &CREATOR, "removed");
    let kept = fixture::repository(&dirs.home, &CREATOR, "kept");
    let open = fixture::repository(&dirs.home, &CREATOR, "open");
    fixture::quarantine(&dirs.home, removed, Kind::Namespace);
    fixture::quarantine(&dirs.home, kept, Kind::Cache);
    assert!(seeding(&dirs.home, removed));
    assert!(cached_issues(&dirs.home, removed) > 0);

    let mut radicled = Radicled::serve(&dirs, &[]);
    assert!(radicled.start()["result"].is_object());
    let entries = listed(&mut radicled);
    assert_eq!(entries.len(), 2, "{entries:?}");
    let entry = entries
        .iter()
        .find(|entry| entry["rid"] == removed.to_string())
        .unwrap();
    assert_eq!(entry["kind"], "namespace", "{entry}");
    assert_eq!(entry["step"], "namespace", "{entry}");
    let qid = qid_of(&mut radicled, removed).unwrap();
    let kept_qid = qid_of(&mut radicled, kept).unwrap();
    assert_ne!(qid, kept_qid);

    // Another record's `qid`, and a repository with no record.
    let reply = radicled.call("rad.remove_repo", removal(removed, &kept_qid));
    assert_eq!(code(&reply), "not_quarantined", "{reply}");
    let reply = radicled.call("rad.remove_repo", removal(open, &qid));
    assert_eq!(code(&reply), "not_quarantined", "{reply}");
    assert!(fixture::storage_of(&dirs.home, removed).is_dir());
    assert!(fixture::storage_of(&dirs.home, open).is_dir());
    assert_eq!(listed(&mut radicled).len(), 2);

    let reply = radicled.call("rad.remove_repo", removal(removed, &qid));
    assert_eq!(reply["result"], json!({ "removed": true }), "{reply}");
    assert!(!fixture::storage_of(&dirs.home, removed).exists());
    assert!(!seeding(&dirs.home, removed));
    assert_eq!(cached_issues(&dirs.home, removed), 0);
    assert_eq!(qid_of(&mut radicled, removed), None);
    // Delivered again: done once already.
    let reply = radicled.call("rad.remove_repo", removal(removed, &qid));
    assert_eq!(code(&reply), "not_quarantined", "{reply}");

    // The others are as they were.
    assert_eq!(qid_of(&mut radicled, kept), Some(kept_qid));
    for rid in [kept, open] {
        assert!(fixture::storage_of(&dirs.home, rid).is_dir());
        assert!(seeding(&dirs.home, rid));
        assert!(cached_issues(&dirs.home, rid) > 0);
    }

    // Params that don't parse.
    for params in [
        json!({}),
        json!({ "rid": removed.to_string() }),
        json!({ "rid": "rad:nope", "qid": qid }),
        json!({ "rid": removed.to_string(), "qid": "not hex" }),
        json!({ "rid": removed.to_string(), "qid": &qid[1..] }),
        json!({ "rid": removed.to_string(), "qid": qid, "force": true }),
    ] {
        let reply = radicled.call("rad.remove_repo", params.clone());
        assert_eq!(code(&reply), "invalid_argument", "{params}: {reply}");
    }

    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(log.contains("the dirty marker is cleared"), "{log}");
    assert_eq!(fixture::marked(&dirs.home), None);
}

/// 0008, "Tests first": removal bound to its record. The repository is
/// removed, then comes back with data of its own and is quarantined again,
/// with a new record. The first removal, delivered late, is
/// `not_quarantined`, and the data survives; the new record's `qid`
/// removes it.
#[test]
fn a_delayed_removal_never_removes_the_repository_that_came_back() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &CREATOR, "returns");
    fixture::quarantine(&dirs.home, rid, Kind::Namespace);
    // What a later clone of it brings back.
    let copy = tempfile::tempdir().unwrap();
    copy_dir(&fixture::storage_of(&dirs.home, rid), copy.path());

    let mut radicled = Radicled::serve(&dirs, &[]);
    assert!(radicled.start()["result"].is_object());
    let first = qid_of(&mut radicled, rid).unwrap();
    let reply = radicled.call("rad.remove_repo", removal(rid, &first));
    assert_eq!(reply["result"], json!({ "removed": true }), "{reply}");
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));

    copy_dir(copy.path(), &fixture::storage_of(&dirs.home, rid));
    fixture::quarantine(&dirs.home, rid, Kind::Cache);
    let mut radicled = Radicled::serve(&dirs, &[]);
    assert!(radicled.start()["result"].is_object());
    let second = qid_of(&mut radicled, rid).unwrap();
    assert_ne!(first, second);
    let reply = radicled.call("rad.remove_repo", removal(rid, &first));
    assert_eq!(code(&reply), "not_quarantined", "{reply}");
    assert!(fixture::storage_of(&dirs.home, rid).is_dir());
    assert_eq!(qid_of(&mut radicled, rid), Some(second.clone()));

    let reply = radicled.call("rad.remove_repo", removal(rid, &second));
    assert_eq!(reply["result"], json!({ "removed": true }), "{reply}");
    assert!(!fixture::storage_of(&dirs.home, rid).exists());
    assert_eq!(listed(&mut radicled), Vec::<Value>::new());
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}

/// A removal main cancels before it starts removes nothing: its request is
/// `cancelled`, and the repository and its record stay.
#[test]
fn a_removal_cancelled_before_it_starts_removes_nothing() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &CREATOR, "cancelled");
    fixture::quarantine(&dirs.home, rid, Kind::Namespace);
    let mut radicled = Radicled::serve(&dirs, &[("FREEDOM_RADICLED_TEST_HOLD_WORK", "1")]);
    assert!(radicled.start()["result"].is_object());
    let qid = qid_of(&mut radicled, rid).unwrap();
    let id = radicled.request("rad.remove_repo", removal(rid, &qid));
    assert!(radicled.logs("test hook: work holds its slot", Duration::from_secs(10)));
    radicled.send(&json!({ "type": "cancel", "id": id }));
    assert_eq!(code(&radicled.reply(id)), "cancelled");
    // The stop's drain waits for the writer, so once the process has exited
    // cleanly, the cancelled work has returned.
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(log.contains("the dirty marker is cleared"), "{log}");
    assert!(!log.contains("was removed"), "{log}");
    assert!(fixture::storage_of(&dirs.home, rid).is_dir());
    assert_eq!(recorded(&dirs.home, rid), Some(qid));
}

/// A removal that holds the node past the pools' drain: the stop doesn't
/// wait for it, or ask the node, so nothing proves the node stopped. The
/// request is answered `stopped` within the connection's 5 s exit, the
/// marker stays, and nothing was removed.
#[test]
fn a_removal_holding_the_node_past_the_drain_keeps_the_marker() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &CREATOR, "held");
    fixture::quarantine(&dirs.home, rid, Kind::Namespace);
    let mut radicled = Radicled::serve(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HOLD_WORK", "deaf"),
            ("FREEDOM_RADICLED_TEST_SHUTDOWN_WITHIN_MS", "1000"),
        ],
    );
    assert!(radicled.start()["result"].is_object());
    let qid = qid_of(&mut radicled, rid).unwrap();
    let id = radicled.request("rad.remove_repo", removal(rid, &qid));
    assert!(radicled.logs("test hook: work holds its slot", Duration::from_secs(10)));
    let asked = Instant::now();
    radicled.shutdown();
    let reply = radicled.reply(id);
    assert_eq!(code(&reply), "stopped", "{reply}");
    assert_eq!(radicled.exit_code(Duration::from_secs(8)), Some(0));
    assert!(asked.elapsed() < Duration::from_secs(8));
    let log = radicled.stderr();
    assert!(
        log.contains("work was still running past the pools' drain"),
        "{log}"
    );
    assert!(log.contains("the node didn't stop cleanly"), "{log}");
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
    assert!(fixture::storage_of(&dirs.home, rid).is_dir());
    assert_eq!(recorded(&dirs.home, rid), Some(qid));
}

/// Copies the directory `from` into `to`, which it makes.
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}
