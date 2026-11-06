//! The online repair through the real binary (design 0008, "Writes":
//! "Online repair after an uncertain write"; "The unit watchdog", "The
//! escape", "The repository gate" and "Tests first": "The dirty marker",
//! "The bound" and "Units and the watchdog"): a COB write whose outcome is
//! unknown has its repository repaired on the writer, one unit a turn,
//! while reads go on and writes to other repositories run between its
//! units; writes to it wait behind it. Done, a clean stop clears the
//! marker; stopped, it stays. A unit that fails quarantines the repository
//! at once; one that hangs ends the process.
//!
//! A write's outcome is made unknown here as a page can make it: a comment
//! on an issue the repository doesn't have fails past the write's start,
//! in libradicle. `FREEDOM_RADICLED_TEST_HOLD_REPAIR` slows each repair
//! turn, or holds it until the test releases it ([`Dirs::held`]), and
//! `FREEDOM_RADICLED_TEST_HANG_UNIT` hangs a unit (src/testhooks.rs).
//! Every node here reaches no one, as in tests/start.rs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::fixture;
use common::*;
use radicle::prelude::RepoId;
use serde_json::{Value, json};

const QUEUED: &str = "an online repair is queued";
const DONE: &str = "an online repair is done";
const STOPPED: &str = "an online repair stopped between units";
const QUARANTINED: &str = "an online repair quarantined its repository";
const FAILED: &str = "an online repair failed outside its repository";
const HOLDS: &str = "test hook: a repair turn holds the node";
const FENCED: &str = "test hook: the stop has fenced the pools";
const UNREPAIRED: &str =
    "a write's outcome is unknown, and its repository isn't repaired; the dirty marker stays";

/// How long a repair of a fixture's repository may take, unheld.
const REPAIRED_WITHIN: Duration = Duration::from_secs(30);

fn code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or_default()
}

fn create(rid: RepoId, title: &str) -> Value {
    json!({
        "op": "create_issue",
        "args": { "rid": rid.to_string(), "title": title, "description": "Its body.", "labels": [] },
    })
}

/// A write whose outcome is unknown: past its start, libradicle finds no
/// such issue.
fn uncertain(rid: RepoId) -> Value {
    json!({
        "op": "comment_issue",
        "args": { "rid": rid.to_string(), "issue_id": "abcdef0123", "body": "Nowhere." },
    })
}

fn titled(home: &Path, rid: RepoId, title: &str) -> bool {
    fixture::issues(home, rid)
        .iter()
        .map(|issue| serde_json::from_str::<Value>(issue).unwrap())
        .any(|issue| issue["title"] == title)
}

fn served(dirs: &Dirs, extra: &[(&str, &str)]) -> Radicled {
    let mut radicled = Radicled::serve(dirs, extra);
    let started = radicled.start();
    assert!(started["result"].is_object(), "{started}");
    radicled
}

/// A repository the service's own identity made, with one issue: its
/// namespace is the one an online repair checks and re-signs.
fn owned(home: &Path, name: &str) -> RepoId {
    fixture::repository(home, &SEED, name)
}

/// `rad.shutdown`, then the exit: 0, its log, and whether the marker was
/// cleared, as the log and the home agree.
fn shut_down(radicled: &mut Radicled, home: &Path) -> (String, bool) {
    radicled.shutdown();
    exited(radicled, home)
}

/// As [`shut_down`], once `rad.shutdown` was sent.
fn exited(radicled: &mut Radicled, home: &Path) -> (String, bool) {
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    let cleared = log.contains("the dirty marker is cleared");
    assert_eq!(cleared, fixture::marked(home).is_none(), "{log}");
    (log, cleared)
}

/// 0008, "Writes" and "Tests first" ("a clean run: the marker is
/// cleared"): an uncertain write's repository is repaired online. Its own
/// namespace, stale, is re-signed, and its COB cache, which lost the
/// repository's rows, is rebuilt and published, which deletes the repair's
/// progress. The gate opens it again, so writes to it run, and a clean
/// stop clears the marker.
#[test]
fn an_uncertain_writes_repository_is_repaired_online_and_a_clean_stop_clears_the_marker() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = owned(&dirs.home, "repaired");
    // What a kill between a ref and its signing leaves, and a cache that
    // lost the repository's rows. No marker, so the start leaves both.
    fixture::unsigned_ref(&dirs.home, rid, NID);
    let signed = fixture::sigrefs(&dirs.home, rid, NID);
    {
        let db = sqlite::open(dirs.home.join("cobs").join("cache.db")).unwrap();
        let mut stmt = db.prepare("DELETE FROM issues WHERE repo = ?1").unwrap();
        stmt.bind((1, rid.to_string().as_str())).unwrap();
        stmt.next().unwrap();
    }
    assert!(fixture::issues(&dirs.home, rid).is_empty());
    let mut radicled = served(&dirs, &[]);

    let reply = radicled.call("rad.write", uncertain(rid));
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    assert!(radicled.logs(DONE, REPAIRED_WITHIN));
    assert_ne!(fixture::sigrefs(&dirs.home, rid, NID), signed);
    assert!(fixture::has_unsigned_ref(&dirs.home, rid, NID));
    assert_eq!(fixture::issues(&dirs.home, rid).len(), 1);
    assert!(!fixture::progress(&dirs.home, rid));

    let reply = radicled.call("rad.write", create(rid, "After its repair"));
    assert!(reply["result"]["id"].is_string(), "{reply}");
    let (log, cleared) = shut_down(&mut radicled, &dirs.home);
    assert!(cleared, "{log}");
    assert!(log.contains(QUEUED), "{log}");
    let done = log.lines().find(|line| line.contains(DONE)).unwrap();
    assert!(done.contains(r#""resigned":true"#), "{done}");
    assert!(done.contains(r#""cache":true"#), "{done}");
    assert!(!log.contains("Nowhere."), "{log}");
    assert!(titled(&dirs.home, rid, "After its repair"));

    // The next start finds nothing to repair: no marker.
    let mut radicled = Radicled::serve(&dirs, &[]);
    let hello = radicled.hello();
    assert!(radicled.call("rad.identity", sealed_to(&hello, &SEED))["result"].is_object());
    let reconciled = radicled.call("rad.reconcile", json!({}));
    assert_eq!(reconciled["result"]["was_dirty"], false, "{reconciled}");
}

/// 0008, "The deadline" ("`rad.shutdown` stops after the current unit")
/// and "The dirty marker": a stop during an online repair lets the turn in
/// progress end, starts no unit after it, and keeps the marker and the
/// repair's progress; the next start's reconciliation repairs. A turn that
/// outlasts the drain holds the node, and the stop still ends within the
/// connection's 5 s exit, with the marker kept.
///
/// Neither half races the drain: each turn is held before its unit until
/// the test releases it. The first is released only once the stop has
/// fenced the writer, so its unit doesn't start and the drain waits for no
/// unit; the second never is, so it outlasts the drain on any runner.
#[test]
fn a_stop_during_an_online_repair_keeps_the_marker_within_the_exit() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = owned(&dirs.home, "interrupted");
    fixture::unsigned_ref(&dirs.home, rid, NID);
    let signed = fixture::sigrefs(&dirs.home, rid, NID);

    let (hold, gate) = dirs.held("until", "release-turn");
    let mut radicled = served(&dirs, &[("FREEDOM_RADICLED_TEST_HOLD_REPAIR", &hold)]);
    let reply = radicled.call("rad.write", uncertain(rid));
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    assert!(radicled.logs(HOLDS, READ_TIMEOUT));
    radicled.shutdown();
    assert!(radicled.logs(FENCED, READ_TIMEOUT));
    std::fs::write(&gate, b"").unwrap();
    // 0, not the exit watchdog's 70: within the connection's 5 s exit.
    let (log, cleared) = exited(&mut radicled, &dirs.home);
    assert!(!cleared, "{log}");
    assert!(log.contains(STOPPED), "{log}");
    assert!(!log.contains(DONE), "{log}");
    assert!(log.contains(UNREPAIRED), "{log}");
    assert!(!log.contains("past the pools' drain"), "{log}");
    assert_eq!(log.matches(HOLDS).count(), 1, "{log}");
    // The turn the stop met ran no unit after it.
    assert_eq!(fixture::sigrefs(&dirs.home, rid, NID), signed);
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));

    // The next start repairs it. Then a turn held past the drain, with
    // the node.
    let (hold, _never) = dirs.held("until", "release-past");
    let mut radicled = Radicled::serve(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HOLD_REPAIR", &hold),
            ("FREEDOM_RADICLED_TEST_SHUTDOWN_WITHIN_MS", "1000"),
        ],
    );
    let hello = radicled.hello();
    assert!(radicled.call("rad.identity", sealed_to(&hello, &SEED))["result"].is_object());
    let reconciled = radicled.call("rad.reconcile", json!({}));
    assert_eq!(reconciled["result"]["was_dirty"], true, "{reconciled}");
    assert_eq!(
        reconciled["result"]["quarantined"]["count"], 0,
        "{reconciled}"
    );
    assert_ne!(fixture::sigrefs(&dirs.home, rid, NID), signed);
    assert!(radicled.call("rad.start", json!({ "alias": "restarted" }))["result"].is_object());
    let reply = radicled.call("rad.write", uncertain(rid));
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    assert!(radicled.logs(HOLDS, READ_TIMEOUT));
    radicled.shutdown();
    // 0, not the exit watchdog's 70 (`teardown_unproven`): the stop ended
    // within the connection's 5 s exit, without waiting for the turn.
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(log.contains("past the pools' drain"), "{log}");
    assert!(log.contains("the dirty marker stays"), "{log}");
    assert!(!log.contains(DONE), "{log}");
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
}

/// 0008, "Writes" ("one unit per writer turn, interleaved with other
/// repositories' writes"; "writes to it wait behind it") and "The
/// repository gate": during an online repair, a read is answered without
/// waiting for the writer, and a write to another repository runs between
/// its units, ahead of a write to the repository under repair admitted
/// before it. That one waits, and runs once its repository is open again.
#[test]
fn reads_and_other_repositories_writes_go_on_during_a_repair_and_its_own_wait_behind_it() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let repaired = owned(&dirs.home, "under-repair");
    let other = owned(&dirs.home, "elsewhere");
    let mut radicled = served(&dirs, &[("FREEDOM_RADICLED_TEST_HOLD_REPAIR", "300")]);

    let reply = radicled.call("rad.write", uncertain(repaired));
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    assert!(radicled.logs(HOLDS, Duration::from_secs(10)));
    let behind = radicled.request("rad.write", create(repaired, "Behind its repair"));
    let between = radicled.request("rad.write", create(other, "Between its units"));
    let read = radicled.request("rad.quarantine_list", json!({ "page": 0 }));
    radicled.arrivals(&[between, read]);
    // Both before the repair was over: its units went on after them.
    assert!(!radicled.logs(DONE, Duration::ZERO));
    let order = radicled.arrivals(&[behind, between, read]);
    assert_eq!(order.last(), Some(&behind), "{order:?}");

    let reply = radicled.reply(read);
    assert_eq!(
        reply["result"],
        json!({ "entries": [], "next_page": null }),
        "{reply}"
    );
    for id in [between, behind] {
        let reply = radicled.reply(id);
        assert!(reply["result"]["id"].is_string(), "{reply}");
    }
    assert!(radicled.logs(DONE, Duration::from_secs(1)));
    let (log, cleared) = shut_down(&mut radicled, &dirs.home);
    assert!(cleared, "{log}");
    // One unit a turn, each held.
    assert!(log.matches(HOLDS).count() > 2, "{log}");
    assert!(titled(&dirs.home, repaired, "Behind its repair"));
    assert!(titled(&dirs.home, other, "Between its units"));
}

/// 0008, "Writes" ("A unit that fails with an error quarantines the
/// repository at once") and "Tests first" ("a unit of the online repair
/// that fails with an error: the repository is quarantined persistently and
/// at once ..., and other repositories keep working"): an owned ref to a
/// missing object can't be signed. Writes to the repository are then
/// `quarantined`, it is listed, and it stays so after a restart. Being
/// quarantined, it no longer keeps the marker.
#[test]
fn a_repair_unit_that_fails_quarantines_its_repository_at_once() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let broken = owned(&dirs.home, "broken");
    let other = owned(&dirs.home, "healthy");
    fixture::missing_object_ref(&dirs.home, broken, NID);
    let mut radicled = served(&dirs, &[]);

    let reply = radicled.call("rad.write", uncertain(broken));
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    assert!(radicled.logs(QUARANTINED, REPAIRED_WITHIN));
    let reply = radicled.call("rad.write", create(broken, "Refused"));
    assert_eq!(code(&reply), "quarantined", "{reply}");
    assert_eq!(
        reply["error"]["data"],
        json!({ "kind": "namespace", "step": "namespaces" }),
        "{reply}"
    );
    let listed = radicled.call("rad.quarantine_list", json!({ "page": 0 }));
    let entries = listed["result"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{listed}");
    assert_eq!(entries[0]["rid"], broken.to_string(), "{listed}");
    assert_eq!(entries[0]["kind"], "namespace", "{listed}");
    let reply = radicled.call("rad.write", create(other, "Unaffected"));
    assert!(reply["result"]["id"].is_string(), "{reply}");
    let (log, cleared) = shut_down(&mut radicled, &dirs.home);
    assert!(cleared, "{log}");
    assert!(!log.contains(DONE), "{log}");
    let line = log.lines().find(|line| line.contains(QUARANTINED)).unwrap();
    assert!(line.contains(&broken.to_string()), "{line}");
    assert!(!line.contains("missing"), "{line}");

    let mut radicled = served(&dirs, &[]);
    let reply = radicled.call("rad.write", create(broken, "Still refused"));
    assert_eq!(code(&reply), "quarantined", "{reply}");
    shut_down(&mut radicled, &dirs.home);
    assert!(!titled(&dirs.home, broken, "Refused"));
    assert!(titled(&dirs.home, other, "Unaffected"));
}

/// A write to a repository that isn't in storage fails past its start, as
/// any libradicle error does (0008, "Writes"), and its repair can't open
/// the repository: the repair quarantines it, at its `begin` unit, and
/// writes nothing. Nothing seeds or fetches it until it is removed, which
/// clears the record and opens it.
#[test]
fn a_repair_of_a_repository_not_in_storage_quarantines_it() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let absent: RepoId = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5".parse().unwrap();
    let mut radicled = served(&dirs, &[]);
    let reply = radicled.call("rad.write", uncertain(absent));
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    assert!(radicled.logs(QUARANTINED, REPAIRED_WITHIN));
    let listed = radicled.call("rad.quarantine_list", json!({ "page": 0 }));
    let entry = &listed["result"]["entries"][0];
    assert_eq!(entry["rid"], absent.to_string(), "{listed}");
    assert_eq!(entry["step"], "begin", "{listed}");
    let reply = radicled.call(
        "rad.remove_repo",
        json!({ "rid": absent.to_string(), "qid": entry["qid"] }),
    );
    assert_eq!(reply["result"], json!({ "removed": true }), "{reply}");
    let (log, cleared) = shut_down(&mut radicled, &dirs.home);
    assert!(cleared, "{log}");
    assert!(!fixture::storage_of(&dirs.home, absent).exists());
}

/// A repair that fails outside its repository, here a quarantine record
/// that doesn't open, quarantines nothing: it is logged, naming the step
/// and no path; the repository stays closed until the next start, its
/// writes `stopped`; other repositories keep working; and the marker
/// stays, so the next start's reconciliation repairs it.
#[test]
fn a_repair_that_fails_outside_its_repository_keeps_it_closed_and_the_marker() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = owned(&dirs.home, "unrecorded");
    let other = owned(&dirs.home, "recorded");
    fixture::unsigned_ref(&dirs.home, rid, NID);
    let mut radicled = served(&dirs, &[]);

    let record = dirs.home.join("node").join("reconcile.db");
    let moved = dirs.home.join("reconcile.db.moved");
    std::fs::rename(&record, &moved).unwrap();
    std::fs::create_dir(&record).unwrap();
    let reply = radicled.call("rad.write", uncertain(rid));
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    assert!(radicled.logs(FAILED, REPAIRED_WITHIN));
    let reply = radicled.call("rad.write", create(rid, "Refused"));
    assert_eq!(code(&reply), "stopped", "{reply}");
    let reply = radicled.call("rad.write", create(other, "Unaffected"));
    assert!(reply["result"]["id"].is_string(), "{reply}");
    let (log, cleared) = shut_down(&mut radicled, &dirs.home);
    assert!(!cleared, "{log}");
    assert!(log.contains(UNREPAIRED), "{log}");
    let line = log.lines().find(|line| line.contains(FAILED)).unwrap();
    assert!(
        line.contains("the quarantine record: its database doesn't open or answer"),
        "{line}"
    );
    assert!(!line.contains(&*dirs.home.to_string_lossy()), "{line}");
    assert!(fixture::has_unsigned_ref(&dirs.home, rid, NID));

    std::fs::remove_dir(&record).unwrap();
    std::fs::rename(&moved, &record).unwrap();
    let signed = fixture::sigrefs(&dirs.home, rid, NID);
    let mut radicled = Radicled::serve(&dirs, &[]);
    let hello = radicled.hello();
    assert!(radicled.call("rad.identity", sealed_to(&hello, &SEED))["result"].is_object());
    let reconciled = radicled.call("rad.reconcile", json!({}));
    assert_eq!(reconciled["result"]["was_dirty"], true, "{reconciled}");
    assert_eq!(
        reconciled["result"]["quarantined"]["count"], 0,
        "{reconciled}"
    );
    assert_ne!(fixture::sigrefs(&dirs.home, rid, NID), signed);
    assert!(!titled(&dirs.home, rid, "Refused"));
}

/// 0008, "The unit watchdog" ("An online repair that hangs ends the
/// process within 30 s") and "Tests first" ("a COB that never returns
/// during an online repair"): a unit that doesn't return ends the process
/// with 70, `unit_overrun`, its record and the marker kept; the next start
/// reruns the unit, and the repository is repaired, not quarantined, after
/// one interruption.
#[test]
fn an_online_repair_unit_that_hangs_ends_the_process_and_the_next_start_repairs() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = owned(&dirs.home, "hanging");
    fixture::unsigned_ref(&dirs.home, rid, NID);
    // No marker, so no cache unit runs at the start: the first is the
    // online repair's.
    let mut radicled = served(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HANG_UNIT", "cache"),
            ("FREEDOM_RADICLED_TEST_UNIT_LIMIT_MS", "1000"),
        ],
    );
    let reply = radicled.call("rad.write", uncertain(rid));
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(70));
    let log = radicled.stderr();
    assert!(log.contains(r#""reason":"unit_overrun""#), "{log}");
    assert!(!log.contains(DONE), "{log}");
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));

    let mut radicled = Radicled::serve(&dirs, &[]);
    let hello = radicled.hello();
    assert!(radicled.call("rad.identity", sealed_to(&hello, &SEED))["result"].is_object());
    let reconciled = radicled.call("rad.reconcile", json!({}));
    assert_eq!(reconciled["result"]["was_dirty"], true, "{reconciled}");
    assert_eq!(
        reconciled["result"]["quarantined"]["count"], 0,
        "{reconciled}"
    );
    assert!(radicled.call("rad.start", json!({ "alias": "restarted" }))["result"].is_object());
    let reply = radicled.call("rad.write", create(rid, "After the restart"));
    assert!(reply["result"]["id"].is_string(), "{reply}");
    shut_down(&mut radicled, &dirs.home);
}
