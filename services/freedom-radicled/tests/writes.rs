//! The writes through the real binary (design 0008, "Writes", "Profiles
//! without a vault", "Errors" and "Tests first": "Writes" and "The dirty
//! marker"): `rad.write`'s COB writes and `rad.unseed` answer today's JSON;
//! before the mutation-start boundary every refusal is definitive and
//! changes nothing; past it only a success is proven, every other end is
//! `outcome_unknown`, and a write that ends so keeps the dirty marker.
//!
//! `FREEDOM_RADICLED_TEST_HOLD_WORK` holds a write before its boundary,
//! `FREEDOM_RADICLED_TEST_HOLD_WRITE` just past it (src/testhooks.rs): for
//! some milliseconds, or until the test releases it ([`Dirs::held`]),
//! before libradicle's call (`until`) or once it has returned (`after`),
//! and it logs the write's end, which a test waits for ([`release`]).
//! Every node here reaches no one, as in tests/start.rs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::fixture;
use common::*;
use radicle::prelude::RepoId;
use radicle::storage::git::reconcile::quarantine::Kind;
use serde_json::{Value, json};

/// A third identity, who makes the repositories the node writes to.
const CREATOR: [u8; 32] = [9; 32];

const STARTED: &str = "test hook: the write has started";
const RETURNED: &str = "test hook: the write has returned";
const CALLED: &str = "test hook: libradicle's call has returned";
const FENCED: &str = "test hook: the stop has fenced the pools";
const HELD: &str = "test hook: work holds its slot";

fn code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or_default()
}

fn create(rid: RepoId, title: &str) -> Value {
    json!({
        "op": "create_issue",
        "args": { "rid": rid.to_string(), "title": title, "description": "Its body.", "labels": [] },
    })
}

/// The issues of `rid` in `home`'s COB cache: each one's JSON.
fn issues(home: &Path, rid: RepoId) -> Vec<String> {
    let db = sqlite::open(home.join("cobs").join("cache.db")).unwrap();
    let mut stmt = db
        .prepare("SELECT issue FROM issues WHERE repo = ?1 ORDER BY id")
        .unwrap();
    stmt.bind((1, rid.to_string().as_str())).unwrap();
    let mut issues = Vec::new();
    while let Ok(sqlite::State::Row) = stmt.next() {
        issues.push(stmt.read::<String, _>(0).unwrap());
    }
    issues
}

/// The issue with `title` in `home`'s COB cache, if there is one.
fn titled(home: &Path, rid: RepoId, title: &str) -> Option<Value> {
    issues(home, rid)
        .iter()
        .map(|issue| serde_json::from_str::<Value>(issue).unwrap())
        .find(|issue| issue["title"] == title)
}

fn served(dirs: &Dirs, extra: &[(&str, &str)]) -> Radicled {
    let mut radicled = Radicled::serve(dirs, extra);
    let started = radicled.start();
    assert!(started["result"].is_object(), "{started}");
    radicled
}

/// Releases the write held until `gate` exists ([`Dirs::held`]), and
/// waits for it to return: its outcome is marked by then, and no work is
/// left for the stop's drain. A hang guard, never a timing assertion: on
/// a loaded runner a COB write can take seconds.
fn release(radicled: &Radicled, gate: &Path) {
    std::fs::write(gate, b"").unwrap();
    assert!(radicled.logs(RETURNED, READ_TIMEOUT));
}

/// `rad.shutdown`, then a stop with a complete drain: exit 0, its log, and
/// whether the marker was cleared.
fn stopped_cleanly(radicled: &mut Radicled, home: &Path) -> (String, bool) {
    radicled.shutdown();
    stopped_cleanly_after_shutdown(radicled, home)
}

/// Each COB write and `rad.unseed`, answering today's JSON; their params
/// checked first. A clean run clears the marker.
#[test]
fn the_writes_answer_todays_json_and_a_clean_run_clears_the_marker() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &CREATOR, "written");
    let mut radicled = served(&dirs, &[]);

    let reply = radicled.call(
        "rad.write",
        json!({
            "op": "create_issue",
            "args": { "rid": rid.to_string(), "title": "Second", "description": "Its body.", "labels": [] },
        }),
    );
    let issue = reply["result"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{reply}"))
        .to_owned();
    assert_eq!(issue.len(), 40, "{reply}");
    assert_eq!(reply["result"], json!({ "id": issue }));
    let reply = radicled.call(
        "rad.write",
        json!({
            "op": "comment_issue",
            "args": { "rid": rid.to_string(), "issue_id": issue, "body": "A comment.", "reply_to": null },
        }),
    );
    let comment = reply["result"]["id"].as_str().unwrap().to_owned();
    let reply = radicled.call(
        "rad.write",
        json!({
            "op": "comment_issue",
            "args": { "rid": rid.to_string(), "issue_id": &issue[..8], "body": "A reply.", "reply_to": comment },
        }),
    );
    assert!(reply["result"]["id"].is_string(), "{reply}");
    let reply = radicled.call(
        "rad.write",
        json!({
            "op": "edit_issue_state",
            "args": { "rid": rid.to_string(), "issue_id": issue, "state": "solved" },
        }),
    );
    assert_eq!(
        reply["result"],
        json!({ "id": issue, "state": "solved" }),
        "{reply}"
    );

    // What libradicle would refuse is refused before the boundary.
    for params in [
        json!({}),
        json!({ "op": "create_issue", "args": { "rid": rid.to_string() } }),
        json!({ "op": "delete_issue", "args": {} }),
        json!({ "op": "edit_issue_state", "args": { "rid": rid.to_string(), "issue_id": issue, "state": "merged" } }),
        json!({ "op": "comment_issue", "args": { "rid": rid.to_string(), "issue_id": "XYZ", "body": "" } }),
    ] {
        let reply = radicled.call("rad.write", params.clone());
        assert_eq!(code(&reply), "invalid_argument", "{params}: {reply}");
    }
    for params in [json!({}), json!({ "rid": "rad:nope" })] {
        let reply = radicled.call("rad.unseed", params.clone());
        assert_eq!(code(&reply), "invalid_argument", "{params}: {reply}");
    }

    let reply = radicled.call("rad.unseed", json!({ "rid": rid.to_string() }));
    assert_eq!(reply["result"], json!({ "unseeded": true }), "{reply}");

    let (_, cleared) = stopped_cleanly(&mut radicled, &dirs.home);
    assert!(cleared);
    let written = titled(&dirs.home, rid, "Second").unwrap();
    assert_eq!(written["state"]["status"], "closed", "{written}");
    assert_eq!(written["state"]["reason"], "solved", "{written}");
    assert_eq!(issues(&dirs.home, rid).len(), 2);
}

/// 0008, "Profiles without a vault": on a node with a throwaway key, a COB
/// write is `needs_vault` and writes nothing; its params are checked
/// first. Unseeding still works.
#[test]
fn a_cob_write_under_a_throwaway_key_is_needs_vault() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &CREATOR, "throwaway");
    let mut radicled = Radicled::serve(&dirs, &[]);
    radicled.hello();
    let identity = radicled.call("rad.identity", json!({ "ephemeral": true }));
    assert_eq!(identity["result"]["ephemeral"], true, "{identity}");
    assert!(radicled.call("rad.reconcile", json!({}))["result"].is_object());
    assert!(radicled.call("rad.start", json!({ "alias": "throwaway" }))["result"].is_object());

    let reply = radicled.call("rad.write", create(rid, "Unpublished"));
    assert_eq!(code(&reply), "needs_vault", "{reply}");
    let reply = radicled.call("rad.write", json!({ "op": "create_issue", "args": {} }));
    assert_eq!(code(&reply), "invalid_argument", "{reply}");
    let reply = radicled.call("rad.unseed", json!({ "rid": rid.to_string() }));
    assert_eq!(reply["result"], json!({ "unseeded": true }), "{reply}");

    stopped_cleanly(&mut radicled, &dirs.home);
    assert_eq!(titled(&dirs.home, rid, "Unpublished"), None);
    assert_eq!(issues(&dirs.home, rid).len(), 1);
}

/// 0008, "The escape" and "Errors": a write to a quarantined repository is
/// `quarantined`, with the record's kind and step, and writes nothing.
/// Unseeding it changes the policy, not the record, and is allowed.
#[test]
fn a_write_to_a_quarantined_repository_is_refused_with_its_kind_and_step() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &CREATOR, "quarantined");
    fixture::quarantine(&dirs.home, rid, Kind::Cache);
    let mut radicled = served(&dirs, &[]);

    let reply = radicled.call("rad.write", create(rid, "Refused"));
    assert_eq!(code(&reply), "quarantined", "{reply}");
    assert_eq!(
        reply["error"]["data"],
        json!({ "kind": "cache", "step": "namespace" }),
        "{reply}"
    );
    let reply = radicled.call("rad.unseed", json!({ "rid": rid.to_string() }));
    assert_eq!(reply["result"], json!({ "unseeded": true }), "{reply}");

    stopped_cleanly(&mut radicled, &dirs.home);
    assert_eq!(titled(&dirs.home, rid, "Refused"), None);
}

/// Before the boundary, failure is definitive: a write that main cancels,
/// that passes its deadline, or that the stop meets, while held before its
/// start, never starts. Each is answered so, nothing is written, and the
/// run stays clean.
#[test]
fn a_write_cancelled_expired_or_stopped_before_its_start_writes_nothing() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &CREATOR, "untouched");
    let mut radicled = served(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HOLD_WORK", "1"),
            ("FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS", "1500"),
        ],
    );

    let cancelled = radicled.request("rad.write", create(rid, "Cancelled"));
    assert!(radicled.logs_times(HELD, 1, Duration::from_secs(10)));
    radicled.send(&json!({ "type": "cancel", "id": cancelled }));
    assert_eq!(code(&radicled.reply(cancelled)), "cancelled");

    let admitted = Instant::now();
    let expired = radicled.request("rad.write", create(rid, "Expired"));
    let reply = radicled.reply(expired);
    assert_eq!(code(&reply), "deadline", "{reply}");
    assert!(admitted.elapsed() >= Duration::from_millis(1500));

    let met = radicled.request("rad.write", create(rid, "Stopped"));
    assert!(radicled.logs_times(HELD, 3, Duration::from_secs(10)));
    radicled.shutdown();
    let reply = radicled.reply(met);
    assert_eq!(code(&reply), "stopped", "{reply}");
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(!log.contains(STARTED), "{log}");
    assert!(log.contains("the dirty marker is cleared"), "{log}");
    assert_eq!(fixture::marked(&dirs.home), None);
    assert_eq!(issues(&dirs.home, rid).len(), 1);
}

/// Past the boundary, main's cancel and the deadline are `outcome_unknown`
/// at once, while the write is still held, and the write then runs on to
/// its end, its reply lost: the issue is recorded. It keeps the writer, so
/// a write queued behind it passes its own deadline unstarted. Once it has
/// returned it is proven, so the stop's drain is complete and the run
/// stays clean. Each write is held until the test releases it, and the
/// stop waits for its end ([`release`]), so nothing here races the 3 s
/// drain; the drain's own wait for a write is
/// [`a_stop_during_a_write_keeps_its_reply_or_leaves_the_marker`]'s.
#[test]
fn past_its_start_a_cancel_or_the_deadline_is_outcome_unknown_and_the_write_completes() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &CREATOR, "late");
    let (hold, gate) = dirs.held("until", "release-cancelled");
    let mut radicled = served(&dirs, &[("FREEDOM_RADICLED_TEST_HOLD_WRITE", &hold)]);
    let cancelled = radicled.request("rad.write", create(rid, "Cancelled late"));
    assert!(radicled.logs_times(STARTED, 1, Duration::from_secs(10)));
    radicled.send(&json!({ "type": "cancel", "id": cancelled }));
    let reply = radicled.reply(cancelled);
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    // At once: the write is still held, and only the test releases it.
    assert!(!radicled.logs(RETURNED, Duration::ZERO));
    release(&radicled, &gate);
    let (_, cleared) = stopped_cleanly(&mut radicled, &dirs.home);
    assert!(cleared);
    assert!(titled(&dirs.home, rid, "Cancelled late").is_some());

    let (hold, gate) = dirs.held("until", "release-late");
    let mut radicled = served(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HOLD_WRITE", &hold),
            ("FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS", "800"),
        ],
    );
    let late = radicled.request("rad.write", create(rid, "Past its deadline"));
    assert!(radicled.logs_times(STARTED, 1, Duration::from_secs(10)));
    let behind = radicled.request("rad.write", create(rid, "Behind it"));
    let reply = radicled.reply(late);
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    let reply = radicled.reply(behind);
    assert_eq!(code(&reply), "deadline", "{reply}");
    assert!(!radicled.logs(RETURNED, Duration::ZERO));
    release(&radicled, &gate);
    let (log, cleared) = stopped_cleanly(&mut radicled, &dirs.home);
    assert!(cleared, "{log}");
    assert!(titled(&dirs.home, rid, "Past its deadline").is_some());
    assert_eq!(titled(&dirs.home, rid, "Behind it"), None);
}

/// Past the boundary, a libradicle error and a panic are each
/// `outcome_unknown`, its text logged with the code. The write may be
/// partial, so its repository is repaired online, one repair a write: the
/// second write waits behind the first's repair. Once both are done, a
/// clean stop clears the marker (src/repair.rs, tests/repair.rs). An
/// unseed's unknown outcome is a policy's, which no repair checks: the
/// marker stays after it, for the next start.
#[test]
fn past_its_start_an_error_or_a_panic_is_outcome_unknown_and_its_repository_is_repaired() {
    const DONE: &str = "an online repair is done";
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &CREATOR, "failing");
    let mut radicled = served(&dirs, &[]);
    for (op, args) in [
        (
            "comment_patch",
            json!({ "rid": rid.to_string(), "revision_id": "abcdef0123", "body": "Nowhere." }),
        ),
        (
            "comment_issue",
            json!({ "rid": rid.to_string(), "issue_id": "abcdef0123", "body": "Nowhere." }),
        ),
    ] {
        let reply = radicled.call("rad.write", json!({ "op": op, "args": args }));
        assert_eq!(code(&reply), "outcome_unknown", "{op}: {reply}");
    }
    assert!(radicled.logs_times(DONE, 2, Duration::from_secs(30)));
    let (log, cleared) = stopped_cleanly(&mut radicled, &dirs.home);
    assert!(cleared, "{log}");
    assert!(log.contains("a write failed past its start"), "{log}");
    assert!(!log.contains("Nowhere."), "{log}");

    let mut radicled = served(&dirs, &[("FREEDOM_RADICLED_TEST_HOLD_WRITE", "panic")]);
    let reply = radicled.call("rad.write", create(rid, "Panicked"));
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    assert!(radicled.logs(DONE, Duration::from_secs(30)));
    let (log, cleared) = stopped_cleanly(&mut radicled, &dirs.home);
    assert!(cleared, "{log}");

    let mut radicled = served(&dirs, &[("FREEDOM_RADICLED_TEST_HOLD_WRITE", "panic")]);
    let reply = radicled.call("rad.unseed", json!({ "rid": rid.to_string() }));
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    let (log, cleared) = stopped_cleanly(&mut radicled, &dirs.home);
    assert!(!cleared, "{log}");
    assert!(!log.contains("an online repair is queued"), "{log}");
    assert!(
        log.contains(
            "an outcome is unknown: a write's whose repository isn't repaired, or a clone's that was cut off; the dirty marker stays"
        ),
        "{log}"
    );
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
}

/// The stop waits for a started write inside its drain, and the write's
/// own reply stands. One that outlasts the drain is `outcome_unknown`,
/// within the connection's 5 s exit, and the marker stays.
///
/// Neither half races the drain. The first write runs libradicle's call
/// to its end, however long it takes, and is held there, unanswered; the
/// test stops the service and releases the write only once the stop has
/// fenced the pools, so the drain meets it and waits for no libradicle
/// work. The second is held before its call until the test releases it,
/// which it never does, so it outlasts the drain on any runner.
#[test]
fn a_stop_during_a_write_keeps_its_reply_or_leaves_the_marker() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &CREATOR, "stopping");
    let (hold, gate) = dirs.held("after", "release-inside");
    let mut radicled = served(&dirs, &[("FREEDOM_RADICLED_TEST_HOLD_WRITE", &hold)]);
    let write = radicled.request("rad.write", create(rid, "Inside the drain"));
    assert!(radicled.logs(CALLED, READ_TIMEOUT));
    radicled.shutdown();
    assert!(radicled.logs(FENCED, READ_TIMEOUT));
    // The stop met the write before its outcome was marked and answered.
    assert!(!radicled.logs(RETURNED, Duration::ZERO));
    // Its reply then, which the drain waits for.
    std::fs::write(&gate, b"").unwrap();
    let reply = radicled.reply(write);
    assert!(reply["result"]["id"].is_string(), "{reply}");
    let (_, cleared) = stopped_cleanly_after_shutdown(&mut radicled, &dirs.home);
    assert!(cleared);
    assert!(titled(&dirs.home, rid, "Inside the drain").is_some());

    let (hold, _never) = dirs.held("until", "release-past");
    let mut radicled = served(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HOLD_WRITE", &hold),
            ("FREEDOM_RADICLED_TEST_SHUTDOWN_WITHIN_MS", "1000"),
        ],
    );
    let write = radicled.request("rad.write", create(rid, "Past the drain"));
    assert!(radicled.logs_times(STARTED, 1, Duration::from_secs(10)));
    radicled.shutdown();
    let reply = radicled.reply(write);
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    // 0, not the exit watchdog's 70 (`teardown_unproven`): the stop ended
    // within the connection's 5 s exit, without waiting for the write.
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(
        log.contains("work was still running past the pools' drain"),
        "{log}"
    );
    // Still held as the process ended.
    assert!(!log.contains(RETURNED), "{log}");
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));
}

/// As [`stopped_cleanly`], once `rad.shutdown` was sent.
fn stopped_cleanly_after_shutdown(radicled: &mut Radicled, home: &Path) -> (String, bool) {
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(!log.contains("past the pools' drain"), "{log}");
    let cleared = log.contains("the dirty marker is cleared");
    assert_eq!(cleared, fixture::marked(home).is_none(), "{log}");
    (log, cleared)
}
