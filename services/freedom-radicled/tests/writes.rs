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
//! `FREEDOM_RADICLED_TEST_HOLD_READ` holds a read where `rad.unseed` meets
//! it (#338). `FREEDOM_RADICLED_TEST_WEDGE_REACTOR` wedges the node's
//! reactor, which `rad.unseed` and `node_info` wait for (#340).
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
const READ_HELD: &str = "test hook: the read holds";
const UNSEED_WAITS: &str = "test hook: the unseed waits for the node";
const WEDGED: &str = "test hook: the gate holds the reactor";
const UNPROVEN: &str = "the node didn't stop cleanly";

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
///
/// The 1.5 s deadline is the expired write's alone, admitted while `from`
/// exists: the others keep their 60 s, so a slow runner can't let it pass
/// before main's cancel or the stop reaches them.
#[test]
fn a_write_cancelled_expired_or_stopped_before_its_start_writes_nothing() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &CREATOR, "untouched");
    let from = dirs.own_home.join("deadline-from");
    let from_arg = from.display().to_string();
    let mut radicled = served(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HOLD_WORK", "1"),
            ("FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS", "1500"),
            ("FREEDOM_RADICLED_TEST_WORK_DEADLINE_FROM", &from_arg),
        ],
    );

    let cancelled = radicled.request("rad.write", create(rid, "Cancelled"));
    assert!(radicled.logs_times(HELD, 1, READ_TIMEOUT));
    radicled.send(&json!({ "type": "cancel", "id": cancelled }));
    assert_eq!(code(&radicled.reply(cancelled)), "cancelled");

    std::fs::write(&from, b"").unwrap();
    let admitted = Instant::now();
    let expired = radicled.request("rad.write", create(rid, "Expired"));
    let reply = radicled.reply(expired);
    assert_eq!(code(&reply), "deadline", "{reply}");
    assert!(admitted.elapsed() >= Duration::from_millis(1500));
    std::fs::remove_file(&from).unwrap();

    // Its hold counted from the lines so far: the expired write logged one
    // only if the writer took it before its deadline.
    let held = radicled.logged(HELD);
    let met = radicled.request("rad.write", create(rid, "Stopped"));
    assert!(radicled.logs_times(HELD, held + 1, READ_TIMEOUT));
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
    assert!(radicled.logs_times(STARTED, 1, READ_TIMEOUT));
    radicled.send(&json!({ "type": "cancel", "id": cancelled }));
    let reply = radicled.reply(cancelled);
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    // At once: the write is still held, and only the test releases it.
    assert!(!radicled.logs(RETURNED, Duration::ZERO));
    release(&radicled, &gate);
    let (_, cleared) = stopped_cleanly(&mut radicled, &dirs.home);
    assert!(cleared);
    assert!(titled(&dirs.home, rid, "Cancelled late").is_some());

    // The write must start before its deadline, which runs from its
    // admission: no signal can stand in for that, so the deadline has
    // headroom. Admission to start touches no disk, but a Windows runner
    // has stalled every process for 5.9 s (issue #311); the 800 ms this
    // had left no room for it.
    let (hold, gate) = dirs.held("until", "release-late");
    let mut radicled = served(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HOLD_WRITE", &hold),
            ("FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS", "8000"),
        ],
    );
    let late = radicled.request("rad.write", create(rid, "Past its deadline"));
    assert!(radicled.logs_times(STARTED, 1, READ_TIMEOUT));
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
    assert!(radicled.logs_times(DONE, 2, READ_TIMEOUT));
    let (log, cleared) = stopped_cleanly(&mut radicled, &dirs.home);
    assert!(cleared, "{log}");
    assert!(log.contains("a write failed past its start"), "{log}");
    assert!(!log.contains("Nowhere."), "{log}");

    let mut radicled = served(&dirs, &[("FREEDOM_RADICLED_TEST_HOLD_WRITE", "panic")]);
    let reply = radicled.call("rad.write", create(rid, "Panicked"));
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    assert!(radicled.logs(DONE, READ_TIMEOUT));
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
    assert!(radicled.logs_times(STARTED, 1, READ_TIMEOUT));
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

/// #338: `rad.unseed` beside a `node_info` read on a node that just
/// started. `FREEDOM_RADICLED_TEST_HOLD_READ` holds the read between its
/// steps, once the listing's identity check has returned and before the
/// listing, where it stalled, until the test releases it. The read holds
/// nothing of the node there, so the unseed completes while the read is
/// held; then the read completes too, listing only what is still seeded,
/// and the stop drains and clears the marker.
///
/// The read used to hold the node shared through the identity check and
/// take it shared again for the listing. The unseed waited for that first
/// hold, and std's lock makes a new shared hold wait behind a waiting
/// exclusive one, on every platform: so the listing waited for the unseed,
/// the unseed for the read, and neither answered; the reads after them
/// waited behind the unseed, and the stop's drain didn't complete.
#[test]
fn an_unseed_beside_a_node_info_read_completes_and_so_does_the_read() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &CREATOR, "unseeded");
    fixture::repository(&dirs.home, &CREATOR, "kept");
    let (hold, gate) = dirs.held("until", "release-node-info");
    let mut radicled = served(&dirs, &[("FREEDOM_RADICLED_TEST_HOLD_READ", &hold)]);

    let read = radicled.request("rad.read", json!({ "op": "node_info", "args": {} }));
    assert!(radicled.logs(READ_HELD, READ_TIMEOUT));
    let unseed = radicled.request("rad.unseed", json!({ "rid": rid.to_string() }));
    // While the read is held: a hang guard, never a timing assertion.
    assert!(
        radicled.any_within(unseed, READ_TIMEOUT),
        "the unseed didn't answer beside the held node_info read"
    );
    let reply = radicled.reply(unseed);
    assert_eq!(reply["result"], json!({ "unseeded": true }), "{reply}");
    assert_eq!(radicled.logged(READ_HELD), 1);

    std::fs::write(&gate, b"").unwrap();
    let info: Value = serde_json::from_slice(&radicled.read_reply(read).unwrap()).unwrap();
    assert_eq!(
        info,
        json!({ "connected_peers": 0, "repos_total": 1, "repos_error": null })
    );
    // And the reads after them.
    let info: Value =
        serde_json::from_slice(&radicled.read("node_info", json!({})).unwrap()).unwrap();
    assert_eq!(info["repos_total"], 1, "{info}");
    let (_, cleared) = stopped_cleanly(&mut radicled, &dirs.home);
    assert!(cleared);
}

/// #338's other read: `rad.unseed` beside a `repo_info` read, held inside
/// its step with the node held shared. The unseed waits for it, as a write
/// waits for any read's step; released, the read completes without taking
/// the node again, then the unseed, and the stop drains and clears the
/// marker. This one never stalled: each of its steps takes the node once.
#[test]
fn an_unseed_beside_a_repo_read_waits_for_its_step_and_both_complete() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &CREATOR, "read");
    let (hold, gate) = dirs.held("until", "release-repo-info");
    let mut radicled = served(&dirs, &[("FREEDOM_RADICLED_TEST_HOLD_READ", &hold)]);

    let read = radicled.request(
        "rad.read",
        json!({ "op": "repo_info", "args": { "rid": rid.to_string() } }),
    );
    assert!(radicled.logs(READ_HELD, READ_TIMEOUT));
    let unseed = radicled.request("rad.unseed", json!({ "rid": rid.to_string() }));
    assert!(radicled.logs(UNSEED_WAITS, READ_TIMEOUT));
    // The read holds the node shared: the unseed can't have it yet.
    assert!(!radicled.any_within(unseed, Duration::ZERO));

    std::fs::write(&gate, b"").unwrap();
    let info: Value = serde_json::from_slice(&radicled.read_reply(read).unwrap()).unwrap();
    assert_eq!(info["rid"], rid.to_string(), "{info}");
    let reply = radicled.reply(unseed);
    assert_eq!(reply["result"], json!({ "unseeded": true }), "{reply}");
    let info: Value =
        serde_json::from_slice(&radicled.read("node_info", json!({})).unwrap()).unwrap();
    assert_eq!(info["repos_total"], 0, "{info}");
    let (_, cleared) = stopped_cleanly(&mut radicled, &dirs.home);
    assert!(cleared);
}

/// A node whose reactor `FREEDOM_RADICLED_TEST_WEDGE_REACTOR` wedges once
/// the test arms it, with `extra`: its one preferred seed is a loopback
/// port nothing listens on, which `rad.connect_seeds` dials, so the gate's
/// ask holds the reactor's thread. The wedge's file, to arm it.
fn wedgeable(dirs: &Dirs, extra: &[(&str, &str)]) -> (Radicled, std::path::PathBuf) {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = dirs.home.join("config.json");
    let mut fields: Value = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    fields["preferredSeeds"] = json!([format!("{}@127.0.0.1:{port}", fixture::nid_of(&[5; 32]))]);
    std::fs::write(&config, fields.to_string()).unwrap();
    let armed = dirs.own_home.join("wedge");
    let armed_text = armed.display().to_string();
    let mut env = vec![("FREEDOM_RADICLED_TEST_WEDGE_REACTOR", armed_text.as_str())];
    env.extend_from_slice(extra);
    (served(dirs, &env), armed)
}

/// Wedges the reactor of a node from [`wedgeable`]: arms the wedge, then
/// dials the seed book, and waits for the gate to hold the reactor.
fn wedge(radicled: &mut Radicled, armed: &Path) {
    std::fs::write(armed, b"").unwrap();
    radicled.request("rad.connect_seeds", json!({ "timeout_ms": 1000 }));
    assert!(radicled.logs(WEDGED, READ_TIMEOUT));
}

/// The calls the stop's log names as waiting on the node's reactor (#340),
/// each with whether it is overdue, and which list named them.
fn named_waiting(log: &str) -> (String, Vec<(String, bool)>) {
    let line = log
        .lines()
        .find(|line| line.contains(UNPROVEN))
        .unwrap_or_else(|| panic!("no unproven stop: {log}"));
    let line: Value = serde_json::from_str(line).unwrap();
    let waiting = &line["waiting_on_node"];
    let calls = waiting["calls"]
        .as_array()
        .unwrap_or_else(|| panic!("{line}"))
        .iter()
        .map(|call| {
            (
                call["call"].as_str().unwrap().to_owned(),
                call["overdue"].as_bool().unwrap(),
            )
        })
        .collect();
    (waiting["listed"].as_str().unwrap().to_owned(), calls)
}

/// #340: a wedged reactor. heartwood answers `sessions` and `unseed` only
/// through its reactor, and its handle waited for it with no bound, holding
/// the node's lock: a reactor that never answered held `node_info`, every
/// `rad.unseed` behind it, and the stop. Each call now waits up to its
/// request's deadline (here 3 s), then returns and lets go of the node:
/// - `node_info` answers `deadline`;
/// - `rad.unseed` answers `outcome_unknown`, past its start: it was sent,
///   and the node may still carry it out;
/// - a second `rad.unseed` behind it starts, and so answers
///   `outcome_unknown` too, not a queued write's `deadline`: neither the
///   writer nor the node is held;
/// - the stop can't prove the node stopped, and its log names the calls
///   still waiting on the reactor from libradicle's list, past their
///   bounds: the read's `sessions` and both unseeds. The marker stays.
///
/// Then a second node, its unseed still waiting within a long bound, with
/// the node held exclusively, when the stop comes: libradicle's list can't
/// be read through the node's lock, and the stop names the unseed from the
/// service's own.
#[test]
fn a_wedged_reactor_answers_each_call_at_its_deadline_and_the_stop_names_them() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let rid = fixture::repository(&dirs.home, &CREATOR, "wedged");
    let unseed = json!({ "rid": rid.to_string() });
    let (mut radicled, armed) = wedgeable(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS", "3000"),
            ("FREEDOM_RADICLED_TEST_SHUTDOWN_WITHIN_MS", "1000"),
            ("FREEDOM_RADICLED_TEST_HOLD_WRITE", "0"),
        ],
    );
    // The reactor answers before the wedge.
    let info: Value =
        serde_json::from_slice(&radicled.read("node_info", json!({})).unwrap()).unwrap();
    assert_eq!(info["connected_peers"], 0, "{info}");
    wedge(&mut radicled, &armed);

    let read = radicled.read("node_info", json!({})).unwrap_err();
    assert_eq!(code(&read), "deadline", "{read}");
    let first = radicled.call("rad.unseed", unseed.clone());
    assert_eq!(code(&first), "outcome_unknown", "{first}");
    assert!(radicled.logs_times(RETURNED, 1, READ_TIMEOUT));
    let second = radicled.call("rad.unseed", unseed.clone());
    assert_eq!(code(&second), "outcome_unknown", "{second}");
    assert!(radicled.logs_times(RETURNED, 2, READ_TIMEOUT));
    assert_eq!(radicled.logged(STARTED), 2);

    radicled.shutdown();
    // The node, asked to stop, doesn't: as the stop lets go of it, its drop
    // waits for it once more, past the connection's 5 s exit, and the exit
    // watchdog ends the process (`teardown_unproven`).
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(70));
    let log = radicled.stderr();
    let (listed, calls) = named_waiting(&log);
    assert_eq!(listed, "node", "{log}");
    assert!(calls.contains(&("sessions".to_owned(), true)), "{log}");
    let unseeds = calls.iter().filter(|call| call.0 == "unseed").count();
    assert_eq!(unseeds, 2, "{log}");
    assert!(calls.iter().all(|call| call.1), "{log}");
    assert_eq!(fixture::marked(&dirs.home), Some(vec![NID.to_owned()]));

    // The unseed holds the node within its bound as the stop comes.
    std::fs::remove_file(&armed).unwrap();
    let (mut radicled, armed) = wedgeable(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS", "30000"),
            ("FREEDOM_RADICLED_TEST_SHUTDOWN_WITHIN_MS", "500"),
            ("FREEDOM_RADICLED_TEST_HOLD_WRITE", "0"),
        ],
    );
    wedge(&mut radicled, &armed);
    let held = radicled.request("rad.unseed", unseed);
    assert!(radicled.logs_times(STARTED, 1, READ_TIMEOUT));
    radicled.shutdown();
    let reply = radicled.reply(held);
    assert_eq!(code(&reply), "outcome_unknown", "{reply}");
    assert!(radicled.exit_code(EXIT_TIMEOUT).is_some());
    let log = radicled.stderr();
    let (listed, calls) = named_waiting(&log);
    assert_eq!(listed, "service", "{log}");
    assert_eq!(calls, [("unseed".to_owned(), false)], "{log}");
    assert!(!log.contains(RETURNED), "{log}");
    std::fs::remove_file(&armed).unwrap();
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
