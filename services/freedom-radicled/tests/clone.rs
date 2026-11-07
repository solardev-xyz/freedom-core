//! `rad.clone` and `rad.connect_seeds` through the real binary (design
//! 0008, "Methods", "Progress", "Deadlines" and "Errors"): the progress
//! queue under a fast producer and a paused reader, main's cancel before
//! and past the clone's start, the deadline, which keeps the clone's slot
//! until it returns, how its end is answered and marked, and the
//! refusals.
//!
//! The clones that make progress here are scripted by the test hooks
//! (`FREEDOM_RADICLED_TEST_CLONE`, src/testhooks.rs): past the clone's
//! start they stand in for libradicle's clone, emit as it does and look at
//! its token as it does, and reach no one. tests/network.rs clones from a
//! loopback peer and dials seeds with libradicle's own code; the
//! deterministic shapes are `vectors/radicle-network.json`'s
//! (src/network/tests.rs).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use common::fixture;
use common::*;
use radicle::storage::git::reconcile::quarantine;
use serde_json::{Value, json};

/// A repository ID the home doesn't hold.
const RID: &str = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5";

/// Each character an envelope widens (as in src/network/progress/tests.rs
/// and the browser's pending contract test).
const MIXED: &str = "\u{0}\\\"\u{e9}\u{1f680}x";

const CUT: char = '\u{2026}';

/// The clone hook's value for `script`.
fn script(script: Value) -> (&'static str, String) {
    ("FREEDOM_RADICLED_TEST_CLONE", script.to_string())
}

fn code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or_default()
}

/// A started node in a quiet home, with `extra` in its environment.
fn started(dirs: &Dirs, extra: &[(&str, &str)]) -> Radicled {
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(dirs, extra);
    let started = radicled.start();
    assert!(started["result"].is_object(), "{started}");
    radicled
}

fn clone(radicled: &mut Radicled, timeout_ms: u64, progress: bool) -> u64 {
    radicled.request(
        "rad.clone",
        json!({ "rid": RID, "timeout_ms": timeout_ms, "progress": progress }),
    )
}

/// An event's progress JSON.
fn event(message: &Value) -> Value {
    serde_json::from_str(message["data"]["event"].as_str().unwrap()).unwrap()
}

fn phases(events: &[Value]) -> Vec<String> {
    events
        .iter()
        .map(|m| event(m)["phase"].as_str().unwrap().to_owned())
        .collect()
}

fn stop_keeps_marker(radicled: &mut Radicled, dirs: &Dirs, kept: bool) {
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    if kept {
        assert!(
            log.contains("a clone's that was cut off; the dirty marker stays"),
            "{log}"
        );
        assert!(fixture::marked(&dirs.home).is_some());
    } else {
        assert!(log.contains("the dirty marker is cleared"), "{log}");
        assert_eq!(fixture::marked(&dirs.home), None);
    }
}

/// 0008, "Progress": a producer far faster than the writer, 1,000 failures
/// whose reasons are 13 KB of every widening character, with main not
/// reading while it produces: every envelope is at most 4 KiB, its
/// reasons cut at character boundaries; the failures past 8 unwritten fold
/// into summaries that count every one; what comes out is at most a few
/// hundred KiB of the 13 MB produced; the terminal event comes last,
/// before the answer, and nothing after it.
#[test]
fn progress_under_a_fast_producer_is_bounded_and_ends_before_the_answer() {
    let dirs = Dirs::new();
    let hook = script(json!({ "failures": 1000, "reason": MIXED, "repeat": 600, "then": "ok" }));
    let mut radicled = started(&dirs, &[(hook.0, &hook.1)]);
    radicled.pause();
    let id = clone(&mut radicled, 120_000, true);
    assert!(radicled.logs(
        "test hook: the clone has emitted its failures",
        READ_TIMEOUT
    ));
    std::thread::sleep(Duration::from_millis(200));
    radicled.resume();
    let (events, reply) = radicled.progress(id);
    assert_eq!(reply["result"], json!({ "ok": true }), "{reply}");

    let wire: usize = events
        .iter()
        .map(|m| m["wire"].as_str().unwrap().len())
        .sum();
    for message in &events {
        let envelope = message["wire"].as_str().unwrap();
        assert!(envelope.len() <= 4096, "{}", envelope.len());
    }
    assert!(wire <= 256 << 10, "{wire} bytes of progress came out");
    // The phase events folded into the latest as they came, faster than
    // the writer: the terminal one is never folded, and comes last.
    let phases = phases(&events);
    assert_eq!(phases.last().map(String::as_str), Some("done"));
    assert_eq!(phases.iter().filter(|p| *p == "done").count(), 1);
    let mut counted = 0;
    let mut summaries = 0;
    for message in &events {
        let event = event(message);
        if event["phase"] != "peer-failed" {
            continue;
        }
        let reasons: Vec<String> = match event.get("summary") {
            Some(summary) => {
                summaries += 1;
                counted += summary["count"].as_u64().unwrap();
                let reasons = summary["reasons"].as_array().unwrap();
                assert!((1..=4).contains(&reasons.len()), "{event}");
                reasons
                    .iter()
                    .map(|r| r.as_str().unwrap().to_owned())
                    .collect()
            }
            None => {
                counted += 1;
                vec![event["reason"].as_str().unwrap().to_owned()]
            }
        };
        for reason in reasons {
            assert!(reason.ends_with(CUT), "{reason:?}");
            for part in ["\u{0}", "\\", "\"", "\u{e9}", "\u{1f680}"] {
                assert!(reason.contains(part), "{reason:?}");
            }
        }
    }
    assert_eq!(counted, 1000);
    assert!(summaries >= 1);
    // Progress stops at the answer.
    assert!(!radicled.progress_after(id, Duration::from_millis(300)));
    stop_keeps_marker(&mut radicled, &dirs, false);
}

/// Without `progress`, a clone sends no event.
#[test]
fn a_clone_without_progress_sends_no_event() {
    let dirs = Dirs::new();
    let hook = script(json!({ "failures": 3, "reason": "refused", "then": "ok" }));
    let mut radicled = started(&dirs, &[(hook.0, &hook.1)]);
    let id = radicled.request("rad.clone", json!({ "rid": RID, "timeout_ms": 5000 }));
    let (events, reply) = radicled.progress(id);
    assert_eq!(reply["result"], json!({ "ok": true }), "{reply}");
    assert!(events.is_empty());
    stop_keeps_marker(&mut radicled, &dirs, false);
}

/// 0008, "Methods": main's cancel of a clone past its start flips its
/// token, which libradicle checks between candidates: the clone stops,
/// its `cancelled` terminal event comes, then `{ cancelled }` as its
/// result. Cut off, it leaves the dirty marker.
#[test]
fn main_cancels_a_running_clone_through_its_token() {
    let dirs = Dirs::new();
    let hook = script(json!({ "failures": 3, "reason": "refused", "then": "hold" }));
    let mut radicled = started(&dirs, &[(hook.0, &hook.1)]);
    let id = clone(&mut radicled, 120_000, true);
    assert!(radicled.logs("test hook: the clone holds", READ_TIMEOUT));
    radicled.cancel(id);
    let (events, reply) = radicled.progress(id);
    assert_eq!(reply["result"], json!({ "cancelled": true }), "{reply}");
    // Its three failures, kept as they are, whatever phase events the
    // writer folded; the terminal one last.
    let phases = phases(&events);
    assert_eq!(
        phases.last().map(String::as_str),
        Some("cancelled"),
        "{phases:?}"
    );
    assert_eq!(
        phases.iter().filter(|p| *p == "peer-failed").count(),
        3,
        "{phases:?}"
    );
    stop_keeps_marker(&mut radicled, &dirs, true);
}

/// Before its start, main's cancel is `cancelled` at once, as for any
/// request, and the clone never runs: running in its slot before the
/// start, or queued behind 8 others. Nothing was cut off: a clean stop
/// clears the marker.
#[test]
fn a_clone_cancelled_before_its_start_never_runs() {
    let dirs = Dirs::new();
    let hook = script(json!({ "failures": 1, "reason": "x", "then": "ok" }));
    let hold = ("FREEDOM_RADICLED_TEST_HOLD_WORK", "1");
    let mut radicled = started(&dirs, &[(hook.0, &hook.1), hold]);
    let held: Vec<u64> = (0..8).map(|_| clone(&mut radicled, 60_000, true)).collect();
    assert!(radicled.logs_times("test hook: work holds its slot", 8, READ_TIMEOUT));
    let queued = clone(&mut radicled, 60_000, true);
    radicled.cancel(queued);
    radicled.cancel(held[0]);
    for id in [queued, held[0]] {
        let (events, reply) = radicled.progress(id);
        assert_eq!(code(&reply), "cancelled", "{reply}");
        assert!(events.is_empty());
    }
    // The stop: the others never started either.
    radicled.shutdown();
    for id in &held[1..] {
        assert_eq!(code(&radicled.reply(*id)), "stopped");
    }
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(!log.contains("the clone has emitted"), "{log}");
    assert!(log.contains("the dirty marker is cleared"), "{log}");
    assert_eq!(fixture::marked(&dirs.home), None);
}

/// 0008, "Deadlines": a clone past `timeout_ms` + its slack is `deadline`,
/// and nothing of it follows; it keeps its slot until libradicle returns:
/// with 8 such clones running, 16 more are queued and the next is `busy`.
/// Each returns once released, and the queued ones then run. The clones
/// the deadline cut off leave the dirty marker.
#[test]
fn a_clone_past_its_deadline_is_deadline_and_keeps_its_slot() {
    let dirs = Dirs::new();
    let (release, released) = dirs.held("until", "release");
    let release = release.strip_prefix("until:").unwrap().to_owned();
    let hook = script(json!({ "failures": 1, "reason": "x", "then": "until", "release": release }));
    let slack = ("FREEDOM_RADICLED_TEST_NETWORK_SLACK_MS", "400");
    let mut radicled = started(&dirs, &[(hook.0, &hook.1), slack]);
    let sent = Instant::now();
    let cut: Vec<u64> = (0..8).map(|_| clone(&mut radicled, 0, true)).collect();
    for id in &cut {
        let (events, reply) = radicled.progress(*id);
        assert_eq!(code(&reply), "deadline", "{reply}");
        assert!(phases(&events).iter().all(|p| p != "done"));
    }
    assert!(sent.elapsed() >= Duration::from_millis(400));
    assert!(
        sent.elapsed() < Duration::from_secs(20),
        "{:?}",
        sent.elapsed()
    );
    // Their slots are held: 16 queued, then `busy`.
    let queued: Vec<u64> = (0..16)
        .map(|_| clone(&mut radicled, 60_000, false))
        .collect();
    let busy = radicled.call(
        "rad.clone",
        json!({ "rid": RID, "timeout_ms": 60_000, "progress": false }),
    );
    assert_eq!(code(&busy), "busy", "{busy}");
    assert!(!radicled.logs("test hook: the clone has answered", Duration::ZERO));
    std::fs::write(&released, b"").unwrap();
    for id in queued {
        assert_eq!(radicled.reply(id)["result"], json!({ "ok": true }));
    }
    assert!(radicled.logs_times("test hook: the clone has answered", 24, READ_TIMEOUT));
    for id in &cut {
        assert!(!radicled.progress_after(*id, Duration::ZERO));
    }
    stop_keeps_marker(&mut radicled, &dirs, true);
}

/// A clone libradicle fails: its events, its `failed` terminal event with
/// libradicle's text, then `failed` with the same text. Proven: a clean
/// stop clears the marker.
#[test]
fn a_failed_clone_is_failed_with_libradicles_text() {
    let dirs = Dirs::new();
    let hook = script(json!({ "failures": 1, "reason": "not connected", "then": "fail" }));
    let mut radicled = started(&dirs, &[(hook.0, &hook.1)]);
    let id = clone(&mut radicled, 5000, true);
    let (events, reply) = radicled.progress(id);
    let message = format!("fetching {RID} failed: not connected");
    assert_eq!(code(&reply), "failed", "{reply}");
    assert_eq!(reply["error"]["message"], message);
    let last = event(events.last().unwrap());
    assert_eq!(last, json!({ "reason": message, "phase": "failed" }));
    stop_keeps_marker(&mut radicled, &dirs, false);
}

/// libradicle's own clone with no seed anywhere: no candidate, so only
/// its `failed` terminal event, and `failed` with its text, as the add-on
/// answers today. Nothing is dialled.
#[test]
fn a_clone_with_no_seed_is_libradicles_no_seeds_failure() {
    let dirs = Dirs::new();
    let mut radicled = started(&dirs, &[]);
    let id = clone(&mut radicled, 2000, true);
    let (events, reply) = radicled.progress(id);
    let message = format!("no seeds found for {RID}");
    assert_eq!(code(&reply), "failed", "{reply}");
    assert_eq!(reply["error"]["message"], message);
    assert_eq!(phases(&events), ["failed"]);
    assert_eq!(event(&events[0])["reason"], message);
    stop_keeps_marker(&mut radicled, &dirs, false);
}

/// The refusals before a clone's start: params (`timeout_ms` is the
/// add-on's `u32`; a RID with the add-on's text), and a repository its
/// gate holds quarantined, with the record's kind and step, until it is
/// removed from quarantine. And `rad.connect_seeds`'s params.
#[test]
fn a_clone_is_refused_before_its_start() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let quarantined = fixture::repository(&dirs.home, &[9; 32], "closed");
    fixture::quarantine(&dirs.home, quarantined, quarantine::Kind::Namespace);
    let mut radicled = Radicled::serve(&dirs, &[]);
    assert!(radicled.start()["result"].is_object());
    for params in [
        json!({}),
        json!({ "rid": RID, "timeout_ms": -1 }),
        json!({ "rid": RID, "timeout_ms": 4_294_967_296_u64 }),
        json!({ "rid": RID, "timeout_ms": 1, "progress": "yes" }),
        json!([RID, 1]),
    ] {
        let reply = radicled.call("rad.clone", params.clone());
        assert_eq!(code(&reply), "invalid_argument", "{params}: {reply}");
        assert_eq!(
            reply["error"]["message"],
            "rad.clone takes { rid, timeout_ms, progress }"
        );
    }
    let reply = radicled.call("rad.clone", json!({ "rid": "rad:x", "timeout_ms": 1 }));
    assert_eq!(code(&reply), "invalid_argument", "{reply}");
    let message = reply["error"]["message"].as_str().unwrap();
    assert!(message.starts_with("invalid RID \"rad:x\": "), "{message}");
    // Refused before its start: no progress at all.
    let id = radicled.request(
        "rad.clone",
        json!({ "rid": quarantined.to_string(), "timeout_ms": 1000, "progress": true }),
    );
    let (events, reply) = radicled.progress(id);
    assert_eq!(code(&reply), "quarantined", "{reply}");
    assert_eq!(reply["error"]["data"]["kind"], "namespace");
    assert!(events.is_empty(), "{events:?}");
    // Removed from quarantine, the repository's gate opens: its clone runs,
    // and fails as libradicle's clone does, its creator's node unreachable.
    let listed = radicled.call("rad.quarantine_list", json!({ "page": 0 }));
    let qid = listed["result"]["entries"][0]["qid"].clone();
    let removed = radicled.call(
        "rad.remove_repo",
        json!({ "rid": quarantined.to_string(), "qid": qid }),
    );
    assert_eq!(removed["result"], json!({ "removed": true }), "{removed}");
    let id = radicled.request(
        "rad.clone",
        json!({ "rid": quarantined.to_string(), "timeout_ms": 1000, "progress": true }),
    );
    let (events, reply) = radicled.progress(id);
    assert_eq!(code(&reply), "failed", "{reply}");
    let message = reply["error"]["message"].as_str().unwrap();
    assert!(message.contains(&quarantined.to_string()), "{message}");
    let last = event(events.last().unwrap());
    assert_eq!(last, json!({ "reason": message, "phase": "failed" }));
    for params in [
        json!({}),
        json!({ "timeout_ms": "1" }),
        json!({ "timeout_ms": 1, "rid": RID }),
    ] {
        let reply = radicled.call("rad.connect_seeds", params);
        assert_eq!(code(&reply), "invalid_argument", "{reply}");
    }
    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
}
