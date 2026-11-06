//! The pools and the write queue through the real binary (design 0008,
//! "Pools and budgets", "Deadlines" and "Start, stop and reconciliation"):
//! they open as `rad.start` answers, refuse past their bounds, enforce
//! their deadlines and main's cancel, and drain at the stop before the node
//! is asked to stop. This build serves quarantine's pooled methods
//! (tests/quarantine.rs), the writes (tests/writes.rs) and `rad.read`'s
//! pass-through ops (tests/reads.rs): `rad.blob`'s work answers `stopped`.
//! `FREEDOM_RADICLED_TEST_HOLD_WORK` holds each in its slot first, the
//! writes before their mutation starts, and the reads before their build.
//!
//! Every node here reaches no one, as in tests/start.rs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use common::fixture;
use common::*;
use serde_json::{Value, json};

const HOLD: (&str, &str) = ("FREEDOM_RADICLED_TEST_HOLD_WORK", "1");

/// A repository ID the home doesn't hold: an unseed of it is held in its
/// slot as any write is, before its start.
const RID: &str = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5";

/// The pooled methods, as 0008's table places them.
const POOLED: [&str; 6] = [
    "rad.quarantine_list",
    "rad.read",
    "rad.blob",
    "rad.remove_repo",
    "rad.unseed",
    "rad.write",
];

/// The pooled methods this build serves: quarantine's (tests/quarantine.rs),
/// the writes (tests/writes.rs) and `rad.read` (tests/reads.rs).
const SERVED: [&str; 5] = [
    "rad.quarantine_list",
    "rad.read",
    "rad.remove_repo",
    "rad.unseed",
    "rad.write",
];

/// A read held in its slot: `status`, which reads no repository.
fn status() -> Value {
    json!({ "op": "status" })
}

fn code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or_default()
}

#[test]
fn pooled_methods_are_admitted_once_the_node_runs_and_the_stop_is_clean() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(&dirs, &[]);
    let hello = radicled.hello();
    let identity = radicled.call("rad.identity", sealed_to(&hello, &SEED));
    assert!(identity["result"].is_object(), "{identity}");
    let reconciled = radicled.call("rad.reconcile", json!({}));
    assert!(reconciled["result"].is_object(), "{reconciled}");
    // Before `RUNNING`: the pools are closed.
    for method in POOLED {
        let reply = radicled.call(method, json!({}));
        assert_eq!(code(&reply), "stopped", "{method}: {reply}");
        assert_eq!(
            reply["error"]["message"], "the Radicle node is not running",
            "{method}: {reply}"
        );
    }
    let started = radicled.call("rad.start", json!({ "alias": "pools" }));
    assert!(started["result"].is_object(), "{started}");
    // Admitted, and run: each one's work answers. The served methods check
    // their params.
    for method in POOLED {
        let reply = radicled.call(method, json!({}));
        if SERVED.contains(&method) {
            assert_eq!(code(&reply), "invalid_argument", "{method}: {reply}");
            continue;
        }
        assert_eq!(code(&reply), "stopped", "{method}: {reply}");
        assert_eq!(
            reply["error"]["message"], "not served in this build",
            "{method}: {reply}"
        );
    }

    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(log.contains("the dirty marker is cleared"), "{log}");
    assert!(!log.contains("past the pools' drain"), "{log}");
    assert_eq!(fixture::marked(&dirs.home), None);
}

/// 4 threads and 320 queued on the read pool, one writer and 16 queued on
/// the write queue; then `busy`. Main's cancel frees a queued place. The
/// stop answers every request it finds `stopped`, queued or running, and,
/// with every thread ended, is clean.
#[test]
fn the_pools_refuse_past_their_bounds_and_drain_at_a_clean_stop() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(&dirs, &[HOLD]);
    assert!(radicled.start()["result"].is_object());

    let mut held: Vec<u64> = (0..4 + 320)
        .map(|_| radicled.request("rad.read", status()))
        .collect();
    let reply = radicled.call("rad.read", json!({}));
    assert_eq!(code(&reply), "busy", "{reply}");
    assert_eq!(
        reply["error"]["message"], "the read queue is full",
        "{reply}"
    );
    held.extend((0..1 + 16).map(|_| radicled.request("rad.unseed", json!({ "rid": RID }))));
    let reply = radicled.call("rad.unseed", json!({}));
    assert_eq!(code(&reply), "busy", "{reply}");
    assert_eq!(
        reply["error"]["message"], "the write queue is full",
        "{reply}"
    );
    // One read pool thread at least holds its slot.
    assert!(radicled.logs("test hook: work holds its slot", Duration::from_secs(10)));

    // The newest read is queued: cancelled, it gives its place back.
    let cancelled = held.remove(4 + 320 - 1);
    radicled.send(&json!({ "type": "cancel", "id": cancelled }));
    assert_eq!(code(&radicled.reply(cancelled)), "cancelled");
    held.push(radicled.request("rad.read", status()));
    let reply = radicled.call("rad.blob", json!({}));
    assert_eq!(code(&reply), "busy", "{reply}");

    radicled.shutdown();
    for id in held {
        let reply = radicled.reply(id);
        assert_eq!(code(&reply), "stopped", "{reply}");
    }
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(log.contains("the dirty marker is cleared"), "{log}");
    assert_eq!(fixture::marked(&dirs.home), None);
}

/// The deadline runs from admission: requests queued and running past it are
/// answered `deadline`, and the running ones' work, cancelled, lets go of
/// its slot, so the stop's drain is complete.
#[test]
fn queued_and_running_work_past_its_deadline_is_deadline() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(
        &dirs,
        &[HOLD, ("FREEDOM_RADICLED_TEST_WORK_DEADLINE_MS", "1500")],
    );
    assert!(radicled.start()["result"].is_object());
    let admitted = Instant::now();
    // Four running and one queued; one writing and one queued.
    let mut ids: Vec<u64> = (0..5)
        .map(|_| radicled.request("rad.read", status()))
        .collect();
    ids.extend((0..2).map(|_| radicled.request("rad.unseed", json!({ "rid": RID }))));
    for id in ids {
        let reply = radicled.reply(id);
        assert_eq!(code(&reply), "deadline", "{reply}");
    }
    assert!(admitted.elapsed() >= Duration::from_millis(1500));

    radicled.shutdown();
    assert_eq!(radicled.exit_code(EXIT_TIMEOUT), Some(0));
    let log = radicled.stderr();
    assert!(log.contains("the dirty marker is cleared"), "{log}");
    assert_eq!(fixture::marked(&dirs.home), None);
}

/// Work that doesn't heed its token holds its thread past the drain's
/// deadline: its request is answered `stopped` all the same, within the
/// connection's 5 s exit, and the marker stays, since nothing proves that
/// work no longer runs.
#[test]
fn work_still_running_past_the_drain_keeps_the_marker() {
    let dirs = Dirs::new();
    configure(&dirs.home, json!({}));
    let mut radicled = Radicled::serve(
        &dirs,
        &[
            ("FREEDOM_RADICLED_TEST_HOLD_WORK", "deaf"),
            ("FREEDOM_RADICLED_TEST_SHUTDOWN_WITHIN_MS", "1000"),
        ],
    );
    assert!(radicled.start()["result"].is_object());
    let write = radicled.request("rad.unseed", json!({ "rid": RID }));
    assert!(radicled.logs("test hook: work holds its slot", Duration::from_secs(10)));
    let asked = Instant::now();
    radicled.shutdown();
    let reply = radicled.reply(write);
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
}
