#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The network operations against `vectors/radicle-network.json`: what
//! main's own code reads at the reference, and the design's queue and
//! answers, replayed through the service's code.

use radicle::node::gate::{Quarantine, RepoState};
use serde_json::{Value, json};

use super::progress::{self, Queue};
use super::*;

const VECTORS: &str = include_str!("../../../../vectors/radicle-network.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn raw(value: &Value) -> Box<RawValue> {
    serde_json::value::to_raw_value(value).unwrap()
}

fn s(value: &Value) -> String {
    value.as_str().unwrap().to_owned()
}

fn n(value: &Value) -> usize {
    usize::try_from(value.as_u64().unwrap()).unwrap()
}

/// A reason as a case writes it: a string, or `{ "$repeat": [unit, n] }`.
fn spelled(reason: &Value) -> String {
    match reason {
        Value::String(text) => text.clone(),
        other => s(&other["$repeat"][0]).repeat(n(&other["$repeat"][1])),
    }
}

/// libradicle's `Progress` a case names.
fn progress_of(p: &Value) -> Progress {
    let nid = || s(&p["nid"]);
    match p["phase"].as_str().unwrap() {
        "resolving" => Progress::Resolving {
            candidates: n(&p["candidates"]),
        },
        "connecting" => Progress::Connecting {
            nid: nid(),
            addr: s(&p["addr"]),
            index: n(&p["index"]),
            total: n(&p["total"]),
        },
        "fetching" => Progress::Fetching {
            nid: nid(),
            index: n(&p["index"]),
            total: n(&p["total"]),
        },
        "peer-failed" => Progress::PeerFailed {
            nid: nid(),
            index: n(&p["index"]),
            total: n(&p["total"]),
            reason: spelled(&p["reason"]),
        },
        "failed" => Progress::Failed {
            reason: spelled(&p["reason"]),
        },
        "done" => Progress::Done,
        "cancelled" => Progress::Cancelled,
        other => panic!("no phase {other}"),
    }
}

/// libradicle's `Error` a case names.
fn error_of(e: &Value) -> libradicle::Error {
    let rid = || RepoId::from_str(e["rid"].as_str().unwrap()).unwrap();
    match e["variant"].as_str().unwrap() {
        "NoSeeds" => libradicle::Error::NoSeeds(rid()),
        "FetchFailed" => libradicle::Error::FetchFailed(rid(), s(&e["reason"])),
        "Timeout" => libradicle::Error::Timeout(rid()),
        "Cancelled" => libradicle::Error::Cancelled,
        "NodeThread" => libradicle::Error::NodeThread(s(&e["message"])),
        "Gated" => libradicle::Error::Gated {
            rid: rid(),
            state: match e["state"].as_str().unwrap() {
                "namespace" => RepoState::Quarantined(Quarantine::Namespace),
                "cache" => RepoState::Quarantined(Quarantine::Cache),
                "repairing" => RepoState::Repairing,
                other => panic!("no state {other}"),
            },
        },
        other => panic!("no variant {other}"),
    }
}

/// The add-on's `{"error": …}` text, as main reads it.
fn addon_error(e: &libradicle::Error) -> String {
    libradicle::json::to_string(|w| libradicle::json::error(w, e))
}

/// The service's answer as a case writes it.
fn written(error: &ErrorBody) -> Value {
    let mut out = json!({ "code": error.code, "message": error.message });
    if let Some(data) = &error.data {
        out["data"] = data.clone();
    }
    out
}

/// 0008, "Methods": `rad.connect_seeds` answers libradicle's report, byte
/// for byte as the add-on's `connectSeeds` returns it to main; a failure,
/// libradicle's text.
#[test]
fn the_seeds_report_is_the_text_main_reads() {
    let vectors = vectors();
    let reports = vectors["reports"].as_array().unwrap();
    assert!(reports.len() >= 6);
    for case in reports {
        let id = case["id"].as_str().unwrap();
        if let Some(error) = case.get("libradicle") {
            let e = error_of(error);
            assert_eq!(addon_error(&e), s(&case["text"]), "{id}");
            let answer = reads::radicle_error(e);
            assert_eq!(written(&answer), case["expect"]["error"], "{id}");
            continue;
        }
        let r = &case["report"];
        let report = libradicle::SeedConnectReport {
            attempted: n(&r["attempted"]),
            connected: n(&r["connected"]),
            target: n(&r["target"]),
            target_reached: r["targetReached"].as_bool().unwrap(),
            elapsed: Duration::from_millis(r["elapsedMs"].as_u64().unwrap()),
            failures: r["failures"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| libradicle::SeedConnectFailure {
                    nid: s(&f["nid"]),
                    addr: s(&f["addr"]),
                    reason: s(&f["reason"]),
                })
                .collect(),
        };
        let answered = super::report(&report).unwrap();
        assert_eq!(answered.get(), s(&case["text"]), "{id}");
        assert_eq!(answered.get(), s(&case["expect"]["result_text"]), "{id}");
    }
}

/// Each progress event is libradicle's text, as the add-on hands it to
/// main's callback: the `event` of its `rad.progress`.
#[test]
fn each_progress_event_is_the_text_main_reads() {
    let vectors = vectors();
    let mut seen = std::collections::HashSet::new();
    for case in vectors["progress"].as_array().unwrap() {
        for event in case["events"].as_array().unwrap() {
            let p = progress_of(&event["progress"]);
            seen.insert(p.phase());
            assert_eq!(progress::text(&p), s(&event["text"]), "{}", case["id"]);
            // One at a time, the queue writes it as it is.
            let mut queue = Queue::new(1);
            queue.push(p);
            let (_, written) = queue.front().unwrap();
            assert_eq!(written, s(&event["text"]));
        }
    }
    assert_eq!(seen.len(), 7, "{seen:?}");
}

/// 0008, "Progress": every queue case of the design's, replayed through
/// the service's queue: the same envelopes, byte for byte, in order.
#[test]
fn the_queue_writes_what_the_design_says() {
    let vectors = vectors();
    let cases = vectors["queue"].as_array().unwrap();
    assert!(cases.len() >= 20);
    for case in cases {
        let id = case["request_id"].as_u64().unwrap();
        let mut queue = Queue::new(id);
        let mut out: Vec<String> = Vec::new();
        let mut take = |queue: &mut Queue| -> bool {
            let Some((slot, event)) = queue.front() else {
                return false;
            };
            let mut envelope = Vec::new();
            fc_protocol::message::write_event(
                &mut envelope,
                progress::EVENT,
                &json!({ "id": id, "event": event }),
            )
            .unwrap();
            assert_eq!(envelope.len(), progress::envelope_len(id, event));
            out.push(String::from_utf8(envelope).unwrap());
            queue.pop(slot);
            true
        };
        for step in case["steps"].as_array().unwrap() {
            if let Some(emit) = step.get("emit") {
                queue.push(progress_of(emit));
            } else {
                for _ in 0..step["take"].as_u64().unwrap() {
                    take(&mut queue);
                }
            }
        }
        while take(&mut queue) {}
        let expected: Vec<String> = case["written"].as_array().unwrap().iter().map(s).collect();
        assert_eq!(out, expected, "{}", case["id"]);
        assert!(out.iter().all(|e| e.len() <= progress::MAX_ENVELOPE));
    }
}

/// 0008, "Methods" and "Errors": how a clone libradicle ended is answered,
/// and whether its outcome is proven; the add-on's texts are libradicle's.
#[test]
fn a_clones_end_is_answered_as_the_design_says() {
    let vectors = vectors();
    let home = tempfile::tempdir().unwrap();
    for case in vectors["results"].as_array().unwrap() {
        let name = case["id"].as_str().unwrap();
        let expect = &case["expect"];
        let main = case["main_cancelled"].as_bool().unwrap_or(false);
        let result = match case.get("libradicle") {
            None => {
                assert_eq!(case["result_text"], "{\"ok\":true}");
                Ok(())
            }
            Some(e) => {
                let e = error_of(e);
                if !matches!(e, libradicle::Error::Cancelled) {
                    assert_eq!(addon_error(&e), s(&case["text"]), "{name}");
                }
                Err(e)
            }
        };
        let (outcome, proven) = outcome(home.path(), result, main);
        assert_eq!(proven, expect["proven"].as_bool().unwrap(), "{name}");
        match outcome {
            Outcome::Result(value) => {
                assert_eq!(value, expect["result"], "{name}");
                // The bytes the add-on returned.
                let text = serde_json::to_string(&value).unwrap();
                assert_eq!(
                    text,
                    s(case.get("result_text").unwrap_or(&case["text"])),
                    "{name}"
                );
            }
            Outcome::Error(error) => assert_eq!(written(&error), expect["error"], "{name}"),
            Outcome::Nothing => assert_eq!(expect["nothing"], true, "{name}"),
        }
    }
}

/// `timeout_ms` is the add-on's `u32`: anything else is
/// `invalid_argument`; `progress` is a boolean, absent or null `false`.
#[test]
fn the_params_are_the_add_ons() {
    let rid = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5";
    let ok = |value: Value| clone_params(Some(&raw(&value)));
    let checked = ok(json!({ "rid": rid, "timeout_ms": 120_000, "progress": true })).unwrap();
    assert_eq!(checked.timeout, Duration::from_secs(120));
    assert!(checked.progress);
    assert!(!ok(json!({ "rid": rid, "timeout_ms": 0 })).unwrap().progress);
    assert!(
        !ok(json!({ "rid": rid, "timeout_ms": 0, "progress": null }))
            .unwrap()
            .progress
    );
    assert_eq!(
        ok(json!({ "rid": rid, "timeout_ms": u32::MAX }))
            .unwrap()
            .timeout,
        Duration::from_millis(u64::from(u32::MAX))
    );
    for bad in [
        json!({}),
        json!({ "rid": rid }),
        json!({ "rid": rid, "timeout_ms": -1 }),
        json!({ "rid": rid, "timeout_ms": 1.5 }),
        json!({ "rid": rid, "timeout_ms": u64::from(u32::MAX) + 1 }),
        json!({ "rid": rid, "timeout_ms": "1" }),
        json!({ "rid": rid, "timeout_ms": 1, "progress": 1 }),
        json!({ "rid": rid, "timeout_ms": 1, "other": 1 }),
        json!([rid, 1]),
    ] {
        let refused = ok(bad.clone()).unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidArgument, "{bad}");
        assert_eq!(
            refused.message,
            "rad.clone takes { rid, timeout_ms, progress }"
        );
    }
    assert!(clone_params(None).is_err());
    // A RID that doesn't parse: the add-on's own text.
    let refused = ok(json!({ "rid": "rad:nope", "timeout_ms": 1 })).unwrap_err();
    assert_eq!(refused.code, ErrorCode::InvalidArgument);
    let parse = RepoId::from_str("rad:nope").unwrap_err();
    assert_eq!(
        refused.message,
        format!("invalid RID \"rad:nope\": {parse}")
    );

    let connect = |value: Value| connect_params(Some(&raw(&value)));
    assert_eq!(
        connect(json!({ "timeout_ms": 15_000 })).unwrap(),
        Duration::from_secs(15)
    );
    for bad in [
        json!({}),
        json!({ "timeout_ms": -5 }),
        json!({ "timeout_ms": 1, "x": 0 }),
        json!([1]),
    ] {
        let refused = connect(bad).unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidArgument);
        assert_eq!(refused.message, "rad.connect_seeds takes { timeout_ms }");
    }
}

/// 0008, "Deadlines": `timeout_ms` + 30 s from admission; params that
/// don't parse get the 30 s alone.
#[test]
fn a_network_deadline_is_its_timeout_and_30_seconds() {
    assert_eq!(SLACK, Duration::from_secs(30));
    assert_eq!(
        within(Some(Duration::from_secs(15))),
        Duration::from_secs(45)
    );
    assert_eq!(within(None), Duration::from_secs(30));
    assert_eq!(
        within(Some(Duration::from_millis(u64::from(u32::MAX)))),
        Duration::from_millis(u64::from(u32::MAX)) + SLACK
    );
}
