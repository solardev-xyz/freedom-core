#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! `rad.stats`'s result against `vectors/radicle-stats.json`: every state
//! the vectors script, written as the design writes it, byte for byte; the
//! constants they hold the service to; and the result's bounds.

use std::time::Duration;

use serde_json::{Value, json};

use super::*;
use crate::pools::{self, Shape};

const VECTORS: &str = include_str!("../../../../vectors/radicle-stats.json");

/// The most bytes the result takes (0008, "Bounds"): one frame, and far
/// less than one.
const MAX_RESULT: usize = 4096;

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn phase(name: &str) -> Phase {
    match name {
        "waiting" => Phase::Waiting,
        "starting" => Phase::Starting,
        "running" => Phase::Running,
        "down" => Phase::Down,
        "stopped" => Phase::Stopped,
        other => panic!("no phase {other}"),
    }
}

fn number(value: &Value) -> usize {
    usize::try_from(value.as_u64().unwrap()).unwrap()
}

fn optional(value: &Value) -> Option<usize> {
    (!value.is_null()).then(|| number(value))
}

fn usage(state: &Value, name: &str, shape: Shape) -> Usage {
    let use_ = &state["pools"][name];
    Usage {
        running: number(&use_["running"]),
        queued: number(&use_["queued"]),
        repairs: number(&use_["repairs"]),
        shape,
    }
}

/// The snapshot a vector's `state` names.
fn snapshot(state: &Value) -> Snapshot {
    Snapshot {
        node: NodeView {
            phase: phase(state["phase"].as_str().unwrap()),
            alive: state["alive"].as_bool(),
            peers: optional(&state["peers"]),
            nat64: (!state["nat64"].is_null()).then(|| state["nat64"].clone()),
        },
        unit: (!state["unit"].is_null()).then(|| Unit {
            kind: state["unit"]["kind"].as_str().unwrap().to_owned(),
            elapsed: Duration::from_micros(state["unit"]["elapsed_us"].as_u64().unwrap()),
            limit: Duration::from_millis(state["unit"]["limit_ms"].as_u64().unwrap()),
        }),
        quarantined: optional(&state["quarantined"]),
        pools: [
            ("read", usage(state, "read", pools::READ)),
            ("network", usage(state, "network", pools::NETWORK)),
            ("write", usage(state, "write", pools::WRITE)),
        ],
        output: (
            state["output"]["used"].as_u64().unwrap(),
            state["output"]["limit"].as_u64().unwrap(),
        ),
        mode: match state["mode"].as_str().unwrap() {
            "direct" => "direct",
            "socks5" => "socks5",
            other => panic!("no mode {other}"),
        },
    }
}

#[test]
fn every_state_is_written_as_the_design_writes_it() {
    let vectors = vectors();
    let mut replayed = 0;
    for list in ["cases", "connections"] {
        for case in vectors[list].as_array().unwrap() {
            let written = serde_json::to_string(&result(&snapshot(&case["state"]))).unwrap();
            assert_eq!(
                written,
                case["result_text"].as_str().unwrap(),
                "{}",
                case["id"]
            );
            assert!(written.len() <= MAX_RESULT, "{}", case["id"]);
            replayed += 1;
        }
    }
    assert_eq!(replayed, 24);
}

#[test]
fn the_vectors_constants_are_the_services() {
    let constants = &vectors()["constants"];
    assert_eq!(constants["output_limit"], crate::output::BUDGET);
    for (name, shape) in [
        ("read", pools::READ),
        ("network", pools::NETWORK),
        ("write", pools::WRITE),
    ] {
        assert_eq!(
            constants["pools"][name],
            json!({ "threads": shape.threads, "queue": shape.queued }),
            "{name}"
        );
    }
    assert_eq!(
        constants["unit_limit_ms"],
        crate::units::UNIT_LIMIT.as_millis() as u64
    );
    assert_eq!(constants["nat64_prefixes"], NAT64_PREFIXES);
    assert_eq!(NAT64_PREFIXES, Nat64State::MAX_PREFIXES);
    assert_eq!(constants["nat64_failures"], NAT64_FAILURES);
    assert_eq!(constants["max_result"], MAX_RESULT);
}

/// The largest result the service can write: every list at its bound,
/// the longest of heartwood's unit kinds, NAT64's longest names, and every
/// number at its most.
#[test]
fn the_largest_result_fits_its_bound() {
    let most = Usage {
        running: usize::MAX,
        queued: usize::MAX,
        repairs: usize::MAX,
        shape: Shape {
            threads: usize::MAX,
            queued: usize::MAX,
        },
    };
    let longest = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128";
    let snapshot = Snapshot {
        node: NodeView {
            phase: Phase::Running,
            alive: Some(true),
            peers: Some(usize::MAX),
            // More than either bound: each is cut.
            nat64: Some(json!({
                "state": "incomplete",
                "prefixes": vec![longest; 100],
                "failures": vec!["over_limit"; 100],
            })),
        },
        unit: Some(Unit {
            kind: "namespace-begin".to_owned(),
            elapsed: Duration::MAX,
            limit: Duration::MAX,
        }),
        quarantined: Some(usize::MAX),
        pools: [("read", most), ("network", most), ("write", most)],
        output: (u64::MAX, u64::MAX),
        mode: "socks5",
    };
    let written = serde_json::to_string(&result(&snapshot)).unwrap();
    assert!(written.len() <= MAX_RESULT, "{}", written.len());
    let value: Value = serde_json::from_str(&written).unwrap();
    assert_eq!(
        value["network"]["nat64"]["prefixes"]
            .as_array()
            .unwrap()
            .len(),
        Nat64State::MAX_PREFIXES
    );
    assert_eq!(
        value["network"]["nat64"]["failures"]
            .as_array()
            .unwrap()
            .len(),
        NAT64_FAILURES
    );
    // A duration past u64's milliseconds is held at their most.
    assert_eq!(value["unit"]["elapsed_ms"], u64::MAX);
}

fn raw(params: &str) -> Box<serde_json::value::RawValue> {
    serde_json::value::RawValue::from_string(params.to_owned()).unwrap()
}

fn request(params: Option<&serde_json::value::RawValue>) -> Request<'_> {
    Request {
        id: 1,
        method: "rad.stats",
        params,
    }
}

#[test]
fn it_takes_no_params() {
    assert!(no_params(&request(None)));
    for params in ["null", "{}", " { } "] {
        let raw = raw(params);
        assert!(no_params(&request(Some(&raw))), "{params}");
    }
    for params in ["[]", "0", "\"\"", "{\"page\":0}", "{\"x\":null}", "false"] {
        let raw = raw(params);
        assert!(!no_params(&request(Some(&raw))), "{params}");
    }
}

#[test]
fn the_record_is_counted_again_where_the_service_changes_it() {
    use radicle::storage::git::reconcile::quarantine::{self, Kind};
    let home = tempfile::tempdir().unwrap();
    let mut record = Quarantine::open(home.path().join(quarantine::QUARANTINE_DB_FILE)).unwrap();
    let counted = Quarantined::default();
    assert_eq!(counted.get(), None);
    counted.recount(&record);
    assert_eq!(counted.get(), Some(0));
    for byte in 1..=3u8 {
        let rid = radicle::prelude::RepoId::from(radicle::git::Oid::from_sha1([byte; 20]));
        record
            .quarantine(rid, Kind::Cache, "cache", None, "", Default::default())
            .unwrap();
    }
    counted.recount(&record);
    assert_eq!(counted.get(), Some(3));
    counted.set(None);
    assert_eq!(counted.get(), None);
}
