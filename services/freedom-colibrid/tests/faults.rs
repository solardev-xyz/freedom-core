//! Faults through the binary (design 0014, COL-4's test hooks): a crash in
//! a step leaves that request's marker open as the process dies, so main
//! names it (the calls before it, each with its own marker, are cleared); a spin leaves it open while the process lives, for main's kill
//! to name; a recycle refuses new requests, finishes the open ones and
//! exits 0, no fault.

// Test code: a failed setup ends the test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::process::Command;
use std::time::{Duration, Instant};

use common::{BIN, Colibrid, Frame};
use serde_json::{Value, json};

fn spawned(env: &[(&str, &str)]) -> Colibrid {
    let mut command = Command::new(BIN);
    command.args(["serve", "--chain", "1"]);
    for (key, value) in env {
        command.env(key, value);
    }
    let mut colibrid = Colibrid::spawn(command);
    colibrid.hello();
    colibrid
}

fn block_number(colibrid: &mut Colibrid) -> u64 {
    colibrid.request(
        "colibri.request",
        json!({
            "client": "c",
            "zk": true,
            "method": "eth_blockNumber",
            "params": "[]",
            "min_latest_block_ts": 1u64,
            "deadline_ms": 60_000u64,
        }),
    )
}

/// The markers for `id` within `wait`, each with the call it names
/// (`colibri.step:execute`, `colibri.stepped`), and whether the process
/// ended.
fn markers(colibrid: &mut Colibrid, id: u64, wait: Duration) -> (Vec<String>, bool) {
    let mut seen = Vec::new();
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        if colibrid.exited() {
            // What it wrote before it died is still in the pipe.
            while let Some(frame) = colibrid.recv(Duration::from_millis(100)) {
                if let Frame::Json(m, _) = frame
                    && m["type"] == "event"
                    && m["data"]["request"] == id
                {
                    seen.push(marker(&m));
                }
            }
            return (seen, true);
        }
        if let Some(Frame::Json(m, _)) = colibrid.recv(Duration::from_millis(100))
            && m["type"] == "event"
            && m["data"]["request"] == id
        {
            seen.push(marker(&m));
        }
    }
    (seen, false)
}

fn marker(m: &Value) -> String {
    match m["data"]["call"].as_str() {
        Some(call) => format!("{}:{call}", m["event"].as_str().unwrap()),
        None => m["event"].as_str().unwrap().to_owned(),
    }
}

/// The calls before the first step, each cleared, then the step's marker
/// left open.
const STEP_LEFT_OPEN: [&str; 7] = [
    "colibri.step:classify",
    "colibri.stepped",
    "colibri.step:create",
    "colibri.stepped",
    "colibri.step:freshness",
    "colibri.stepped",
    "colibri.step:execute",
];

#[test]
fn a_crash_in_a_step_dies_with_its_marker_open() {
    let mut colibrid = spawned(&[("FREEDOM_COLIBRID_TEST_STEP", "crash")]);
    let id = block_number(&mut colibrid);
    let (seen, ended) = markers(&mut colibrid, id, Duration::from_secs(20));
    assert!(ended, "the process didn't die");
    assert_eq!(seen, STEP_LEFT_OPEN, "the step is left open");
}

#[test]
fn a_spin_in_a_step_keeps_its_marker_open() {
    let mut colibrid = spawned(&[("FREEDOM_COLIBRID_TEST_STEP", "spin")]);
    let id = block_number(&mut colibrid);
    let (seen, ended) = markers(&mut colibrid, id, Duration::from_secs(3));
    assert!(!ended, "the process died");
    assert_eq!(seen, STEP_LEFT_OPEN, "the step is left open");
}

#[test]
fn a_recycle_finishes_its_requests_and_exits_0() {
    // A budget every process is over after its first step.
    let mut colibrid = spawned(&[("FREEDOM_COLIBRID_TEST_MEMORY_BUDGET", "1")]);
    let first = block_number(&mut colibrid);
    let mut asked = None;
    let deadline = Instant::now() + Duration::from_secs(30);
    while asked.is_none() && Instant::now() < deadline {
        if let Some(Frame::Json(m, _)) = colibrid.recv(Duration::from_millis(200))
            && m["method"] == "shell.colibri_fetch"
        {
            asked = m["id"].as_u64();
        }
    }
    let ask = asked.expect("no fetch");
    if cfg!(target_os = "linux") {
        // Read only on Linux so far: the budget applies there.
        let second = block_number(&mut colibrid);
        let mut refused: Option<Value> = None;
        let deadline = Instant::now() + Duration::from_secs(30);
        while refused.is_none() && Instant::now() < deadline {
            if let Some(Frame::Json(m, _)) = colibrid.recv(Duration::from_millis(200))
                && m["type"] == "response"
                && m["id"] == second
            {
                refused = Some(m);
            }
        }
        assert_eq!(refused.unwrap()["error"]["code"], "busy");
    }
    colibrid.respond(ask, json!({ "error": "HTTP error! Status: 500" }));
    let mut replied = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    while !replied && Instant::now() < deadline {
        if let Some(Frame::Json(m, _)) = colibrid.recv(Duration::from_millis(200)) {
            if m["method"] == "shell.colibri_fetch" {
                let ask = m["id"].as_u64().unwrap();
                colibrid.respond(ask, json!({ "error": "HTTP error! Status: 500" }));
            }
            replied = m["type"] == "response" && m["id"] == first;
        }
    }
    assert!(replied, "the open request wasn't finished");
    if cfg!(target_os = "linux") {
        assert_eq!(colibrid.exit_code(Duration::from_secs(20)), Some(0));
    }
}
