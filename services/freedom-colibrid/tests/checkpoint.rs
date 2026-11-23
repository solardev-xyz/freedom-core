//! The checkpoint process's own paths through the binary (design 0014,
//! "Spawn"), with the `testhooks` feature:
//! - a cancel while the proof is being fetched ends the wait at once: the
//!   fetch is dropped, nothing more is asked or called (the commit point
//!   wasn't reached, so the connection answers the cancel), and the
//!   process exits 0;
//! - a cancel during a verifier's creation that fails wins over the
//!   failure, and no free follows (there is nothing to free);
//! - past its resident-memory budget after the decoding, the check fails
//!   before any other call into the C core.

// Test code: a failed setup ends the test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::process::Command;
use std::time::{Duration, Instant};

use common::{BIN, Colibrid, Frame, repo_root};
use serde_json::{Value, json};

const WAIT: Duration = Duration::from_secs(30);

/// COL-1's `checkpoint-mainnet` proof, as the prover served it.
fn mainnet_proof() -> Vec<u8> {
    std::fs::read(repo_root().join(
        "vectors/fixtures/colibri/bodies/d522993401e852dc0b0a73971ca818a5b44a6da8f996b36d1037f7ef00d54431.bin",
    ))
    .unwrap()
}

fn spawned(chain: u64, env: &[(&str, &str)]) -> Colibrid {
    let mut command = Command::new(BIN);
    command.args(["checkpoint", "--chain", &chain.to_string()]);
    command.envs(env.iter().copied());
    let mut colibrid = Colibrid::spawn(command);
    colibrid.hello();
    colibrid
}

fn check(colibrid: &mut Colibrid) -> u64 {
    colibrid.request(
        "colibri.checkpoint",
        json!({ "min_latest_block_ts": 1u64, "deadline_ms": 60_000u64 }),
    )
}

/// The next frame matching `want`, within [`WAIT`]; the markers' calls on
/// the way are added to `calls`.
fn until(colibrid: &mut Colibrid, calls: &mut Vec<String>, want: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + WAIT;
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        if let Some(Frame::Json(m, _)) = colibrid.recv(Duration::from_millis(100)) {
            if m["type"] == "event" && m["event"] == "colibri.step" {
                calls.push(m["data"]["call"].as_str().unwrap_or_default().to_owned());
            }
            if want(&m) {
                return m;
            }
            seen.push(m);
        }
    }
    panic!(
        "nothing came; calls {calls:?}; seen {seen:?}; stderr: {}",
        colibrid.stderr()
    );
}

/// Answers the proof fetch with `proof`.
fn answer_the_proof(colibrid: &mut Colibrid, calls: &mut Vec<String>, proof: Vec<u8>) {
    let ask = until(colibrid, calls, |m| {
        m["type"] == "request" && m["params"]["type"] == "checkpoint_proof"
    });
    let len = proof.len();
    colibrid.answer_body(ask["id"].as_u64().unwrap(), 0, proof, len);
}

#[test]
fn a_cancel_during_the_proof_fetch_ends_the_check() {
    let mut colibrid = spawned(1, &[]);
    let id = check(&mut colibrid);
    let mut calls = Vec::new();
    let ask = until(&mut colibrid, &mut calls, |m| {
        m["type"] == "request" && m["params"]["type"] == "checkpoint_proof"
    });
    let ask = ask["id"].as_u64().unwrap();
    let cancelled = Instant::now();
    colibrid.cancel(id);
    // The wait ends at once: the fetch is dropped with the check (its ask
    // is cancelled with main, or ends with the process), and the one-shot
    // process exits. Before the commit point the connection answers the
    // cancel itself.
    let mut seen = Vec::new();
    while !colibrid.exited() && cancelled.elapsed() < WAIT {
        if let Some(Frame::Json(m, _)) = colibrid.recv(Duration::from_millis(100)) {
            seen.push(m);
        }
    }
    while let Some(Frame::Json(m, _)) = colibrid.recv(Duration::from_millis(100)) {
        seen.push(m);
    }
    assert!(
        cancelled.elapsed() < Duration::from_secs(10),
        "the check kept waiting for its proof"
    );
    let replies: Vec<&Value> = seen
        .iter()
        .filter(|m| m["type"] == "response" && m["id"] == id)
        .collect();
    assert_eq!(replies.len(), 1, "{seen:?}");
    assert_eq!(replies[0]["error"]["code"], "cancelled", "{seen:?}");
    assert!(
        seen.iter()
            .all(|m| m["type"] != "request" && m["type"] != "event"),
        "{seen:?}"
    );
    assert!(calls.is_empty(), "{calls:?}");
    // A cancel the service sent can only be the proof's.
    assert!(
        seen.iter()
            .filter(|m| m["type"] == "cancel")
            .all(|m| m["id"] == ask),
        "{seen:?}"
    );
    assert_eq!(colibrid.exit_code(WAIT), Some(0));
}

#[test]
fn a_cancel_during_a_failing_creation_wins() {
    // Chain 10 (OP Mainnet) is an OP-Stack chain, which this verifier-only
    // build has no request type for: the proof decodes, and the verifier's
    // creation then fails ("chain not supported"), slowly.
    let mut colibrid = spawned(10, &[("FREEDOM_COLIBRID_TEST_CREATE", "sleep:1500")]);
    let id = check(&mut colibrid);
    let mut calls = Vec::new();
    answer_the_proof(&mut colibrid, &mut calls, mainnet_proof());
    until(&mut colibrid, &mut calls, |m| {
        m["type"] == "event" && m["event"] == "colibri.step" && m["data"]["call"] == "create"
    });
    colibrid.cancel(id);
    let reply = until(&mut colibrid, &mut calls, |m| {
        m["type"] == "response" && m["id"] == id
    });
    assert_eq!(reply["error"]["code"], "cancelled", "{reply}");
    // The decoding and the creation; nothing created, so nothing freed.
    assert_eq!(calls, ["decode", "create"]);
    assert_eq!(colibrid.exit_code(WAIT), Some(0));
}

#[test]
fn past_its_memory_budget_after_the_decoding_the_check_fails() {
    // A budget the process is over at its first reading.
    let mut colibrid = spawned(1, &[("FREEDOM_COLIBRID_TEST_MEMORY_BUDGET", "1")]);
    let id = check(&mut colibrid);
    let mut calls = Vec::new();
    answer_the_proof(&mut colibrid, &mut calls, mainnet_proof());
    let reply = until(&mut colibrid, &mut calls, |m| {
        m["type"] == "response" && m["id"] == id
    });
    let result = &reply["result"];
    assert_eq!(result["status"], "error", "{reply}");
    assert_eq!(result["stage"], "decode", "{reply}");
    assert_eq!(
        result["error"], "resident memory past the checkpoint process's budget",
        "{reply}"
    );
    // No call after the decoding.
    assert_eq!(calls, ["decode"]);
    assert_eq!(colibrid.exit_code(WAIT), Some(0));
}
