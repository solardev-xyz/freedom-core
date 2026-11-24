//! freedom-colibrid against a scripted main (design 0014, COL-4): the
//! handshake, what it refuses before any context, its budgets, cancels,
//! a body that breaks its head, and its gate. The vectors through the
//! binary are in `tests/service_vectors.rs`.

// Test code: a failed setup ends the test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::time::{Duration, Instant};

use common::{Colibrid, Dirs, Frame};
use serde_json::{Value, json};

const WAIT: Duration = Duration::from_secs(60);

fn request_params(method: &str, params: &str) -> Value {
    json!({
        "client": "c1",
        "zk": true,
        "method": method,
        "params": params,
        "min_latest_block_ts": 1_795_387_164u64,
        "deadline_ms": 60_000u64,
    })
}

/// Reads frames until request `id`'s reply, answering every fetch with
/// `answer`. Returns the reply and the markers seen.
fn until_reply(
    colibrid: &mut Colibrid,
    id: u64,
    mut answer: impl FnMut(&mut Colibrid, u64, &Value),
) -> (Value, Vec<String>) {
    let mut markers = Vec::new();
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        let Some(frame) = colibrid.recv(Duration::from_secs(1)) else {
            continue;
        };
        let Frame::Json(message, _) = frame else {
            continue;
        };
        match message["type"].as_str() {
            Some("event") => markers.push(format!(
                "{}:{}",
                message["event"].as_str().unwrap_or_default(),
                message["data"]["request"]
            )),
            Some("request") if message["method"] == "shell.colibri_fetch" => {
                let ask = message["id"].as_u64().unwrap();
                assert_eq!(message["params"]["request"], id);
                answer(colibrid, ask, &message["params"]);
            }
            Some("response") if message["id"] == id => return (message, markers),
            _ => {}
        }
    }
    panic!("no reply to {id}; stderr: {}", colibrid.stderr());
}

#[test]
fn hello_reports_the_build_and_a_private_process_writes_nothing() {
    let dirs = Dirs::new("hello");
    let mut colibrid = Colibrid::serve(1, None);
    let hello = colibrid.hello();
    assert_eq!(hello["protocol"], 1);
    assert_eq!(hello["service_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(hello["colibri_version"], "3.0.3");
    assert_eq!(hello["client_version"], 196_611);
    assert_eq!(hello["chain_id"], 1);
    assert_eq!(hello["network"], "offline");
    assert_eq!(hello["build"]["prover"], false);
    assert!(hello["confinement"].is_object(), "{hello}");
    let id = colibrid.request("colibri.stats", json!({}));
    let (reply, markers) = until_reply(&mut colibrid, id, |_, _, _| {});
    assert_eq!(reply["result"]["open_requests"], 0);
    assert_eq!(reply["result"]["store_keys"], 0);
    assert!(markers.is_empty());
    assert_eq!(colibrid.shutdown(), Some(0));
    // A private process names no directory: nothing in the temp dirs.
    assert_eq!(std::fs::read_dir(dirs.data()).unwrap().count(), 0);
}

#[test]
fn refusals_come_before_any_context() {
    let mut colibrid = Colibrid::serve(1, None);
    colibrid.hello();
    for (method, params, text) in [
        (
            "eth_call",
            r#"[{"to":"0x01"},"latest"]"#,
            "Method eth_call is not supported",
        ),
        ("eth_gasPrice", "[]", "Method eth_gasPrice is not supported"),
        (
            "eth_getBalance",
            r#"["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","safe"]"#,
            r#"Colibri cannot prove eth_getBalance at block "safe""#,
        ),
        (
            "eth_getBalance",
            r#"["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"]"#,
            "Colibri cannot prove eth_getBalance with params of length 1",
        ),
        (
            "eth_getBlockByNumber",
            r#"["pending",false]"#,
            r#"Colibri cannot prove eth_getBlockByNumber at block "pending""#,
        ),
    ] {
        let id = colibrid.request("colibri.request", request_params(method, params));
        let (reply, markers) = until_reply(&mut colibrid, id, |_, _, _| {
            panic!("a refused request fetched")
        });
        assert_eq!(
            reply["result"],
            json!({ "status": "error", "error": text }),
            "{method}"
        );
        // No context, so no marker.
        assert!(markers.is_empty(), "{method}: {markers:?}");
    }
    let id = colibrid.request("colibri.nope", json!({}));
    let (reply, _) = until_reply(&mut colibrid, id, |_, _, _| {});
    assert_eq!(reply["error"]["code"], "unknown_method");
    let id = colibrid.request("colibri.request", json!({ "client": "c1" }));
    let (reply, _) = until_reply(&mut colibrid, id, |_, _, _| {});
    assert_eq!(reply["error"]["code"], "invalid_argument");
    let id = colibrid.request("colibri.checkpoint", json!({}));
    let (reply, _) = until_reply(&mut colibrid, id, |_, _, _| {});
    assert_eq!(reply["error"]["code"], "invalid_argument");
    let id = colibrid.request("colibri.forget", json!({ "client": "c1" }));
    let (reply, _) = until_reply(&mut colibrid, id, |_, _, _| {});
    assert_eq!(reply["result"], json!({}));
    assert_eq!(colibrid.shutdown(), Some(0));
}

#[test]
fn a_body_that_breaks_its_head_fails_its_fetch_alone() {
    for longer in [true, false] {
        let mut colibrid = Colibrid::serve(1, None);
        colibrid.hello();
        let id = colibrid.request(
            "colibri.request",
            request_params(
                "eth_getBalance",
                r#"["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","latest"]"#,
            ),
        );
        let mut first = true;
        let (reply, markers) = until_reply(&mut colibrid, id, |c, ask, _| {
            if std::mem::take(&mut first) {
                let body = vec![7u8; 1000];
                c.answer_body(ask, 0, body, if longer { 1001 } else { 999 });
            } else {
                c.respond(ask, json!({ "error": "HTTP error! Status: 500" }));
            }
        });
        let error = reply["result"]["error"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert_eq!(reply["result"]["status"], "error", "{reply}");
        assert!(error.contains("Colibri body length mismatch"), "{error}");
        // Every marker is cleared, in order.
        for pair in markers.chunks(2) {
            assert_eq!(
                pair,
                [
                    format!("colibri.step:{id}"),
                    format!("colibri.stepped:{id}")
                ]
            );
        }
        assert_eq!(colibrid.shutdown(), Some(0));
    }
}

#[test]
fn open_requests_are_bounded_and_cancels_are_answered() {
    let mut colibrid = Colibrid::serve(1, None);
    colibrid.hello();
    let params = request_params(
        "eth_getBalance",
        r#"["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","latest"]"#,
    );
    let ids: Vec<u64> = (0..16)
        .map(|_| colibrid.request("colibri.request", params.clone()))
        .collect();
    // Each waits on its fetches, which go unanswered.
    let mut asking = std::collections::HashSet::new();
    let deadline = Instant::now() + WAIT;
    while asking.len() < 16 && Instant::now() < deadline {
        if let Some(Frame::Json(message, _)) = colibrid.recv(Duration::from_secs(1))
            && message["method"] == "shell.colibri_fetch"
        {
            asking.insert(message["params"]["request"].as_u64().unwrap());
        }
    }
    assert_eq!(asking.len(), 16);
    let extra = colibrid.request("colibri.request", params.clone());
    let (reply, _) = until_reply(&mut colibrid, extra, |_, _, _| {});
    assert_eq!(reply["error"]["code"], "busy", "{reply}");
    // Past their commit point, so the service answers the cancels itself.
    for id in &ids {
        colibrid.cancel(*id);
    }
    let mut cancelled = std::collections::HashSet::new();
    let deadline = Instant::now() + WAIT;
    while cancelled.len() < 16 && Instant::now() < deadline {
        if let Some(Frame::Json(message, _)) = colibrid.recv(Duration::from_secs(1))
            && message["type"] == "response"
            && message["error"]["code"] == "cancelled"
        {
            cancelled.insert(message["id"].as_u64().unwrap());
        }
    }
    assert_eq!(cancelled.len(), 16, "stderr: {}", colibrid.stderr());
    let id = colibrid.request("colibri.stats", json!({}));
    let (reply, _) = until_reply(&mut colibrid, id, |_, _, _| {});
    assert_eq!(reply["result"]["open_requests"], 0);
    assert_eq!(colibrid.shutdown(), Some(0));
}

#[test]
fn the_gate_is_held_for_the_process_life() {
    let dirs = Dirs::new("gate");
    let mut first = Colibrid::serve(1, Some(&dirs));
    first.hello();
    let mut second = Colibrid::serve(1, Some(&dirs));
    assert_eq!(second.exit_code(Duration::from_secs(20)), Some(75));
    assert_eq!(first.shutdown(), Some(0));
}

#[test]
fn usage_errors_exit_64() {
    for args in [
        &["serve"][..],
        &["serve", "--chain", "1", "--data-dir", "/tmp"],
        &["checkpoint"],
    ] {
        let status = std::process::Command::new(common::BIN)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(64), "{args:?}");
    }
}

#[test]
fn a_body_past_its_bound_is_refused_at_its_head() {
    let mut colibrid = Colibrid::serve(1, None);
    colibrid.hello();
    let id = colibrid.request(
        "colibri.request",
        request_params(
            "eth_getBalance",
            r#"["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","latest"]"#,
        ),
    );
    let mut first = true;
    let (reply, _) = until_reply(&mut colibrid, id, |c, ask, _| {
        if std::mem::take(&mut first) {
            // Over 16 MiB: refused before any of it is read, so main is told
            // to stop and the C core sees a busy fetch.
            c.respond(
                ask,
                json!({ "node": 0, "bytes": (16u64 << 20) + 1, "body": true }),
            );
        } else {
            c.respond(ask, json!({ "error": "HTTP error! Status: 500" }));
        }
    });
    let error = reply["result"]["error"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(error.contains("Colibri fetch busy"), "{reply}");
    assert_eq!(colibrid.shutdown(), Some(0));
}

#[test]
fn a_cancel_during_a_step_wins_when_the_step_returns() {
    let mut command = std::process::Command::new(common::BIN);
    command
        .args(["serve", "--chain", "1"])
        .env("FREEDOM_COLIBRID_TEST_STEP", "sleep:1500");
    let mut colibrid = Colibrid::spawn(command);
    colibrid.hello();
    let id = colibrid.request("colibri.request", request_params("eth_blockNumber", "[]"));
    // The fourth call is the step (after the classification, the context
    // and its freshness bound): cancel while it sleeps.
    let mut steps = 0;
    let deadline = Instant::now() + WAIT;
    while steps < 4 && Instant::now() < deadline {
        if let Some(Frame::Json(m, _)) = colibrid.recv(Duration::from_millis(100))
            && m["type"] == "event"
            && m["event"] == "colibri.step"
        {
            steps += 1;
        }
    }
    assert_eq!(steps, 4);
    colibrid.cancel(id);
    let mut fetched = false;
    let mut reply = None;
    let deadline = Instant::now() + WAIT;
    while reply.is_none() && Instant::now() < deadline {
        if let Some(Frame::Json(m, _)) = colibrid.recv(Duration::from_millis(100)) {
            fetched |= m["method"] == "shell.colibri_fetch";
            if m["type"] == "response" && m["id"] == id {
                reply = Some(m);
            }
        }
    }
    let reply = reply.expect("no reply");
    assert_eq!(reply["error"]["code"], "cancelled", "{reply}");
    assert!(!fetched, "the cancelled step's requests were fetched");
    // The step, then the context's free, and nothing more.
    let stats = colibrid.request("colibri.stats", json!({}));
    let (stats, _) = until_reply(&mut colibrid, stats, |_, _, _| {});
    assert_eq!(stats["result"]["calls"], 5, "{stats}");
    assert_eq!(colibrid.shutdown(), Some(0));
}

#[test]
fn a_cancel_during_the_classification_wins_when_it_returns() {
    let mut command = std::process::Command::new(common::BIN);
    command
        .args(["serve", "--chain", "1"])
        .env("FREEDOM_COLIBRID_TEST_CLASSIFY", "sleep:1500");
    let mut colibrid = Colibrid::spawn(command);
    colibrid.hello();
    let id = colibrid.request("colibri.request", request_params("eth_blockNumber", "[]"));
    // The first call is the classification: cancel while it sleeps, past
    // the commit point (its marker).
    let mut marked = false;
    let deadline = Instant::now() + WAIT;
    while !marked && Instant::now() < deadline {
        if let Some(Frame::Json(m, _)) = colibrid.recv(Duration::from_millis(100)) {
            marked = m["type"] == "event" && m["event"] == "colibri.step";
        }
    }
    assert!(marked);
    colibrid.cancel(id);
    let mut markers = 1;
    let mut reply = None;
    let deadline = Instant::now() + WAIT;
    while reply.is_none() && Instant::now() < deadline {
        if let Some(Frame::Json(m, _)) = colibrid.recv(Duration::from_millis(100)) {
            markers += usize::from(m["type"] == "event" && m["event"] == "colibri.step");
            if m["type"] == "response" && m["id"] == id {
                reply = Some(m);
            }
        }
    }
    let reply = reply.expect("no reply");
    assert_eq!(reply["error"]["code"], "cancelled", "{reply}");
    // The classification alone: no context was made, so none is freed.
    assert_eq!(markers, 1);
    let stats = colibrid.request("colibri.stats", json!({}));
    let (stats, _) = until_reply(&mut colibrid, stats, |_, _, _| {});
    assert_eq!(stats["result"]["calls"], 1, "{stats}");
    assert_eq!(colibrid.shutdown(), Some(0));
}

#[test]
fn a_deadline_past_the_clock_panics_nothing() {
    let mut colibrid = Colibrid::serve(1, None);
    colibrid.hello();
    let mut params = request_params("eth_blockNumber", "[]");
    params["deadline_ms"] = json!(u64::MAX);
    let id = colibrid.request("colibri.request", params);
    // Where the clock can't hold it (macOS counts nanoseconds in 64 bits),
    // the request is refused; where it can (Linux), it runs to its fetches.
    // Either way, nothing panics.
    let deadline = Instant::now() + WAIT;
    let mut outcome = None;
    while outcome.is_none() && Instant::now() < deadline {
        if let Some(Frame::Json(m, _)) = colibrid.recv(Duration::from_millis(100)) {
            if m["type"] == "response" && m["id"] == id {
                assert_eq!(m["error"]["code"], "invalid_argument", "{m}");
                outcome = Some("refused");
            } else if m["method"] == "shell.colibri_fetch" {
                outcome = Some("fetching");
            }
        }
    }
    assert!(outcome.is_some(), "neither: stderr {}", colibrid.stderr());
    assert!(!colibrid.exited(), "the process died");
    assert_eq!(colibrid.shutdown(), Some(0));
}
