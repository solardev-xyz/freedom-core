//! Fragmented responses and bulk credit end to end (design 0005, Frames):
//! the real binary, with the test playing main.
//!
//! - **Core to main:** the `test.*` methods (enabled by
//!   `FREEDOM_CORED_TEST_METHODS`) make responses of any size, as the chain
//!   thread's large replies are (`tests/chain.rs` has those).
//! - **Main to core:** naming's `shell.rpc` requests are the core's pending
//!   requests, which main answers in fragments.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use base64::Engine as _;
use common::*;
use serde_json::{Value, json};

const TEST_METHODS: (&str, &str) = ("FREEDOM_CORED_TEST_METHODS", "1");
const MIB: usize = 1 << 20;
const MAX_MESSAGE: usize = 32 * MIB;

/// A core with the test methods, after a handshake that offered fragments
/// or not. Its capabilities offer fragments either way.
fn core(offer: bool) -> (tempfile::TempDir, Core) {
    let (root, data, locks) = dirs();
    let mut core = spawn_env("serve", &data, &locks, &[], &[TEST_METHODS]);
    let hello = if offer {
        core.hello_fragments()
    } else {
        core.hello()
    };
    let capabilities = hello["result"]["capabilities"].as_array().unwrap();
    assert!(capabilities.contains(&json!("fragments")), "{hello}");
    (root, core)
}

/// What `test.large` answers: `bytes` letters, `a` to `z` repeating.
fn letters(bytes: usize) -> String {
    let mut text = "abcdefghijklmnopqrstuvwxyz".repeat(bytes.div_ceil(26));
    text.truncate(bytes);
    text
}

/// Reads frames up to and including a response's last fragment.
fn until_last(core: &mut Core) -> Vec<Wire> {
    let mut wires = Vec::new();
    loop {
        let wire = core.recv_wire();
        let last = matches!(wire, Wire::Last(_));
        wires.push(wire);
        if last {
            return wires;
        }
    }
}

/// The one fragmented response among `wires`, from its begin, checked as
/// main checks it: every fragment within a frame and not empty, exactly the
/// declared size in all.
fn reassemble(wires: &[Wire]) -> Value {
    let mut declared = None;
    let mut payload = Vec::new();
    for wire in wires {
        match wire {
            Wire::Begin { bytes, .. } => {
                assert!(declared.is_none(), "one response at a time");
                assert!(*bytes > MIB && *bytes <= MAX_MESSAGE, "{bytes}");
                declared = Some(*bytes);
            }
            Wire::Fragment(bytes) | Wire::Last(bytes) => {
                assert!(declared.is_some(), "a fragment before its begin");
                assert!(!bytes.is_empty() && bytes.len() <= MIB);
                payload.extend_from_slice(bytes);
            }
            Wire::Message(_) | Wire::Credit => {}
        }
    }
    assert_eq!(Some(payload.len()), declared);
    serde_json::from_slice(&payload).unwrap()
}

/// The whole messages among `wires`.
fn messages(wires: &[Wire]) -> Vec<&Value> {
    wires
        .iter()
        .filter_map(|wire| match wire {
            Wire::Message(value) => Some(value),
            _ => None,
        })
        .collect()
}

#[test]
fn a_large_response_arrives_in_fragments_with_control_messages_between() {
    let (_root, mut core) = core(true);
    let size = 4 * MIB;
    // Main stalls once the response has begun...
    core.pause_after_begin();
    core.send(&request(2, "test.large", json!({ "bytes": size })));
    let begin = core.recv_wire();
    assert!(matches!(begin, Wire::Begin { id: 2, .. }), "{begin:?}");
    // ...asks for the vault's status, and reads on once the core has had
    // ample time to answer it.
    core.send(&request(3, "vault.status", json!({})));
    std::thread::sleep(Duration::from_millis(300));
    core.resume_reading();
    let wires = until_last(&mut core);
    // The reply was written between two fragments, not after the response.
    let status = wires
        .iter()
        .position(|w| matches!(w, Wire::Message(m) if m["id"] == 3))
        .expect("the status reply comes before the last fragment");
    assert!(matches!(wires[0], Wire::Fragment(_)), "{wires:?}");
    assert!(status > 0 && status < wires.len() - 1, "{wires:?}");
    assert_eq!(messages(&wires)[0]["result"]["exists"], false);
    // Five fragments: four full ones, then the rest.
    let fragments = wires
        .iter()
        .filter(|w| matches!(w, Wire::Fragment(_) | Wire::Last(_)))
        .count();
    assert_eq!(fragments, 5);
    let mut all = vec![begin];
    all.extend(wires);
    let response = reassemble(&all);
    assert_eq!(response["type"], "response");
    assert_eq!(response["id"], 2);
    assert_eq!(response["result"].as_str().unwrap(), letters(size));
}

#[test]
fn a_response_waits_for_credit_while_whole_messages_go() {
    let (_root, mut core) = core(true);
    core.send(&request(2, "test.large", json!({ "bytes": 2 * MIB })));
    let first = until_last(&mut core);
    assert!(matches!(first[0], Wire::Begin { id: 2, .. }));
    assert_eq!(
        reassemble(&first)["result"].as_str().unwrap().len(),
        2 * MIB
    );
    // Main hasn't returned the credit: the next large response waits...
    core.send(&request(3, "test.large", json!({ "bytes": 3 * MIB })));
    // ...while replies go, a small response included (`call` refuses any
    // frame but a whole message).
    assert_eq!(
        core.call(4, "vault.status", json!({}))["result"]["exists"],
        false
    );
    let small = core.call(5, "test.large", json!({ "bytes": 1000 }));
    assert_eq!(small["result"].as_str().unwrap(), letters(1000));
    // A response over the cap is never begun: it fails as too large.
    let over = core.call(6, "test.large", json!({ "bytes": MAX_MESSAGE }));
    assert_eq!(over["error"]["code"], "too_large", "{over}");
    // The credit comes back: the waiting response begins.
    core.send_credit();
    let second = until_last(&mut core);
    assert!(matches!(second[0], Wire::Begin { id: 3, .. }), "{second:?}");
    assert_eq!(
        reassemble(&second)["result"].as_str().unwrap(),
        letters(3 * MIB)
    );
    // Returned again, it lets the next one begin at once.
    core.send_credit();
    core.send(&request(7, "test.large", json!({ "bytes": MIB + 1 })));
    let third = until_last(&mut core);
    assert!(matches!(third[0], Wire::Begin { id: 7, .. }));
    assert_eq!(reassemble(&third)["id"], 7);
    // Shutdown doesn't wait for a credit main never returns: the waiting
    // response is dropped, and the core exits well within the writer's 2 s
    // drain.
    core.send(&request(8, "test.large", json!({ "bytes": 2 * MIB })));
    let started = Instant::now();
    assert_eq!(
        core.call_shell(9, "core.shutdown", json!({}))["result"],
        json!({})
    );
    assert_eq!(core.rest(), Vec::<Value>::new());
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a_cancel_after_begin_changes_nothing() {
    let (_root, mut core) = core(true);
    core.pause_after_begin();
    core.send(&request(2, "test.large", json!({ "bytes": 3 * MIB })));
    let begin = core.recv_wire();
    assert!(matches!(begin, Wire::Begin { id: 2, .. }));
    core.send(&json!({ "type": "cancel", "id": 2 }));
    core.send(&request(3, "vault.status", json!({})));
    core.resume_reading();
    // The response completes, whole.
    let mut wires = vec![begin];
    wires.extend(until_last(&mut core));
    let response = reassemble(&wires);
    assert_eq!(response["id"], 2);
    assert_eq!(response["result"].as_str().unwrap().len(), 3 * MIB);
    // Nothing else answers request 2: the status reply, sent after the
    // cancel, is the next and only other message.
    let mut seen: Vec<Value> = messages(&wires).into_iter().cloned().collect();
    if !seen.iter().any(|m| m["id"] == 3) {
        seen.push(core.recv());
    }
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0]["id"], 3);
}

/// Main's answer to `shell.rpc` request `id`, from the recordings.
fn rpc_answer(request: &Value, answers: &std::collections::BTreeMap<String, String>) -> Value {
    let body: Value = serde_json::from_str(request["params"]["body"].as_str().unwrap()).unwrap();
    let answer = &answers[body["method"].as_str().unwrap()];
    let encoded = base64::engine::general_purpose::STANDARD.encode(answer);
    json!({
        "type": "response",
        "id": request["id"],
        "result": { "status": 200, "body": encoded },
    })
}

/// Configures naming (request 20) and starts a resolution (request 30): the
/// core's first `shell.rpc` request to main.
fn first_rpc(core: &mut Core) -> Value {
    core.call(20, "naming.configure", naming_snapshot());
    core.send(&request(
        30,
        "naming.resolve_content",
        json!({ "name": "vitalik.eth" }),
    ));
    let first = core.recv();
    assert_eq!(first["method"], "shell.rpc", "{first}");
    first
}

#[test]
fn the_core_returns_credit_once_naming_has_each_answer() {
    let (_root, mut core) = core(true);
    let answers = naming_recorded();
    let mut waiting = vec![first_rpc(&mut core)];
    // Main answers every shell.rpc in three fragments, beginning each only
    // once the core has returned the credit for the one before.
    let mut holding = true;
    let mut answered = 0;
    let mut credits = 0;
    let reply = loop {
        if holding && let Some(next) = waiting.pop() {
            for frame in fragmented(&rpc_answer(&next, &answers), 3) {
                core.send_raw(&frame);
            }
            holding = false;
            answered += 1;
        }
        match core.recv_wire() {
            Wire::Credit => {
                assert!(!holding, "a credit main wasn't owed");
                holding = true;
                credits += 1;
            }
            Wire::Message(m) if m["method"] == "shell.rpc" => waiting.insert(0, m),
            Wire::Message(m) if m["type"] == "response" && m["id"] == 30 => break m,
            Wire::Message(m) => assert!(
                m["type"] == "cancel" || m["method"] == "shell.prefetch",
                "{m}"
            ),
            other => panic!("unexpected {other:?}"),
        }
    };
    assert_eq!(reply["result"]["result"]["type"], "ok", "{reply}");
    assert!(
        answered >= 7,
        "anchor and legs went through main: {answered}"
    );
    // The last answer's credit follows the reply it completed.
    while credits < answered {
        match core.recv_wire() {
            Wire::Credit => credits += 1,
            Wire::Message(_) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(credits, answered);
}

#[test]
fn a_cancelled_resolution_still_takes_its_begun_answer_and_credit_returns() {
    let (_root, mut core) = core(true);
    let answers = naming_recorded();
    let rpc = first_rpc(&mut core);
    let frames = fragmented(&rpc_answer(&rpc, &answers), 3);
    assert_eq!(frames.len(), 4);
    // Main begins its answer, then the caller cancels the resolution.
    core.send_raw(&frames[0]);
    core.send_raw(&frames[1]);
    core.send(&json!({ "type": "cancel", "id": 30 }));
    let (reply, others) = until_response_keeping_requests(&mut core, 30);
    assert_eq!(reply["error"]["code"], "cancelled", "{reply}");
    // The begun answer still completes; the core consumes it and gives the
    // credit back.
    core.send_raw(&frames[2]);
    core.send_raw(&frames[3]);
    until_credit(&mut core);
    // Main may begin again, for another request still waiting for main.
    for frame in fragmented(&rpc_answer(&others[0], &answers), 2) {
        core.send_raw(&frame);
    }
    until_credit(&mut core);
    // The vault still answers, among naming's requests.
    core.send(&request(40, "vault.status", json!({})));
    assert_eq!(core.until_response(40)["result"]["exists"], false);
}

/// Reads until the response to `id`, keeping the core's `shell.rpc`
/// requests seen on the way.
fn until_response_keeping_requests(core: &mut Core, id: u64) -> (Value, Vec<Value>) {
    let mut requests = Vec::new();
    loop {
        let message = core.recv();
        if message["method"] == "shell.rpc" {
            requests.push(message);
        } else if message["type"] == "response" && message["id"] == id {
            return (message, requests);
        }
    }
}

/// Reads until the core returns main's credit, past other messages.
fn until_credit(core: &mut Core) {
    loop {
        match core.recv_wire() {
            Wire::Credit => return,
            Wire::Message(_) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn an_answer_the_core_cancelled_after_it_began_is_dropped_and_credit_returns() {
    let (_root, mut core) = core(true);
    let answers = naming_recorded();
    // Probes left unanswered time out after half a second.
    let mut snapshot = naming_snapshot();
    snapshot["quorum"]["timeout_ms"] = json!(500);
    core.call(20, "naming.configure", snapshot);
    core.send(&request(
        30,
        "naming.resolve_content",
        json!({ "name": "vitalik.eth" }),
    ));
    let rpc = core.recv();
    assert_eq!(rpc["method"], "shell.rpc", "{rpc}");
    let frames = fragmented(&rpc_answer(&rpc, &answers), 3);
    core.send_raw(&frames[0]);
    core.send_raw(&frames[1]);
    // Main is slow: the core gives up on the request and cancels it, its
    // answer begun.
    let mut others = Vec::new();
    loop {
        let message = core.recv();
        if message["method"] == "shell.rpc" {
            others.push(message);
        } else if message["type"] == "cancel" && message["id"] == rpc["id"] {
            break;
        }
    }
    // The answer still completes; the core consumes it, drops it as late,
    // and gives the credit back.
    core.send_raw(&frames[2]);
    core.send_raw(&frames[3]);
    until_credit(&mut core);
    // Main may begin again, for another request: cancelled or not, it waits
    // for main's terminal answer, which is dropped the same way.
    for frame in fragmented(&rpc_answer(&others[0], &answers), 2) {
        core.send_raw(&frame);
    }
    until_credit(&mut core);
    core.send(&request(40, "vault.status", json!({})));
    assert_eq!(core.until_response(40)["result"]["exists"], false);
}

#[test]
fn eof_in_the_middle_of_a_fragmented_answer_is_eof() {
    let (_root, mut core) = core(true);
    let rpc = first_rpc(&mut core);
    let frames = fragmented(&rpc_answer(&rpc, &naming_recorded()), 3);
    core.send_raw(&frames[0]);
    core.send_raw(&frames[1]);
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
    let stderr = core.stderr();
    assert!(
        stderr.contains("stdin closed in the middle of a fragmented response"),
        "{stderr}"
    );
}

#[test]
fn malformed_fragments_close_the_connection() {
    let begin = |id: u64, bytes: usize| {
        raw_frame(
            KIND_BEGIN,
            json!({ "id": id, "bytes": bytes }).to_string().as_bytes(),
        )
    };
    // A whole answer to the pending shell.rpc that naming takes as it is
    // (an endpoint's HTTP failure), so only the reader closes the
    // connection: `{}` would be a malformed reply, which naming closes on
    // too, and either thread could be first.
    let whole = |id: u64| {
        frame(&json!({
            "type": "response",
            "id": id,
            "result": { "status": 503, "body": "" },
        }))
    };
    // Each case: what main sends, given the ID of a pending shell.rpc
    // request, and the category the core logs as it closes.
    type Case = (&'static str, Box<dyn Fn(u64) -> Vec<u8>>);
    let cases: Vec<Case> = vec![
        ("begin_unknown_id", Box::new(move |id| begin(id + 1000, 10))),
        (
            "begin_without_credit",
            Box::new(move |id| [begin(id, 10), begin(id, 10)].concat()),
        ),
        ("begin_size", Box::new(move |id| begin(id, MAX_MESSAGE + 1))),
        (
            "begin_header",
            Box::new(|id| raw_frame(KIND_BEGIN, json!({ "id": id }).to_string().as_bytes())),
        ),
        (
            "empty_fragment",
            Box::new(move |id| [begin(id, 10), raw_frame(KIND_FRAGMENT, b"")].concat()),
        ),
        (
            "fragment_without_begin",
            Box::new(|_| raw_frame(KIND_LAST, b"{}")),
        ),
        (
            "fragment_length",
            Box::new(move |id| [begin(id, 10), raw_frame(KIND_LAST, b"{}")].concat()),
        ),
        ("credit_payload", Box::new(|_| raw_frame(KIND_CREDIT, b"x"))),
        // One response per request (0001): a whole one after a begin for
        // the same request, or a begin after a whole one.
        (
            "duplicate_response",
            Box::new(move |id| [begin(id, 10), whole(id)].concat()),
        ),
        (
            "begin_unknown_id",
            Box::new(move |id| [whole(id), begin(id, 10)].concat()),
        ),
        // Main offered fragments: the core holds main's credit already.
        (
            "unsolicited_credit",
            Box::new(|_| raw_frame(KIND_CREDIT, b"")),
        ),
        // Complete, but not the response the begin named.
        (
            "fragmented_not_its_response",
            Box::new(move |id| {
                let other = json!({ "type": "response", "id": id + 1, "result": {} });
                let payload = serde_json::to_vec(&other).unwrap();
                [begin(id, payload.len()), raw_frame(KIND_LAST, &payload)].concat()
            }),
        ),
    ];
    for (category, bytes) in cases {
        let (_root, mut core) = core(true);
        let rpc = first_rpc(&mut core);
        core.send_raw(&bytes(rpc["id"].as_u64().unwrap()));
        assert_eq!(core.exit_code(Duration::from_secs(5)), 76, "{category}");
        let stderr = core.stderr();
        assert!(
            stderr.contains(&format!(r#""category":"{category}""#)),
            "{category}: {stderr}"
        );
    }
}

#[test]
fn a_whole_response_for_a_begun_one_closes_the_connection() {
    let (_root, mut core) = core(true);
    let answers = naming_recorded();
    let rpc = first_rpc(&mut core);
    let other = loop {
        let message = core.recv();
        if message["method"] == "shell.rpc" {
            break message;
        }
    };
    // Main begins its answer to one request...
    let begin = json!({ "id": rpc["id"], "bytes": 2 * MIB }).to_string();
    core.send_raw(&raw_frame(KIND_BEGIN, begin.as_bytes()));
    // ...meanwhile answers another whole, and asks the vault: both fine.
    core.send(&rpc_answer(&other, &answers));
    core.send(&request(40, "vault.status", json!({})));
    assert_eq!(core.until_response(40)["result"]["exists"], false);
    // Then it answers the begun request whole as well: a second response
    // for it, which closes the connection rather than strand the begun
    // one's reservation and credit.
    core.send(&json!({
        "type": "response",
        "id": rpc["id"],
        "error": { "code": "internal", "message": "probe" },
    }));
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);
    let stderr = core.stderr();
    assert!(
        stderr.contains(r#""category":"duplicate_response""#),
        "{stderr}"
    );
}

#[test]
fn a_main_that_did_not_offer_gets_no_fragments() {
    let (_root, mut core) = core(false);
    // `call` refuses any frame but a whole message.
    let big = core.call(2, "test.large", json!({ "bytes": 2 * MIB }));
    assert_eq!(big["error"]["code"], "too_large", "{big}");
    let fits = MIB - 64;
    let whole = core.call(3, "test.large", json!({ "bytes": fits }));
    assert_eq!(whole["result"].as_str().unwrap(), letters(fits));
    // The core still takes main's fragments: it offered them.
    let rpc = first_rpc(&mut core);
    for frame in fragmented(&rpc_answer(&rpc, &naming_recorded()), 2) {
        core.send_raw(&frame);
    }
    until_credit(&mut core);
    // A credit the core was never given is a protocol error.
    core.send_credit();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 76);
    assert!(core.stderr().contains(r#""category":"unsolicited_credit""#));
}

#[test]
fn test_methods_need_their_hook() {
    let (_root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello_fragments();
    let reply = core.call(2, "test.large", json!({ "bytes": 10 }));
    assert_eq!(reply["error"]["code"], "unknown_method");
}
