//! The swarm thread's streams through the core (design 0015, "Streams",
//! "Bounds" and "Deadlines and cancel"; SWM-4 PR 6, D4 and D13): the real
//! binary and the test as main, frame by frame.
//!
//! - **An upload's part and its `swarm.body`:** a `publishData` whose data
//!   is a part (with the test hooks' stand-in for the stores, which PR 7
//!   replaces): main streams the part within the core's credit, asks for
//!   the call's body and reads it within its own. The core credits the part
//!   only for bytes it has put on the body ("credit goes in only when it can
//!   go out"), so a main that stops reading the body holds one window each
//!   way; the idle bound, shortened by its hook, then ends the upload.
//! - **A part's abort that names its file's error code** reaches the
//!   machine, which ends the upload; the same name on another code is main
//!   breaking the protocol.
//! - **A body's credit after main answered its call** ends the connection
//!   (D4: the route went with the answer).
//! - **A cancelled stream main never ends** ends the connection at the idle
//!   bound.
//! - **The 32 streams' slots** (here one, by its hook): a second streamed
//!   read waits for the first's stream to end.
//! - **A fragmented 1 MiB `/stamps` reply** is reassembled within its bound;
//!   one past it is refused before anything is reserved.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod swarm_world;

use std::time::{Duration, Instant};

use common::{KIND_ABORT, KIND_DATA, KIND_END, KIND_STREAM_CREDIT, Wire, stream_frame};
use serde_json::{Value, json};
use swarm_world::{Main, WINDOW, page};

const SITE: &str = "https://app.example";

/// One usable batch, as the node lists it.
const STAMPS: &str = r#"{"stamps":[{"batchID":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","utilization":0,"usable":true,"label":"freedom","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000}]}"#;

/// The node's answer to the upload.
const REFERENCE: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A core with the Swarm grants moved, the stand-in stores and `env`'s
/// hooks, `SITE` connected.
fn main_with(env: &[(&str, &str)]) -> Main {
    let mut hooks = vec![("FREEDOM_CORED_TEST_SWARM_WRITES", "accept")];
    hooks.extend_from_slice(env);
    let mut main = swarm_world::main_with(&["swarm"], &hooks);
    main.world(json!({
        "reset": true,
        "clock": 1_767_225_600_123u64,
        "grants": { SITE: {
            "origin": SITE, "connectedAt": 1, "lastUsed": 1,
            "autoApprove": { "publish": false, "feeds": false, "signing": false, "messaging": false },
        } },
    }));
    main
}

/// `publishData` of `n` bytes, streamed as part 0.
fn publish(n: usize) -> String {
    format!(
        r#"{{"method":{{"string":"swarm_publishData"}},"params":{{"object":[["data",{{"bytes":{n},"kind":"Uint8Array","part":0}}],["contentType",{{"string":"application/octet-stream"}}]]}},"approval":"user"}}"#
    )
}

/// `publishData` of `bytes`, inline.
fn publish_inline(bytes: &[u8]) -> String {
    format!(
        r#"{{"method":{{"string":"swarm_publishData"}},"params":{{"object":[["data",{{"bytes":{},"kind":"Uint8Array","base64":"{}"}}],["contentType",{{"string":"application/octet-stream"}}]]}},"approval":"user"}}"#,
        bytes.len(),
        b64(bytes)
    )
}

/// The part's byte `k`.
fn part_byte(k: usize) -> u8 {
    u8::try_from(k % 251).unwrap()
}

/// How main plays an upload.
#[derive(Clone, Copy, PartialEq)]
enum Play {
    /// Credits the body as it reads it, and the upload succeeds.
    Honest,
    /// Never credits the body.
    Stall,
    /// Aborts the part after its first frame, naming `ENOENT`
    /// (`body_stream_error`), or naming it on `stalled`.
    Unreadable,
    UnreadableStalled,
}

/// What main saw of one upload.
#[derive(Default, Debug)]
struct Seen {
    /// The core's answer to the page.
    answer: Option<Value>,
    /// `shell.swarm_api`'s `bzz_file` call, main's `swarm.body` for it, and
    /// the core's `shell.swarm_part`.
    call: Option<u64>,
    body: Option<u64>,
    part: Option<u64>,
    /// The body's head (`{ bytes }`), its bytes, and its terminal.
    head: Option<Value>,
    body_bytes: Vec<u8>,
    body_end: Option<String>,
    /// Part bytes main sent, and the core's credit for them.
    part_sent: u64,
    part_credit: u64,
    /// The core's cancels of its own requests.
    cancels: Vec<u64>,
    /// The most part credit the core had given beyond the body bytes main
    /// had allowed (its window and its credit): never above zero.
    credit_past_body: i64,
    /// When the last of main's frames for the upload went.
    last_progress: Option<Instant>,
}

/// Plays one upload of `n` bytes as `play` says, until the page's answer
/// and every stream's end.
fn upload(main: &mut Main, n: usize, play: Play) -> Seen {
    let request = main.request(&page(SITE), &publish(n));
    let mut seen = Seen::default();
    let mut body_credit = 0u64;
    let mut part_done = false;
    let mut call_answered = false;
    loop {
        let finished = seen.answer.is_some()
            && (seen.call.is_none() || call_answered)
            && (seen.part.is_none() || part_done)
            && (seen.head.is_none() || seen.body_end.is_some());
        if finished {
            break;
        }
        match main.core.recv_wire() {
            Wire::Message(message) => match message["type"].as_str().unwrap() {
                "request" => {
                    let id = message["id"].as_u64().unwrap();
                    let params = &message["params"];
                    match message["method"].as_str().unwrap() {
                        "shell.swarm_ready" => main.answer(id, json!({ "ok": true })),
                        "approval.recheck" => {
                            main.answer(id, json!({ "live": true, "agent": false }));
                        }
                        "shell.swarm_api" if params["form"] == "stamps" => main.answer(
                            id,
                            json!({ "status": 200, "status_text": "OK", "headers": [],
                                "body_base64": b64(STAMPS.as_bytes()) }),
                        ),
                        "shell.swarm_api" => {
                            assert_eq!(params["form"], "bzz_file", "{message}");
                            assert_eq!(params["body"], json!({ "stream": n }));
                            seen.call = Some(id);
                            // Main asks for the call's body.
                            let body = main.id();
                            main.core.send(&json!({
                                "type": "request", "id": body, "method": "swarm.body",
                                "params": { "for": id }, "context": { "caller": "shell" },
                            }));
                            seen.body = Some(body);
                            seen.last_progress = Some(Instant::now());
                        }
                        "shell.swarm_part" => {
                            assert_eq!(params, &json!({ "for": request, "part": 0 }));
                            seen.part = Some(id);
                            main.answer(id, json!({ "bytes": n }));
                            send_part(main, &mut seen, n, play, &mut part_done);
                        }
                        other => panic!("the thread asked {other}"),
                    }
                }
                "response" => {
                    let id = message["id"].as_u64().unwrap();
                    if id == request {
                        seen.answer = Some(message);
                    } else if Some(id) == seen.body {
                        seen.head = Some(message["result"].clone());
                    } else {
                        panic!("an answer to nothing: {message}");
                    }
                }
                "cancel" => {
                    let id = message["id"].as_u64().unwrap();
                    seen.cancels.push(id);
                    if Some(id) == seen.call && !call_answered {
                        main.refuse(id, json!({ "code": "cancelled", "message": "Cancelled" }));
                        call_answered = true;
                    }
                    if Some(id) == seen.part && !part_done {
                        main.abort(id, "cancelled");
                        part_done = true;
                    }
                }
                other => panic!("{other}: {message}"),
            },
            Wire::Stream { kind, id, rest } => {
                if kind == KIND_STREAM_CREDIT && Some(id) == seen.part {
                    seen.part_credit +=
                        u64::from(u32::from_be_bytes(rest[..4].try_into().unwrap()));
                    let allowed = WINDOW + body_credit;
                    seen.credit_past_body = seen
                        .credit_past_body
                        .max(seen.part_credit as i64 - allowed as i64);
                    if !part_done {
                        send_part(main, &mut seen, n, play, &mut part_done);
                    }
                    continue;
                }
                assert_eq!(Some(id), seen.body, "a frame of another stream: {kind}");
                match kind {
                    KIND_DATA => {
                        seen.body_bytes.extend_from_slice(&rest);
                        if play != Play::Stall {
                            body_credit += rest.len() as u64;
                            main.core.send_raw(&common::stream_frame(
                                KIND_STREAM_CREDIT,
                                id,
                                &u32::try_from(rest.len()).unwrap().to_be_bytes(),
                            ));
                            seen.last_progress = Some(Instant::now());
                        }
                    }
                    KIND_END => {
                        seen.body_end = Some("end".into());
                        // The node took the body: main answers the call.
                        let call = seen.call.unwrap();
                        main.answer(
                            call,
                            json!({
                                "status": 201, "status_text": "Created",
                                "headers": [["content-type", "application/json"], ["swarm-tag", "41"]],
                                "body_base64": b64(format!(r#"{{"reference":"{REFERENCE}"}}"#).as_bytes()),
                            }),
                        );
                        call_answered = true;
                    }
                    KIND_ABORT => {
                        let abort: Value = serde_json::from_slice(&rest).unwrap();
                        seen.body_end = Some(abort["code"].as_str().unwrap().to_owned());
                    }
                    other => panic!("a body frame of kind {other}"),
                }
            }
            Wire::Credit => {}
            other => panic!("{other:?}"),
        }
    }
    seen
}

/// Main sends the part's next bytes, as far as the core's credit allows.
fn send_part(main: &mut Main, seen: &mut Seen, n: usize, play: Play, done: &mut bool) {
    let part = seen.part.unwrap();
    while (seen.part_sent as usize) < n {
        let room = (WINDOW + seen.part_credit).saturating_sub(seen.part_sent);
        if room == 0 {
            return;
        }
        let from = seen.part_sent as usize;
        let len = (n - from).min(64 * 1024).min(room as usize);
        let bytes: Vec<u8> = (from..from + len).map(part_byte).collect();
        main.core.send_raw(&stream_frame(KIND_DATA, part, &bytes));
        seen.part_sent += len as u64;
        seen.last_progress = Some(Instant::now());
        if matches!(play, Play::Unreadable | Play::UnreadableStalled) {
            let code = if play == Play::Unreadable {
                "body_stream_error"
            } else {
                "stalled"
            };
            let abort = json!({ "code": code, "message": "read failed", "error_code": "ENOENT" });
            main.core.send_raw(&stream_frame(
                KIND_ABORT,
                part,
                abort.to_string().as_bytes(),
            ));
            *done = true;
            return;
        }
    }
    main.core.send_raw(&stream_frame(KIND_END, part, b""));
    *done = true;
}

/// The core ended with a protocol error of `category`.
fn ended_with(main: &mut Main, category: &str) {
    assert_eq!(main.core.exit_code(Duration::from_secs(10)), 76);
    let stderr = main.core.stderr();
    assert!(
        stderr.contains(&format!(r#""category":"{category}""#)),
        "{category}: {stderr}"
    );
}

/// The thread holds nothing, once the writer has told it of the answers
/// it wrote.
fn settled(main: &mut Main) {
    for _ in 0..200 {
        if main.world(json!({})) == json!({ "memory": 0, "requests": 0, "streams": 0 }) {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("the thread still holds {}", main.world(json!({})));
}

/// A 300,000-byte upload: the part and the body each within their windows,
/// the part credited only for what went out on the body, and every byte of
/// the part on the body, in order.
#[test]
fn credit_goes_in_only_when_it_can_go_out() {
    let mut main = main_with(&[]);
    let n = 300_000;
    let seen = upload(&mut main, n, Play::Honest);
    let answer = seen.answer.clone().unwrap();
    let result = answer["result"]["result_typed"].to_string();
    assert!(result.contains(REFERENCE), "{answer}");
    assert_eq!(seen.head, Some(json!({ "bytes": n })));
    assert_eq!(seen.body_end.as_deref(), Some("end"));
    let want: Vec<u8> = (0..n).map(part_byte).collect();
    assert!(
        seen.body_bytes == want,
        "the body is the part, byte for byte"
    );
    assert_eq!(seen.part_sent, n as u64);
    assert!(seen.credit_past_body <= 0, "{seen:?}");
    // The part's credit is what went out, less what main never needed.
    assert!(seen.part_credit <= n as u64, "{}", seen.part_credit);
    assert!(seen.cancels.is_empty(), "{:?}", seen.cancels);
    settled(&mut main);
}

/// Main stops reading the body: the core holds one window each way, the
/// part credited for no more than the body's window, and at the idle bound
/// (1 s here) it cancels the call and the part, ends the body and
/// answers the page; nothing is held after.
#[test]
fn a_stalled_body_ends_at_the_idle_bound() {
    let mut main = main_with(&[("FREEDOM_CORED_TEST_SWARM_IDLE_MS", "1000")]);
    let n = 600_000;
    let seen = upload(&mut main, n, Play::Stall);
    let answered = Instant::now();
    assert!(
        seen.body_bytes.len() as u64 <= WINDOW,
        "{}",
        seen.body_bytes.len()
    );
    assert!(seen.part_credit <= WINDOW, "{}", seen.part_credit);
    assert!(seen.part_sent <= 2 * WINDOW, "{}", seen.part_sent);
    assert!(seen.credit_past_body <= 0);
    let idle = answered.duration_since(seen.last_progress.unwrap());
    assert!(idle >= Duration::from_millis(900), "{idle:?}");
    // The call and the part cancelled; the body ended short.
    assert!(seen.cancels.contains(&seen.call.unwrap()));
    assert!(seen.cancels.contains(&seen.part.unwrap()));
    assert_eq!(seen.body_end.as_deref(), Some("cancelled"));
    let answer = seen.answer.clone().unwrap();
    assert!(
        answer["result"]["error_typed"].is_object(),
        "the upload failed: {answer}"
    );
    settled(&mut main);
}

/// A part's abort naming its file's error code reaches the machine: the
/// body ends `body_stream_error`, the call is cancelled, the page answered,
/// and the connection goes on. The same name on `stalled` ends it.
#[test]
fn a_parts_error_code_reaches_the_machine() {
    let mut main = main_with(&[]);
    let seen = upload(&mut main, 200_000, Play::Unreadable);
    assert_eq!(seen.body_end.as_deref(), Some("body_stream_error"));
    assert!(seen.cancels.contains(&seen.call.unwrap()));
    let answer = seen.answer.clone().unwrap();
    assert!(answer["result"]["error_typed"].is_object(), "{answer}");
    settled(&mut main);
    // The connection goes on: another upload succeeds.
    let seen = upload(&mut main, 1000, Play::Honest);
    assert!(seen.answer.clone().unwrap()["result"]["result_typed"].is_object());
    settled(&mut main);

    let mut main = main_with(&[]);
    main.request(&page(SITE), &publish(200_000));
    drive_until_exit(&mut main, 200_000, Play::UnreadableStalled);
    ended_with(&mut main, "abort_code");
}

/// Plays an upload to its part, which `play` ends as main breaking the
/// protocol.
fn drive_until_exit(main: &mut Main, n: usize, play: Play) {
    let mut seen = Seen::default();
    let mut done = false;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let Some(wire) = main.core.recv_wire_within(Duration::from_millis(200)) else {
            continue;
        };
        if let Wire::Message(message) = wire {
            if message["type"] != "request" {
                continue;
            }
            let id = message["id"].as_u64().unwrap();
            let params = &message["params"];
            match message["method"].as_str().unwrap() {
                "shell.swarm_ready" => main.answer(id, json!({ "ok": true })),
                "approval.recheck" => main.answer(id, json!({ "live": true, "agent": false })),
                "shell.swarm_api" if params["form"] == "stamps" => main.answer(
                    id,
                    json!({ "status": 200, "status_text": "OK", "headers": [],
                        "body_base64": b64(STAMPS.as_bytes()) }),
                ),
                "shell.swarm_api" => {
                    let body = main.id();
                    main.core.send(&json!({
                        "type": "request", "id": body, "method": "swarm.body",
                        "params": { "for": id }, "context": { "caller": "shell" },
                    }));
                }
                "shell.swarm_part" => {
                    seen.part = Some(id);
                    main.answer(id, json!({ "bytes": n }));
                    send_part(main, &mut seen, n, play, &mut done);
                    return;
                }
                _ => {}
            }
        }
    }
    panic!("no part asked")
}

/// D4: once main has answered the call, the body's route is closed, so a
/// credit for it after that is a protocol error: the core ends, whether
/// the event loop routes it after the thread closed the route, or before
/// (the credit right behind the answer, which the thread then refuses).
#[test]
fn a_bodys_credit_after_its_calls_answer_ends_the_connection() {
    let mut main = main_with(&[]);
    let seen = upload(&mut main, 1000, Play::Honest);
    assert!(seen.answer.clone().unwrap()["result"]["result_typed"].is_object());
    settled(&mut main);
    main.core.send_raw(&stream_frame(
        KIND_STREAM_CREDIT,
        seen.body.unwrap(),
        &1000u32.to_be_bytes(),
    ));
    ended_with(&mut main, "stream_closed");

    // Right behind the answer.
    let mut main = main_with(&[]);
    main.request(&page(SITE), &publish(1000));
    let mut seen = Seen::default();
    let mut done = false;
    loop {
        match main.core.recv_wire() {
            Wire::Message(message) if message["type"] == "request" => {
                let id = message["id"].as_u64().unwrap();
                let params = &message["params"];
                match message["method"].as_str().unwrap() {
                    "shell.swarm_ready" => main.answer(id, json!({ "ok": true })),
                    "approval.recheck" => {
                        main.answer(id, json!({ "live": true, "agent": false }));
                    }
                    "shell.swarm_api" if params["form"] == "stamps" => main.answer(
                        id,
                        json!({ "status": 200, "status_text": "OK", "headers": [],
                            "body_base64": b64(STAMPS.as_bytes()) }),
                    ),
                    "shell.swarm_api" => {
                        seen.call = Some(id);
                        let body = main.id();
                        seen.body = Some(body);
                        main.core.send(&json!({
                            "type": "request", "id": body, "method": "swarm.body",
                            "params": { "for": id }, "context": { "caller": "shell" },
                        }));
                    }
                    "shell.swarm_part" => {
                        seen.part = Some(id);
                        main.answer(id, json!({ "bytes": 1000 }));
                        send_part(&mut main, &mut seen, 1000, Play::Honest, &mut done);
                    }
                    other => panic!("{other}"),
                }
            }
            Wire::Stream {
                kind: KIND_END, id, ..
            } if Some(id) == seen.body => break,
            _ => {}
        }
    }
    let answer = json!({
        "type": "response", "id": seen.call.unwrap(), "result": {
            "status": 201, "status_text": "Created", "headers": [["swarm-tag", "41"]],
            "body_base64": b64(format!(r#"{{"reference":"{REFERENCE}"}}"#).as_bytes()),
        },
    });
    let mut both = common::frame(&answer);
    both.extend_from_slice(&stream_frame(
        KIND_STREAM_CREDIT,
        seen.body.unwrap(),
        &1000u32.to_be_bytes(),
    ));
    main.core.send_raw(&both);
    ended_with(&mut main, "stream_closed");
}

/// A part the core cancelled that main never ends: at the idle bound
/// (1 s here) after the cancel, the core ends the connection.
#[test]
fn a_cancelled_stream_main_never_ends_ends_the_connection() {
    let mut main = main_with(&[("FREEDOM_CORED_TEST_SWARM_IDLE_MS", "1000")]);
    let n = 600_000;
    main.request(&page(SITE), &publish(n));
    let mut seen = Seen::default();
    let mut done = false;
    // Until the core cancels the part: main answers the call's cancel, and
    // stops there, never ending the part.
    let cancelled = loop {
        match main.core.recv_wire() {
            Wire::Message(message) if message["type"] == "request" => {
                let id = message["id"].as_u64().unwrap();
                let params = &message["params"];
                match message["method"].as_str().unwrap() {
                    "shell.swarm_ready" => main.answer(id, json!({ "ok": true })),
                    "approval.recheck" => {
                        main.answer(id, json!({ "live": true, "agent": false }));
                    }
                    "shell.swarm_api" if params["form"] == "stamps" => main.answer(
                        id,
                        json!({ "status": 200, "status_text": "OK", "headers": [],
                            "body_base64": b64(STAMPS.as_bytes()) }),
                    ),
                    "shell.swarm_api" => {
                        seen.call = Some(id);
                        let body = main.id();
                        main.core.send(&json!({
                            "type": "request", "id": body, "method": "swarm.body",
                            "params": { "for": id }, "context": { "caller": "shell" },
                        }));
                    }
                    "shell.swarm_part" => {
                        seen.part = Some(id);
                        main.answer(id, json!({ "bytes": n }));
                        send_part(&mut main, &mut seen, n, Play::Stall, &mut done);
                    }
                    other => panic!("{other}"),
                }
            }
            Wire::Message(message) if message["type"] == "cancel" => {
                let id = message["id"].as_u64().unwrap();
                if Some(id) == seen.call {
                    main.refuse(id, json!({ "code": "cancelled", "message": "Cancelled" }));
                }
                if Some(id) == seen.part {
                    break Instant::now();
                }
            }
            Wire::Message(_) | Wire::Stream { .. } | Wire::Credit => {}
            other => panic!("{other:?}"),
        }
    };
    ended_with(&mut main, "swarm_stream_unterminated");
    assert!(cancelled.elapsed() >= Duration::from_millis(900));
}

/// A `readFeedEntry` of the latest entry, by topic and owner.
fn latest(n: u8) -> String {
    let topic = format!("{n:02x}").repeat(32);
    let owner = "11".repeat(20);
    format!(
        r#"{{"method":{{"string":"swarm_readFeedEntry"}},"params":{{"object":[["topic",{{"string":"{topic}"}}],["owner",{{"string":"{owner}"}}]]}}}}"#
    )
}

/// The latest entry's head, with the index headers the read requires.
fn feed_head(len: usize) -> Value {
    json!({ "status": 200, "status_text": "OK", "headers": [
        ["content-type", "application/octet-stream"], ["content-length", len.to_string()],
        ["swarm-feed-index", "0000000000000000"], ["swarm-feed-index-next", "0000000000000001"],
    ] })
}

/// D4's slots (one, by its hook): a second streamed read's call waits until
/// the first's stream has ended, then goes; both answer.
#[test]
fn a_streamed_read_waits_for_a_streams_slot() {
    let mut main = main_with(&[("FREEDOM_CORED_TEST_SWARM_STREAMS", "1")]);
    let first = main.request(&page(SITE), &latest(1));
    let second = main.request(&page(SITE), &latest(2));
    let mut calls = Vec::new();
    let mut ready = 0;
    // Both readiness checks, then the first's call alone.
    while calls.is_empty() || ready < 2 {
        let message = main.recv();
        assert_eq!(message["type"], "request", "{message}");
        let id = message["id"].as_u64().unwrap();
        match message["method"].as_str().unwrap() {
            "shell.swarm_ready" => {
                ready += 1;
                main.answer(id, json!({ "ok": true }));
            }
            "shell.swarm_api" => {
                assert_eq!(message["params"]["for"], first, "{message}");
                assert_eq!(message["params"]["form"], "feed_latest");
                calls.push(id);
            }
            other => panic!("{other}"),
        }
    }
    let held = main.world(json!({}));
    assert_eq!(held["streams"], 1, "{held}");
    // No second call while the first's stream is open.
    assert!(
        main.core
            .recv_wire_within(Duration::from_millis(300))
            .is_none()
    );
    main.answer(calls[0], feed_head(5));
    main.core
        .send_raw(&stream_frame(KIND_DATA, calls[0], b"hello"));
    assert!(matches!(
        main.core.recv_wire(),
        Wire::Stream {
            kind: KIND_STREAM_CREDIT,
            ..
        }
    ));
    main.core.send_raw(&stream_frame(KIND_END, calls[0], b""));
    // The first answers; the second's call goes.
    let mut answered = Vec::new();
    while answered.len() < 2 {
        let message = main.recv();
        match message["type"].as_str().unwrap() {
            "response" => answered.push(message["id"].as_u64().unwrap()),
            "request" => {
                assert_eq!(message["method"], "shell.swarm_api");
                assert_eq!(message["params"]["for"], second);
                let id = message["id"].as_u64().unwrap();
                main.answer(id, feed_head(2));
                main.core.send_raw(&stream_frame(KIND_DATA, id, b"hi"));
                main.core.send_raw(&stream_frame(KIND_END, id, b""));
            }
            other => panic!("{other}: {message}"),
        }
    }
    assert_eq!(answered, [first, second]);
    settled(&mut main);
}

/// A 1 MiB `/stamps` reply, fragmented, is reassembled within its bound
/// (`b64(1 MiB) + 16 KiB`), and the upload goes on; one whose begin is past
/// the bound is a protocol error, before anything is reserved.
#[test]
fn a_fragmented_megabyte_reply_within_its_bound_and_past_it() {
    for (extra, ok) in [(0usize, true), (16 * 1024, false)] {
        let mut main = main_with(&[]);
        let request = main.request(&page(SITE), &publish_inline(b"0123456789"));
        loop {
            let message = main.recv();
            let id = message["id"].as_u64().unwrap();
            match message["method"].as_str() {
                Some("shell.swarm_ready") => main.answer(id, json!({ "ok": true })),
                Some("approval.recheck") => {
                    main.answer(id, json!({ "live": true, "agent": false }));
                }
                Some("shell.swarm_api") => {
                    assert_eq!(message["params"]["form"], "stamps");
                    // One batch, padded with JSON's white space to the
                    // form's 1 MiB cap, and past it by `extra`.
                    let mut body = STAMPS.as_bytes().to_vec();
                    body.resize(1024 * 1024 + extra, b' ');
                    let reply = json!({ "type": "response", "id": id, "result": {
                        "status": 200, "status_text": "OK", "headers": [],
                        "body_base64": b64(&body),
                    } });
                    // Past the bound, the begin alone ends the core: no
                    // fragment of it is read.
                    let frames = common::fragmented(&reply, 8);
                    let frames = if ok { &frames[..] } else { &frames[..1] };
                    for frame in frames {
                        main.core.send_raw(frame);
                    }
                    break;
                }
                other => panic!("{other:?}: {message}"),
            }
        }
        if !ok {
            ended_with(&mut main, "begin_over_bound");
            continue;
        }
        // Reassembled: the upload goes on to its call.
        loop {
            let message = main.recv();
            let id = message["id"].as_u64().unwrap();
            match message["method"].as_str() {
                Some("approval.recheck") => {
                    main.answer(id, json!({ "live": true, "agent": false }));
                }
                Some("shell.swarm_api") => {
                    assert_eq!(message["params"]["form"], "bzz_file", "{message}");
                    main.answer(
                        id,
                        json!({ "status": 201, "status_text": "Created",
                            "headers": [["swarm-tag", "7"]],
                            "body_base64": b64(format!(r#"{{"reference":"{REFERENCE}"}}"#).as_bytes()) }),
                    );
                }
                None if id == request => {
                    assert!(message["result"]["result_typed"].is_object(), "{message}");
                    break;
                }
                other => panic!("{other:?}: {message}"),
            }
        }
        settled(&mut main);
    }
}
