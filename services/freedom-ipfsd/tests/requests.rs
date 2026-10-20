//! `ipfs.request` through the binary (design 0007, "Methods", "Frames",
//! "Cancel, deadlines and admission", "Errors" and "Panics"): a persistent
//! process over a store seeded with blocks, offline, so nothing touches the
//! network.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};

/// Lets a request's own headers hold or panic its work (src/testhooks.rs).
const HOOKS: (&str, &str) = ("FREEDOM_IPFSD_TEST_REQUEST_HOOKS", "1");
/// The service's admission bound.
const ADMITTED: usize = 512;
/// The credit window.
const WINDOW: usize = 128 << 10;

fn bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// A persistent process over a store seeded with `blocks`, its instance
/// `p-1` started; and the blocks' CIDs.
fn serving(dirs: &Dirs, blocks: &[Vec<u8>], env: &[(&str, &str)]) -> (Ipfsd, Vec<String>) {
    let cids = seed(dirs, blocks);
    let mut ipfsd = Ipfsd::persistent(dirs, env);
    ipfsd.hello();
    let started = ipfsd.start(disk("p-1"));
    assert_eq!(started["result"]["instance"], "p-1", "{started}");
    (ipfsd, cids)
}

/// A `GET` whose work a test hook holds or panics at `phase`.
fn hooked(instance: &str, path: &str, hook: &str, phase: &str, headers_ms: u64) -> Value {
    json!({ "instance": instance, "method": "GET", "path": path,
        "headers": [[hook, phase]], "headers_ms": headers_ms })
}

fn held(instance: &str, path: &str, phase: &str) -> Value {
    hooked(instance, path, "x-freedom-test-hold", phase, 30_000)
}

/// Sends `params` until a request is admitted rather than `busy`: a slot
/// is released once a request's work has ended and its outcome is written,
/// a moment after main reads it. Returns the admitted request's ID, or
/// `None` if none was within 10 s.
fn admitted_eventually(ipfsd: &mut Ipfsd, params: &Value) -> Option<u64> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let id = ipfsd.request("ipfs.request", params.clone());
        let reply = ipfsd.reply(id);
        if reply["error"]["code"] != "busy" {
            assert!(reply["result"]["status"].is_number(), "{reply}");
            return Some(id);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// Sends `params` until a request is refused `busy`: the slot of a request
/// that just ended is released a moment after main reads its end. Returns
/// the refusal; panics if every request within 10 s was admitted.
fn admitted_eventually_busy(ipfsd: &mut Ipfsd, params: &Value) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let id = ipfsd.request("ipfs.request", params.clone());
        let reply = ipfsd.reply(id);
        if reply["error"]["code"] == "busy" {
            return reply;
        }
        let _ = ipfsd.body(id);
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("never busy")
}

fn shut_down(mut ipfsd: Ipfsd) -> String {
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    ipfsd.stderr()
}

#[test]
fn a_request_streams_its_body_from_the_store_under_credit() {
    let dirs = Dirs::new();
    let big = bytes(600 << 10, 1);
    let small = bytes(1000, 2);
    let (mut ipfsd, cids) = serving(&dirs, &[big.clone(), small.clone()], &[]);

    let id = ipfsd.request("ipfs.request", get("p-1", &format!("/ipfs/{}", cids[0])));
    let head = ipfsd.reply(id);
    assert_eq!(head["result"]["status"], 200, "{head}");
    assert_eq!(head["result"]["body"], true, "{head}");
    let headers = head["result"]["headers"].as_array().unwrap();
    assert!(
        headers
            .iter()
            .all(|pair| pair.as_array().is_some_and(|pair| pair.len() == 2)),
        "{head}"
    );
    // Without credit: the window, in frames of at most 64 KiB, then
    // nothing more.
    let mut body = Vec::new();
    while body.len() < WINDOW {
        let frame = ipfsd.stream(id);
        assert_eq!(frame["stream"], "data", "{frame}");
        let chunk = unhex(frame["hex"].as_str().unwrap());
        assert!(!chunk.is_empty() && chunk.len() <= 64 << 10);
        body.extend_from_slice(&chunk);
    }
    assert_eq!(body.len(), WINDOW);
    assert!(
        !ipfsd.stream_frame_within(id, Duration::from_millis(500)),
        "nothing past the window without credit"
    );
    // With credit as it is consumed: the rest, then `end`.
    ipfsd.credit(id, u32::try_from(WINDOW).unwrap());
    let (rest, terminal) = ipfsd.body(id);
    body.extend_from_slice(&rest);
    assert_eq!(terminal["stream"], "end", "{terminal}");
    assert_eq!(body.len(), big.len());
    assert!(body == big, "the body is the block's bytes");

    // A range of the small one: 206, and those bytes.
    let id = ipfsd.request(
        "ipfs.request",
        json!({ "instance": "p-1", "method": "GET", "path": format!("/ipfs/{}", cids[1]),
            "headers": [["range", "bytes=0-9"]], "headers_ms": 30000 }),
    );
    let head = ipfsd.reply(id);
    assert_eq!(head["result"]["status"], 206, "{head}");
    let (range, terminal) = ipfsd.body(id);
    assert_eq!(
        (range.as_slice(), &terminal["stream"]),
        (&small[..10], &json!("end"))
    );

    // HEAD: the head says no body, and no stream opens.
    let id = ipfsd.request(
        "ipfs.request",
        json!({ "instance": "p-1", "method": "HEAD", "path": format!("/ipfs/{}", cids[1]),
            "headers": [], "headers_ms": 30000 }),
    );
    let head = ipfsd.reply(id);
    assert_eq!(
        (&head["result"]["status"], &head["result"]["body"]),
        (&json!(200), &json!(false)),
        "{head}"
    );
    assert!(!ipfsd.stream_frame_within(id, Duration::from_millis(300)));
    shut_down(ipfsd);
}

#[test]
fn admission_is_bounded_at_512_and_a_cancel_before_the_head_frees_its_slot() {
    let dirs = Dirs::new();
    let (mut ipfsd, cids) = serving(&dirs, &[bytes(1000, 3)], &[HOOKS]);
    let path = format!("/ipfs/{}", cids[0]);
    let ids: Vec<u64> = (0..ADMITTED)
        .map(|_| ipfsd.request("ipfs.request", held("p-1", &path, "head")))
        .collect();
    let refused = ipfsd.call("ipfs.request", get("p-1", &path));
    assert_eq!(refused["error"]["code"], "busy", "{refused}");
    // Cancelled before its head: `cancelled`, and once its work has ended,
    // its slot is free again.
    ipfsd.cancel(ids[0]);
    assert_eq!(ipfsd.reply(ids[0])["error"]["code"], "cancelled");
    let admitted = admitted_eventually(&mut ipfsd, &get("p-1", &path)).expect("a slot freed");
    let (_, terminal) = ipfsd.body(admitted);
    assert_eq!(terminal["stream"], "end");
    // The other 511 are still held, and admitted: one more fills the
    // bound again.
    ipfsd.request("ipfs.request", held("p-1", &path, "head"));
    let refused = admitted_eventually_busy(&mut ipfsd, &get("p-1", &path));
    assert_eq!(refused["error"]["code"], "busy", "{refused}");
    shut_down(ipfsd);
}

#[test]
fn an_open_stream_keeps_its_slot_until_its_end_is_written() {
    let dirs = Dirs::new();
    let body = bytes(WINDOW, 11);
    let (mut ipfsd, cids) = serving(&dirs, std::slice::from_ref(&body), &[HOOKS]);
    let path = format!("/ipfs/{}", cids[0]);
    for _ in 1..ADMITTED {
        ipfsd.request("ipfs.request", held("p-1", &path, "head"));
    }
    // Main stops reading: the writer blocks inside the body, its `end`
    // queued behind. The work has queued all of it and ended, but its
    // stream is open: it still counts, and the next request is refused.
    ipfsd.pause_reading();
    let id = ipfsd.request("ipfs.request", get("p-1", &path));
    std::thread::sleep(Duration::from_secs(1));
    let refused = ipfsd.request("ipfs.request", get("p-1", &path));
    std::thread::sleep(Duration::from_millis(500));
    ipfsd.resume_reading();
    assert_eq!(ipfsd.reply(refused)["error"]["code"], "busy");
    let (read, terminal) = ipfsd.body(id);
    assert_eq!((read == body, &terminal["stream"]), (true, &json!("end")));
    // Once its `end` is written, its slot is free.
    assert!(
        admitted_eventually(&mut ipfsd, &get("p-1", &path)).is_some(),
        "released once the stream ended"
    );
    shut_down(ipfsd);
}

#[test]
fn a_cancel_after_the_head_aborts_the_stream_and_ends_its_work() {
    let dirs = Dirs::new();
    let (mut ipfsd, cids) = serving(&dirs, &[bytes(300 << 10, 4)], &[HOOKS]);
    let path = format!("/ipfs/{}", cids[0]);
    for _ in 1..ADMITTED {
        ipfsd.request("ipfs.request", held("p-1", &path, "head"));
    }
    // Its head written, its work held before the body.
    let id = ipfsd.request("ipfs.request", held("p-1", &path, "body"));
    let head = ipfsd.reply(id);
    assert_eq!(head["result"]["body"], true, "{head}");
    let refused = ipfsd.call("ipfs.request", get("p-1", &path));
    assert_eq!(refused["error"]["code"], "busy", "{refused}");
    ipfsd.cancel(id);
    let abort = ipfsd.stream(id);
    assert_eq!(
        (&abort["stream"], &abort["code"]),
        (&json!("abort"), &json!("cancelled")),
        "{abort}"
    );
    assert!(
        admitted_eventually(&mut ipfsd, &get("p-1", &path)).is_some(),
        "its work ended, and its slot is free"
    );
    shut_down(ipfsd);
}

#[test]
fn no_head_within_headers_ms_is_deadline_and_ends_the_work() {
    let dirs = Dirs::new();
    let (mut ipfsd, cids) = serving(&dirs, &[bytes(300 << 10, 5)], &[HOOKS]);
    let path = format!("/ipfs/{}", cids[0]);
    for _ in 2..ADMITTED {
        ipfsd.request("ipfs.request", held("p-1", &path, "head"));
    }
    // After the head there is no deadline in the service: a body held past
    // headers_ms isn't cut.
    let streaming = ipfsd.request(
        "ipfs.request",
        hooked("p-1", &path, "x-freedom-test-hold", "body", 300),
    );
    assert_eq!(ipfsd.reply(streaming)["result"]["body"], true);
    let sent = Instant::now();
    let late = ipfsd.request(
        "ipfs.request",
        hooked("p-1", &path, "x-freedom-test-hold", "head", 300),
    );
    let reply = ipfsd.reply(late);
    assert_eq!(reply["error"]["code"], "deadline", "{reply}");
    assert!(sent.elapsed() >= Duration::from_millis(300));
    assert!(
        admitted_eventually(&mut ipfsd, &get("p-1", &path)).is_some(),
        "the late request's work ended, and its slot is free"
    );
    assert!(
        !ipfsd.stream_frame_within(streaming, Duration::from_millis(500)),
        "the open stream is untouched"
    );
    ipfsd.cancel(streaming);
    assert_eq!(ipfsd.stream(streaming)["code"], "cancelled");
    shut_down(ipfsd);
}

#[test]
fn a_request_for_an_instance_that_is_not_live_is_stopped_as_are_those_a_stop_ends() {
    let dirs = Dirs::new();
    let (mut ipfsd, cids) = serving(&dirs, &[bytes(300 << 10, 6)], &[HOOKS]);
    let path = format!("/ipfs/{}", cids[0]);
    let unknown = ipfsd.call("ipfs.request", get("p-9", &path));
    assert_eq!(unknown["error"]["code"], "stopped", "{unknown}");
    // In flight when its instance stops: a head not yet given, and an open
    // stream.
    let waiting = ipfsd.request("ipfs.request", held("p-1", &path, "head"));
    let streaming = ipfsd.request("ipfs.request", held("p-1", &path, "body"));
    assert_eq!(ipfsd.reply(streaming)["result"]["body"], true);
    let stop = ipfsd.stop("p-1");
    assert_eq!(stop["result"]["instance"], "p-1", "{stop}");
    assert_eq!(ipfsd.reply(waiting)["error"]["code"], "stopped");
    let abort = ipfsd.stream(streaming);
    assert_eq!(
        (&abort["stream"], &abort["code"]),
        (&json!("abort"), &json!("stopped")),
        "{abort}"
    );
    // Retired: never served again.
    let retired = ipfsd.call("ipfs.request", get("p-1", &path));
    assert_eq!(retired["error"]["code"], "stopped", "{retired}");
    shut_down(ipfsd);
}

#[test]
fn a_stop_aborts_a_stream_whose_work_has_ended_but_whose_end_is_unwritten() {
    let dirs = Dirs::new();
    // A body of one window: all of it queued without credit, and more than
    // a pipe's buffer.
    let (mut ipfsd, cids) = serving(&dirs, &[bytes(WINDOW, 10)], &[]);
    let path = format!("/ipfs/{}", cids[0]);
    // Main stops reading: the writer blocks inside the first data frame,
    // with the rest of the body and its `end` queued behind it. The work
    // has queued all of it, within the window, and ended.
    ipfsd.pause_reading();
    let id = ipfsd.request("ipfs.request", get("p-1", &path));
    std::thread::sleep(Duration::from_secs(1));
    let stop = ipfsd.request("ipfs.stop", json!({ "instance": "p-1" }));
    std::thread::sleep(Duration::from_secs(1));
    ipfsd.resume_reading();
    assert_eq!(ipfsd.reply(id)["result"]["body"], true);
    // The stream is aborted `stopped`: its queued data and end are purged.
    let mut received = 0;
    let terminal = loop {
        let frame = ipfsd.stream(id);
        if frame["stream"] != "data" {
            break frame;
        }
        received += unhex(frame["hex"].as_str().unwrap()).len();
    };
    assert_eq!(
        (&terminal["stream"], &terminal["code"]),
        (&json!("abort"), &json!("stopped")),
        "{terminal}"
    );
    assert!(received < WINDOW, "{received}");
    assert_eq!(ipfsd.reply(stop)["result"]["instance"], "p-1");
    shut_down(ipfsd);
}

#[test]
fn a_request_panic_is_internal_and_retires_its_instance_only() {
    let dirs = Dirs::new();
    let small = bytes(1000, 7);
    let (mut ipfsd, cids) = serving(&dirs, &[small.clone(), bytes(300 << 10, 8)], &[HOOKS]);
    let (small_path, big_path) = (format!("/ipfs/{}", cids[0]), format!("/ipfs/{}", cids[1]));
    let id = ipfsd.request("ipfs.request", get("p-1", &small_path));
    assert_eq!(ipfsd.reply(id)["result"]["status"], 200);
    assert_eq!(ipfsd.body(id).0, small);

    // Before its head: `internal`. Its instance's other request is stopped,
    // the instance retired, and only then the event.
    let waiting = ipfsd.request("ipfs.request", held("p-1", &small_path, "head"));
    let panicking = ipfsd.request(
        "ipfs.request",
        hooked(
            "p-1",
            &small_path,
            "x-freedom-test-panic",
            "request",
            30_000,
        ),
    );
    let reply = ipfsd.reply(panicking);
    assert_eq!(reply["error"]["code"], "internal", "{reply}");
    assert_eq!(ipfsd.reply(waiting)["error"]["code"], "stopped");
    let retired = ipfsd.event("ipfs.instance_retired");
    assert_eq!(
        retired["data"],
        json!({ "instance": "p-1", "reason": "panic" }),
        "{retired}"
    );
    let fenced = ipfsd.call("ipfs.request", get("p-1", &small_path));
    assert_eq!(fenced["error"]["code"], "stopped", "{fenced}");

    // The process goes on: a new instance serves.
    let started = ipfsd.start(disk("p-2"));
    assert_eq!(started["result"]["instance"], "p-2", "{started}");
    let id = ipfsd.request("ipfs.request", get("p-2", &small_path));
    assert_eq!(ipfsd.reply(id)["result"]["status"], 200);
    assert_eq!(ipfsd.body(id).0, small);

    // Once its head is queued: an abort if the head was written, its only
    // reply `internal` if not.
    let panicking = ipfsd.request(
        "ipfs.request",
        hooked("p-2", &big_path, "x-freedom-test-panic", "body", 30_000),
    );
    let reply = ipfsd.reply(panicking);
    if reply["result"]["body"] == true {
        let abort = ipfsd.stream(panicking);
        assert_eq!(
            (&abort["stream"], &abort["code"]),
            (&json!("abort"), &json!("internal")),
            "{abort}"
        );
    } else {
        assert_eq!(reply["error"]["code"], "internal", "{reply}");
    }
    let retired = ipfsd.event("ipfs.instance_retired");
    assert_eq!(retired["data"]["instance"], "p-2", "{retired}");

    let stderr = shut_down(ipfsd);
    assert_eq!(
        stderr.matches(r#"{"panic":"request"}"#).count(),
        2,
        "{stderr}"
    );
    assert!(!stderr.contains("SECRET"), "{stderr}");
}

#[test]
fn http_failures_are_heads_and_a_panic_retires_one_private_instance_only() {
    let mut ipfsd = Ipfsd::ephemeral(&[HOOKS]);
    ipfsd.hello();
    for instance in ["e-1", "e-2"] {
        let started = ipfsd.start(memory(instance));
        assert_eq!(started["result"]["instance"], instance, "{started}");
    }
    // Nothing is stored and routing is offline: an HTTP failure, as a head
    // with its body, as today.
    let missing = "/ipfs/bafkreibqphrxowsfix3hzojgk7grevwfojnu52chl5g3sg4pfwphq7yepq";
    let id = ipfsd.request("ipfs.request", get("e-1", missing));
    let head = ipfsd.reply(id);
    let status = head["result"]["status"].as_u64().unwrap();
    assert!((400..600).contains(&status), "{head}");
    if head["result"]["body"] == true {
        assert_eq!(ipfsd.body(id).1["stream"], "end");
    }

    // A panic on e-1 retires e-1 alone: e-2's request in flight goes on.
    let waiting = ipfsd.request("ipfs.request", held("e-2", missing, "head"));
    let panicking = ipfsd.request(
        "ipfs.request",
        hooked("e-1", missing, "x-freedom-test-panic", "request", 30_000),
    );
    assert_eq!(ipfsd.reply(panicking)["error"]["code"], "internal");
    let retired = ipfsd.event("ipfs.instance_retired");
    assert_eq!(
        retired["data"],
        json!({ "instance": "e-1", "reason": "panic" })
    );
    assert_eq!(
        ipfsd.call("ipfs.request", get("e-1", missing))["error"]["code"],
        "stopped"
    );
    ipfsd.cancel(waiting);
    assert_eq!(ipfsd.reply(waiting)["error"]["code"], "cancelled");
    let id = ipfsd.request("ipfs.request", get("e-2", missing));
    assert!(ipfsd.reply(id)["result"]["status"].is_number());
    // And the partition's next instance starts.
    assert_eq!(ipfsd.start(memory("e-3"))["result"]["instance"], "e-3");
    shut_down(ipfsd);
}

#[test]
fn malformed_requests_are_invalid_argument() {
    let dirs = Dirs::new();
    let (mut ipfsd, cids) = serving(&dirs, &[bytes(10, 9)], &[]);
    let path = format!("/ipfs/{}", cids[0]);
    let good = get("p-1", &path);
    let mut cases: Vec<Value> = vec![json!(null), json!([1]), json!("p-1")];
    for (member, value) in [
        ("instance", json!("p 1")),
        ("method", json!("POST")),
        ("method", json!(1)),
        ("path", json!("/http/example.com")),
        ("path", json!("")),
        ("headers", json!([["bad name", "x"]])),
        ("headers", json!([["x", "a\nb"]])),
        ("headers_ms", json!(0)),
        ("headers_ms", json!(30_001)),
        ("extra", json!(1)),
    ] {
        let mut params = good.clone();
        params[member] = value;
        cases.push(params);
    }
    for missing in ["instance", "method", "path", "headers", "headers_ms"] {
        let mut params = good.clone();
        params.as_object_mut().unwrap().remove(missing);
        cases.push(params);
    }
    for params in cases {
        let reply = ipfsd.call("ipfs.request", params.clone());
        assert_eq!(
            reply["error"]["code"], "invalid_argument",
            "{params}: {reply}"
        );
        // A fixed message, never the input.
        assert!(
            !reply["error"]["message"]
                .as_str()
                .unwrap()
                .contains("example.com")
        );
    }
    // More distinct header names than a header map holds (24,576), in one
    // frame: refused, not a panic in the parser (freedom-ipfs#39). Main
    // refuses this first, by 0006's 64 KiB of headers.
    let mut params = good.clone();
    params["headers"] = (0..25_000)
        .map(|i| json!([format!("x-h{i}"), ""]))
        .collect();
    let reply = ipfsd.call("ipfs.request", params);
    assert_eq!(
        reply["error"]["code"], "invalid_argument",
        "{}",
        reply["error"]
    );
    // The good one still is.
    let id = ipfsd.request("ipfs.request", good);
    assert_eq!(ipfsd.reply(id)["result"]["status"], 200);
    shut_down(ipfsd);
}
