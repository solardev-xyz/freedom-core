//! The engine's streams through the fake [`Io`] (SWM-4 PR 6): a streamed
//! read's slot and charge, the slots' queue, a cancel at every stage of a
//! stream leaving no stream, charge or route behind, a cancelled stream
//! main never ends, `readData`'s leaves on the hashing pool, an upload's
//! part and body with their credit, the idle bound, a part's file error,
//! `swarm.body`'s refusals and its route's close.

use super::*;
use fc_swarm_provider::machine::{BodyAbort, stream_charge};

const OWNER: &str = "1111111111111111111111111111111111111111";

/// An engine with `bounds` (the tests' `engine`, which a test's own
/// `engine` would hide).
fn fresh(bounds: Bounds) -> Engine {
    engine(bounds)
}

/// A `readFeedEntry` of the latest entry of topic `t` (one byte, repeated)
/// by `OWNER`.
fn latest(t: u8) -> Result<Params, &'static str> {
    let topic = format!("{t:02x}").repeat(32);
    params(
        "swarm_readFeedEntry",
        Value::object([("topic", Value::str(&topic)), ("owner", Value::str(OWNER))]),
        None,
    )
}

/// The latest entry's head for `len` bytes.
fn feed_head(len: usize) -> String {
    serde_json::json!({ "status": 200, "status_text": "OK", "headers": [
        ["content-type", "application/octet-stream"], ["content-length", len.to_string()],
        ["swarm-feed-index", "0000000000000000"], ["swarm-feed-index-next", "0000000000000001"],
    ] })
    .to_string()
}

/// Request `id`, a latest read, to its streamed call if one goes: main's
/// ID for its readiness check.
fn to_ready(engine: &mut Engine, io: &mut Fake, id: u64, t: u8) -> u64 {
    engine
        .request(io, 0, id, latest(t), Some(page(None)))
        .unwrap();
    let (ready, method, _) = io.last();
    assert_eq!(method, "shell.swarm_ready");
    ready
}

/// Request `id`, a latest read, to its streamed call: main's ID for it.
fn to_stream(engine: &mut Engine, io: &mut Fake, id: u64, t: u8) -> u64 {
    let ready = to_ready(engine, io, id, t);
    engine.response(io, 0, ready, Ok(ok_ready())).unwrap();
    let (call, method, params) = io.last();
    assert_eq!(method, "shell.swarm_api");
    assert_eq!(params["form"], "feed_latest");
    assert_eq!(params["stream"], true);
    assert_eq!(io.opens.get(&call), Some(&Codes::SwarmPiece));
    call
}

/// What a latest read reserves: its `max_bytes`, the site's `maxBytes`.
fn read_charge(io: &Fake, call: u64) -> usize {
    let (_, _, params, _) = io.sent.iter().find(|s| s.0 == call).unwrap();
    stream_charge(usize::try_from(params["max_bytes"].as_u64().unwrap()).unwrap())
}

/// Nothing held: no charge, request or stream.
fn nothing_held(engine: &Engine) {
    assert_eq!(engine.memory_used(), 0, "a charge held");
    assert_eq!(engine.requests(), 0, "a request held");
    assert_eq!(engine.streams_held(), 0, "a stream's slot held");
}

#[test]
fn a_streamed_read_holds_its_slot_and_its_charge_to_its_answer() {
    let mut engine = fresh(Bounds::default());
    let mut io = Fake::default();
    let call = to_stream(&mut engine, &mut io, 1, 0xaa);
    let charge = read_charge(&io, call);
    assert_eq!(engine.memory_used(), BASE + charge);
    assert_eq!(engine.streams_held(), 1);
    engine
        .response(&mut io, 0, call, Ok(&feed_head(10)))
        .unwrap();
    assert_eq!(io.replied, [(call, Some(None))]);
    engine
        .stream_data(&mut io, 0, call, b"the latest".to_vec())
        .unwrap();
    // A read lets its bytes go at once: their credit goes back.
    assert_eq!(io.credits, [(call, 10)]);
    assert_eq!(engine.streams_held(), 1);
    engine.stream_end(&mut io, 0, call, None).unwrap();
    let Answer::Result(text) = io.answer_of(1) else {
        panic!()
    };
    assert!(text.contains("dGhlIGxhdGVzdA=="), "{text}");
    // The stream's slot and route go at its end; its charge, now the
    // result's, once the answer is written.
    assert_eq!(engine.streams_held(), 0);
    assert_eq!(io.forgotten, [StreamKey::Piece(call)]);
    assert_eq!(engine.memory_used(), BASE + charge);
    engine.written(&mut io, 0, 1).unwrap();
    nothing_held(&engine);
}

#[test]
fn a_streamed_reply_answered_whole_lets_go_at_once() {
    let mut engine = fresh(Bounds::default());
    let mut io = Fake::default();
    let call = to_stream(&mut engine, &mut io, 1, 0xaa);
    engine
        .response(&mut io, 0, call, Ok(&whole(404, b"")))
        .unwrap();
    assert_eq!(io.replied, [(call, None)]);
    assert_eq!(io.forgotten, [StreamKey::Piece(call)]);
    assert_eq!(engine.streams_held(), 0);
    assert!(matches!(io.answer_of(1), Answer::Result(_)));
    engine.written(&mut io, 0, 1).unwrap();
    nothing_held(&engine);
}

#[test]
fn a_streamed_call_waits_for_a_streams_slot() {
    let mut engine = fresh(Bounds {
        streams: 1,
        ..Bounds::default()
    });
    let mut io = Fake::default();
    let first = to_stream(&mut engine, &mut io, 1, 0xaa);
    let ready = to_ready(&mut engine, &mut io, 2, 0xbb);
    engine.response(&mut io, 0, ready, Ok(ok_ready())).unwrap();
    // The second's call holds its charge and its call's slot, and waits.
    assert_eq!(io.last().0, ready);
    assert!(
        stages(&engine, 2).contains("Streams"),
        "{:?}",
        stages(&engine, 2)
    );
    engine
        .response(&mut io, 0, first, Ok(&feed_head(1)))
        .unwrap();
    engine.stream_data(&mut io, 0, first, vec![7]).unwrap();
    assert_eq!(io.last().0, ready, "still waiting while the first streams");
    engine.stream_end(&mut io, 0, first, None).unwrap();
    let (second, method, params) = io.last();
    assert_eq!(method, "shell.swarm_api");
    assert_eq!(params["for"], 2);
    assert_eq!(engine.streams_held(), 1);
    engine
        .response(&mut io, 0, second, Ok(&whole(500, b"")))
        .unwrap();
    for id in [1, 2] {
        let _ = io.answer_of(id);
        engine.written(&mut io, 0, id).unwrap();
    }
    nothing_held(&engine);
}

/// A cancel at each stage of a streamed call: waiting for its charge, for
/// its call's slot, for a stream's slot, for the gate, sent, and streaming.
/// Each leaves no stream, charge or route behind once main has ended what
/// it opened.
#[test]
fn a_cancel_at_each_stage_of_a_stream_leaves_nothing() {
    // Waiting for its charge: the pool holds only the base.
    let mut engine = fresh(Bounds {
        memory: BASE + 1024,
        ..Bounds::default()
    });
    let mut io = Fake::default();
    let ready = to_ready(&mut engine, &mut io, 1, 0xaa);
    engine.response(&mut io, 0, ready, Ok(ok_ready())).unwrap();
    assert!(stages(&engine, 1).contains("Memory"));
    engine.cancel(&mut io, 0, 1).unwrap();
    assert!(matches!(io.answer_of(1), Answer::Error(_)));
    engine.written(&mut io, 0, 1).unwrap();
    nothing_held(&engine);

    // Waiting for its call's slot, and for a stream's slot.
    for (bounds, stage) in [
        (
            Bounds {
                api: 0,
                ..Bounds::default()
            },
            "Slot",
        ),
        (
            Bounds {
                streams: 0,
                ..Bounds::default()
            },
            "Streams",
        ),
    ] {
        let mut engine = fresh(bounds);
        let mut io = Fake::default();
        let ready = to_ready(&mut engine, &mut io, 1, 0xaa);
        engine.response(&mut io, 0, ready, Ok(ok_ready())).unwrap();
        assert!(stages(&engine, 1).contains(stage), "{stage}");
        engine.cancel(&mut io, 0, 1).unwrap();
        let _ = io.answer_of(1);
        engine.written(&mut io, 0, 1).unwrap();
        nothing_held(&engine);
        assert!(io.forgotten.is_empty(), "nothing routed");
    }

    // Waiting for the gate, a stream's slot taken.
    let mut engine = fresh(Bounds::default());
    let mut io = Fake::default();
    let ready = to_ready(&mut engine, &mut io, 1, 0xaa);
    io.full = true;
    engine.response(&mut io, 0, ready, Ok(ok_ready())).unwrap();
    assert!(stages(&engine, 1).contains("Outbox"));
    assert_eq!(engine.streams_held(), 1);
    engine.cancel(&mut io, 0, 1).unwrap();
    let _ = io.answer_of(1);
    engine.written(&mut io, 0, 1).unwrap();
    nothing_held(&engine);

    // Sent, its head not yet come: cancelled at main, which opens the
    // stream all the same; it retires until main's terminal.
    let mut engine = fresh(Bounds::default());
    let mut io = Fake::default();
    let call = to_stream(&mut engine, &mut io, 1, 0xaa);
    engine.cancel(&mut io, 0, 1).unwrap();
    assert_eq!(io.cancels, [call]);
    let _ = io.answer_of(1);
    engine.written(&mut io, 0, 1).unwrap();
    engine
        .response(&mut io, 0, call, Ok(&feed_head(5)))
        .unwrap();
    assert_eq!(engine.streams_held(), 1, "the slot until main's terminal");
    assert!(engine.memory_used() > 0, "the charge until main's terminal");
    engine.stream_retired(&mut io, 0, call).unwrap();
    assert_eq!(io.forgotten, [StreamKey::Piece(call)]);
    nothing_held(&engine);

    // Streaming: its credit stops, and it retires until main's terminal.
    let mut engine = fresh(Bounds::default());
    let mut io = Fake::default();
    let call = to_stream(&mut engine, &mut io, 1, 0xaa);
    engine
        .response(&mut io, 0, call, Ok(&feed_head(5)))
        .unwrap();
    engine.stream_data(&mut io, 0, call, vec![1, 2]).unwrap();
    engine.cancel(&mut io, 0, 1).unwrap();
    assert_eq!(io.cancels, [call]);
    let _ = io.answer_of(1);
    engine.written(&mut io, 0, 1).unwrap();
    assert_eq!(engine.streams_held(), 1);
    engine.stream_retired(&mut io, 0, call).unwrap();
    assert_eq!(io.forgotten, [StreamKey::Piece(call)]);
    nothing_held(&engine);
}

#[test]
fn a_cancelled_stream_main_never_ends_ends_the_connection() {
    let mut engine = fresh(Bounds {
        idle_ms: 1000,
        ..Bounds::default()
    });
    let mut io = Fake::default();
    let call = to_stream(&mut engine, &mut io, 1, 0xaa);
    engine
        .response(&mut io, 0, call, Ok(&feed_head(5)))
        .unwrap();
    engine.cancel(&mut io, 100, 1).unwrap();
    assert_eq!(engine.next_due(), Some(1100));
    engine.tick(&mut io, 1099).unwrap();
    assert_eq!(
        engine.tick(&mut io, 1100),
        Err(Fault("swarm_stream_unterminated"))
    );
}

/// Request 1, a `readData` of a two-leaf file, to its leaves' check on
/// the hashing pool: the job, as the pool takes it.
fn to_hashing(engine: &mut Engine, io: &mut Fake) -> (u64, AskId, Job) {
    let data: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    let mut chunker = fc_swarm::chunker::Chunker::new();
    chunker.write(&data, &mut |_| {}).unwrap();
    let root = chunker.finish(&mut |_| {});
    let reference: String = root.address().iter().map(|b| format!("{b:02x}")).collect();
    engine
        .request(
            io,
            0,
            1,
            params(
                "swarm_readData",
                Value::object([("reference", Value::str(&reference))]),
                None,
            ),
            Some(page(None)),
        )
        .unwrap();
    let (ready, _, _) = io.last();
    engine.response(io, 0, ready, Ok(ok_ready())).unwrap();
    let (root_call, _, params) = io.last();
    assert_eq!(params["form"], "chunk");
    engine
        .response(io, 0, root_call, Ok(&whole(200, &root.wire())))
        .unwrap();
    let (bytes, _, params) = io.last();
    assert_eq!(params["form"], "bytes");
    assert_eq!(
        params["headers"],
        serde_json::json!([["range", "bytes=0-8191"]])
    );
    let head =
        serde_json::json!({ "status": 206, "status_text": "Partial Content", "headers": [] });
    engine
        .response(io, 0, bytes, Ok(&head.to_string()))
        .unwrap();
    engine
        .stream_data(io, 0, bytes, data[..4096].to_vec())
        .unwrap();
    engine
        .stream_data(io, 0, bytes, data[4096..].to_vec())
        .unwrap();
    engine.stream_end(io, 0, bytes, None).unwrap();
    assert_eq!(io.hashes.len(), 1);
    io.hashes.pop().unwrap()
}

/// `readData`: the root, the leaves' ranged stream, their check on the
/// hashing pool, and the answer once it's back.
#[test]
fn read_data_checks_its_leaves_on_the_hashing_pool() {
    let mut engine = fresh(Bounds::default());
    let mut io = Fake::default();
    let (id, ask, job) = to_hashing(&mut engine, &mut io);
    assert_eq!(id, 1);
    assert!(io.answers.is_empty(), "the request waits for the pool");
    engine.hashed(&mut io, 0, id, ask, job.run()).unwrap();
    let Answer::Result(text) = io.answer_of(1) else {
        panic!()
    };
    assert!(text.starts_with(r#"{"result_typed":"#), "{text}");
    engine.written(&mut io, 0, 1).unwrap();
    nothing_held(&engine);
}

/// A request cancelled while its leaves are on the pool is answered at
/// once, and held, with its charge, until the job is back.
#[test]
fn a_hashing_job_holds_its_request_past_its_cancel() {
    let mut engine = fresh(Bounds::default());
    let mut io = Fake::default();
    let (id, ask, job) = to_hashing(&mut engine, &mut io);
    engine.cancel(&mut io, 0, 1).unwrap();
    assert!(matches!(io.answer_of(1), Answer::Error(e) if e.code == ErrorCode::Cancelled));
    engine.written(&mut io, 0, 1).unwrap();
    assert_eq!(engine.requests(), 1, "held for its job");
    assert!(engine.memory_used() > 0, "and the bytes it holds");
    engine.hashed(&mut io, 0, id, ask, job.run()).unwrap();
    nothing_held(&engine);
}

// ---------------------------------------------------------------------------
// An upload's part and body.

const STAMPS: &str = r#"{"stamps":[{"batchID":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","utilization":0,"usable":true,"label":"freedom","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000}]}"#;

/// `swarm.body`'s ID, main's.
const BODY: u64 = 900;

fn stubbed() -> Bounds {
    Bounds {
        stub_writes: true,
        idle_ms: 1000,
        ..Bounds::default()
    }
}

/// Request 1, a `publishData` of `n` bytes from part 0, to its streamed
/// upload: main's ID for the `bzz_file` call.
fn to_upload(engine: &mut Engine, io: &mut Fake, n: u64) -> u64 {
    let data = Value::Bytes(fc_swarm_provider::value::Bytes {
        len: n,
        kind: fc_swarm_provider::value::BytesKind::Uint8Array,
        source: fc_swarm_provider::value::Source::Part(0),
        data: true,
    });
    let call = Call {
        method: Value::str("swarm_publishData"),
        params: Value::object([
            ("data", data),
            ("contentType", Value::str("application/octet-stream")),
        ]),
        key: JsString::from(SITE),
        approval: Some(fc_swarm_provider::machine::Approval::User),
    };
    engine
        .request(
            io,
            0,
            1,
            Ok(Params {
                method: call.method,
                params: call.params,
                approval: call.approval,
                deadline_ms: None,
            }),
            Some(page(None)),
        )
        .unwrap();
    loop {
        let (id, method, params) = io.last();
        match method {
            "shell.swarm_ready" => engine.response(io, 0, id, Ok(ok_ready())).unwrap(),
            "approval.recheck" => engine
                .response(io, 0, id, Ok(r#"{"live":true,"agent":false}"#))
                .unwrap(),
            "shell.swarm_api" if params["form"] == "stamps" => engine
                .response(io, 0, id, Ok(&whole(200, STAMPS.as_bytes())))
                .unwrap(),
            "shell.swarm_api" => {
                assert_eq!(params["form"], "bzz_file");
                assert_eq!(params["body"], serde_json::json!({ "stream": n }));
                assert_eq!(io.opens.get(&id), None, "its reply opens no stream");
                return id;
            }
            other => panic!("{other}"),
        }
    }
}

/// Main asks for the call's body: the core's head, then its part's ask.
fn open_body(engine: &mut Engine, io: &mut Fake, call: u64, n: u64) -> u64 {
    engine
        .body_request(io, 0, BODY, Some(&format!(r#"{{"for":{call}}}"#)))
        .unwrap();
    assert_eq!(io.bodies, [(BODY, BodyOut::Head { bytes: n })]);
    let (part, method, params) = io.last();
    assert_eq!(method, "shell.swarm_part");
    assert_eq!(params, serde_json::json!({ "for": 1, "part": 0 }));
    assert_eq!(io.opens.get(&part), Some(&Codes::SwarmPart));
    engine
        .response(io, 0, part, Ok(&format!(r#"{{"bytes":{n}}}"#)))
        .unwrap();
    assert_eq!(io.replied, [(part, Some(Some(n)))]);
    // The part holds a stream's slot; the call, whose reply opens none,
    // doesn't.
    assert_eq!(engine.streams_held(), 1);
    part
}

fn body_bytes(io: &Fake) -> usize {
    io.bodies
        .iter()
        .map(|(_, out)| match out {
            BodyOut::Data(bytes) => bytes.len(),
            _ => 0,
        })
        .sum()
}

fn part_credit(io: &Fake, part: u64) -> usize {
    io.credits
        .iter()
        .filter(|(id, _)| *id == part)
        .map(|(_, n)| n)
        .sum()
}

const FRAME: usize = 64 * 1024;

#[test]
fn a_parts_credit_goes_in_only_when_it_can_go_out() {
    let mut engine = fresh(stubbed());
    let mut io = Fake::default();
    let n = 4 * FRAME as u64;
    let call = to_upload(&mut engine, &mut io, n);
    let part = open_body(&mut engine, &mut io, call, n);
    // Two frames fill the body's window: each goes out, and is credited.
    for _ in 0..2 {
        engine
            .stream_data(&mut io, 0, part, vec![7; FRAME])
            .unwrap();
    }
    assert_eq!(
        (body_bytes(&io), part_credit(&io, part)),
        (2 * FRAME, 2 * FRAME)
    );
    // The third finds the body's window shut: it waits, uncredited.
    engine
        .stream_data(&mut io, 0, part, vec![7; FRAME])
        .unwrap();
    assert_eq!(
        (body_bytes(&io), part_credit(&io, part)),
        (2 * FRAME, 2 * FRAME)
    );
    // Main's credit on the body lets it go, and its credit come.
    engine.body_credit(&mut io, 0, BODY, FRAME).unwrap();
    assert_eq!(
        (body_bytes(&io), part_credit(&io, part)),
        (3 * FRAME, 3 * FRAME)
    );
    engine
        .stream_data(&mut io, 0, part, vec![7; FRAME])
        .unwrap();
    engine.stream_end(&mut io, 0, part, None).unwrap();
    engine.body_credit(&mut io, 0, BODY, 3 * FRAME).unwrap();
    assert_eq!(body_bytes(&io), 4 * FRAME);
    assert_eq!(io.bodies.last(), Some(&(BODY, BodyOut::End)));
    assert!(io.forgotten.contains(&StreamKey::Piece(part)));
    // The node answers: the body's route closes with the call's answer.
    let reply = serde_json::json!({
        "status": 201, "status_text": "Created", "headers": [["swarm-tag", "41"]],
        "body_base64": fc_swarm_provider::value::encode_base64(format!(r#"{{"reference":"{}"}}"#, "b2".repeat(32)).as_bytes()),
    });
    engine
        .response(&mut io, 0, call, Ok(&reply.to_string()))
        .unwrap();
    assert!(io.forgotten.contains(&StreamKey::Body(BODY)));
    assert!(matches!(io.answer_of(1), Answer::Result(text) if text.contains("result_typed")));
    engine.written(&mut io, 0, 1).unwrap();
    nothing_held(&engine);
    // A credit for it after that is main breaking the protocol (D4).
    assert_eq!(
        engine.body_credit(&mut io, 0, BODY, 1),
        Err(Fault("stream_closed"))
    );
    assert_eq!(engine.late_credit(BODY), Err(Fault("stream_closed")));
}

#[test]
fn an_idle_upload_ends_at_its_bound() {
    let mut engine = fresh(stubbed());
    let mut io = Fake::default();
    let n = 4 * FRAME as u64;
    let call = to_upload(&mut engine, &mut io, n);
    let part = open_body(&mut engine, &mut io, call, n);
    for _ in 0..3 {
        engine
            .stream_data(&mut io, 10, part, vec![7; FRAME])
            .unwrap();
    }
    // The bound runs from main's last frame.
    assert_eq!(engine.next_due(), Some(1010));
    engine.tick(&mut io, 1009).unwrap();
    assert!(io.answers.is_empty());
    engine.tick(&mut io, 1010).unwrap();
    // The call and the part cancelled, the body ended, the page answered.
    assert!(
        io.cancels.contains(&call) && io.cancels.contains(&part),
        "{:?}",
        io.cancels
    );
    assert_eq!(
        io.bodies.last(),
        Some(&(BODY, BodyOut::Abort(BodyAbort::Cancelled)))
    );
    let Answer::Result(text) = io.answer_of(1) else {
        panic!()
    };
    assert!(text.starts_with(r#"{"error_typed":"#), "{text}");
    engine.written(&mut io, 0, 1).unwrap();
    // Main's answers to what was cancelled let the rest go.
    engine
        .response(
            &mut io,
            1020,
            call,
            Err(r#"{"code":"cancelled","message":"Cancelled"}"#),
        )
        .unwrap();
    engine.stream_retired(&mut io, 1020, part).unwrap();
    nothing_held(&engine);
    assert!(io.forgotten.contains(&StreamKey::Body(BODY)));
}

#[test]
fn a_parts_file_error_ends_the_upload() {
    let mut engine = fresh(stubbed());
    let mut io = Fake::default();
    let n = 2 * FRAME as u64;
    let call = to_upload(&mut engine, &mut io, n);
    let part = open_body(&mut engine, &mut io, call, n);
    engine
        .stream_data(&mut io, 0, part, vec![7; FRAME])
        .unwrap();
    let code = fc_swarm_provider::machine::ErrorCode::new("ENOENT").unwrap();
    engine
        .stream_end(
            &mut io,
            0,
            part,
            Some(fc_swarm_provider::machine::Abort::Unreadable(code)),
        )
        .unwrap();
    assert_eq!(
        io.bodies.last(),
        Some(&(BODY, BodyOut::Abort(BodyAbort::BodyStreamError)))
    );
    assert!(io.cancels.contains(&call));
    assert!(
        matches!(io.answer_of(1), Answer::Result(text) if text.starts_with(r#"{"error_typed":"#))
    );
    engine.written(&mut io, 0, 1).unwrap();
    engine
        .response(
            &mut io,
            0,
            call,
            Err(r#"{"code":"cancelled","message":"Cancelled"}"#),
        )
        .unwrap();
    nothing_held(&engine);
}

#[test]
fn swarm_body_is_refused_or_ends_the_connection_as_it_names() {
    let mut engine = fresh(stubbed());
    let mut io = Fake::default();
    let call = to_upload(&mut engine, &mut io, 10);
    // Params that don't read, and a call that isn't the core's.
    for (body, params) in [
        (901, Some(r#"{"for":"x"}"#)),
        (902, None),
        (903, Some(r#"{"for":12345}"#)),
    ] {
        engine.body_request(&mut io, 0, body, params).unwrap();
        assert_eq!(
            io.refused.last().map(|(id, e)| (*id, e.code)),
            Some((body, ErrorCode::InvalidArgument))
        );
        assert_eq!(io.forgotten.last(), Some(&StreamKey::Body(body)));
    }
    // The call's body, then a second ask for it: main broke the protocol.
    engine
        .body_request(&mut io, 0, BODY, Some(&format!(r#"{{"for":{call}}}"#)))
        .unwrap();
    assert_eq!(
        engine.body_request(&mut io, 0, BODY + 1, Some(&format!(r#"{{"for":{call}}}"#))),
        Err(Fault("swarm_wrong_kind"))
    );
}

#[test]
fn a_body_main_cancels_closes_its_route() {
    let mut engine = fresh(stubbed());
    let mut io = Fake::default();
    let n = 2 * FRAME as u64;
    let call = to_upload(&mut engine, &mut io, n);
    let part = open_body(&mut engine, &mut io, call, n);
    engine.body_cancelled(&mut io, 0, BODY).unwrap();
    assert_eq!(io.forgotten.last(), Some(&StreamKey::Body(BODY)));
    // Main answers the call as its node failed; the upload ends.
    engine
        .response(&mut io, 0, call, Ok(r#"{"failed":"error"}"#))
        .unwrap();
    assert!(io.cancels.contains(&part));
    assert!(matches!(io.answer_of(1), Answer::Result(_)));
    engine.written(&mut io, 0, 1).unwrap();
    engine.stream_retired(&mut io, 0, part).unwrap();
    nothing_held(&engine);
    assert_eq!(engine.late_credit(BODY), Err(Fault("stream_closed")));
}
