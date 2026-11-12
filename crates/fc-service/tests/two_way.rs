//! A two-way service connection end to end, over OS pipes (design 0014,
//! COL-3): the service's own requests to main, main's bodies in answer to
//! them, and events the service waits to see written. A toy service on one
//! side; on the other the test, playing main with fc-protocol's decoder.

#![cfg(not(any(target_os = "ios", target_os = "android")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::future::Future;
use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver as Channel};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake};
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::frame::{Decoder, Frame, KIND_JSON, Kinds};
use fc_protocol::stream::{Abort, AbortCode, Side, StreamFrame, WINDOW};
use fc_service::Exit;
use fc_service::conn::{
    self, AskFailed, Asked, Body, BodyError, Connection, End, Hello, Options, Request, Service,
};
use serde_json::{Value, json};

/// Blocks on a future with the current thread as its waker.
fn block_on<F: Future>(future: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Arc::new(Unpark(std::thread::current())).into();
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
        std::thread::park_timeout(Duration::from_millis(50));
    }
}

/// Byte `i` of every body here.
fn pattern(from: usize, len: usize) -> Vec<u8> {
    (from..from + len).map(|i| (i % 251) as u8).collect()
}

fn failed(failed: &AskFailed) -> Value {
    match failed {
        AskFailed::Error(error) => json!({ "error": error.code }),
        AskFailed::Deadline => json!("deadline"),
        AskFailed::Closed => json!("closed"),
    }
}

/// Reads a body to its end: its length, whether its bytes are the pattern,
/// and how it ended.
fn read_all(body: &mut Body) -> Value {
    let mut got = Vec::new();
    let ended = loop {
        match block_on(body.chunk()) {
            Ok(Some(chunk)) => {
                assert!(!chunk.is_empty() && chunk.len() <= 64 << 10);
                got.extend_from_slice(&chunk);
            }
            Ok(None) => break json!("end"),
            Err(BodyError::Aborted(abort)) => break json!({ "aborted": abort.code.as_str() }),
            Err(BodyError::Closed) => break json!("closed"),
        }
    };
    // Its end stays its end.
    assert_eq!(block_on(body.chunk()).is_ok(), ended == "end");
    json!({ "len": got.len(), "pattern": got == pattern(0, got.len()), "ended": ended })
}

#[derive(Default)]
struct Toy {
    /// Requests and bodies held unpolled.
    asked: Mutex<Vec<Asked>>,
    bodies: Arc<Mutex<Vec<Body>>>,
    /// What each awaited request came to, as it is replied.
    outcomes: Arc<Mutex<Vec<Value>>>,
    ends: Mutex<Vec<End>>,
    conn: Mutex<Option<Connection>>,
}

impl Service for Toy {
    fn hello(&self, _hello: &Hello) -> Result<serde_json::Map<String, Value>, ErrorBody> {
        Ok(serde_json::Map::new())
    }

    fn request(&self, conn: &Connection, request: Request<'_>) {
        *self.conn.lock().unwrap() = Some(conn.clone());
        let params: Value = request
            .params
            .map(|raw| serde_json::from_str(raw.get()).unwrap())
            .unwrap_or(Value::Null);
        let id = request.id;
        match request.method {
            // Asks main `method` with `params`, within `deadline_ms` if
            // given. `mode`: "await" (the default) answers this request
            // with main's reply, reading a body to its end; "hold" keeps a
            // body unread; "first" reads its first chunk and drops it;
            // "drop" drops the request at once; "unpolled" keeps it
            // without polling it.
            "t.ask" => {
                let deadline = params["deadline_ms"]
                    .as_u64()
                    .map(|ms| Instant::now() + Duration::from_millis(ms));
                let method = params["method"].as_str().unwrap_or("shell.t");
                let asked = match conn.ask(method, &params["params"], deadline) {
                    Ok(asked) => asked,
                    Err(error) => {
                        conn.reply(id, &json!({ "refused": format!("{error:?}") }))
                            .unwrap();
                        return;
                    }
                };
                let asked_id = asked.id();
                let mode = params["mode"].as_str().unwrap_or("await").to_owned();
                match mode.as_str() {
                    "drop" => {
                        drop(asked);
                        conn.reply(id, &json!({ "asked": asked_id })).unwrap();
                        return;
                    }
                    "unpolled" => {
                        self.asked.lock().unwrap().push(asked);
                        conn.reply(id, &json!({ "asked": asked_id })).unwrap();
                        return;
                    }
                    _ => {}
                }
                let conn = conn.clone();
                let bodies = self.bodies.clone();
                let outcomes = self.outcomes.clone();
                std::thread::spawn(move || {
                    let answer = match block_on(asked) {
                        Ok(answer) => answer,
                        Err(error) => {
                            let outcome = json!({ "asked": asked_id, "failed": failed(&error) });
                            outcomes.lock().unwrap().push(outcome.clone());
                            let _ = conn.reply(id, &outcome);
                            return;
                        }
                    };
                    let result: Value = serde_json::from_str(answer.result.get()).unwrap();
                    let mut outcome = json!({ "asked": asked_id, "result": result });
                    if let Some(mut body) = answer.body {
                        assert_eq!(body.id(), asked_id);
                        match mode.as_str() {
                            // Kept for the test's length.
                            "hold" => {
                                outcome["held"] = json!(true);
                                bodies.lock().unwrap().push(body);
                            }
                            "first" => {
                                let first = block_on(body.chunk()).unwrap().unwrap();
                                outcome["first"] = json!(first.len());
                            }
                            _ => outcome["body"] = read_all(&mut body),
                        }
                    }
                    outcomes.lock().unwrap().push(outcome.clone());
                    let _ = conn.reply(id, &outcome);
                });
            }
            // How many of its requests the connection holds.
            "t.asks" => conn.reply(id, &json!({ "asks": conn.asks() })).unwrap(),
            // An event waited for until written, within `wait_ms`: this
            // request's reply says how that went. A marker that may still
            // arrive is cleared first, ahead of the reply, as 0014's step
            // marker is: `t.stepped`.
            "t.mark" => {
                let wait = Duration::from_millis(params["wait_ms"].as_u64().unwrap());
                let conn = conn.clone();
                std::thread::spawn(move || {
                    let marked = conn.event_written("t.marked", &json!({ "n": id }), wait);
                    if marked == Err(fc_service::conn::WrittenError::Unfinished) {
                        conn.event_for(id, "t.stepped", &json!({ "n": id }))
                            .unwrap();
                    }
                    conn.reply(id, &json!({ "marked": format!("{marked:?}") }))
                        .unwrap();
                });
            }
            // A plain event, then the reply.
            "t.event" => {
                conn.event(params["name"].as_str().unwrap(), &json!({}))
                    .unwrap();
                conn.reply(id, &Value::Null).unwrap();
            }
            // A body of the service's own, never ended: `len` bytes queued.
            "t.hang" => {
                conn.head(id, &json!({ "body": true }), true).unwrap();
                let len = params["len"].as_u64().unwrap() as usize;
                assert_eq!(conn.push(id, &pattern(0, len)).unwrap(), len);
            }
            "t.echo" => conn.reply(id, &json!({ "echo": params })).unwrap(),
            _ => conn
                .reply_error(id, &ErrorBody::new(ErrorCode::UnknownMethod, "unknown"))
                .unwrap(),
        }
    }

    fn cancel(&self, _conn: &Connection, _id: u64) {}

    fn end(&self, _conn: &Connection, end: End) {
        self.ends.lock().unwrap().push(end);
        // What the service held goes with the connection.
        self.asked.lock().unwrap().clear();
        self.bodies.lock().unwrap().clear();
    }
}

/// Holds the writer inside the write of the first frame whose JSON has
/// `needle`, before any of its bytes reach the pipe, until released.
#[derive(Clone, Default)]
struct Gate {
    needle: Arc<Mutex<Option<String>>>,
    state: Arc<(Mutex<(bool, bool)>, Condvar)>,
}

impl Gate {
    fn on(needle: &str) -> Gate {
        let gate = Gate::default();
        *gate.needle.lock().unwrap() = Some(needle.to_owned());
        gate
    }

    /// Waits until the writer is held.
    fn held(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut state = self.state.0.lock().unwrap();
        while !state.0 {
            let left = deadline
                .checked_duration_since(Instant::now())
                .expect("the write never began");
            state = self.state.1.wait_timeout(state, left).unwrap().0;
        }
    }

    fn release(&self) {
        self.state.0.lock().unwrap().1 = true;
        self.state.1.notify_all();
    }
}

struct Gated {
    pipe: std::io::PipeWriter,
    gate: Gate,
}

impl Write for Gated {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let needle = self.gate.needle.lock().unwrap().clone();
        let ours = needle.is_some_and(|needle| {
            bytes.len() > 5
                && bytes[4] == KIND_JSON
                && String::from_utf8_lossy(&bytes[5..]).contains(&needle)
        });
        if ours {
            *self.gate.needle.lock().unwrap() = None;
            let mut state = self.gate.state.0.lock().unwrap();
            state.0 = true;
            self.gate.state.1.notify_all();
            while !state.1 {
                state = self.gate.state.1.wait(state).unwrap();
            }
        }
        self.pipe.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.pipe.flush()
    }
}

/// Main's side of a running connection.
struct Main {
    to_service: Option<std::io::PipeWriter>,
    chunks: Channel<Vec<u8>>,
    decoder: Decoder,
    pending: VecDeque<Frame>,
    exit: Channel<Exit>,
    toy: Arc<Toy>,
    /// Credit the service returned, per stream of main's.
    credit: std::collections::BTreeMap<u64, u64>,
}

fn options() -> Options {
    let mut options = Options::new("t", 1, Instant::now());
    options.exit_watchdog = None;
    options.two_way = true;
    options
}

fn start(options: Options) -> Main {
    start_with(options, None)
}

fn start_with(options: Options, gate: Option<Gate>) -> Main {
    let (stdin_reader, stdin_writer) = std::io::pipe().unwrap();
    let (mut stdout_reader, stdout_writer) = std::io::pipe().unwrap();
    let toy = Arc::new(Toy::default());
    let (exit_tx, exit) = mpsc::channel();
    let service = toy.clone();
    // A two-way connection's main reads all four stream kinds; a one-way
    // one's, the service's three.
    let side = if options.two_way {
        Side::Both
    } else {
        Side::Receiver
    };
    std::thread::spawn(move || {
        let exit = match gate {
            Some(gate) => conn::run(
                service,
                options,
                stdin_reader,
                Gated {
                    pipe: stdout_writer,
                    gate,
                },
            ),
            None => conn::run(service, options, stdin_reader, stdout_writer),
        };
        let _ = exit_tx.send(exit);
    });
    let (chunk_tx, chunks) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buffer = vec![0u8; 65536];
        while let Ok(n) = stdout_reader.read(&mut buffer) {
            if n == 0 || chunk_tx.send(buffer[..n].to_vec()).is_err() {
                return;
            }
        }
    });
    let mut main = Main {
        to_service: Some(stdin_writer),
        chunks,
        decoder: Decoder::with_kinds(Kinds::service(side)),
        pending: VecDeque::new(),
        exit,
        toy,
        credit: Default::default(),
    };
    main.request(
        1,
        "t.hello",
        json!({ "protocol": 1, "shell_version": "0.9.0", "frames": ["stream"] }),
    );
    assert_eq!(
        main.message(),
        json!({ "type": "response", "id": 1, "result": { "protocol": 1 } })
    );
    main
}

impl Main {
    fn send(&mut self, bytes: &[u8]) {
        if let Some(pipe) = &mut self.to_service {
            let _ = pipe.write_all(bytes);
        }
    }

    fn json(&mut self, value: Value) {
        let mut out = Vec::new();
        fc_protocol::frame::encode_json(value.to_string().as_bytes(), &mut out).unwrap();
        self.send(&out);
    }

    fn request(&mut self, id: u64, method: &str, params: Value) {
        self.json(json!({ "type": "request", "id": id, "method": method, "params": params }));
    }

    fn respond(&mut self, id: u64, result: Value) {
        self.json(json!({ "type": "response", "id": id, "result": result }));
    }

    fn stream(&mut self, frame: StreamFrame<'_>) {
        let mut out = Vec::new();
        frame.encode(&mut out).unwrap();
        self.send(&out);
    }

    /// Body bytes `from..from + len` of stream `id`, in frames of at most
    /// 64 KiB.
    fn data(&mut self, id: u64, from: usize, len: usize) {
        let bytes = pattern(from, len);
        for chunk in bytes.chunks(64 << 10) {
            self.stream(StreamFrame::Data { id, bytes: chunk });
        }
    }

    fn close(&mut self) {
        self.to_service = None;
    }

    /// The next frame from the service.
    fn frame(&mut self) -> Option<Frame> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return Some(frame);
            }
            let chunk = self.chunks.recv_timeout(Duration::from_secs(10)).ok()?;
            let mut rest = &chunk[..];
            while !rest.is_empty() {
                let consumed = self.decoder.push(rest).unwrap();
                rest = &rest[consumed..];
                while let Some(frame) = self.decoder.pop() {
                    self.pending.push_back(frame);
                }
            }
        }
    }

    /// The next JSON message, with any credit before it counted.
    fn message(&mut self) -> Value {
        loop {
            let frame = self.frame().expect("a frame");
            if frame.kind == KIND_JSON {
                return serde_json::from_slice(&frame.payload).unwrap();
            }
            match StreamFrame::from_frame(&frame).unwrap() {
                StreamFrame::Credit { id, bytes } => {
                    *self.credit.entry(id).or_default() += u64::from(bytes);
                }
                other => panic!("{other:?}"),
            }
        }
    }

    /// Nothing more comes from the service for a while.
    fn quiet(&mut self) {
        if self.pending.is_empty()
            && let Ok(chunk) = self.chunks.recv_timeout(Duration::from_millis(300))
        {
            panic!("unexpected bytes from the service: {chunk:?}");
        }
        assert!(self.pending.is_empty(), "{:?}", self.pending);
    }

    fn exit(&self) -> Exit {
        self.exit.recv_timeout(Duration::from_secs(10)).unwrap()
    }

    fn ends(&self) -> Vec<End> {
        self.toy.ends.lock().unwrap().clone()
    }

    fn asks(&mut self, id: u64) -> Value {
        self.request(id, "t.asks", Value::Null);
        let reply = self.message();
        assert_eq!(reply["id"], id, "{reply}");
        reply["result"]["asks"].clone()
    }
}

#[test]
fn a_request_to_main_is_answered() {
    let mut main = start(options());
    main.request(
        2,
        "t.ask",
        json!({ "method": "shell.t", "params": { "x": [1, 2] } }),
    );
    // The service's own request: its ID space starts at 1, and it has no
    // caller context.
    let asked = main.message();
    assert_eq!(
        asked,
        json!({ "type": "request", "id": 1, "method": "shell.t", "params": { "x": [1, 2] } })
    );
    main.respond(1, json!({ "node": 0 }));
    assert_eq!(
        main.message(),
        json!({ "type": "response", "id": 2, "result": { "asked": 1, "result": { "node": 0 } } })
    );
    // An error reply.
    main.request(3, "t.ask", json!({ "params": null }));
    assert_eq!(main.message()["id"], 2);
    main.json(json!({ "type": "response", "id": 2,
        "error": { "code": "busy", "message": "Colibri fetch busy" } }));
    assert_eq!(
        main.message()["result"],
        json!({ "asked": 2, "failed": { "error": "busy" } })
    );
    assert_eq!(main.asks(4), 0);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
    assert_eq!(main.ends(), [End::Eof]);
}

#[test]
fn main_streams_a_body_under_credit() {
    let mut main = start(options());
    let len = 300_000;
    main.request(2, "t.ask", json!({ "params": {} }));
    assert_eq!(main.message()["id"], 1);
    main.respond(1, json!({ "node": 0, "bytes": len, "body": true }));
    // Main sends only as its credit allows: the window, then what the
    // service has taken.
    let mut sent = 0;
    while sent < len {
        let credited = main.credit.get(&1).copied().unwrap_or(0) as usize;
        let room = (credited + WINDOW).saturating_sub(sent).min(len - sent);
        if room == 0 {
            match StreamFrame::from_frame(&main.frame().expect("credit")).unwrap() {
                StreamFrame::Credit { id: 1, bytes } => {
                    *main.credit.entry(1).or_default() += u64::from(bytes);
                }
                other => panic!("{other:?}"),
            }
            continue;
        }
        main.data(1, sent, room);
        sent += room;
    }
    main.stream(StreamFrame::End { id: 1 });
    let reply = main.message();
    assert_eq!(
        reply["result"],
        json!({ "asked": 1, "result": { "node": 0, "bytes": len, "body": true },
            "body": { "len": len, "pattern": true, "ended": "end" } }),
        "{reply}"
    );
    // Credit for every byte taken, never past what was sent.
    assert!(main.credit[&1] as usize <= len);
    assert_eq!(main.asks(3), 0);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

#[test]
fn a_body_past_the_window_is_a_protocol_error() {
    let mut main = start(options());
    main.request(2, "t.ask", json!({ "params": {}, "mode": "hold" }));
    assert_eq!(main.message()["id"], 1);
    main.respond(1, json!({ "body": true }));
    assert_eq!(main.message()["result"]["held"], true);
    // Nothing taken, so nothing credited: the window is all main may send.
    main.data(1, 0, WINDOW);
    main.request(3, "t.echo", json!(3));
    assert_eq!(main.message()["result"]["echo"], 3);
    main.data(1, WINDOW, 1);
    assert_eq!(main.exit(), Exit::Protocol);
    assert_eq!(main.ends(), [End::Protocol("window_overrun")]);
}

#[test]
fn main_ends_a_body_only_with_a_pieces_codes() {
    for code in [
        AbortCode::Cancelled,
        AbortCode::Stalled,
        AbortCode::BodyStreamError,
    ] {
        let mut main = start(options());
        main.request(2, "t.ask", json!({ "params": {} }));
        assert_eq!(main.message()["id"], 1);
        main.respond(1, json!({ "body": true }));
        main.data(1, 0, 1000);
        main.stream(StreamFrame::Abort {
            id: 1,
            abort: Abort::new(code, "m"),
        });
        let reply = main.message();
        assert_eq!(
            reply["result"]["body"],
            json!({ "len": 1000, "pattern": true, "ended": { "aborted": code.as_str() } }),
            "{code:?}"
        );
        assert_eq!(main.asks(3), 0);
        main.close();
        assert_eq!(main.exit(), Exit::Ok);
    }
    // Any other: a service's own five, the core's verified bodies' codes.
    for code in AbortCode::ALL.into_iter().filter(|code| {
        !matches!(
            code,
            AbortCode::Cancelled | AbortCode::Stalled | AbortCode::BodyStreamError
        )
    }) {
        let mut main = start(options());
        main.request(2, "t.ask", json!({ "params": {}, "mode": "hold" }));
        assert_eq!(main.message()["id"], 1);
        main.respond(1, json!({ "body": true }));
        assert_eq!(main.message()["result"]["held"], true);
        main.stream(StreamFrame::Abort {
            id: 1,
            abort: Abort::new(code, "m"),
        });
        assert_eq!(main.exit(), Exit::Protocol, "{code:?}");
        assert_eq!(main.ends(), [End::Protocol("abort_code")], "{code:?}");
    }
}

#[test]
fn a_request_dropped_unanswered_is_cancelled() {
    let mut main = start(options());
    main.request(2, "t.ask", json!({ "params": {}, "mode": "drop" }));
    // The request, then its cancel, in that order, whichever came first.
    let mut seen = Vec::new();
    while seen.len() < 3 {
        seen.push(main.message());
    }
    let request = seen.iter().position(|m| m["type"] == "request").unwrap();
    let cancel = seen.iter().position(|m| m["type"] == "cancel").unwrap();
    assert!(request < cancel, "{seen:?}");
    assert_eq!(seen[cancel], json!({ "type": "cancel", "id": 1 }));
    assert!(seen.iter().any(|m| m["result"]["asked"] == 1));
    // Main still answers it, with a body: dropped as it comes, and the
    // record goes at the stream's end.
    main.respond(1, json!({ "body": true }));
    main.data(1, 0, 70_000);
    assert_eq!(main.asks(3), 1);
    main.stream(StreamFrame::End { id: 1 });
    assert_eq!(main.asks(4), 0);
    // No credit for it, and the connection goes on.
    assert_eq!(main.credit.get(&1), None);
    main.request(5, "t.echo", json!(5));
    assert_eq!(main.message()["result"]["echo"], 5);
    // A reply without a body, after the cancel, is dropped too.
    main.request(6, "t.ask", json!({ "params": {}, "mode": "drop" }));
    let mut seen = Vec::new();
    while seen.len() < 3 {
        seen.push(main.message());
    }
    assert!(
        seen.contains(&json!({ "type": "cancel", "id": 2 })),
        "{seen:?}"
    );
    main.respond(2, json!({ "late": true }));
    assert_eq!(main.asks(7), 0);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

#[test]
fn a_body_dropped_before_its_end_is_cancelled() {
    let mut main = start(options());
    main.request(2, "t.ask", json!({ "params": {}, "mode": "first" }));
    assert_eq!(main.message()["id"], 1);
    main.respond(1, json!({ "body": true }));
    main.data(1, 0, 1000);
    let mut seen = Vec::new();
    while seen.len() < 2 {
        seen.push(main.message());
    }
    assert!(
        seen.contains(&json!({ "type": "cancel", "id": 1 })),
        "{seen:?}"
    );
    assert!(
        seen.iter().any(|m| m["result"]["first"] == 1000),
        "{seen:?}"
    );
    // What main still sends is dropped, its end ends the record.
    main.data(1, 1000, 5000);
    main.stream(StreamFrame::Abort {
        id: 1,
        abort: Abort::cancelled(),
    });
    assert_eq!(main.asks(3), 0);
    // The one chunk taken was credited, as it was taken.
    main.quiet();
    assert!(main.credit.get(&1).copied().unwrap_or(0) <= 1000);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

#[test]
fn a_deadline_cancels_a_request_main_has_not_answered() {
    let mut main = start(options());
    let started = Instant::now();
    main.request(2, "t.ask", json!({ "params": {}, "deadline_ms": 200 }));
    assert_eq!(main.message()["id"], 1);
    let mut seen = Vec::new();
    while seen.len() < 2 {
        seen.push(main.message());
    }
    assert!(started.elapsed() >= Duration::from_millis(200));
    assert!(
        seen.contains(&json!({ "type": "cancel", "id": 1 })),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|m| m["result"] == json!({ "asked": 1, "failed": "deadline" })),
        "{seen:?}"
    );
    // Main's late reply is dropped.
    main.respond(1, json!({ "late": true }));
    assert_eq!(main.asks(3), 0);

    // Nobody polls this one: the lifecycle thread cancels it on time.
    let started = Instant::now();
    main.request(
        4,
        "t.ask",
        json!({ "params": {}, "deadline_ms": 200, "mode": "unpolled" }),
    );
    let mut seen = Vec::new();
    while seen.len() < 2 {
        seen.push(main.message());
    }
    assert!(seen.iter().any(|m| m["result"]["asked"] == 2), "{seen:?}");
    assert_eq!(main.message(), json!({ "type": "cancel", "id": 2 }));
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(200) && took < Duration::from_secs(2),
        "{took:?}"
    );
    // A head that crossed the cancel opens a stream that is dropped.
    main.respond(2, json!({ "body": true }));
    main.data(2, 0, 10);
    main.stream(StreamFrame::End { id: 2 });
    // The future still holds it until the service lets go.
    assert_eq!(main.asks(5), 1);
    main.toy.asked.lock().unwrap().clear();
    assert_eq!(main.asks(6), 0);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

/// 0009's rule, on a service's connection: a stream is the body of a
/// response, numbered by its request, so one number names a stream each
/// way, and a frame's kind says which.
#[test]
fn one_number_names_a_stream_each_way() {
    let mut main = start(options());
    main.request(2, "t.ask", json!({ "params": {} }));
    assert_eq!(main.message()["id"], 1);
    main.request(3, "t.ask", json!({ "params": {} }));
    assert_eq!(main.message()["id"], 2);
    main.respond(2, json!({ "body": true }));
    // Main's request 2's body, from the service: the service's request 2's,
    // from main.
    main.request(4, "t.hang", json!({ "len": 100 }));
    assert_eq!(
        main.message(),
        json!({ "type": "response", "id": 4, "result": { "body": true } })
    );
    match StreamFrame::from_frame(&main.frame().unwrap()).unwrap() {
        StreamFrame::Data { id: 4, bytes } => assert_eq!(bytes, pattern(0, 100)),
        other => panic!("{other:?}"),
    }
    main.data(2, 0, 50);
    main.stream(StreamFrame::Credit { id: 4, bytes: 100 });
    main.stream(StreamFrame::End { id: 2 });
    let reply = main.message();
    assert_eq!(
        reply["result"]["body"],
        json!({ "len": 50, "pattern": true, "ended": "end" }),
        "{reply}"
    );
    main.respond(1, json!({}));
    assert_eq!(main.message()["result"]["asked"], 1);
    // Credit past what the service sent on its stream 4 is still main's
    // protocol error.
    main.stream(StreamFrame::Credit { id: 4, bytes: 1 });
    assert_eq!(main.exit(), Exit::Protocol);
    assert_eq!(main.ends(), [End::Protocol("credit_overgrant")]);
}

#[test]
fn main_breaking_the_service_streams_is_a_protocol_error() {
    for (category, script) in [
        (
            "stream_not_open",
            Box::new(|main: &mut Main| main.data(1, 0, 1)) as Box<dyn Fn(&mut Main)>,
        ),
        (
            "stream_unknown",
            Box::new(|main: &mut Main| main.stream(StreamFrame::End { id: 2 })),
        ),
        (
            "unsolicited_response",
            Box::new(|main: &mut Main| main.respond(2, json!({}))),
        ),
    ] {
        let mut main = start(options());
        main.request(2, "t.ask", json!({ "params": {}, "mode": "unpolled" }));
        let mut seen = Vec::new();
        while seen.len() < 2 {
            seen.push(main.message());
        }
        assert!(seen.iter().any(|m| m["type"] == "request"), "{seen:?}");
        script(&mut main);
        assert_eq!(main.exit(), Exit::Protocol, "{category}");
        assert_eq!(main.ends(), [End::Protocol(category)]);
    }
}

#[test]
fn the_connection_holds_at_most_its_requests() {
    let mut options = options();
    options.max_asks = 2;
    let mut main = start(options);
    for id in [2, 3] {
        main.request(id, "t.ask", json!({ "params": {}, "mode": "unpolled" }));
        let mut seen = Vec::new();
        while seen.len() < 2 {
            seen.push(main.message());
        }
    }
    main.request(4, "t.ask", json!({ "params": {} }));
    assert_eq!(main.message()["result"], json!({ "refused": "Full" }));
    // Answered, still held: then let go of, room again.
    main.respond(1, json!({}));
    main.respond(2, json!({}));
    assert_eq!(main.asks(5), 2);
    main.toy.asked.lock().unwrap().clear();
    assert_eq!(main.asks(6), 0);
    main.request(7, "t.ask", json!({ "params": {} }));
    assert_eq!(main.message()["id"], 3);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

#[test]
fn a_one_way_connection_takes_none_of_it() {
    let mut options = options();
    options.two_way = false;
    let mut main = start(options);
    main.request(2, "t.ask", json!({ "params": {} }));
    assert_eq!(main.message()["result"], json!({ "refused": "OneWay" }));
    // Main's data is refused at its header, as 0007 has it.
    main.data(1, 0, 1);
    assert_eq!(main.exit(), Exit::Protocol);
    assert_eq!(main.ends(), [End::Protocol("stream_direction")]);
}

#[test]
fn an_event_waited_for_is_written_before_the_wait_returns() {
    let mut main = start(options());
    main.request(2, "t.mark", json!({ "wait_ms": 1000 }));
    assert_eq!(
        main.message(),
        json!({ "type": "event", "event": "t.marked", "data": { "n": 2 } })
    );
    assert_eq!(main.message()["result"]["marked"], "Ok(())");
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

#[test]
fn an_event_still_queued_past_its_wait_is_taken_back() {
    // The writer is held writing an earlier event: the marker waits behind
    // it, past its wait.
    let gate = Gate::on("t.block");
    let mut main = start_with(options(), Some(gate.clone()));
    main.request(2, "t.event", json!({ "name": "t.block" }));
    gate.held();
    let started = Instant::now();
    main.request(3, "t.mark", json!({ "wait_ms": 100 }));
    // Its reply comes once the writer is free: the wait has passed by then.
    std::thread::sleep(Duration::from_millis(1000));
    gate.release();
    assert_eq!(main.message()["event"], "t.block");
    let mut seen = Vec::new();
    while seen.len() < 2 {
        seen.push(main.message());
    }
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert!(seen.iter().any(|m| m["id"] == 2), "{seen:?}");
    assert!(
        seen.iter()
            .any(|m| m["result"]["marked"] == "Err(Withdrawn)"),
        "{seen:?}"
    );
    // The marker never comes.
    main.quiet();
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

#[test]
fn an_event_being_written_past_its_wait_may_still_arrive() {
    let gate = Gate::on("t.marked");
    let mut main = start_with(options(), Some(gate.clone()));
    main.request(2, "t.mark", json!({ "wait_ms": 100 }));
    gate.held();
    std::thread::sleep(Duration::from_millis(1000));
    gate.release();
    // Its write had begun: it arrives, whole, and its sender knew it might.
    // Its clearing event, queued after it, comes after it and before the
    // reply (0014, "The step marker": main never sees it left open).
    assert_eq!(main.message()["event"], "t.marked");
    assert_eq!(
        main.message(),
        json!({ "type": "event", "event": "t.stepped", "data": { "n": 2 } })
    );
    assert_eq!(main.message()["result"]["marked"], "Err(Unfinished)");
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

/// Once the connection has ended, nothing more is asked or marked.
#[test]
fn nothing_is_asked_after_the_end() {
    let mut main = start(options());
    main.request(2, "t.ask", json!({ "params": {} }));
    assert_eq!(main.message()["id"], 1);
    main.request(3, "t.ask", json!({ "params": {} }));
    assert_eq!(main.message()["id"], 2);
    main.respond(2, json!({ "body": true }));
    main.data(2, 0, 10);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
    // What waited resolves: the request main never answered, and the body
    // it never ended.
    let deadline = Instant::now() + Duration::from_secs(10);
    while main.toy.outcomes.lock().unwrap().len() < 2 {
        assert!(Instant::now() < deadline, "a waiter never woke");
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut outcomes = main.toy.outcomes.lock().unwrap().clone();
    outcomes.sort_by_key(|outcome| outcome["asked"].as_u64());
    assert_eq!(
        outcomes,
        [
            json!({ "asked": 1, "failed": "closed" }),
            json!({ "asked": 2, "result": { "body": true },
                "body": { "len": 10, "pattern": true, "ended": "closed" } }),
        ]
    );
    let conn = main.toy.conn.lock().unwrap().clone().unwrap();
    assert!(conn.is_ended());
    assert_eq!(
        conn.ask("shell.t", &json!({}), None).unwrap_err(),
        fc_service::conn::AskError::Closed
    );
    assert_eq!(
        conn.event_written("t.x", &json!({}), Duration::from_secs(1)),
        Err(fc_service::conn::WrittenError::Closed)
    );
}

/// Review of #334, round 1: once the connection ends, the service's
/// requests leave nothing behind, whether the service polled what it held
/// to `Closed` or dropped it in its teardown: requests main never answered,
/// and bodies main never ended.
#[test]
fn the_end_leaves_no_request_behind() {
    let mut main = start(options());
    // Awaited: 1 never answered, 2's body never ended.
    main.request(2, "t.ask", json!({ "params": {} }));
    assert_eq!(main.message()["id"], 1);
    main.request(3, "t.ask", json!({ "params": {} }));
    assert_eq!(main.message()["id"], 2);
    main.respond(2, json!({ "body": true }));
    main.data(2, 0, 10);
    // Held unpolled: 3, never answered; held unread: 4's body. Both are
    // dropped in the teardown.
    main.request(4, "t.ask", json!({ "params": {}, "mode": "unpolled" }));
    let mut seen = vec![main.message(), main.message()];
    seen.sort_by_key(|m| m["type"] == "response");
    assert_eq!(seen[0]["id"], 3, "{seen:?}");
    assert_eq!(seen[1]["result"]["asked"], 3, "{seen:?}");
    main.request(5, "t.ask", json!({ "params": {}, "mode": "hold" }));
    assert_eq!(main.message()["id"], 4);
    main.respond(4, json!({ "body": true }));
    main.data(4, 0, 10);
    let held = main.message();
    assert_eq!(held["result"]["held"], true, "{held}");
    assert_eq!(main.asks(6), 4);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
    let deadline = Instant::now() + Duration::from_secs(10);
    while main.toy.outcomes.lock().unwrap().len() < 3 {
        assert!(Instant::now() < deadline, "a waiter never woke");
        std::thread::sleep(Duration::from_millis(5));
    }
    let outcomes = main.toy.outcomes.lock().unwrap().clone();
    assert!(
        outcomes.contains(&json!({ "asked": 1, "failed": "closed" })),
        "{outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .any(|o| o["asked"] == 2 && o["body"]["ended"] == "closed"),
        "{outcomes:?}"
    );
    let conn = main.toy.conn.lock().unwrap().clone().unwrap();
    assert_eq!(conn.asks(), 0);
}
