//! The service connection end to end, over OS pipes: a toy service on one
//! side, and on the other the test playing main with fc-protocol's decoder
//! and stream Receiver.

#![cfg(not(any(target_os = "ios", target_os = "android")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::future::Future;
use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver as Channel};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake};
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::frame::{Decoder, Frame, KIND_JSON, Kinds};
use fc_protocol::stream::{Abort, AbortCode, Delivery, Receiver, Side, StreamFrame, credit_frame};
use fc_service::Exit;
use fc_service::conn::{self, Connection, End, Hello, Options, Request, Service};
use serde_json::{Value, json};

/// Blocks on a future with the current thread as its waker: enough for the
/// toy service's producers, without an async runtime.
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

fn body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[derive(Default)]
struct Toy {
    cancels: Mutex<Vec<u64>>,
    ends: Mutex<Vec<End>>,
    conn: Mutex<Option<Connection>>,
}

impl Service for Toy {
    fn hello(&self, hello: &Hello) -> Result<serde_json::Map<String, Value>, ErrorBody> {
        if hello.shell_version == "refuse" {
            return Err(ErrorBody::new(ErrorCode::InvalidArgument, "refused"));
        }
        Ok(json!({ "service_version": "test", "kind": "toy" })
            .as_object()
            .cloned()
            .unwrap())
    }

    fn request(&self, conn: &Connection, request: Request<'_>) {
        let params: Value = request
            .params
            .map(|raw| serde_json::from_str(raw.get()).unwrap())
            .unwrap_or(Value::Null);
        match request.method {
            "t.echo" => {
                *self.conn.lock().unwrap() = Some(conn.clone());
                conn.reply(request.id, &json!({ "echo": params })).unwrap();
            }
            "t.event" => {
                conn.event("t.happened", &json!({ "n": 1 })).unwrap();
                conn.reply(request.id, &Value::Null).unwrap();
            }
            "t.body" => {
                let len = params["len"].as_u64().unwrap() as usize;
                let (conn, id) = (conn.clone(), request.id);
                conn.head(id, &json!({ "body": true }), true).unwrap();
                std::thread::spawn(move || {
                    let bytes = body(len);
                    for chunk in bytes.chunks(10_000) {
                        if block_on(conn.send(id, chunk)).is_err() {
                            return;
                        }
                    }
                    let _ = conn.finish(id);
                });
            }
            // Never answered: a body that waits for a cancel.
            "t.hang" => {
                conn.head(request.id, &json!({ "body": true }), true)
                    .unwrap();
                conn.push(request.id, b"first bytes").unwrap();
            }
            "t.fail" => conn.fail(Exit::Internal),
            // Settles another request as a panic would.
            "t.settle" => {
                let target = params["id"].as_u64().unwrap();
                let settled = conn.settle(
                    target,
                    &ErrorBody::new(ErrorCode::Internal, "internal"),
                    &Abort::new(AbortCode::Internal, "internal"),
                );
                conn.reply(request.id, &json!({ "settled": format!("{settled:?}") }))
                    .unwrap();
            }
            // Reports, as an event, once another request is settled on the
            // wire.
            "t.watch" => {
                let target = params["id"].as_u64().unwrap();
                let conn = conn.clone();
                conn.reply(request.id, &Value::Null).unwrap();
                std::thread::spawn(move || {
                    block_on(conn.settled(target));
                    conn.event("t.settled", &json!({ "id": target })).unwrap();
                });
            }
            _ => conn
                .reply_error(
                    request.id,
                    &ErrorBody::new(ErrorCode::UnknownMethod, "unknown"),
                )
                .unwrap(),
        }
    }

    fn cancel(&self, _conn: &Connection, id: u64) {
        self.cancels.lock().unwrap().push(id);
    }

    fn end(&self, _conn: &Connection, end: End) {
        self.ends.lock().unwrap().push(end);
    }
}

/// Main's side of a running connection.
struct Main {
    to_service: Option<std::io::PipeWriter>,
    chunks: Channel<Vec<u8>>,
    decoder: Decoder,
    pending: std::collections::VecDeque<Frame>,
    exit: Channel<Exit>,
    toy: Arc<Toy>,
}

fn options() -> Options {
    let mut options = Options::new("t", 1, Instant::now());
    options.exit_watchdog = None;
    options
}

fn start(options: Options) -> Main {
    let (stdin_reader, stdin_writer) = std::io::pipe().unwrap();
    let (mut stdout_reader, stdout_writer) = std::io::pipe().unwrap();
    let toy = Arc::new(Toy::default());
    let (exit_tx, exit) = mpsc::channel();
    let service = toy.clone();
    std::thread::spawn(move || {
        let _ = exit_tx.send(conn::run(service, options, stdin_reader, stdout_writer));
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
    Main {
        to_service: Some(stdin_writer),
        chunks,
        decoder: Decoder::with_kinds(Kinds::service(Side::Receiver)),
        pending: Default::default(),
        exit,
        toy,
    }
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

    fn hello(&mut self) -> Value {
        self.request(
            1,
            "t.hello",
            json!({ "protocol": 1, "shell_version": "0.9.0", "frames": ["stream"] }),
        );
        self.message()
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

    fn message(&mut self) -> Value {
        let frame = self.frame().expect("a frame");
        assert_eq!(frame.kind, KIND_JSON, "{frame:?}");
        serde_json::from_slice(&frame.payload).unwrap()
    }

    fn exit(&self) -> Exit {
        self.exit.recv_timeout(Duration::from_secs(10)).unwrap()
    }

    fn ends(&self) -> Vec<End> {
        self.toy.ends.lock().unwrap().clone()
    }
}

#[test]
fn hello_requests_and_shutdown() {
    let mut main = start(options());
    let hello = main.hello();
    assert_eq!(
        hello,
        json!({ "type": "response", "id": 1, "result": {
            "protocol": 1, "service_version": "test", "kind": "toy" } })
    );
    main.request(2, "t.echo", json!({ "x": [1, 2] }));
    assert_eq!(main.message()["result"], json!({ "echo": { "x": [1, 2] } }));
    main.request(3, "t.nope", json!({}));
    assert_eq!(main.message()["error"]["code"], "unknown_method");
    // Events go ahead of replies.
    main.request(4, "t.event", Value::Null);
    assert_eq!(main.message()["event"], "t.happened");
    assert_eq!(main.message()["id"], 4);
    // A context, as 0001's envelope has, is ignored.
    main.json(json!({ "type": "request", "id": 5, "method": "t.echo",
        "params": 1, "context": { "caller": "shell" } }));
    assert_eq!(main.message()["result"]["echo"], 1);
    main.request(6, "t.shutdown", Value::Null);
    assert_eq!(main.exit(), Exit::Ok);
    assert_eq!(main.ends(), [End::Shutdown]);
}

#[test]
fn a_body_streams_under_credit() {
    let mut main = start(options());
    main.hello();
    let len = 300_000;
    main.request(2, "t.body", json!({ "len": len }));
    let mut receiver = Receiver::new();
    receiver.request(2).unwrap();
    let head = main.message();
    assert_eq!(head["result"]["body"], true);
    receiver.reply(2, true).unwrap();
    let mut got = Vec::new();
    let mut ended = false;
    while !ended {
        let frame = main.frame().expect("the body's frames");
        match receiver
            .receive(StreamFrame::from_frame(&frame).unwrap())
            .unwrap()
        {
            Delivery::Data { .. } => {}
            Delivery::End { .. } => ended = true,
            other => panic!("{other:?}"),
        }
        // The consumer pulls everything at once, and returns credit: the
        // producer waits for it beyond the 128 KiB window.
        while let Some(pulled) = receiver.pull(2, usize::MAX) {
            if pulled.chunk.is_empty() {
                break;
            }
            got.extend_from_slice(&pulled.chunk);
            if let Some(credit) = pulled.credit {
                main.send(&credit_frame(2, credit).unwrap());
            }
            if pulled.eof {
                break;
            }
        }
    }
    assert_eq!(got, body(len));
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
    assert_eq!(main.ends(), [End::Eof]);
}

#[test]
fn a_settle_owes_what_is_written_and_settled_waits_for_the_terminal() {
    let mut main = start(options());
    main.hello();
    // Answered already: a settle is late.
    main.request(2, "t.echo", json!(2));
    assert_eq!(main.message()["result"]["echo"], 2);
    main.request(3, "t.settle", json!({ "id": 2 }));
    assert_eq!(main.message()["result"]["settled"], "Ok(Already)");

    // An open stream: the abort purges it, and the watcher sees it end
    // only once the abort is written.
    main.request(4, "t.hang", Value::Null);
    assert_eq!(main.message()["result"]["body"], true);
    assert!(matches!(
        StreamFrame::from_frame(&main.frame().unwrap()).unwrap(),
        StreamFrame::Data { id: 4, .. }
    ));
    main.request(5, "t.watch", json!({ "id": 4 }));
    assert_eq!(main.message()["id"], 5);
    main.request(6, "t.settle", json!({ "id": 4 }));
    match StreamFrame::from_frame(&main.frame().unwrap()).unwrap() {
        StreamFrame::Abort { id: 4, abort } => assert_eq!(abort.code, AbortCode::Internal),
        other => panic!("{other:?}"),
    }
    // The settle's reply and the watcher's event, in either order.
    let next = [main.message(), main.message()];
    assert!(
        next.iter().any(|m| m["result"]["settled"] == "Ok(Aborted)"),
        "{next:?}"
    );
    assert!(
        next.iter()
            .any(|m| *m == json!({ "type": "event", "event": "t.settled", "data": { "id": 4 } })),
        "{next:?}"
    );
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

#[test]
fn a_cancel_aborts_an_open_stream_and_reaches_the_service() {
    let mut main = start(options());
    main.hello();
    main.request(2, "t.hang", Value::Null);
    assert_eq!(main.message()["result"]["body"], true);
    let first = main.frame().unwrap();
    assert!(matches!(
        StreamFrame::from_frame(&first).unwrap(),
        StreamFrame::Data { id: 2, .. }
    ));
    main.json(json!({ "type": "cancel", "id": 2 }));
    match StreamFrame::from_frame(&main.frame().unwrap()).unwrap() {
        StreamFrame::Abort { id: 2, abort } => assert_eq!(abort.code.as_str(), "cancelled"),
        other => panic!("{other:?}"),
    }
    // A late cancel changes nothing and never reaches the service.
    main.json(json!({ "type": "cancel", "id": 2 }));
    main.json(json!({ "type": "cancel", "id": 99 }));
    main.request(3, "t.echo", json!(3));
    assert_eq!(main.message()["result"]["echo"], 3);
    assert_eq!(*main.toy.cancels.lock().unwrap(), [2]);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

#[test]
fn the_handshake_comes_first_and_must_match() {
    // Anything before it.
    let mut main = start(options());
    main.request(1, "t.echo", json!(1));
    assert_eq!(main.exit(), Exit::Protocol);
    assert_eq!(main.ends(), [End::Protocol("not_hello_first")]);

    // A protocol main doesn't speak: refused with a reply, then exit 76.
    let mut main = start(options());
    main.request(
        1,
        "t.hello",
        json!({ "protocol": 2, "shell_version": "0.9.0", "frames": ["stream"] }),
    );
    assert_eq!(main.message()["error"]["code"], "protocol_mismatch");
    assert_eq!(main.exit(), Exit::Protocol);

    // Without stream frames.
    let mut main = start(options());
    main.request(
        1,
        "t.hello",
        json!({ "protocol": 1, "shell_version": "0.9.0", "frames": [] }),
    );
    assert_eq!(main.message()["error"]["code"], "protocol_mismatch");
    assert_eq!(main.exit(), Exit::Protocol);

    // Refused by the service.
    let mut main = start(options());
    main.request(
        1,
        "t.hello",
        json!({ "protocol": 1, "shell_version": "refuse", "frames": ["stream"] }),
    );
    assert_eq!(main.message()["error"]["code"], "invalid_argument");
    assert_eq!(main.exit(), Exit::Protocol);

    // Twice.
    let mut main = start(options());
    main.hello();
    main.hello_again();
    assert_eq!(main.exit(), Exit::Protocol);
    assert_eq!(main.ends(), [End::Protocol("second_hello")]);
}

impl Main {
    fn hello_again(&mut self) {
        self.request(
            2,
            "t.hello",
            json!({ "protocol": 1, "shell_version": "0.9.0", "frames": ["stream"] }),
        );
    }
}

#[test]
fn the_handshake_has_a_deadline() {
    let mut options = options();
    options.hello_timeout = Duration::from_millis(200);
    let main = start(options);
    let started = Instant::now();
    assert_eq!(main.exit(), Exit::Protocol);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(main.ends(), [End::HelloTimeout]);
}

#[test]
fn protocol_errors_end_the_connection() {
    for (setup, category) in [
        (
            Box::new(|main: &mut Main| main.request(1, "t.echo", Value::Null))
                as Box<dyn Fn(&mut Main)>,
            "request_order",
        ),
        (
            Box::new(|main: &mut Main| main.send(&credit_frame(7, 1).unwrap())),
            "stream_unknown",
        ),
        (
            Box::new(|main: &mut Main| {
                main.json(json!({ "type": "response", "id": 1, "result": 1 }))
            }),
            "unsolicited_response",
        ),
        (
            Box::new(|main: &mut Main| main.send(&[0, 0, 0, 2, 0x01, b'['])),
            "invalid_message",
        ),
        (
            // Data from main: refused at the frame header.
            Box::new(|main: &mut Main| {
                let mut out = Vec::new();
                StreamFrame::Data { id: 1, bytes: b"x" }
                    .encode(&mut out)
                    .unwrap();
                main.send(&out);
            }),
            "stream_direction",
        ),
    ] {
        let mut main = start(options());
        main.hello();
        setup(&mut main);
        assert_eq!(main.exit(), Exit::Protocol, "{category}");
        assert_eq!(main.ends(), [End::Protocol(category)]);
    }
}

#[test]
fn the_service_can_end_the_connection() {
    let mut main = start(options());
    main.hello();
    main.request(2, "t.fail", Value::Null);
    assert_eq!(main.exit(), Exit::Internal);
    assert_eq!(main.ends(), [End::Fatal(Exit::Internal)]);
}

#[test]
fn a_main_that_stops_reading_is_a_writer_stall() {
    let mut options = options();
    options.writer_stall = Duration::from_millis(300);
    let (stdin_reader, mut stdin_writer) = std::io::pipe().unwrap();
    // Nobody reads stdout.
    let (_stdout_reader, stdout_writer) = std::io::pipe().unwrap();
    let toy = Arc::new(Toy::default());
    let (exit_tx, exit) = mpsc::channel();
    let service = toy.clone();
    std::thread::spawn(move || {
        let _ = exit_tx.send(conn::run(service, options, stdin_reader, stdout_writer));
    });
    let mut frames = Vec::new();
    for message in [
        json!({ "type": "request", "id": 1, "method": "t.hello",
            "params": { "protocol": 1, "shell_version": "x", "frames": ["stream"] } }),
        // A body larger than any pipe's buffer, without credit: the window.
        json!({ "type": "request", "id": 2, "method": "t.body", "params": { "len": 131072 } }),
    ] {
        fc_protocol::frame::encode_json(message.to_string().as_bytes(), &mut frames).unwrap();
    }
    stdin_writer.write_all(&frames).unwrap();
    assert_eq!(
        exit.recv_timeout(Duration::from_secs(10)).unwrap(),
        Exit::Protocol
    );
    assert_eq!(*toy.ends.lock().unwrap(), [End::WriterStall]);
}

#[test]
fn replies_after_the_end_are_refused() {
    use fc_protocol::stream::SendError;
    let mut main = start(options());
    main.hello();
    main.request(2, "t.echo", json!(2));
    assert_eq!(main.message()["result"]["echo"], 2);
    main.request(3, "t.hang", Value::Null);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
    let conn = main.toy.conn.lock().unwrap().clone().unwrap();
    assert!(conn.is_ended());
    assert_eq!(conn.reply(9, &1), Err(SendError::Closed));
    assert_eq!(block_on(conn.send(3, b"more")), Err(SendError::Closed));
}

#[cfg(unix)]
#[test]
fn a_parent_already_gone_ends_at_once() {
    let mut options = options();
    // Not our parent.
    options.parent_pid = Some(u32::MAX);
    let main = start(options);
    assert_eq!(main.exit(), Exit::Ok);
    assert!(main.ends().is_empty(), "nothing was started");
}
