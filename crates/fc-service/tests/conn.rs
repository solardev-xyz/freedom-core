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
use fc_service::conn::{self, Connection, End, Headed, Hello, Options, Request, Service};
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

/// A head's charge: counts itself out when dropped.
struct Charged(Arc<Mutex<usize>>);

impl Drop for Charged {
    fn drop(&mut self) {
        *self.0.lock().unwrap() -= 1;
    }
}

/// A charge whose drop calls back into its connection, as a reservation's
/// drop can, by waking work that looks at the connection: it deadlocks if
/// dropped under the connection's lock.
struct Reentrant(Connection, mpsc::Sender<()>);

impl Drop for Reentrant {
    fn drop(&mut self) {
        let _ = self.0.stats();
        let _ = self.1.send(());
    }
}

#[derive(Default)]
struct Toy {
    headed: Mutex<Vec<Headed>>,
    /// Heads' charges not yet released.
    charged: Arc<Mutex<usize>>,
    cancels: Mutex<Vec<u64>>,
    /// Holds the next cancel callback until it receives.
    cancel_gate: Mutex<Option<mpsc::Receiver<()>>>,
    /// Reentrant charges, as each is dropped.
    reentered: Mutex<Option<mpsc::Sender<()>>>,
    ends: Mutex<Vec<End>>,
    conn: Mutex<Option<Connection>>,
}

impl Toy {
    /// A charge that counts itself, or with `reenter`, one that calls back
    /// into the connection.
    fn charge(&self, conn: &Connection, params: &Value) -> conn::Charge {
        if params["reenter"] == true {
            let reentered = self.reentered.lock().unwrap().clone().unwrap();
            Box::new(Reentrant(conn.clone(), reentered))
        } else {
            *self.charged.lock().unwrap() += 1;
            Box::new(Charged(self.charged.clone()))
        }
    }
}

/// `now` moved by `in_ms` (negative: into the past).
fn deadline_in(in_ms: i64) -> Instant {
    let now = Instant::now();
    if in_ms >= 0 {
        now + Duration::from_millis(in_ms.unsigned_abs())
    } else {
        now - Duration::from_millis(in_ms.unsigned_abs())
    }
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
        *self.conn.lock().unwrap() = Some(conn.clone());
        let params: Value = request
            .params
            .map(|raw| serde_json::from_str(raw.get()).unwrap())
            .unwrap_or(Value::Null);
        match request.method {
            "t.echo" => conn.reply(request.id, &json!({ "echo": params })).unwrap(),
            "t.nobody" => conn
                .head(request.id, &json!({ "body": false }), false)
                .unwrap(),
            // A head due `in_ms` from now (negative: past due), with
            // `pad` in it if given, and a charge that counts itself (or,
            // with `reenter`, one that calls back into the connection).
            "t.head_by" => {
                let deadline = deadline_in(params["in_ms"].as_i64().unwrap());
                let charge = self.charge(conn, &params);
                let head = json!({ "body": false, "pad": params["pad"] });
                let headed = conn.head_by(
                    params["id"].as_u64().unwrap_or(request.id),
                    &head,
                    false,
                    deadline,
                    &ErrorBody::new(ErrorCode::Deadline, "late"),
                    Some(charge),
                );
                if let Ok(headed) = headed {
                    self.headed.lock().unwrap().push(headed);
                }
            }
            // A reply, or with `error` an error, due `in_ms` from now.
            "t.reply_by" => {
                let deadline = deadline_in(params["in_ms"].as_i64().unwrap());
                let late = ErrorBody::new(ErrorCode::Deadline, "late");
                let charge = Some(self.charge(conn, &params));
                let replied = if params["error"] == true {
                    conn.reply_error_by(
                        request.id,
                        &ErrorBody::new(ErrorCode::Busy, "busy"),
                        deadline,
                        &late,
                        charge,
                    )
                } else {
                    conn.reply_by(
                        request.id,
                        &json!({ "in_time": true }),
                        deadline,
                        &late,
                        charge,
                    )
                };
                if let Ok(replied) = replied {
                    self.headed.lock().unwrap().push(replied);
                }
            }
            // A body of `len` bytes in one send, reported once the send
            // ends: how much of it was queued.
            "t.send_all" => {
                let len = params["len"].as_u64().unwrap() as usize;
                let (conn, id) = (conn.clone(), request.id);
                conn.head(id, &json!({ "body": true }), true).unwrap();
                std::thread::spawn(move || {
                    let bytes = body(len);
                    let mut send = std::pin::pin!(conn.send(id, &bytes));
                    let ended = block_on(send.as_mut());
                    let _ = conn.event(
                        "t.sent",
                        &json!({ "sent": send.sent(), "ok": ended.is_ok() }),
                    );
                });
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
        let gate = self.cancel_gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.recv_timeout(Duration::from_secs(10)).unwrap();
        }
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
    start_with(options, |pipe| pipe)
}

/// As [`start`], with stdout wrapped by `output`.
fn start_with<W: Write + Send + 'static>(
    options: Options,
    output: impl FnOnce(std::io::PipeWriter) -> W,
) -> Main {
    let (stdin_reader, stdin_writer) = std::io::pipe().unwrap();
    let (mut stdout_reader, stdout_writer) = std::io::pipe().unwrap();
    let toy = Arc::new(Toy::default());
    let (exit_tx, exit) = mpsc::channel();
    let service = toy.clone();
    let output = output(stdout_writer);
    std::thread::spawn(move || {
        let _ = exit_tx.send(conn::run(service, options, stdin_reader, output));
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

/// Holds the writer inside the first write of request 2's frame of `kind`,
/// before any of its bytes reach the pipe, until released.
#[derive(Clone)]
struct Gate {
    kind: u8,
    state: Arc<(Mutex<(bool, bool)>, std::sync::Condvar)>,
}

impl Gate {
    fn new(kind: u8) -> Gate {
        Gate {
            kind,
            state: Arc::default(),
        }
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
    /// The held write fails once released, as a write to a main that has
    /// gone does.
    fail: bool,
}

impl Write for Gated {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let ours = bytes.len() > 4
            && bytes[4] == self.gate.kind
            && if self.gate.kind == KIND_JSON {
                serde_json::from_slice::<Value>(&bytes[5..]).is_ok_and(|m| m["id"] == 2)
            } else {
                bytes.get(5..13) == Some(&2u64.to_be_bytes()[..])
            };
        if ours {
            let mut state = self.gate.state.0.lock().unwrap();
            state.0 = true;
            self.gate.state.1.notify_all();
            while !state.1 {
                state = self.gate.state.1.wait(state).unwrap();
            }
            if self.fail {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
        }
        self.pipe.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.pipe.flush()
    }
}

/// Review of #140: a request isn't settled while the writer is still
/// writing its terminal: a reply, a head without a body, a stream's end or
/// its abort.
#[test]
fn settled_waits_for_a_terminal_still_being_written() {
    use fc_protocol::frame::{KIND_ABORT, KIND_END};
    for (case, kind) in [
        ("reply", KIND_JSON),
        ("head without a body", KIND_JSON),
        ("end", KIND_END),
        ("abort", KIND_ABORT),
    ] {
        let gate = Gate::new(kind);
        let held = gate.clone();
        let mut main = start_with(options(), move |pipe| Gated {
            pipe,
            gate: held,
            fail: false,
        });
        main.hello();
        match case {
            "reply" => main.request(2, "t.echo", json!(2)),
            "head without a body" => main.request(2, "t.nobody", Value::Null),
            "end" => {
                main.request(2, "t.body", json!({ "len": 0 }));
                assert_eq!(main.message()["id"], 2);
            }
            _ => {
                main.request(2, "t.hang", Value::Null);
                assert_eq!(main.message()["id"], 2);
                main.frame().unwrap();
                main.json(json!({ "type": "cancel", "id": 2 }));
            }
        }
        gate.held();
        let conn = main.toy.conn.lock().unwrap().clone().unwrap();
        let waker = std::task::Waker::noop();
        let mut settled = std::pin::pin!(conn.settled(2));
        let early = settled
            .as_mut()
            .poll(&mut Context::from_waker(waker))
            .is_ready();
        gate.release();
        main.frame().unwrap();
        // Written and flushed: settled now.
        block_on(settled);
        main.close();
        assert_eq!(main.exit(), Exit::Ok);
        assert!(
            !early,
            "{case}: settled while its terminal was being written"
        );
    }
}

#[test]
fn a_head_is_queued_only_before_its_deadline() {
    let mut main = start(options());
    main.hello();
    main.request(2, "t.head_by", json!({ "in_ms": 60_000 }));
    assert_eq!(main.message()["result"]["body"], false);
    // Past its deadline: the late reply instead.
    main.request(3, "t.head_by", json!({ "in_ms": -1 }));
    let late = main.message();
    assert_eq!(
        (&late["id"], &late["error"]["code"]),
        (&json!(3), &json!("deadline"))
    );
    // The toy records what it queued after the call returns.
    let deadline = Instant::now() + Duration::from_secs(10);
    while main.toy.headed.lock().unwrap().len() < 2 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        *main.toy.headed.lock().unwrap(),
        [Headed::Queued, Headed::Late]
    );
    // Each head's charge went with it: the written head's once written,
    // and the late one's at once.
    released(&main.toy.charged);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

/// Waits until every counted charge has been released.
fn released(charged: &Mutex<usize>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while *charged.lock().unwrap() > 0 {
        assert!(Instant::now() < deadline, "a charge was never released");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn a_queued_head_holds_its_charge_until_the_writer_takes_it() {
    let gate = Gate::new(KIND_JSON);
    let held = gate.clone();
    let mut main = start_with(options(), move |pipe| Gated {
        pipe,
        gate: held,
        fail: false,
    });
    main.hello();
    // The writer is held inside request 2's reply, so request 3's head
    // waits in the queue with its charge.
    main.request(2, "t.echo", json!(2));
    gate.held();
    main.request(3, "t.head_by", json!({ "in_ms": 60_000 }));
    let deadline = Instant::now() + Duration::from_secs(10);
    while main.toy.headed.lock().unwrap().is_empty() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(*main.toy.charged.lock().unwrap(), 1, "held while queued");
    gate.release();
    assert_eq!(main.message()["id"], 2);
    assert_eq!(main.message()["id"], 3);
    released(&main.toy.charged);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

/// Review of #141: a head's charge lasts until the writer has written and
/// flushed it, not only claimed it.
#[test]
fn a_heads_charge_lasts_until_it_is_written() {
    let gate = Gate::new(KIND_JSON);
    let held = gate.clone();
    let mut main = start_with(options(), move |pipe| Gated {
        pipe,
        gate: held,
        fail: false,
    });
    main.hello();
    main.request(2, "t.head_by", json!({ "in_ms": 60_000 }));
    // The writer is inside the head's write.
    gate.held();
    assert_eq!(*main.toy.charged.lock().unwrap(), 1, "held while written");
    gate.release();
    assert_eq!(main.message()["id"], 2);
    released(&main.toy.charged);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

/// Review of #141: a head is encoded in a buffer of exactly
/// `head_len`'s size, which counts the frame on the wire, and one larger
/// than the writer's buffer is written whole.
/// Records the size of each write.
struct Recorded {
    pipe: std::io::PipeWriter,
    writes: Arc<Mutex<Vec<usize>>>,
}

impl Write for Recorded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let written = self.pipe.write(bytes)?;
        self.writes.lock().unwrap().push(written);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.pipe.flush()
    }
}

#[test]
fn head_len_is_what_a_head_holds_on_the_wire() {
    let writes = Arc::new(Mutex::new(Vec::new()));
    let recorded = writes.clone();
    let mut main = start_with(options(), move |pipe| Recorded {
        pipe,
        writes: recorded,
    });
    main.hello();
    for (id, pad) in [(2, "small".to_owned()), (3, "\u{800}".repeat(40_000))] {
        main.request(id, "t.head_by", json!({ "in_ms": 60_000, "pad": pad }));
        let frame = main.frame().unwrap();
        let head: Value = serde_json::from_slice(&frame.payload).unwrap();
        assert_eq!(head["result"]["pad"], pad);
        let expected = conn::head_len(id, &json!({ "body": false, "pad": pad })).unwrap();
        assert_eq!(expected, 5 + frame.payload.len(), "{id}");
    }
    assert!(conn::head_len(4, &json!({ "pad": "x".repeat(1 << 20) })).is_err());
    // The large head: its 5-byte frame header written alone, then the
    // head's own buffer, never copied into the writer's.
    assert!(
        writes.lock().unwrap().contains(&5),
        "{:?}",
        writes.lock().unwrap()
    );
    released(&main.toy.charged);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

/// Review of #141: a charge is never dropped under the connection's lock,
/// on any path: a head queued and written, a late head, a head for a
/// request already answered, and a head still queued when the writer
/// fails; and a reply's (`reply_by`): written, late, still queued when the
/// writer fails, or purged when the stream state fails.
/// The child runs one case and exits; a deadlock is a child that hangs.
#[test]
fn a_charge_is_dropped_outside_the_connections_lock() {
    for case in [
        "written",
        "late",
        "answered",
        "writer_failed",
        "reply_written",
        "reply_late",
        "reply_writer_failed",
        "reply_purged",
    ] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "reentrant_charge_case", "--test-threads=1"])
            .env("FC_SERVICE_REENTRANT_CASE", case)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.is_some_and(|status| status.success()),
            "{case}: {status:?}"
        );
    }
}

/// One case of [`a_charge_is_dropped_outside_the_connections_lock`], when
/// run as its child; nothing otherwise.
#[test]
fn reentrant_charge_case() {
    let Ok(case) = std::env::var("FC_SERVICE_REENTRANT_CASE") else {
        return;
    };
    // The writer fails inside request 2's reply, with request 3's head
    // queued behind it.
    let gate = Gate::new(KIND_JSON);
    let held = gate.clone();
    let failing = case.ends_with("writer_failed");
    let mut main = start_with(options(), move |pipe| Gated {
        pipe,
        gate: held,
        fail: failing,
    });
    main.hello();
    let (reentered, dropped) = mpsc::channel();
    *main.toy.reentered.lock().unwrap() = Some(reentered);
    match case.as_str() {
        "written" => {
            main.request(3, "t.head_by", json!({ "in_ms": 60_000, "reenter": true }));
            assert_eq!(main.message()["id"], 3);
        }
        "late" => {
            main.request(3, "t.head_by", json!({ "in_ms": -1, "reenter": true }));
            assert_eq!(main.message()["error"]["code"], "deadline");
        }
        "answered" => {
            main.request(2, "t.echo", json!(2));
            gate.release();
            assert_eq!(main.message()["id"], 2);
            // The toy heads request 2, answered already: refused.
            let params = json!({ "in_ms": 60_000, "reenter": true, "id": 2 });
            main.request(3, "t.head_by", params);
        }
        "reply_written" => {
            main.request(3, "t.reply_by", json!({ "in_ms": 60_000, "reenter": true }));
            assert_eq!(main.message()["result"]["in_time"], true);
        }
        "reply_late" => {
            main.request(3, "t.reply_by", json!({ "in_ms": -1, "reenter": true }));
            assert_eq!(main.message()["error"]["code"], "deadline");
        }
        _ => {
            // Request 3's head or reply waits behind request 2's held write;
            // then the writer fails, or the stream state does.
            main.request(2, "t.echo", json!(2));
            gate.held();
            let method = if case.starts_with("reply") {
                "t.reply_by"
            } else {
                "t.head_by"
            };
            main.request(3, method, json!({ "in_ms": 60_000, "reenter": true }));
            let deadline = Instant::now() + Duration::from_secs(10);
            while main.toy.headed.lock().unwrap().is_empty() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(5));
            }
            if case == "reply_purged" {
                // Credit for a request with no stream: the stream state
                // fails, and drops what is queued.
                main.send(&credit_frame(3, 1).unwrap());
            }
            gate.release();
        }
    }
    dropped.recv_timeout(Duration::from_secs(10)).unwrap();
    gate.release();
    main.close();
    let _ = main.exit();
}

#[test]
fn a_reply_by_is_queued_only_before_its_deadline() {
    let mut main = start(options());
    main.hello();
    main.request(2, "t.reply_by", json!({ "in_ms": 60_000 }));
    assert_eq!(main.message()["result"]["in_time"], true);
    main.request(3, "t.reply_by", json!({ "in_ms": -1 }));
    assert_eq!(main.message()["error"]["code"], "deadline");
    main.request(4, "t.reply_by", json!({ "in_ms": 60_000, "error": true }));
    assert_eq!(main.message()["error"]["code"], "busy");
    main.request(5, "t.reply_by", json!({ "in_ms": -1, "error": true }));
    assert_eq!(main.message()["error"]["code"], "deadline");
    let deadline = Instant::now() + Duration::from_secs(10);
    while main.toy.headed.lock().unwrap().len() < 4 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        *main.toy.headed.lock().unwrap(),
        [Headed::Queued, Headed::Late, Headed::Queued, Headed::Late]
    );
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

/// Review of #143: a reply queued by `reply_by` keeps its charge while it
/// waits behind another frame and while it is written, and releases it
/// once written; a late one at once.
#[test]
fn a_reply_by_holds_its_charge_until_it_is_written() {
    let gate = Gate::new(KIND_JSON);
    let held = gate.clone();
    let mut main = start_with(options(), move |pipe| Gated {
        pipe,
        gate: held,
        fail: false,
    });
    main.hello();
    // Request 2's own reply, held inside its write.
    main.request(2, "t.reply_by", json!({ "in_ms": 60_000 }));
    gate.held();
    assert_eq!(*main.toy.charged.lock().unwrap(), 1, "held while written");
    // Request 3's, queued behind it.
    main.request(3, "t.reply_by", json!({ "in_ms": 60_000 }));
    let deadline = Instant::now() + Duration::from_secs(10);
    while main.toy.headed.lock().unwrap().len() < 2 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(*main.toy.charged.lock().unwrap(), 2, "held while queued");
    gate.release();
    assert_eq!(main.message()["id"], 2);
    assert_eq!(main.message()["id"], 3);
    released(&main.toy.charged);
    // Late: its charge goes at once.
    main.request(4, "t.reply_by", json!({ "in_ms": -1 }));
    assert_eq!(main.message()["error"]["code"], "deadline");
    released(&main.toy.charged);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

/// Review of #141: a request isn't settled while its accepted cancel is
/// being handed to the service, even once its abort is written, so the
/// service's record of it is still there for the callback.
#[test]
fn a_cancelled_request_is_settled_only_after_the_cancel_callback() {
    let mut main = start(options());
    main.hello();
    main.request(2, "t.hang", Value::Null);
    assert_eq!(main.message()["result"]["body"], true);
    main.frame().unwrap();
    let conn = main.toy.conn.lock().unwrap().clone().unwrap();
    let (release, gate) = mpsc::channel();
    *main.toy.cancel_gate.lock().unwrap() = Some(gate);
    main.json(json!({ "type": "cancel", "id": 2 }));
    match StreamFrame::from_frame(&main.frame().unwrap()).unwrap() {
        StreamFrame::Abort { id: 2, abort } => assert_eq!(abort.code.as_str(), "cancelled"),
        other => panic!("{other:?}"),
    }
    // Its abort is written and flushed, its callback still running.
    let mut settled = std::pin::pin!(conn.settled(2));
    let waker = std::task::Waker::noop();
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline {
        assert!(
            settled
                .as_mut()
                .poll(&mut Context::from_waker(waker))
                .is_pending(),
            "settled while its cancel was being handed over"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    release.send(()).unwrap();
    block_on(settled);
    assert_eq!(*main.toy.cancels.lock().unwrap(), [2]);
    main.close();
    assert_eq!(main.exit(), Exit::Ok);
}

/// Review of #141: a send that fails says how much of it was queued.
#[test]
fn a_failed_send_says_how_much_it_queued() {
    let mut main = start(options());
    main.hello();
    main.request(2, "t.send_all", json!({ "len": 200_000 }));
    assert_eq!(main.message()["result"]["body"], true);
    let mut received = 0;
    while received < 128 << 10 {
        match StreamFrame::from_frame(&main.frame().unwrap()).unwrap() {
            StreamFrame::Data { id: 2, bytes } => received += bytes.len(),
            other => panic!("{other:?}"),
        }
    }
    // One more byte of credit, taken, then a cancel.
    main.send(&credit_frame(2, 1).unwrap());
    match StreamFrame::from_frame(&main.frame().unwrap()).unwrap() {
        StreamFrame::Data { id: 2, bytes } => received += bytes.len(),
        other => panic!("{other:?}"),
    }
    main.json(json!({ "type": "cancel", "id": 2 }));
    let mut sent = None;
    while sent.is_none() {
        let frame = main.frame().unwrap();
        if frame.kind == KIND_JSON {
            let event: Value = serde_json::from_slice(&frame.payload).unwrap();
            sent = Some(event["data"].clone());
        }
    }
    assert_eq!(sent.unwrap(), json!({ "sent": received, "ok": false }));
    assert_eq!(received, (128 << 10) + 1);
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
