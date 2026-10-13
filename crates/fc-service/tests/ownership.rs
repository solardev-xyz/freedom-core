//! The connection's ownership rules over OS pipes (review of #106): what a
//! cancel can still drop, how many requests the connection holds, which
//! callbacks run after the end, wakers outside the lock, the closing phase,
//! and the process's result.

#![cfg(not(any(target_os = "ios", target_os = "android")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::future::Future;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Wake};
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::frame::{Decoder, Frame, KIND_JSON, Kinds};
use fc_protocol::stream::{SendError, Side, StreamFrame, WINDOW, credit_frame};
use fc_service::Exit;
use fc_service::conn::{self, Connection, End, Hello, Options, Request, Service};
use serde_json::{Value, json};

#[derive(Default)]
struct Svc {
    calls: Mutex<Vec<String>>,
    cancels: Mutex<Vec<u64>>,
    ends: Mutex<Vec<End>>,
    conn: Mutex<Option<Connection>>,
    /// Requests `t.later` holds unanswered.
    later: Mutex<Vec<u64>>,
    /// `t.slow` waits for this.
    slow: Mutex<Option<mpsc::Receiver<()>>>,
    in_callback: AtomicBool,
    end_overlapped: AtomicBool,
    /// Service::end fails with 70.
    fatal_at_end: bool,
    /// Service::end answers what `t.later` holds and tries new work.
    answer_at_end: bool,
    at_end: Mutex<Vec<(String, Result<(), SendError>)>>,
}

impl Service for Svc {
    fn hello(&self, _: &Hello) -> Result<serde_json::Map<String, Value>, ErrorBody> {
        Ok(Default::default())
    }

    fn request(&self, conn: &Connection, req: Request<'_>) {
        self.in_callback.store(true, Ordering::SeqCst);
        *self.conn.lock().unwrap() = Some(conn.clone());
        self.calls.lock().unwrap().push(req.method.to_string());
        match req.method {
            "t.later" => self.later.lock().unwrap().push(req.id),
            // Answers the request `t.later` holds, then heads its own.
            "t.head_after" => {
                let held = self.later.lock().unwrap().pop().unwrap();
                conn.reply(held, &json!({})).unwrap();
                conn.head(req.id, &json!({ "body": true }), true).unwrap();
            }
            "t.stream" => {
                conn.head(req.id, &json!({ "body": true }), true).unwrap();
                conn.push(req.id, &[7; 10]).unwrap();
                conn.finish(req.id).unwrap();
            }
            "t.window" => {
                conn.head(req.id, &json!({ "body": true }), true).unwrap();
                conn.push(req.id, &vec![3; WINDOW]).unwrap();
            }
            "t.big" => conn.reply(req.id, &"x".repeat(950_000)).unwrap(),
            "t.busy" => conn
                .reply_error(req.id, &ErrorBody::new(ErrorCode::Busy, "Busy"))
                .unwrap(),
            "t.fatal" => conn.fail(Exit::Internal),
            "t.record" => {}
            "t.slow" => {
                let release = self.slow.lock().unwrap().take().unwrap();
                release.recv().unwrap();
                // Owed, so still queued while the connection closes.
                conn.reply(req.id, &json!("late")).unwrap();
            }
            _ => conn.reply(req.id, &Value::Null).unwrap(),
        }
        self.in_callback.store(false, Ordering::SeqCst);
    }

    fn cancel(&self, _: &Connection, id: u64) {
        self.cancels.lock().unwrap().push(id);
    }

    fn end(&self, conn: &Connection, end: End) {
        if self.in_callback.load(Ordering::SeqCst) {
            self.end_overlapped.store(true, Ordering::SeqCst);
        }
        self.ends.lock().unwrap().push(end);
        if self.answer_at_end {
            let held = self.later.lock().unwrap().clone();
            let mut at_end = self.at_end.lock().unwrap();
            at_end.push(("reply".into(), conn.reply(held[0], &json!("stopped"))));
            at_end.push((
                "head with a body".into(),
                conn.head(held[1], &json!({}), true),
            ));
            at_end.push((
                "event".into(),
                conn.event("t.late", &1).map_err(|_| SendError::Closed),
            ));
        }
        if self.fatal_at_end {
            conn.fail(Exit::Internal);
        }
    }
}

fn opts() -> Options {
    let mut options = Options::new("t", 1, Instant::now());
    options.exit_watchdog = None;
    options.writer_stall = Duration::from_secs(10);
    options
}

fn framed(value: Value) -> Vec<u8> {
    let mut out = Vec::new();
    fc_protocol::frame::encode_json(value.to_string().as_bytes(), &mut out).unwrap();
    out
}

fn request(id: u64, method: &str) -> Vec<u8> {
    framed(json!({ "type": "request", "id": id, "method": method, "params": {} }))
}

fn hello() -> Vec<u8> {
    framed(json!({ "type": "request", "id": 1, "method": "t.hello",
        "params": { "protocol": 1, "shell_version": "x", "frames": ["stream"] } }))
}

fn cancel(id: u64) -> Vec<u8> {
    framed(json!({ "type": "cancel", "id": id }))
}

fn wait_for(what: &str, done: impl Fn() -> bool) {
    let until = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < until, "never reached: {what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Main's reading end of stdout.
struct Out {
    pipe: std::io::PipeReader,
    decoder: Decoder,
    pending: std::collections::VecDeque<Frame>,
}

impl Out {
    fn new(pipe: std::io::PipeReader) -> Self {
        Out {
            pipe,
            decoder: Decoder::with_kinds(Kinds::service(Side::Receiver)),
            pending: Default::default(),
        }
    }

    /// The next frame, or `None` at EOF.
    fn frame(&mut self) -> Option<Frame> {
        let mut buffer = [0u8; 65536];
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return Some(frame);
            }
            let n = self.pipe.read(&mut buffer).unwrap();
            if n == 0 {
                return None;
            }
            let mut rest = &buffer[..n];
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
}

struct Running {
    main: Option<std::io::PipeWriter>,
    out: Out,
    exit: mpsc::Receiver<Exit>,
    svc: Arc<Svc>,
}

impl Running {
    fn send(&mut self, bytes: &[u8]) {
        self.main.as_mut().unwrap().write_all(bytes).unwrap();
    }

    fn exit(&self) -> Exit {
        self.exit.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    fn conn(&self) -> Connection {
        self.svc.conn.lock().unwrap().clone().unwrap()
    }
}

fn start_with(
    svc: Svc,
    options: Options,
    output: impl Fn(std::io::PipeWriter) -> Box<dyn Write + Send>,
) -> Running {
    let svc = Arc::new(svc);
    let (input, main) = std::io::pipe().unwrap();
    let (out, stdout) = std::io::pipe().unwrap();
    let (tx, exit) = mpsc::channel();
    let service = svc.clone();
    let stdout = output(stdout);
    std::thread::spawn(move || {
        let _ = tx.send(conn::run(service, options, input, stdout));
    });
    Running {
        main: Some(main),
        out: Out::new(out),
        exit,
        svc,
    }
}

fn start(svc: Svc, options: Options) -> Running {
    start_with(svc, options, |pipe| Box::new(pipe))
}

/// A stdout whose writes each wait for a permit from the test: the test
/// sees a write begin and decides when it proceeds.
#[derive(Clone, Default)]
struct Pace(Arc<(Mutex<(usize, usize)>, Condvar)>);

impl Pace {
    /// Lets `n` more writes through.
    fn permit(&self, n: usize) {
        self.0.0.lock().unwrap().1 += n;
        self.0.1.notify_all();
    }

    /// Waits until write number `n` (from 1) has begun.
    fn wait_entered(&self, n: usize) {
        let until = Instant::now() + Duration::from_secs(5);
        let mut state = self.0.0.lock().unwrap();
        while state.0 < n {
            let left = until
                .checked_duration_since(Instant::now())
                .expect("write never began");
            state = self.0.1.wait_timeout(state, left).unwrap().0;
        }
    }
}

struct Paced {
    pipe: std::io::PipeWriter,
    pace: Pace,
}

impl Write for Paced {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        {
            let (state, changed) = &*self.pace.0;
            let mut state = state.lock().unwrap();
            state.0 += 1;
            changed.notify_all();
            while state.1 == 0 {
                state = changed.wait(state).unwrap();
            }
            state.1 -= 1;
        }
        self.pipe.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.pipe.flush()
    }
}

fn start_paced(svc: Svc) -> (Running, Pace) {
    let pace = Pace::default();
    let writes = pace.clone();
    let running = start_with(svc, opts(), move |pipe| {
        Box::new(Paced {
            pipe,
            pace: writes.clone(),
        })
    });
    (running, pace)
}

// ---- what a cancel can still drop ----------------------------------------

#[test]
fn a_head_behind_a_frame_being_written_is_still_cancellable() {
    let (mut run, pace) = start_paced(Svc::default());
    pace.permit(1);
    run.send(&hello());
    run.out.message();
    // Reply 2's write begins and waits.
    run.send(&request(2, "t.echo"));
    pace.wait_entered(2);
    // Behind it: reply 3, then head 4.
    let mut both = request(3, "t.later");
    both.extend(request(4, "t.head_after"));
    run.send(&both);
    wait_for("head 4 queued", || run.svc.calls.lock().unwrap().len() == 3);
    pace.permit(1);
    assert_eq!(run.out.message()["id"], 2);
    // Reply 3's write begins: head 4 is still queued, unwritten.
    pace.wait_entered(3);
    run.send(&cancel(4));
    wait_for("the cancel", || *run.svc.cancels.lock().unwrap() == [4]);
    pace.permit(1000);
    assert_eq!(run.out.message()["id"], 3);
    // `cancelled` is request 4's only reply: no head, no stream.
    let four = run.out.message();
    assert_eq!(four["id"], 4, "{four}");
    assert_eq!(four["error"]["code"], "cancelled", "{four}");
    run.send(&request(5, "t.echo"));
    let next = run.out.frame().unwrap();
    assert_eq!(
        next.kind, KIND_JSON,
        "nothing of stream 4 follows: {next:?}"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&next.payload).unwrap()["id"],
        5
    );
    run.main = None;
    assert_eq!(run.exit(), Exit::Ok);
}

#[test]
fn an_end_behind_a_frame_being_written_is_still_cancellable() {
    let (mut run, pace) = start_paced(Svc::default());
    pace.permit(1);
    run.send(&hello());
    run.out.message();
    run.send(&request(2, "t.echo"));
    pace.wait_entered(2);
    // Head, 10 bytes and end queued behind reply 2.
    run.send(&request(3, "t.stream"));
    wait_for("stream 3 queued", || {
        run.svc.calls.lock().unwrap().len() == 2
    });
    pace.permit(2);
    assert_eq!(run.out.message()["id"], 2);
    assert_eq!(run.out.message()["id"], 3);
    // The data frame's write begins: the end is still queued.
    pace.wait_entered(4);
    run.send(&cancel(3));
    wait_for("the cancel", || *run.svc.cancels.lock().unwrap() == [3]);
    pace.permit(1000);
    let data = run.out.frame().unwrap();
    assert!(matches!(
        StreamFrame::from_frame(&data).unwrap(),
        StreamFrame::Data { id: 3, bytes } if bytes.len() == 10
    ));
    match StreamFrame::from_frame(&run.out.frame().unwrap()).unwrap() {
        StreamFrame::Abort { id: 3, abort } => assert_eq!(abort.code.as_str(), "cancelled"),
        other => panic!("the cancel was beaten by an unwritten end: {other:?}"),
    }
    run.main = None;
    assert_eq!(run.exit(), Exit::Ok);
}

// ---- how many requests the connection holds ------------------------------

#[test]
fn refusals_behind_a_blocked_writer_are_bounded_then_all_answered() {
    let mut run = start(Svc::default(), opts());
    run.send(&hello());
    run.out.message();
    // Nobody reads stdout now: the writer blocks inside this reply.
    run.send(&request(2, "t.big"));
    wait_for("t.big", || run.svc.calls.lock().unwrap().len() == 1);
    let mut input = Vec::new();
    for id in 3..=2002 {
        input.extend(request(id, "t.busy"));
    }
    let mut main = run.main.take().unwrap();
    let writer = std::thread::spawn(move || {
        main.write_all(&input).unwrap();
        main
    });
    let admitted = 1 + conn::MAX_REQUESTS;
    wait_for("the allowance", || {
        run.svc.calls.lock().unwrap().len() == admitted
    });
    std::thread::sleep(Duration::from_millis(200));
    // The rest are parked, not handed to the service, not recorded.
    assert_eq!(run.svc.calls.lock().unwrap().len(), admitted);
    let stats = run.conn().stats();
    assert_eq!(stats.live_requests, conn::MAX_REQUESTS);
    // Main reads again: every request is answered, in order.
    let big = run.out.message();
    assert_eq!(big["id"], 2);
    for id in 3..=2002u64 {
        let reply = run.out.message();
        assert_eq!(
            (reply["id"].as_u64(), &reply["error"]["code"]),
            (Some(id), &json!("busy"))
        );
    }
    assert_eq!(run.svc.calls.lock().unwrap().len(), 2001);
    assert_eq!(run.conn().stats().live_requests, 0);
    run.main = Some(writer.join().unwrap());
    run.main = None;
    assert_eq!(run.exit(), Exit::Ok);
}

/// A connection that holds one request at a time.
fn one_at_a_time() -> Options {
    let mut options = opts();
    options.max_requests = 1;
    options
}

#[test]
fn a_parked_request_cancelled_gets_cancelled_and_never_reaches_the_service() {
    let mut run = start(Svc::default(), one_at_a_time());
    run.send(&hello());
    run.out.message();
    let mut frames = request(2, "t.later");
    frames.extend(request(3, "t.echo"));
    frames.extend(cancel(3));
    run.send(&frames);
    wait_for("t.later", || run.svc.calls.lock().unwrap().len() == 1);
    std::thread::sleep(Duration::from_millis(100));
    // Request 2 frees the connection's one place once its reply is written.
    run.conn().reply(2, &json!("done")).unwrap();
    assert_eq!(run.out.message()["id"], 2);
    let three = run.out.message();
    assert_eq!(
        (three["id"].as_u64(), &three["error"]["code"]),
        (Some(3), &json!("cancelled"))
    );
    assert_eq!(*run.svc.calls.lock().unwrap(), ["t.later"]);
    assert!(run.svc.cancels.lock().unwrap().is_empty());
    run.main = None;
    assert_eq!(run.exit(), Exit::Ok);
}

#[test]
fn shutdown_behind_parked_requests_is_handled_on_arrival() {
    let mut run = start(Svc::default(), one_at_a_time());
    run.send(&hello());
    run.out.message();
    let mut frames = request(2, "t.later");
    frames.extend(request(3, "t.echo"));
    frames.extend(request(4, "t.shutdown"));
    run.send(&frames);
    assert_eq!(run.exit(), Exit::Ok);
    assert_eq!(*run.svc.ends.lock().unwrap(), [End::Shutdown]);
    assert_eq!(*run.svc.calls.lock().unwrap(), ["t.later"]);
}

#[test]
fn credit_for_a_parked_request_is_an_overgrant() {
    let mut run = start(Svc::default(), one_at_a_time());
    run.send(&hello());
    run.out.message();
    let mut frames = request(2, "t.later");
    frames.extend(request(3, "t.echo"));
    frames.extend(credit_frame(3, 1).unwrap());
    run.send(&frames);
    assert_eq!(run.exit(), Exit::Protocol);
    assert_eq!(
        *run.svc.ends.lock().unwrap(),
        [End::Protocol("credit_overgrant")]
    );
}

// ---- no callback after the end -------------------------------------------

#[test]
fn nothing_is_dispatched_after_the_end() {
    let mut run = start(Svc::default(), opts());
    run.send(&hello());
    run.out.message();
    // In one write: the first ends the connection.
    let mut frames = request(2, "t.fatal");
    frames.extend(request(3, "t.record"));
    frames.extend(cancel(2));
    run.send(&frames);
    assert_eq!(run.exit(), Exit::Internal);
    assert_eq!(*run.svc.calls.lock().unwrap(), ["t.fatal"]);
    assert!(run.svc.cancels.lock().unwrap().is_empty());
}

#[test]
fn the_teardown_waits_for_a_callback_already_running() {
    let (release, wait) = mpsc::channel();
    let svc = Svc {
        slow: Mutex::new(Some(wait)),
        ..Default::default()
    };
    let mut run = start(svc, opts());
    run.send(&hello());
    run.out.message();
    run.send(&request(2, "t.slow"));
    wait_for("t.slow", || run.svc.in_callback.load(Ordering::SeqCst));
    // Another thread ends the connection while the callback runs.
    run.conn().fail(Exit::Internal);
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        run.svc.ends.lock().unwrap().is_empty(),
        "end ran beside the callback"
    );
    release.send(()).unwrap();
    assert_eq!(run.exit(), Exit::Internal);
    assert!(!run.svc.end_overlapped.load(Ordering::SeqCst));
    assert_eq!(*run.svc.ends.lock().unwrap(), [End::Fatal(Exit::Internal)]);
    // Its owed reply, queued while the connection closed, was written.
    let reply = run.out.message();
    assert_eq!(
        (reply["id"].as_u64(), &reply["result"]),
        (Some(2), &json!("late"))
    );
}

// ---- wakers outside the lock ---------------------------------------------

struct StatsWake {
    conn: Connection,
    woke: mpsc::Sender<bool>,
}

impl Wake for StatsWake {
    fn wake(self: Arc<Self>) {
        let _ = self.conn.stats();
        let _ = self.woke.send(self.conn.is_ended());
    }
}

/// Fills stream 2's window, then parks a send with a waker that calls
/// back into the connection.
fn waiting_send(run: &mut Running) -> mpsc::Receiver<bool> {
    run.send(&hello());
    run.out.message();
    run.send(&request(2, "t.window"));
    run.out.message();
    let mut bytes = 0;
    while bytes < WINDOW {
        let frame = run.out.frame().unwrap();
        bytes += frame.payload.len() - 8;
    }
    let conn = run.conn();
    let (woke, rx) = mpsc::channel();
    let waker = Arc::new(StatsWake {
        conn: conn.clone(),
        woke,
    })
    .into();
    let mut cx = Context::from_waker(&waker);
    let mut send = std::pin::pin!(conn.send(2, b"next"));
    assert!(send.as_mut().poll(&mut cx).is_pending());
    rx
}

#[test]
fn a_waker_may_call_back_into_the_connection_on_credit() {
    let mut run = start(Svc::default(), opts());
    let woke = waiting_send(&mut run);
    run.send(&credit_frame(2, 1).unwrap());
    assert_eq!(woke.recv_timeout(Duration::from_secs(2)), Ok(false));
}

#[test]
fn a_waker_may_call_back_into_the_connection_on_cancel_and_end() {
    let mut run = start(Svc::default(), opts());
    let woke = waiting_send(&mut run);
    run.send(&cancel(2));
    assert_eq!(woke.recv_timeout(Duration::from_secs(2)), Ok(false));

    let mut run = start(Svc::default(), opts());
    let woke = waiting_send(&mut run);
    run.main = None;
    assert_eq!(woke.recv_timeout(Duration::from_secs(2)), Ok(true));
    assert_eq!(run.exit(), Exit::Ok);
}

// ---- the closing phase and the process's result --------------------------

#[test]
fn a_teardown_failure_sets_the_processs_result() {
    let svc = Svc {
        fatal_at_end: true,
        ..Default::default()
    };
    let mut run = start(svc, opts());
    run.send(&hello());
    run.out.message();
    run.main = None;
    assert_eq!(run.exit(), Exit::Internal);
    // The connection still ended as it did.
    assert_eq!(*run.svc.ends.lock().unwrap(), [End::Eof]);
}

#[test]
fn while_closing_what_is_owed_is_queued_and_written_and_nothing_new() {
    let svc = Svc {
        answer_at_end: true,
        ..Default::default()
    };
    let mut run = start(svc, opts());
    run.send(&hello());
    run.out.message();
    let mut frames = request(2, "t.later");
    frames.extend(request(3, "t.later"));
    frames.extend(request(4, "t.shutdown"));
    run.send(&frames);
    assert_eq!(run.exit(), Exit::Ok);
    let at_end = run.svc.at_end.lock().unwrap().clone();
    assert_eq!(
        at_end,
        [
            ("reply".to_string(), Ok(())),
            ("head with a body".to_string(), Err(SendError::Closed)),
            ("event".to_string(), Err(SendError::Closed)),
        ]
    );
    // Main, still reading, gets the teardown's reply.
    let reply = run.out.message();
    assert_eq!(
        (reply["id"].as_u64(), &reply["result"]),
        (Some(2), &json!("stopped"))
    );
    assert!(run.out.frame().is_none());
}

// ---- the handshake comes first, in time ----------------------------------

#[test]
fn an_event_before_the_handshake_ends_the_connection() {
    let mut run = start(Svc::default(), opts());
    let mut frames = framed(json!({ "type": "event", "event": "t.before", "data": null }));
    frames.extend(hello());
    run.send(&frames);
    assert_eq!(run.exit(), Exit::Protocol);
    assert_eq!(
        *run.svc.ends.lock().unwrap(),
        [End::Protocol("not_hello_first")]
    );
    // Nothing answered the hello behind it.
    assert!(run.out.frame().is_none());
}

#[test]
fn a_handshake_after_its_deadline_is_refused() {
    for _ in 0..10 {
        let options = Options {
            started: Instant::now() - Duration::from_secs(20),
            ..opts()
        };
        let mut run = start(Svc::default(), options);
        // The lifecycle thread may or may not have looked yet: either way
        // the handshake must not succeed.
        if let Some(main) = run.main.as_mut() {
            let _ = main.write_all(&hello());
        }
        run.main = None;
        assert_eq!(run.exit(), Exit::Protocol);
        assert_eq!(*run.svc.ends.lock().unwrap(), [End::HelloTimeout]);
        assert!(run.out.frame().is_none(), "a late handshake was answered");
    }
}

// ---- the exit watchdog, in a child process --------------------------------

const CHILD: &str = "FC_SERVICE_OWNERSHIP_CHILD";

/// A service whose teardown never finishes.
struct Hangs;

impl Service for Hangs {
    fn hello(&self, _: &Hello) -> Result<serde_json::Map<String, Value>, ErrorBody> {
        Ok(Default::default())
    }
    fn request(&self, _: &Connection, _: Request<'_>) {}
    fn cancel(&self, _: &Connection, _: u64) {}
    fn end(&self, _: &Connection, _: End) {
        std::thread::sleep(Duration::from_secs(10));
    }
}

/// The child half: a connection whose main closes stdin at once, so it
/// ends with EOF (exit 0) and its teardown hangs.
#[test]
fn child() {
    let Ok(mode) = std::env::var(CHILD) else {
        return;
    };
    if mode == "blocked_stderr" {
        // A line main never drains, written directly (no log thread): it
        // blocks holding stderr's lock, as the connection's end is logged.
        std::thread::spawn(|| {
            let _ = std::io::stderr().lock().write_all(&vec![b'x'; 1 << 20]);
        });
        std::thread::sleep(Duration::from_millis(100));
    }
    let mut options = Options::new("t", 1, Instant::now());
    options.exit_watchdog = Some(Duration::from_millis(300));
    let (input, main) = std::io::pipe().unwrap();
    drop(main);
    let exit = conn::run(Arc::new(Hangs), options, input, std::io::sink());
    panic!("the watchdog should have ended the process, not run ({exit:?})");
}

fn run_child(mode: &str) -> Option<(i32, String)> {
    use std::process::Stdio;
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child", "--nocapture", "--test-threads=1"])
        .env(CHILD, mode)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let drained = mode != "blocked_stderr";
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        if drained {
            let _ = stderr.read_to_string(&mut text);
        } else {
            // Never read: keep the pipe open until the child is gone.
            std::thread::sleep(Duration::from_secs(4));
            drop(stderr);
        }
        text
    });
    let until = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= until {
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let Some(status) = status else {
        child.kill().unwrap();
        child.wait().unwrap();
        return None;
    };
    Some((status.code().unwrap_or(-1), reader.join().unwrap()))
}

#[test]
fn the_exit_watchdog_exits_70_while_the_teardown_is_unproven() {
    let (code, stderr) = run_child("hang").expect("the watchdog never fired");
    // The connection ended with EOF (0), but its teardown never returned.
    assert_eq!(code, 70, "{stderr}");
    assert!(
        stderr.contains(r#""reason":"teardown_unproven""#),
        "{stderr}"
    );
}

#[test]
fn the_exit_watchdog_fires_even_when_stderr_is_not_drained() {
    let exited = run_child("blocked_stderr");
    assert_eq!(exited.map(|(code, _)| code), Some(70));
}
