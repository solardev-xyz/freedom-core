//! The `ipfs.*` methods on fc-service's connection (design 0007, "Methods").
//!
//! - `ipfs.hello` answers the service's version, the freedom-ipfs build it
//!   links, and which process this is. The connection checks the protocol
//!   and frame kinds first, and adds `protocol`.
//! - `ipfs.start` and `ipfs.stop`: [`Instances`].
//! - `ipfs.request`: [`Requests`].
//! - `ipfs.shutdown` ends the connection (fc-service); [`Service::end`]
//!   then tears down every instance, and the process exits 0.
//! - `ipfs.stats`: [`Stats`].

use std::sync::Arc;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::{Connection, End, Hello, Request, Service};
use serde_json::{Map, Value, json};

use crate::build_info;
use crate::instances::Instances;
use crate::requests::Requests;
use crate::stats::Stats;

pub struct IpfsService {
    instances: Arc<Instances>,
    requests: Arc<Requests>,
    stats: Arc<Stats>,
}

impl IpfsService {
    pub fn new(
        instances: Arc<Instances>,
        requests: Arc<Requests>,
        stats: Arc<Stats>,
    ) -> IpfsService {
        IpfsService {
            instances,
            requests,
            stats,
        }
    }
}

impl Service for IpfsService {
    fn hello(&self, _hello: &Hello) -> Result<Map<String, Value>, ErrorBody> {
        let mut members = Map::new();
        members.insert("service_version".into(), env!("CARGO_PKG_VERSION").into());
        members.insert(
            "freedom_ipfs".into(),
            json!({
                "version": build_info::FREEDOM_IPFS_VERSION,
                "git_commit": build_info::FREEDOM_IPFS_COMMIT,
            }),
        );
        members.insert("kind".into(), self.instances.kind().name().into());
        Ok(members)
    }

    fn request(&self, conn: &Connection, request: Request<'_>) {
        match request.method {
            "ipfs.start" => self.instances.start(conn, request.id, request.params),
            "ipfs.stop" => self.instances.stop(conn, request.id, request.params),
            "ipfs.request" => {
                self.requests
                    .request(&self.instances, conn, request.id, request.params);
            }
            "ipfs.stats" => self.stats.stats(
                &self.instances,
                &self.requests,
                conn,
                request.id,
                request.params,
            ),
            _ => {
                let _ = conn.reply_error(
                    request.id,
                    &ErrorBody::new(ErrorCode::UnknownMethod, "unknown method"),
                );
            }
        }
    }

    fn cancel(&self, conn: &Connection, id: u64) {
        self.requests.cancel(id);
        self.stats.cancel(id);
        self.instances.cancel(conn, id);
    }

    fn end(&self, conn: &Connection, _end: End) {
        self.instances.end(conn);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::{Read, Write};
    use std::sync::mpsc::{self, Receiver};
    use std::sync::{Condvar, Mutex};
    use std::time::{Duration, Instant};

    use fc_service::conn::{self, Options};

    use super::*;
    use crate::budget::Budgets;
    use crate::instances::Kind;
    use crate::stats::STATS_DEADLINE;

    const WAIT: Duration = Duration::from_secs(10);

    /// The writer's pace: each write it begins is counted, then waits for a
    /// permit, so a test can hold the writer inside a frame.
    #[derive(Clone, Default)]
    struct Pace(Arc<(Mutex<(usize, usize)>, Condvar)>);

    impl Pace {
        fn permit(&self, n: usize) {
            self.0.0.lock().unwrap().1 += n;
            self.0.1.notify_all();
        }

        /// Waits until the writer has begun `n` writes.
        fn begun(&self, n: usize) {
            let deadline = Instant::now() + WAIT;
            let mut state = self.0.0.lock().unwrap();
            while state.0 < n {
                let left = deadline
                    .checked_duration_since(Instant::now())
                    .expect("the writer never began");
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
            let mut state = self.pace.0.0.lock().unwrap();
            state.0 += 1;
            self.pace.0.1.notify_all();
            while state.1 == 0 {
                state = self.pace.0.1.wait(state).unwrap();
            }
            state.1 -= 1;
            drop(state);
            self.pipe.write(bytes)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.pipe.flush()
        }
    }

    /// The service, reporting the cancels it sees and answering a barrier,
    /// so a test knows what the reader has handled.
    struct Observed {
        inner: IpfsService,
        seen: mpsc::Sender<&'static str>,
    }

    impl Service for Observed {
        fn hello(&self, hello: &Hello) -> Result<Map<String, Value>, ErrorBody> {
            self.inner.hello(hello)
        }

        fn request(&self, conn: &Connection, request: Request<'_>) {
            if request.method == "test.barrier" {
                self.seen.send("barrier").unwrap();
                conn.reply(request.id, &json!({})).unwrap();
            } else {
                self.inner.request(conn, request);
            }
        }

        fn cancel(&self, conn: &Connection, id: u64) {
            self.seen.send("cancel").unwrap();
            self.inner.cancel(conn, id);
        }

        fn end(&self, conn: &Connection, end: End) {
            self.inner.end(conn, end);
        }
    }

    /// The service, with its cancel callback held while a test says so.
    struct Delayed {
        inner: IpfsService,
        /// The next cancel waits until this receives.
        gate: Arc<Mutex<Option<Receiver<()>>>>,
    }

    impl Service for Delayed {
        fn hello(&self, hello: &Hello) -> Result<Map<String, Value>, ErrorBody> {
            self.inner.hello(hello)
        }

        fn request(&self, conn: &Connection, request: Request<'_>) {
            self.inner.request(conn, request);
        }

        fn cancel(&self, conn: &Connection, id: u64) {
            let gate = self.gate.lock().unwrap().take();
            if let Some(gate) = gate {
                gate.recv_timeout(WAIT).unwrap();
            }
            self.inner.cancel(conn, id);
        }

        fn end(&self, conn: &Connection, end: End) {
            self.inner.end(conn, end);
        }
    }

    fn send(input: &mut impl Write, message: Value) {
        let mut frame = Vec::new();
        fc_protocol::frame::encode_json(message.to_string().as_bytes(), &mut frame).unwrap();
        input.write_all(&frame).unwrap();
    }

    fn request(input: &mut impl Write, id: u64, method: &str, params: Value) {
        send(
            input,
            json!({ "type": "request", "id": id, "method": method, "params": params }),
        );
    }

    /// Main's side of stdout: each message as it arrives.
    fn messages(mut output: std::io::PipeReader) -> Receiver<Value> {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            loop {
                let mut header = [0u8; 5];
                if output.read_exact(&mut header).is_err() {
                    return;
                }
                let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
                let mut payload = vec![0u8; (len as usize).saturating_sub(1)];
                if output.read_exact(&mut payload).is_err() {
                    return;
                }
                // A stream frame: its kind, its stream and its length.
                let message = if header[4] == fc_protocol::frame::KIND_JSON {
                    serde_json::from_slice(&payload).unwrap()
                } else {
                    let id = u64::from_be_bytes(payload[..8].try_into().unwrap());
                    json!({ "stream": header[4], "stream_id": id, "len": payload.len() - 8 })
                };
                if tx.send(message).is_err() {
                    return;
                }
            }
        });
        rx
    }

    /// Review of #129, M2: a cancel that arrives while the start's success
    /// waits behind a frame the writer is writing gets `cancelled`, and the
    /// instance is retired, not left live behind main's back.
    #[test]
    fn a_cancel_beating_the_writer_to_a_starts_success_retires_the_instance() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build()
            .unwrap();
        let budgets = Arc::new(Budgets::new(&Kind::Ephemeral).unwrap());
        let requests = Requests::new(runtime.handle().clone(), budgets.memory.clone());
        let instances = Instances::new(
            Kind::Ephemeral,
            runtime.handle().clone(),
            requests.clone(),
            budgets.clone(),
        );
        let (seen, events) = mpsc::channel();
        let service = Arc::new(Observed {
            inner: IpfsService::new(
                instances.clone(),
                requests,
                Stats::new(runtime.handle().clone(), budgets, STATS_DEADLINE, false),
            ),
            seen,
        });
        let (input, mut main_out) = std::io::pipe().unwrap();
        let (main_in, output) = std::io::pipe().unwrap();
        let replies = messages(main_in);
        let pace = Pace::default();
        let mut options = Options::new("ipfs", 1, Instant::now());
        // In-process: the test's own process must not be ended.
        options.exit_watchdog = None;
        let paced = Paced {
            pipe: output,
            pace: pace.clone(),
        };
        let run = std::thread::spawn(move || conn::run(service, options, input, paced));

        pace.permit(1);
        request(
            &mut main_out,
            1,
            "ipfs.hello",
            json!({ "protocol": 1, "shell_version": "test", "frames": ["stream"] }),
        );
        assert!(replies.recv_timeout(WAIT).unwrap()["result"].is_object());

        // The writer is held inside the next frame, an unknown method's
        // error, so the start's success queues behind it.
        request(&mut main_out, 2, "ipfs.nothing", json!({}));
        pace.begun(2);
        request(
            &mut main_out,
            3,
            "ipfs.start",
            json!({
                "instance": "e-1",
                "store": { "kind": "memory", "max_bytes": 1048576 },
                "routing": { "mode": "offline", "delegated_routers": [],
                    "dht_query_timeout_s": 3, "dht_max_providers": 32 },
                "gateway": { "max_concurrent_requests": 8, "request_queue_timeout_ms": 15000 },
                "network": { "mode": "direct" }
            }),
        );
        let deadline = Instant::now() + WAIT;
        while !instances.is_live("e-1") {
            assert!(Instant::now() < deadline, "the instance never came up");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Live, and its success queued: main cancels, then a barrier shows
        // the reader has handled the cancel.
        send(&mut main_out, json!({ "type": "cancel", "id": 3 }));
        request(&mut main_out, 4, "test.barrier", json!({}));
        assert_eq!(events.recv_timeout(WAIT).unwrap(), "cancel");
        assert_eq!(events.recv_timeout(WAIT).unwrap(), "barrier");
        assert!(!instances.is_live("e-1"));

        pace.permit(usize::MAX / 2);
        let unknown = replies.recv_timeout(WAIT).unwrap();
        assert_eq!(unknown["id"], 2);
        assert_eq!(unknown["error"]["code"], "unknown_method");
        let start = replies.recv_timeout(WAIT).unwrap();
        assert_eq!(start["id"], 3, "{start}");
        assert_eq!(start["error"]["code"], "cancelled", "{start}");
        assert_eq!(replies.recv_timeout(WAIT).unwrap()["id"], 4);

        // Retired: a stop finds nothing, and the ID stays taken.
        request(&mut main_out, 5, "ipfs.stop", json!({ "instance": "e-1" }));
        let stop = replies.recv_timeout(WAIT).unwrap();
        assert_eq!(stop["error"]["code"], "stopped", "{stop}");
        request(&mut main_out, 6, "ipfs.shutdown", json!({}));
        drop(main_out);
        assert_eq!(run.join().unwrap(), fc_service::Exit::Ok);
        runtime.shutdown_background();
    }

    /// A connection over pipes to the service, with a paced writer, and an
    /// ephemeral offline instance `e-1` started.
    struct Harness {
        runtime: tokio::runtime::Runtime,
        budgets: Arc<Budgets>,
        requests: Arc<Requests>,
        instances: Arc<Instances>,
        stats: Arc<Stats>,
        /// Holds the next cancel callback, once set.
        cancel_gate: Arc<Mutex<Option<Receiver<()>>>>,
        input: std::io::PipeWriter,
        replies: Receiver<Value>,
        pace: Pace,
        run: std::thread::JoinHandle<fc_service::Exit>,
    }

    impl Harness {
        /// With `writes` writes permitted once `e-1` is up: more are
        /// permitted with [`Pace::permit`].
        fn new(writes: usize) -> Harness {
            Harness::with(writes, 512, STATS_DEADLINE)
        }

        /// As [`Harness::new`], with a process runtime of `blocking`
        /// blocking threads, and `ipfs.stats` due in `stats_deadline`.
        fn with(writes: usize, blocking: usize, stats_deadline: Duration) -> Harness {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .max_blocking_threads(blocking)
                .enable_time()
                .build()
                .unwrap();
            let budgets = Arc::new(Budgets::new(&Kind::Ephemeral).unwrap());
            let requests = Requests::new(runtime.handle().clone(), budgets.memory.clone());
            let instances = Instances::new(
                Kind::Ephemeral,
                runtime.handle().clone(),
                requests.clone(),
                budgets.clone(),
            );
            let stats = Stats::new(
                runtime.handle().clone(),
                budgets.clone(),
                stats_deadline,
                false,
            );
            let cancel_gate = Arc::new(Mutex::new(None));
            let service = Arc::new(Delayed {
                inner: IpfsService::new(instances.clone(), requests.clone(), stats.clone()),
                gate: cancel_gate.clone(),
            });
            let (input, mut main_out) = std::io::pipe().unwrap();
            let (main_in, output) = std::io::pipe().unwrap();
            let replies = messages(main_in);
            let pace = Pace::default();
            // The handshake's reply and the start's.
            pace.permit(2 + writes);
            let mut options = Options::new("ipfs", 1, Instant::now());
            options.exit_watchdog = None;
            let paced = Paced {
                pipe: output,
                pace: pace.clone(),
            };
            let run = std::thread::spawn(move || conn::run(service, options, input, paced));
            request(
                &mut main_out,
                1,
                "ipfs.hello",
                json!({ "protocol": 1, "shell_version": "test", "frames": ["stream"] }),
            );
            assert!(replies.recv_timeout(WAIT).unwrap()["result"].is_object());
            request(
                &mut main_out,
                2,
                "ipfs.start",
                json!({
                    "instance": "e-1",
                    "store": { "kind": "memory", "max_bytes": 1048576 },
                    "routing": { "mode": "offline", "delegated_routers": [],
                        "dht_query_timeout_s": 3, "dht_max_providers": 32 },
                    "gateway": { "max_concurrent_requests": 8, "request_queue_timeout_ms": 15000 },
                    "network": { "mode": "direct" }
                }),
            );
            assert_eq!(
                replies.recv_timeout(WAIT).unwrap()["result"]["instance"],
                "e-1"
            );
            Harness {
                runtime,
                budgets,
                requests,
                instances,
                stats,
                cancel_gate,
                input: main_out,
                replies,
                pace,
                run,
            }
        }

        /// A `HEAD` for content the instance doesn't have: an HTTP failure,
        /// as a head without a body.
        fn head(&mut self, id: u64, headers_ms: u64) {
            request(
                &mut self.input,
                id,
                "ipfs.request",
                json!({ "instance": "e-1", "method": "HEAD",
                    "path": "/ipfs/bafkreibqphrxowsfix3hzojgk7grevwfojnu52chl5g3sg4pfwphq7yepq",
                    "headers": [], "headers_ms": headers_ms }),
            );
        }

        fn shut_down(mut self) {
            self.pace.permit(usize::MAX / 2);
            request(&mut self.input, 1 << 20, "ipfs.shutdown", json!({}));
            drop(self.input);
            assert_eq!(self.run.join().unwrap(), fc_service::Exit::Ok);
            self.runtime.shutdown_background();
        }
    }

    /// Holds both workers of a runtime until released.
    #[derive(Clone, Default)]
    struct Workers(Arc<(Mutex<bool>, Condvar)>);

    impl Workers {
        fn hold(handle: &tokio::runtime::Handle) -> Workers {
            let gate = Workers::default();
            let (held, holding) = mpsc::channel();
            for _ in 0..2 {
                let (gate, held) = (gate.clone(), held.clone());
                drop(handle.spawn(async move {
                    held.send(()).unwrap();
                    let mut released = gate.0.0.lock().unwrap();
                    while !*released {
                        released = gate.0.1.wait(released).unwrap();
                    }
                }));
            }
            holding.recv_timeout(WAIT).unwrap();
            holding.recv_timeout(WAIT).unwrap();
            gate
        }

        fn release(&self) {
            *self.0.0.lock().unwrap() = true;
            self.0.1.notify_all();
        }
    }

    /// Review of #140: a request is admitted until its terminal is written,
    /// not only claimed: here a head without a body, held in its write.
    #[test]
    fn admission_lasts_until_a_bodiless_head_is_written() {
        let mut harness = Harness::new(0);
        harness.head(3, 30_000);
        // The writer is inside the head's write, and the work has ended:
        // its watcher has had time to see it.
        harness.pace.begun(3);
        std::thread::sleep(Duration::from_millis(500));
        let held = harness.requests.admitted();
        harness.pace.permit(usize::MAX / 2);
        assert_eq!(harness.replies.recv_timeout(WAIT).unwrap()["id"], 3);
        let deadline = Instant::now() + WAIT;
        while harness.requests.admitted() > 0 {
            assert!(Instant::now() < deadline, "released once written");
            std::thread::sleep(Duration::from_millis(5));
        }
        harness.shut_down();
        assert_eq!(held, 1, "its terminal was still being written");
    }

    /// Review of #140: a head the work produces after `headers_ms` is never
    /// sent, even with the deadline's watcher held up.
    #[test]
    fn a_late_head_never_beats_a_delayed_deadline_watcher() {
        let mut harness = Harness::new(usize::MAX / 2);
        let context = harness
            .instances
            .with_live("e-1", |running| running.instance.context().clone())
            .unwrap();
        let work = Workers::hold(context.handle());
        let watchers = Workers::hold(harness.runtime.handle());
        harness.head(3, 10);
        let deadline = Instant::now() + WAIT;
        while harness.requests.admitted() == 0 {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        // Past its deadline before its work can even run.
        std::thread::sleep(Duration::from_millis(150));
        work.release();
        let reply = harness.replies.recv_timeout(WAIT).unwrap();
        watchers.release();
        harness.shut_down();
        assert_eq!(reply["error"]["code"], "deadline", "{reply}");
    }

    #[test]
    fn a_deadline_watcher_answers_work_that_never_runs() {
        let mut harness = Harness::new(usize::MAX / 2);
        let context = harness
            .instances
            .with_live("e-1", |running| running.instance.context().clone())
            .unwrap();
        let work = Workers::hold(context.handle());
        harness.head(3, 10);
        let reply = harness.replies.recv_timeout(WAIT).unwrap();
        work.release();
        harness.shut_down();
        assert_eq!(reply["error"]["code"], "deadline", "{reply}");
    }

    #[test]
    fn a_head_queued_in_time_survives_a_delayed_watcher() {
        let mut harness = Harness::new(usize::MAX / 2);
        let watchers = Workers::hold(harness.runtime.handle());
        let sent = Instant::now();
        harness.head(3, 1000);
        let reply = harness.replies.recv_timeout(WAIT).unwrap();
        let elapsed = sent.elapsed();
        // The watcher runs only once its deadline has long passed.
        std::thread::sleep(Duration::from_millis(1100));
        watchers.release();
        harness.shut_down();
        assert!(elapsed < Duration::from_millis(1000), "{elapsed:?}");
        assert_eq!(reply["result"]["body"], false, "{reply}");
    }

    /// Holds `n` threads of a runtime's blocking pool until released.
    fn hold_blocking(handle: &tokio::runtime::Handle, n: usize) -> Workers {
        let gate = Workers::default();
        let (held, holding) = mpsc::channel();
        for _ in 0..n {
            let (gate, held) = (gate.clone(), held.clone());
            drop(handle.spawn_blocking(move || {
                held.send(()).unwrap();
                let mut released = gate.0.0.lock().unwrap();
                while !*released {
                    released = gate.0.1.wait(released).unwrap();
                }
            }));
        }
        for _ in 0..n {
            holding.recv_timeout(WAIT).unwrap();
        }
        gate
    }

    impl Harness {
        fn stats(&mut self, id: u64) {
            request(
                &mut self.input,
                id,
                "ipfs.stats",
                json!({ "instance": "e-1" }),
            );
        }

        /// A request the reader answers at once: once its reply is in,
        /// everything sent before it has been handled.
        fn barrier(&mut self, id: u64) {
            request(&mut self.input, id, "ipfs.nothing", json!({}));
        }

        /// Puts `data` in `e-1`'s store as a block of `codec`: its CID, as
        /// bytes and as text.
        fn put(&self, codec: u64, data: &[u8]) -> (Vec<u8>, String) {
            let store = self
                .instances
                .with_live("e-1", |running| running.instance.node().store().clone())
                .unwrap();
            let cid = freedom_ipfs_core::cid_from_data(codec, data);
            store.put_block(&cid, data).unwrap();
            (cid.to_bytes(), cid.to_string())
        }

        fn memory_used(&self) -> usize {
            self.budgets.memory.used()
        }

        /// Waits until `e-1`'s memory use is `used`.
        fn memory_back_to(&self, used: usize) {
            let deadline = Instant::now() + WAIT;
            while self.memory_used() != used {
                assert!(
                    Instant::now() < deadline,
                    "{} != {used}",
                    self.memory_used()
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        fn counters(&self) -> Value {
            self.instances
                .with_live("e-1", |running| running.counters.snapshot())
                .unwrap()
        }

        /// `e-1`'s counters once `freed` requests have ended: an outcome is
        /// counted as the work ends, a moment after its terminal.
        fn counters_once_freed(&self, freed: u64) -> Value {
            let deadline = Instant::now() + WAIT;
            loop {
                let counted = self.counters();
                if counted["total_freed"] == freed {
                    return counted;
                }
                assert!(Instant::now() < deadline, "{counted}");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    /// A UnixFS directory of one entry, `name`, for the raw block `cid`
    /// of `size` bytes.
    fn directory(name: &str, cid: &[u8], size: u64) -> Vec<u8> {
        fn varint(mut n: u64, out: &mut Vec<u8>) {
            while n >= 0x80 {
                out.push((n as u8) | 0x80);
                n >>= 7;
            }
            out.push(n as u8);
        }
        fn field(tag: u8, bytes: &[u8], out: &mut Vec<u8>) {
            out.push(tag);
            varint(bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        let mut link = Vec::new();
        field(0x0a, cid, &mut link);
        field(0x12, name.as_bytes(), &mut link);
        link.push(0x18);
        varint(size, &mut link);
        let mut node = Vec::new();
        field(0x12, &link, &mut node);
        field(0x0a, &[0x08, 1], &mut node);
        node
    }

    /// Review of #141, M1: a memory refusal before the head is queued
    /// against the head's deadline, as a head is: queued after it, it is
    /// `deadline`, whichever runtime runs first.
    #[test]
    fn a_memory_refusal_after_the_deadline_is_deadline() {
        let mut harness = Harness::new(usize::MAX / 2);
        let memory = harness.budgets.memory.clone();
        let pressure = memory.try_reserve(memory.available()).unwrap();
        let context = harness
            .instances
            .with_live("e-1", |running| running.instance.context().clone())
            .unwrap();
        let work = Workers::hold(context.handle());
        let watchers = Workers::hold(harness.runtime.handle());
        harness.head(3, 10);
        let deadline = Instant::now() + WAIT;
        while harness.requests.admitted() == 0 {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        // Past its deadline before its work can even run; then its head
        // can't be reserved.
        std::thread::sleep(Duration::from_millis(150));
        work.release();
        let reply = harness.replies.recv_timeout(WAIT).unwrap();
        watchers.release();
        drop(pressure);
        let counted = harness.counters_once_freed(1);
        harness.shut_down();
        assert_eq!(reply["error"]["code"], "deadline", "{reply}");
        assert_eq!(counted["last_native_error_code"], "deadline", "{counted}");
    }

    /// Review of #141, M2: the stats' 5 s run from when the reader handles
    /// the request, and a reply its job produces after them is `deadline`,
    /// even with the watcher held up.
    #[test]
    fn a_stats_reply_past_its_deadline_is_deadline() {
        let mut harness = Harness::with(usize::MAX / 2, 2, Duration::from_millis(300));
        let pool = hold_blocking(harness.runtime.handle(), 2);
        let watchers = Workers::hold(harness.runtime.handle());
        harness.stats(3);
        harness.barrier(4);
        assert_eq!(harness.replies.recv_timeout(WAIT).unwrap()["id"], 4);
        std::thread::sleep(Duration::from_millis(400));
        // The job runs only now, past its deadline.
        pool.release();
        let reply = harness.replies.recv_timeout(WAIT).unwrap();
        watchers.release();
        let ran = harness.stats.ran();
        harness.shut_down();
        assert_eq!(
            (&reply["id"], &reply["error"]["code"]),
            (&json!(3), &json!("deadline")),
            "{reply}"
        );
        // It started past its deadline, its watcher still held: no SQL.
        assert_eq!(ran, (1, 0));
    }

    /// Review of #141, M2: a stats reply queued in time stands, however
    /// late its watcher runs.
    #[test]
    fn a_stats_reply_in_time_survives_a_delayed_watcher() {
        let mut harness = Harness::with(usize::MAX / 2, 512, Duration::from_millis(300));
        let watchers = Workers::hold(harness.runtime.handle());
        harness.stats(3);
        let reply = harness.replies.recv_timeout(WAIT).unwrap();
        std::thread::sleep(Duration::from_millis(400));
        watchers.release();
        harness.barrier(4);
        let next = harness.replies.recv_timeout(WAIT).unwrap();
        harness.shut_down();
        assert!(reply["result"]["gateway"].is_object(), "{reply}");
        assert_eq!(next["id"], 4, "nothing more for 3: {next}");
    }

    /// Review of #141, M3: at most 4 stats jobs are outstanding, counted
    /// until each closure is dropped; a cancel fences and aborts its job,
    /// which never runs its SQL. Main sends 500 and cancels each while the
    /// blocking pool is held.
    #[test]
    fn cancelled_stats_jobs_are_bounded_and_never_run() {
        // Their deadlines far off: the cancels alone stop them.
        let mut harness = Harness::with(usize::MAX / 2, 2, Duration::from_secs(60));
        let pool = hold_blocking(harness.runtime.handle(), 2);
        for id in 3..503 {
            harness.stats(id);
            send(&mut harness.input, json!({ "type": "cancel", "id": id }));
        }
        harness.barrier(503);
        let (mut cancelled, mut busy) = (0, 0);
        loop {
            let reply = harness.replies.recv_timeout(WAIT).unwrap();
            match reply["error"]["code"].as_str() {
                _ if reply["id"] == 503 => break,
                Some("cancelled") => cancelled += 1,
                Some("busy") => busy += 1,
                _ => panic!("{reply}"),
            }
        }
        assert_eq!((cancelled, busy), (4, 496));
        assert_eq!(harness.stats.outstanding(), 4, "aborted, not yet dropped");
        pool.release();
        let deadline = Instant::now() + WAIT;
        while harness.stats.outstanding() > 0 {
            assert!(Instant::now() < deadline, "the bound was never freed");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(harness.stats.ran(), (0, 0), "a cancelled job ran");
        // The bound is free again.
        harness.stats(504);
        let reply = harness.replies.recv_timeout(WAIT).unwrap();
        harness.shut_down();
        assert!(reply["result"]["store"].is_object(), "{reply}");
    }

    /// Review of #141, M3: a job past its deadline is fenced and aborted
    /// too, and its place is held until its closure is dropped.
    #[test]
    fn expired_stats_jobs_are_fenced_and_hold_their_place_until_dropped() {
        let mut harness = Harness::with(usize::MAX / 2, 2, Duration::from_millis(300));
        let pool = hold_blocking(harness.runtime.handle(), 2);
        for id in 3..7 {
            harness.stats(id);
        }
        for _ in 3..7 {
            let reply = harness.replies.recv_timeout(WAIT).unwrap();
            assert_eq!(reply["error"]["code"], "deadline", "{reply}");
        }
        harness.stats(7);
        let refused = harness.replies.recv_timeout(WAIT).unwrap();
        assert_eq!(refused["error"]["code"], "busy", "{refused}");
        pool.release();
        let deadline = Instant::now() + WAIT;
        while harness.stats.outstanding() > 0 {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        let ran = harness.stats.ran();
        harness.shut_down();
        assert_eq!(ran, (0, 0));
    }

    /// Review of #141, m2: a cancel is counted even if its request's work
    /// ends, and its abort is written, before the service's callback runs.
    #[test]
    fn an_accepted_cancel_is_always_counted() {
        let mut harness = Harness::new(usize::MAX / 2);
        let (_, cid) = harness.put(0x55, &vec![7u8; 300 << 10]);
        request(
            &mut harness.input,
            3,
            "ipfs.request",
            json!({ "instance": "e-1", "method": "GET", "path": format!("/ipfs/{cid}"),
                "headers": [], "headers_ms": 30000 }),
        );
        assert_eq!(
            harness.replies.recv_timeout(WAIT).unwrap()["result"]["body"],
            true
        );
        let mut received = 0;
        while received < 128 << 10 {
            received += harness.replies.recv_timeout(WAIT).unwrap()["len"]
                .as_u64()
                .unwrap();
        }
        let (release, gate) = mpsc::channel();
        *harness.cancel_gate.lock().unwrap() = Some(gate);
        send(&mut harness.input, json!({ "type": "cancel", "id": 3 }));
        let abort = harness.replies.recv_timeout(WAIT).unwrap();
        assert_eq!(abort["stream"], fc_protocol::frame::KIND_ABORT, "{abort}");
        // The abort is written and the work ends, while the callback is
        // held: the request stays admitted until the callback has run.
        let until = Instant::now() + Duration::from_millis(300);
        while Instant::now() < until {
            assert_eq!(
                harness.requests.admitted(),
                1,
                "freed before its cancel ran"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        release.send(()).unwrap();
        let counted = harness.counters_once_freed(1);
        harness.shut_down();
        assert_eq!(
            (&counted["total_cancelled"], &counted["total_freed"]),
            (&json!(1), &json!(1)),
            "{counted}"
        );
        assert_eq!(counted["bytes_read"], 128 << 10, "{counted}");
    }

    /// Review of #141, concurrency 1: a head over 64 KiB (a 30,000-byte
    /// UTF-8 name, percent-encoded in its headers) holds a reservation of
    /// every byte it holds, its frame header included, while the writer
    /// writes it, and releases it once written.
    #[test]
    fn a_large_head_is_charged_while_it_is_written() {
        let mut harness = Harness::new(0);
        let name = "\u{800}".repeat(10_000);
        let (raw, _) = harness.put(0x55, b"small");
        let (_, root) = harness.put(0x70, &directory(&name, &raw, 5));
        let baseline = harness.memory_used();
        request(
            &mut harness.input,
            3,
            "ipfs.request",
            json!({ "instance": "e-1", "method": "HEAD", "path": format!("/ipfs/{root}/{name}"),
                "headers": [], "headers_ms": 30000 }),
        );
        // The writer is inside the head's first write.
        harness.pace.begun(3);
        let held = harness.memory_used() - baseline;
        harness.pace.permit(usize::MAX / 2);
        let head = harness.replies.recv_timeout(WAIT).unwrap();
        harness.memory_back_to(baseline);
        harness.shut_down();
        assert_eq!(head["result"]["status"], 200, "{head}");
        let encoded = serde_json::to_vec(&head).unwrap().len();
        assert!(encoded > 64 << 10, "{encoded}");
        assert_eq!(held, 5 + encoded, "the frame, exactly");
    }

    /// A head's charge lasts while it is written and while it waits behind
    /// another frame, and goes once it is written: the writer is held at
    /// acknowledged points rather than timed.
    #[test]
    fn a_pending_head_holds_its_size_until_it_is_written() {
        let mut harness = Harness::new(0);
        let baseline = harness.memory_used();
        harness.head(3, 30_000);
        // The writer is inside head 3's write: held.
        harness.pace.begun(3);
        let writing = harness.memory_used() - baseline;
        assert!(writing > 0);
        // Head 4 waits behind it, with its own.
        harness.head(4, 30_000);
        let deadline = Instant::now() + WAIT;
        while harness.memory_used() - baseline == writing {
            assert!(Instant::now() < deadline, "head 4 never reserved");
            std::thread::sleep(Duration::from_millis(5));
        }
        let queued = harness.memory_used() - baseline;
        harness.pace.permit(usize::MAX / 2);
        let three = harness.replies.recv_timeout(WAIT).unwrap();
        let four = harness.replies.recv_timeout(WAIT).unwrap();
        harness.memory_back_to(baseline);
        harness.shut_down();
        let frame = |head: &Value| 5 + serde_json::to_vec(head).unwrap().len();
        assert_eq!(writing, frame(&three), "{three}");
        assert_eq!(queued, frame(&three) + frame(&four), "{four}");
    }

    /// Review of #141, M3: a job cancelled once it has started, too late
    /// to abort, runs no SQL: it checks its fence first.
    #[test]
    fn a_job_cancelled_as_it_starts_runs_no_sql() {
        let mut harness = Harness::with(usize::MAX / 2, 512, Duration::from_secs(60));
        let (started, running) = mpsc::channel();
        let (release, held) = mpsc::channel::<()>();
        harness.stats.before_fence(Box::new(move || {
            started.send(()).unwrap();
            held.recv_timeout(WAIT).unwrap();
        }));
        harness.stats(3);
        running.recv_timeout(WAIT).unwrap();
        send(&mut harness.input, json!({ "type": "cancel", "id": 3 }));
        // `cancelled` is written before the service's cancel callback
        // runs: a barrier the reader answers after it acknowledges the
        // callback, and so the fence.
        harness.barrier(4);
        let reply = harness.replies.recv_timeout(WAIT).unwrap();
        assert_eq!(reply["error"]["code"], "cancelled", "{reply}");
        let barrier = harness.replies.recv_timeout(WAIT).unwrap();
        assert_eq!(barrier["id"], 4, "{barrier}");
        release.send(()).unwrap();
        let deadline = Instant::now() + WAIT;
        while harness.stats.outstanding() > 0 {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        let ran = harness.stats.ran();
        harness.shut_down();
        assert_eq!(ran, (1, 0), "started, and stopped at its fence");
    }

    /// A `HEAD` for a directory entry whose 120,000-character name makes
    /// its head larger than a frame.
    fn oversized_head(harness: &mut Harness, id: u64, headers_ms: u64) {
        let name = "\u{800}".repeat(120_000);
        let (raw, _) = harness.put(0x55, b"small");
        let (_, root) = harness.put(0x70, &directory(&name, &raw, 5));
        request(
            &mut harness.input,
            id,
            "ipfs.request",
            json!({ "instance": "e-1", "method": "HEAD", "path": format!("/ipfs/{root}/{name}"),
                "headers": [], "headers_ms": headers_ms }),
        );
    }

    /// Review of #141, round 2: a head too large for a frame is `internal`
    /// if that is queued in time, and `deadline` if its work runs late.
    #[test]
    fn an_oversized_head_is_internal_in_time_and_deadline_after() {
        let mut harness = Harness::new(usize::MAX / 2);
        oversized_head(&mut harness, 3, 30_000);
        let in_time = harness.replies.recv_timeout(WAIT).unwrap();
        let context = harness
            .instances
            .with_live("e-1", |running| running.instance.context().clone())
            .unwrap();
        let work = Workers::hold(context.handle());
        let watchers = Workers::hold(harness.runtime.handle());
        oversized_head(&mut harness, 4, 10);
        let deadline = Instant::now() + WAIT;
        while harness.requests.admitted() == 0 {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        // Past its deadline before its work can even run.
        std::thread::sleep(Duration::from_millis(150));
        work.release();
        let late = harness.replies.recv_timeout(WAIT).unwrap();
        watchers.release();
        let counted = harness.counters_once_freed(2);
        harness.shut_down();
        assert_eq!(
            (&in_time["id"], &in_time["error"]["code"]),
            (&json!(3), &json!("internal")),
            "{in_time}"
        );
        assert_eq!(
            (&late["id"], &late["error"]["code"]),
            (&json!(4), &json!("deadline")),
            "{late}"
        );
        assert_eq!(counted["last_native_error_code"], "deadline", "{counted}");
    }

    /// Review of #143: the 4 stats calls are counted until their replies
    /// are written, not until their jobs end: with the writer held, 4
    /// replies wait, a 5th call is `busy`, and their places free once
    /// they are written.
    #[test]
    fn stats_replies_waiting_for_the_writer_hold_their_places() {
        let mut harness = Harness::new(0);
        // The writer is held inside head 3.
        harness.head(3, 30_000);
        harness.pace.begun(3);
        for id in 4..8 {
            harness.stats(id);
        }
        // Every job has queued its reply and ended.
        let deadline = Instant::now() + WAIT;
        while harness.stats.replied() < 4 {
            assert!(Instant::now() < deadline, "the jobs never replied");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(harness.stats.outstanding(), 4, "held by their replies");
        harness.stats(8);
        harness.barrier(9);
        harness.pace.permit(usize::MAX / 2);
        assert_eq!(harness.replies.recv_timeout(WAIT).unwrap()["id"], 3);
        for id in 4..8 {
            let reply = harness.replies.recv_timeout(WAIT).unwrap();
            assert_eq!(reply["id"], id, "{reply}");
            assert!(reply["result"]["gateway"].is_object(), "{reply}");
        }
        let refused = harness.replies.recv_timeout(WAIT).unwrap();
        assert_eq!(
            (&refused["id"], &refused["error"]["code"]),
            (&json!(8), &json!("busy")),
            "{refused}"
        );
        assert_eq!(harness.replies.recv_timeout(WAIT).unwrap()["id"], 9);
        // Written: their places are free.
        let deadline = Instant::now() + WAIT;
        while harness.stats.outstanding() > 0 {
            assert!(Instant::now() < deadline, "the places were never freed");
            std::thread::sleep(Duration::from_millis(5));
        }
        let ran = harness.stats.ran();
        harness.shut_down();
        assert_eq!(ran, (4, 4), "the 5th never started");
    }
}
