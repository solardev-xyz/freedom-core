//! The `ipfs.*` methods on fc-service's connection (design 0007, "Methods").
//!
//! - `ipfs.hello` answers the service's version, the freedom-ipfs build it
//!   links, and which process this is. The connection checks the protocol
//!   and frame kinds first, and adds `protocol`.
//! - `ipfs.start` and `ipfs.stop`: [`Instances`].
//! - `ipfs.request`: [`Requests`].
//! - `ipfs.shutdown` ends the connection (fc-service); [`Service::end`]
//!   then tears down every instance, and the process exits 0.
//! - `ipfs.stats` comes with the budgets (PR 3b). Until then, as any other
//!   method, it is `unknown_method`.

use std::sync::Arc;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::{Connection, End, Hello, Request, Service};
use serde_json::{Map, Value, json};

use crate::build_info;
use crate::instances::Instances;
use crate::requests::Requests;

pub struct IpfsService {
    instances: Arc<Instances>,
    requests: Arc<Requests>,
}

impl IpfsService {
    pub fn new(instances: Arc<Instances>, requests: Arc<Requests>) -> IpfsService {
        IpfsService {
            instances,
            requests,
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
    use crate::instances::Kind;

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
                if output.read_exact(&mut payload).is_err()
                    || tx.send(serde_json::from_slice(&payload).unwrap()).is_err()
                {
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
        let requests = Requests::new(runtime.handle().clone());
        let instances = Instances::new(Kind::Ephemeral, runtime.handle().clone(), requests.clone());
        let (seen, events) = mpsc::channel();
        let service = Arc::new(Observed {
            inner: IpfsService::new(instances.clone(), requests),
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
        requests: Arc<Requests>,
        instances: Arc<Instances>,
        input: std::io::PipeWriter,
        replies: Receiver<Value>,
        pace: Pace,
        run: std::thread::JoinHandle<fc_service::Exit>,
    }

    impl Harness {
        /// With `writes` writes permitted once `e-1` is up: more are
        /// permitted with [`Pace::permit`].
        fn new(writes: usize) -> Harness {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_time()
                .build()
                .unwrap();
            let requests = Requests::new(runtime.handle().clone());
            let instances =
                Instances::new(Kind::Ephemeral, runtime.handle().clone(), requests.clone());
            let service = Arc::new(IpfsService::new(instances.clone(), requests.clone()));
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
                requests,
                instances,
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
            .with_live("e-1", |instance, _| instance.context().clone())
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
            .with_live("e-1", |instance, _| instance.context().clone())
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
}
