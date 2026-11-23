//! The step marker when main's writer is held (design 0014, "The step
//! marker"), with the service in-process and its output gated:
//! - a marker still queued after its second is taken back and never
//!   written: the request ends `busy`, and the C core isn't entered;
//! - a marker still being written then may reach main late: the service
//!   clears it (`colibri.stepped`) before its `busy`, so main reads the
//!   marker, its clearing event, then `busy`, never a step left open.

// Test code: a failed setup ends the test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{self, PipeWriter, Read, Write};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use fc_protocol::frame::KIND_JSON;
use fc_service::conn::{self, Options};
use freedom_colibrid::service::ColibriService;
use freedom_colibrid::shared::Shared;
use freedom_colibrid::store::Store;
use serde_json::{Value, json};

/// Main's side of the pipe holds the service's writer inside the first
/// write that contains `needle`, until released.
struct Gated {
    inner: PipeWriter,
    needle: Vec<u8>,
    armed: bool,
    gate: Arc<(Mutex<bool>, Condvar)>,
}

impl Write for Gated {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.armed && buf.windows(self.needle.len()).any(|w| w == self.needle) {
            self.armed = false;
            let (held, signal) = &*self.gate;
            let mut held = held.lock().unwrap();
            while *held {
                held = signal.wait(held).unwrap();
            }
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct InProcess {
    input: PipeWriter,
    messages: Receiver<Value>,
    gate: Arc<(Mutex<bool>, Condvar)>,
    next_id: u64,
}

impl InProcess {
    fn start(needle: &str) -> InProcess {
        let (main_reads, service_writes) = io::pipe().unwrap();
        let (service_reads, main_writes) = io::pipe().unwrap();
        let gate = Arc::new((Mutex::new(true), Condvar::new()));
        let output = Gated {
            inner: service_writes,
            needle: needle.as_bytes().to_vec(),
            armed: true,
            gate: Arc::clone(&gate),
        };
        let shared = Arc::new(Shared::new(1, Arc::new(Store::memory())));
        let service = Arc::new(ColibriService::new(shared, json!({})));
        let mut options = Options::new("colibri", 1, Instant::now());
        options.exit_watchdog = None;
        options.two_way = true;
        std::thread::spawn(move || conn::run(service, options, service_reads, output));
        let (tx, messages) = mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = main_reads;
            let mut header = [0u8; 4];
            while reader.read_exact(&mut header).is_ok() {
                let mut frame = vec![0u8; u32::from_be_bytes(header) as usize];
                if reader.read_exact(&mut frame).is_err() {
                    break;
                }
                if frame.first() == Some(&KIND_JSON)
                    && tx
                        .send(serde_json::from_slice(&frame[1..]).unwrap())
                        .is_err()
                {
                    break;
                }
            }
        });
        let mut main = InProcess {
            input: main_writes,
            messages,
            gate,
            next_id: 1,
        };
        main.request(
            "colibri.hello",
            json!({ "protocol": 1, "shell_version": "test", "frames": ["stream"] }),
        );
        main
    }

    fn request(&mut self, method: &str, params: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let payload =
            json!({ "type": "request", "id": id, "method": method, "params": params }).to_string();
        let mut frame = ((payload.len() + 1) as u32).to_be_bytes().to_vec();
        frame.push(KIND_JSON);
        frame.extend_from_slice(payload.as_bytes());
        self.input.write_all(&frame).unwrap();
        id
    }

    fn release(&self) {
        let (held, signal) = &*self.gate;
        *held.lock().unwrap() = false;
        signal.notify_all();
    }

    /// The steps the service has run (`colibri.stats`).
    fn steps(&mut self) -> u64 {
        let id = self.request("colibri.stats", json!({}));
        self.until_reply(id).last().unwrap()["result"]["steps"]
            .as_u64()
            .unwrap()
    }

    /// Every message until request `id`'s reply.
    fn until_reply(&self, id: u64) -> Vec<Value> {
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(message) = self.messages.recv_timeout(Duration::from_millis(200)) {
                let done = message["type"] == "response" && message["id"] == id;
                seen.push(message);
                if done {
                    return seen;
                }
            }
        }
        panic!("no reply to {id}: {seen:?}");
    }
}

fn block_number() -> Value {
    json!({
        "client": "c",
        "zk": true,
        "method": "eth_blockNumber",
        "params": "[]",
        "min_latest_block_ts": 1u64,
        "deadline_ms": 60_000u64,
    })
}

#[test]
fn a_marker_still_queued_is_taken_back_and_the_request_is_busy() {
    // The writer is held inside `colibri.stats`' reply, so the marker
    // queued behind it can't be written within its second.
    let mut main = InProcess::start("open_requests");
    let stats = main.request("colibri.stats", json!({}));
    let id = main.request("colibri.request", block_number());
    std::thread::sleep(Duration::from_millis(1500));
    main.release();
    let seen = main.until_reply(id);
    assert!(seen.iter().any(|m| m["id"] == stats), "{seen:?}");
    assert!(
        !seen.iter().any(|m| m["type"] == "event"),
        "a marker taken back never reaches main: {seen:?}"
    );
    assert_eq!(seen.last().unwrap()["error"]["code"], "busy", "{seen:?}");
    assert_eq!(main.steps(), 0, "the C core was entered");
}

#[test]
fn a_marker_still_being_written_is_cleared_before_busy() {
    // The writer is held inside the marker itself.
    let mut main = InProcess::start("colibri.step");
    let id = main.request("colibri.request", block_number());
    std::thread::sleep(Duration::from_millis(1500));
    main.release();
    let seen = main.until_reply(id);
    let order: Vec<String> = seen
        .iter()
        .filter(|m| m["type"] == "event" || m["id"] == id)
        .map(|m| match m["type"].as_str() {
            Some("event") => format!("{}:{}", m["event"].as_str().unwrap(), m["data"]["request"]),
            _ => format!("reply:{}", m["error"]["code"].as_str().unwrap_or("result")),
        })
        .collect();
    assert_eq!(
        order,
        [
            format!("colibri.step:{id}"),
            format!("colibri.stepped:{id}"),
            "reply:busy".to_owned()
        ]
    );
    assert_eq!(main.steps(), 0, "the C core was entered");
}
