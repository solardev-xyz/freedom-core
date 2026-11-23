//! The step marker when main's writer is held (design 0014, "The step
//! marker"), with the service in-process and its output gated:
//! - a marker still queued after its second is taken back and never
//!   written: the request ends `busy`, and the C core isn't entered;
//! - a marker still being written then may reach main late: the service
//!   clears it (`colibri.stepped`) before its `busy`, so main reads the
//!   marker, its clearing event, then `busy`, never a step left open;
//! - every call into the C core has a marker of its own: held at the n-th
//!   marker of a request, the service has made exactly n − 1 calls, for
//!   every n the request reaches (its classification, the replay clock's
//!   setting, the context's creation and freshness bound, each step and
//!   each answer, and the free). The service's own count of calls can't
//!   show two calls under one marker, so the request is also run without
//!   the replay clock: one marker fewer.
//!
//! The in-process services share one C core, so the tests take turns.

// Test code: a failed setup ends the test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{self, PipeWriter, Read, Write};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use fc_protocol::frame::KIND_JSON;
use fc_service::conn::{self, Options};
use freedom_colibrid::service::ColibriService;
use freedom_colibrid::shared::{Mode, Shared};
use freedom_colibrid::store::Store;
use serde_json::{Value, json};

/// Main's side of the pipe holds the service's writer inside the first
/// write that contains `needle`, until released.
struct Gated {
    inner: PipeWriter,
    needle: Vec<u8>,
    /// Holds at this occurrence of the needle (1 for the first).
    nth: usize,
    seen: usize,
    armed: bool,
    gate: Arc<Gate>,
}

/// Whether the writer is to be held, and whether it is.
struct Gate {
    state: Mutex<(bool, bool)>,
    signal: Condvar,
}

/// The in-process tests share one C core: one at a time.
static TURN: Mutex<()> = Mutex::new(());

impl Write for Gated {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let found = buf
            .windows(self.needle.len())
            .filter(|w| *w == self.needle)
            .count();
        if self.armed && found > 0 && self.seen + found >= self.nth {
            self.armed = false;
            let mut state = self.gate.state.lock().unwrap();
            state.1 = true;
            self.gate.signal.notify_all();
            while state.0 {
                state = self.gate.signal.wait(state).unwrap();
            }
        }
        self.seen += found;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct InProcess {
    input: PipeWriter,
    messages: Receiver<Value>,
    gate: Arc<Gate>,
    next_id: u64,
    /// Messages read while waiting for the writer to be held.
    backlog: Vec<Value>,
}

impl InProcess {
    fn start(needle: &str) -> InProcess {
        InProcess::start_at(needle, 1)
    }

    fn start_at(needle: &str, nth: usize) -> InProcess {
        let (main_reads, service_writes) = io::pipe().unwrap();
        let (service_reads, main_writes) = io::pipe().unwrap();
        let gate = Arc::new(Gate {
            state: Mutex::new((true, false)),
            signal: Condvar::new(),
        });
        let output = Gated {
            inner: service_writes,
            needle: needle.as_bytes().to_vec(),
            nth,
            seen: 0,
            armed: true,
            gate: Arc::clone(&gate),
        };
        let shared = Arc::new(Shared::new(1, Arc::new(Store::memory()), Mode::Serve));
        let service = Arc::new(ColibriService::start(shared, json!({})).unwrap());
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
            backlog: Vec::new(),
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
        self.gate.state.lock().unwrap().0 = false;
        self.gate.signal.notify_all();
    }

    /// Whether the writer is held now.
    fn holding(&self) -> bool {
        self.gate.state.lock().unwrap().1
    }

    /// Answers fetches until the writer is held, for at most `wait`.
    fn until_held(&mut self, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if self.holding() {
                return true;
            }
            if let Ok(message) = self.messages.recv_timeout(Duration::from_millis(50)) {
                if message["type"] == "request" && message["method"] == "shell.colibri_fetch" {
                    self.fail_fetch(message["id"].as_u64().unwrap());
                }
                self.backlog.push(message);
            }
        }
        self.holding()
    }

    /// The calls the service has made into the C core (`colibri.stats`).
    fn calls(&mut self) -> u64 {
        let id = self.request("colibri.stats", json!({}));
        self.until_reply(id).last().unwrap()["result"]["calls"]
            .as_u64()
            .unwrap()
    }

    /// The steps the service has run (`colibri.stats`).
    fn steps(&mut self) -> u64 {
        let id = self.request("colibri.stats", json!({}));
        self.until_reply(id).last().unwrap()["result"]["steps"]
            .as_u64()
            .unwrap()
    }

    /// Answers fetch `ask` with an error, as main does for a failed fetch.
    fn fail_fetch(&mut self, ask: u64) {
        let payload = json!({ "type": "response", "id": ask, "result": { "error": "HTTP error! Status: 500" } })
            .to_string();
        let mut frame = ((payload.len() + 1) as u32).to_be_bytes().to_vec();
        frame.push(KIND_JSON);
        frame.extend_from_slice(payload.as_bytes());
        self.input.write_all(&frame).unwrap();
    }

    /// Every message until request `id`'s reply, each fetch answered with an
    /// error on the way.
    fn until_reply(&mut self, id: u64) -> Vec<Value> {
        let mut seen = std::mem::take(&mut self.backlog);
        if seen
            .iter()
            .any(|m| m["type"] == "response" && m["id"] == id)
        {
            return seen;
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(message) = self.messages.recv_timeout(Duration::from_millis(200)) {
                if message["type"] == "request" && message["method"] == "shell.colibri_fetch" {
                    self.fail_fetch(message["id"].as_u64().unwrap());
                }
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

/// [`block_number`] at a fixed clock (the replay's `test_clock_ms`): one
/// call more, the clock's setting. The clock is now's, as the in-process
/// services share it.
fn block_number_at_a_fixed_clock() -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let mut params = block_number();
    params["test_clock_ms"] = json!(u64::try_from(now.as_millis()).unwrap());
    params
}

/// The calls `params` makes, unheld, each fetch failing, as their markers
/// name them: checked to be one marker and its clearing event each, and as
/// many as the service counts.
fn calls_unheld(params: &Value) -> Vec<String> {
    let mut main = InProcess::start_at("\"colibri.step\"", usize::MAX);
    main.release();
    let id = main.request("colibri.request", params.clone());
    let seen = main.until_reply(id);
    let markers = order(&seen, id);
    for pair in markers[..markers.len() - 1].chunks(2) {
        assert_eq!(pair, ["colibri.step", "colibri.stepped"], "{markers:?}");
    }
    let calls: Vec<String> = seen
        .iter()
        .filter(|m| m["type"] == "event" && m["event"] == "colibri.step")
        .map(|m| m["data"]["call"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(main.calls(), calls.len() as u64);
    calls
}

#[test]
fn a_marker_still_queued_is_taken_back_and_the_request_is_busy() {
    let _turn = TURN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    let _turn = TURN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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

/// The markers and the reply of request `id` in `seen`, in order.
fn order(seen: &[Value], id: u64) -> Vec<String> {
    seen.iter()
        .filter(|m| m["type"] == "event" || m["id"] == id)
        .map(|m| match m["type"].as_str() {
            Some("event") => m["event"].as_str().unwrap().to_owned(),
            _ => format!("reply:{}", m["error"]["code"].as_str().unwrap_or("result")),
        })
        .collect()
}

#[test]
fn every_call_into_the_c_core_has_a_marker_of_its_own() {
    let _turn = TURN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Unheld: how many calls the request makes. The clock's setting is a
    // call of its own, with a marker of its own: the count the service
    // keeps can't show that, so the request is run both ways.
    let params = block_number_at_a_fixed_clock();
    let calls = calls_unheld(&params);
    assert_eq!(
        calls[..5],
        ["classify", "clock", "create", "freshness", "execute"],
        "{calls:?}"
    );
    assert_eq!(calls.last().unwrap(), "free", "{calls:?}");
    let mut without_clock = calls.clone();
    without_clock.remove(1);
    assert_eq!(calls_unheld(&block_number()), without_clock);
    let calls = calls.len();
    // Held at each marker in turn: the calls before it ran, it didn't.
    for nth in 1..=calls {
        let mut main = InProcess::start_at("\"colibri.step\"", nth);
        let before = main.calls();
        let id = main.request("colibri.request", params.clone());
        assert!(
            main.until_held(Duration::from_secs(30)),
            "marker {nth} never written"
        );
        // Past the marker's second.
        std::thread::sleep(Duration::from_millis(1300));
        main.release();
        let seen = main.until_reply(id);
        let markers = order(&seen, id);
        assert_eq!(
            markers.last().unwrap(),
            "reply:busy",
            "marker {nth}: {markers:?}"
        );
        assert_eq!(
            markers.iter().filter(|m| *m == "colibri.step").count(),
            nth,
            "marker {nth}: {markers:?}"
        );
        assert_eq!(
            markers.iter().filter(|m| *m == "colibri.stepped").count(),
            nth,
            "every marker cleared, marker {nth}: {markers:?}"
        );
        assert_eq!(
            main.calls() - before,
            (nth - 1) as u64,
            "marker {nth}: a call ran unmarked"
        );
    }
}
