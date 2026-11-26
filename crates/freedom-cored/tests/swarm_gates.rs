//! Design 0015's SWM-4 gates through the binary (SWM-4 PR 10a), after
//! `dweb_gates.rs`: the real core, the test as main ([`Rig`]: every
//! request, stream and body at once, answered as an honest main and node
//! would), and what the gates measure printed.
//!
//! - **Memory:** a 50 MiB `publishFiles` of 100 files streams with the
//!   core's resident memory up less than 4 MiB; eight concurrent 5 MiB feed
//!   reads (four latest, four at an index) whose charges never pass the
//!   swarm thread's 64 MiB, the reads that wait completing in order; eight
//!   dense 1 MiB `/stamps` replies within their charges.
//! - **Cancel at each stage** of a request: before main's reply, with the
//!   reply in flight, mid-stream (a part, a node's body, an upload's body),
//!   at the vault (its answer parked) and while the lane mines: no `shell.*`
//!   request left open, nothing signed or uploaded after, no charge held.
//! - **The interleaving gate's variants** through the pipe: the site's
//!   active identity switched to a shared one through `swarm.identities`,
//!   and a manifest projection's revoke (`swarm.manifest`'s disconnect),
//!   each with the change winning and waiting.
//! - **`vault.lock`** answered while two uploads and a mining job run,
//!   each shown running through the window: within a debug build's slack
//!   (1,000 ms at p99, as `dweb_gates.rs` allows its debug run) in CI, and
//!   within 0009's gate (50 ms at p99) over a 10 s `#[ignore]`d run.
//! - **Malformed replies** from main, one of each kind, each ending the
//!   connection; **a stalled node** ending an upload at the idle bound.
//! - **Coverage:** every `methods`, `stores` and `shell` case of
//!   `vectors/swarm.json` is played by a pipe test or named here.
//!
//! **Resident memory** is read from `/proc` (Linux only). The peak is
//! charged against the core's own resident memory just before the load:
//! `/proc/<pid>/clear_refs` (`5`) starts `VmHWM` again from `VmRSS`, so the
//! peak the load reached is measured, not the vault import's or the start's.
//! Where that file can't be written, `VmRSS` is sampled as the load runs.
//!
//! **Heavy, `#[ignore]`d:** a stalled upload at D13's real 60 s idle
//! bound, no hook shortening it; and `vault.lock` for 10 s against 0009's
//! 50 ms, best on a quiet machine:
//!
//! ```sh
//! cargo test -p freedom-cored --features testhooks --test swarm_gates -- --ignored --nocapture
//! ```
//!
//! Every test here needs the test hooks (`test.swarm_world` and the swarm
//! thread's hooks), which build only into debug and test builds, so the
//! figures are a debug build's. The 50 MiB publish takes under 2 s, so it
//! runs in CI whole.

// The gates print what they measure.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

mod common;
mod swarm_world;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use common::{KIND_ABORT, KIND_DATA, KIND_END, KIND_STREAM_CREDIT, Wire, stream_frame};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use swarm_world::{Main, WINDOW, logic, page};

const MIB: usize = 1 << 20;
/// The test clock's `Date.now()`.
const CLOCK: u64 = 1_767_225_600_123;
const SITE: &str = "https://app.example";
/// The swarm thread's memory (design 0015, Budgets).
const POOL: usize = 64 * MIB;

/// One usable batch, as the node lists it.
const STAMPS: &str = r#"{"stamps":[{"batchID":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","utilization":0,"usable":true,"label":"freedom","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000}]}"#;

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn hex(bytes: &[u8]) -> String {
    logic::hex(bytes)
}

/// A site's Swarm grant, connected, its rules off unless named.
fn grant(site: &str, rules: &[&str]) -> Value {
    let on = |rule: &str| rules.contains(&rule);
    json!({
        "origin": site, "connectedAt": 1, "lastUsed": 1,
        "autoApprove": {
            "publish": on("publish"), "feeds": on("feeds"),
            "signing": on("signing"), "messaging": on("messaging"),
        },
        "messaging": { "grantedAt": 1 },
    })
}

fn grants(sites: &[&str]) -> Value {
    let mut out = serde_json::Map::new();
    for site in sites {
        out.insert((*site).to_owned(), grant(site, &[]));
    }
    Value::Object(out)
}

/// A whole node reply, as main answers `shell.swarm_api`.
fn whole(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Value {
    json!({
        "status": status, "status_text": logic::reason_phrase(status),
        "headers": headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "body_base64": b64(body),
    })
}

/// A streamed reply's head.
fn head(status: u16, headers: &[(&str, String)]) -> Value {
    json!({
        "status": status, "status_text": logic::reason_phrase(status),
        "headers": headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
    })
}

/// The node's answer to an upload it took: its reference and tag.
fn created(reference: &str, tag: u64) -> Value {
    whole(
        201,
        &[
            ("content-type", "application/json; charset=utf-8"),
            ("swarm-tag", &tag.to_string()),
        ],
        format!(r#"{{"reference":"{reference}"}}"#).as_bytes(),
    )
}

/// A SOC upload's answer: the SOC's own address, read from its path.
fn soc_created(path: &str) -> Value {
    let segments: Vec<&str> = path.split('/').collect();
    let owner: [u8; 20] = logic::unhex(segments[2]).try_into().unwrap();
    let id: [u8; 32] = logic::unhex(segments[3]).try_into().unwrap();
    let address = fc_swarm::verify::soc_address(&id, &owner);
    whole(
        201,
        &[("content-type", "application/json; charset=utf-8")],
        format!(r#"{{"reference":"{}"}}"#, hex(&address)).as_bytes(),
    )
}

// ---------------------------------------------------------------------------
// The test as main.

/// One of the core's requests of main.
#[derive(Debug, Clone)]
struct Asked {
    id: u64,
    method: String,
    params: Value,
}

impl Asked {
    fn form(&self) -> &str {
        self.params["form"].as_str().unwrap_or("")
    }

    /// The method, and a node call's form.
    fn name(&self) -> String {
        match self.method.as_str() {
            "shell.swarm_api" => format!("shell.swarm_api {}", self.form()),
            "shell.swarm_ready" => format!(
                "shell.swarm_ready {}",
                self.params["check"].as_str().unwrap_or("")
            ),
            other => other.to_owned(),
        }
    }

    /// The request it asks for.
    fn parent(&self) -> Option<u64> {
        self.params["for"]
            .as_u64()
            .or_else(|| self.params["request"].as_u64())
    }

    /// Whether it is a node call that puts something on the network.
    fn uploads(&self) -> bool {
        self.method == "shell.swarm_api"
            && [
                "bzz_file",
                "bzz_tar",
                "bytes_up",
                "chunk_up",
                "soc_up",
                "feed_manifest",
                "pss_send",
            ]
            .contains(&self.form())
    }
}

/// How main answers one of the core's requests.
enum Reply {
    /// `{ result }` at once.
    Whole(Value),
    /// A streamed reply: its head, then `body` within the core's credit,
    /// then its end.
    Stream { head: Value, body: Vec<u8> },
    /// A part: `{ bytes }`, then its bytes within the core's credit, then
    /// its end.
    Part(Vec<u8>),
    /// A call whose body streams: main asks for it with `swarm.body`, reads
    /// it, and answers the call with this at its end (none: the node's
    /// reference is the SHA-256 of the body, its tag 101).
    Upload(Option<Value>),
    /// Left unanswered, until the core cancels it or the test answers.
    Hold,
    /// Nothing at all (main's own timers: `shell.prefetch`).
    Ignore,
}

/// A stream main sends the core: a node's streamed reply, or a part.
struct Out {
    data: Vec<u8>,
    sent: usize,
    /// The core's credit past the stream's window.
    credit: u64,
    name: String,
    /// Main stops sending here (a stalled part), and never ends it.
    stall_at: Option<usize>,
}

/// A body the core sends main for one of its calls (`swarm.body`).
struct BodyIn {
    call: u64,
    /// Main's answer to the call at the body's end (none: the SHA-256 of
    /// the body as its reference).
    reply: Option<Value>,
    head: Option<u64>,
    len: usize,
    sha: Sha256,
    terminal: Option<String>,
    name: String,
}

/// A core ask main hasn't ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Open {
    Held,
    Streaming,
    Uploading,
}

type Handler = Box<dyn FnMut(&Asked) -> Reply>;

/// The cancel sweep's state for one run: the stages seen so far, the one
/// to cancel at, and what came after the cancel.
struct Sweep {
    /// The request the sweep cancels (a page's, or main's own).
    request: u64,
    at: usize,
    seen: Vec<String>,
    /// When the cancel went, and the stage it went at.
    cancelled: Option<String>,
    /// Signatures the vault had made when the cancel went.
    signed_at_cancel: usize,
    /// The last frame read before the cancel went: a FIFO round trip
    /// through the swarm thread (`test.swarm_world`) just before it, so
    /// every ask the core made before the cancel has been read by then, and
    /// any frame read after it was written after the cancel went in.
    cancelled_after: u64,
    /// The core's asks read after the cancel (`shell.swarm_unsubscribe`
    /// aside).
    after: Vec<String>,
}

/// A vault answer the swarm thread parks (`FREEDOM_CORED_TEST_SWARM_HOLD`).
struct Hold {
    kind: &'static str,
    parked: PathBuf,
    release: PathBuf,
    /// The parked answer was seen this run.
    seen: bool,
}

struct Rig {
    main: Main,
    handler: Handler,
    /// Answers to main's own requests, with when each was read.
    answers: BTreeMap<u64, (Value, Instant)>,
    /// Every ask of the core, in order, with when it came.
    asked: Vec<(Asked, Instant)>,
    open: BTreeMap<u64, Open>,
    /// The core's cancels of its own asks.
    cancels: Vec<u64>,
    out: BTreeMap<u64, Out>,
    bodies: BTreeMap<u64, BodyIn>,
    /// Bodies whose terminal came, by their call.
    done_bodies: BTreeMap<u64, BodyIn>,
    /// Main holds its bulk credit (design 0005): it may begin a fragmented
    /// answer.
    bulk: bool,
    queued: VecDeque<Vec<Vec<u8>>>,
    /// Main credits each body frame as it reads it (the node takes it).
    credit_bodies: bool,
    events: Vec<Value>,
    /// When main last sent a stream frame.
    progress: Option<Instant>,
    sweep: Option<Sweep>,
    hold: Option<Hold>,
    /// The vault's signature marker (`FREEDOM_CORED_TEST_SWARM_SIGN_MARKER`).
    marker: Option<PathBuf>,
    /// A subscription's search: since its readiness was answered.
    mining: Option<Instant>,
    /// Resident memory sampled as the load runs, in KiB (where
    /// `clear_refs` can't be written).
    sampled: Option<u64>,
    /// A fragmented message being read: its declared length and its bytes.
    partial: Option<(usize, Vec<u8>)>,
    /// Main stops sending each part here, and never ends it (a stalled
    /// read of the picked file).
    stall_parts_at: Option<usize>,
    /// Frames read during a barrier, handled after it, with their numbers.
    backlog: VecDeque<(Wire, Instant, u64)>,
    /// How many frames have been read off the pipe, and the number of the
    /// one being handled.
    read: u64,
    handling: u64,
}

impl Rig {
    fn new(main: Main, handler: Handler) -> Rig {
        Rig {
            main,
            handler,
            answers: BTreeMap::new(),
            asked: Vec::new(),
            open: BTreeMap::new(),
            cancels: Vec::new(),
            out: BTreeMap::new(),
            bodies: BTreeMap::new(),
            done_bodies: BTreeMap::new(),
            bulk: true,
            queued: VecDeque::new(),
            credit_bodies: true,
            events: Vec::new(),
            progress: None,
            sweep: None,
            hold: None,
            marker: None,
            mining: None,
            sampled: None,
            partial: None,
            stall_parts_at: None,
            backlog: VecDeque::new(),
            read: 0,
            handling: 0,
        }
    }

    /// A page's `swarm.request`: its ID.
    fn request(&mut self, site: &str, params: &str) -> u64 {
        self.main.request(&page(site), params)
    }

    /// One of main's own methods (or the chrome's): its ID.
    fn own(&mut self, method: &str, params: &Value, caller: &str) -> u64 {
        self.main.own_request(method, params, caller)
    }

    fn cancel(&mut self, id: u64) {
        self.main.core.send(&json!({ "type": "cancel", "id": id }));
    }

    /// `test.swarm_world`, answered while everything else is.
    fn world(&mut self, params: Value) -> Value {
        let id = self.own("test.swarm_world", &params, "shell");
        self.until(Duration::from_secs(30), "test.swarm_world", |rig| {
            rig.answers.contains_key(&id)
        });
        let (answer, _) = self.answers.remove(&id).unwrap();
        assert!(answer["result"].is_object(), "{answer}");
        answer["result"].clone()
    }

    /// Waits until the thread holds no charge, request or stream (a base
    /// goes once the writer has written its answer, a moment after main
    /// reads it).
    fn settled(&mut self) {
        let mut held = Value::Null;
        for _ in 0..400 {
            held = self.world(json!({}));
            if held == json!({ "memory": 0, "requests": 0, "streams": 0 }) {
                return;
            }
            self.step(Duration::from_millis(5));
        }
        panic!("the thread still holds {held}");
    }

    /// Request `id`'s answer, once it came.
    fn answer(&self, id: u64) -> &Value {
        &self.answers[&id].0
    }

    fn answered(&self, id: u64) -> bool {
        self.answers.contains_key(&id)
    }

    /// Handles what comes until `done`, for at most `within`.
    fn until(&mut self, within: Duration, what: &str, done: impl Fn(&Rig) -> bool) {
        let deadline = Instant::now() + within;
        while !done(self) {
            assert!(
                Instant::now() < deadline,
                "not within {within:?}: {what}; open {:?}, out {:?}, bodies {:?}; the sweep's \
                 stages {:?}, cancelled at {:?}; the last asks {:?}",
                self.open,
                self.out.keys().collect::<Vec<_>>(),
                self.bodies.keys().collect::<Vec<_>>(),
                self.sweep.as_ref().map(|s| &s.seen),
                self.sweep.as_ref().map(|s| &s.cancelled),
                self.asked
                    .iter()
                    .rev()
                    .take(4)
                    .map(|(a, _)| (a.id, a.name()))
                    .collect::<Vec<_>>(),
            );
            self.step(Duration::from_millis(20));
        }
    }

    /// Main's answer to the core's request `id`, fragmented past one frame
    /// (and then only while main holds its bulk credit).
    fn send_answer(&mut self, id: u64, result: Value) {
        let message = json!({ "type": "response", "id": id, "result": result });
        let len = serde_json::to_vec(&message).unwrap().len();
        if len <= fc_protocol::frame::MAX_PAYLOAD {
            self.main.core.send(&message);
            return;
        }
        let pieces = len.div_ceil(fc_protocol::frame::MAX_PAYLOAD / 2);
        self.queued.push_back(common::fragmented(&message, pieces));
        self.flush_fragments();
    }

    fn flush_fragments(&mut self) {
        if !self.bulk {
            return;
        }
        if let Some(frames) = self.queued.pop_front() {
            self.bulk = false;
            for frame in frames {
                self.main.core.send_raw(&frame);
            }
        }
    }

    fn refuse_cancelled(&mut self, id: u64) {
        self.main
            .refuse(id, json!({ "code": "cancelled", "message": "Cancelled" }));
    }

    /// Notes a stage of the sweep, and cancels its request there if it is
    /// the one: whether it did.
    fn stage(&mut self, name: String) -> bool {
        let Some(sweep) = self.sweep.as_mut() else {
            return false;
        };
        if sweep.cancelled.is_some() {
            return false;
        }
        sweep.seen.push(name.clone());
        if sweep.seen.len() - 1 != sweep.at {
            return false;
        }
        let request = sweep.request;
        // Everything the core wrote before this is read first.
        self.barrier();
        let read = self.read;
        let signed = self.marker.as_ref().map_or(0, |m| lines(m));
        let sweep = self.sweep.as_mut().unwrap();
        sweep.cancelled = Some(name);
        sweep.signed_at_cancel = signed;
        sweep.cancelled_after = read;
        self.cancel(request);
        true
    }

    /// A FIFO round trip through the swarm thread: `test.swarm_world {}`,
    /// answered once the thread has handled everything main sent before it,
    /// its answer written after every frame the thread wrote before. The
    /// frames read meanwhile wait in the backlog, handled after.
    fn barrier(&mut self) {
        let id = self.main.id();
        self.main.core.send(&json!({
            "type": "request", "id": id, "method": "test.swarm_world", "params": {},
            "context": { "caller": "shell" },
        }));
        loop {
            let wire = self.main.core.recv_wire();
            self.read += 1;
            if let Wire::Message(message) = &wire
                && message["type"] == "response"
                && message["id"] == id
            {
                return;
            }
            let at = self.main.core.arrived();
            self.backlog.push_back((wire, at, self.read));
        }
    }

    /// Whether the frame being handled was read after the sweep's cancel.
    fn after_cancel(&self) -> bool {
        self.sweep
            .as_ref()
            .is_some_and(|s| s.cancelled.is_some() && self.handling > s.cancelled_after)
    }

    /// One item from the core, if one comes within `within`; main's streams
    /// pumped first. Whether something came.
    fn step(&mut self, within: Duration) -> bool {
        self.pump();
        self.sample();
        let (wire, at) = match self.backlog.pop_front() {
            Some((wire, at, n)) => {
                self.handling = n;
                (wire, at)
            }
            None => {
                let Some(wire) = self.main.core.recv_wire_within(within) else {
                    self.idle();
                    return false;
                };
                self.read += 1;
                self.handling = self.read;
                (wire, self.main.core.arrived())
            }
        };
        match wire {
            Wire::Message(message) => self.message(message, at),
            // Whole frames and stream frames come between a fragmented
            // message's fragments (the writer's rule).
            Wire::Begin { bytes, .. } => {
                assert!(
                    self.partial.is_none(),
                    "a begin inside a fragmented message"
                );
                self.partial = Some((bytes, Vec::with_capacity(bytes)));
            }
            Wire::Fragment(part) => {
                self.partial
                    .as_mut()
                    .expect("a fragment")
                    .1
                    .extend_from_slice(&part);
            }
            Wire::Last(part) => {
                let (bytes, mut payload) = self.partial.take().expect("a last fragment");
                payload.extend_from_slice(&part);
                assert_eq!(payload.len(), bytes);
                self.main.core.send_credit();
                let message = serde_json::from_slice(&payload).unwrap();
                self.message(message, at);
            }
            Wire::Credit => {
                self.bulk = true;
                self.flush_fragments();
            }
            Wire::Stream {
                kind: KIND_STREAM_CREDIT,
                id,
                rest,
            } => {
                let n = u32::from_be_bytes(rest[..4].try_into().unwrap());
                if let Some(out) = self.out.get_mut(&id) {
                    out.credit += u64::from(n);
                }
            }
            Wire::Stream { kind, id, rest } => self.body_frame(kind, id, &rest),
        }
        true
    }

    fn message(&mut self, message: Value, at: Instant) {
        match message["type"].as_str().unwrap() {
            "event" => self.events.push(message),
            "response" => {
                let id = message["id"].as_u64().unwrap();
                if let Some(body) = self.bodies.get_mut(&id) {
                    match message["result"]["bytes"].as_u64() {
                        Some(bytes) => body.head = Some(bytes),
                        None => {
                            let mut body = self.bodies.remove(&id).unwrap();
                            body.terminal = Some(format!("refused: {message}"));
                            self.done_bodies.insert(body.call, body);
                        }
                    }
                    return;
                }
                let first = self.answers.insert(id, (message, at));
                assert!(first.is_none(), "one answer to {id}");
            }
            "request" => {
                let asked = Asked {
                    id: message["id"].as_u64().unwrap(),
                    method: message["method"].as_str().unwrap().to_owned(),
                    params: message["params"].clone(),
                };
                assert_eq!(message["context"]["caller"], "shell", "{message}");
                self.requested(asked, at);
            }
            "cancel" => {
                let id = message["id"].as_u64().unwrap();
                self.cancels.push(id);
                if self.out.remove(&id).is_some() {
                    self.open.remove(&id);
                    self.main.abort(id, "cancelled");
                    return;
                }
                match self.open.remove(&id) {
                    Some(Open::Held | Open::Uploading) => self.refuse_cancelled(id),
                    Some(Open::Streaming) => unreachable!("a stream main sends is in `out`"),
                    // Answered already: the answer crossed the cancel.
                    None => {}
                }
            }
            other => panic!("{other}: {message}"),
        }
    }

    fn requested(&mut self, asked: Asked, at: Instant) {
        let reply = (self.handler)(&asked);
        if matches!(reply, Reply::Ignore) {
            return;
        }
        if asked.method == "shell.swarm_ready" {
            self.mining = (asked.params["check"] == "subscribe").then(Instant::now);
        } else {
            self.mining = None;
        }
        if self.after_cancel() && asked.method != "shell.swarm_unsubscribe" {
            let name = asked.name();
            self.sweep.as_mut().unwrap().after.push(name);
        }
        let name = format!("{} {}", self.asked.len(), asked.name());
        self.asked.push((asked.clone(), at));
        let reply = if self.stage(format!("{name}: before its reply")) {
            Reply::Hold
        } else {
            // A stage here sends the cancel first: the reply then crosses
            // the core's cancel of the ask.
            self.stage(format!("{name}: its reply in flight"));
            reply
        };
        self.act(&asked, reply, name);
    }

    fn act(&mut self, asked: &Asked, reply: Reply, name: String) {
        let id = asked.id;
        match reply {
            Reply::Whole(result) => self.send_answer(id, result),
            Reply::Stream { head, body } => {
                self.send_answer(id, head);
                self.open.insert(id, Open::Streaming);
                self.out.insert(
                    id,
                    Out {
                        data: body,
                        sent: 0,
                        credit: 0,
                        name,
                        stall_at: None,
                    },
                );
            }
            Reply::Part(bytes) => {
                self.send_answer(id, json!({ "bytes": bytes.len() }));
                self.open.insert(id, Open::Streaming);
                self.out.insert(
                    id,
                    Out {
                        data: bytes,
                        sent: 0,
                        credit: 0,
                        name,
                        stall_at: self.stall_parts_at,
                    },
                );
            }
            Reply::Upload(reply) => {
                let body = self.main.id();
                self.main.core.send(&json!({
                    "type": "request", "id": body, "method": "swarm.body",
                    "params": { "for": id }, "context": { "caller": "shell" },
                }));
                self.open.insert(id, Open::Uploading);
                self.bodies.insert(
                    body,
                    BodyIn {
                        call: id,
                        reply,
                        head: None,
                        len: 0,
                        sha: Sha256::new(),
                        terminal: None,
                        name,
                    },
                );
            }
            Reply::Hold => {
                self.open.insert(id, Open::Held);
            }
            Reply::Ignore => {}
        }
    }

    /// A frame of a body the core sends main.
    fn body_frame(&mut self, kind: u8, id: u64, rest: &[u8]) {
        let body = self
            .bodies
            .get_mut(&id)
            .unwrap_or_else(|| panic!("a frame of kind {kind:#04x} for stream {id}"));
        match kind {
            KIND_DATA => {
                assert!(body.head.is_some(), "a body's data before its head");
                let first = body.len == 0;
                body.len += rest.len();
                body.sha.update(rest);
                let name = format!("{}: its body mid-stream", body.name);
                if self.credit_bodies {
                    let n = u32::try_from(rest.len()).unwrap();
                    self.main.core.send_raw(&stream_frame(
                        KIND_STREAM_CREDIT,
                        id,
                        &n.to_be_bytes(),
                    ));
                }
                if first {
                    self.stage(name);
                }
            }
            KIND_END | KIND_ABORT => {
                let mut body = self.bodies.remove(&id).unwrap();
                body.terminal = Some(if kind == KIND_END {
                    "end".to_owned()
                } else {
                    let abort: Value = serde_json::from_slice(rest).unwrap();
                    abort["code"].as_str().unwrap().to_owned()
                });
                // The node took the whole body: main answers the call.
                if kind == KIND_END && self.open.get(&body.call) == Some(&Open::Uploading) {
                    self.open.remove(&body.call);
                    let reply = body
                        .reply
                        .clone()
                        .unwrap_or_else(|| created(&hex(&body.sha.clone().finalize()), 101));
                    self.send_answer(body.call, reply);
                }
                self.done_bodies.insert(body.call, body);
            }
            other => panic!("a body frame of kind {other:#04x}"),
        }
    }

    /// Main's streams: each one's next bytes as far as the core's credit
    /// allows, a frame at a time round the streams, and its end once all
    /// went.
    fn pump(&mut self) {
        loop {
            let mut moved = false;
            let ids: Vec<u64> = self.out.keys().copied().collect();
            for id in ids {
                let out = self.out.get_mut(&id).unwrap();
                let until = out.stall_at.unwrap_or(out.data.len());
                if out.sent >= until {
                    if out.stall_at.is_none() {
                        self.out.remove(&id);
                        self.open.remove(&id);
                        self.main.core.send_raw(&stream_frame(KIND_END, id, b""));
                        moved = true;
                    }
                    continue;
                }
                let room = (WINDOW + out.credit).saturating_sub(out.sent as u64) as usize;
                if room == 0 {
                    continue;
                }
                let n = room.min(64 * 1024).min(until - out.sent);
                let first = out.sent == 0;
                let frame = stream_frame(KIND_DATA, id, &out.data[out.sent..out.sent + n]);
                out.sent += n;
                let name = format!("{}: mid-stream", out.name);
                self.main.core.send_raw(&frame);
                self.progress = Some(Instant::now());
                moved = true;
                if first {
                    self.stage(name);
                }
            }
            if !moved {
                return;
            }
        }
    }

    /// Nothing came: a parked vault answer, or a search under way, is a
    /// stage of the sweep.
    fn idle(&mut self) {
        if let Some(hold) = self.hold.as_mut()
            && !hold.seen
            && hold.parked.exists()
        {
            hold.seen = true;
            let (kind, release) = (hold.kind, hold.release.clone());
            // Cancelled here, the parked answer goes only once the thread
            // has handled the cancel: what it does then is after the cancel.
            if self.stage(format!("the vault's {kind} answer parked")) {
                self.barrier();
            }
            std::fs::write(release, "").unwrap();
        }
        if self
            .mining
            .is_some_and(|since| since.elapsed() > Duration::from_millis(100))
        {
            self.mining = None;
            self.stage("the lane mining".to_owned());
        }
    }

    /// Resident memory, sampled where the peak can't be started again.
    fn sample(&mut self) {
        if let Some(most) = self.sampled.as_mut() {
            *most = (*most).max(resident(&self.main.core).map_or(0, |(rss, _)| rss));
        }
    }
}

/// Lines on a marker file (none when it isn't there).
fn lines(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path).map_or(0, |t| t.lines().count())
}

// ---------------------------------------------------------------------------
// Resident memory.

/// The core's resident memory now and at its peak, in KiB (Linux only).
#[cfg(target_os = "linux")]
fn resident(core: &common::Core) -> Option<(u64, u64)> {
    Some(core.memory_kib())
}

#[cfg(not(target_os = "linux"))]
fn resident(_: &common::Core) -> Option<(u64, u64)> {
    None
}

/// What a load is measured against: the core's resident memory just
/// before it, the peak started again there (or sampled from there).
struct Baseline {
    rss: u64,
    reset: bool,
}

/// Starts the core's peak again from its resident memory now (`5` to
/// `clear_refs`); where that can't be done, samples it as the load runs.
fn baseline(rig: &mut Rig) -> Option<Baseline> {
    let (rss, _) = resident(&rig.main.core)?;
    let pid = rig.main.core.child.id();
    let reset = std::fs::write(format!("/proc/{pid}/clear_refs"), "5").is_ok();
    if !reset {
        rig.sampled = Some(rss);
    }
    let (rss, _) = resident(&rig.main.core)?;
    Some(Baseline { rss, reset })
}

/// The load's peak over its baseline, in KiB, and how it was read.
fn grown(rig: &mut Rig, base: &Option<Baseline>) -> Option<(u64, u64, &'static str)> {
    let base = base.as_ref()?;
    let (_, hwm) = resident(&rig.main.core)?;
    let (peak, how) = if base.reset {
        (hwm, "VmHWM since clear_refs")
    } else {
        (rig.sampled.take().unwrap_or(0), "VmRSS sampled")
    };
    Some((base.rss, peak.saturating_sub(base.rss), how))
}

// ---------------------------------------------------------------------------
// The 50 MiB publish.

/// The vectors' `publish-files-100-files-50mib`: its request, its parts and
/// the reference the node gave (SHA-256 of the tar it took).
fn fifty_mib_case() -> (String, Vec<Vec<u8>>, String) {
    let text = logic::text_of("swarm.json");
    let index = fc_json::index::Index::new(&text).unwrap();
    let case = logic::get(index.root(), "methods")
        .children()
        .find(|c| logic::get(*c, "id").is_str("publish-files-100-files-50mib"))
        .unwrap();
    let step = logic::get(case, "steps").children().next().unwrap();
    let request = format!(
        r#"{{"method":{{"string":"swarm_publishFiles"}},"params":{},"approval":"user"}}"#,
        swarm_world::wire_typed(logic::get(step, "params"))
    );
    let parts = logic::get(step, "parts")
        .children()
        .map(|part| {
            logic::content(
                &logic::string(logic::get(part, "seed")),
                logic::number(logic::get(part, "length")) as usize,
            )
        })
        .collect();
    let reference = logic::string(logic::get(logic::get(step, "result"), "reference"));
    (request, parts, reference)
}

/// Main for an upload: ready, live, one usable batch, part `k` from
/// `parts`, and an upload's body answered with the SHA-256 of what came as
/// its reference.
fn uploads(parts: Option<Vec<Vec<u8>>>) -> Handler {
    Box::new(move |asked: &Asked| match asked.method.as_str() {
        "shell.swarm_ready" => Reply::Whole(json!({ "ok": true })),
        "approval.recheck" => Reply::Whole(json!({ "live": true, "agent": false })),
        "shell.swarm_api" if asked.form() == "stamps" => Reply::Whole(whole(
            200,
            &[("content-type", "application/json")],
            STAMPS.as_bytes(),
        )),
        // A body the params carry goes whole; a streamed one through
        // `swarm.body`.
        "shell.swarm_api" if asked.uploads() => match asked.params["body"]["base64"].as_str() {
            Some(body) => {
                use base64::Engine as _;
                let body = base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .unwrap();
                Reply::Whole(created(&logic::sha(&body), 101))
            }
            None => Reply::Upload(None),
        },
        "shell.swarm_part" => {
            let parent = asked.parent().unwrap();
            let k = u32::try_from(asked.params["part"].as_u64().unwrap()).unwrap();
            let bytes = parts
                .as_ref()
                .and_then(|all| all.get(k as usize))
                .unwrap_or_else(|| panic!("no part {k} for {parent}"));
            Reply::Part(bytes.clone())
        }
        "shell.prefetch" => Reply::Ignore,
        other => panic!("the thread asked {other}: {:?}", asked.params),
    })
}

/// What a publish gave.
struct Published {
    answer: Value,
    /// The tar the node took: its SHA-256 and length.
    sha: String,
    len: usize,
    took: Duration,
}

/// Publishes `request` (its parts `parts`) from `SITE`.
fn publish(rig: &mut Rig, request: &str, parts: Vec<Vec<u8>>) -> Published {
    rig.handler = uploads(Some(parts));
    let start = Instant::now();
    let id = rig.request(SITE, request);
    rig.until(Duration::from_secs(600), "the publish", |rig| {
        rig.answered(id) && rig.open.is_empty() && rig.bodies.is_empty()
    });
    let took = start.elapsed();
    let (call, body) = rig.done_bodies.pop_last().unwrap();
    assert!(rig.open.is_empty() && call > 0);
    assert_eq!(body.terminal.as_deref(), Some("end"));
    Published {
        answer: rig.answer(id).clone(),
        sha: hex(&body.sha.clone().finalize()),
        len: body.len,
        took,
    }
}

/// A core with `env`'s hooks, the Swarm grants and stores moved, `SITE`
/// connected, the clock set.
fn rig_with(env: &[(&str, &str)], sites: &[&str]) -> Rig {
    let main = swarm_world::main_with(&["swarm"], env);
    let mut rig = Rig::new(main, uploads(None));
    rig.world(json!({ "reset": true, "clock": CLOCK, "grants": grants(sites) }));
    rig
}

/// How many publishes the warm core makes after the first.
const WARM_PUBLISHES: usize = 4;

/// The publish gate, the vectors' 50 MiB of 100 files, its tar byte for
/// byte the reference's each time:
///
/// - on a core that has published nothing yet, its peak counting the
///   upload path's one-time allocations: up less than 4 MiB;
/// - then [`WARM_PUBLISHES`] more on the same core, settled between them,
///   against the warm core's settled resident memory with its peak started
///   again once before them: the peak over all of them up less than 4 MiB
///   (each one's, and whatever they left behind together), and the settled
///   resident memory after the last within 1 MiB of the warm core's, so it
///   doesn't grow with the count (a leak of more than a quarter MiB a
///   publish fails it).
#[test]
fn a_50_mib_publish_of_100_files_streams_with_resident_memory_up_under_4_mib() {
    let (request, parts, reference) = fifty_mib_case();
    let total: usize = parts.iter().map(Vec::len).sum();
    let mut rig = rig_with(&[], &[SITE]);
    let check = |rig: &mut Rig, published: Published, what: &str| {
        let Published {
            answer,
            sha,
            len,
            took,
        } = published;
        let result = answer["result"]["result_typed"].to_string();
        assert!(result.contains(&reference), "{what}: {answer}");
        assert_eq!(
            sha, reference,
            "{what}: the tar the node took is the reference's"
        );
        assert!(
            len > total,
            "{what}: the tar holds every file: {len} of {total}"
        );
        rig.settled();
        eprintln!(
            "[publish, 50 MiB, {what}] 100 files, a {len}-byte tar streamed in {took:?} \
             ({:.1} MiB/s)",
            total as f64 / MIB as f64 / took.as_secs_f64(),
        );
    };
    // The first.
    let base = baseline(&mut rig);
    let first = publish(&mut rig, &request, parts.clone());
    let grew = grown(&mut rig, &base);
    check(&mut rig, first, "first publish");
    let Some((before, up, how)) = grew else {
        for k in 0..WARM_PUBLISHES {
            let published = publish(&mut rig, &request, parts.clone());
            check(&mut rig, published, &format!("publish {}", k + 2));
        }
        eprintln!("[publish, 50 MiB] resident memory: not measured here");
        return;
    };
    eprintln!(
        "[publish, 50 MiB, first publish] resident memory: {before} KiB before, peak +{up} KiB ({how})"
    );
    assert!(
        up < 4 * 1024,
        "the first publish: resident memory up {up} KiB, not under 4 MiB"
    );
    // The warm core.
    let warm = resident(&rig.main.core).unwrap().0;
    let base = baseline(&mut rig);
    let mut settled = Vec::new();
    for k in 0..WARM_PUBLISHES {
        let published = publish(&mut rig, &request, parts.clone());
        check(&mut rig, published, &format!("publish {}", k + 2));
        settled.push(resident(&rig.main.core).unwrap().0);
    }
    let (_, up, how) = grown(&mut rig, &base).unwrap();
    let last = *settled.last().unwrap();
    eprintln!(
        "[publish, 50 MiB, {WARM_PUBLISHES} more] resident memory: {warm} KiB settled before them, \
         peak +{up} KiB over all of them ({how}); settled after each: {settled:?} KiB"
    );
    assert!(
        up < 4 * 1024,
        "resident memory up {up} KiB over the warm publishes, not under 4 MiB"
    );
    assert!(
        last <= warm + 1024,
        "settled resident memory grew from {warm} KiB to {last} KiB over {WARM_PUBLISHES} publishes"
    );
}

// ---------------------------------------------------------------------------
// Eight concurrent 5 MiB feed reads.

/// keys.json's test keys (the abandon mnemonic's).
fn test_keys() -> logic::Keys {
    let text = logic::text_of("keys.json");
    let index = fc_json::index::Index::new(&text).unwrap();
    logic::keys(&index)
}

/// What a read charges for `n` bytes it may hold (design 0015, "The swarm
/// thread's memory"): `n + 2 × b64(n) + 16 KiB`.
fn stream_charge(n: usize) -> usize {
    n + 2 * (4 * n.div_ceil(3)) + 16 * 1024
}

/// `readFeedEntry` by topic and owner, at `index` or the latest.
fn read_feed(topic: &[u8; 32], owner: &[u8; 20], index: Option<u64>) -> String {
    let index = index.map_or(String::new(), |i| {
        format!(r#",["index",{{"number":"{i}"}}]"#)
    });
    format!(
        r#"{{"method":{{"string":"swarm_readFeedEntry"}},"params":{{"object":[["topic",{{"string":"{}"}}],["owner",{{"string":"{}"}}]{index}]}}}}"#,
        hex(topic),
        hex(owner)
    )
}

/// The node for the reads: by path, a whole reply or a streamed one.
#[derive(Clone)]
enum Served {
    Whole(Value),
    Stream(Value, std::rc::Rc<Vec<u8>>),
}

fn reads_node(paths: BTreeMap<String, Served>) -> Handler {
    Box::new(move |asked: &Asked| match asked.method.as_str() {
        "shell.swarm_ready" => Reply::Whole(json!({ "ok": true })),
        "approval.recheck" => Reply::Whole(json!({ "live": true, "agent": false })),
        "shell.swarm_api" => match paths.get(asked.params["path"].as_str().unwrap()) {
            Some(Served::Whole(reply)) => Reply::Whole(reply.clone()),
            Some(Served::Stream(head, body)) => Reply::Stream {
                head: head.clone(),
                body: body.as_ref().clone(),
            },
            None => panic!("the node has no {}", asked.params),
        },
        "shell.prefetch" => Reply::Ignore,
        other => panic!("the thread asked {other}: {:?}", asked.params),
    })
}

/// Eight connected sites each read a 5 MiB feed entry at once, four the
/// latest entry and four at an explicit index (its SOC, then the 5 MiB it
/// wraps). Each read charges about 18.4 MiB, so three run at once: the
/// charges never pass the 64 MiB, the reads that don't fit wait and then
/// complete in the order they came, every entry arrives whole, and
/// resident memory stays within the charges.
#[test]
fn eight_concurrent_5_mib_feed_reads_stay_within_64_mib() {
    const N: usize = 5 * MIB;
    let sites: Vec<String> = (0..8).map(|k| format!("https://r{k}.example")).collect();
    let all: Vec<&str> = sites.iter().map(String::as_str).collect();
    let keys = test_keys();
    let key = keys.of("publisher:0");
    let owner = fc_evm::address_of(key);
    let mut paths = BTreeMap::new();
    let mut requests = Vec::new();
    let mut entries = Vec::new();
    for k in 0..8u8 {
        let topic = [0x10 + k; 32];
        let data = std::rc::Rc::new(logic::content(&format!("feed-entry/{k}"), N));
        if k < 4 {
            let head = head(
                200,
                &[
                    ("content-type", "application/octet-stream".to_owned()),
                    ("content-length", N.to_string()),
                    ("swarm-feed-index", format!("{:016x}", 7)),
                    ("swarm-feed-index-next", format!("{:016x}", 8)),
                ],
            );
            paths.insert(
                format!("/feeds/{}/{}", hex(&owner), hex(&topic)),
                Served::Stream(head, data.clone()),
            );
            requests.push(read_feed(&topic, &owner, None));
        } else {
            // The update at index 3 wraps the entry's root chunk.
            let id = fc_swarm::verify::feed_update_id(&topic, 3);
            let mut chunks = BTreeMap::new();
            let root = logic::tree_of(&data, &mut chunks);
            let payload = root.payload().to_vec();
            let signed = fc_swarm::sign_soc(key, &id, Some(root.span()), &payload).unwrap();
            let wire = fc_swarm::soc::body(&id, &signed, &payload).unwrap();
            paths.insert(
                format!("/chunks/{}", hex(&signed.soc_address)),
                Served::Whole(whole(
                    200,
                    &[("content-type", "binary/octet-stream")],
                    &wire,
                )),
            );
            let head = head(
                200,
                &[
                    ("content-type", "application/octet-stream".to_owned()),
                    ("content-length", N.to_string()),
                ],
            );
            paths.insert(
                format!("/bytes/{}", hex(&root.address())),
                Served::Stream(head, data.clone()),
            );
            requests.push(read_feed(&topic, &owner, Some(3)));
        }
        entries.push(data);
    }
    let mut rig = rig_with(&[], &all);
    rig.handler = reads_node(paths);
    rig.world(json!({ "peak": true }));
    let base = baseline(&mut rig);
    let start = Instant::now();
    let ids: Vec<u64> = requests
        .iter()
        .zip(&sites)
        .map(|(params, site)| rig.request(site, params))
        .collect();
    rig.until(Duration::from_secs(300), "the reads", |rig| {
        ids.iter().all(|id| rig.answered(*id))
    });
    let took = start.elapsed();
    let grew = grown(&mut rig, &base);
    let peak = rig.world(json!({ "peak": true }))["peak"].as_u64().unwrap() as usize;
    rig.settled();
    // Every entry whole.
    for (k, id) in ids.iter().enumerate() {
        let answer = rig.answer(*id)["result"]["result_typed"].to_string();
        assert!(
            answer.contains(&b64(&entries[k])),
            "read {k}: {}",
            &answer[..answer.len().min(300)]
        );
    }
    // When each read's first node call went, and when it was answered.
    let first_call = |id: u64| {
        rig.asked
            .iter()
            .find(|(a, _)| a.method == "shell.swarm_api" && a.parent() == Some(id))
            .map(|(_, at)| *at)
            .unwrap()
    };
    let answered = |id: u64| rig.answers[&id].1;
    let first_answer = ids.iter().map(|id| answered(*id)).min().unwrap();
    let waited: Vec<u64> = ids
        .iter()
        .copied()
        .filter(|id| first_call(*id) > first_answer)
        .collect();
    let order: Vec<u64> = {
        let mut by_answer = waited.clone();
        by_answer.sort_by_key(|id| answered(*id));
        by_answer
    };
    let charge = stream_charge(N);
    eprintln!(
        "[feed reads] 8 × 5 MiB (4 latest, 4 at an index) in {took:?}; each charged {:.2} MiB; \
         the pool's peak {:.2} MiB of 64; {} waited, answered in order {:?} (sent {:?})",
        charge as f64 / MIB as f64,
        peak as f64 / MIB as f64,
        waited.len(),
        order,
        waited,
    );
    assert!(peak <= POOL, "the charges passed 64 MiB: {peak}");
    assert!(peak >= 3 * charge, "three reads ran at once: {peak}");
    assert!(
        waited.len() >= 4,
        "the reads that don't fit wait: {waited:?}"
    );
    assert_eq!(order, waited, "the reads that waited complete in order");
    match grew {
        Some((base, up, how)) => {
            eprintln!(
                "[feed reads] resident memory: {base} KiB before, peak +{up} KiB ({how}); \
                 the charges' peak {} KiB",
                peak / 1024
            );
            assert!(
                up <= (peak / 1024) as u64,
                "resident memory up {up} KiB, past the charges' {} KiB",
                peak / 1024
            );
        }
        None => eprintln!("[feed reads] resident memory: not measured here"),
    }
}

// ---------------------------------------------------------------------------
// Eight dense 1 MiB `/stamps` replies.

/// A `/stamps` batch's fields but its label (fc-swarm-provider's reader
/// tests' `BATCH`).
const BATCH: &str = r#""batchID":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","utilization":0,"usable":true,"depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"batchTTL":864000"#;

/// `text` with white space before its last byte, to `len` bytes.
fn padded_to(text: &str, len: usize) -> Vec<u8> {
    assert!(text.len() <= len, "{} past {len}", text.len());
    let (body, last) = text.split_at(text.len() - 1);
    let mut out = body.as_bytes().to_vec();
    out.resize(len - 1, b' ');
    out.extend_from_slice(last.as_bytes());
    out
}

/// The adversarial `/stamps` replies of design 0015's "JSON replies", each
/// at the form's 1 MiB cap or as near it as its shape allows: a reply of
/// white space; one batch whose label is the whole reply; a dense array
/// under an unknown key; 4,096 minimal batches; empty batches, whose
/// refusal's text the reader writes; nesting at 64 inside a batch; a key
/// repeated through the reply; `stamps` itself repeated.
fn dense_stamps() -> Vec<(&'static str, Vec<u8>)> {
    use fc_swarm_provider::stamps::{STAMPS_BATCH_CAP, STAMPS_REPLY_CAP as M};
    let minimal = |i: usize| {
        format!(
            "{{\"batchID\":\"{i:064x}\",\"utilization\":0,\"usable\":true,\"label\":\"\",\"depth\":0,\"amount\":\"0\",\"bucketDepth\":0,\"blockNumber\":0,\"immutableFlag\":true,\"batchTTL\":0}}"
        )
    };
    let list = |items: Vec<String>| format!("{{\"stamps\":[{}]}}", items.join(","));
    let label = {
        let prefix = format!("{{\"stamps\":[{{{BATCH},\"label\":\"");
        let mut text = prefix.clone();
        text.push_str(&"l".repeat(M - prefix.len() - 4));
        text.push_str("\"}]}");
        text
    };
    let dense = {
        let suffix = "],\"stamps\":[]}";
        let mut text = String::from("{\"x\":[0");
        let n = (M - text.len() - suffix.len()) / 2;
        text.push_str(&",0".repeat(n));
        text.push_str(suffix);
        text
    };
    let nested = format!(
        "{{\"stamps\":[{{{BATCH},\"label\":\"\",\"u\":{}{}}}]}}",
        "[".repeat(fc_swarm_provider::json::MAX_NESTING - 3),
        "]".repeat(fc_swarm_provider::json::MAX_NESTING - 3)
    );
    let repeated_key = {
        let mut text = format!("{{\"stamps\":[{{{BATCH}");
        while text.len() < M - 64 {
            text.push_str(",\"label\":\"xxxxxxxxxxxxxxxx\"");
        }
        text.push_str(",\"label\":\"last\"}]}");
        text
    };
    let repeated_stamps = {
        let mut text = String::from("{");
        while text.len() < M - 1024 {
            text.push_str(&format!("\"stamps\":[{}],", minimal(1)));
        }
        text.push_str(&format!("\"stamps\":[{{{BATCH},\"label\":\"end\"}}]}}"));
        text
    };
    let shapes = vec![
        ("white space", padded_to("{\"stamps\":[]}", M)),
        ("a label the whole reply", label.into_bytes()),
        ("a dense array under an unknown key", padded_to(&dense, M)),
        (
            "4,096 minimal batches",
            padded_to(&list((0..STAMPS_BATCH_CAP).map(minimal).collect()), M),
        ),
        (
            "empty batches refused",
            padded_to(&list(vec!["{}".to_owned(); 300]), M),
        ),
        ("nesting at 64", padded_to(&nested, M)),
        ("a key repeated", padded_to(&repeated_key, M)),
        ("stamps repeated", padded_to(&repeated_stamps, M)),
    ];
    for (what, body) in &shapes {
        assert!(
            body.len() <= M && body.len() > M - 1024,
            "{what}: {}",
            body.len()
        );
    }
    shapes
}

/// `publishData` of `bytes`, inline.
fn publish_inline(bytes: &[u8]) -> String {
    format!(
        r#"{{"method":{{"string":"swarm_publishData"}},"params":{{"object":[["data",{{"bytes":{},"kind":"Uint8Array","base64":"{}"}}],["contentType",{{"string":"application/octet-stream"}}]]}},"approval":"user"}}"#,
        bytes.len(),
        b64(bytes)
    )
}

/// Eight uploads at once, each of whose `/stamps` reply is 1 MiB of one of
/// the adversarial shapes: all eight calls' charges (7.7 MiB each) are
/// held at once within the 64 MiB, main answers them together, the core
/// reads each within its charge and every upload is answered; resident
/// memory stays within the charges.
#[test]
fn eight_dense_1_mib_stamps_replies_stay_within_their_charges() {
    use fc_swarm_provider::machine::{Form, node::whole_charge};
    let shapes = dense_stamps();
    let sites: Vec<String> = (0..8).map(|k| format!("https://s{k}.example")).collect();
    let all: Vec<&str> = sites.iter().map(String::as_str).collect();
    let mut rig = rig_with(&[], &all);
    // Main holds each `/stamps` call until all eight are out.
    let mut inner = uploads(None);
    rig.handler = Box::new(move |asked: &Asked| {
        if asked.form() == "stamps" {
            Reply::Hold
        } else {
            inner(asked)
        }
    });
    rig.world(json!({ "peak": true }));
    let base = baseline(&mut rig);
    let start = Instant::now();
    let ids: Vec<u64> = sites
        .iter()
        .map(|site| rig.request(site, &publish_inline(b"0123456789")))
        .collect();
    let stamps_calls = |rig: &Rig| -> Vec<(u64, u64)> {
        rig.asked
            .iter()
            .filter(|(a, _)| a.form() == "stamps")
            .map(|(a, _)| (a.parent().unwrap(), a.id))
            .collect()
    };
    rig.until(Duration::from_secs(30), "eight /stamps calls", |rig| {
        stamps_calls(rig).len() == 8
    });
    let held = rig.world(json!({}))["memory"].as_u64().unwrap() as usize;
    for (parent, call) in stamps_calls(&rig) {
        let k = ids.iter().position(|id| *id == parent).unwrap();
        rig.open.remove(&call);
        let reply = whole(200, &[("content-type", "application/json")], &shapes[k].1);
        rig.send_answer(call, reply);
    }
    rig.until(Duration::from_secs(120), "the uploads", |rig| {
        ids.iter().all(|id| rig.answered(*id)) && rig.open.is_empty()
    });
    let took = start.elapsed();
    let grew = grown(&mut rig, &base);
    let peak = rig.world(json!({ "peak": true }))["peak"].as_u64().unwrap() as usize;
    rig.settled();
    let charge = whole_charge(Form::Stamps);
    // What each shape gives the page: published, or the error code its
    // batch choice or bee-js's schema gives.
    let wants = [
        Some(4900),
        None,
        Some(4900),
        Some(4900),
        Some(-32603),
        None,
        None,
        None,
    ];
    let mut report = String::new();
    for (k, id) in ids.iter().enumerate() {
        let got = match swarm_world::outcome(rig.answer(*id)) {
            fc_swarm_provider::machine::Outcome::Result(_) => None,
            fc_swarm_provider::machine::Outcome::Error(failure) => {
                report += &format!(
                    "\n  {}: {} {}",
                    shapes[k].0,
                    failure.code,
                    &failure.message.as_str()[..failure.message.as_str().len().min(60)]
                );
                Some(failure.code)
            }
            other => panic!("{}: {other:?}", shapes[k].0),
        };
        if got.is_none() {
            report += &format!("\n  {}: published", shapes[k].0);
        }
        assert_eq!(got, wants[k], "{}", shapes[k].0);
    }
    eprintln!(
        "[dense /stamps] 8 × 1 MiB in {took:?}; each call charged {:.2} MiB; {:.2} MiB held with \
         all eight out; the pool's peak {:.2} MiB of 64:{report}",
        charge as f64 / MIB as f64,
        held as f64 / MIB as f64,
        peak as f64 / MIB as f64,
    );
    assert!(held >= 8 * charge, "all eight charges held at once: {held}");
    assert!(peak <= POOL, "the charges passed 64 MiB: {peak}");
    match grew {
        Some((base, up, how)) => {
            eprintln!(
                "[dense /stamps] resident memory: {base} KiB before, peak +{up} KiB ({how}); \
                 the charges' peak {} KiB",
                peak / 1024
            );
            assert!(
                up <= (peak / 1024) as u64,
                "resident memory up {up} KiB, past the charges' {} KiB",
                peak / 1024
            );
        }
        None => eprintln!("[dense /stamps] resident memory: not measured here"),
    }
}

// ---------------------------------------------------------------------------
// A cancel at each stage.

/// The interleaving gate's case (`write-soc-app-scoped-other-site-other-index`):
/// its grants, its feed store, its raw SOC's params.
struct SocCase {
    grants: Value,
    feeds: String,
    request: String,
}

fn soc_case() -> SocCase {
    let text = logic::text_of("swarm.json");
    let index = fc_json::index::Index::new(&text).unwrap();
    let case = logic::get(index.root(), "methods")
        .children()
        .find(|c| logic::get(*c, "id").is_str(GATE_CASE))
        .unwrap();
    let step = logic::get(case, "steps").children().next().unwrap();
    SocCase {
        grants: serde_json::from_str(logic::get(case, "grants").raw()).unwrap(),
        feeds: logic::string(logic::get(case, "feeds")),
        request: format!(
            r#"{{"method":{{"string":"swarm_writeSingleOwnerChunk"}},"params":{},"approval":"auto"}}"#,
            swarm_world::wire_typed(logic::get(step, "params"))
        ),
    }
}

/// `app.example` holds app-scoped index 0, exclusively; `other.example`
/// index 1. A raw SOC from `app.example` at its index.
const GATE_CASE: &str = "write-soc-app-scoped-other-site-other-index";

/// Main for a raw SOC: ready, live, one usable batch, and the SOC's upload
/// answered with its own address.
fn soc_node() -> Handler {
    Box::new(|asked: &Asked| match asked.method.as_str() {
        "shell.swarm_ready" => Reply::Whole(json!({ "ok": true })),
        "approval.recheck" => Reply::Whole(json!({ "live": true, "agent": false })),
        "shell.swarm_api" if asked.form() == "stamps" => Reply::Whole(whole(
            200,
            &[("content-type", "application/json")],
            STAMPS.as_bytes(),
        )),
        "shell.swarm_api" if asked.form() == "soc_up" => {
            Reply::Whole(soc_created(asked.params["path"].as_str().unwrap()))
        }
        "shell.prefetch" => Reply::Ignore,
        other => panic!("the thread asked {other}: {:?}", asked.params),
    })
}

/// Main for a GSOC subscription: ready, live, the subscription opened and
/// closed.
fn subscribe_node() -> Handler {
    Box::new(|asked: &Asked| match asked.method.as_str() {
        "shell.swarm_ready" => Reply::Whole(json!({ "ok": true })),
        "approval.recheck" => Reply::Whole(json!({ "live": true, "agent": false })),
        "shell.swarm_subscribe" => Reply::Whole(json!({ "id": swarm_world::SUBSCRIPTION_ID })),
        "shell.swarm_unsubscribe" => Reply::Whole(json!({})),
        "shell.prefetch" => Reply::Ignore,
        other => panic!("the thread asked {other}: {:?}", asked.params),
    })
}

/// Main for `swarm.manifest`'s check: the manifest fetched.
fn manifest_node() -> Handler {
    Box::new(|asked: &Asked| match asked.method.as_str() {
        "shell.swarm_manifest" => Reply::Whole(json!({
            "status": 200, "body_base64": b64(MANIFEST.as_bytes()),
        })),
        other => panic!("the thread asked {other}: {:?}", asked.params),
    })
}

const MANIFEST: &str = r#"{"schema":"freedom-manifest/1","name":"Freedom Notes","description":"Notes on Swarm","capabilities":{"swarm":{"publish":{"why":"To publish your notes"}}}}"#;
const BZZ_SITE: &str = "bzz://5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

/// One request the sweep cancels at each of its stages.
struct Scenario {
    name: &'static str,
    /// `test.swarm_world`'s params before each run.
    world: Value,
    handler: fn() -> Handler,
    /// Sends the request: its ID.
    send: Box<dyn Fn(&mut Rig) -> u64>,
    /// A check of each cancelled run, given its stage.
    check: Option<fn(&Rig, &str)>,
}

impl Rig {
    /// Waits until the swarm thread holds no parked vault answer: the last
    /// run's released answers go before the hold is armed again, since one
    /// still parked would hold the next run's behind it.
    fn unparked(&mut self) {
        for _ in 0..400 {
            if self.world(json!({ "parked": true }))["parked"] == 0 {
                return;
            }
            self.step(Duration::from_millis(5));
        }
        panic!("parked vault answers left");
    }

    /// Per run: what the last run saw goes.
    fn fresh(&mut self) {
        self.asked.clear();
        self.cancels.clear();
        self.done_bodies.clear();
        self.answers.clear();
        self.mining = None;
        if self.hold.is_some() {
            self.unparked();
        }
        if let Some(hold) = self.hold.as_mut() {
            let _ = std::fs::remove_file(&hold.parked);
            let _ = std::fs::remove_file(&hold.release);
            hold.seen = false;
        }
    }

    /// Runs `scenario` once, cancelling at stage `at` (`usize::MAX`: never):
    /// the sweep's record of it.
    fn run(&mut self, scenario: &Scenario, at: usize) -> (u64, Sweep) {
        self.fresh();
        self.backlog.clear();
        self.world(scenario.world.clone());
        self.handler = (scenario.handler)();
        let id = (scenario.send)(self);
        self.sweep = Some(Sweep {
            request: id,
            at,
            seen: Vec::new(),
            cancelled: None,
            signed_at_cancel: 0,
            cancelled_after: 0,
            after: Vec::new(),
        });
        self.until(Duration::from_secs(60), scenario.name, |rig| {
            rig.answered(id) && rig.open.is_empty() && rig.out.is_empty() && rig.bodies.is_empty()
        });
        let sweep = self.sweep.take().unwrap();
        (id, sweep)
    }
}

/// Every stage of `scenario` (an honest run's), then one run cancelled at
/// each: the request answered `cancelled`; every ask of main the core had
/// open cancelled by the core (the run ends only once each has ended);
/// nothing asked after the cancel but a close of the subscription it
/// opened (a FIFO round trip through the swarm thread just before the
/// cancel goes, so every frame read after it was written after the cancel
/// went in; a parked vault answer released only once a second round trip
/// shows the thread has handled the cancel); no signature after the
/// cancel; and nothing held after: no charge, no request, no stream.
fn sweep(rig: &mut Rig, scenario: &Scenario) -> usize {
    let (id, honest) = rig.run(scenario, usize::MAX);
    let answer = rig.answer(id).clone();
    assert!(
        answer.get("result").is_some(),
        "{}: {answer}",
        scenario.name
    );
    rig.settled();
    let stages: Vec<(usize, String)> = honest.seen.iter().cloned().enumerate().collect();
    assert!(!stages.is_empty(), "{}: no stage", scenario.name);
    for (at, stage) in &stages {
        let (id, run) = rig.run(scenario, *at);
        let what = format!("{}, at {stage}", scenario.name);
        assert_eq!(run.cancelled.as_deref(), Some(stage.as_str()), "{what}");
        let answer = rig.answer(id).clone();
        assert_eq!(answer["error"]["code"], "cancelled", "{what}: {answer}");
        assert!(
            run.after.is_empty(),
            "{what}: asked after the cancel: {:?}",
            run.after
        );
        if let Some(marker) = &rig.marker {
            assert_eq!(
                lines(marker),
                run.signed_at_cancel,
                "{what}: signed after the cancel"
            );
        }
        rig.settled();
        if let Some(check) = scenario.check {
            check(rig, stage);
        }
    }
    eprintln!(
        "[cancel] {}: {} stages, each cancelled:\n  {}",
        scenario.name,
        stages.len(),
        stages
            .iter()
            .map(|(_, s)| s.as_str())
            .collect::<Vec<_>>()
            .join("\n  ")
    );
    stages.len()
}

/// A page's requests: an upload with a part (its readiness, live facts,
/// batch, part, body and the record after it), a latest feed read and one
/// at an index (each node body mid-stream), and main's own `swarm.publish`
/// and `swarm.manifest` check.
#[test]
fn a_cancel_at_each_stage_leaves_nothing_open_signed_uploaded_or_held() {
    let mut rig = rig_with(&[], &[SITE]);
    let part = logic::content("cancel/part", 300_000);
    let keys = test_keys();
    let key = keys.of("publisher:0");
    let owner = fc_evm::address_of(key);
    let topic = [0x31; 32];
    let entry = std::rc::Rc::new(logic::content("cancel/entry", 300_000));
    let mut chunks = BTreeMap::new();
    let root = logic::tree_of(&entry, &mut chunks);
    let id = fc_swarm::verify::feed_update_id(&topic, 2);
    let payload = root.payload().to_vec();
    let signed = fc_swarm::sign_soc(key, &id, Some(root.span()), &payload).unwrap();
    let wire = fc_swarm::soc::body(&id, &signed, &payload).unwrap();
    let mut paths = BTreeMap::new();
    let headers = |index: bool| {
        let mut h = vec![
            ("content-type", "application/octet-stream".to_owned()),
            ("content-length", entry.len().to_string()),
        ];
        if index {
            h.push(("swarm-feed-index", format!("{:016x}", 2)));
            h.push(("swarm-feed-index-next", format!("{:016x}", 3)));
        }
        h
    };
    paths.insert(
        format!("/feeds/{}/{}", hex(&owner), hex(&topic)),
        Served::Stream(head(200, &headers(true)), entry.clone()),
    );
    paths.insert(
        format!("/chunks/{}", hex(&signed.soc_address)),
        Served::Whole(whole(
            200,
            &[("content-type", "binary/octet-stream")],
            &wire,
        )),
    );
    paths.insert(
        format!("/bytes/{}", hex(&root.address())),
        Served::Stream(head(200, &headers(false)), entry.clone()),
    );
    thread_local! {
        static PART: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
        static PATHS: std::cell::RefCell<BTreeMap<String, Served>> = const { std::cell::RefCell::new(BTreeMap::new()) };
    }
    PART.with(|p| *p.borrow_mut() = part);
    PATHS.with(|p| *p.borrow_mut() = paths);
    let world = json!({ "reset": true, "clock": CLOCK, "grants": grants(&[SITE, BZZ_SITE]) });
    let scenarios = [
        Scenario {
            name: "publishData of a 300,000-byte part",
            world: world.clone(),
            handler: || uploads(Some(vec![PART.with(|p| p.borrow().clone())])),
            send: Box::new(|rig: &mut Rig| {
                rig.request(
                    SITE,
                    r#"{"method":{"string":"swarm_publishData"},"params":{"object":[["data",{"bytes":300000,"kind":"Uint8Array","part":0}],["contentType",{"string":"application/octet-stream"}]]},"approval":"user"}"#,
                )
            }),
            check: None,
        },
        Scenario {
            name: "readFeedEntry, the latest entry",
            world: world.clone(),
            handler: || reads_node(PATHS.with(|p| p.borrow().clone())),
            send: Box::new(move |rig: &mut Rig| {
                rig.request(SITE, &read_feed(&topic, &owner, None))
            }),
            check: None,
        },
        Scenario {
            name: "readFeedEntry at an index",
            world: world.clone(),
            handler: || reads_node(PATHS.with(|p| p.borrow().clone())),
            send: Box::new(move |rig: &mut Rig| {
                rig.request(SITE, &read_feed(&topic, &owner, Some(2)))
            }),
            check: None,
        },
        Scenario {
            name: "main's swarm.publish of a picked file",
            world: world.clone(),
            handler: || uploads(Some(vec![PART.with(|p| p.borrow().clone())])),
            send: Box::new(|rig: &mut Rig| {
                rig.own(
                    "swarm.publish",
                    &json!({
                        "kind": "file", "parts": [{ "bytes": 300_000, "part": 0 }],
                        "name": "notes.txt", "pin": true, "deferred": true,
                        "history": { "type": "file", "name": "notes.txt" },
                    }),
                    "shell",
                )
            }),
            check: None,
        },
        Scenario {
            name: "main's swarm.manifest check",
            world: world.clone(),
            handler: manifest_node,
            send: Box::new(|rig: &mut Rig| {
                rig.own(
                    "swarm.manifest",
                    &json!({
                        "op": "check", "key": { "string": BZZ_SITE },
                        "url": { "string": format!("{BZZ_SITE}/index.html") },
                        "eager": { "boolean": true },
                    }),
                    "shell",
                )
            }),
            check: None,
        },
    ];
    let start = Instant::now();
    let mut stages = 0;
    for scenario in &scenarios {
        stages += sweep(&mut rig, scenario);
    }
    eprintln!("[cancel] {stages} stages in {:?}", start.elapsed());
}

/// A raw SOC, with the vault's answers parked by the hold hook: a cancel at
/// each stage of it, the owner's and the signature's parks among them; no
/// signature after any cancel, and nothing uploaded.
#[test]
fn a_cancel_at_each_stage_of_a_raw_soc_signs_and_uploads_nothing_after() {
    let case = soc_case();
    let world = json!({
        "reset": true, "clock": CLOCK, "grants": case.grants, "feeds": case.feeds,
    });
    for kind in ["owner", "sign"] {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("signed");
        let parked = dir.path().join("parked");
        let release = dir.path().join("release");
        let hold = format!("{kind}={}={}", parked.display(), release.display());
        let main = swarm_world::main_with(
            &["swarm"],
            &[
                (
                    "FREEDOM_CORED_TEST_SWARM_SIGN_MARKER",
                    marker.to_str().unwrap(),
                ),
                ("FREEDOM_CORED_TEST_SWARM_HOLD", &hold),
            ],
        );
        let mut rig = Rig::new(main, soc_node());
        rig.main.import_vault();
        rig.marker = Some(marker.clone());
        rig.hold = Some(Hold {
            kind,
            parked,
            release,
            seen: false,
        });
        let request = case.request.clone();
        let scenario = Scenario {
            name: if kind == "owner" {
                "a raw SOC, its owner parked"
            } else {
                "a raw SOC, its signature parked"
            },
            world: world.clone(),
            handler: soc_node,
            send: Box::new(move |rig: &mut Rig| rig.request(SITE, &request)),
            check: None,
        };
        let before = lines(&marker);
        let stages = sweep(&mut rig, &scenario);
        assert!(stages > 0);
        eprintln!(
            "[cancel] {}: {} signatures in all (the honest runs' and those before a cancel)",
            scenario.name,
            lines(&marker) - before
        );
    }
}

/// A GSOC subscription whose search the lane runs slowly (20 ms before each
/// batch): a cancel at each stage, the search among them; a subscription
/// opened before the cancel is closed.
#[test]
fn a_cancel_at_each_stage_of_a_subscription_closes_what_it_opened() {
    let main = swarm_world::main_with(
        &["swarm"],
        &[("FREEDOM_CORED_TEST_SWARM_MINE_DELAY_MS", "20")],
    );
    let mut rig = Rig::new(main, subscribe_node());
    let scenario = Scenario {
        name: "a GSOC subscription mined",
        world: json!({ "reset": true, "clock": CLOCK, "grants": grants(&[SITE]) }),
        handler: subscribe_node,
        send: Box::new(|rig: &mut Rig| {
            rig.request(
                SITE,
                r#"{"method":{"string":"swarm_subscribe"},"params":{"object":[["kind",{"string":"gsoc"}],["topic",{"string":"room"}]]}}"#,
            )
        }),
        // A subscription main opened is closed: once its open was answered
        // (in flight past the cancel, or before it).
        check: Some(|rig: &Rig, stage: &str| {
            let asked = |method: &str| rig.asked.iter().any(|(a, _)| a.method == method);
            let opened =
                asked("shell.swarm_subscribe") && !stage.contains("swarm_subscribe: before");
            assert_eq!(asked("shell.swarm_unsubscribe"), opened, "at {stage}");
        }),
    };
    sweep(&mut rig, &scenario);
}

// ---------------------------------------------------------------------------
// The interleaving gate's variants (design 0015, "SW-1 in the core"):
// `tests/swarm_writes.rs` plays another site taking the index, a revoke
// through the keeper, a cancel, the deadline and a failed write; here the
// change comes the way main makes it, through `swarm.identities` and
// `swarm.manifest`.

/// A core whose vault answers of `kind` park until the test releases them,
/// its vault the test mnemonic's, its signatures counted.
struct Gate {
    rig: Rig,
    _dir: tempfile::TempDir,
    marker: PathBuf,
    parked: PathBuf,
    release: PathBuf,
    case: SocCase,
}

impl Gate {
    fn new(kind: &str) -> Gate {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("signed");
        let parked = dir.path().join("parked");
        let release = dir.path().join("release");
        let hold = format!("{kind}={}={}", parked.display(), release.display());
        let main = swarm_world::main_with(
            &["swarm"],
            &[
                (
                    "FREEDOM_CORED_TEST_SWARM_SIGN_MARKER",
                    marker.to_str().unwrap(),
                ),
                ("FREEDOM_CORED_TEST_SWARM_HOLD", &hold),
            ],
        );
        let mut rig = Rig::new(main, soc_node());
        rig.main.import_vault();
        Gate {
            rig,
            _dir: dir,
            marker,
            parked,
            release,
            case: soc_case(),
        }
    }

    /// The case's world afresh, the hold armed, and `app.example` given a
    /// Bee wallet identity beside its exclusive one (not active): a shared
    /// identity to switch to.
    fn arm(&mut self) {
        self.rig.fresh();
        self.rig.unparked();
        let _ = std::fs::remove_file(&self.parked);
        let _ = std::fs::remove_file(&self.release);
        self.rig.world(json!({
            "reset": true, "clock": CLOCK, "grants": self.case.grants, "feeds": self.case.feeds,
        }));
        let made = self.op(
            "swarm.identities",
            json!({ "op": "ensureAntWalletIdentity", "key": { "string": SITE } }),
            "shell",
        );
        let made = self.rig.answer(made).clone();
        assert!(made["result"]["result_typed"].is_object(), "{made}");
        let feeds = self.feeds();
        assert!(feeds.contains("\"bee-wallet\""), "{feeds}");
        assert!(
            feeds.contains("\"activeIdentityId\": \"app-scoped:0\""),
            "{feeds}"
        );
    }

    /// One of main's (or the chrome's) store ops, sent and answered: its
    /// ID.
    fn op(&mut self, method: &str, params: Value, caller: &str) -> u64 {
        let id = self.rig.own(method, &params, caller);
        self.rig
            .until(Duration::from_secs(30), "the op's answer", |rig| {
                rig.answered(id)
            });
        id
    }

    /// Sends an op, then a FIFO round trip through the swarm thread
    /// (`test.swarm_world`), which answers only once the thread has handled
    /// the op, after any answer the op made at once: its ID, and whether it
    /// was answered. An op the hold doesn't defer has also written its
    /// change by then (the thread writes the stores synchronously), though
    /// one whose answer reads owners answers later, as the vault does.
    fn op_waits(&mut self, method: &str, params: Value, caller: &str) -> (u64, bool) {
        let id = self.rig.own(method, &params, caller);
        self.rig.world(json!({}));
        (id, self.rig.answered(id))
    }

    fn feeds(&self) -> String {
        std::fs::read_to_string(self.rig.main.core.grant_root.join("swarm-feeds.json")).unwrap()
    }

    fn grants_file(&self) -> Option<String> {
        std::fs::read_to_string(self.rig.main.core.grant_root.join("swarm-permissions.json")).ok()
    }

    fn signed(&self) -> usize {
        lines(&self.marker)
    }

    /// The raw SOC, sent; main serves it until its vault answer parks.
    fn soc_parked(&mut self) -> u64 {
        let id = self.rig.request(SITE, &self.case.request.clone());
        let parked = self.parked.clone();
        self.rig
            .until(Duration::from_secs(10), "the vault's answer parked", |_| {
                parked.exists()
            });
        id
    }

    fn release(&mut self) {
        std::fs::write(&self.release, "").unwrap();
    }

    /// Request `id`'s outcome, once answered and every ask ended: its
    /// reason (empty for a result) and how many SOCs went to the node.
    fn outcome(&mut self, id: u64) -> (String, usize) {
        self.rig
            .until(Duration::from_secs(30), "the raw SOC", |rig| {
                rig.answered(id) && rig.open.is_empty()
            });
        let posts = self
            .rig
            .asked
            .iter()
            .filter(|(a, _)| a.parent() == Some(id) && a.form() == "soc_up")
            .count();
        (reason_of(self.rig.answer(id)), posts)
    }

    /// The site's next raw SOC, the hold released: its reason and uploads.
    fn next_soc(&mut self) -> (String, usize) {
        self.release();
        let id = self.rig.request(SITE, &self.case.request.clone());
        self.outcome(id)
    }
}

/// A `swarm.request`'s error reason (`data.reason`), or "" for a result.
fn reason_of(answer: &Value) -> String {
    match swarm_world::outcome(answer) {
        fc_swarm_provider::machine::Outcome::Result(_) => String::new(),
        fc_swarm_provider::machine::Outcome::Error(failure) => {
            match failure.data.as_ref().map(|d| d.get("reason")) {
                Some(fc_swarm_provider::value::Value::String(reason)) => reason.as_str().to_owned(),
                _ => format!("{} {}", failure.code, failure.message.as_str()),
            }
        }
        other => panic!("{other:?}"),
    }
}

/// main's `activateIdentity` of the Bee wallet, a shared identity, for the
/// site.
fn switch_to_shared() -> Value {
    json!({ "op": "activateIdentity", "key": { "string": SITE }, "identity_id": { "string": "bee-wallet" } })
}

/// The chrome's `activate-feed-identity` of the same.
fn chrome_switch_to_shared() -> Value {
    json!({ "op": "activate-feed-identity", "origin": { "string": SITE }, "identity_id": { "string": "bee-wallet" } })
}

/// A manifest's disconnect of the site (`swarm:manifest-disconnect`): its
/// projections revoke the feed grant and the connection.
fn disconnect() -> Value {
    json!({ "op": "disconnect", "origin": { "string": SITE } })
}

/// The change wins: the raw SOC paused after its first SW-1 check (the
/// vault's owner parked), main switches the site's active identity to the
/// shared Bee wallet through `swarm.identities`, or a manifest's
/// disconnect revokes its feed grant, at once; resumed, the re-check
/// refuses: no signature, no upload.
#[test]
fn gate_the_change_wins_through_swarm_identities_and_swarm_manifest() {
    let mut gate = Gate::new("owner");
    for (what, method, params, want) in [
        (
            "a switch to a shared identity",
            "swarm.identities",
            switch_to_shared(),
            "shared_identity",
        ),
        (
            "a manifest's disconnect",
            "swarm.manifest",
            disconnect(),
            "feed_not_granted",
        ),
    ] {
        gate.arm();
        let soc = gate.soc_parked();
        // No hold yet: made at once.
        let id = gate.op(method, params, "shell");
        let made = gate.rig.answer(id).clone();
        assert!(made["result"]["result_typed"].is_object(), "{what}: {made}");
        gate.release();
        let (reason, posts) = gate.outcome(soc);
        eprintln!(
            "[gate] the change wins, {what}: {reason}, {} signed, {posts} uploaded",
            gate.signed()
        );
        assert_eq!(reason, want, "{what}");
        assert_eq!(
            (gate.signed(), posts),
            (0, 0),
            "{what}: nothing signed or uploaded"
        );
        gate.rig.settled();
    }
}

/// The change waits: the raw SOC paused with its signature parked, the
/// chrome's switch of the site's identity to the shared Bee wallet, or a
/// manifest's disconnect, waits: no answer, and nothing written. Released,
/// the change lands as the signature ends the hold, before the SOC's batch
/// and upload: the switch leaves the signed SOC to be uploaded and refuses
/// the site's next one `shared_identity`; the disconnect makes the
/// upload's guard refuse the signed SOC, as it refuses one signed just
/// before a revoke.
#[test]
fn gate_the_change_waits_through_swarm_identities_and_swarm_manifest() {
    let mut gate = Gate::new("sign");
    // The switch.
    gate.arm();
    let feeds = gate.feeds();
    let soc = gate.soc_parked();
    let (switch, answered) = gate.op_waits("swarm.identities", chrome_switch_to_shared(), "chrome");
    assert!(!answered, "the switch waits for the hold");
    assert_eq!(gate.feeds(), feeds, "and writes nothing");
    gate.release();
    let (reason, posts) = gate.outcome(soc);
    gate.rig
        .until(Duration::from_secs(10), "the switch's answer", |rig| {
            rig.answered(switch)
        });
    let made = gate.rig.answer(switch).clone();
    assert!(made["result"]["result_typed"].is_object(), "{made}");
    assert!(
        gate.feeds()
            .contains("\"activeIdentityId\": \"bee-wallet\"")
    );
    eprintln!(
        "[gate] the change waits, a switch to a shared identity: the SOC {}, {} signed, {posts} uploaded",
        if reason.is_empty() {
            "published"
        } else {
            &reason
        },
        gate.signed()
    );
    assert_eq!(reason, "", "the signed SOC is uploaded");
    assert_eq!((gate.signed(), posts), (1, 1));
    let (reason, posts) = gate.next_soc();
    assert_eq!(reason, "shared_identity", "the site's next raw SOC");
    assert_eq!((gate.signed(), posts), (1, 0));
    gate.rig.settled();

    // The disconnect.
    gate.arm();
    let feeds = gate.feeds();
    let grants = gate.grants_file();
    let signed = gate.signed();
    let soc = gate.soc_parked();
    let (disconnect, answered) = gate.op_waits("swarm.manifest", disconnect(), "shell");
    assert!(!answered, "the disconnect waits for the hold");
    assert_eq!(gate.feeds(), feeds, "and writes no feed store");
    assert_eq!(gate.grants_file(), grants, "nor the grants");
    gate.release();
    let (reason, posts) = gate.outcome(soc);
    gate.rig
        .until(Duration::from_secs(10), "the disconnect's answer", |rig| {
            rig.answered(disconnect)
        });
    let made = gate.rig.answer(disconnect).clone();
    assert_eq!(
        made["result"]["result_typed"],
        json!({ "boolean": true }),
        "{made}"
    );
    assert!(
        gate.feeds().contains("\"feedGranted\": false"),
        "{}",
        gate.feeds()
    );
    eprintln!(
        "[gate] the change waits, a manifest's disconnect: the SOC {reason}, {} signed, {posts} uploaded",
        gate.signed() - signed
    );
    // The guard reads the site's rule before its connection (the
    // reference's order), and the SOC came under the signing rule, which
    // went with the grant.
    assert_eq!(
        reason, "not_auto_approved",
        "the upload's guard refuses the signed SOC"
    );
    assert_eq!(
        (gate.signed() - signed, posts),
        (1, 0),
        "signed, not uploaded"
    );
    let (next, posts) = gate.next_soc();
    eprintln!("[gate] the site's next raw SOC after the disconnect: {next}");
    assert_eq!(
        (next.as_str(), posts),
        ("not_connected", 0),
        "the site's next raw SOC"
    );
    assert_eq!(gate.signed() - signed, 1);
    gate.rig.settled();
}

// ---------------------------------------------------------------------------
// `vault.lock` under the swarm thread's load.

/// Percentiles of `samples`, in ms: p50, p99 and the largest.
fn spread(samples: &[Duration]) -> (f64, f64, f64) {
    let mut v: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1e3).collect();
    v.sort_by(f64::total_cmp);
    let at = |p: f64| v[((v.len() as f64 * p).ceil() as usize).clamp(1, v.len()) - 1];
    (at(0.5), at(0.99), at(1.0))
}

/// What one `vault.lock` gate run measured.
struct VaultRun {
    samples: Vec<Duration>,
    window: Duration,
    /// Upload body bytes the core streamed to main during the window.
    moved: usize,
    /// Batches the lane ran during the window.
    batches: u64,
    uploads: usize,
}

/// Every upload body's bytes so far, streaming or done.
fn body_bytes(rig: &Rig) -> usize {
    rig.bodies.values().map(|b| b.len).sum::<usize>()
        + rig.done_bodies.values().map(|b| b.len).sum::<usize>()
}

/// `vault.lock` every 20 ms for `window` while two 50 MiB uploads stream
/// (the vectors' 100 files, from two sites; one that ends is followed by
/// another from its site, so two stream throughout) and the lane mines a
/// GSOC signer (`delay_ms` before each of `long-608`'s 120 batches, so the
/// search outlasts the window). A lock counts only when it went with both
/// bodies streaming and the search not yet ended; over the window the lane
/// must have run batches as its delay allows, read from the hook's own
/// state, and the bodies must have moved.
fn vault_under_load(window: Duration, delay_ms: u64) -> VaultRun {
    const B: &str = "https://b.example";
    let (request, parts, _) = fifty_mib_case();
    let delay = delay_ms.to_string();
    let main = swarm_world::main_with(
        &["swarm"],
        &[("FREEDOM_CORED_TEST_SWARM_MINE_DELAY_MS", &delay)],
    );
    let mut rig = Rig::new(main, uploads(None));
    rig.world(json!({ "reset": true, "clock": CLOCK, "grants": grants(&[SITE, B]) }));
    let mut upload = uploads(Some(parts));
    let mut subscribe = subscribe_node();
    rig.handler = Box::new(move |asked: &Asked| {
        if asked.method.starts_with("shell.swarm_subscribe")
            || asked.method == "shell.swarm_unsubscribe"
        {
            subscribe(asked)
        } else {
            upload(asked)
        }
    });
    let search = rig.request(
        SITE,
        r#"{"method":{"string":"swarm_subscribe"},"params":{"object":[["kind",{"string":"gsoc"}],["topic",{"string":"long-608"}]]}}"#,
    );
    let mut uploading = [
        (SITE, rig.request(SITE, &request)),
        (B, rig.request(B, &request)),
    ];
    let mut ids: Vec<u64> = uploading.iter().map(|(_, id)| *id).collect();
    rig.until(Duration::from_secs(30), "the bodies", |rig| {
        rig.bodies.len() == 2 && rig.bodies.values().all(|b| b.len > 0)
    });
    let searching = |rig: &Rig| {
        !rig.asked
            .iter()
            .any(|(a, _)| a.method == "approval.recheck" && a.parent() == Some(search))
    };
    let lane = |rig: &mut Rig| rig.world(json!({ "mining": true }))["mining"].clone();
    let before = lane(&mut rig);
    assert_eq!(before["off"], false, "{before}");
    assert!(searching(&rig), "the search runs");
    let moved_before = body_bytes(&rig);
    let start = Instant::now();
    let mut locks = Vec::new();
    let mut next = start;
    while start.elapsed() < window {
        // An upload that ended is followed by another from its site.
        for (site, id) in &mut uploading {
            if rig.answered(*id) {
                *id = rig.request(site, &request);
                ids.push(*id);
            }
        }
        if Instant::now() >= next {
            let streaming = rig.bodies.values().filter(|b| b.len > 0).count();
            let id = rig.own("vault.lock", &json!({}), "chrome");
            locks.push((id, Instant::now(), streaming == 2 && searching(&rig)));
            next += Duration::from_millis(20);
        }
        rig.step(Duration::from_millis(1));
    }
    let window = start.elapsed();
    let moved = body_bytes(&rig) - moved_before;
    let after = lane(&mut rig);
    assert!(searching(&rig), "the search outlasts the window");
    assert_eq!(after["off"], false, "{after}");
    let batches = after["batches"].as_u64().unwrap() - before["batches"].as_u64().unwrap();
    rig.until(Duration::from_secs(10), "the last locks", |rig| {
        locks.iter().all(|(id, _, _)| rig.answered(*id))
    });
    let samples: Vec<Duration> = locks
        .iter()
        .filter(|(_, _, counts)| *counts)
        .map(|(id, sent, _)| {
            let (answer, arrived) = &rig.answers[id];
            assert_eq!(answer["result"], json!({}), "{answer}");
            *arrived - *sent
        })
        .collect();
    rig.until(
        Duration::from_secs(120),
        "the uploads and the search",
        |rig| ids.iter().all(|id| rig.answered(*id)) && rig.answered(search) && rig.open.is_empty(),
    );
    for id in &ids {
        let answer = rig.answer(*id);
        assert!(answer["result"]["result_typed"].is_object(), "{answer}");
    }
    let answer = rig.answer(search);
    assert!(answer["result"]["result_typed"].is_object(), "{answer}");
    rig.settled();
    // The lane ran as its delay allows, at least half of it; the bodies
    // moved 8 MiB a second of the window at least.
    let allowed = window.as_millis() as u64 / delay_ms;
    assert!(
        batches * 2 >= allowed,
        "{batches} batches in {window:?}, of some {allowed}"
    );
    assert!(
        moved as f64 >= 8.0 * MIB as f64 * window.as_secs_f64(),
        "{moved} body bytes in {window:?}"
    );
    VaultRun {
        samples,
        window,
        moved,
        batches,
        uploads: ids.len(),
    }
}

fn report_vault(run: &VaultRun, what: &str) -> f64 {
    let (p50, p99, max) = spread(&run.samples);
    eprintln!(
        "[vault, {what}] vault.lock while two uploads streamed ({} uploads in all, {:.1} MiB of \
         bodies in the window) and the lane mined ({} batches in it), for {:?}: n {} p50 \
         {p50:.1} ms p99 {p99:.1} ms max {max:.1} ms",
        run.uploads,
        run.moved as f64 / MIB as f64,
        run.batches,
        run.window,
        run.samples.len(),
    );
    p99
}

/// `vault.lock` during two uploads and a mining job, for 2 s: answered,
/// its figures printed. A debug build on a shared runner: a loose bound,
/// 1,000 ms at p99, as `dweb_gates.rs`'s 0009 gate allows its debug run;
/// 0009's 50 ms is the `#[ignore]`d 10 s run's.
#[test]
fn vault_lock_is_answered_during_two_uploads_and_a_mining_job() {
    let run = vault_under_load(Duration::from_secs(2), 30);
    assert!(
        run.samples.len() >= 50,
        "{} locks counted",
        run.samples.len()
    );
    let p99 = report_vault(&run, "2 s");
    assert!(p99 < 1_000.0, "p99 {p99:.1} ms");
}

/// 0009's gate, 50 ms at p99, over 10 s (some 500 locks, so a scheduler
/// pause or two can't decide it): heavy, run by hand on a quiet machine.
/// Every swarm gate needs the test hooks, so this is a debug build's
/// figure too.
#[test]
#[ignore]
fn vault_lock_is_answered_within_0009s_gate_during_two_uploads_and_a_mining_job() {
    let run = vault_under_load(Duration::from_secs(10), 100);
    assert!(
        run.samples.len() >= 250,
        "{} locks counted",
        run.samples.len()
    );
    let p99 = report_vault(&run, "10 s");
    assert!(p99 <= 50.0, "0009's gate: p99 {p99:.1} ms");
}

// ---------------------------------------------------------------------------
// Malformed replies from main, and a stalled node.

/// The request a malformed reply's case drives the core to.
#[derive(Clone, Copy)]
enum Drive {
    /// `readChunk`: its readiness, then its chunk.
    ReadChunk,
    /// The latest feed entry: its readiness, then its streamed reply.
    Latest,
    /// `publishData` of a 300,000-byte part: readiness, the batch, the
    /// live facts, the upload, its part.
    Publish,
    /// A GSOC subscription by `chat` (one batch): readiness, the search,
    /// the live facts, the open; the live facts refused after the open, so
    /// the core closes it.
    Subscribe,
    /// `swarm.manifest`'s check: main's fetch.
    Manifest,
}

/// What main sends in place of its answer to the ask: a response's members
/// (beside `type` and `id`), or frames made for the ask's ID.
enum Bad {
    Members(Value),
    Frames(fn(u64) -> Vec<Vec<u8>>),
}

fn read_chunk_request() -> String {
    format!(
        r#"{{"method":{{"string":"swarm_readChunk"}},"params":{{"object":[["reference",{{"string":"{}"}}]]}}}}"#,
        "f9335c1f06d729ae3e725352a445fa01a1e9dc20e937f0ef19ab199b1fb2827b"
    )
}

/// An honest main for `drive`, which holds the first ask named `target`.
fn driving(drive: Drive, target: &'static str) -> Handler {
    let topic = [0x42; 32];
    let mut inner: Handler = match drive {
        Drive::ReadChunk | Drive::Latest => {
            let mut paths = BTreeMap::new();
            paths.insert(
                format!("/feeds/{}/{}", "11".repeat(20), hex(&topic)),
                Served::Stream(
                    head(
                        200,
                        &[
                            ("content-length", "5".to_owned()),
                            ("swarm-feed-index", format!("{:016x}", 0)),
                            ("swarm-feed-index-next", format!("{:016x}", 1)),
                        ],
                    ),
                    std::rc::Rc::new(b"hello".to_vec()),
                ),
            );
            reads_node(paths)
        }
        Drive::Publish => uploads(Some(vec![vec![7; 300_000]])),
        Drive::Subscribe => {
            let mut rechecks = 0;
            Box::new(move |asked: &Asked| match asked.method.as_str() {
                // The second recheck, after the open, refuses: the core
                // closes the subscription.
                "approval.recheck" => {
                    rechecks += 1;
                    Reply::Whole(json!({ "live": rechecks == 1, "agent": false }))
                }
                _ => subscribe_node()(asked),
            })
        }
        Drive::Manifest => manifest_node(),
    };
    let mut held = false;
    Box::new(move |asked: &Asked| {
        if !held && asked.name() == target {
            held = true;
            return Reply::Hold;
        }
        inner(asked)
    })
}

fn send_drive(rig: &mut Rig, drive: Drive) {
    match drive {
        Drive::ReadChunk => {
            rig.request(SITE, &read_chunk_request());
        }
        Drive::Latest => {
            rig.request(SITE, &read_feed(&[0x42; 32], &[0x11; 20], None));
        }
        Drive::Publish => {
            rig.request(
                SITE,
                r#"{"method":{"string":"swarm_publishData"},"params":{"object":[["data",{"bytes":300000,"kind":"Uint8Array","part":0}],["contentType",{"string":"application/octet-stream"}]]},"approval":"user"}"#,
            );
        }
        Drive::Subscribe => {
            rig.request(
                SITE,
                r#"{"method":{"string":"swarm_subscribe"},"params":{"object":[["kind",{"string":"gsoc"}],["topic",{"string":"chat"}]]}}"#,
            );
        }
        Drive::Manifest => {
            rig.own(
                "swarm.manifest",
                &json!({
                    "op": "check", "key": { "string": BZZ_SITE },
                    "url": { "string": format!("{BZZ_SITE}/index.html") },
                    "eager": { "boolean": true },
                }),
                "shell",
            );
        }
    }
}

/// A part's head, then `n` bytes of data in one frame.
fn part_frames(id: u64, head: usize, n: usize) -> Vec<Vec<u8>> {
    vec![
        common::frame(&json!({ "type": "response", "id": id, "result": { "bytes": head } })),
        stream_frame(KIND_DATA, id, &vec![7; n]),
    ]
}

/// Main breaks the protocol at each of the swarm thread's asks, one way
/// at a time, each on a fresh core: every one ends the connection (exit
/// 76, a protocol error's category on stderr), as 0001 and 0009 make a
/// malformed reply, D5.
#[test]
fn every_malformed_reply_from_main_ends_the_connection() {
    let whole_ok = |members: Value| {
        let mut reply = json!({ "status": 200, "status_text": "OK", "headers": [] });
        for (k, v) in members.as_object().unwrap() {
            reply[k] = v.clone();
        }
        reply
    };
    let cases: Vec<(&str, Drive, &str, Bad, &str)> = vec![
        (
            "a readiness of another type",
            Drive::ReadChunk,
            "shell.swarm_ready reachable",
            Bad::Members(json!({ "result": { "ok": "yes" } })),
            "swarm_reply",
        ),
        (
            "a refusal without its reason",
            Drive::ReadChunk,
            "shell.swarm_ready reachable",
            Bad::Members(json!({ "result": { "ok": false } })),
            "swarm_reply",
        ),
        (
            "a readiness with a reason",
            Drive::ReadChunk,
            "shell.swarm_ready reachable",
            Bad::Members(json!({ "result": { "ok": true, "reason": "x" } })),
            "swarm_reply",
        ),
        (
            "a readiness that is an array",
            Drive::ReadChunk,
            "shell.swarm_ready reachable",
            Bad::Members(json!({ "result": [true] })),
            "swarm_reply",
        ),
        (
            "a cancelled answer to an ask never cancelled",
            Drive::ReadChunk,
            "shell.swarm_ready reachable",
            Bad::Members(json!({ "error": { "code": "cancelled", "message": "Cancelled" } })),
            "swarm_reply",
        ),
        (
            "an error of another code",
            Drive::ReadChunk,
            "shell.swarm_ready reachable",
            Bad::Members(json!({ "error": { "code": "internal", "message": "no" } })),
            "swarm_reply",
        ),
        (
            "a whole reply without its body",
            Drive::ReadChunk,
            "shell.swarm_api chunk",
            Bad::Members(json!({ "result": whole_ok(json!({})) })),
            "swarm_reply",
        ),
        (
            "base64 that doesn't decode",
            Drive::ReadChunk,
            "shell.swarm_api chunk",
            Bad::Members(json!({ "result": whole_ok(json!({ "body_base64": "AQ" })) })),
            "swarm_reply",
        ),
        (
            "a status past 599",
            Drive::ReadChunk,
            "shell.swarm_api chunk",
            Bad::Members(
                json!({ "result": whole_ok(json!({ "status": 600, "body_base64": "" })) }),
            ),
            "swarm_reply",
        ),
        (
            "a reason phrase that isn't a string",
            Drive::ReadChunk,
            "shell.swarm_api chunk",
            Bad::Members(
                json!({ "result": whole_ok(json!({ "status_text": 200, "body_base64": "" })) }),
            ),
            "swarm_reply",
        ),
        (
            "a header of three members",
            Drive::ReadChunk,
            "shell.swarm_api chunk",
            Bad::Members(
                json!({ "result": whole_ok(json!({ "headers": [["a", "b", "c"]], "body_base64": "" })) }),
            ),
            "swarm_reply",
        ),
        (
            "an unknown member",
            Drive::ReadChunk,
            "shell.swarm_api chunk",
            Bad::Members(json!({ "result": whole_ok(json!({ "body_base64": "", "extra": 1 })) })),
            "swarm_reply",
        ),
        (
            "a failure outside the closed set",
            Drive::ReadChunk,
            "shell.swarm_api chunk",
            Bad::Members(json!({ "result": { "failed": "nonsense" } })),
            "swarm_reply",
        ),
        (
            "a refusal of no grammar rule",
            Drive::ReadChunk,
            "shell.swarm_api chunk",
            Bad::Members(
                json!({ "error": { "code": "invalid_argument", "message": "no", "data": { "rule": "nonsense" } } }),
            ),
            "swarm_reply",
        ),
        (
            "a chunk past its cap",
            Drive::ReadChunk,
            "shell.swarm_api chunk",
            Bad::Members(json!({ "result": whole_ok(json!({ "body_base64": b64(&[0; 4202]) })) })),
            "swarm_reply_bounds",
        ),
        (
            "a streamed call answered whole with success",
            Drive::Latest,
            "shell.swarm_api feed_latest",
            Bad::Members(json!({ "result": whole_ok(json!({ "body_base64": b64(b"hello") })) })),
            "swarm_reply_bounds",
        ),
        (
            "a streamed head with an unknown member",
            Drive::Latest,
            "shell.swarm_api feed_latest",
            Bad::Members(json!({ "result": whole_ok(json!({ "extra": true })) })),
            "swarm_reply",
        ),
        (
            "a node body's data after its end",
            Drive::Latest,
            "shell.swarm_api feed_latest",
            Bad::Frames(|id| {
                vec![
                    common::frame(&json!({ "type": "response", "id": id,
                    "result": { "status": 200, "status_text": "OK", "headers": [] } })),
                    stream_frame(KIND_END, id, b""),
                    stream_frame(KIND_DATA, id, b"more"),
                ]
            }),
            "stream_not_open|stream_unknown",
        ),
        (
            "a node body's abort that isn't JSON",
            Drive::Latest,
            "shell.swarm_api feed_latest",
            Bad::Frames(|id| {
                vec![
                    common::frame(&json!({ "type": "response", "id": id,
                    "result": { "status": 200, "status_text": "OK", "headers": [] } })),
                    stream_frame(KIND_ABORT, id, b"not json"),
                ]
            }),
            "abort_payload",
        ),
        (
            "a part's head of another type",
            Drive::Publish,
            "shell.swarm_part",
            Bad::Members(json!({ "result": { "bytes": "300000" } })),
            "swarm_reply",
        ),
        (
            "a part's head with an unknown member",
            Drive::Publish,
            "shell.swarm_part",
            Bad::Members(json!({ "result": { "bytes": 300_000, "extra": 1 } })),
            "swarm_reply",
        ),
        (
            "a part longer than its head",
            Drive::Publish,
            "shell.swarm_part",
            Bad::Frames(|id| {
                let mut frames = part_frames(id, 10, 11);
                frames.push(stream_frame(KIND_END, id, b""));
                frames
            }),
            "swarm_part_length",
        ),
        (
            "a part shorter than its head",
            Drive::Publish,
            "shell.swarm_part",
            Bad::Frames(|id| {
                let mut frames = part_frames(id, 300_000, 10);
                frames.push(stream_frame(KIND_END, id, b""));
                frames
            }),
            "swarm_part_length",
        ),
        (
            "a part's abort with a code no part has",
            Drive::Publish,
            "shell.swarm_part",
            Bad::Frames(|id| {
                let mut frames = part_frames(id, 300_000, 10);
                let abort = json!({ "code": "too_large", "message": "x" }).to_string();
                frames.push(stream_frame(KIND_ABORT, id, abort.as_bytes()));
                frames
            }),
            "abort_code",
        ),
        (
            "live facts of another type",
            Drive::Publish,
            "approval.recheck",
            Bad::Members(json!({ "result": { "live": "yes", "agent": false } })),
            "swarm_reply",
        ),
        (
            "live facts without custody",
            Drive::Publish,
            "approval.recheck",
            Bad::Members(json!({ "result": { "live": true } })),
            "swarm_reply",
        ),
        (
            "an open's id that isn't a string",
            Drive::Subscribe,
            "shell.swarm_subscribe",
            Bad::Members(json!({ "result": { "id": 5 } })),
            "swarm_reply",
        ),
        (
            "an open both opened and failed",
            Drive::Subscribe,
            "shell.swarm_subscribe",
            Bad::Members(json!({ "result": { "id": "x", "failed": { "message": "no" } } })),
            "swarm_reply",
        ),
        (
            "an open's failure without its text",
            Drive::Subscribe,
            "shell.swarm_subscribe",
            Bad::Members(json!({ "result": { "failed": { "reason": "x" } } })),
            "swarm_reply",
        ),
        (
            "a close's answer with a member",
            Drive::Subscribe,
            "shell.swarm_unsubscribe",
            Bad::Members(json!({ "result": { "closed": true } })),
            "swarm_reply",
        ),
        (
            "a fetch without its body",
            Drive::Manifest,
            "shell.swarm_manifest",
            Bad::Members(json!({ "result": { "status": 200 } })),
            "swarm_reply",
        ),
        (
            "a fetch past 8 KiB and a byte",
            Drive::Manifest,
            "shell.swarm_manifest",
            Bad::Members(
                json!({ "result": { "status": 200, "body_base64": b64(&[b' '; 8 * 1024 + 2]) } }),
            ),
            "swarm_reply",
        ),
        (
            "a fetch failed: false",
            Drive::Manifest,
            "shell.swarm_manifest",
            Bad::Members(json!({ "result": { "failed": false } })),
            "swarm_reply",
        ),
    ];
    let start = Instant::now();
    let mut report = Vec::new();
    for (what, drive, target, bad, want) in cases {
        let mut rig = rig_with(&[], &[SITE, BZZ_SITE]);
        rig.handler = driving(drive, target);
        send_drive(&mut rig, drive);
        rig.until(Duration::from_secs(30), what, |rig| {
            rig.open.values().any(|o| *o == Open::Held)
        });
        let id = *rig.open.iter().find(|(_, o)| **o == Open::Held).unwrap().0;
        match bad {
            Bad::Members(members) => {
                let mut message = json!({ "type": "response", "id": id });
                for (k, v) in members.as_object().unwrap() {
                    message[k] = v.clone();
                }
                rig.main.core.send(&message);
            }
            Bad::Frames(frames) => {
                for frame in frames(id) {
                    rig.main.core.send_raw(&frame);
                }
            }
        }
        // The core ends (its stdout read on the harness's thread meanwhile).
        let code = rig.main.core.exit_code(Duration::from_secs(10));
        assert_eq!(code, 76, "{what}");
        let stderr = rig.main.core.stderr();
        let category = stderr
            .split(r#""category":""#)
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or("")
            .to_owned();
        assert!(!category.is_empty(), "{what}: {stderr}");
        // `a|b`: either, as timing decides (data after a stream's end
        // finds its route closed, or already forgotten).
        assert!(
            want.split('|').any(|w| w == category),
            "{what}: {category}, not {want}"
        );
        report.push(format!("{what} ({target}): {category}"));
    }
    eprintln!(
        "[malformed] {} replies, each ending the connection, in {:?}:\n  {}",
        report.len(),
        start.elapsed(),
        report.join("\n  ")
    );
}

/// A stalled upload of a 600,000-byte part: its answer, and how long after
/// main's last frame for it the core answered.
fn stalled_upload(rig: &mut Rig) -> (Value, Duration, Vec<u64>) {
    rig.fresh();
    let id = rig.request(
        SITE,
        r#"{"method":{"string":"swarm_publishData"},"params":{"object":[["data",{"bytes":600000,"kind":"Uint8Array","part":0}],["contentType",{"string":"application/octet-stream"}]]},"approval":"user"}"#,
    );
    rig.until(Duration::from_secs(120), "the stalled upload", |rig| {
        rig.answered(id) && rig.open.is_empty() && rig.out.is_empty() && rig.bodies.is_empty()
    });
    let idle = rig.answers[&id].1 - rig.progress.unwrap();
    let cancels = rig.cancels.clone();
    (rig.answer(id).clone(), idle, cancels)
}

/// What an upload's call and part were, by their forms.
fn asks_of(rig: &Rig, name: &str) -> Vec<u64> {
    rig.asked
        .iter()
        .filter(|(a, _)| a.name() == name)
        .map(|(a, _)| a.id)
        .collect()
}

/// A stalled node, at the idle bound (1 s here, D13's 60 s shortened by
/// its hook): an upload whose picked file stops mid-way, and one whose node
/// stops taking its body, each end at the bound, the part and the call
/// cancelled and the page answered with an error; and main's
/// `swarm.publish` whose `/stamps` reply never comes ends at the whole
/// reply's bound (300 s, here 1 s). Nothing is held after.
#[test]
fn a_stalled_node_ends_an_upload_at_the_idle_bound() {
    let mut rig = rig_with(
        &[
            ("FREEDOM_CORED_TEST_SWARM_IDLE_MS", "1000"),
            ("FREEDOM_CORED_TEST_SWARM_WHOLE_MS", "1000"),
        ],
        &[SITE],
    );
    let part = vec![7u8; 600_000];
    rig.handler = uploads(Some(vec![part.clone()]));
    // The picked file stops after 200,000 bytes.
    rig.stall_parts_at = Some(200_000);
    let (answer, idle, cancels) = stalled_upload(&mut rig);
    let report = format!("the part stalled: answered {idle:?} after main's last frame");
    assert!(answer["result"]["error_typed"].is_object(), "{answer}");
    assert!(
        cancels.contains(&asks_of(&rig, "shell.swarm_part")[0]),
        "the part cancelled"
    );
    assert!(
        cancels.contains(&asks_of(&rig, "shell.swarm_api bzz_file")[0]),
        "the call cancelled"
    );
    assert!(
        idle >= Duration::from_millis(990) && idle < Duration::from_secs(4),
        "{report}"
    );
    rig.settled();

    // The node stops taking the body: main credits none of it.
    rig.stall_parts_at = None;
    rig.credit_bodies = false;
    let (answer, idle2, cancels) = stalled_upload(&mut rig);
    rig.credit_bodies = true;
    assert!(answer["result"]["error_typed"].is_object(), "{answer}");
    assert!(
        cancels.contains(&asks_of(&rig, "shell.swarm_api bzz_file")[0]),
        "the call cancelled"
    );
    let body = rig.done_bodies.values().next().unwrap();
    assert!(
        body.len as u64 <= WINDOW,
        "the body held to its window: {}",
        body.len
    );
    assert_eq!(body.terminal.as_deref(), Some("cancelled"));
    assert!(
        idle2 >= Duration::from_millis(990) && idle2 < Duration::from_secs(4),
        "{idle2:?}"
    );
    rig.settled();

    // main's swarm.publish: its `/stamps` call never answered.
    rig.fresh();
    let mut inner = uploads(Some(vec![part]));
    rig.handler = Box::new(move |asked: &Asked| {
        if asked.form() == "stamps" {
            Reply::Hold
        } else {
            inner(asked)
        }
    });
    let start = Instant::now();
    let id = rig.own(
        "swarm.publish",
        &json!({
            "kind": "file", "parts": [{ "bytes": 600_000, "part": 0 }], "name": "notes.txt",
            "pin": true, "deferred": true, "history": { "type": "file", "name": "notes.txt" },
        }),
        "shell",
    );
    rig.until(Duration::from_secs(30), "the publish", |rig| {
        rig.answered(id) && rig.open.is_empty() && rig.out.is_empty() && rig.bodies.is_empty()
    });
    let whole = rig.answers[&id].1 - start;
    let answer = rig.answer(id).clone();
    assert!(answer["result"]["error_typed"].is_object(), "{answer}");
    assert!(
        cancels_of(&rig, "shell.swarm_api stamps"),
        "the call cancelled at its bound"
    );
    assert!(
        whole >= Duration::from_millis(990) && whole < Duration::from_secs(4),
        "{whole:?}"
    );
    rig.settled();
    eprintln!(
        "[stalled] at the 1 s idle bound: {report}; the body uncredited: answered {idle2:?} after; \
         swarm.publish's unanswered /stamps: answered {whole:?} after it was sent"
    );
}

fn cancels_of(rig: &Rig, name: &str) -> bool {
    asks_of(rig, name).iter().any(|id| rig.cancels.contains(id))
}

/// D13's real bound, no hook: a picked file that stops mid-way ends its
/// upload 60 s after main's last frame (a minute: run by hand).
#[test]
#[ignore]
fn a_stalled_node_ends_an_upload_after_60_s_idle() {
    let mut rig = rig_with(&[], &[SITE]);
    rig.handler = uploads(Some(vec![vec![7u8; 600_000]]));
    rig.stall_parts_at = Some(200_000);
    let (answer, idle, _) = stalled_upload(&mut rig);
    eprintln!("[stalled] at the shipped bound: answered {idle:?} after main's last frame");
    assert!(answer["result"]["error_typed"].is_object(), "{answer}");
    assert!(
        idle >= Duration::from_secs(60) && idle < Duration::from_secs(63),
        "{idle:?}"
    );
    rig.settled();
}

// ---------------------------------------------------------------------------
// Coverage: every case played or named.

/// Cases no pipe test plays, each with why and where the core's own answer
/// is pinned instead.
const NAMED: &[(&str, &str)] = &[
    ("not-connected-unsubscribe-without-page", UNSUBSCRIBE),
    ("unsubscribe-params-null", UNSUBSCRIBE),
    ("unsubscribe-id-missing", UNSUBSCRIBE),
    ("unsubscribe-id-empty", UNSUBSCRIBE),
    ("unsubscribe-id-number", UNSUBSCRIBE),
    ("unsubscribe-unknown", UNSUBSCRIBE),
    ("unsubscribe-without-page-connected", UNSUBSCRIBE),
];

const UNSUBSCRIBE: &str = "swarm_unsubscribe is main's own (D5): main closes the subscription it \
    opened, and the core answers the method invalid_argument (tests/swarm.rs, \
    the_door_answers_before_any_machine_runs)";

/// The string literals of the constant `name` in `source`, each with its
/// bracket depth and whether it is the first in its tuple.
fn literals(source: &str, name: &str) -> Vec<(String, usize, bool)> {
    let at = source
        .find(&format!("const {name}:"))
        .unwrap_or_else(|| panic!("no const {name}"));
    let rest = &source[at..];
    let rest = &rest[rest.find('=').unwrap() + 1..];
    let mut out = Vec::new();
    let (mut depth, mut first) = (0usize, true);
    let mut chars = rest.chars();
    let mut started = false;
    while let Some(c) = chars.next() {
        match c {
            '[' | '(' => {
                depth += 1;
                started = true;
                first = true;
            }
            ']' | ')' => {
                depth -= 1;
                if started && depth == 0 {
                    break;
                }
            }
            '"' => {
                let mut text = String::new();
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' => {
                            let _ = chars.next();
                        }
                        c => text.push(c),
                    }
                }
                out.push((text, depth, first));
                first = false;
            }
            _ => {}
        }
    }
    out
}

/// A `[&str; N]` constant's strings.
fn strings(source: &str, name: &str) -> Vec<String> {
    literals(source, name)
        .into_iter()
        .map(|(s, _, _)| s)
        .collect()
}

/// A `&[(&str, &str)]` constant's first strings (the cases' ids).
fn left_out(source: &str, name: &str) -> Vec<String> {
    literals(source, name)
        .into_iter()
        .filter(|(_, depth, first)| *depth == 2 && *first)
        .map(|(s, _, _)| s)
        .collect()
}

/// The `(name, count)` pairs a test asserts after `marker`.
fn asserted_counts(source: &str, marker: &str) -> BTreeMap<String, usize> {
    let at = source.find(marker).unwrap_or_else(|| panic!("no {marker}"));
    let rest = &source[at..];
    let rest = &rest[rest.find("assert_eq!(").unwrap()..];
    let rest = &rest[..rest.find(");").unwrap()];
    let mut counts = BTreeMap::new();
    for pair in rest.split('(').skip(2) {
        let mut it = pair.split(',');
        let (Some(name), Some(n)) = (it.next(), it.next()) else {
            continue;
        };
        let name = name.trim().trim_matches('"');
        let n: usize = n
            .trim_end_matches(|c: char| c == ')' || c == ']' || c.is_whitespace())
            .trim()
            .parse()
            .unwrap();
        counts.insert(name.to_owned(), n);
    }
    counts
}

/// Every `methods`, `stores` and `shell` case of `vectors/swarm.json` is
/// one a pipe test plays, by that test's own selection (its constants read
/// from its source, so the two can't drift), or is named, by a pipe test's
/// left-out list or [`NAMED`] here, with why. A case nothing plays or names
/// fails, and so does a name for a case that isn't there.
#[test]
fn every_case_is_played_through_the_pipe_or_named() {
    let swarm = include_str!("swarm.rs");
    let writes = include_str!("swarm_writes.rs");
    let shell = include_str!("swarm_shell.rs");
    let played = strings(swarm, "PLAYED");
    let groups = [strings(writes, "PUBLISH"), strings(writes, "FEEDS")];
    let mut named: BTreeMap<String, &str> = BTreeMap::new();
    for id in left_out(swarm, "LEFT_OUT") {
        named.insert(id, "tests/swarm.rs");
    }
    for id in left_out(writes, "LEFT_OUT") {
        named.insert(id, "tests/swarm_writes.rs");
    }
    for (id, why) in NAMED {
        assert!(!why.is_empty());
        named.insert((*id).to_owned(), "tests/swarm_gates.rs");
    }
    assert!(
        !played.is_empty() && groups.iter().all(|g| !g.is_empty()),
        "{played:?} {groups:?}"
    );

    let text = logic::text_of("swarm.json");
    let index = fc_json::index::Index::new(&text).unwrap();
    let mut seen = BTreeSet::new();
    let mut unplayed = Vec::new();
    let mut by: BTreeMap<&str, usize> = BTreeMap::new();
    for case in logic::get(index.root(), "methods").children() {
        let id = logic::string(logic::get(case, "id"));
        seen.insert(id.clone());
        if let Some(test) = named.get(&id) {
            *by.entry(test).or_default() += 0;
            continue;
        }
        let steps: Vec<_> = logic::get(case, "steps").children().collect();
        let methods: Vec<Option<String>> = steps
            .iter()
            .map(|s| s.get("method").map(logic::string))
            .collect();
        let in_played = |m: &Option<String>| m.as_ref().is_some_and(|m| played.contains(m));
        // tests/swarm.rs: a case with one of its methods (main's own
        // unsubscribe and an upload status's uploads beside it), or the
        // method dispatch's own cases.
        let dispatch = id.starts_with("method-")
            && steps.iter().all(|s| {
                s.get("page")
                    .is_some_and(|p| p.kind() == fc_json::index::Kind::False)
            })
            && !methods.iter().any(in_played);
        let status = methods
            .iter()
            .any(|m| m.as_deref() == Some("swarm_getUploadStatus"));
        let others = methods.iter().any(|m| {
            m.as_ref().is_some_and(|m| {
                !played.contains(m)
                    && m != "swarm_unsubscribe"
                    && !(status && m == "swarm_publishFiles")
            })
        });
        let by_swarm = (methods.iter().any(in_played) && !others) || dispatch;
        // tests/swarm_writes.rs: every method of the case in one group.
        let by_writes = groups.iter().any(|group| {
            methods
                .iter()
                .all(|m| m.as_ref().is_some_and(|m| group.contains(m)))
        });
        if by_swarm {
            *by.entry("tests/swarm.rs").or_default() += 1;
        }
        if by_writes {
            *by.entry("tests/swarm_writes.rs").or_default() += 1;
        }
        if !by_swarm && !by_writes {
            unplayed.push(format!("{id} {methods:?}"));
        }
    }
    assert!(
        unplayed.is_empty(),
        "methods cases no pipe test plays or names:\n  {}",
        unplayed.join("\n  ")
    );
    let stale: Vec<&String> = named.keys().filter(|id| !seen.contains(*id)).collect();
    assert!(
        stale.is_empty(),
        "named cases that aren't in the vectors: {stale:?}"
    );

    // tests/swarm_shell.rs plays the whole `stores` and `shell` sections
    // and counts them by kind and method: the counts it asserts are the
    // sections'.
    let count = |section: &str, key: &str| {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for case in logic::get(index.root(), section).children() {
            *counts
                .entry(logic::string(logic::get(case, key)))
                .or_default() += 1;
        }
        counts
    };
    let stores = count("stores", "kind");
    let shells = count("shell", "method");
    assert_eq!(
        stores,
        asserted_counts(shell, "fn every_stores_case_through_the_pipe")
    );
    assert_eq!(
        shells,
        asserted_counts(shell, "fn every_shell_case_through_the_pipe")
    );
    eprintln!(
        "[coverage] {} methods cases: {} by tests/swarm.rs, {} by tests/swarm_writes.rs, {} named \
         ({} here); stores {stores:?} and shell {shells:?} by tests/swarm_shell.rs",
        seen.len(),
        by.get("tests/swarm.rs").copied().unwrap_or(0),
        by.get("tests/swarm_writes.rs").copied().unwrap_or(0),
        named.len(),
        NAMED.len(),
    );
}
