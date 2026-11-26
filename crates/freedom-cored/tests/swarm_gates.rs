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
//! - **`vault.lock`** answered within 0009's gate while two uploads and a
//!   mining job run.
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
//! **Heavy, `#[ignore]`d:** the 50 MiB publish in a release build (the hooks
//! drop out of optimized builds, so it runs with the shipped bounds), and a
//! stalled upload at the real 60 s idle bound:
//!
//! ```sh
//! cargo test -p freedom-cored --all-features --test swarm_gates -- --ignored --nocapture --test-threads 1
//! ```

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

const KIB: u64 = 1 << 10;
const MIB: usize = 1 << 20;
/// The test clock's `Date.now()`.
const CLOCK: u64 = 1_767_225_600_123;
const SITE: &str = "https://app.example";
/// The swarm thread's memory (design 0015, Budgets).
const POOL: usize = 64 * MIB;

/// One usable batch, as the node lists it.
const STAMPS: &str = r#"{"stamps":[{"batchID":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","utilization":0,"usable":true,"label":"freedom","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000}]}"#;

/// The node's reference for an upload it took.
const REFERENCE: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";

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
    /// `{ error }` at once.
    Refuse(Value),
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
    /// The core reacted to the cancel (a cancel of its own, or the
    /// request's answer): every ask after this is one it made after it.
    reacted: bool,
    /// The core's asks after its reaction (`shell.swarm_unsubscribe`
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
                "not within {within:?}: {what}; open {:?}, out {:?}",
                self.open,
                self.out.keys().collect::<Vec<_>>()
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
        sweep.cancelled = Some(name);
        sweep.signed_at_cancel = self.marker.as_ref().map_or(0, |m| lines(m));
        let request = sweep.request;
        self.cancel(request);
        true
    }

    /// One item from the core, if one comes within `within`; main's streams
    /// pumped first. Whether something came.
    fn step(&mut self, within: Duration) -> bool {
        self.pump();
        self.sample();
        let Some(wire) = self.main.core.recv_wire_within(within) else {
            self.idle();
            return false;
        };
        let at = self.main.core.arrived();
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
            other => panic!("an unexpected frame: {other:?}"),
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
                if let Some(sweep) = self.sweep.as_mut()
                    && sweep.request == id
                    && sweep.cancelled.is_some()
                {
                    sweep.reacted = true;
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
                if let Some(sweep) = self.sweep.as_mut()
                    && sweep.cancelled.is_some()
                {
                    sweep.reacted = true;
                }
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
        if let Some(sweep) = self.sweep.as_mut()
            && sweep.reacted
            && asked.method != "shell.swarm_unsubscribe"
        {
            sweep.after.push(asked.name());
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
            Reply::Refuse(error) => self.main.refuse(id, error),
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
                        stall_at: None,
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
            self.stage(format!("the vault's {kind} answer parked"));
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

/// `publishFiles` of `n` files of `size` bytes, each a part.
fn files_request(n: usize, size: usize) -> String {
    let files: Vec<String> = (0..n)
        .map(|k| {
            format!(
                r#"{{"object":[["path",{{"string":"files/{k:03}.bin"}}],["bytes",{{"bytes":{size},"kind":"Uint8Array","part":{k}}}]]}}"#
            )
        })
        .collect();
    format!(
        r#"{{"method":{{"string":"swarm_publishFiles"}},"params":{{"object":[["files",{{"array":[{}]}}]]}},"approval":"user"}}"#,
        files.join(",")
    )
}

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

/// Main for an upload: ready, live, one usable batch, each part from
/// `parts` (by the request it is for and its number), and an upload's
/// body answered with the SHA-256 of what came as its reference.
fn uploads(parts: BTreeMap<(u64, u32), Vec<u8>>, fallback: Option<Vec<Vec<u8>>>) -> Handler {
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
                .get(&(parent, k))
                .cloned()
                .or_else(|| fallback.as_ref().map(|all| all[k as usize].clone()))
                .unwrap_or_else(|| panic!("no part {k} for {parent}"));
            Reply::Part(bytes)
        }
        "shell.prefetch" => Reply::Ignore,
        other => panic!("the thread asked {other}: {:?}", asked.params),
    })
}

/// Publishes `request` (its parts `parts`) from `SITE` with the core's
/// peak memory started again just before: the answer, the tar's SHA-256
/// and length, how long it took, and what it grew by.
fn publish_measured(
    rig: &mut Rig,
    request: &str,
    parts: Vec<Vec<u8>>,
) -> (
    Value,
    String,
    usize,
    Duration,
    Option<(u64, u64, &'static str)>,
) {
    rig.handler = uploads(BTreeMap::new(), Some(parts));
    let base = baseline(rig);
    let start = Instant::now();
    let id = rig.request(SITE, request);
    rig.until(Duration::from_secs(600), "the publish", |rig| {
        rig.answered(id) && rig.open.is_empty() && rig.bodies.is_empty()
    });
    let took = start.elapsed();
    let grew = grown(rig, &base);
    let (call, body) = rig.done_bodies.pop_last().unwrap();
    assert!(rig.open.is_empty() && call > 0);
    assert_eq!(body.terminal.as_deref(), Some("end"));
    let answer = rig.answer(id).clone();
    let sha = hex(&body.sha.clone().finalize());
    (answer, sha, body.len, took, grew)
}

/// A core with `env`'s hooks, the Swarm grants and stores moved, `SITE`
/// connected, the clock set.
fn rig_with(env: &[(&str, &str)], sites: &[&str]) -> Rig {
    let main = swarm_world::main_with(&["swarm"], env);
    let mut rig = Rig::new(main, uploads(BTreeMap::new(), None));
    rig.world(json!({ "reset": true, "clock": CLOCK, "grants": grants(sites) }));
    rig
}

/// The publish gate, the vectors' 50 MiB of 100 files, its tar byte for
/// byte the reference's: on a core that has published nothing yet (the
/// upload path's one-time allocations count), then again on the same core
/// (what streaming alone holds). Each grows resident memory by less than
/// 4 MiB.
#[test]
fn a_50_mib_publish_of_100_files_streams_with_resident_memory_up_under_4_mib() {
    let (request, parts, reference) = fifty_mib_case();
    let total: usize = parts.iter().map(Vec::len).sum();
    let mut rig = rig_with(&[], &[SITE]);
    for what in ["first publish", "second publish"] {
        let (answer, sha, len, took, grew) = publish_measured(&mut rig, &request, parts.clone());
        let result = answer["result"]["result_typed"].to_string();
        assert!(result.contains(&reference), "{answer}");
        assert_eq!(sha, reference, "the tar the node took is the reference's");
        assert!(len > total, "the tar holds every file: {len} of {total}");
        rig.settled();
        eprintln!(
            "[publish, 50 MiB, {what}] 100 files, a {len}-byte tar streamed in {took:?} \
             ({:.1} MiB/s)",
            total as f64 / MIB as f64 / took.as_secs_f64(),
        );
        match grew {
            Some((base, up, how)) => {
                eprintln!(
                    "[publish, 50 MiB, {what}] resident memory: {base} KiB before, peak +{up} KiB ({how})"
                );
                assert!(
                    up < 4 * 1024,
                    "[{what}] resident memory up {up} KiB, not under 4 MiB"
                );
            }
            None => eprintln!("[publish, 50 MiB, {what}] resident memory: not measured here"),
        }
    }
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
    let mut inner = uploads(BTreeMap::new(), None);
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
const SITE_B: &str = "https://other.example";

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
    /// Per run: what the last run saw goes.
    fn fresh(&mut self) {
        self.asked.clear();
        self.cancels.clear();
        self.done_bodies.clear();
        self.answers.clear();
        self.mining = None;
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
        self.world(scenario.world.clone());
        self.handler = (scenario.handler)();
        let id = (scenario.send)(self);
        self.sweep = Some(Sweep {
            request: id,
            at,
            seen: Vec::new(),
            cancelled: None,
            signed_at_cancel: 0,
            reacted: false,
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
/// nothing asked after the core's reaction to the cancel but a close of
/// the subscription it opened; no signature after the cancel; and nothing
/// held after: no charge, no request, no stream.
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
            handler: || {
                uploads(
                    BTreeMap::new(),
                    Some(vec![PART.with(|p| p.borrow().clone())]),
                )
            },
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
            handler: || {
                uploads(
                    BTreeMap::new(),
                    Some(vec![PART.with(|p| p.borrow().clone())]),
                )
            },
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

    /// One of main's (or the chrome's) store ops, sent: its ID, answered
    /// or not.
    fn op(&mut self, method: &str, params: Value, caller: &str) -> u64 {
        let id = self.rig.own(method, &params, caller);
        self.rig
            .until(Duration::from_millis(300), "", |rig| rig.answered(id));
        id
    }

    /// Sends an op and gives it 300 ms: its ID, and whether it was answered.
    fn op_waits(&mut self, method: &str, params: Value, caller: &str) -> (u64, bool) {
        let id = self.rig.own(method, &params, caller);
        let until = Instant::now() + Duration::from_millis(300);
        while Instant::now() < until && !self.rig.answered(id) {
            self.rig.step(Duration::from_millis(20));
        }
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
