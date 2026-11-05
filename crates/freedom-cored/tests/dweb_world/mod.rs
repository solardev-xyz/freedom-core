//! The test as main for design 0009's `dweb.verify`: the real binary at
//! protocol 2, and the honest Ant and gateway of `dweb-verify.json` it
//! reaches through `shell.dweb_get`. Shared by `dweb` (the requests one by
//! one) and `dweb_gates` (the bounds and the load).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::common::{
    Core, KIND_ABORT, KIND_DATA, KIND_END, KIND_STREAM_CREDIT, Wire, dirs, request, shell_request,
    spawn_env, stream_frame,
};

pub const WINDOW: usize = 128 << 10;
pub const MAX_DATA: usize = 64 << 10;
pub const SITE_A: &str = "3c8b9184787f719e7184f51b5c595a950d8cec49c765dc0e5a8f1c253e54591c";
pub const SITE_V1: &str = "bafybeiguwjmddvr4iiah6ekgvrovb5zfb6eg5c6loikxvxlxzlwea5dabm";
/// file-524288-rs0's single-file manifest: `/file.bin`, 512 KiB.
pub const FILE_512K: &str = "eee70ccdb4cff5547504369812f82dcb20d77ab263fe38ae77f4ca29b4e00e66";
/// file-67108865-rs1's single-file manifest: `/file.bin`, 64 MiB and a
/// byte, erasure-coded at level 1.
pub const FILE_64M: &str = "bf3387903a09a221a2ffdfaf8a9c65d8e6d47530b06725c5a80e18886a1246e9";
/// file-10485760-v1-balanced: 10 MiB in 40 raw leaves under one node.
pub const IPFS_10M: &str = "bafybeicts2tssv6avpna26sql26mlrowdhxwjpskl35ibnxdf7tf7cgo5a";
pub const INDEX_HTML: &[u8] = b"<!doctype html><title>site</title><p>index</p>\n";

pub fn b64(bytes: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn vectors(name: &str) -> Value {
    let path = format!("{}/../../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

pub fn unb64(v: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str().unwrap())
        .unwrap()
}

/// The vectors' content: SHA-256(seed ‖ u64_be(i)), concatenated, cut.
pub fn content(seed: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut i = 0u64;
    while out.len() < n {
        let mut h = Sha256::new();
        h.update(seed.as_bytes());
        h.update(i.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        i += 1;
    }
    out.truncate(n);
    out
}

/// How main answers a piece.
#[derive(Clone)]
pub enum Answer {
    Whole(u16, Vec<(String, String)>, Vec<u8>),
    /// A stream: its head, its body, and, with `cut`, an abort with that
    /// code after that many bytes instead of its end.
    Stream {
        status: u16,
        headers: Vec<(String, String)>,
        body: Cow<'static, [u8]>,
        cut: Option<(usize, &'static str)>,
    },
    /// Never answered until the core cancels it.
    Hold,
    /// A stream's head, then nothing until the core cancels it.
    Open,
}

/// The honest nodes of dweb-verify.json: Ant's chunks and files, the
/// gateway's blocks. Read once, for every test.
pub struct Honest {
    pub chunks: HashMap<String, Vec<u8>>,
    pub files: HashMap<String, Vec<u8>>,
    pub blocks: HashMap<String, Vec<u8>>,
}

pub fn honest() -> &'static Honest {
    static HONEST: std::sync::OnceLock<Honest> = std::sync::OnceLock::new();
    HONEST.get_or_init(Honest::read)
}

/// The honest nodes, and the answers a test changes, by path prefix.
/// Its gateway serves raw blocks only.
pub struct World {
    pub honest: &'static Honest,
    pub changes: Vec<(String, Answer)>,
    /// Streams whose path starts so are cut after that many bytes, with
    /// that abort code.
    pub cuts: Vec<(String, usize, &'static str)>,
}

impl Honest {
    fn read() -> Self {
        let d = vectors("dweb-verify.json");
        let mut chunks = HashMap::new();
        for (a, w) in d["swarm"]["chunks"].as_object().unwrap() {
            chunks.insert(a.clone(), unb64(w));
        }
        let mut files = HashMap::new();
        for f in d["swarm"]["files"].as_array().unwrap() {
            // Ant's lone-leaf trees join to other bytes than the content:
            // the world doesn't serve them.
            if f["joined_equals_content"] == false {
                continue;
            }
            let size = f["size"].as_u64().unwrap() as usize;
            let seed = f["seed"].as_str().unwrap();
            files.insert(f["root"].as_str().unwrap().to_owned(), content(seed, size));
        }
        for m in d["swarm"]["manifests"].as_array().unwrap() {
            for e in m["entries"].as_array().unwrap() {
                if let (Some(r), Some(seed)) = (e["data_ref"].as_str(), e["seed"].as_str()) {
                    let size = e["size"].as_u64().unwrap() as usize;
                    files.insert(r.to_owned(), content(seed, size));
                }
            }
        }
        let mut blocks = HashMap::new();
        for (c, b) in d["ipfs"]["blocks"].as_object().unwrap() {
            blocks.insert(c.clone(), unb64(b));
        }
        let mut leaves = |bytes: &[u8], list: &Value| {
            for l in list.as_array().unwrap() {
                let from = l["from"].as_u64().unwrap() as usize;
                let len = l["length"].as_u64().unwrap() as usize;
                blocks
                    .entry(l["cid"].as_str().unwrap().to_owned())
                    .or_insert_with(|| bytes[from..from + len].to_vec());
            }
        };
        for dir in d["ipfs"]["directories"].as_array().unwrap() {
            for e in dir["entries"].as_array().unwrap() {
                let size = e["size"].as_u64().unwrap() as usize;
                let bytes = match (e["text"].as_str(), e["seed"].as_str()) {
                    (Some(t), _) => t.as_bytes().to_vec(),
                    (None, Some(seed)) => content(seed, size),
                    _ => continue,
                };
                leaves(&bytes, &e["leaves"]);
            }
        }
        // The raw-leaved files, whose leaves are slices of their content.
        for f in d["ipfs"]["files"].as_array().unwrap() {
            let raw = f["leaves"].as_array().is_some_and(|l| {
                l.iter()
                    .all(|l| l["cid"].as_str().unwrap().starts_with("bafkrei"))
            });
            if let (true, Some(seed)) = (raw, f["seed"].as_str()) {
                let size = f["size"].as_u64().unwrap() as usize;
                leaves(&content(seed, size), &f["leaves"]);
            }
        }
        Self {
            chunks,
            files,
            blocks,
        }
    }
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

impl World {
    pub fn new() -> Self {
        Self {
            honest: honest(),
            changes: Vec::new(),
            cuts: Vec::new(),
        }
    }

    pub fn cut(mut self, prefix: &str, after: usize, code: &'static str) -> Self {
        self.cuts.push((prefix.to_owned(), after, code));
        self
    }

    pub fn change(mut self, prefix: &str, answer: Answer) -> Self {
        self.changes.push((prefix.to_owned(), answer));
        self
    }

    pub fn stream(
        status: u16,
        headers: Vec<(String, String)>,
        body: impl Into<Cow<'static, [u8]>>,
    ) -> Answer {
        Answer::Stream {
            status,
            headers,
            body: body.into(),
            cut: None,
        }
    }

    pub fn answer(&self, path: &str, headers: &[(String, String)]) -> Answer {
        let mut answer = self.honest(path, headers);
        if let Answer::Stream { cut, .. } = &mut answer
            && let Some((_, after, code)) = self.cuts.iter().find(|(p, ..)| path.starts_with(p))
        {
            *cut = Some((*after, *code));
        }
        answer
    }

    fn honest(&self, path: &str, headers: &[(String, String)]) -> Answer {
        if let Some((_, a)) = self.changes.iter().find(|(p, _)| path.starts_with(p)) {
            return a.clone();
        }
        // The gateway serves no CARs: a CAR request gets a 200 that
        // isn't one, as a gateway that ignores `format=car` answers.
        if path.contains("format=car") {
            let html = ("content-type".to_owned(), "text/html".to_owned());
            return Self::stream(200, vec![html], &b"<p>not a CAR</p>"[..]);
        }
        let not_found = || Answer::Whole(404, vec![], b"{}".to_vec());
        if let Some(a) = path.strip_prefix("/chunks/") {
            return match self.honest.chunks.get(a) {
                Some(w) => Answer::Whole(200, vec![], w.clone()),
                None => not_found(),
            };
        }
        if let Some(r) = path.strip_prefix("/bytes/") {
            let Some(file) = self.honest.files.get(r) else {
                return Self::stream(404, vec![], &b""[..]);
            };
            let range = headers.iter().find(|(n, _)| n == "range").unwrap();
            let (a, b) = range
                .1
                .strip_prefix("bytes=")
                .unwrap()
                .split_once('-')
                .unwrap();
            let (a, b): (usize, usize) = (a.parse().unwrap(), b.parse().unwrap());
            let b = b.min(file.len() - 1);
            let cr = format!("bytes {a}-{b}/{}", file.len());
            return Self::stream(206, vec![("content-range".into(), cr)], &file[a..=b]);
        }
        let cid = path
            .strip_prefix("/ipfs/")
            .unwrap()
            .split('?')
            .next()
            .unwrap();
        match self.honest.blocks.get(cid) {
            Some(b) => Self::stream(
                200,
                vec![("content-type".into(), "application/vnd.ipld.raw".into())],
                &b[..],
            ),
            None => Self::stream(404, vec![], &b""[..]),
        }
    }
}

/// A piece main is streaming: what is left of it, and the core's credit.
pub struct Flow {
    pub body: Cow<'static, [u8]>,
    pub at: usize,
    pub room: usize,
    pub cut: Option<(usize, &'static str)>,
    /// [`Answer::Open`]: it never ends.
    pub open: bool,
}

/// What one of main's requests got.
#[derive(Debug)]
pub struct Got {
    pub result: Option<Value>,
    /// The body, while main keeps bodies ([`Main::keep_bodies`]).
    pub body: Vec<u8>,
    /// The body's bytes, kept or not.
    pub len: usize,
    pub ended: bool,
    pub abort: Option<Value>,
    /// When main sent the request.
    pub sent: Instant,
    /// When its response came off the pipe.
    pub answered: Option<Instant>,
    /// When its body ended or aborted.
    pub finished: Option<Instant>,
}

impl Got {
    fn new() -> Self {
        Self {
            result: None,
            body: Vec::new(),
            len: 0,
            ended: false,
            abort: None,
            sent: Instant::now(),
            answered: None,
            finished: None,
        }
    }

    pub fn done(&self) -> bool {
        match &self.result {
            None => false,
            Some(m) if m.get("error").is_some() => true,
            Some(m) if m["result"]["body"] == true => self.ended || self.abort.is_some(),
            Some(_) => true,
        }
    }

    /// The protocol error's code, if it got one.
    pub fn error_code(&self) -> Option<&str> {
        self.result.as_ref()?["error"]["code"].as_str()
    }

    /// From sending it to its response.
    pub fn to_answer(&self) -> Option<Duration> {
        Some(self.answered? - self.sent)
    }
}

/// The test as main: the core at protocol 2 and the world it reaches.
pub struct Main {
    pub _dir: tempfile::TempDir,
    pub core: Core,
    pub world: World,
    pub next_id: u64,
    pub flows: BTreeMap<u64, Flow>,
    /// Every `shell.dweb_get` the core sent: its ID and params.
    pub asked: Vec<(u64, Value)>,
    pub held: Vec<u64>,
    /// The core's cancels of its pieces.
    pub cancels: Vec<u64>,
    pub got: BTreeMap<u64, Got>,
    /// Whether main credits the verified bodies as they come.
    pub credits_bodies: bool,
    /// Whether main keeps the verified bodies' bytes, or only counts them.
    pub keep_bodies: bool,
    /// The core's events.
    pub events: Vec<Value>,
    /// The core's pieces main hasn't ended, and whether each streams.
    pub pieces: BTreeMap<u64, bool>,
    /// Of those, the ones not yet answered.
    pub unanswered: usize,
    /// Of those, the streamed ones.
    pub streams: usize,
    /// The most of each seen at once.
    pub most_unanswered: usize,
    pub most_streams: usize,
    /// How long main takes to answer each piece: a node's round trip.
    pub delay: Duration,
    /// The pieces waiting out that delay, in order.
    pub due: VecDeque<(Instant, u64, Value)>,
}

impl Main {
    pub fn new(world: World) -> Self {
        Self::with_env(world, &[])
    }

    /// The core, started with `env`.
    pub fn with_env(world: World, env: &[(&str, &str)]) -> Self {
        let (dir, data, locks) = dirs();
        let mut core = spawn_env("serve", &data, &locks, &[], env);
        let hello = core.hello_streams();
        assert_eq!(hello["result"]["protocol"], 2, "{hello}");
        let caps = hello["result"]["capabilities"].as_array().unwrap();
        assert!(caps.contains(&json!("dweb.verify")), "{hello}");
        Self {
            _dir: dir,
            core,
            world,
            next_id: 2,
            flows: BTreeMap::new(),
            asked: Vec::new(),
            held: Vec::new(),
            cancels: Vec::new(),
            got: BTreeMap::new(),
            credits_bodies: true,
            keep_bodies: true,
            events: Vec::new(),
            pieces: BTreeMap::new(),
            unanswered: 0,
            streams: 0,
            most_unanswered: 0,
            most_streams: 0,
            delay: Duration::ZERO,
            due: VecDeque::new(),
        }
    }

    /// Sends `method` with `params`; its ID.
    pub fn call(&mut self, method: &str, params: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let request = shell_request(id, method, params);
        self.got.insert(id, Got::new());
        self.core.send(&request);
        id
    }

    pub fn verify(&mut self, params: Value) -> u64 {
        self.call("dweb.verify", params)
    }

    /// Sends the browser's `vault.lock`; its ID.
    pub fn lock(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.got.insert(id, Got::new());
        self.core.send(&request(id, "vault.lock", json!({})));
        id
    }

    /// Answers every held piece as the honest world does.
    pub fn release_held(&mut self) {
        self.world.changes.clear();
        for id in std::mem::take(&mut self.held) {
            let params = self.asked.iter().find(|(g, _)| *g == id).unwrap().1.clone();
            self.answer_piece(id, &params);
        }
    }

    pub fn cancel(&mut self, id: u64) {
        self.core.send(&json!({ "type": "cancel", "id": id }));
    }

    /// Main has ended piece `id`.
    fn piece_ended(&mut self, id: u64) {
        if self.pieces.remove(&id) == Some(true) {
            self.streams -= 1;
        }
    }

    /// Writes what the core's credit allows of each piece, ending or
    /// cutting a piece once its bytes have gone. True if it wrote.
    pub fn send_pieces(&mut self) -> bool {
        let mut wrote = false;
        let mut ended = Vec::new();
        for (&id, f) in self.flows.iter_mut() {
            let stop = f.cut.map_or(f.body.len(), |(n, _)| n.min(f.body.len()));
            while f.at < stop && f.room > 0 {
                let n = f.room.min(MAX_DATA).min(stop - f.at);
                let frame = stream_frame(KIND_DATA, id, &f.body[f.at..f.at + n]);
                self.core.send_raw(&frame);
                f.at += n;
                f.room -= n;
                wrote = true;
            }
            if f.at == stop && !f.open {
                match f.cut {
                    Some((_, code)) => {
                        let abort = json!({ "code": code, "message": "cut" }).to_string();
                        self.core
                            .send_raw(&stream_frame(KIND_ABORT, id, abort.as_bytes()));
                    }
                    None => self.core.send_raw(&stream_frame(KIND_END, id, b"")),
                }
                ended.push(id);
                wrote = true;
            }
        }
        for id in ended {
            self.flows.remove(&id);
            self.piece_ended(id);
        }
        wrote
    }

    pub fn respond(&mut self, id: u64, result: Value) {
        self.core
            .send(&json!({ "type": "response", "id": id, "result": result }));
    }

    /// A `shell.dweb_get`: noted, then answered as the world answers it,
    /// at once or after [`Main::delay`].
    fn piece(&mut self, request: &Value) {
        let id = request["id"].as_u64().unwrap();
        let params = request["params"].clone();
        let stream = params["stream"] == true;
        self.asked.push((id, params.clone()));
        self.pieces.insert(id, stream);
        self.unanswered += 1;
        self.streams += usize::from(stream);
        self.most_unanswered = self.most_unanswered.max(self.unanswered);
        self.most_streams = self.most_streams.max(self.streams);
        if self.delay.is_zero() {
            self.answer_piece(id, &params);
        } else {
            self.due
                .push_back((Instant::now() + self.delay, id, params));
        }
    }

    /// Answers the pieces whose delay has passed; when the next is due.
    fn answer_due(&mut self) -> Option<Instant> {
        let now = Instant::now();
        while let Some((at, ..)) = self.due.front() {
            if *at > now {
                return Some(*at);
            }
            let (_, id, params) = self.due.pop_front().unwrap();
            self.answer_piece(id, &params);
        }
        None
    }

    fn answer_piece(&mut self, id: u64, params: &Value) {
        let path = params["path"].as_str().unwrap().to_owned();
        let headers: Vec<(String, String)> = params["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| (h[0].as_str().unwrap().into(), h[1].as_str().unwrap().into()))
            .collect();
        let stream = params["stream"] == true;
        let pairs = |h: &[(String, String)]| -> Value {
            h.iter()
                .map(|(n, v)| json!([n, v]))
                .collect::<Vec<_>>()
                .into()
        };
        let flow = |body, cut, open| Flow {
            body,
            at: 0,
            room: WINDOW,
            cut,
            open,
        };
        match self.world.answer(&path, &headers) {
            Answer::Whole(status, headers, body) => {
                self.respond(
                    id,
                    json!({ "status": status, "headers": pairs(&headers), "body_base64": b64(body) }),
                );
                self.unanswered -= 1;
                self.piece_ended(id);
            }
            Answer::Stream {
                status,
                headers,
                body,
                cut,
            } => {
                assert!(stream, "{path}");
                self.respond(
                    id,
                    json!({ "status": status, "headers": pairs(&headers), "body": true }),
                );
                self.unanswered -= 1;
                self.flows.insert(id, flow(body, cut, false));
            }
            Answer::Open => {
                assert!(stream, "{path}");
                let head = json!({ "status": 200, "headers": [], "body": true });
                self.respond(id, head);
                self.unanswered -= 1;
                self.flows.insert(id, flow(Cow::Borrowed(&[]), None, true));
            }
            Answer::Hold => self.held.push(id),
        }
    }

    /// One frame from the core, handled as main handles it.
    pub fn take(&mut self, wire: Wire) {
        match wire {
            Wire::Message(m) if m["type"] == "request" => {
                assert_eq!(m["method"], "shell.dweb_get", "{m}");
                self.piece(&m);
            }
            Wire::Message(m) if m["type"] == "cancel" => {
                let id = m["id"].as_u64().unwrap();
                self.cancels.push(id);
                if self.flows.remove(&id).is_some() {
                    let abort = json!({ "code": "cancelled", "message": "Cancelled" });
                    self.core
                        .send_raw(&stream_frame(KIND_ABORT, id, abort.to_string().as_bytes()));
                    self.piece_ended(id);
                } else if let Some(at) = self.held.iter().position(|h| *h == id) {
                    self.held.remove(at);
                    self.respond(id, json!({ "failed": "aborted" }));
                    self.unanswered -= 1;
                    self.piece_ended(id);
                } else if let Some(at) = self.due.iter().position(|(_, d, _)| *d == id) {
                    self.due.remove(at);
                    self.respond(id, json!({ "failed": "aborted" }));
                    self.unanswered -= 1;
                    self.piece_ended(id);
                }
            }
            Wire::Message(m) if m["type"] == "response" => {
                let id = m["id"].as_u64().unwrap();
                let arrived = self.core.arrived();
                let got = self.got.get_mut(&id).expect("a response to main's request");
                assert!(got.result.is_none(), "a second response: {m}");
                got.result = Some(m);
                got.answered = Some(arrived);
            }
            Wire::Message(m) if m["type"] == "event" => self.events.push(m),
            Wire::Stream { kind, id, rest } => match kind {
                KIND_DATA => {
                    let got = self.got.get_mut(&id).expect("a body of main's request");
                    assert!(!got.ended && got.abort.is_none());
                    got.len += rest.len();
                    if self.keep_bodies {
                        got.body.extend_from_slice(&rest);
                    }
                    if self.credits_bodies {
                        let n = u32::try_from(rest.len()).unwrap().to_be_bytes();
                        self.core
                            .send_raw(&stream_frame(KIND_STREAM_CREDIT, id, &n));
                    }
                }
                KIND_END => {
                    let arrived = self.core.arrived();
                    let got = self.got.get_mut(&id).unwrap();
                    got.ended = true;
                    got.finished = Some(arrived);
                }
                KIND_ABORT => {
                    let arrived = self.core.arrived();
                    let got = self.got.get_mut(&id).unwrap();
                    got.abort = Some(serde_json::from_slice(&rest).unwrap());
                    got.finished = Some(arrived);
                }
                KIND_STREAM_CREDIT => {
                    let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
                    if let Some(f) = self.flows.get_mut(&id) {
                        f.room += n;
                    }
                }
                other => panic!("stream kind {other:#04x}"),
            },
            other => panic!("unexpected from the core: {other:?}"),
        }
    }

    /// One turn: writes what credit allows, then takes one frame, waiting
    /// up to `quiet` if it wrote nothing. False if nothing moved.
    pub fn step(&mut self, quiet: Duration) -> bool {
        let next = self.answer_due();
        let wrote = self.send_pieces();
        let mut wait = if wrote {
            Duration::from_millis(1)
        } else {
            quiet
        };
        // A piece still to answer keeps main moving.
        let waiting = next.is_some();
        if let Some(at) = next {
            wait = wait.min(at.saturating_duration_since(Instant::now()));
        }
        match self.core.recv_wire_within(wait) {
            Some(wire) => {
                self.take(wire);
                true
            }
            None => wrote || waiting,
        }
    }

    /// Runs main until `done`, or until nothing has moved for `quiet`.
    pub fn run_until(&mut self, quiet: Duration, done: impl Fn(&Self) -> bool) -> bool {
        loop {
            if done(self) {
                return true;
            }
            if !self.step(quiet) {
                return done(self);
            }
        }
    }

    /// Runs main until each of `ids` is answered whole.
    pub fn settle(&mut self, ids: &[u64]) {
        let ok = self.run_until(Duration::from_secs(20), |m| {
            ids.iter().all(|id| m.got[id].done())
        });
        assert!(
            ok,
            "{:?}",
            ids.iter().map(|id| &self.got[id]).collect::<Vec<_>>()
        );
    }

    pub fn result(&self, id: u64) -> &Value {
        &self.got[&id].result.as_ref().unwrap()["result"]
    }

    pub fn error_code(&self, id: u64) -> &Value {
        &self.got[&id].result.as_ref().unwrap()["error"]["code"]
    }
}

/// A verify plan for `root` and `path`, the backend's retry, timers,
/// response and trust as dweb.open writes them (dweb-verify-plans.json).
pub fn plan(root: Value, path: &str, headers: Value) -> Value {
    let node = if root.get("swarm").is_some() {
        "ant"
    } else {
        "ipfs"
    };
    // The file is read once: a load test makes hundreds of plans.
    static PLANS: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    let plans = PLANS.get_or_init(|| vectors("dweb-verify-plans.json"));
    let mut plan = plans["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["plan"]["verify"]["node"] == node)
        .unwrap()["plan"]
        .clone();
    let v = &mut plan["verify"];
    v["root"] = root;
    v["path"] = path.into();
    v["query"] = "".into();
    v["headers"] = headers;
    plan
}

pub fn params(plan: Value, method: &str, car: Option<bool>) -> Value {
    let mut p = json!({
        "plan": plan, "method": method, "partition": null, "private": false, "deadline_ms": 360_000,
    });
    if let Some(car) = car {
        p["car"] = car.into();
    }
    p
}

pub fn swarm(path: &str) -> Value {
    params(
        plan(json!({ "swarm": SITE_A }), path, json!([])),
        "GET",
        None,
    )
}

pub fn ipfs(path: &str, car: bool) -> Value {
    params(
        plan(json!({ "ipfs": SITE_V1 }), path, json!([])),
        "GET",
        Some(car),
    )
}
