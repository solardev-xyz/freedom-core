//! The verifier's Swarm walk (design 0009, step 3b) against the honest
//! Ant of vectors/dweb-verify.json, as main and the hashing pool drive it:
//!
//! - every `/bzz` exchange Ant answered there, reproduced through the
//!   world (status, headers less the node's, and body), with the design's
//!   deviations named;
//! - every `swarm/*` request case of vectors/dweb-verify-cases.json: the
//!   head and body, the error before the head, or the head and exactly the
//!   bytes released before the abort;
//! - the machine's own rules: credit never past what was received, nothing
//!   credited once a piece is cancelled, results it didn't ask for refused,
//!   the request's memory within its bound throughout and back at zero.
//!
//! Each run checks the invariants after every step.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use base64::Engine as _;
use fc_dweb::verifier::{
    Head, Method, Misuse, Output, PieceFailure, PieceId, PieceRequest, REQUEST_BUDGET,
    STREAM_WINDOW, Verifier,
};
use fc_dweb::{
    Ant, Backend, ContentTrust, ErrorPlan, Node, ResponseOp, Root, Trust, Verify, retry, timers,
};
use fc_swarm::tree;
use serde_json::Value as Json;
use sha2::{Digest, Sha256};

fn load(name: &str) -> Json {
    let path = format!("{}/../../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn b64(v: &Json) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str().unwrap())
        .unwrap()
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// content(seed, n): SHA-256(seed ‖ u64_be(i)), concatenated and cut.
fn content(seed: &str, n: usize) -> Vec<u8> {
    if let Some(text) = seed.strip_prefix("literal:") {
        return text.as_bytes()[..n].to_vec();
    }
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

// ---------------------------------------------------------------------------
// The honest Ant.

#[derive(Clone)]
struct LeafSource {
    seed: String,
    from: usize,
    len: usize,
    span: u64,
}

type Joined = ([u8; 32], std::rc::Rc<Vec<u8>>);

struct Store {
    chunks: HashMap<[u8; 32], Vec<u8>>,
    leaves: HashMap<[u8; 32], LeafSource>,
    contents: RefCell<HashMap<String, std::rc::Rc<Vec<u8>>>>,
    sizes: HashMap<String, usize>,
    /// Owner and topic, in hex, to the latest update's index.
    feeds: HashMap<(String, String), Option<u64>>,
    /// The last file joined, for the requests that follow on it.
    joined: RefCell<Option<Joined>>,
}

impl Store {
    fn new(doc: &Json) -> Self {
        let s = &doc["swarm"];
        let mut chunks = HashMap::new();
        for (address, wire) in s["chunks"].as_object().unwrap() {
            chunks.insert(hex32(address), b64(wire));
        }
        let mut store = Self {
            chunks,
            leaves: HashMap::new(),
            contents: RefCell::new(HashMap::new()),
            sizes: HashMap::new(),
            feeds: HashMap::new(),
            joined: RefCell::new(None),
        };
        let mut sources: Vec<([u8; 32], String, usize)> = Vec::new();
        for f in s["files"].as_array().unwrap() {
            sources.push((
                hex32(f["root"].as_str().unwrap()),
                f["seed"].as_str().unwrap().to_owned(),
                f["size"].as_u64().unwrap() as usize,
            ));
        }
        for m in s["manifests"].as_array().unwrap() {
            for e in m["entries"].as_array().unwrap() {
                let (Some(seed), Some(r)) = (e["seed"].as_str(), e["data_ref"].as_str()) else {
                    continue;
                };
                if r.len() == 64 {
                    sources.push((
                        hex32(r),
                        seed.to_owned(),
                        e["size"].as_u64().unwrap() as usize,
                    ));
                }
            }
        }
        // Files Ant served whole, by their ETag.
        for e in s["exchanges"].as_array().unwrap() {
            let r = &e["response"];
            if e["request"]["method"] != "GET" || r["status"] != 200 {
                continue;
            }
            let Some(c) = r["body"].get("content") else {
                continue;
            };
            if c["from"] != 0 {
                continue;
            }
            let Some(etag) = header(&r["headers"], "etag") else {
                continue;
            };
            let etag = etag.trim_matches('"');
            if etag.len() == 64 {
                sources.push((
                    hex32(etag),
                    c["seed"].as_str().unwrap().to_owned(),
                    c["length"].as_u64().unwrap() as usize,
                ));
            }
        }
        for shape in s["shapes"].as_array().unwrap() {
            let mut from = 0;
            for l in shape["leaves"].as_array().unwrap() {
                let size = l["size"].as_u64().unwrap() as usize;
                let seed = l["seed"].as_str().unwrap().to_owned();
                store.size(&seed, size);
                store.leaves.insert(
                    hex32(l["address"].as_str().unwrap()),
                    LeafSource {
                        seed,
                        from: 0,
                        len: size,
                        span: l["span"].as_u64().unwrap_or(size as u64),
                    },
                );
                from += size;
            }
            let _ = from;
        }
        for (root, seed, size) in sources {
            store.size(&seed, size);
            store.index(root, &seed, 0, size as u64);
        }
        for f in s["feeds"].as_array().unwrap() {
            let latest = f["updates"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| u["index"].as_u64().unwrap())
                .max();
            store.feeds.insert(
                (
                    f["owner"].as_str().unwrap().to_owned(),
                    f["topic"].as_str().unwrap().to_owned(),
                ),
                latest,
            );
        }
        store
    }

    fn size(&mut self, seed: &str, size: usize) {
        let e = self.sizes.entry(seed.to_owned()).or_insert(0);
        *e = (*e).max(size);
    }

    /// Maps a data tree's leaves to their content.
    fn index(&mut self, address: [u8; 32], seed: &str, from: u64, len: u64) {
        if tree::is_leaf(len) {
            if !self.chunks.contains_key(&address) {
                self.leaves.insert(
                    address,
                    LeafSource {
                        seed: seed.to_owned(),
                        from: from as usize,
                        len: len as usize,
                        span: len,
                    },
                );
            }
            return;
        }
        let Some(wire) = self.chunks.get(&address).cloned() else {
            return;
        };
        let chunk = fc_swarm::verify::Chunk {
            span: wire[..8].try_into().unwrap(),
            payload: &wire[8..],
        };
        let Ok(node) = tree::intermediate(&chunk, len) else {
            return;
        };
        let mut at = from;
        for i in 0..node.len() {
            let (child, child_len) = node.child(i).unwrap();
            self.index(child, seed, at, child_len);
            at += child_len;
        }
    }

    fn content(&self, seed: &str) -> std::rc::Rc<Vec<u8>> {
        if let Some(c) = self.contents.borrow().get(seed) {
            return c.clone();
        }
        let n = self.sizes.get(seed).copied().unwrap_or(0);
        let c = std::rc::Rc::new(content(seed, n));
        self.contents
            .borrow_mut()
            .insert(seed.to_owned(), c.clone());
        c
    }

    fn wire(&self, address: &[u8; 32], extra: &HashMap<[u8; 32], Vec<u8>>) -> Option<Vec<u8>> {
        if let Some(w) = extra.get(address).or_else(|| self.chunks.get(address)) {
            return Some(w.clone());
        }
        let l = self.leaves.get(address)?;
        let c = self.content(&l.seed);
        let mut w = l.span.to_le_bytes().to_vec();
        w.extend_from_slice(&c[l.from..l.from + l.len]);
        Some(w)
    }

    /// The file's bytes as Ant's joiner reads them.
    fn join(
        &self,
        address: &[u8; 32],
        extra: &HashMap<[u8; 32], Vec<u8>>,
    ) -> Option<std::rc::Rc<Vec<u8>>> {
        if let Some((a, j)) = self.joined.borrow().as_ref()
            && a == address
            && extra.is_empty()
        {
            return Some(j.clone());
        }
        let wire = self.wire(address, extra)?;
        let (_, len) = tree::decode_span(&wire[..8].try_into().unwrap());
        let mut out = Vec::new();
        self.join_node(&wire, len, extra, &mut out)?;
        let out = std::rc::Rc::new(out);
        *self.joined.borrow_mut() = Some((*address, out.clone()));
        Some(out)
    }

    fn join_node(
        &self,
        wire: &[u8],
        len: u64,
        extra: &HashMap<[u8; 32], Vec<u8>>,
        out: &mut Vec<u8>,
    ) -> Option<()> {
        if tree::is_leaf(len) {
            let payload = &wire[8..];
            out.extend_from_slice(&payload[..(len as usize).min(payload.len())]);
            return Some(());
        }
        let chunk = fc_swarm::verify::Chunk {
            span: wire[..8].try_into().unwrap(),
            payload: &wire[8..],
        };
        let node = tree::intermediate(&chunk, len).ok()?;
        for i in 0..node.len() {
            let (child, child_len) = node.child(i)?;
            let w = self.wire(&child, extra)?;
            self.join_node(&w, child_len, extra, out)?;
        }
        Some(())
    }
}

fn header<'a>(headers: &'a Json, name: &str) -> Option<&'a str> {
    headers
        .as_array()?
        .iter()
        .find(|h| h[0] == name)
        .and_then(|h| h[1].as_str())
}

/// What a piece's request gets.
enum Answer {
    Whole {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    Stream {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        /// Bytes sent before the stream goes silent.
        stall_after: Option<usize>,
    },
}

/// The honest node with one case's chunks and changes.
struct World<'s> {
    store: &'s Store,
    extra: HashMap<[u8; 32], Vec<u8>>,
    changes: Vec<Json>,
}

impl<'s> World<'s> {
    fn honest(store: &'s Store) -> Self {
        Self {
            store,
            extra: HashMap::new(),
            changes: Vec::new(),
        }
    }

    fn of(store: &'s Store, world: &Json) -> Self {
        let mut w = Self::honest(store);
        if let Some(chunks) = world["chunks"].as_object() {
            for (a, wire) in chunks {
                w.extra.insert(hex32(a), b64(&wire["base64"]));
            }
        }
        if let Some(changes) = world["changes"].as_array() {
            w.changes = changes.clone();
        }
        w
    }

    fn change(&self, piece: &str, key: &str, value: &str) -> Option<&Json> {
        self.changes
            .iter()
            .find(|c| c["piece"] == piece && c[key] == value)
    }

    fn answer(&self, req: &PieceRequest) -> Answer {
        let not_found = || Answer::Whole {
            status: 404,
            headers: vec![],
            body: br#"{"code":404,"message":"Not Found"}"#.to_vec(),
        };
        if let Some(a) = req.path.strip_prefix("/chunks/") {
            assert!(!req.stream);
            if let Some(c) = self.change("chunk", "address", a) {
                if let Some(status) = c["status"].as_u64() {
                    return Answer::Whole {
                        status: status as u16,
                        headers: vec![],
                        body: b64(&c["body"]["base64"]),
                    };
                }
                if let Some(wire) = c.get("wire") {
                    return Answer::Whole {
                        status: 200,
                        headers: vec![],
                        body: b64(&wire["base64"]),
                    };
                }
                let mut wire = self.store.wire(&hex32(a), &self.extra).unwrap();
                let at = c["flip"].as_u64().unwrap() as usize;
                wire[at] ^= 1;
                return Answer::Whole {
                    status: 200,
                    headers: vec![],
                    body: wire,
                };
            }
            return match self.store.wire(&hex32(a), &self.extra) {
                Some(wire) => Answer::Whole {
                    status: 200,
                    headers: vec![],
                    body: wire,
                },
                None => not_found(),
            };
        }
        if let Some(rest) = req.path.strip_prefix("/feeds/") {
            assert!(!req.stream);
            assert!(
                req.headers
                    .iter()
                    .any(|h| h == &("swarm-only-root-chunk".to_owned(), "true".to_owned()))
            );
            let (owner, topic) = rest.split_once('/').unwrap();
            return match self.store.feeds.get(&(owner.to_owned(), topic.to_owned())) {
                Some(Some(index)) => Answer::Whole {
                    status: 200,
                    headers: vec![("swarm-feed-index".to_owned(), format!("{index:016x}"))],
                    body: vec![],
                },
                _ => not_found(),
            };
        }
        let r = req.path.strip_prefix("/bytes/").unwrap();
        assert!(req.stream);
        let range = req
            .headers
            .iter()
            .find(|(n, _)| n == "range")
            .map(|(_, v)| v.clone())
            .unwrap();
        let (fs, fe) = range
            .strip_prefix("bytes=")
            .unwrap()
            .split_once('-')
            .map(|(a, b)| (a.parse::<usize>().unwrap(), b.parse::<usize>().unwrap()))
            .unwrap();
        let change = self.change("bytes", "reference", r);
        if let Some(body) = change.and_then(|c| c.get("body")) {
            let total = self
                .store
                .wire(&hex32(r), &self.extra)
                .map_or(0, |w| tree::decode_span(&w[..8].try_into().unwrap()).1);
            return Answer::Stream {
                status: 206,
                headers: vec![(
                    "content-range".to_owned(),
                    format!("bytes {fs}-{fe}/{total}"),
                )],
                body: b64(&body["base64"]),
                stall_after: None,
            };
        }
        let Some(file) = self.store.join(&hex32(r), &self.extra) else {
            return Answer::Stream {
                status: 404,
                headers: vec![],
                body: vec![],
                stall_after: None,
            };
        };
        let total = file.len();
        let mut status = 206;
        let mut cr = format!("bytes {fs}-{fe}/{total}");
        let (mut body, base) = (file[fs..=fe].to_vec(), fs);
        let mut base = base;
        let mut stall = None;
        if let Some(c) = change {
            match c["answer"].as_str() {
                Some("whole") => {
                    status = 200;
                    body = file.to_vec();
                    base = 0;
                }
                Some("at_zero") => status = 200,
                _ => {}
            }
            if let Some(x) = c["content_range"].as_str() {
                cr = x.to_owned();
            }
            if let Some(at) = c["flip"].as_u64() {
                let at = at as usize;
                if at >= base && at - base < body.len() {
                    body[at - base] ^= 1;
                }
            }
            if let Some(n) = c["end_after"].as_u64() {
                body.truncate(n as usize);
            }
            stall = c["stall_after"].as_u64().map(|n| n as usize);
        }
        let headers = if status == 206 {
            vec![("content-range".to_owned(), cr)]
        } else {
            vec![("content-length".to_owned(), body.len().to_string())]
        };
        Answer::Stream {
            status,
            headers,
            body,
            stall_after: stall,
        }
    }
}

// ---------------------------------------------------------------------------
// The driver: main, the hashing pool and the page.

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ending {
    End,
    Abort(String, String),
    Error(u16, String),
    Cancelled,
}

#[derive(Debug, Default)]
struct Run {
    head: Option<Head>,
    body: Vec<u8>,
    ending: Option<Ending>,
    pieces: Vec<PieceRequest>,
    jobs: usize,
    /// The most the request held or had reserved at once.
    peak: usize,
    /// For each answer held back: the streams open when it went out.
    held_after: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Order {
    /// Each action in the order it was asked for.
    Fifo,
    /// The newest first: replies and results out of order.
    Lifo,
}

#[derive(Debug, Clone, Copy)]
struct Opts {
    budget: usize,
    order: Order,
    /// The page's credit per step, or all at once.
    page: Option<usize>,
    /// Cancel the request after this many steps.
    cancel_after: Option<usize>,
    /// A chunk whose answer main holds back until nothing else moves.
    hold: Option<[u8; 32]>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            budget: REQUEST_BUDGET,
            order: Order::Fifo,
            page: None,
            cancel_after: None,
            hold: None,
        }
    }
}

enum Action {
    Answer(PieceRequest),
    Job(fc_dweb::verifier::Job),
    More(PieceId),
    Terminal(PieceId),
    Page,
}

struct SimStream {
    body: Vec<u8>,
    at: usize,
    sent: usize,
    credited: usize,
    stall_after: Option<usize>,
    cancelled: bool,
    done: bool,
}

fn run(label: &str, plan: &Verify, method: Method, world: &World<'_>, opts: Opts) -> Run {
    let mut v = Verifier::with_budget(7, plan, method, None, false, opts.budget)
        .unwrap_or_else(|e| panic!("plan refused at {e}: {plan:?}"));
    let mut out = Run::default();
    let mut queue: VecDeque<Action> = VecDeque::new();
    let mut streams: BTreeMap<PieceId, SimStream> = BTreeMap::new();
    let mut cancelled_wholes: BTreeSet<PieceId> = BTreeSet::new();
    let mut owed_page = 0usize;
    let mut steps = 0usize;
    let mut held: Vec<Action> = Vec::new();
    let held_path = opts.hold.map(|a| format!("/chunks/{}", hex::encode(a)));
    loop {
        while let Some(o) = v.poll() {
            match o {
                Output::Piece(req) => {
                    assert!(out.ending.is_none(), "a piece after the end");
                    out.pieces.push(req.clone());
                    queue.push_back(Action::Answer(req));
                }
                Output::CancelPiece(id) => {
                    if let Some(s) = streams.get_mut(&id) {
                        assert!(!s.cancelled);
                        s.cancelled = true;
                        queue.push_back(Action::Terminal(id));
                    } else {
                        cancelled_wholes.insert(id);
                    }
                }
                Output::Credit { piece, bytes } => {
                    let s = streams.get_mut(&piece).expect("credit for a stream");
                    assert!(!s.cancelled, "credit after a cancel");
                    assert!(bytes > 0);
                    s.credited += bytes;
                    assert!(
                        s.credited <= s.sent,
                        "credit for bytes never received: {} of {}",
                        s.credited,
                        s.sent
                    );
                    queue.push_back(Action::More(piece));
                }
                Output::Hash(job) => {
                    out.jobs += 1;
                    queue.push_back(Action::Job(job));
                }
                Output::Head(h) => {
                    assert!(out.head.is_none() && out.ending.is_none());
                    out.head = Some(h);
                }
                Output::Body(b) => {
                    assert!(
                        out.head.as_ref().is_some_and(|h| h.body),
                        "a body without its head"
                    );
                    assert!(out.ending.is_none());
                    assert!(!b.is_empty() && b.len() <= fc_dweb::verifier::MAX_FRAME);
                    owed_page += b.len();
                    out.body.extend_from_slice(&b);
                    if opts.page.is_none() {
                        v.body_credit(owed_page).unwrap();
                        owed_page = 0;
                    } else {
                        queue.push_back(Action::Page);
                    }
                }
                Output::End => end(&mut out, Ending::End),
                Output::Abort { code, message } => {
                    end(
                        &mut out,
                        Ending::Abort(code.as_str().to_owned(), message.to_owned()),
                    );
                }
                Output::Error(e) => end(&mut out, Ending::Error(e.status, e.message.clone())),
                Output::Cancelled => end(&mut out, Ending::Cancelled),
            }
        }
        assert!(
            v.reserved() <= opts.budget,
            "reserved {} past the budget",
            v.reserved()
        );
        out.peak = out.peak.max(v.reserved());
        // Credit never runs past the reservation: the room main may still
        // fill on every open stream is room the machine holds reserved.
        let mut room = 0;
        for s in streams.values() {
            assert!(s.sent - s.credited <= STREAM_WINDOW);
            if !s.done {
                room += STREAM_WINDOW - (s.sent - s.credited);
            }
        }
        assert!(
            room <= v.reserved(),
            "{label}: open credit {room} past the reservation {}",
            v.reserved()
        );
        assert!(
            owed_page <= fc_dweb::verifier::BODY_WINDOW,
            "{label}: the body ran past main's window"
        );
        steps += 1;
        if opts.cancel_after == Some(steps) {
            v.cancel();
            continue;
        }
        let action = match opts.order {
            Order::Fifo => queue.pop_front(),
            Order::Lifo => queue.pop_back(),
        };
        let action = match action {
            Some(Action::Answer(req)) if held_path.as_deref() == Some(req.path.as_str()) => {
                held.push(Action::Answer(req));
                continue;
            }
            None if !held.is_empty() => {
                out.held_after.push(streams.len());
                held.pop()
            }
            a => a,
        };
        let Some(action) = action else {
            // Nothing moves: main's body idle timer ends a silent stream
            // the core still waits on.
            let stalled = streams
                .iter()
                .find(|(_, s)| !s.done && !s.cancelled)
                .map(|(id, _)| *id);
            if let Some(id) = stalled {
                streams.get_mut(&id).unwrap().done = true;
                v.piece_failed(id, PieceFailure::Stalled).unwrap();
                continue;
            }
            break;
        };
        match action {
            Action::Answer(req) => {
                if cancelled_wholes.contains(&req.id) {
                    v.piece_failed(req.id, PieceFailure::Aborted).unwrap();
                    continue;
                }
                match world.answer(&req) {
                    Answer::Whole {
                        status,
                        headers,
                        body,
                    } => {
                        if body.len() > req.max_bytes.unwrap() {
                            v.piece_failed(req.id, PieceFailure::TooLarge).unwrap();
                        } else {
                            v.piece_whole(req.id, status, headers, body).unwrap();
                        }
                    }
                    Answer::Stream {
                        status,
                        headers,
                        body,
                        stall_after,
                    } => {
                        v.piece_head(req.id, status, headers).unwrap();
                        streams.insert(
                            req.id,
                            SimStream {
                                body,
                                at: 0,
                                sent: 0,
                                credited: 0,
                                stall_after,
                                cancelled: false,
                                done: false,
                            },
                        );
                        queue.push_back(Action::More(req.id));
                    }
                }
            }
            Action::Job(job) => v.hashed(job.run()).unwrap(),
            Action::More(id) => {
                let s = streams.get_mut(&id).unwrap();
                if s.done || s.cancelled {
                    continue;
                }
                let limit = s.stall_after.unwrap_or(s.body.len()).min(s.body.len());
                if s.at < limit {
                    let room = STREAM_WINDOW - (s.sent - s.credited);
                    if room == 0 {
                        continue;
                    }
                    let n = room.min(fc_dweb::verifier::MAX_FRAME).min(limit - s.at);
                    let frame = s.body[s.at..s.at + n].to_vec();
                    s.at += n;
                    s.sent += n;
                    v.piece_data(id, frame).unwrap();
                    queue.push_back(Action::More(id));
                } else if s.stall_after.is_none() {
                    s.done = true;
                    v.piece_end(id).unwrap();
                }
            }
            Action::Terminal(id) => {
                let s = streams.get_mut(&id).unwrap();
                if s.done {
                    continue;
                }
                // A frame that crossed the cancel, within the window, then
                // main's abort.
                let room = STREAM_WINDOW - (s.sent - s.credited);
                if s.at < s.body.len() && room > 0 && s.stall_after.is_none_or(|n| s.at < n) {
                    let n = (s.body.len() - s.at).min(1000).min(room);
                    let frame = s.body[s.at..s.at + n].to_vec();
                    s.at += n;
                    s.sent += n;
                    v.piece_data(id, frame).unwrap();
                }
                s.done = true;
                v.piece_failed(id, PieceFailure::Aborted).unwrap();
            }
            Action::Page => {
                if owed_page > 0 {
                    let n = owed_page.min(opts.page.unwrap());
                    owed_page -= n;
                    v.body_credit(n).unwrap();
                    if owed_page > 0 {
                        queue.push_back(Action::Page);
                    }
                }
            }
        }
    }
    assert!(
        out.ending.is_some() || out.head.as_ref().is_some_and(|h| !h.body),
        "{label}: no terminal: {:?} {} bytes, pieces {:?}",
        out.head,
        out.body.len(),
        out.pieces.iter().map(|p| &p.path).collect::<Vec<_>>()
    );
    assert_eq!(v.reserved(), 0, "{label}: reservations left");
    assert!(v.finished(), "{label}: not finished");
    out
}

fn end(out: &mut Run, e: Ending) {
    assert!(
        out.ending.is_none(),
        "two terminals: {:?} then {e:?}",
        out.ending
    );
    out.ending = Some(e);
}

fn plan(root: &str, path: &str, query: &str, headers: Vec<(String, String)>) -> Verify {
    let backend = Backend::ant(Ant::External, true);
    Verify {
        node: Node::Ant,
        root: Root::Swarm(root.to_owned()),
        path: path.to_owned(),
        query: query.to_owned(),
        headers,
        retry: retry(backend),
        timers: timers(backend),
        response: vec![ResponseOp::CanonicalizeRedirect, ResponseOp::StripPageState],
        trust: Trust {
            name: None,
            content: ContentTrust::Verified,
        },
    }
}

/// A body as the vectors write it.
fn body_of(store: &Store, b: &Json) -> Expected {
    if let Some(c) = b.get("content") {
        let seed = c["seed"].as_str().unwrap();
        let from = c["from"].as_u64().unwrap() as usize;
        let n = c["length"].as_u64().unwrap() as usize;
        let full = store.content(seed);
        let bytes = if full.len() >= from + n {
            full[from..from + n].to_vec()
        } else {
            content(seed, from + n)[from..].to_vec()
        };
        return Expected::Bytes(bytes);
    }
    if let Some(x) = b.get("base64") {
        return Expected::Bytes(b64(x));
    }
    if let Some(h) = b.get("sha256") {
        return Expected::Digest(
            b["length"].as_u64().unwrap() as usize,
            h.as_str().unwrap().to_owned(),
        );
    }
    assert_eq!(b["length"], 0, "{b}");
    Expected::Bytes(vec![])
}

enum Expected {
    Bytes(Vec<u8>),
    Digest(usize, String),
}

fn check_body(id: &str, got: &[u8], want: &Expected) {
    match want {
        Expected::Bytes(b) => {
            assert_eq!(got.len(), b.len(), "{id}: body length");
            assert!(got == b.as_slice(), "{id}: body bytes");
        }
        Expected::Digest(n, h) => {
            assert_eq!(got.len(), *n, "{id}: body length");
            assert_eq!(hex::encode(Sha256::digest(got)), *h, "{id}: body digest");
        }
    }
}

fn pairs(v: &Json) -> Vec<(String, String)> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p[0].as_str().unwrap().to_owned(),
                p[1].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The exchanges.

/// How the core's answer to an exchange differs from Ant's, by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    /// Ant's answer, reproduced.
    Same,
    /// An encrypted reference inside the walk (`encrypted-in-walk`).
    Encrypted,
    /// A feed with no update: the node's 404, with the core's message.
    NodeMiss,
}

fn kind_of(e: &Json) -> Kind {
    let case = e["case"].as_str().unwrap();
    match case {
        "feed-encrypted" | "encrypted-below-plain-root" => Kind::Encrypted,
        "feed-empty" => Kind::NodeMiss,
        _ => Kind::Same,
    }
}

/// The exchanges of the 67,108,865-byte files, most of them whole reads,
/// replay in tests of their own so they run in parallel: the raw trees,
/// then each manifest's exchanges by the parity of their number.
fn big(case: &str, id: &str, part: usize) -> bool {
    let n: usize = id.rsplit('#').next().unwrap().parse().unwrap();
    match part {
        0 => case.starts_with("file-67108865-") && !case.ends_with("-manifest"),
        1 | 2 => case == "file-67108865-rs0-manifest" && n % 2 == part - 1,
        _ => case == "file-67108865-rs1-manifest" && n % 2 == part - 3,
    }
}

#[test]
fn bzz_exchanges() {
    let n = replay(|case, _| !case.starts_with("file-67108865-"));
    assert_eq!(n.total, 249, "{n:?}");
    assert_eq!(n.unplanned, 2, "{n:?}");
    assert_eq!(n.kinds.get(&Kind::Encrypted), Some(&5), "{n:?}");
    assert_eq!(n.kinds.get(&Kind::NodeMiss), Some(&4), "{n:?}");
    assert!(n.runs > 150, "{n:?}");
}

#[test]
fn bzz_exchanges_big_raw() {
    assert_eq!(replay(|case, id| big(case, id, 0)).total, 12);
}

#[test]
fn bzz_exchanges_big_manifest_0() {
    assert_eq!(replay(|case, id| big(case, id, 1)).total, 3);
}

#[test]
fn bzz_exchanges_big_manifest_1() {
    assert_eq!(replay(|case, id| big(case, id, 2)).total, 4);
}

#[test]
fn bzz_exchanges_big_manifest_2() {
    assert_eq!(replay(|case, id| big(case, id, 3)).total, 3);
}

#[test]
fn bzz_exchanges_big_manifest_3() {
    assert_eq!(replay(|case, id| big(case, id, 4)).total, 4);
}

/// What a plan is made of here: root, path, query and headers.
type PlanKey = (String, String, String, Vec<(String, String)>);

#[derive(Debug)]
struct Replayed {
    /// The `/bzz` exchanges of the chosen cases.
    total: usize,
    unplanned: usize,
    kinds: BTreeMap<Kind, usize>,
    runs: usize,
}

fn replay(choose: impl Fn(&str, &str) -> bool) -> Replayed {
    let doc = load("dweb-verify.json");
    let store = Store::new(&doc);
    let world = World::honest(&store);
    let node_headers: Vec<String> = doc["meta"]["ant"]["node_headers"]["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_owned())
        .collect();
    let exchanges = doc["swarm"]["exchanges"].as_array().unwrap();
    let by_id: HashMap<&str, &Json> = exchanges
        .iter()
        .map(|e| (e["id"].as_str().unwrap(), e))
        .collect();
    let mut kinds: BTreeMap<Kind, usize> = BTreeMap::new();
    let mut unplanned = Vec::new();
    let mut runs: HashMap<PlanKey, Run> = HashMap::new();
    let mut total = 0;
    for e in exchanges {
        let id = e["id"].as_str().unwrap();
        let req = &e["request"];
        let Some(rest) = req["path"].as_str().unwrap().strip_prefix("/bzz/") else {
            continue;
        };
        if !choose(e["case"].as_str().unwrap(), id) {
            continue;
        }
        // HEAD and ranges are step 3b-1's second part.
        if req["method"] != "GET" || header(&req["headers"], "range").is_some() {
            continue;
        }
        total += 1;
        let (root, below) = rest.split_at(64);
        let (path, query) = match below.find('?') {
            Some(at) => (&below[..at], &below[at..]),
            None => (below, ""),
        };
        let method = Method::Get;
        let p = plan(root, path, query, vec![]);
        if Verifier::new(1, &p, method, None, false).is_err() {
            // No verify plan reaches it: main's validation refuses an
            // encoded separator, as the core does.
            unplanned.push(id.to_owned());
            continue;
        }
        // The plan is all the machine sees: a request whose plan matches an
        // earlier one's (only headers the plan drops differ) gets its run.
        let key = (
            root.to_owned(),
            path.to_owned(),
            query.to_owned(),
            p.headers.clone(),
        );
        let got = runs
            .entry(key)
            .or_insert_with(|| run(id, &p, method, &world, Opts::default()));
        let kind = kind_of(e);
        *kinds.entry(kind).or_default() += 1;
        match kind {
            Kind::Same => {
                let r = &e["response"];
                let head = got
                    .head
                    .as_ref()
                    .unwrap_or_else(|| panic!("{id}: no head: {:?}", got.ending));
                assert_eq!(
                    head.status,
                    r["status"].as_u64().unwrap() as u16,
                    "{id}: status ({:?})",
                    got.ending
                );
                let want_headers: Vec<(String, String)> = pairs(&r["headers"])
                    .into_iter()
                    .filter(|(n, _)| !node_headers.contains(n))
                    .collect();
                assert_eq!(head.headers, want_headers, "{id}: headers");
                assert_eq!(head.body, method == Method::Get, "{id}");
                let feed = e["case"].as_str().unwrap().starts_with("feed-");
                let label = head.trust.content;
                assert!(
                    label == ContentTrust::Verified
                        || (feed && label == ContentTrust::LatestAsserted),
                    "{id}: {label:?}"
                );
                if method == Method::Get {
                    assert_eq!(got.ending, Some(Ending::End), "{id}");
                    check_body(id, &got.body, &body_of(&store, &r["body"]));
                } else {
                    assert!(got.body.is_empty() && got.ending.is_none(), "{id}");
                }
            }
            Kind::Encrypted => {
                assert_eq!(
                    got.ending,
                    Some(Ending::Error(
                        502,
                        fc_dweb::verifier::SWARM_UNVERIFIABLE.to_owned()
                    )),
                    "{id}"
                );
            }
            Kind::NodeMiss => {
                assert_eq!(
                    got.ending,
                    Some(Ending::Error(
                        404,
                        fc_dweb::verifier::SWARM_NOT_FOUND.to_owned()
                    )),
                    "{id}"
                );
            }
        }
    }
    for id in &unplanned {
        let path = by_id[id.as_str()]["request"]["path"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase();
        assert!(
            path.contains("%2f") || path.contains("%5c"),
            "{id}: refused"
        );
    }
    assert_eq!(
        kinds.values().sum::<usize>() + unplanned.len(),
        total,
        "{kinds:?}"
    );
    Replayed {
        total,
        unplanned: unplanned.len(),
        kinds,
        runs: runs.len(),
    }
}

// ---------------------------------------------------------------------------
// The request cases.

fn check_case(store: &Store, id: &str, step: &Json, opts: Opts) {
    let p = &step["plan"];
    let plan = plan(
        p["root"]["swarm"].as_str().unwrap(),
        p["path"].as_str().unwrap(),
        p["query"].as_str().unwrap(),
        pairs(&p["headers"]),
    );
    let method = Method::Get;
    let world = World::of(store, &step["world"]);
    let got = run(id, &plan, method, &world, opts);
    let x = &step["expect"];
    if let Some(err) = x.get("error") {
        let status = err["status"].as_u64().unwrap() as u16;
        assert_eq!(
            err["body"]["code"].as_u64(),
            Some(u64::from(status)),
            "{id}"
        );
        let message = err["body"]["message"].as_str().unwrap().to_owned();
        assert_eq!(
            got.ending,
            Some(Ending::Error(status, message.clone())),
            "{id}"
        );
        assert!(got.head.is_none() && got.body.is_empty(), "{id}");
        // The page's body is the core's own.
        assert_eq!(
            ErrorPlan::body(&error_plan(status, &message)),
            serde_json::to_string(&err["body"]).unwrap(),
            "{id}"
        );
        return;
    }
    let h = &x["head"];
    let head = got
        .head
        .as_ref()
        .unwrap_or_else(|| panic!("{id}: no head: {:?}", got.ending));
    assert_eq!(
        head.status,
        h["status"].as_u64().unwrap() as u16,
        "{id}: status"
    );
    assert_eq!(head.headers, pairs(&h["headers"]), "{id}: headers");
    assert_eq!(
        head.trust.name.as_deref(),
        h["trust"]["name"].as_str(),
        "{id}"
    );
    assert_eq!(
        head.trust.content.as_str(),
        h["trust"]["content"].as_str().unwrap(),
        "{id}"
    );
    if let Some(t) = x.get("truncated") {
        check_body(id, &got.body, &body_of(store, &t["released"]));
        let a = &t["abort"];
        assert_eq!(
            got.ending,
            Some(Ending::Abort(
                a["code"].as_str().unwrap().to_owned(),
                a["message"].as_str().unwrap().to_owned()
            )),
            "{id}"
        );
    } else {
        check_body(id, &got.body, &body_of(store, &x["body"]));
        if method == Method::Get {
            assert_eq!(got.ending, Some(Ending::End), "{id}");
        }
    }
}

fn error_plan(status: u16, message: &str) -> ErrorPlan {
    ErrorPlan {
        status,
        message: message.to_owned(),
    }
}

/// The `swarm/*` cases, less those with HEAD or a range: step 3b-1's
/// second part.
fn swarm_cases() -> Vec<Json> {
    let plain = |s: &Json| {
        s["method"] == "GET"
            && s["plan"]["headers"]
                .as_array()
                .is_some_and(|h| h.is_empty())
    };
    load("dweb-verify-cases.json")["requests"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["id"].as_str().unwrap().starts_with("swarm/"))
        .filter(|c| match c["steps"].as_array() {
            Some(steps) => steps.iter().all(plain),
            None => plain(c),
        })
        .cloned()
        .collect()
}

#[test]
fn every_swarm_request_case() {
    let store = Store::new(&load("dweb-verify.json"));
    let cases = swarm_cases();
    let mut n = 0;
    for c in &cases {
        let id = c["id"].as_str().unwrap();
        if let Some(steps) = c["steps"].as_array() {
            // Each step is a request of its own (the shared state is 3c's).
            for (i, s) in steps.iter().enumerate() {
                check_case(&store, &format!("{id}#{i}"), s, Opts::default());
                n += 1;
            }
        } else {
            check_case(&store, id, c, Opts::default());
            n += 1;
        }
    }
    assert_eq!(n, 26, "{n}");
}

/// The same cases with replies and hash results out of order, and a page
/// that reads slowly: the outcome is the same.
#[test]
fn request_cases_in_other_orders() {
    let store = Store::new(&load("dweb-verify.json"));
    for c in swarm_cases().iter().filter(|c| c.get("steps").is_none()) {
        let id = c["id"].as_str().unwrap();
        check_case(
            &store,
            id,
            c,
            Opts {
                order: Order::Lifo,
                ..Opts::default()
            },
        );
        check_case(
            &store,
            id,
            c,
            Opts {
                page: Some(1000),
                ..Opts::default()
            },
        );
    }
}

// ---------------------------------------------------------------------------
// The machine's own rules.

const SITE_A: &str = "3c8b9184787f719e7184f51b5c595a950d8cec49c765dc0e5a8f1c253e54591c";
const FILE_512K: &str = "d5bc5564ebcbeee060f251c1b4befe69514a801fb2a363635657fbee6d3c610f";

/// Results the machine didn't ask for, or got twice, are refused and
/// change nothing.
#[test]
fn hash_results_it_did_not_ask_for_are_refused() {
    let doc = load("dweb-verify.json");
    let store = Store::new(&doc);
    let world = World::honest(&store);
    let p = plan(SITE_A, "/style.css", "", vec![]);
    let mut v = Verifier::new(3, &p, Method::Get, None, false).unwrap();
    let mut other = Verifier::new(4, &p, Method::Get, None, false).unwrap();
    let Some(Output::Piece(req)) = v.poll() else {
        panic!("the root first")
    };
    let Some(Output::Piece(other_req)) = other.poll() else {
        panic!()
    };
    let Answer::Whole { body, .. } = world.answer(&req) else {
        panic!()
    };
    v.piece_whole(req.id, 200, vec![], body.clone()).unwrap();
    other.piece_whole(other_req.id, 200, vec![], body).unwrap();
    let Some(Output::Hash(job)) = v.poll() else {
        panic!("the root's check")
    };
    let Some(Output::Hash(other_job)) = other.poll() else {
        panic!()
    };
    assert_eq!(job.id().request, 3);
    let done = job.run();
    let before = v.reserved();
    // Another request's job, with the same number.
    assert_eq!(v.hashed(other_job.run()), Err(Misuse::UnknownJob));
    assert_eq!(v.reserved(), before);
    assert!(v.poll().is_none());
    v.hashed(done.clone()).unwrap();
    assert_eq!(v.hashed(done), Err(Misuse::DuplicateJob));
    // A piece never asked for, and a reply to one that has ended.
    assert_eq!(
        v.piece_whole(PieceId(99), 200, vec![], vec![]),
        Err(Misuse::UnknownPiece)
    );
    assert_eq!(
        v.piece_whole(req.id, 200, vec![], vec![]),
        Err(Misuse::EndedPiece)
    );
    assert_eq!(v.body_credit(1), Err(Misuse::BodyCredit));
}

/// A stream's data within its window only, its head first, frames in
/// bounds.
#[test]
fn stream_protocol_errors() {
    let doc = load("dweb-verify.json");
    let store = Store::new(&doc);
    let world = World::honest(&store);
    let p = plan(FILE_512K, "/", "", vec![]);
    let mut v = Verifier::new(5, &p, Method::Get, None, false).unwrap();
    let mut queue = VecDeque::new();
    let stream = loop {
        while let Some(o) = v.poll() {
            match o {
                Output::Piece(r) if r.stream => queue.push_front(Err(r)),
                Output::Piece(r) => queue.push_back(Ok(r)),
                Output::Hash(j) => {
                    v.hashed(j.run()).unwrap();
                }
                _ => {}
            }
        }
        match queue.pop_front().unwrap() {
            Ok(r) => {
                let Answer::Whole {
                    status,
                    headers,
                    body,
                } = world.answer(&r)
                else {
                    panic!()
                };
                v.piece_whole(r.id, status, headers, body).unwrap();
            }
            Err(r) => break r,
        }
    };
    assert_eq!(v.piece_data(stream.id, vec![1]), Err(Misuse::BeforeHead));
    assert_eq!(
        v.piece_whole(stream.id, 200, vec![], vec![]),
        Err(Misuse::WrongKind)
    );
    let Answer::Stream {
        status,
        headers,
        body,
        ..
    } = world.answer(&stream)
    else {
        panic!()
    };
    v.piece_head(stream.id, status, headers.clone()).unwrap();
    assert_eq!(
        v.piece_head(stream.id, status, headers),
        Err(Misuse::SecondHead)
    );
    assert_eq!(v.piece_data(stream.id, vec![]), Err(Misuse::Frame));
    assert_eq!(v.piece_data(stream.id, vec![0; 65537]), Err(Misuse::Frame));
    v.piece_data(stream.id, body[..65536].to_vec()).unwrap();
    v.piece_data(stream.id, body[65536..131072].to_vec())
        .unwrap();
    // The window is full until the machine credits some back; it hashes
    // first, so no credit yet.
    assert_eq!(v.piece_data(stream.id, vec![0]), Err(Misuse::BeyondCredit));
}

/// The request's memory: a budget too small for a piece's room ends the
/// walk as unverifiable, with every reservation back at zero; one just
/// large enough gives the honest answer.
#[test]
fn budgets_exhausted_at_each_reservation() {
    let store = Store::new(&load("dweb-verify.json"));
    let world = World::honest(&store);
    let style = plan(SITE_A, "/style.css", "", vec![]);
    let big = plan(FILE_512K, "/", "", vec![]);
    for p in [&style, &big] {
        let honest = run("budget", p, Method::Get, &world, Opts::default());
        assert_eq!(honest.ending, Some(Ending::End));
        for budget in [
            0,
            100,
            4200,
            4201,
            9000,
            20_000,
            100_000,
            STREAM_WINDOW,
            STREAM_WINDOW + 20_000,
            300_000,
        ] {
            let got = run(
                "budget",
                p,
                Method::Get,
                &world,
                Opts {
                    budget,
                    ..Opts::default()
                },
            );
            match &got.ending {
                Some(Ending::End) => {
                    assert_eq!(got.body, honest.body, "{budget}");
                    assert_eq!(got.head, honest.head, "{budget}");
                }
                Some(Ending::Error(502, m)) | Some(Ending::Abort(_, m)) => {
                    assert_eq!(m, fc_dweb::verifier::SWARM_UNVERIFIABLE, "{budget}");
                }
                other => panic!("{budget}: {other:?}"),
            }
        }
    }
}

/// A cancel at every step: before the head `cancelled`, after it an abort,
/// with only verified bytes released and nothing left reserved.
#[test]
fn cancel_at_every_step() {
    let store = Store::new(&load("dweb-verify.json"));
    let world = World::honest(&store);
    let p = plan(FILE_512K, "/", "", vec![]);
    let honest = run("cancel", &p, Method::Get, &world, Opts::default());
    let want = content("file-524288", 524_288);
    assert_eq!(honest.body, want);
    for at in 1..200 {
        let got = run(
            "cancel",
            &p,
            Method::Get,
            &world,
            Opts {
                cancel_after: Some(at),
                ..Opts::default()
            },
        );
        match got.ending {
            Some(Ending::Cancelled) => assert!(got.head.is_none()),
            Some(Ending::Abort(code, _)) => {
                assert_eq!(code, "cancelled");
                assert!(got.head.is_some());
            }
            Some(Ending::End) => {}
            other => panic!("{at}: {other:?}"),
        }
        assert!(
            want.starts_with(&got.body),
            "{at}: a prefix of the right bytes"
        );
    }
}

/// Credit stays within the reservation (the driver checks it at every
/// step: credit only for bytes received, none once a piece is cancelled,
/// and every open stream's room reserved) on an abort after a leaf fails,
/// and on a cancel mid-body, with a page that reads slowly so verified
/// bytes wait in the machine. A range's is step 3b-1's second part.
#[test]
fn credit_within_the_reservation_on_an_abort_and_a_cancel() {
    let store = Store::new(&load("dweb-verify.json"));
    let honest = World::honest(&store);
    let want = content("file-524288", 524_288);
    let slow = Opts {
        page: Some(4096),
        ..Opts::default()
    };
    // An abort: the sixth leaf flipped in the stream and in /chunks.
    let flipped = World {
        store: &store,
        extra: HashMap::new(),
        changes: vec![
            serde_json::json!({"piece": "bytes", "reference": FILE_512K, "flip": 20_487}),
        ],
    };
    let whole = plan(FILE_512K, "/", "", vec![]);
    let got = run("abort", &whole, Method::Get, &flipped, slow);
    assert_eq!(
        got.ending,
        Some(Ending::Abort(
            "verification_failed".to_owned(),
            fc_dweb::verifier::SWARM_VERIFICATION_FAILED.to_owned()
        ))
    );
    assert!(want[..20_480].starts_with(&got.body));
    // A cancel while the body streams.
    let got = run(
        "cancel",
        &whole,
        Method::Get,
        &honest,
        Opts {
            cancel_after: Some(60),
            ..slow
        },
    );
    assert!(
        matches!(got.ending, Some(Ending::Abort(ref c, _)) if c == "cancelled"),
        "{:?}",
        got.ending
    );
    assert!(want.starts_with(&got.body));
}

/// A page that reads slowly holds the node back: the machine credits a
/// stream only for bytes that have left it, so what it holds stays within
/// the stream's window and the body's.
#[test]
fn a_slow_page_backpressures_the_stream() {
    let store = Store::new(&load("dweb-verify.json"));
    let honest = World::honest(&store);
    let p = plan(FILE_512K, "/", "", vec![]);
    let got = run(
        "slow",
        &p,
        Method::Get,
        &honest,
        Opts {
            page: Some(512),
            ..Opts::default()
        },
    );
    assert_eq!(got.ending, Some(Ending::End));
    assert_eq!(got.body, content("file-524288", 524_288));
    assert_eq!(got.pieces.iter().filter(|r| r.stream).count(), 1);
    // The stream's window, a few chunk pieces and the tree: what waits for
    // the page is inside the window.
    assert!(got.peak <= STREAM_WINDOW + 32 * 1024, "{}", got.peak);
}

/// A stream that ends early, while the bytes it sent last wait for their
/// leaves' parent: those bytes are still checked and released once the
/// parent comes, and only then does the request end, at the bytes the
/// stream never sent. Bee's tree of 67,108,865 bytes, its second level-1
/// chunk held back, and the stream ending 5,000 bytes past it.
#[test]
fn bytes_stashed_before_an_early_end_are_still_used() {
    let doc = load("dweb-verify.json");
    let store = Store::new(&doc);
    let root = "d9c55a1a8dda7402193768ba15520a913290fd67788df01bf9b116f7e11e6452";
    // The root's first child, and its second: the level-1 chunk at 512 KiB.
    let child = |address: [u8; 32], len: u64, i: usize| {
        let wire = store.wire(&address, &HashMap::new()).unwrap();
        let chunk = fc_swarm::verify::Chunk {
            span: wire[..8].try_into().unwrap(),
            payload: &wire[8..],
        };
        tree::intermediate(&chunk, len).unwrap().child(i).unwrap()
    };
    let (l2, l2_len) = child(hex32(root), 67_108_865, 0);
    let (l1, _) = child(l2, l2_len, 1);
    let world = World {
        store: &store,
        extra: HashMap::new(),
        changes: vec![
            serde_json::json!({"piece": "bytes", "reference": root, "end_after": 524_288 + 5_000}),
        ],
    };
    let p = plan(root, "/", "", vec![]);
    let got = run(
        "stash",
        &p,
        Method::Get,
        &world,
        Opts {
            hold: Some(l1),
            ..Opts::default()
        },
    );
    assert_eq!(
        got.ending,
        Some(Ending::Abort(
            "piece_failed".to_owned(),
            fc_dweb::verifier::SWARM_STOPPED.to_owned()
        ))
    );
    // The stream opened and ended without the held chunk: nothing the walk
    // needed to start waited on it.
    assert_eq!(got.held_after, [1]);
    assert_eq!(got.body.len(), 524_288 + 4_096);
    assert!(content("file-67108865", 528_384) == got.body);
}
