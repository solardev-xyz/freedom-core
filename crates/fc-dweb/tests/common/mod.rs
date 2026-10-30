//! What the verifier's tests share: the driver that plays main, the
//! hashing pool and the page around a `Verifier` against a world, checking
//! the machine's invariants after every step, and the vectors' helpers.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use base64::Engine as _;
use fc_dweb::Verify;
use fc_dweb::store::{FloorCheck, Store, Ticket};
use fc_dweb::verifier::{
    Head, Method, Options, Output, PieceFailure, PieceId, PieceRequest, REQUEST_BUDGET,
    STREAM_WINDOW, Verifier,
};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};

pub fn load(name: &str) -> Json {
    let path = format!("{}/../../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

pub fn b64(v: &Json) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str().unwrap())
        .unwrap()
}

/// content(seed, n): SHA-256(seed ‖ u64_be(i)), concatenated and cut.
pub fn content(seed: &str, n: usize) -> Vec<u8> {
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

/// The node a test's verifier reaches.
pub trait World {
    fn answer(&self, req: &PieceRequest) -> Answer;
}

/// What a piece's request gets.
pub enum Answer {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ending {
    End,
    Abort(String, String),
    Error(u16, String),
    Cancelled,
}

#[derive(Debug, Default)]
pub struct Run {
    pub head: Option<Head>,
    pub body: Vec<u8>,
    pub ending: Option<Ending>,
    pub pieces: Vec<PieceRequest>,
    pub jobs: usize,
    /// The most the request held or had reserved at once.
    pub peak: usize,
    /// For each answer held back: the streams open when it went out.
    pub held_after: Vec<usize>,
    /// Pieces the partition's cache answered, and chunks given back for it.
    pub cached: usize,
    pub remembered: usize,
    /// The driver's steps.
    pub steps: usize,
    /// The records held to the floor: their sequence, and the verdict.
    pub floors: Vec<(u64, FloorCheck)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// Each action in the order it was asked for.
    Fifo,
    /// The newest first: replies and results out of order.
    Lifo,
}

#[derive(Debug, Clone, Copy)]
pub struct Opts {
    pub budget: usize,
    pub order: Order,
    /// The page's credit per step, or all at once; `Some(0)`: a page that
    /// never reads, so the request stalls once the gateway is held back.
    pub page: Option<usize>,
    /// Cancel the request after this many steps.
    pub cancel_after: Option<usize>,
    /// Forget the request's partition after this many steps (with a store).
    pub forget_after: Option<usize>,
    /// A chunk whose answer main holds back until nothing else moves.
    pub hold: Option<[u8; 32]>,
    /// Whether the gateway serves ordered CARs.
    pub car: bool,
    /// The clock, for IPNS records.
    pub now: i64,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            budget: REQUEST_BUDGET,
            order: Order::Fifo,
            page: None,
            cancel_after: None,
            forget_after: None,
            hold: None,
            car: true,
            now: 0,
        }
    }
}

enum Action {
    Answer(PieceRequest),
    /// A whole piece the partition's cache answers.
    Cached(PieceId, Vec<u8>),
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

pub fn run(label: &str, plan: &Verify, method: Method, world: &dyn World, opts: Opts) -> Run {
    run_shared(label, plan, method, world, opts, None, None)
}

/// A request in `partition` (none: the profile's) with the dweb thread's
/// `store`: its `/chunks` pieces answered from the partition's cache when
/// it holds them, and the chunks its walk gives back kept there.
pub fn run_shared(
    label: &str,
    plan: &Verify,
    method: Method,
    world: &dyn World,
    opts: Opts,
    mut store: Option<&mut Store>,
    partition: Option<&str>,
) -> Run {
    let ticket: Option<Ticket> = store.as_deref_mut().map(|s| s.begin(partition));
    let mut v = Verifier::new(
        7,
        plan,
        method,
        partition,
        partition.is_some(),
        Options {
            budget: opts.budget,
            now: opts.now,
            car: opts.car,
        },
    )
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
                    let hit = match (store.as_deref_mut(), &ticket) {
                        (Some(s), Some(t)) => s.answer(t, &req),
                        _ => None,
                    };
                    match hit {
                        Some(wire) => {
                            out.cached += 1;
                            queue.push_back(Action::Cached(req.id, wire));
                        }
                        None => queue.push_back(Action::Answer(req)),
                    }
                }
                Output::Floor {
                    name,
                    sequence,
                    valid_until,
                } => {
                    // The dweb thread checks and raises the floor in one step.
                    let check = match (store.as_deref_mut(), &ticket) {
                        (Some(s), Some(t)) => s.floor(t, &name, sequence, valid_until, opts.now),
                        _ => FloorCheck::Accepted,
                    };
                    out.floors.push((sequence, check));
                    v.floor(check).unwrap();
                }
                Output::Remember { address, wire } => {
                    // Only a verified content-addressed chunk: never a
                    // single-owner one.
                    assert!(
                        fc_swarm::verify::check_chunk(&address, &wire).is_ok(),
                        "{label}: remembered a chunk that isn't its address's"
                    );
                    out.remembered += 1;
                    if let (Some(s), Some(t)) = (store.as_deref_mut(), &ticket) {
                        s.remember(t, address, wire);
                    }
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
            "{label}: reserved {} past the budget",
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
        out.steps = steps;
        if opts.cancel_after == Some(steps) {
            v.cancel();
            continue;
        }
        if opts.forget_after == Some(steps)
            && let Some(s) = store.as_deref_mut()
        {
            s.forget(partition);
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
            Action::Cached(id, wire) => {
                if cancelled_wholes.contains(&id) {
                    v.piece_failed(id, PieceFailure::Aborted).unwrap();
                    continue;
                }
                v.piece_whole(id, 200, vec![], wire).unwrap();
            }
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
                if owed_page > 0 && opts.page != Some(0) {
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
    if opts.page == Some(0) {
        // Stalled on the page: what it asked for is the test's question.
        return out;
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

pub fn end(out: &mut Run, e: Ending) {
    assert!(
        out.ending.is_none(),
        "two terminals: {:?} then {e:?}",
        out.ending
    );
    out.ending = Some(e);
}

pub enum Expected {
    Bytes(Vec<u8>),
    Digest(usize, String),
}

pub fn check_body(id: &str, got: &[u8], want: &Expected) {
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

pub fn pairs(v: &Json) -> Vec<(String, String)> {
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
