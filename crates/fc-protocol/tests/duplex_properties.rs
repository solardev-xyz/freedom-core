//! Property tests for design 0009's streams in both directions on the
//! core's connection.
//!
//! An honest core ([`Duplex`]) and an honest main (a [`Receiver`] for the
//! bodies the core sends, a [`Sender`] for those it answers the core's
//! requests with) joined by two byte pipes through the real codecs, both at
//! protocol 2 ([`Kinds::CORE_STREAMS`]). Both sides number their requests
//! from the same values, so every stream ID names a stream in each
//! direction. Under random interleavings of requests, producers, writers,
//! readers and consumers on both sides, and how the pipes cut the bytes:
//! - no protocol error arises on either side;
//! - every request gets exactly one reply, and every body arrives whole and
//!   in order, in both directions;
//! - the core holds no ring: its consumers hold what they are given, and
//!   what they haven't released stays within the window;
//! - credit the core owes is one record per open stream at most, also while
//!   its writer isn't polled and streams end with credit unwritten;
//! - once everything runs freely, both sides settle and hold nothing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, VecDeque};

use fc_protocol::frame::{Decoder, Frame, KIND_JSON, Kinds};
use fc_protocol::message::Message;
use fc_protocol::stream::{
    Arrived, Delivery, Duplex, Received, Receiver, Replied, SendError, Sender, StreamFrame, WINDOW,
    Wrote, credit_frame,
};

/// xorshift64*: the same pseudo-random cases on every run.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }
}

/// Byte `k` of a body, by its direction and ID.
fn body(seed: u64, offset: usize, len: usize) -> Vec<u8> {
    let start = usize::try_from((seed % 251 + offset as u64 % 251) % 251).unwrap();
    (0..len).map(|i| ((start + i) % 251) as u8).collect()
}

/// A body's pattern seed: the core's bodies and main's differ for one ID.
fn seed(id: u64, from_core: bool) -> u64 {
    if from_core { id } else { id + 100 }
}

fn head(id: u64) -> Vec<u8> {
    format!(r#"{{"type":"response","id":{id},"result":{{"status":200,"headers":[],"body":true}}}}"#)
        .into_bytes()
}

fn request(id: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let json = format!(
        r#"{{"type":"request","id":{id},"method":"ipfs.request","params":{{}},"context":{{"caller":"shell"}}}}"#
    );
    fc_protocol::frame::encode_json(json.as_bytes(), &mut out).unwrap();
    out
}

/// One body, sent by one side in answer to the other's request.
#[derive(Debug, Default)]
struct Flow {
    len: usize,
    asked: bool,
    admitted: bool,
    headed: bool,
    pushed: usize,
    finished: bool,
    replied: bool,
    /// Bytes the consumer has, and those it still holds unreleased.
    got: usize,
    held: usize,
    complete: bool,
}

struct Pipe {
    rng: Rng,
    core: Duplex,
    /// Main: the bodies it receives (main's requests), and sends (the
    /// core's requests).
    receiver: Receiver,
    sender: Sender,
    /// By ID: main's requests (the core sends their bodies) and the core's
    /// (main sends theirs).
    mains: BTreeMap<u64, Flow>,
    cores: BTreeMap<u64, Flow>,
    to_core: VecDeque<u8>,
    to_main: VecDeque<u8>,
    core_decoder: Decoder,
    main_decoder: Decoder,
    /// Steps taken, and how many of the first the core's writer sits out.
    steps: usize,
    writer_held: usize,
}

impl Pipe {
    fn new(seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        let flows = |rng: &mut Rng| {
            let count = 1 + rng.below(6);
            (0..count)
                .map(|i| {
                    let len = match rng.below(3) {
                        0 => rng.below(10),
                        1 => rng.below(5000),
                        _ => rng.below(3 * WINDOW),
                    };
                    // The same IDs on both sides.
                    (
                        10 + 3 * i as u64,
                        Flow {
                            len,
                            ..Flow::default()
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        let mains = flows(&mut rng);
        let cores = flows(&mut rng);
        Pipe {
            rng,
            core: Duplex::new(),
            receiver: Receiver::new(),
            sender: Sender::new(),
            mains,
            cores,
            to_core: VecDeque::new(),
            to_main: VecDeque::new(),
            core_decoder: Decoder::with_kinds(Kinds::CORE_STREAMS),
            main_decoder: Decoder::with_kinds(Kinds::CORE_STREAMS),
            steps: 0,
            writer_held: 0,
        }
    }

    // ---- requests ----------------------------------------------------------

    fn main_asks(&mut self) -> bool {
        let Some((&id, flow)) = self.mains.iter_mut().find(|(_, f)| !f.asked) else {
            return false;
        };
        flow.asked = true;
        self.receiver.request(id).unwrap();
        self.to_core.extend(request(id));
        true
    }

    fn core_asks(&mut self) -> bool {
        let Some((&id, flow)) = self.cores.iter_mut().find(|(_, f)| !f.asked) else {
            return false;
        };
        flow.asked = true;
        self.core.ask(id).unwrap();
        self.to_main.extend(request(id));
        true
    }

    // ---- reading -----------------------------------------------------------

    fn core_reads(&mut self, max: usize) -> bool {
        let take = max.min(self.to_core.len());
        if take == 0 {
            return false;
        }
        let input: Vec<u8> = self.to_core.drain(..take).collect();
        let mut rest = &input[..];
        while !rest.is_empty() {
            let consumed = self.core_decoder.push(rest).unwrap();
            rest = &rest[consumed..];
            while let Some(frame) = self.core_decoder.pop() {
                self.core_takes(&frame);
            }
        }
        true
    }

    fn core_takes(&mut self, frame: &Frame) {
        if frame.kind == KIND_JSON {
            match Message::decode(&frame.payload).unwrap() {
                Message::Request { id, .. } => {
                    self.core.request(id).unwrap();
                    self.mains.get_mut(&id).unwrap().admitted = true;
                }
                Message::Response { id, .. } => {
                    assert_eq!(self.core.answered(id, true).unwrap(), Replied::Deliver);
                    let flow = self.cores.get_mut(&id).unwrap();
                    assert!(!flow.replied, "{id}: one reply");
                    flow.replied = true;
                }
                other => panic!("{other:?}"),
            }
            return;
        }
        let stream = StreamFrame::from_frame(frame).unwrap();
        let bytes = match &stream {
            StreamFrame::Data { bytes, .. } => bytes.to_vec(),
            _ => Vec::new(),
        };
        match self.core.receive(stream).unwrap() {
            Received::Credited(_) => {}
            Received::Arrived(Arrived::Data { id, len }) => {
                let flow = self.cores.get_mut(&id).unwrap();
                assert!(flow.replied, "{id}: no data before the head");
                assert_eq!(
                    bytes,
                    body(seed(id, false), flow.got, len),
                    "{id}: in order"
                );
                flow.got += len;
                flow.held += len;
                assert!(flow.held <= WINDOW, "{id}: within the window");
            }
            Received::Arrived(Arrived::End { id }) => {
                let flow = self.cores.get_mut(&id).unwrap();
                assert_eq!(flow.got, flow.len, "{id}: every byte, once");
                flow.complete = true;
            }
            other => panic!("{other:?}"),
        }
    }

    fn main_reads(&mut self, max: usize) -> bool {
        let take = max.min(self.to_main.len());
        if take == 0 {
            return false;
        }
        let input: Vec<u8> = self.to_main.drain(..take).collect();
        let mut rest = &input[..];
        while !rest.is_empty() {
            let consumed = self.main_decoder.push(rest).unwrap();
            rest = &rest[consumed..];
            while let Some(frame) = self.main_decoder.pop() {
                self.main_takes(&frame);
            }
        }
        true
    }

    fn main_takes(&mut self, frame: &Frame) {
        if frame.kind == KIND_JSON {
            match Message::decode(&frame.payload).unwrap() {
                Message::Request { id, .. } => {
                    self.sender.request(id).unwrap();
                    self.cores.get_mut(&id).unwrap().admitted = true;
                }
                Message::Response { id, .. } => {
                    assert_eq!(self.receiver.reply(id, true).unwrap(), Replied::Deliver);
                    let flow = self.mains.get_mut(&id).unwrap();
                    assert!(!flow.replied, "{id}: one reply");
                    flow.replied = true;
                }
                other => panic!("{other:?}"),
            }
            return;
        }
        // Main reads the core's connection by kind too: credit is for the
        // bodies it sends, the rest for those it receives.
        match StreamFrame::from_frame(frame).unwrap() {
            credit @ StreamFrame::Credit { .. } => {
                self.sender.receive(credit).unwrap();
            }
            stream => match self.receiver.receive(stream).unwrap() {
                Delivery::Data { .. } => {}
                Delivery::End { id, drained } => {
                    if drained {
                        let flow = self.mains.get_mut(&id).unwrap();
                        assert_eq!(flow.got, flow.len, "{id}");
                        flow.complete = true;
                    }
                }
                other => panic!("{other:?}"),
            },
        }
    }

    // ---- producers ---------------------------------------------------------

    /// A producer on `core`'s side, or main's, does its next piece of work.
    fn produce(&mut self, core: bool, max: usize) -> bool {
        let flows = if core { &self.mains } else { &self.cores };
        let ready: Vec<u64> = flows
            .iter()
            .filter(|(_, f)| f.admitted && !f.finished)
            .map(|(&id, _)| id)
            .collect();
        if ready.is_empty() {
            return false;
        }
        let id = ready[self.rng.below(ready.len())];
        let pick = self.rng.below(max) + 1;
        let (sender, flow) = if core {
            (self.core.sender_mut(), self.mains.get_mut(&id).unwrap())
        } else {
            (&mut self.sender, self.cores.get_mut(&id).unwrap())
        };
        if !flow.headed {
            sender.head(id, head(id), true).unwrap();
            flow.headed = true;
            return true;
        }
        if flow.pushed < flow.len {
            let end = flow.len.min(flow.pushed + pick);
            let bytes = body(seed(id, core), flow.pushed, end - flow.pushed);
            match sender.push(id, &bytes) {
                Ok(taken) => flow.pushed += taken,
                Err(SendError::Gone) => panic!("{id}: gone"),
                Err(error) => panic!("{id}: {error:?}"),
            }
            return true;
        }
        sender.finish(id).unwrap();
        flow.finished = true;
        true
    }

    // ---- writers -----------------------------------------------------------

    fn core_writes(&mut self, frames: usize) -> bool {
        let mut wrote = false;
        for _ in 0..frames {
            let mut out = Vec::new();
            match self.core.next_frame(&mut out) {
                None => break,
                Some(Wrote::Credit { .. } | Wrote::Sent(_)) => {}
            }
            wrote = true;
            self.to_main.extend(out);
        }
        wrote
    }

    fn main_writes(&mut self, frames: usize) -> bool {
        let mut wrote = false;
        for _ in 0..frames {
            let mut out = Vec::new();
            if self.sender.next_frame(&mut out).is_none() {
                break;
            }
            wrote = true;
            self.to_core.extend(out);
        }
        wrote
    }

    // ---- consumers ---------------------------------------------------------

    /// Main's consumer pulls from one of its streams, and credits the core.
    fn main_consumes(&mut self, max: usize) -> bool {
        let open: Vec<u64> = self
            .mains
            .keys()
            .copied()
            .filter(|id| self.receiver.info(*id).is_some_and(|i| i.buffered > 0))
            .collect();
        if open.is_empty() {
            return false;
        }
        let id = open[self.rng.below(open.len())];
        let pulled = self.receiver.pull(id, max).unwrap();
        let flow = self.mains.get_mut(&id).unwrap();
        assert_eq!(
            pulled.chunk,
            body(seed(id, true), flow.got, pulled.chunk.len()),
            "{id}"
        );
        flow.got += pulled.chunk.len();
        if let Some(credit) = pulled.credit {
            self.to_core.extend(credit_frame(id, credit).unwrap());
        }
        if pulled.eof {
            assert_eq!(flow.got, flow.len, "{id}");
            flow.complete = true;
        }
        true
    }

    /// The core's consumer lets go of some of what it holds.
    fn core_releases(&mut self, max: usize) -> bool {
        let holding: Vec<u64> = self
            .cores
            .iter()
            .filter(|(_, f)| f.held > 0)
            .map(|(&id, _)| id)
            .collect();
        if holding.is_empty() {
            return false;
        }
        let id = holding[self.rng.below(holding.len())];
        let flow = self.cores.get_mut(&id).unwrap();
        let n = flow.held.min(self.rng.below(max) + 1);
        flow.held -= n;
        self.core.release(id, n).unwrap();
        true
    }

    fn check_bounds(&self) {
        assert!(self.core.owed() <= self.core.inbound().outstanding());
        for (&id, flow) in &self.cores {
            if let Some(info) = self.core.inbound().info(id) {
                assert!(info.received - info.returned <= WINDOW as u64, "{id}");
                assert_eq!(info.received - info.returned, flow.held as u64, "{id}");
            }
        }
        assert!(self.receiver.ring_bytes() <= self.receiver.outstanding() * WINDOW);
        assert!(self.core.failed().is_none());
    }

    fn step(&mut self) {
        let max = [1, 100, 5000, 70_000, 1 << 20][self.rng.below(5)];
        let frames = self.rng.below(6);
        match self.rng.below(14) {
            0 => {
                self.main_asks();
            }
            1 => {
                self.core_asks();
            }
            2 | 3 => {
                self.produce(true, max);
            }
            4 | 5 => {
                self.produce(false, max);
            }
            6 => {
                if self.steps >= self.writer_held {
                    self.core_writes(frames);
                }
            }
            7 => {
                self.main_writes(frames);
            }
            8 | 9 => {
                self.core_reads(max);
            }
            10 | 11 => {
                self.main_reads(max);
            }
            12 => {
                self.main_consumes(max);
            }
            _ => {
                self.core_releases(max);
            }
        }
        self.steps += 1;
        self.check_bounds();
    }

    fn settle(&mut self) {
        for round in 0.. {
            assert!(round < 100_000, "no progress");
            let moved = self.main_asks()
                | self.core_asks()
                | self.produce(true, 1 << 20)
                | self.produce(false, 1 << 20)
                | self.core_writes(usize::MAX)
                | self.main_writes(usize::MAX)
                | self.core_reads(usize::MAX)
                | self.main_reads(usize::MAX)
                | self.main_consumes(usize::MAX)
                | self.core_releases(usize::MAX);
            self.check_bounds();
            if !moved {
                break;
            }
        }
        for (id, flow) in self.mains.iter().chain(&self.cores) {
            assert!(flow.replied && flow.complete, "{id}: {flow:?}");
        }
        assert_eq!(self.core.sender().live(), 0);
        assert_eq!(self.core.inbound().outstanding(), 0);
        assert_eq!(self.core.owed(), 0);
        assert_eq!(self.sender.live(), 0);
        assert_eq!(self.receiver.outstanding(), 0);
        assert!(self.to_main.is_empty() && self.to_core.is_empty());
        assert!(self.core_decoder.is_at_boundary() && self.main_decoder.is_at_boundary());
    }
}

#[test]
fn honest_peers_both_ways_through_one_connection() {
    for seed in 1..=96 {
        let mut pipe = Pipe::new(seed);
        let steps = 200 + pipe.rng.below(3000);
        // Every other run, the core's writer isn't polled until the end:
        // credit it owes piles up, and its streams end with it unwritten.
        pipe.writer_held = if seed % 2 == 0 { steps } else { 0 };
        for _ in 0..steps {
            pipe.step();
        }
        pipe.settle();
    }
}
