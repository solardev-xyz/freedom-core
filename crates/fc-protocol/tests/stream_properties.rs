//! Property tests for design 0007's streams.
//!
//! **The pipe:** an honest service ([`Sender`]) and an honest main
//! ([`Receiver`]) joined by two byte pipes through the real codecs, under
//! random interleavings of producers, the writer, main's reader, consumers,
//! local cancels, credit and how the pipes cut the bytes. Whatever the
//! interleaving:
//! - no protocol error arises on either side;
//! - every request gets exactly one reply, and every stream at most one
//!   terminal, after its head;
//! - every byte a consumer pulls is the body's next byte, and a body that
//!   ends without a cancel or an abort is delivered whole;
//! - the bounds hold at every step: the writer's cap and storage, one ring
//!   of the window per stream in main, at most three control entries per
//!   live request, and every data frame either 64 KiB or all that was
//!   queued;
//! - once the producers and consumers run freely, everything settles and
//!   both sides hold nothing.
//!
//! **The decoder:** random stream frames decode the same in any chunking,
//! and random bytes never panic it and leave it failed for good.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;

use fc_protocol::frame::{Decoder, Frame, KIND_JSON, Kinds};
use fc_protocol::message::Message;
use fc_protocol::stream::{
    Abort, AbortCode, Cancel, Delivery, MAX_DATA, Receiver, Replied, Retire, SMALL_FRAME,
    SendError, Sender, Side, StreamFrame, WINDOW, Written, credit_frame,
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

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

/// Byte `k` of stream `id`'s body.
fn body(id: u64, offset: usize, len: usize) -> Vec<u8> {
    let start = usize::try_from((id % 251 + offset as u64 % 251) % 251).unwrap();
    (0..len).map(|i| ((start + i) % 251) as u8).collect()
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Answer {
    Body { len: usize, abort_at: Option<usize> },
    NoBody,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Outcome {
    Complete,
    Delivered,
    Aborted(AbortCode),
    /// Main cancelled it, and its record is gone.
    Retired,
}

#[derive(Debug)]
struct Req {
    id: u64,
    answer: Answer,
    // The service.
    admitted: bool,
    answered: bool,
    pushed: usize,
    stopped: bool,
    // Main.
    replies: usize,
    retired: bool,
    pulled: usize,
    outcome: Option<Outcome>,
}

struct Pipe {
    rng: Rng,
    sender: Sender,
    data_cap: usize,
    receiver: Receiver,
    reqs: Vec<Req>,
    next_request: usize,
    /// Main to the service, and the service to main.
    to_service: VecDeque<u8>,
    to_main: VecDeque<u8>,
    service_decoder: Decoder,
    main_decoder: Decoder,
    cancels: bool,
}

impl Pipe {
    fn new(seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        let data_cap = [WINDOW, 3 * WINDOW, 16 << 20][rng.below(3)];
        let count = 1 + rng.below(12);
        let reqs = (0..count)
            .map(|i| {
                let answer = match rng.below(10) {
                    0 => Answer::NoBody,
                    1 => Answer::Error,
                    _ => {
                        let len = match rng.below(4) {
                            0 => rng.below(10),
                            1 => rng.below(5000),
                            _ => rng.below(3 * WINDOW),
                        };
                        let abort_at = rng.chance(15).then(|| rng.below(len + 1));
                        Answer::Body { len, abort_at }
                    }
                };
                Req {
                    // IDs increase, with gaps: main's other requests.
                    id: 10 + 3 * i as u64,
                    answer,
                    admitted: false,
                    answered: false,
                    pushed: 0,
                    stopped: false,
                    replies: 0,
                    retired: false,
                    pulled: 0,
                    outcome: None,
                }
            })
            .collect();
        Pipe {
            rng,
            sender: Sender::with_data_cap(data_cap),
            data_cap,
            receiver: Receiver::new(),
            reqs,
            next_request: 0,
            to_service: VecDeque::new(),
            to_main: VecDeque::new(),
            service_decoder: Decoder::with_kinds(Kinds::service(Side::Sender)),
            main_decoder: Decoder::with_kinds(Kinds::service(Side::Receiver)),
            cancels: true,
        }
    }

    fn req(&mut self, id: u64) -> &mut Req {
        self.reqs.iter_mut().find(|r| r.id == id).unwrap()
    }

    fn send_json(&mut self, json: &str) {
        let mut out = Vec::new();
        fc_protocol::frame::encode_json(json.as_bytes(), &mut out).unwrap();
        self.to_service.extend(out);
    }

    // ---- main --------------------------------------------------------------

    /// Main sends its next request.
    fn send_request(&mut self) -> bool {
        let Some(req) = self.reqs.get(self.next_request) else {
            return false;
        };
        let id = req.id;
        self.next_request += 1;
        self.receiver.request(id).unwrap();
        self.send_json(&format!(
            r#"{{"type":"request","id":{id},"method":"ipfs.request","params":{{}},"context":{{"caller":"shell"}}}}"#
        ));
        true
    }

    /// Main reads up to `max` bytes the service wrote.
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
            let Message::Response { id, outcome } = Message::decode(&frame.payload).unwrap() else {
                panic!("the service sends responses only");
            };
            let (opens, cancelled) = match outcome {
                Ok(result) => (result.get().contains(r#""body":true"#), false),
                Err(error) => (
                    false,
                    error.parse().unwrap().code == fc_protocol::error::ErrorCode::Cancelled,
                ),
            };
            let replied = self.receiver.reply(id, opens).unwrap();
            let req = self.req(id);
            req.replies += 1;
            assert_eq!(req.replies, 1, "{id}: one reply");
            assert_eq!(replied == Replied::Retired, req.retired, "{id}");
            // Only main's cancel makes a `cancelled` reply.
            assert!(
                !cancelled || req.retired,
                "{id}: cancelled without a cancel"
            );
            if !opens {
                req.outcome = Some(if req.retired {
                    Outcome::Retired
                } else {
                    Outcome::Delivered
                });
            }
            return;
        }
        let frame = StreamFrame::from_frame(frame).unwrap();
        match self.receiver.receive(frame).unwrap() {
            Delivery::Data { .. } => {}
            Delivery::End { id, drained } => {
                if drained {
                    self.complete(id);
                }
            }
            Delivery::Abort { id, abort } => {
                let req = self.req(id);
                assert!(!req.retired);
                req.outcome = Some(Outcome::Aborted(abort.code));
            }
            Delivery::Dropped { id } => {
                let retiring = self.receiver.info(id).is_some();
                let req = self.req(id);
                assert!(req.retired, "{id}: dropped only while retiring");
                if !retiring {
                    req.outcome = Some(Outcome::Retired);
                }
            }
        }
    }

    fn complete(&mut self, id: u64) {
        let req = self.req(id);
        let Answer::Body { len, .. } = req.answer else {
            panic!("{id}: an end without a body");
        };
        assert_eq!(req.pulled, len, "{id}: every byte, once");
        req.outcome = Some(Outcome::Complete);
    }

    /// A consumer pulls from a random open stream.
    fn consume(&mut self, max: usize) -> bool {
        let open: Vec<u64> = self
            .reqs
            .iter()
            .filter(|r| r.outcome.is_none() && !r.retired)
            .map(|r| r.id)
            .filter(|id| {
                self.receiver
                    .info(*id)
                    .is_some_and(|info| info.buffered > 0)
            })
            .collect();
        if open.is_empty() {
            return false;
        }
        let id = open[self.rng.below(open.len())];
        let pulled = self.receiver.pull(id, max).unwrap();
        let req = self.req(id);
        assert_eq!(
            pulled.chunk,
            body(id, req.pulled, pulled.chunk.len()),
            "{id}"
        );
        req.pulled += pulled.chunk.len();
        if let Some(credit) = pulled.credit {
            assert_eq!(credit as usize, pulled.chunk.len());
            self.to_service.extend(credit_frame(id, credit).unwrap());
        }
        if pulled.eof {
            self.complete(id);
        }
        true
    }

    /// Main cancels a random request it holds.
    fn cancel(&mut self) -> bool {
        let held: Vec<u64> = self
            .reqs
            .iter()
            .filter(|r| self.receiver.info(r.id).is_some() && !r.retired)
            .map(|r| r.id)
            .collect();
        if held.is_empty() {
            return false;
        }
        let id = held[self.rng.below(held.len())];
        match self.receiver.cancel(id) {
            Retire::SendCancel => {
                self.req(id).retired = true;
                self.send_json(&format!(r#"{{"type":"cancel","id":{id}}}"#));
            }
            Retire::Freed => {
                let req = self.req(id);
                req.retired = true;
                req.outcome = Some(Outcome::Retired);
            }
            Retire::Nothing => panic!("{id}: a held request"),
        }
        true
    }

    // ---- the service ---------------------------------------------------------

    /// The service reads up to `max` bytes main wrote. Its reader never
    /// waits on the writer.
    fn service_reads(&mut self, max: usize) -> bool {
        let take = max.min(self.to_service.len());
        if take == 0 {
            return false;
        }
        let input: Vec<u8> = self.to_service.drain(..take).collect();
        let mut rest = &input[..];
        while !rest.is_empty() {
            let consumed = self.service_decoder.push(rest).unwrap();
            rest = &rest[consumed..];
            while let Some(frame) = self.service_decoder.pop() {
                self.service_takes(&frame);
            }
        }
        true
    }

    fn service_takes(&mut self, frame: &Frame) {
        if frame.kind != KIND_JSON {
            self.sender
                .receive(StreamFrame::from_frame(frame).unwrap())
                .unwrap();
            return;
        }
        match Message::decode(&frame.payload).unwrap() {
            Message::Request { id, .. } => {
                self.sender.request(id).unwrap();
                self.req(id).admitted = true;
            }
            Message::Cancel { id } => {
                if self.sender.cancel(id).unwrap() == Cancel::Cancelled {
                    self.req(id).stopped = true;
                }
            }
            other => panic!("{other:?}"),
        }
    }

    fn ready(&self) -> Vec<usize> {
        (0..self.reqs.len())
            .filter(|&i| self.reqs[i].admitted && !self.reqs[i].stopped)
            .collect()
    }

    /// A random producer does its next piece of work.
    fn produce(&mut self, max: usize) -> bool {
        let ready = self.ready();
        if ready.is_empty() {
            return false;
        }
        let i = ready[self.rng.below(ready.len())];
        self.produce_one(i, max)
    }

    /// Every producer does its next piece of work.
    fn produce_all(&mut self, max: usize) -> bool {
        let mut moved = false;
        for i in self.ready() {
            moved |= self.produce_one(i, max);
        }
        moved
    }

    /// Request `i`'s producer does its next piece of work, if it can.
    fn produce_one(&mut self, i: usize, max: usize) -> bool {
        let Req {
            id,
            answer,
            answered,
            pushed,
            ..
        } = self.reqs[i];
        let result = if !answered {
            let head = |body: bool| {
                format!(r#"{{"type":"response","id":{id},"result":{{"status":200,"headers":[],"body":{body}}}}}"#)
                    .into_bytes()
            };
            match answer {
                Answer::Body { .. } => self.sender.head(id, head(true), true),
                Answer::NoBody => self.sender.head(id, head(false), false),
                Answer::Error => self.sender.reply(
                    id,
                    format!(
                        r#"{{"type":"response","id":{id},"error":{{"code":"busy","message":"b"}}}}"#
                    )
                    .into_bytes(),
                ),
            }
            .map(|()| {
                self.reqs[i].answered = true;
                if !matches!(answer, Answer::Body { .. }) {
                    self.reqs[i].stopped = true;
                }
            })
        } else {
            let Answer::Body { len, abort_at } = answer else {
                unreachable!("stopped once answered");
            };
            if abort_at.is_some_and(|at| pushed >= at) {
                self.sender
                    .abort(id, &Abort::new(AbortCode::Internal, "panic"))
                    .map(|()| self.reqs[i].stopped = true)
            } else if pushed < len {
                let end = len.min(pushed + 1 + self.rng.below(max));
                let bytes = body(id, pushed, end - pushed);
                let before = self.sender.room(id);
                match self.sender.push(id, &bytes) {
                    Ok(taken) => {
                        // As much as the room allows, unless the writer's
                        // cap would cut it below 4 KiB.
                        let room = before.unwrap().min(bytes.len());
                        assert!(
                            taken == room
                                || (taken == 0 && room < SMALL_FRAME && room < bytes.len()),
                            "{id}: took {taken} of {room}"
                        );
                        self.reqs[i].pushed += taken;
                        if taken == 0 {
                            return false;
                        }
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            } else {
                self.sender.finish(id).map(|()| self.reqs[i].stopped = true)
            }
        };
        match result {
            Ok(()) => {}
            // A cancel settled it first.
            Err(SendError::Gone) => self.reqs[i].stopped = true,
            Err(error) => panic!("{id}: {error:?}"),
        }
        true
    }

    /// The writer writes up to `frames` frames.
    fn write(&mut self, frames: usize) -> bool {
        let mut wrote = false;
        for _ in 0..frames {
            let mut out = Vec::new();
            let Some(written) = self.sender.next_frame(&mut out) else {
                break;
            };
            wrote = true;
            if let Written::Data { id, len } = written {
                // Coalescing: as large as the queue and 64 KiB allow.
                assert!((1..=MAX_DATA).contains(&len));
                assert!(len == MAX_DATA || self.sender.queued(id) == Some(0));
            }
            self.to_main.extend(out);
        }
        wrote
    }

    // ---- both ------------------------------------------------------------------

    fn check_bounds(&self) {
        assert!(self.sender.held() <= self.data_cap);
        assert!(self.sender.held_capacity() <= self.sender.held() + self.sender.live() * (8 << 10));
        assert!(self.sender.control_entries() <= 3 * self.sender.live());
        assert!(self.sender.rotation_entries() <= self.sender.live());
        assert!(self.receiver.ring_bytes() <= self.receiver.outstanding() * WINDOW);
        for req in &self.reqs {
            if let Some(info) = self.receiver.info(req.id) {
                assert!(info.buffered <= WINDOW);
                assert!(info.received - info.returned <= WINDOW as u64);
            }
            if let Some(room) = self.sender.room(req.id) {
                assert!(room <= WINDOW);
            }
        }
    }

    fn step(&mut self) {
        let max = [1, 100, 5000, 70_000, 1 << 20][self.rng.below(5)];
        match self.rng.below(16) {
            0 => {
                self.send_request();
            }
            1..=3 => {
                self.produce(max);
            }
            4..=5 => {
                let frames = self.rng.below(6);
                self.write(frames);
            }
            6..=8 => {
                self.main_reads(max);
            }
            9..=11 => {
                self.consume(max);
            }
            12..=14 => {
                self.service_reads(max);
            }
            _ => {
                if self.cancels && self.rng.chance(20) {
                    self.cancel();
                }
            }
        }
        self.check_bounds();
    }

    /// Everything runs freely until nothing moves.
    fn settle(&mut self) {
        self.cancels = false;
        for round in 0.. {
            assert!(round < 100_000, "no progress");
            let moved = self.send_request()
                | self.service_reads(usize::MAX)
                | self.produce_all(1 << 20)
                | self.write(usize::MAX)
                | self.main_reads(usize::MAX)
                | self.consume(usize::MAX);
            self.check_bounds();
            if !moved {
                break;
            }
        }
        // Producers that found no room get none: they are done or stopped.
        assert!(self.reqs.iter().all(|r| r.stopped), "{:?}", self.reqs);
        assert_eq!(self.sender.live(), 0);
        assert_eq!(self.sender.held(), 0);
        assert_eq!(self.receiver.outstanding(), 0);
        assert!(self.to_main.is_empty() && self.to_service.is_empty());
        assert!(self.main_decoder.is_at_boundary() && self.service_decoder.is_at_boundary());
        for req in &self.reqs {
            assert_eq!(req.replies, 1, "{req:?}");
            let outcome = req.outcome.unwrap_or_else(|| panic!("{req:?}"));
            if req.retired {
                continue;
            }
            match (req.answer, outcome) {
                (Answer::Body { abort_at: None, .. }, Outcome::Complete) => {}
                (
                    Answer::Body {
                        abort_at: Some(_), ..
                    },
                    Outcome::Aborted(AbortCode::Internal),
                ) => {}
                (Answer::NoBody | Answer::Error, Outcome::Delivered) => {}
                other => panic!("{}: {other:?}", req.id),
            }
        }
    }
}

#[test]
fn honest_peers_through_the_pipe() {
    for seed in 1..=96 {
        let mut pipe = Pipe::new(seed);
        let steps = 200 + pipe.rng.below(3000);
        for _ in 0..steps {
            pipe.step();
        }
        pipe.settle();
    }
}

#[test]
fn honest_peers_without_cancels_deliver_every_body() {
    for seed in 1000..1032 {
        let mut pipe = Pipe::new(seed);
        pipe.cancels = false;
        for _ in 0..2000 {
            pipe.step();
        }
        pipe.settle();
        for req in &pipe.reqs {
            assert!(!req.retired);
        }
    }
}

// ---- the decoder ---------------------------------------------------------------

/// A random stream frame from the service.
fn random_frame(rng: &mut Rng, out: &mut Vec<u8>) {
    let id = 1 + rng.below(1 << 20) as u64;
    match rng.below(4) {
        0 => {
            let len = [1, 2, 4095, 4096, MAX_DATA][rng.below(5)].min(1 + rng.below(MAX_DATA));
            StreamFrame::Data {
                id,
                bytes: &body(id, 0, len),
            }
            .encode(out)
            .unwrap();
        }
        1 => StreamFrame::End { id }.encode(out).unwrap(),
        2 => StreamFrame::Abort {
            id,
            abort: Abort::new(AbortCode::BodyStreamError, "x".repeat(rng.below(900))),
        }
        .encode(out)
        .unwrap(),
        _ => fc_protocol::frame::encode_json(br#"{"type":"response","id":1,"result":{}}"#, out)
            .unwrap(),
    }
}

fn decode_all(input: &[u8], kinds: Kinds, rng: &mut Rng) -> Result<Vec<(u8, Vec<u8>)>, String> {
    let mut decoder = Decoder::with_kinds(kinds);
    let mut frames = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let piece = &rest[..rest.len().min(1 + rng.below(70_000))];
        let consumed = decoder.push(piece).map_err(|e| e.category().to_owned())?;
        rest = &rest[consumed..];
        while let Some(frame) = decoder.pop() {
            if frame.kind != KIND_JSON {
                StreamFrame::from_frame(&frame).map_err(|e| e.category().to_owned())?;
            }
            frames.push((frame.kind, frame.payload.to_vec()));
        }
    }
    if !decoder.is_at_boundary() {
        return Err("truncated".into());
    }
    Ok(frames)
}

#[test]
fn any_chunking_decodes_the_same() {
    let mut rng = Rng::new(7);
    for _ in 0..64 {
        let mut stream = Vec::new();
        for _ in 0..1 + rng.below(40) {
            random_frame(&mut rng, &mut stream);
        }
        let kinds = Kinds::service(Side::Receiver);
        let whole = decode_all(&stream, kinds, &mut Rng::new(1)).unwrap();
        for seed in 0..4 {
            let mut chunks = Rng::new(rng.next() ^ seed);
            assert_eq!(decode_all(&stream, kinds, &mut chunks).unwrap(), whole);
        }
        // A cut anywhere inside the last frame is a truncation.
        let cut = stream.len() - 1 - rng.below(4);
        assert_eq!(
            decode_all(&stream[..cut], kinds, &mut rng).unwrap_err(),
            "truncated"
        );
    }
}

#[test]
fn random_bytes_never_panic_and_failure_sticks() {
    let mut rng = Rng::new(11);
    for _ in 0..2000 {
        let side = [Side::Receiver, Side::Sender][rng.below(2)];
        let mut decoder = Decoder::with_kinds(Kinds::service(side));
        let len = rng.below(64);
        let mut input: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        // Mostly plausible headers: small lengths and stream kinds.
        if len >= 5 && rng.chance(80) {
            input[..4].copy_from_slice(&u32::try_from(rng.below(40)).unwrap().to_be_bytes());
            input[4] = 2 + rng.below(4) as u8;
        }
        let mut failed = None;
        for piece in input.chunks(1 + rng.below(8)) {
            match decoder.push(piece) {
                Ok(_) => {
                    while let Some(frame) = decoder.pop() {
                        let _ = StreamFrame::from_frame(&frame);
                    }
                }
                Err(error) => {
                    if let Some(first) = failed {
                        assert_eq!(error, first, "the first error sticks");
                    }
                    failed = Some(error);
                }
            }
        }
        if let Some(first) = failed {
            assert_eq!(decoder.push(&[0]), Err(first));
            assert!(decoder.pop().is_none());
        }
    }
}

#[test]
fn a_protocol_error_fails_each_side_for_good() {
    let mut sender = Sender::new();
    sender.request(5).unwrap();
    let overgrant = StreamFrame::Credit { id: 5, bytes: 1 };
    let error = sender.receive(overgrant.clone()).unwrap_err();
    assert_eq!(sender.request(6), Err(error));
    assert_eq!(sender.receive(overgrant), Err(error));
    assert_eq!(sender.head(5, b"{}".to_vec(), true), Err(SendError::Closed));
    assert_eq!(sender.next_frame(&mut Vec::new()), None);
    assert_eq!(sender.failed(), Some(error));

    let mut receiver = Receiver::new();
    receiver.request(5).unwrap();
    let error = receiver.receive(StreamFrame::End { id: 5 }).unwrap_err();
    assert_eq!(receiver.reply(5, true), Err(error));
    assert_eq!(receiver.outstanding(), 0, "every record goes");
    assert_eq!(receiver.failed(), Some(error));
}
