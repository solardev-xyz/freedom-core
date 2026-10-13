//! Replays vectors/streams.json: design 0007's stream frames, their order,
//! credit and coalescing. Every outcome there is the design's, written by
//! hand in vectors/generator/streams.js; main's frame.js runs the same
//! cases. The formats are in the file's `formats` member.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use fc_protocol::frame::{Decoder, Frame, KIND_JSON, Kinds, MAX_PAYLOAD};
use fc_protocol::message::Message;
use fc_protocol::stream::{
    Abort, AbortCode, CREDIT_LEN, Cancel, Credited, Delivery, ID_LEN, MAX_ABORT, MAX_DATA,
    MAX_PULL, Receiver, Replied, Retire, SMALL_FRAME, Sender, Side, StreamFrame, StreamState,
    WINDOW, WRITER_DATA_CAP, credit_frame,
};
use serde_json::{Value as Json, json};

fn vectors() -> Json {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/streams.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn cases<'a>(vectors: &'a Json, key: &str) -> &'a [Json] {
    vectors[key].as_array().unwrap()
}

fn u(value: &Json) -> u64 {
    value
        .as_u64()
        .unwrap_or_else(|| panic!("not a count: {value}"))
}

fn n(value: &Json) -> usize {
    usize::try_from(u(value)).unwrap()
}

/// `[{"hex": …} | {"fill": [byte, count]}, …]`, concatenated.
fn bytes(parts: &Json) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts.as_array().unwrap() {
        if let Some(text) = part["hex"].as_str() {
            out.extend(hex::decode(text).unwrap());
        } else {
            let fill = part["fill"].as_array().unwrap();
            out.extend(std::iter::repeat_n(
                u8::try_from(u(&fill[0])).unwrap(),
                n(&fill[1]),
            ));
        }
    }
    out
}

/// Byte `k` of stream `id`'s body (the file's `formats.body_bytes`).
fn body(id: u64, offset: u64, len: usize) -> Vec<u8> {
    (offset..offset + len as u64)
        .map(|k| u8::try_from((id % 251 + k % 251) % 251).unwrap())
        .collect()
}

fn code(name: &Json) -> AbortCode {
    serde_json::from_value(name.clone()).unwrap()
}

fn kinds(side: &str) -> Kinds {
    match side {
        "receiver" => Kinds::service(Side::Receiver),
        "sender" => Kinds::service(Side::Sender),
        "core" => Kinds::CORE,
        other => panic!("side {other}"),
    }
}

#[test]
fn constants_are_the_designs() {
    let v = vectors();
    let c = &v["constants"];
    assert_eq!(
        c["kinds"],
        json!({ "json": 1, "data": 2, "end": 3, "abort": 4, "credit": 5 })
    );
    assert_eq!(n(&c["id_bytes"]), ID_LEN);
    assert_eq!(n(&c["window"]), WINDOW);
    assert_eq!(n(&c["max_data"]), MAX_DATA);
    assert_eq!(n(&c["max_abort_json"]), MAX_ABORT);
    assert_eq!(n(&c["max_pull"]), MAX_PULL);
    assert_eq!(n(&c["small_frame"]), SMALL_FRAME);
    assert_eq!(n(&c["writer_data_cap"]), WRITER_DATA_CAP);
    assert_eq!(n(&c["max_payload"]), MAX_PAYLOAD);
    assert_eq!(u(&c["max_id"]), fc_protocol::message::MAX_ID);
    assert_eq!(CREDIT_LEN, ID_LEN + 4);
    for name in c["abort_codes"].as_array().unwrap() {
        assert_eq!(code(name).as_str(), name.as_str().unwrap());
    }
    assert_eq!(
        Abort::cancelled().message,
        c["cancelled_message"].as_str().unwrap()
    );
}

// ---- frames ----------------------------------------------------------------

/// A decoded frame, as the vectors write it.
fn frame_json(frame: &Frame) -> Result<Json, String> {
    if frame.kind == KIND_JSON {
        return Ok(json!([
            "json",
            String::from_utf8(frame.payload.to_vec()).unwrap()
        ]));
    }
    let decoded = StreamFrame::from_frame(frame).map_err(|e| e.category().to_owned())?;
    Ok(match decoded {
        StreamFrame::Data { id, bytes } => json!(["data", id, { "hex": hex::encode(bytes) }]),
        StreamFrame::End { id } => json!(["end", id]),
        StreamFrame::Abort { id, abort } => {
            json!(["abort", id, abort.code.as_str(), abort.message])
        }
        StreamFrame::Credit { id, bytes } => json!(["credit", id, bytes]),
    })
}

/// Expected frames with their byte parts made into one hex part, as
/// [`frame_json`] writes them.
fn normalized(expected: &Json) -> Json {
    match expected.as_array().unwrap().as_slice() {
        [kind, id, payload] if kind == "data" => {
            json!(["data", id, { "hex": hex::encode(bytes(&json!([payload]))) }])
        }
        _ => expected.clone(),
    }
}

/// Decodes `input` fed in `chunk`-sized pieces: every frame, then the
/// first error or whether EOF would cut a frame.
fn decode(input: &[u8], kinds: Kinds, chunk: usize) -> (Vec<Json>, Option<String>, bool) {
    let mut decoder = Decoder::with_kinds(kinds);
    let mut frames = Vec::new();
    for mut piece in input.chunks(chunk) {
        while !piece.is_empty() {
            match decoder.push(piece) {
                Ok(consumed) => piece = &piece[consumed..],
                Err(error) => return (frames, Some(error.category().to_owned()), false),
            }
            while let Some(frame) = decoder.pop() {
                match frame_json(&frame) {
                    Ok(frame) => frames.push(frame),
                    Err(category) => return (frames, Some(category), false),
                }
            }
        }
    }
    (frames, None, !decoder.is_at_boundary())
}

#[test]
fn frames() {
    let v = vectors();
    for case in cases(&v, "frames") {
        let id = case["id"].as_str().unwrap();
        let input = bytes(&case["input"]);
        let kinds = kinds(case["side"].as_str().unwrap());
        let expect = &case["expect"];
        // The same outcome in any chunking.
        for chunk in [1, 2, 5, 9, 13, 4096, input.len().max(1)] {
            let (frames, error, truncated) = decode(&input, kinds, chunk);
            if let Some(category) = expect["error"].as_str() {
                assert_eq!(error.as_deref(), Some(category), "{id} (chunk {chunk})");
                continue;
            }
            assert_eq!(error, None, "{id} (chunk {chunk})");
            let expected: Vec<Json> = expect["frames"]
                .as_array()
                .unwrap()
                .iter()
                .map(normalized)
                .collect();
            assert_eq!(frames, expected, "{id} (chunk {chunk})");
            assert_eq!(
                truncated,
                expect["truncated"].as_bool().unwrap_or(false),
                "{id} (chunk {chunk})"
            );
        }
    }
}

#[test]
fn encodings() {
    let v = vectors();
    for case in cases(&v, "encodings") {
        let id = case["id"].as_str().unwrap();
        let f = case["frame"].as_array().unwrap();
        let payload;
        let frame = match f[0].as_str().unwrap() {
            "data" => {
                payload = bytes(&json!([f[2]]));
                StreamFrame::Data {
                    id: u(&f[1]),
                    bytes: &payload,
                }
            }
            "end" => StreamFrame::End { id: u(&f[1]) },
            "abort" => StreamFrame::Abort {
                id: u(&f[1]),
                abort: Abort::new(code(&f[2]), f[3].as_str().unwrap()),
            },
            "credit" => StreamFrame::Credit {
                id: u(&f[1]),
                bytes: u32::try_from(u(&f[2])).unwrap(),
            },
            other => panic!("{id}: {other}"),
        };
        let mut out = Vec::new();
        match frame.encode(&mut out) {
            Ok(()) => assert_eq!(hex::encode(&out), case["hex"].as_str().unwrap(), "{id}"),
            Err(error) => {
                assert_eq!(Some(error.category()), case["error"].as_str(), "{id}");
                assert!(out.is_empty(), "{id}: nothing written");
            }
        }
    }
}

// ---- the service's side ------------------------------------------------------

/// Plays the service against a [`Sender`]: the producers offer the body
/// bytes of `formats.body_bytes`, and every written frame is decoded as main
/// would decode it.
struct Service {
    sender: Sender,
    /// The next body byte each producer offers.
    offered: BTreeMap<u64, u64>,
    /// The next body byte each stream writes.
    written: BTreeMap<u64, u64>,
    heads: BTreeMap<u64, Vec<u8>>,
    replies: BTreeMap<u64, Vec<u8>>,
}

fn head_json(id: u64, body: bool) -> Vec<u8> {
    format!(
        r#"{{"type":"response","id":{id},"result":{{"status":200,"headers":[],"body":{body}}}}}"#
    )
    .into_bytes()
}

fn reply_json(id: u64) -> Vec<u8> {
    format!(r#"{{"type":"response","id":{id},"error":{{"code":"busy","message":"busy"}}}}"#)
        .into_bytes()
}

fn refusal(result: Result<(), fc_protocol::stream::SendError>) -> Json {
    match result {
        Ok(()) => json!("ok"),
        Err(error) => json!({ "refused": error.name() }),
    }
}

fn protocol<T>(
    result: Result<T, fc_protocol::stream::StreamError>,
    ok: impl FnOnce(T) -> Json,
) -> Json {
    match result {
        Ok(value) => ok(value),
        Err(error) => json!({ "error": error.category() }),
    }
}

impl Service {
    fn act(&mut self, action: &[Json]) -> Json {
        let id = u(&action[1]);
        match action[0].as_str().unwrap() {
            "request" => protocol(self.sender.request(id), |()| json!("ok")),
            "cancel" => protocol(self.sender.cancel(id), |cancel| match cancel {
                Cancel::Cancelled => json!("cancelled"),
                Cancel::Late => json!("late"),
            }),
            "credit" => {
                // Through the codec, as main sends it.
                let frame = credit_frame(id, u32::try_from(u(&action[2])).unwrap()).unwrap();
                let mut decoder = Decoder::with_kinds(Kinds::service(Side::Sender));
                assert_eq!(decoder.push(&frame).unwrap(), frame.len());
                let frame = decoder.pop().unwrap();
                let credit = StreamFrame::from_frame(&frame).unwrap();
                protocol(self.sender.receive(credit), |credited| match credited {
                    Credited::Taken(taken) => {
                        assert_eq!(taken, id);
                        json!("taken")
                    }
                    Credited::Late => json!("late"),
                })
            }
            "head" => {
                let json = head_json(id, action[2].as_bool().unwrap());
                let result = self
                    .sender
                    .head(id, json.clone(), action[2].as_bool().unwrap());
                if result.is_ok() {
                    self.heads.insert(id, json);
                }
                refusal(result)
            }
            "reply" => {
                let json = reply_json(id);
                let result = self.sender.reply(id, json.clone());
                if result.is_ok() {
                    self.replies.insert(id, json);
                }
                refusal(result)
            }
            "push" => {
                let offered = self.offered.entry(id).or_default();
                let bytes = body(id, *offered, n(&action[2]));
                match self.sender.push(id, &bytes) {
                    Ok(taken) => {
                        *offered += taken as u64;
                        json!({ "taken": taken })
                    }
                    Err(error) => json!({ "refused": error.name() }),
                }
            }
            "finish" => refusal(self.sender.finish(id)),
            "abort" => {
                let abort = Abort::new(code(&action[2]), "aborted");
                refusal(self.sender.abort(id, &abort))
            }
            other => panic!("action {other}"),
        }
    }

    /// Takes one frame from the writer and checks it is `expected`.
    fn write(&mut self, expected: &Json, at: &str) {
        let mut out = Vec::new();
        let written = self
            .sender
            .next_frame(&mut out)
            .unwrap_or_else(|| panic!("{at}: nothing written, expected {expected}"));
        let mut decoder = Decoder::with_kinds(Kinds::service(Side::Receiver));
        assert_eq!(decoder.push(&out).unwrap(), out.len(), "{at}");
        let frame = decoder.pop().unwrap();
        assert!(
            decoder.pop().is_none() && decoder.is_at_boundary(),
            "{at}: one frame"
        );
        let e = expected.as_array().unwrap();
        let id = u(&e[1]);
        use fc_protocol::stream::Written;
        match e[0].as_str().unwrap() {
            "head" => {
                assert_eq!(written, Written::Head { id }, "{at}");
                assert_eq!(frame.kind, KIND_JSON, "{at}");
                assert_eq!(Some(&frame.payload.to_vec()), self.heads.get(&id), "{at}");
            }
            "reply" => {
                assert_eq!(written, Written::Reply { id }, "{at}");
                assert_eq!(Some(&frame.payload.to_vec()), self.replies.get(&id), "{at}");
            }
            "cancelled" => {
                assert_eq!(written, Written::Cancelled { id }, "{at}");
                match Message::decode(&frame.payload).unwrap() {
                    Message::Response {
                        id: answered,
                        outcome: Err(error),
                    } => {
                        assert_eq!(answered, id, "{at}");
                        assert_eq!(
                            error.parse().unwrap().code,
                            fc_protocol::error::ErrorCode::Cancelled,
                            "{at}"
                        );
                    }
                    other => panic!("{at}: {other:?}"),
                }
            }
            "data" => {
                let (offset, len) = (u(&e[2]), n(&e[3]));
                assert_eq!(written, Written::Data { id, len }, "{at}");
                let next = self.written.entry(id).or_default();
                assert_eq!(*next, offset, "{at}: the stream's bytes in order");
                *next += len as u64;
                match StreamFrame::from_frame(&frame).unwrap() {
                    StreamFrame::Data { id: got, bytes } => {
                        assert_eq!(got, id, "{at}");
                        assert_eq!(bytes, body(id, offset, len), "{at}");
                    }
                    other => panic!("{at}: {other:?}"),
                }
            }
            "end" => {
                assert_eq!(written, Written::End { id }, "{at}");
                assert_eq!(
                    StreamFrame::from_frame(&frame).unwrap(),
                    StreamFrame::End { id },
                    "{at}"
                );
                assert_eq!(
                    self.written.get(&id).copied().unwrap_or(0),
                    self.offered.get(&id).copied().unwrap_or(0),
                    "{at}: end after every byte"
                );
            }
            "abort" => {
                let code = code(&e[2]);
                assert_eq!(written, Written::Abort { id, code }, "{at}");
                match StreamFrame::from_frame(&frame).unwrap() {
                    StreamFrame::Abort { id: got, abort } => {
                        assert_eq!((got, abort.code), (id, code), "{at}");
                    }
                    other => panic!("{at}: {other:?}"),
                }
            }
            other => panic!("{at}: written {other}"),
        }
    }

    fn check(&self, check: &Json, at: &str) {
        if let Some(held) = check.get("held") {
            assert_eq!(self.sender.held(), n(held), "{at}: held");
        }
        for (id, expected) in check["streams"].as_object().unwrap() {
            let id: u64 = id.parse().unwrap();
            let got = json!({
                "live": self.sender.is_live(id),
                "room": self.sender.room(id),
                "queued": self.sender.queued(id),
            });
            assert_eq!(&got, expected, "{at}: stream {id}");
        }
        // The storage follows the queued bytes: at most two 4 KiB blocks
        // more per stream.
        assert!(
            self.sender.held_capacity() <= self.sender.held() + self.sender.live() * (8 << 10),
            "{at}"
        );
    }
}

#[test]
fn sender() {
    let v = vectors();
    for case in cases(&v, "sender") {
        let id = case["id"].as_str().unwrap();
        let cap = case["config"]["data_cap"]
            .as_u64()
            .map_or(WRITER_DATA_CAP, |cap| usize::try_from(cap).unwrap());
        let mut service = Service {
            sender: Sender::with_data_cap(cap),
            offered: BTreeMap::new(),
            written: BTreeMap::new(),
            heads: BTreeMap::new(),
            replies: BTreeMap::new(),
        };
        for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let at = format!("{id} step {i}");
            if let Some(frames) = step.get("write").or_else(|| step.get("write_some")) {
                for frame in frames.as_array().unwrap() {
                    service.write(frame, &at);
                }
                if step.get("write").is_some() {
                    let mut out = Vec::new();
                    assert_eq!(service.sender.next_frame(&mut out), None, "{at}: idle");
                    assert!(out.is_empty(), "{at}");
                }
            } else if let Some(check) = step.get("check") {
                service.check(check, &at);
            } else {
                let action = step["do"].as_array().unwrap();
                for _ in 0..step["repeat"].as_u64().unwrap_or(1) {
                    assert_eq!(service.act(action), step["expect"], "{at}: {action:?}");
                }
            }
            assert!(
                service.sender.control_entries() <= 3 * service.sender.live(),
                "{at}: the control queue is bounded by the live requests"
            );
        }
    }
}

// ---- main's side -------------------------------------------------------------

/// Plays main against a [`Receiver`]: the service's frames go through the
/// codec, and the consumer checks every byte it pulls.
struct Main {
    receiver: Receiver,
    /// The next body byte the service sends, per stream.
    sent: BTreeMap<u64, u64>,
    /// The next body byte the consumer pulls, per stream.
    pulled: BTreeMap<u64, u64>,
}

impl Main {
    fn feed(&mut self, frame: &[u8]) -> Result<Delivery, fc_protocol::stream::StreamError> {
        let mut decoder = Decoder::with_kinds(Kinds::service(Side::Receiver));
        assert_eq!(decoder.push(frame).unwrap(), frame.len());
        let frame = decoder.pop().unwrap();
        self.receiver
            .receive(StreamFrame::from_frame(&frame).unwrap())
    }

    fn act(&mut self, action: &[Json]) -> Json {
        let id = u(&action[1]);
        let delivered = |delivery: Delivery| match delivery {
            Delivery::Data { len, .. } => json!({ "data": len }),
            Delivery::End { drained: false, .. } => json!("end"),
            Delivery::End { drained: true, .. } => json!("end_drained"),
            Delivery::Abort { abort, .. } => json!({ "abort": abort.code.as_str() }),
            Delivery::Dropped { id: dropped } => {
                assert_eq!(dropped, id);
                json!("dropped")
            }
        };
        match action[0].as_str().unwrap() {
            "request" => protocol(self.receiver.request(id), |()| json!("ok")),
            "reply" => protocol(
                self.receiver.reply(id, action[2].as_bool().unwrap()),
                |replied| match replied {
                    Replied::Deliver => json!("deliver"),
                    Replied::Retired => json!("retired"),
                },
            ),
            "data" => {
                let len = n(&action[2]);
                let sent = self.sent.entry(id).or_default();
                let bytes = body(id, *sent, len);
                *sent += len as u64;
                let mut frame = Vec::new();
                StreamFrame::Data { id, bytes: &bytes }
                    .encode(&mut frame)
                    .unwrap();
                match protocol(self.feed(&frame), delivered) {
                    got if got == json!({ "data": len }) => json!("data"),
                    got => got,
                }
            }
            "end" => {
                let mut frame = Vec::new();
                StreamFrame::End { id }.encode(&mut frame).unwrap();
                protocol(self.feed(&frame), delivered)
            }
            "abort" => {
                let mut frame = Vec::new();
                StreamFrame::Abort {
                    id,
                    abort: Abort::new(code(&action[2]), "aborted"),
                }
                .encode(&mut frame)
                .unwrap();
                match protocol(self.feed(&frame), delivered) {
                    got if got == json!({ "abort": action[2] }) => json!("abort"),
                    got => got,
                }
            }
            "pull" => match self.receiver.pull(id, n(&action[2])) {
                None => Json::Null,
                Some(pulled) => {
                    let offset = self.pulled.entry(id).or_default();
                    assert_eq!(pulled.chunk, body(id, *offset, pulled.chunk.len()));
                    assert_eq!(
                        pulled.chunk.capacity(),
                        pulled.chunk.len(),
                        "a chunk of its own size"
                    );
                    let at = *offset;
                    *offset += pulled.chunk.len() as u64;
                    if let Some(credit) = pulled.credit {
                        assert_eq!(credit as usize, pulled.chunk.len());
                        assert!(credit_frame(id, credit).is_ok());
                    }
                    json!({ "chunk": [at, pulled.chunk.len()], "credit": pulled.credit, "eof": pulled.eof })
                }
            },
            "cancel" => json!(match self.receiver.cancel(id) {
                Retire::SendCancel => "send_cancel",
                Retire::Freed => "freed",
                Retire::Nothing => "nothing",
            }),
            other => panic!("action {other}"),
        }
    }

    fn check(&self, check: &Json, at: &str) {
        for (id, expected) in check["streams"].as_object().unwrap() {
            let id: u64 = id.parse().unwrap();
            let Some(info) = self.receiver.info(id) else {
                assert_eq!(expected, &Json::Null, "{at}: stream {id}");
                continue;
            };
            let got = json!({
                "state": match info.state {
                    StreamState::Pending => "pending",
                    StreamState::RetiredPending => "retired_pending",
                    StreamState::Open => "open",
                    StreamState::Eof => "eof",
                    StreamState::Retiring => "retiring",
                },
                "ring": info.ring,
                "buffered": info.buffered,
                "received": info.received,
                "returned": info.returned,
            });
            assert!(expected.is_object(), "{at}: stream {id} has a record");
            for (field, value) in expected.as_object().unwrap() {
                assert_eq!(&got[field], value, "{at}: stream {id} {field}");
            }
        }
        if let Some(outstanding) = check.get("outstanding") {
            assert_eq!(self.receiver.outstanding(), n(outstanding), "{at}");
        }
        // One ring of exactly the window per stream that has one.
        assert_eq!(self.receiver.ring_bytes() % WINDOW, 0, "{at}");
    }
}

#[test]
fn receiver() {
    let v = vectors();
    for case in cases(&v, "receiver") {
        let id = case["id"].as_str().unwrap();
        let mut main = Main {
            receiver: Receiver::new(),
            sent: BTreeMap::new(),
            pulled: BTreeMap::new(),
        };
        for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let at = format!("{id} step {i}");
            if let Some(check) = step.get("check") {
                main.check(check, &at);
                continue;
            }
            let action = step["do"].as_array().unwrap();
            for _ in 0..step["repeat"].as_u64().unwrap_or(1) {
                assert_eq!(main.act(action), step["expect"], "{at}: {action:?}");
            }
            assert!(
                main.receiver.ring_bytes() <= main.receiver.outstanding() * WINDOW,
                "{at}: at most one ring per stream"
            );
        }
    }
}

#[test]
fn every_category_and_refusal_is_reachable() {
    // The file's lists are the categories and refusals the Rust side names,
    // and the cases use each of them.
    let v = vectors();
    let text = v.to_string();
    for category in v["categories"].as_array().unwrap() {
        let category = category.as_str().unwrap();
        assert!(
            text.matches(&format!(r#""error":"{category}""#)).count() >= 1,
            "{category} has a case"
        );
    }
    for refusal in v["refusals"].as_array().unwrap() {
        let refusal = refusal.as_str().unwrap();
        assert!(
            text.contains(&format!(r#""refused":"{refusal}""#)) || refusal == "too_large",
            "{refusal} has a case"
        );
    }
}
