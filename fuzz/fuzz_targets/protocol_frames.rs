//! fc-protocol's receiving side, from the pipe's bytes up: the frame
//! decoder, fragment reassembly (design 0005) and stream frames (design
//! 0007), with every JSON message decoded as the core decodes it.
//!
//! The first byte picks the connection and how the rest is cut:
//! - `% 3`: a `freedom-cored` connection, or a service connection as main
//!   reads it (data, end, abort) or as the service reads it (credit);
//! - `/ 3 % 64 + 1`: the size of each read, so headers and payloads are
//!   split everywhere a pipe could split them.
//!
//! It checks, besides panics:
//! - the decoder takes input or yields a frame on every push, and no
//!   payload is over 1 MiB;
//! - main's rings never hold more than one window per stream;
//! - frames the service's sender writes decode on main's side.

#![no_main]

use std::collections::BTreeMap;

use fc_protocol::fragment::{Delivery, Reassembler};
use fc_protocol::frame::{self, Decoder, Frame, Kinds, MAX_PAYLOAD};
use fc_protocol::message::Message;
use fc_protocol::secret::{MAX_SECRET_BYTES, SecretBytes};
use fc_protocol::stream::{self, Receiver, Sender, Side, StreamFrame};
use libfuzzer_sys::fuzz_target;
use serde_json::value::RawValue;

/// Streams open on each side before the input arrives: requests 1 to 4.
const STREAMS: u64 = 4;
/// A window of body bytes for the sender to queue.
static BODY: [u8; stream::WINDOW] = [0x5a; stream::WINDOW];

fuzz_target!(|data: &[u8]| {
    let Some((&mode, input)) = data.split_first() else {
        return;
    };
    let side = match mode % 3 {
        0 => None,
        1 => Some(Side::Receiver),
        _ => Some(Side::Sender),
    };
    let kinds = side.map_or(Kinds::CORE, Kinds::service);
    let piece = usize::from(mode / 3) % 64 + 1;

    let mut connection = Connection::new(side);
    let mut decoder = Decoder::with_kinds(kinds);
    let mut rest = input;
    while !rest.is_empty() {
        let take = piece.min(rest.len());
        let Ok(consumed) = decoder.push(&rest[..take]) else {
            return;
        };
        rest = &rest[consumed..];
        let mut popped = false;
        while let Some(frame) = decoder.pop() {
            popped = true;
            assert!(frame.payload.len() <= MAX_PAYLOAD);
            if !connection.take(frame) {
                return;
            }
        }
        assert!(
            consumed > 0 || popped,
            "the decoder neither took input nor yielded a frame"
        );
    }
});

/// One connection's receiving state. Each `take` returns false once the
/// connection would be closed for a protocol error.
struct Connection {
    side: Option<Side>,
    reassembler: Reassembler,
    receiver: Receiver,
    sender: Sender,
    data_frames: u32,
}

impl Connection {
    fn new(side: Option<Side>) -> Self {
        let mut connection = Connection {
            side,
            reassembler: Reassembler::new(),
            receiver: Receiver::new(),
            sender: Sender::new(),
            data_frames: 0,
        };
        for id in 1..=STREAMS {
            match side {
                Some(Side::Receiver) => {
                    let receiver = &mut connection.receiver;
                    receiver
                        .request(id)
                        .expect("a fresh receiver takes request IDs");
                    receiver
                        .reply(id, true)
                        .expect("a pending request takes its head");
                }
                Some(Side::Sender) => {
                    let sender = &mut connection.sender;
                    sender
                        .request(id)
                        .expect("a fresh sender takes request IDs");
                    sender
                        .head(id, b"{}".to_vec(), true)
                        .expect("a fresh request takes its head");
                    // A full window, so credit has something to return.
                    connection.fill(id);
                }
                None => {}
            }
        }
        connection
    }

    fn take(&mut self, frame: Frame) -> bool {
        match (self.side, frame.kind) {
            (None, _) => self.take_core(frame),
            (Some(_), frame::KIND_JSON) => {
                decode_message(&frame.payload);
                true
            }
            (Some(Side::Receiver), _) => self.take_body(&frame),
            (Some(Side::Sender), _) => self.take_credit(&frame),
        }
    }

    /// A `freedom-cored` connection: whole messages and fragmented
    /// responses. A pending request is any odd ID.
    fn take_core(&mut self, frame: Frame) -> bool {
        match self.reassembler.push(frame, |id| id % 2 == 1) {
            Ok(Delivery::Message { frame, .. }) => decode_message(&frame.payload),
            Ok(Delivery::Response { payload, .. }) => {
                decode_message(&payload);
                // Handed to its consumer: the peer may begin again.
                self.reassembler.grant();
            }
            Ok(Delivery::Credit | Delivery::Taken) => {}
            Err(_) => return false,
        }
        true
    }

    /// Main's side of a service connection: data, end and abort.
    fn take_body(&mut self, frame: &Frame) -> bool {
        let Ok(decoded) = StreamFrame::from_frame(frame) else {
            return false;
        };
        match self.receiver.receive(decoded) {
            Ok(stream::Delivery::Data { id, .. }) => {
                // A consumer that reads every other chunk, so windows both
                // fill up and drain.
                self.data_frames += 1;
                if self.data_frames.is_multiple_of(2) {
                    let _ = self.receiver.pull(id, stream::MAX_PULL);
                }
            }
            Ok(_) => {}
            Err(_) => return false,
        }
        assert!(self.receiver.ring_bytes() <= STREAMS as usize * stream::WINDOW);
        for id in 1..=STREAMS {
            if let Some(info) = self.receiver.info(id) {
                assert!(info.buffered <= stream::WINDOW);
                assert!(info.returned <= info.received);
                assert!(info.received - info.returned <= stream::WINDOW as u64);
            }
        }
        true
    }

    /// The service's side: credit, which lets it queue and write more.
    fn take_credit(&mut self, frame: &Frame) -> bool {
        let Ok(decoded) = StreamFrame::from_frame(frame) else {
            return false;
        };
        match self.sender.receive(decoded) {
            Ok(stream::Credited::Taken(id)) => self.fill(id),
            Ok(_) => {}
            Err(_) => return false,
        }
        true
    }

    /// Queues as much of stream `id`'s body as its window and the writer
    /// allow, then writes everything queued, checking that main's side
    /// decodes it.
    fn fill(&mut self, id: u64) {
        if let Some(room) = self.sender.room(id) {
            let _ = self.sender.push(id, &BODY[..room.min(BODY.len())]);
        }
        assert!(self.sender.held() <= stream::WRITER_DATA_CAP);
        let mut main = Decoder::with_kinds(Kinds::service(Side::Receiver));
        let mut out = Vec::new();
        while self.sender.next_frame(&mut out).is_some() {
            let mut bytes = out.as_slice();
            while !bytes.is_empty() {
                let consumed = main
                    .push(bytes)
                    .expect("main decodes what the sender writes");
                bytes = &bytes[consumed..];
                let mut popped = false;
                while let Some(frame) = main.pop() {
                    popped = true;
                    if frame.kind != frame::KIND_JSON {
                        assert!(StreamFrame::from_frame(&frame).is_ok());
                    }
                }
                assert!(consumed > 0 || popped);
            }
            out.clear();
        }
        assert!(main.is_at_boundary(), "the sender wrote a partial frame");
    }
}

/// Decodes a message as the core does, and every member of its params,
/// result or data as a secret field would be.
fn decode_message(payload: &[u8]) {
    let Ok(message) = Message::decode(payload) else {
        return;
    };
    let members = match message {
        Message::Request {
            params: Some(raw), ..
        }
        | Message::Event {
            data: Some(raw), ..
        }
        | Message::Response {
            outcome: Ok(raw), ..
        } => raw,
        Message::Response {
            outcome: Err(error),
            ..
        } => {
            let _ = error.parse();
            return;
        }
        _ => return,
    };
    let Ok(members) = serde_json::from_str::<BTreeMap<String, &RawValue>>(members.get()) else {
        return;
    };
    for raw in members.values() {
        if let Ok(secret) = SecretBytes::from_raw(raw) {
            assert!(secret.as_bytes().len() <= MAX_SECRET_BYTES);
        }
    }
}
