//! Round trips, generated (design 0001, Testing: `proptest` round trips).
//! What each encoder writes, its decoder reads back as it was, whatever the
//! input and however the pipe cuts the bytes:
//!
//! - **frames:** whole messages and bulk credit, through the decoder;
//! - **fragmented responses** (design 0005): a response of up to three
//!   fragments, with whole messages between them, through the decoder and
//!   the reassembler; and the begin's header alone;
//! - **message envelopes:** requests, results, errors and events, as
//!   [`Message::decode`] reads them;
//! - **secret fields:** a [`SecretResponse`], base64 and hex fields beside
//!   public ones, in one exactly sized buffer, read back with
//!   [`SecretBytes::from_raw`].
//!
//! Stream frames (design 0007) have their own in `stream_properties.rs`.
//! The cases are bounded so the suite stays quick: the fragment property
//! runs a handful of cases of up to 2 MiB each.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::fragment::{self, Begin, Delivery, Reassembler, Splitter};
use fc_protocol::frame::{self, Decoder, Frame, KIND_CREDIT, KIND_JSON, MAX_PAYLOAD};
use fc_protocol::message::{
    self, Context, MAX_ID, Message, write_error, write_event, write_request, write_result,
};
use fc_protocol::secret::{SecretBytes, SecretResponse};
use proptest::prelude::*;
use serde_json::Value;
use serde_json::value::RawValue;

/// Pushes `bytes` into `decoder` in pieces of the sizes `cuts` gives, in
/// turn, popping frames as the decoder asks (backpressure), and returns
/// every frame in order.
fn decode_in_pieces(decoder: &mut Decoder, bytes: &[u8], cuts: &[usize]) -> Vec<Frame> {
    let mut frames = Vec::new();
    let mut at = 0;
    let mut cut = cuts.iter().cycle();
    while at < bytes.len() {
        let end = bytes.len().min(at + *cut.next().unwrap());
        let mut piece = &bytes[at..end];
        while !piece.is_empty() {
            let taken = decoder.push(piece).unwrap();
            piece = &piece[taken..];
            while let Some(frame) = decoder.pop() {
                frames.push(frame);
            }
        }
        at = end;
    }
    assert!(decoder.is_at_boundary());
    frames
}

fn id() -> impl Strategy<Value = u64> {
    1..=MAX_ID
}

/// JSON values of a few levels: what params, results and event data carry.
fn json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<u32>().prop_map(|n| Value::from(f64::from(n) / 8.0)),
        ".{0,24}".prop_map(Value::String),
    ];
    leaf.prop_recursive(3, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map("[a-z_]{1,12}", inner, 0..6)
                .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
}

fn object() -> impl Strategy<Value = Value> {
    prop::collection::btree_map("[a-z_]{1,12}", json(), 0..6)
        .prop_map(|map| Value::Object(map.into_iter().collect()))
}

fn error_code() -> impl Strategy<Value = ErrorCode> {
    prop_oneof![
        Just(ErrorCode::VaultLocked),
        Just(ErrorCode::IncorrectPassword),
        Just(ErrorCode::InvalidArgument),
        Just(ErrorCode::Storage),
        Just(ErrorCode::Internal),
    ]
}

fn parsed(raw: &RawValue) -> Value {
    serde_json::from_str(raw.get()).unwrap()
}

/// `cases` per property, and no regression files written into the tree: a
/// failure prints its minimal input, which a test can then pin.
fn config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config(128))]

    /// Whole messages and bulk credit, back to back, come out of the
    /// decoder as they went in, however the bytes are cut.
    #[test]
    fn frames_decode_as_encoded_in_any_pieces(
        payloads in prop::collection::vec(
            prop::option::of(prop::collection::vec(any::<u8>(), 0..2048)),
            1..12,
        ),
        cuts in prop::collection::vec(1usize..96, 1..16),
    ) {
        let mut bytes = Vec::new();
        for payload in &payloads {
            match payload {
                Some(payload) => frame::encode(KIND_JSON, payload, &mut bytes).unwrap(),
                None => bytes.extend_from_slice(&fragment::credit_frame()),
            }
        }
        let frames = decode_in_pieces(&mut Decoder::new(), &bytes, &cuts);
        prop_assert_eq!(frames.len(), payloads.len());
        for (frame, payload) in frames.iter().zip(&payloads) {
            match payload {
                Some(payload) => {
                    prop_assert_eq!(frame.kind, KIND_JSON);
                    prop_assert_eq!(frame.payload.as_slice(), payload.as_slice());
                }
                None => {
                    prop_assert_eq!(frame.kind, KIND_CREDIT);
                    prop_assert!(frame.payload.is_empty());
                }
            }
        }
    }

    /// A begin frame's header reads back as written.
    #[test]
    fn begin_headers_read_back(id in id(), bytes in any::<u64>()) {
        let begin = Begin { id, bytes };
        prop_assert_eq!(Begin::decode(&begin.encode()).unwrap(), begin);
    }

    /// Requests, results, errors and events read back as written.
    #[test]
    fn envelopes_read_back(
        id in id(),
        method in "[a-z][a-z0-9_]{0,15}\\.[a-z][a-z0-9_]{0,23}",
        params in object(),
        result in json(),
        code in error_code(),
        text in ".{0,64}",
        data in prop::option::of(object()),
        event in "[a-z][a-z0-9_.]{0,31}",
        chrome in any::<bool>(),
    ) {
        let context = if chrome { Context::chrome() } else { Context::shell() };
        let mut out = Vec::new();
        write_request(&mut out, id, &method, &params, &context).unwrap();
        match Message::decode(&out).unwrap() {
            Message::Request { id: read, method: name, params: Some(raw), context: read_context } => {
                prop_assert_eq!(read, id);
                prop_assert_eq!(name.as_ref(), method.as_str());
                prop_assert_eq!(&parsed(raw), &params);
                prop_assert_eq!(read_context, context);
            }
            other => prop_assert!(false, "not the request: {other:?}"),
        }

        let mut out = Vec::new();
        write_result(&mut out, id, &result).unwrap();
        match Message::decode(&out).unwrap() {
            Message::Response { id: read, outcome: Ok(raw) } => {
                prop_assert_eq!(read, id);
                prop_assert_eq!(&parsed(raw), &result);
            }
            other => prop_assert!(false, "not the result: {other:?}"),
        }

        let mut body = ErrorBody::new(code, text);
        body.data = data;
        let mut out = Vec::new();
        write_error(&mut out, id, &body).unwrap();
        match Message::decode(&out).unwrap() {
            Message::Response { id: read, outcome: Err(raw) } => {
                prop_assert_eq!(read, id);
                prop_assert_eq!(raw.parse().unwrap(), body);
            }
            other => prop_assert!(false, "not the error: {other:?}"),
        }

        let mut out = Vec::new();
        write_event(&mut out, &event, &result).unwrap();
        match Message::decode(&out).unwrap() {
            Message::Event { event: name, data: Some(raw) } => {
                prop_assert_eq!(name.as_ref(), event.as_str());
                prop_assert_eq!(&parsed(raw), &result);
            }
            other => prop_assert!(false, "not the event: {other:?}"),
        }
    }

    /// A response with secret fields is one buffer of exactly its size, and
    /// every field reads back: base64 through `SecretBytes::from_raw`, hex
    /// as `0x` and lowercase hex, public fields as their JSON.
    #[test]
    fn secret_fields_read_back(
        id in id(),
        secret in prop::collection::vec(any::<u8>(), 0..4096),
        key in prop::collection::vec(any::<u8>(), 0..64),
        public in json(),
    ) {
        let payload = SecretResponse::new(id)
            .public("public", &public)
            .unwrap()
            .secret("secret", &secret)
            .secret_hex("key", &key)
            .finish()
            .unwrap();
        prop_assert_eq!(payload.len(), payload.capacity());
        let Message::Response { id: read, outcome: Ok(raw) } = Message::decode(&payload).unwrap()
        else {
            panic!("not a result");
        };
        prop_assert_eq!(read, id);
        let fields: BTreeMap<String, &RawValue> = serde_json::from_str(raw.get()).unwrap();
        prop_assert_eq!(fields.len(), 3);
        let opened = SecretBytes::from_raw(fields["secret"]).unwrap();
        prop_assert_eq!(opened.as_bytes(), secret.as_slice());
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        prop_assert_eq!(parsed(fields["key"]), Value::String(format!("0x{hex}")));
        prop_assert_eq!(parsed(fields["public"]), public);
    }
}

proptest! {
    // Each case moves up to 2 MiB through the decoder and the reassembler.
    #![proptest_config(config(12))]

    /// A fragmented response (design 0005): its begin, then fragments of at
    /// most a frame's payload, with whole messages between any two frames,
    /// reassembles to exactly the response, and the messages pass through in
    /// order, however the bytes are cut.
    #[test]
    fn a_fragmented_response_reassembles_whole(
        id in id(),
        len in prop_oneof![1usize..4096, (MAX_PAYLOAD - 2)..(MAX_PAYLOAD + 3), (2 * MAX_PAYLOAD - 1)..(2 * MAX_PAYLOAD + 2)],
        seed in any::<u8>(),
        between in prop::collection::vec(any::<bool>(), 1..5),
        cuts in prop::collection::vec(1usize..(1 << 17), 1..8),
    ) {
        let response: Vec<u8> = (0..len)
            .map(|at| (at % 251) as u8 ^ seed)
            .collect();
        let (begin, mut splitter) = Splitter::begin(id, len).unwrap();
        let mut bytes = begin;
        let mut events = 0u64;
        let mut between = between.iter().cycle();
        let mut event = |bytes: &mut Vec<u8>| {
            if *between.next().unwrap() {
                let mut json = Vec::new();
                write_event(&mut json, "between", &events).unwrap();
                frame::encode(KIND_JSON, &json, bytes).unwrap();
                events += 1;
            }
        };
        event(&mut bytes);
        while let Some((header, range)) = splitter.next_fragment() {
            bytes.extend_from_slice(&header);
            bytes.extend_from_slice(&response[range]);
            event(&mut bytes);
        }
        prop_assert!(splitter.is_done());

        let frames = decode_in_pieces(&mut Decoder::new(), &bytes, &cuts);
        let mut reassembler = Reassembler::new();
        let mut seen = 0u64;
        let mut whole = None;
        for frame in frames {
            match reassembler.push(frame, |pending| pending == id).unwrap() {
                Delivery::Message { frame, answers } => {
                    prop_assert_eq!(answers, None);
                    let Message::Event { data: Some(raw), .. } = Message::decode(&frame.payload).unwrap()
                    else {
                        panic!("not the event");
                    };
                    prop_assert_eq!(parsed(raw), Value::from(seen));
                    seen += 1;
                }
                Delivery::Response { id: read, payload } => {
                    prop_assert_eq!(read, id);
                    prop_assert!(whole.is_none());
                    whole = Some(payload);
                }
                Delivery::Taken => {}
                Delivery::Credit => prop_assert!(false, "no credit was sent"),
            }
        }
        prop_assert_eq!(seen, events);
        let whole = whole.expect("the response");
        prop_assert!(whole.as_slice() == response.as_slice(), "the response differs");
        prop_assert!(!reassembler.in_progress());
    }
}

/// `message::check_id`'s bounds, which the strategies above draw from.
#[test]
fn ids_are_one_to_two_to_the_53_minus_one() {
    assert!(message::check_id(0).is_err());
    assert!(message::check_id(MAX_ID).is_ok());
    assert!(message::check_id(MAX_ID + 1).is_err());
}
