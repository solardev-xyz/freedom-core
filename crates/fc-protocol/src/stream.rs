//! Design 0007's stream frames: response bodies over the same pipe as the
//! JSON messages, in four kinds taken from 0001's reserved range.
//!
//! | Kind | Name | Direction | Payload after the 8-byte stream ID |
//! |---|---|---|---|
//! | `0x02` | data | the answering side → the requester | 1 to 65 536 body bytes |
//! | `0x03` | end | the answering side → the requester | none: the body is complete |
//! | `0x04` | abort | the answering side → the requester | JSON `{ code, message }`, ≤ 1 KiB: the body is truncated |
//! | `0x05` | credit | the requester → the answering side | a `u32` big-endian above zero: bytes it has handed on |
//!
//! On a service connection the service answers and main requests. On the
//! core's at protocol 2 both do: main answers the core's `shell.dweb_get`.
//!
//! The stream ID is the envelope ID of the request whose response opened
//! it, and request IDs strictly increase within a connection. A head (a
//! `0x01` response) with `body: true` opens the stream; then come data and
//! exactly one terminal, `end` or `abort`.
//!
//! The rules, and where they live:
//! - **The frames** ([`StreamFrame`]): a payload's length is checked
//!   against its kind at the frame header ([`crate::frame::Kinds`]), then
//!   the ID (a valid message ID), an abort's JSON and a credit above zero.
//! - **The side that sends bodies** ([`Sender`], the service): per-stream
//!   FIFOs behind a control queue, debit at queueing against a 128 KiB
//!   window, checked credit, an abort that purges, cancel against an
//!   unwritten head, the outcome a panic or a teardown owes a request
//!   ([`Sender::settle`]), and coalescing into frames of up to 64 KiB.
//! - **The side that receives them** ([`Receiver`], main): checked
//!   receive accounting, one 128 KiB ring per stream, pulls of up to
//!   64 KiB that return credit, and retirement on a local cancel.
//! - **Both, on one connection** ([`Duplex`], `freedom-cored` at protocol
//!   2, design 0009): the bodies the core sends in answer to main's
//!   requests ([`Sender`]) and those main sends in answer to the core's
//!   ([`Inbound`]), each in its requester's ID space, so a frame's kind says
//!   which. The core holds no ring: data goes straight to the stream's
//!   consumer, which holds it in room it reserved, and its credit is sent,
//!   ahead of the sender's frames, once the consumer lets the bytes go.
//!
//! Sans-I/O, like the rest of the crate: the caller feeds frames and events
//! in and takes frames and deliveries out. `vectors/streams.json` holds the
//! design's cases, which main's `frame.js` runs too.

use std::fmt;

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};

use crate::frame::{
    Frame, FrameError, KIND_ABORT, KIND_DATA, KIND_END, KIND_STREAM_CREDIT, MAX_PAYLOAD,
};
use crate::message::check_id;

mod duplex;
mod inbound;
mod receiver;
mod sender;

pub use duplex::{Duplex, Received, Wrote};
pub use inbound::{Arrived, Inbound, InboundInfo, InboundState, Overcredit};
pub use receiver::{Delivery, Pulled, Receiver, Replied, Retire, StreamInfo, StreamState};
pub use sender::{Cancel, Credited, SendError, Sender, Settled, Written};

/// The stream ID that starts every stream frame's payload: 8 bytes,
/// big-endian.
pub const ID_LEN: usize = 8;
/// Each stream's credit window, fixed by the handshake: 128 KiB.
pub const WINDOW: usize = 128 << 10;
/// The most body bytes one data frame carries: 64 KiB.
pub const MAX_DATA: usize = 64 << 10;
/// The most JSON an abort carries after its ID: 1 KiB.
pub const MAX_ABORT: usize = 1 << 10;
/// A credit frame's payload: the ID and a `u32`.
pub const CREDIT_LEN: usize = ID_LEN + 4;
/// The most a pull copies out of main's ring at once: 64 KiB.
pub const MAX_PULL: usize = 64 << 10;
/// Coalescing: a data frame smaller than this is written only when it is
/// all that is pending, or all the credit allows. [`Sender`] cuts every
/// frame as large as it can, so its small frames are always one of those.
pub const SMALL_FRAME: usize = 4 << 10;
/// The most data the service's writer holds, queued and unwritten, across
/// its streams: 16 MiB.
pub const WRITER_DATA_CAP: usize = 16 << 20;

/// Which end of the streams a connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Receives bodies (main): takes data, end and abort; sends credit.
    Receiver,
    /// Sends bodies (the service): takes credit; sends data, end and abort.
    Sender,
    /// Both (`freedom-cored`'s connection at protocol 2, design 0009): it
    /// takes all four, and a frame's kind says which of its streams it
    /// names ([`Duplex`]).
    Both,
}

impl Side {
    /// Whether this side takes stream frames of `kind`.
    pub fn takes(self, kind: u8) -> bool {
        match self {
            Side::Receiver => matches!(kind, KIND_DATA | KIND_END | KIND_ABORT),
            Side::Sender => kind == KIND_STREAM_CREDIT,
            Side::Both => matches!(kind, KIND_DATA | KIND_END | KIND_ABORT | KIND_STREAM_CREDIT),
        }
    }
}

/// Checks a stream frame's payload length against its kind: the ID, then
/// 1 to [`MAX_DATA`] body bytes, nothing, 1 to [`MAX_ABORT`] bytes of JSON,
/// or a `u32`.
pub(crate) fn check_length(kind: u8, len: usize) -> Result<(), FrameError> {
    let bad = FrameError::StreamLength { kind, len };
    let Some(after) = len.checked_sub(ID_LEN) else {
        return Err(bad);
    };
    match kind {
        KIND_DATA if after == 0 => Err(FrameError::EmptyData),
        KIND_DATA if after <= MAX_DATA => Ok(()),
        KIND_END if after == 0 => Ok(()),
        KIND_ABORT if (1..=MAX_ABORT).contains(&after) => Ok(()),
        KIND_STREAM_CREDIT if after == CREDIT_LEN - ID_LEN => Ok(()),
        _ => Err(bad),
    }
}

/// A protocol error in the streams: the receiver of the frame logs it and
/// closes the connection (0001). Every state machine stays failed after
/// its first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    /// A length or direction the frame header should have refused.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// A stream ID that is not a valid message ID.
    #[error("stream ID {0} is zero or above 2^53 - 1")]
    BadId(u64),
    /// An abort whose payload is not `{ code, message }` with a known code.
    #[error("an abort payload that is not {{ code, message }}")]
    AbortPayload,
    /// A credit of zero bytes.
    #[error("a credit of zero bytes")]
    CreditZero,
    /// A request whose ID is not above every earlier one.
    #[error("request {id} after request {highest}: IDs strictly increase")]
    RequestOrder { id: u64, highest: u64 },
    /// A stream frame for an ID above the highest request ID seen.
    #[error("a stream frame for {0}, above the highest request ID")]
    Unknown(u64),
    /// A data or terminal frame for a request whose stream isn't open:
    /// before its head, after a head without a body or an error reply, or
    /// after its terminal.
    #[error("a stream frame for {0}, whose stream is not open")]
    NotOpen(u64),
    /// Credit beyond what was sent (`credited > sent`).
    #[error("credit for stream {0} beyond what was sent")]
    Overgrant(u64),
    /// Data beyond the window (`received − returned > 128 KiB`).
    #[error("data for stream {0} beyond its window")]
    Overrun(u64),
    /// A response to a request that isn't pending: unsolicited, or a
    /// second one.
    #[error("a response to {0}, which is not pending")]
    UnsolicitedResponse(u64),
}

impl StreamError {
    /// A fixed name for the failure, safe to log and shared with main's
    /// `frame.js` through `vectors/streams.json`.
    pub fn category(&self) -> &'static str {
        match self {
            StreamError::Frame(error) => error.category(),
            StreamError::BadId(_) => "stream_id",
            StreamError::AbortPayload => "abort_payload",
            StreamError::CreditZero => "credit_zero",
            StreamError::RequestOrder { .. } => "request_order",
            StreamError::Unknown(_) => "stream_unknown",
            StreamError::NotOpen(_) => "stream_not_open",
            StreamError::Overgrant(_) => "credit_overgrant",
            StreamError::Overrun(_) => "window_overrun",
            StreamError::UnsolicitedResponse(_) => "unsolicited_response",
        }
    }
}

/// Why a body was truncated (design 0007, Errors). On the wire it is a
/// JSON string, and only a string: serde's derived enum would also take an
/// externally tagged unit variant (`{"cancelled": null}`), which design 0007
/// and main's `frame.js` refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortCode {
    /// Main's `cancel`.
    Cancelled,
    /// A panic on the request's task.
    Internal,
    /// Upstream's code for a failing body.
    BodyStreamError,
    /// The instance was stopped.
    Stopped,
    /// The stream's next block couldn't reserve memory in time.
    Busy,
}

impl AbortCode {
    /// Every code, in the order the design lists them.
    const ALL: [AbortCode; 5] = [
        AbortCode::Cancelled,
        AbortCode::Internal,
        AbortCode::BodyStreamError,
        AbortCode::Stopped,
        AbortCode::Busy,
    ];

    /// The code on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            AbortCode::Cancelled => "cancelled",
            AbortCode::Internal => "internal",
            AbortCode::BodyStreamError => "body_stream_error",
            AbortCode::Stopped => "stopped",
            AbortCode::Busy => "busy",
        }
    }

    /// The code a wire name stands for, if it is one.
    fn from_name(name: &str) -> Option<Self> {
        AbortCode::ALL
            .into_iter()
            .find(|code| code.as_str() == name)
    }
}

/// The wire names, for serde's error message.
const ABORT_CODE_NAMES: &[&str] = &[
    "cancelled",
    "internal",
    "body_stream_error",
    "stopped",
    "busy",
];

/// A string naming one of the codes: escapes are read as JSON reads them,
/// and anything but a string (an object, a number) is refused.
impl<'de> Deserialize<'de> for AbortCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Name;

        impl Visitor<'_> for Name {
            type Value = AbortCode;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an abort code, as a string")
            }

            fn visit_str<E: de::Error>(self, name: &str) -> Result<AbortCode, E> {
                AbortCode::from_name(name).ok_or_else(|| E::unknown_variant(name, ABORT_CODE_NAMES))
            }
        }

        deserializer.deserialize_str(Name)
    }
}

/// An abort frame's JSON: a code and a message, and no other member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Abort {
    pub code: AbortCode,
    pub message: String,
}

impl Abort {
    pub fn new(code: AbortCode, message: impl Into<String>) -> Self {
        Abort {
            code,
            message: message.into(),
        }
    }

    /// The abort a cancel of an open stream writes.
    pub fn cancelled() -> Self {
        Abort::new(AbortCode::Cancelled, "Cancelled")
    }

    /// Its JSON, `{"code":…,"message":…}`, if it fits an abort frame.
    pub fn to_json(&self) -> Result<Vec<u8>, StreamError> {
        let json = serde_json::to_vec(self).map_err(|_| StreamError::AbortPayload)?;
        check_length(KIND_ABORT, ID_LEN.saturating_add(json.len()))?;
        Ok(json)
    }

    /// Parses an abort's JSON: an object with exactly `code`, one of the
    /// abort codes, and `message`, a string, each once.
    pub fn from_json(json: &[u8]) -> Result<Self, StreamError> {
        let text = std::str::from_utf8(json).map_err(|_| StreamError::AbortPayload)?;
        // serde's derived structs would also take an array.
        if !text.trim_start().starts_with('{') {
            return Err(StreamError::AbortPayload);
        }
        serde_json::from_str(text).map_err(|_| StreamError::AbortPayload)
    }
}

/// A decoded stream frame. A data frame borrows its body from the frame.
#[derive(Clone, PartialEq, Eq)]
pub enum StreamFrame<'a> {
    Data { id: u64, bytes: &'a [u8] },
    End { id: u64 },
    Abort { id: u64, abort: Abort },
    Credit { id: u64, bytes: u32 },
}

/// Bodies are page content: `Debug` shows their length, not their bytes.
impl fmt::Debug for StreamFrame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamFrame::Data { id, bytes } => f
                .debug_struct("Data")
                .field("id", id)
                .field("len", &bytes.len())
                .finish(),
            StreamFrame::End { id } => f.debug_struct("End").field("id", id).finish(),
            StreamFrame::Abort { id, abort } => f
                .debug_struct("Abort")
                .field("id", id)
                .field("code", &abort.code)
                .finish_non_exhaustive(),
            StreamFrame::Credit { id, bytes } => f
                .debug_struct("Credit")
                .field("id", id)
                .field("bytes", bytes)
                .finish(),
        }
    }
}

impl<'a> StreamFrame<'a> {
    /// Decodes a stream frame's payload: its length for `kind`, the ID, then
    /// the rest. A decoder built with [`crate::frame::Kinds::service`] has
    /// already checked the length and the direction.
    pub fn decode(kind: u8, payload: &'a [u8]) -> Result<Self, StreamError> {
        check_length(kind, payload.len())?;
        let bad = StreamError::Frame(FrameError::StreamLength {
            kind,
            len: payload.len(),
        });
        let (id, rest) = payload.split_at_checked(ID_LEN).ok_or(bad)?;
        let id = u64::from_be_bytes(id.try_into().map_err(|_| bad)?);
        let id = check_id(id).map_err(|_| StreamError::BadId(id))?;
        match kind {
            KIND_DATA => Ok(StreamFrame::Data { id, bytes: rest }),
            KIND_END => Ok(StreamFrame::End { id }),
            KIND_ABORT => Ok(StreamFrame::Abort {
                id,
                abort: Abort::from_json(rest)?,
            }),
            KIND_STREAM_CREDIT => match u32::from_be_bytes(rest.try_into().map_err(|_| bad)?) {
                0 => Err(StreamError::CreditZero),
                bytes => Ok(StreamFrame::Credit { id, bytes }),
            },
            other => Err(StreamError::Frame(FrameError::UnknownKind(other))),
        }
    }

    /// Decodes a frame the decoder produced.
    pub fn from_frame(frame: &'a Frame) -> Result<Self, StreamError> {
        Self::decode(frame.kind, &frame.payload)
    }

    /// The stream it belongs to.
    pub fn id(&self) -> u64 {
        match self {
            StreamFrame::Data { id, .. }
            | StreamFrame::End { id }
            | StreamFrame::Abort { id, .. }
            | StreamFrame::Credit { id, .. } => *id,
        }
    }

    /// Its frame kind.
    pub fn kind(&self) -> u8 {
        match self {
            StreamFrame::Data { .. } => KIND_DATA,
            StreamFrame::End { .. } => KIND_END,
            StreamFrame::Abort { .. } => KIND_ABORT,
            StreamFrame::Credit { .. } => KIND_STREAM_CREDIT,
        }
    }

    /// Appends the whole frame to `out`, after checking it as a decoder
    /// would. Nothing is written for a frame that would be refused.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), StreamError> {
        match self {
            StreamFrame::Data { id, bytes } => {
                out.extend_from_slice(&data_header(*id, bytes.len())?);
                out.extend_from_slice(bytes);
            }
            StreamFrame::End { id } => out.extend_from_slice(&end_frame(*id)?),
            StreamFrame::Abort { id, abort } => {
                let id = valid_id(*id)?;
                let json = abort.to_json()?;
                put_header(out, KIND_ABORT, id, json.len());
                out.extend_from_slice(&json);
            }
            StreamFrame::Credit { id, bytes } => {
                out.extend_from_slice(&credit_frame(*id, *bytes)?);
            }
        }
        Ok(())
    }
}

fn valid_id(id: u64) -> Result<u64, StreamError> {
    check_id(id).map_err(|_| StreamError::BadId(id))
}

/// Appends a stream frame's 13-byte start: the length of everything after
/// it, the kind and the ID. `after` is what follows the ID, within the
/// kind's bound.
fn put_header(out: &mut Vec<u8>, kind: u8, id: u64, after: usize) {
    out.extend_from_slice(&start(kind, id, after));
}

fn start(kind: u8, id: u64, after: usize) -> [u8; 13] {
    // The kind byte, the ID and the rest; at most 1 + 8 + 65 536.
    let len = u32::try_from(1 + ID_LEN + after.min(MAX_PAYLOAD)).unwrap_or(u32::MAX);
    let mut out = [0u8; 13];
    out[..4].copy_from_slice(&len.to_be_bytes());
    out[4] = kind;
    out[5..].copy_from_slice(&id.to_be_bytes());
    out
}

/// The 13 bytes that start a data frame of `len` body bytes for stream
/// `id`, for a writer that sends the body from where it lies.
pub fn data_header(id: u64, len: usize) -> Result<[u8; 13], StreamError> {
    let id = valid_id(id)?;
    check_length(KIND_DATA, ID_LEN.saturating_add(len))?;
    Ok(start(KIND_DATA, id, len))
}

/// Stream `id`'s end frame.
pub fn end_frame(id: u64) -> Result<[u8; 13], StreamError> {
    Ok(start(KIND_END, valid_id(id)?, 0))
}

/// A credit frame returning `bytes` of stream `id`'s window.
pub fn credit_frame(id: u64, bytes: u32) -> Result<[u8; 17], StreamError> {
    let id = valid_id(id)?;
    if bytes == 0 {
        return Err(StreamError::CreditZero);
    }
    let mut out = [0u8; 17];
    out[..13].copy_from_slice(&start(KIND_STREAM_CREDIT, id, 4));
    out[13..].copy_from_slice(&bytes.to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Decoder, Kinds};

    #[test]
    fn lengths_by_kind() {
        use FrameError::*;
        for (kind, len, ok) in [
            (KIND_DATA, 9, true),
            (KIND_DATA, ID_LEN + MAX_DATA, true),
            (KIND_DATA, ID_LEN + MAX_DATA + 1, false),
            (KIND_END, 8, true),
            (KIND_END, 9, false),
            (KIND_END, 7, false),
            (KIND_ABORT, 9, true),
            (KIND_ABORT, ID_LEN + MAX_ABORT, true),
            (KIND_ABORT, ID_LEN + MAX_ABORT + 1, false),
            (KIND_ABORT, 8, false),
            (KIND_STREAM_CREDIT, 12, true),
            (KIND_STREAM_CREDIT, 11, false),
            (KIND_STREAM_CREDIT, 13, false),
            (KIND_DATA, 0, false),
        ] {
            assert_eq!(check_length(kind, len).is_ok(), ok, "{kind} {len}");
        }
        assert_eq!(check_length(KIND_DATA, 8), Err(EmptyData));
        assert_eq!(
            check_length(KIND_END, 3),
            Err(StreamLength {
                kind: KIND_END,
                len: 3
            })
        );
    }

    #[test]
    fn frames_round_trip_through_the_decoder() {
        let body = [7u8; 300];
        let frames = [
            StreamFrame::Data {
                id: 41,
                bytes: &body,
            },
            StreamFrame::End { id: 41 },
            StreamFrame::Abort {
                id: 42,
                abort: Abort::new(AbortCode::BodyStreamError, "upstream body failed"),
            },
        ];
        let mut stream = Vec::new();
        for frame in &frames {
            frame.encode(&mut stream).unwrap();
        }
        let mut decoder = Decoder::with_kinds(Kinds::service(Side::Receiver));
        assert_eq!(decoder.push(&stream).unwrap(), stream.len());
        let decoded: Vec<Frame> = std::iter::from_fn(|| decoder.pop()).collect();
        let decoded: Vec<StreamFrame<'_>> = decoded
            .iter()
            .map(|f| StreamFrame::from_frame(f).unwrap())
            .collect();
        assert_eq!(decoded, frames);

        let mut credit = Vec::new();
        StreamFrame::Credit { id: 41, bytes: 9 }
            .encode(&mut credit)
            .unwrap();
        assert_eq!(credit, credit_frame(41, 9).unwrap());
        let mut decoder = Decoder::with_kinds(Kinds::service(Side::Sender));
        decoder.push(&credit).unwrap();
        let frame = decoder.pop().unwrap();
        assert_eq!(
            StreamFrame::from_frame(&frame).unwrap(),
            StreamFrame::Credit { id: 41, bytes: 9 }
        );
    }

    #[test]
    fn encoders_refuse_what_a_decoder_refuses() {
        let mut out = Vec::new();
        let empty = StreamFrame::Data { id: 1, bytes: &[] };
        assert_eq!(
            empty.encode(&mut out),
            Err(StreamError::Frame(FrameError::EmptyData))
        );
        let long = vec![0u8; MAX_DATA + 1];
        assert!(matches!(
            StreamFrame::Data {
                id: 1,
                bytes: &long
            }
            .encode(&mut out),
            Err(StreamError::Frame(FrameError::StreamLength { .. }))
        ));
        assert_eq!(
            StreamFrame::End { id: 0 }.encode(&mut out),
            Err(StreamError::BadId(0))
        );
        assert_eq!(credit_frame(1, 0), Err(StreamError::CreditZero));
        assert_eq!(
            data_header(1, usize::MAX)
                .map(|_| ())
                .unwrap_err()
                .category(),
            "stream_length"
        );
        let wordy = Abort::new(AbortCode::Internal, "x".repeat(MAX_ABORT));
        assert!(matches!(
            StreamFrame::Abort {
                id: 1,
                abort: wordy
            }
            .encode(&mut out),
            Err(StreamError::Frame(FrameError::StreamLength { .. }))
        ));
        assert!(out.is_empty(), "nothing written for a refused frame");
    }

    #[test]
    fn abort_json_is_a_closed_shape() {
        assert_eq!(
            Abort::from_json(br#"{"code":"busy","message":"m"}"#).unwrap(),
            Abort::new(AbortCode::Busy, "m")
        );
        for bad in [
            &br#"{"code":"busy"}"#[..],
            br#"{"message":"m"}"#,
            br#"{"code":"nope","message":"m"}"#,
            br#"{"code":"busy","message":"m","data":1}"#,
            br#"{"code":"busy","code":"busy","message":"m"}"#,
            br#"["busy","m"]"#,
            br#"{"code":"busy","message":7}"#,
            b"\xff",
            b"",
            // serde's derived enum would take these: an externally tagged
            // unit variant.
            br#"{"code":{"cancelled":null},"message":"m"}"#,
            br#"{"code":{"busy":[]},"message":"m"}"#,
            br#"{"code":["busy"],"message":"m"}"#,
            br#"{"code":null,"message":"m"}"#,
        ] {
            assert_eq!(
                Abort::from_json(bad),
                Err(StreamError::AbortPayload),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_eq!(
            Abort::cancelled().to_json().unwrap(),
            br#"{"code":"cancelled","message":"Cancelled"}"#
        );
    }

    #[test]
    fn abort_codes_are_strings_only() {
        // A backslash, so the escapes below are JSON's, not Rust's.
        const BS: char = '\\';
        for code in AbortCode::ALL {
            let name = code.as_str();
            // The string, plain and with its first letter escaped.
            let escaped = format!("{BS}u{:04x}{}", u32::from(name.as_bytes()[0]), &name[1..]);
            for text in [name.to_owned(), escaped.clone()] {
                let json = format!(r#"{{"code":"{text}","message":"m"}}"#);
                assert_eq!(
                    Abort::from_json(json.as_bytes()).unwrap(),
                    Abort::new(code, "m"),
                    "{json}"
                );
            }
            // The object form, under either spelling.
            for text in [name.to_owned(), escaped] {
                let json = format!(r#"{{"code":{{"{text}":null}},"message":"m"}}"#);
                assert_eq!(
                    Abort::from_json(json.as_bytes()),
                    Err(StreamError::AbortPayload),
                    "{json}"
                );
            }
            assert_eq!(AbortCode::from_name(name), Some(code));
        }
        assert_eq!(AbortCode::from_name("Busy"), None);
        assert_eq!(ABORT_CODE_NAMES, AbortCode::ALL.map(AbortCode::as_str));
    }

    #[test]
    fn debug_never_prints_bodies() {
        let frame = StreamFrame::Data {
            id: 1,
            bytes: b"SECRET",
        };
        assert!(!format!("{frame:?}").contains("SECRET"));
    }
}
