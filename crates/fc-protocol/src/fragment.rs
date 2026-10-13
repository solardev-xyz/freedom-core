//! Fragmented responses and bulk credit (design 0005, Frames).
//!
//! A response over one frame ([`MAX_PAYLOAD`]) goes out as a **begin**
//! (kind `0x12`, a header `{ "id": <request ID>, "bytes": <total size> }`),
//! **fragments** (`0x10`) and a **last** fragment (`0x11`). Only responses
//! fragment; requests stay within one frame.
//!
//! **Bulk credit:** each side holds one credit for the other direction,
//! granted by the handshake. A sender begins only while it holds the credit,
//! and beginning spends it. The receiver returns it with an empty **credit**
//! frame (`0x13`) once the completed response has been handed to its
//! consumer. So at most one response per direction is in reassembly, and the
//! receiver can reserve its bytes at begin.
//!
//! **One response per request** (0001): once a response has begun, a whole
//! response for the same request is a duplicate, and a response read whole
//! can't be followed by a begin for its request.
//!
//! Sans-I/O: [`Splitter`] cuts a response into frames for a writer, and
//! [`Reassembler`] turns the frames a decoder produced back into whole
//! messages, completed responses and credit returns. Every malformed
//! sequence is a [`FragmentError`]: a protocol error, so the receiver logs
//! it and closes the connection.

use std::fmt;
use std::ops::Range;

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::frame::{
    self, Frame, KIND_BEGIN, KIND_CREDIT, KIND_FRAGMENT, KIND_JSON, KIND_LAST, MAX_MESSAGE,
    MAX_PAYLOAD,
};
use crate::message::{Message, check_id};

/// A fragmented stream the receiver must close on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FragmentError {
    /// A begin while the sender holds no credit, which includes a begin
    /// while another response is in reassembly.
    #[error("a begin while the sender holds no credit")]
    NoCredit,
    /// A begin whose ID is not a pending request of the receiver's.
    #[error("a begin for request {0}, which is not pending")]
    UnknownId(u64),
    /// A whole response for the request whose response is in reassembly:
    /// its second response.
    #[error("a whole response for request {0}, whose response has begun")]
    DuplicateResponse(u64),
    /// A begin whose size is zero or over the message cap.
    #[error("a response of {0} bytes, zero or over the message cap")]
    BadSize(u64),
    /// A begin header that isn't `{ "id": <ID>, "bytes": <size> }`.
    #[error("a begin header that is not {{ id, bytes }}")]
    BadHeader,
    /// A fragment or last frame without bytes.
    #[error("an empty fragment")]
    EmptyFragment,
    /// A fragment or last frame with no response in reassembly.
    #[error("a fragment with no response in reassembly")]
    NoResponse,
    /// The fragments add up to more than the begin declared, or the last
    /// one leaves the response short.
    #[error("fragments of {got} bytes for a response of {expected}")]
    LengthMismatch { expected: u64, got: u64 },
    /// A credit frame that isn't empty.
    #[error("a credit frame with a payload")]
    CreditPayload,
    /// A frame kind that carries no part of a message (a decoder never
    /// produces one).
    #[error("frame kind {0:#04x} is not a message kind")]
    UnexpectedKind(u8),
}

/// A begin frame's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Begin {
    /// The ID of the request the response answers.
    pub id: u64,
    /// The response's total size: the serialized message, as a `0x01`
    /// payload would carry it.
    pub bytes: u64,
}

impl Begin {
    /// The header's JSON.
    pub fn encode(&self) -> Vec<u8> {
        format!(r#"{{"id":{},"bytes":{}}}"#, self.id, self.bytes).into_bytes()
    }

    /// Parses a begin frame's payload: an object with exactly `id`, a valid
    /// message ID, and `bytes`.
    pub fn decode(payload: &[u8]) -> Result<Self, FragmentError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Header {
            id: u64,
            bytes: u64,
        }
        let text = std::str::from_utf8(payload).map_err(|_| FragmentError::BadHeader)?;
        if !text.trim_start().starts_with('{') {
            return Err(FragmentError::BadHeader);
        }
        let header: Header = serde_json::from_str(text).map_err(|_| FragmentError::BadHeader)?;
        let id = check_id(header.id).map_err(|_| FragmentError::BadHeader)?;
        Ok(Begin {
            id,
            bytes: header.bytes,
        })
    }
}

/// The credit frame: five bytes, no payload.
pub fn credit_frame() -> [u8; 5] {
    // Length 1 (the kind alone), kind 0x13.
    [0, 0, 0, 1, KIND_CREDIT]
}

/// Cuts one response into frames: its begin, then fragments of at most
/// [`MAX_PAYLOAD`] bytes, the last of kind `0x11`. The writer sends each
/// fragment's header and then its range of the payload from where it lies,
/// and may send whole messages between any two frames.
#[derive(Debug)]
pub struct Splitter {
    len: usize,
    offset: usize,
    done: bool,
}

impl Splitter {
    /// The begin frame for response `id` of `len` serialized bytes, and the
    /// splitter for its fragments. A response over [`MAX_MESSAGE`] is never
    /// begun: its sender replaces it with a `too_large` failure.
    pub fn begin(id: u64, len: usize) -> Result<(Vec<u8>, Self), FragmentError> {
        let id = check_id(id).map_err(|_| FragmentError::BadHeader)?;
        let bytes = u64::try_from(len).map_err(|_| FragmentError::BadSize(u64::MAX))?;
        if len == 0 || len > MAX_MESSAGE {
            return Err(FragmentError::BadSize(bytes));
        }
        let header = Begin { id, bytes }.encode();
        let mut out = Vec::with_capacity(header.len() + 5);
        frame::encode(KIND_BEGIN, &header, &mut out).map_err(|_| FragmentError::BadHeader)?;
        Ok((
            out,
            Splitter {
                len,
                offset: 0,
                done: false,
            },
        ))
    }

    /// The next fragment: its frame header and its range in the payload.
    /// `None` once the last fragment has been taken.
    pub fn next_fragment(&mut self) -> Option<([u8; 5], Range<usize>)> {
        if self.done {
            return None;
        }
        let end = self.len.min(self.offset + MAX_PAYLOAD);
        let last = end == self.len;
        let kind = if last { KIND_LAST } else { KIND_FRAGMENT };
        let header = frame::header(kind, end - self.offset).ok()?;
        let range = self.offset..end;
        self.offset = end;
        self.done = last;
        Some((header, range))
    }

    /// Whether the last fragment has been taken.
    pub fn is_done(&self) -> bool {
        self.done
    }
}

/// What a frame amounts to, once the reassembler has taken it.
pub enum Delivery {
    /// A whole message (kind `0x01`), to decode at once, also between
    /// another response's fragments. `answers` is the request it responds
    /// to, if it is a response: the receiver retires that ID, so no begin
    /// can follow for it.
    Message { frame: Frame, answers: Option<u64> },
    /// A fragmented response, complete: exactly the begin's `bytes`, to
    /// decode as a `0x01` payload is.
    Response {
        id: u64,
        payload: Zeroizing<Vec<u8>>,
    },
    /// The peer returned this side's bulk credit (kind `0x13`).
    Credit,
    /// A begin or a fragment, taken in; nothing to hand on yet.
    Taken,
}

/// Bodies can carry secrets: `Debug` shows only kinds, IDs and sizes.
impl fmt::Debug for Delivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Delivery::Message { frame, answers } => f
                .debug_struct("Message")
                .field("frame", frame)
                .field("answers", answers)
                .finish(),
            Delivery::Response { id, payload } => f
                .debug_struct("Response")
                .field("id", id)
                .field("len", &payload.len())
                .finish(),
            Delivery::Credit => f.write_str("Credit"),
            Delivery::Taken => f.write_str("Taken"),
        }
    }
}

/// A response in reassembly.
struct Partial {
    id: u64,
    bytes: usize,
    payload: Zeroizing<Vec<u8>>,
}

/// The receiving side: turns decoded frames into whole messages, completed
/// responses and credit returns.
///
/// - **At begin** it checks the sender's credit, the size against the
///   message cap and the ID against the receiver's pending requests, then
///   reserves exactly the declared bytes, in one `Zeroizing` buffer. Since
///   the credit allows one response in reassembly, nothing else is ever
///   reserved, and a fragment never needs room the begin didn't take.
/// - **Whole messages** pass through. Each one's envelope is read to find
///   a response: one for the request in reassembly is a duplicate.
/// - **Fragments** append; the last completes the response, which must be
///   exactly the declared size.
/// - **After an error** it stays failed, and the partial response is wiped.
pub struct Reassembler {
    cap: usize,
    peer_credit: bool,
    current: Option<Partial>,
    failed: Option<FragmentError>,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// A receiver whose peer holds its credit, as the handshake grants it.
    pub fn new() -> Self {
        Reassembler {
            cap: MAX_MESSAGE,
            peer_credit: true,
            current: None,
            failed: None,
        }
    }

    /// Takes one decoded frame. `pending` says whether an ID is a pending
    /// request of the receiver's. It is asked only at a begin, once every
    /// other check has passed, so the receiver may claim the ID there: the
    /// begin is then accepted.
    pub fn push(
        &mut self,
        frame: Frame,
        pending: impl FnOnce(u64) -> bool,
    ) -> Result<Delivery, FragmentError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let delivery = self.take(frame, pending);
        if let Err(error) = delivery {
            self.failed = Some(error);
            self.current = None;
        }
        delivery
    }

    fn take(
        &mut self,
        frame: Frame,
        pending: impl FnOnce(u64) -> bool,
    ) -> Result<Delivery, FragmentError> {
        match frame.kind {
            KIND_JSON => {
                // A malformed envelope is the decoder's to report, as for
                // any whole message.
                let answers = match Message::decode(&frame.payload) {
                    Ok(Message::Response { id, .. }) => Some(id),
                    _ => None,
                };
                if let (Some(id), Some(partial)) = (answers, &self.current)
                    && id == partial.id
                {
                    return Err(FragmentError::DuplicateResponse(id));
                }
                Ok(Delivery::Message { frame, answers })
            }
            KIND_CREDIT if frame.payload.is_empty() => Ok(Delivery::Credit),
            KIND_CREDIT => Err(FragmentError::CreditPayload),
            KIND_BEGIN => {
                let begin = Begin::decode(&frame.payload)?;
                if !self.peer_credit {
                    return Err(FragmentError::NoCredit);
                }
                let bytes = usize::try_from(begin.bytes)
                    .ok()
                    .filter(|bytes| (1..=self.cap).contains(bytes))
                    .ok_or(FragmentError::BadSize(begin.bytes))?;
                if !pending(begin.id) {
                    return Err(FragmentError::UnknownId(begin.id));
                }
                self.peer_credit = false;
                self.current = Some(Partial {
                    id: begin.id,
                    bytes,
                    payload: Zeroizing::new(Vec::with_capacity(bytes)),
                });
                Ok(Delivery::Taken)
            }
            KIND_FRAGMENT | KIND_LAST => {
                let Some(partial) = self.current.as_mut() else {
                    return Err(FragmentError::NoResponse);
                };
                if frame.payload.is_empty() {
                    return Err(FragmentError::EmptyFragment);
                }
                let got = partial.payload.len() + frame.payload.len();
                let mismatch = FragmentError::LengthMismatch {
                    expected: partial.bytes as u64,
                    got: got as u64,
                };
                if got > partial.bytes || (frame.kind == KIND_LAST && got != partial.bytes) {
                    return Err(mismatch);
                }
                // Within the reservation: the buffer never reallocates, so
                // no copy of the bytes is left behind unwiped.
                partial.payload.extend_from_slice(&frame.payload);
                if frame.kind == KIND_FRAGMENT {
                    return Ok(Delivery::Taken);
                }
                let Some(Partial { id, payload, .. }) = self.current.take() else {
                    return Err(FragmentError::NoResponse);
                };
                Ok(Delivery::Response { id, payload })
            }
            other => Err(FragmentError::UnexpectedKind(other)),
        }
    }

    /// This side has returned the peer's credit (it sent `0x13`): the peer
    /// may begin again.
    pub fn grant(&mut self) {
        self.peer_credit = true;
    }

    /// Whether the peer holds this side's credit.
    pub fn peer_holds_credit(&self) -> bool {
        self.peer_credit
    }

    /// Whether a response is in reassembly: EOF now cuts it short.
    pub fn in_progress(&self) -> bool {
        self.current.is_some()
    }

    /// The bytes reserved for the response in reassembly.
    pub fn reserved(&self) -> usize {
        self.current.as_ref().map_or(0, |p| p.payload.capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Decoder;

    fn frame(kind: u8, payload: &[u8]) -> Frame {
        Frame {
            kind,
            payload: Zeroizing::new(payload.to_vec()),
        }
    }

    fn begin(id: u64, bytes: u64) -> Frame {
        frame(KIND_BEGIN, &Begin { id, bytes }.encode())
    }

    /// A reassembler for which request 7 is pending.
    fn pending(id: u64) -> bool {
        id == 7
    }

    #[test]
    fn begin_headers_round_trip() {
        let header = Begin {
            id: 7,
            bytes: 3 << 20,
        };
        assert_eq!(header.encode(), br#"{"id":7,"bytes":3145728}"#);
        assert_eq!(Begin::decode(&header.encode()), Ok(header));
        for bad in [
            &br#"{"id":7}"#[..],
            br#"{"bytes":5}"#,
            br#"{"id":7,"bytes":5,"extra":1}"#,
            br#"{"id":0,"bytes":5}"#,
            br#"{"id":9007199254740992,"bytes":5}"#,
            br#"{"id":7,"bytes":-1}"#,
            br#"{"id":"7","bytes":5}"#,
            br#"[7,5]"#,
            b"",
            b"\xff",
        ] {
            assert_eq!(
                Begin::decode(bad),
                Err(FragmentError::BadHeader),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_split_response_reassembles_in_any_chunking() {
        // Three fragments; whole messages between them; any read sizes.
        let payload: Vec<u8> = (0..(2 * MAX_PAYLOAD + 1000))
            .map(|i| (i % 251) as u8)
            .collect();
        let (begin, mut splitter) = Splitter::begin(7, payload.len()).unwrap();
        let mut stream = begin;
        let mut fragments = 0;
        while let Some((header, range)) = splitter.next_fragment() {
            stream.extend_from_slice(&header);
            stream.extend_from_slice(&payload[range]);
            frame::encode_json(br#"{"type":"event","event":"x","data":{}}"#, &mut stream).unwrap();
            fragments += 1;
        }
        assert!(splitter.is_done());
        assert_eq!(fragments, 3);
        for chunk in [7, 4096, 1 << 20, stream.len()] {
            let mut decoder = Decoder::new();
            let mut reassembler = Reassembler::new();
            let mut messages = 0;
            let mut responses = Vec::new();
            for mut piece in stream.chunks(chunk) {
                while !piece.is_empty() {
                    let consumed = decoder.push(piece).unwrap();
                    piece = &piece[consumed..];
                    while let Some(frame) = decoder.pop() {
                        match reassembler.push(frame, pending).unwrap() {
                            Delivery::Message { .. } => messages += 1,
                            Delivery::Response { id, payload } => {
                                responses.push((id, payload.to_vec()));
                            }
                            Delivery::Taken => {}
                            Delivery::Credit => panic!("no credit was sent"),
                        }
                    }
                }
            }
            // Each whole message is handed on as it arrives, the last one
            // after the response.
            assert_eq!(messages, 3, "chunk {chunk}");
            assert_eq!(responses, [(7, payload.clone())], "chunk {chunk}");
            assert!(!reassembler.in_progress());
            assert!(!reassembler.peer_holds_credit());
        }
    }

    #[test]
    fn the_splitter_refuses_what_must_not_begin() {
        assert_eq!(
            Splitter::begin(7, MAX_MESSAGE + 1).unwrap_err(),
            FragmentError::BadSize(MAX_MESSAGE as u64 + 1)
        );
        assert_eq!(
            Splitter::begin(7, 0).unwrap_err(),
            FragmentError::BadSize(0)
        );
        assert_eq!(
            Splitter::begin(0, 10).unwrap_err(),
            FragmentError::BadHeader
        );
        // At the cap: 32 fragments, the last one full.
        let (_, mut splitter) = Splitter::begin(7, MAX_MESSAGE).unwrap();
        let ranges: Vec<_> = std::iter::from_fn(|| splitter.next_fragment()).collect();
        assert_eq!(ranges.len(), 32);
        assert!(ranges[..31].iter().all(|(h, _)| h[4] == KIND_FRAGMENT));
        assert_eq!(ranges[31].0[4], KIND_LAST);
        assert_eq!(ranges[31].1, MAX_MESSAGE - MAX_PAYLOAD..MAX_MESSAGE);
        // A response of one byte: a lone last fragment.
        let (_, mut splitter) = Splitter::begin(7, 1).unwrap();
        let (header, range) = splitter.next_fragment().unwrap();
        assert_eq!((header, range), ([0, 0, 0, 2, KIND_LAST], 0..1));
        assert!(splitter.next_fragment().is_none());
    }

    #[test]
    fn the_reservation_is_exactly_the_declared_size() {
        let mut r = Reassembler::new();
        assert!(matches!(
            r.push(begin(7, 3 << 20), pending),
            Ok(Delivery::Taken)
        ));
        assert!(r.in_progress());
        assert_eq!(r.reserved(), 3 << 20);
        assert!(matches!(
            r.push(frame(KIND_FRAGMENT, &[1; 1 << 20]), pending),
            Ok(Delivery::Taken)
        ));
        assert_eq!(r.reserved(), 3 << 20, "fragments never reallocate");
    }

    #[test]
    fn credit_allows_one_response_at_a_time() {
        let mut r = Reassembler::new();
        assert!(r.peer_holds_credit());
        r.push(begin(7, 2), pending).unwrap();
        r.push(frame(KIND_LAST, b"{}"), pending).unwrap();
        // Spent: another begin waits for this side's credit frame.
        assert!(!r.peer_holds_credit());
        r.grant();
        assert!(matches!(r.push(begin(7, 2), pending), Ok(Delivery::Taken)));
    }

    #[test]
    fn whole_messages_and_credit_pass_through() {
        let mut r = Reassembler::new();
        assert!(matches!(
            r.push(frame(KIND_JSON, b"{}"), |_| unreachable!()),
            Ok(Delivery::Message { frame: f, answers: None }) if f.payload.as_slice() == b"{}"
        ));
        assert!(matches!(
            r.push(frame(KIND_CREDIT, b""), |_| unreachable!()),
            Ok(Delivery::Credit)
        ));
        // Mid-response too.
        r.push(begin(7, 4), pending).unwrap();
        r.push(frame(KIND_FRAGMENT, b"ab"), pending).unwrap();
        assert!(matches!(
            r.push(frame(KIND_JSON, b"[]"), pending),
            Ok(Delivery::Message { answers: None, .. })
        ));
        // Whole messages of every other kind, and responses to other
        // requests, still pass: a request may even reuse the number, as the
        // peer's IDs are its own.
        for (message, answers) in [
            (&br#"{"type":"response","id":8,"result":{}}"#[..], Some(8)),
            (
                br#"{"type":"response","id":9,"error":{"code":"busy","message":"b"}}"#,
                Some(9),
            ),
            (
                br#"{"type":"request","id":7,"method":"m","context":{"caller":"chrome"}}"#,
                None,
            ),
            (br#"{"type":"cancel","id":7}"#, None),
            (br#"{"type":"event","event":"e","data":{}}"#, None),
        ] {
            let delivery = r.push(frame(KIND_JSON, message), pending).unwrap();
            assert!(
                matches!(delivery, Delivery::Message { answers: a, .. } if a == answers),
                "{}",
                String::from_utf8_lossy(message)
            );
        }
        assert!(matches!(
            r.push(frame(KIND_CREDIT, b""), pending),
            Ok(Delivery::Credit)
        ));
        assert!(matches!(
            r.push(frame(KIND_LAST, b"cd"), pending),
            Ok(Delivery::Response { id: 7, payload }) if payload.as_slice() == b"abcd"
        ));
    }

    /// Feeds `frames` to a fresh reassembler and returns its first error.
    fn first_error(frames: Vec<Frame>) -> FragmentError {
        let mut r = Reassembler::new();
        for frame in frames {
            if let Err(error) = r.push(frame, pending) {
                // It stays failed.
                assert_eq!(r.push(frame_json(), pending).unwrap_err(), error);
                assert!(!r.in_progress(), "the partial response is dropped");
                return error;
            }
        }
        panic!("no error");
    }

    fn frame_json() -> Frame {
        frame(KIND_JSON, b"{}")
    }

    #[test]
    fn every_protocol_error() {
        use FragmentError::*;
        // A begin while the sender holds no credit: one in reassembly...
        assert_eq!(first_error(vec![begin(7, 10), begin(7, 10)]), NoCredit);
        // ...or one completed whose credit hasn't come back.
        assert_eq!(
            first_error(vec![begin(7, 1), frame(KIND_LAST, b"x"), begin(7, 1)]),
            NoCredit
        );
        // An unknown ID: not a pending request of the receiver's.
        assert_eq!(first_error(vec![begin(8, 10)]), UnknownId(8));
        // A size over the message cap, or none at all.
        assert_eq!(
            first_error(vec![begin(7, MAX_MESSAGE as u64 + 1)]),
            BadSize(MAX_MESSAGE as u64 + 1)
        );
        assert_eq!(first_error(vec![begin(7, u64::MAX)]), BadSize(u64::MAX));
        assert_eq!(first_error(vec![begin(7, 0)]), BadSize(0));
        // A begin that isn't a header.
        assert_eq!(
            first_error(vec![frame(KIND_BEGIN, br#"{"id":7}"#)]),
            BadHeader
        );
        // An empty fragment, or an empty last one.
        assert_eq!(
            first_error(vec![begin(7, 10), frame(KIND_FRAGMENT, b"")]),
            EmptyFragment
        );
        assert_eq!(
            first_error(vec![begin(7, 10), frame(KIND_LAST, b"")]),
            EmptyFragment
        );
        // A fragment or last frame with no response in reassembly.
        assert_eq!(first_error(vec![frame(KIND_FRAGMENT, b"x")]), NoResponse);
        assert_eq!(first_error(vec![frame(KIND_LAST, b"x")]), NoResponse);
        assert_eq!(
            first_error(vec![
                begin(7, 1),
                frame(KIND_LAST, b"x"),
                frame(KIND_LAST, b"y")
            ]),
            NoResponse
        );
        // A length mismatch: past the size, or a last one that leaves it
        // short.
        assert_eq!(
            first_error(vec![begin(7, 3), frame(KIND_FRAGMENT, b"abcd")]),
            LengthMismatch {
                expected: 3,
                got: 4
            }
        );
        assert_eq!(
            first_error(vec![
                begin(7, 3),
                frame(KIND_FRAGMENT, b"ab"),
                frame(KIND_LAST, b"cd")
            ]),
            LengthMismatch {
                expected: 3,
                got: 4
            }
        );
        assert_eq!(
            first_error(vec![begin(7, 3), frame(KIND_LAST, b"ab")]),
            LengthMismatch {
                expected: 3,
                got: 2
            }
        );
        // Complete but not last: the next byte is one too many.
        assert_eq!(
            first_error(vec![
                begin(7, 2),
                frame(KIND_FRAGMENT, b"ab"),
                frame(KIND_LAST, b"c")
            ]),
            LengthMismatch {
                expected: 2,
                got: 3
            }
        );
        // A credit frame with a payload.
        assert_eq!(first_error(vec![frame(KIND_CREDIT, b"x")]), CreditPayload);
        // A whole response for the request whose response has begun, an
        // error or a result, before any fragment or between them.
        assert_eq!(
            first_error(vec![
                begin(7, 10),
                frame(
                    KIND_JSON,
                    br#"{"type":"response","id":7,"error":{"code":"internal","message":"x"}}"#
                )
            ]),
            DuplicateResponse(7)
        );
        assert_eq!(
            first_error(vec![
                begin(7, 10),
                frame(KIND_FRAGMENT, b"abc"),
                frame(KIND_JSON, br#"{"type":"response","id":7,"result":null}"#)
            ]),
            DuplicateResponse(7)
        );
        // A kind that isn't one.
        assert_eq!(first_error(vec![frame(0x02, b"")]), UnexpectedKind(0x02));
    }

    #[test]
    fn the_pending_check_is_asked_only_at_a_begin() {
        let mut r = Reassembler::new();
        let mut asked = Vec::new();
        r.push(begin(7, 2), |id| {
            asked.push(id);
            true
        })
        .unwrap();
        r.push(frame(KIND_LAST, b"{}"), |_| unreachable!()).unwrap();
        assert_eq!(asked, [7]);
    }

    #[test]
    fn debug_never_prints_bodies() {
        let delivery = Delivery::Response {
            id: 7,
            payload: Zeroizing::new(b"SECRET".to_vec()),
        };
        let debug = format!("{delivery:?}");
        assert!(!debug.contains("SECRET"), "{debug}");
        assert!(
            !format!(
                "{:?}",
                Delivery::Message {
                    frame: frame(KIND_JSON, b"SECRET"),
                    answers: None
                }
            )
            .contains("SECRET")
        );
    }

    #[test]
    fn the_credit_frame_decodes_as_credit() {
        let mut d = Decoder::new();
        d.push(&credit_frame()).unwrap();
        let mut r = Reassembler::new();
        assert!(matches!(
            r.push(d.pop().unwrap(), |_| unreachable!()),
            Ok(Delivery::Credit)
        ));
    }
}
