//! Frames: a `u32` big-endian length of everything after it, a `u8` kind,
//! then the payload (design 0001, "Transport and framing").
//!
//! The decoder is sans-I/O: feed it whatever the pipe returned, take out
//! complete frames. Each payload lands in its own exactly sized `Zeroizing`
//! buffer, so a frame that carried a password is wiped when it's dropped and
//! no shared buffer keeps stale bytes in its spare capacity.
//!
//! The decoder holds at most [`MAX_READY_FRAMES`] complete frames. Once the
//! payloads it holds reach [`MAX_READY_BYTES`], it stops taking input; the
//! frame that crosses the threshold is still completed, so it holds less
//! than `MAX_READY_BYTES + MAX_PAYLOAD` bytes (3 MiB). `push` says how much
//! input it consumed. The caller pops frames, then pushes the rest:
//! backpressure, not an error.

use std::collections::VecDeque;

use zeroize::Zeroizing;

/// The largest payload: 1 MiB.
pub const MAX_PAYLOAD: usize = 1 << 20;
/// One JSON message.
pub const KIND_JSON: u8 = 0x01;
/// Kinds `0x02..=0x0F` are reserved for Phase 4 streams (protocol v2).
pub const RESERVED_KINDS: std::ops::RangeInclusive<u8> = 0x02..=0x0F;
/// The most complete frames the decoder holds before `push` stops.
pub const MAX_READY_FRAMES: usize = 64;
/// Payload bytes held in complete frames at which `push` stops taking input
/// (a threshold: the frame that crosses it is still completed).
pub const MAX_READY_BYTES: usize = 2 * MAX_PAYLOAD;

/// A malformed stream. The receiver logs it and closes the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("frame length {0} is zero or above the limit")]
    BadLength(u32),
    #[error("unknown frame kind {0:#04x}")]
    UnknownKind(u8),
}

/// A complete frame.
pub struct Frame {
    pub kind: u8,
    pub payload: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("kind", &self.kind)
            .field("len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// Appends one JSON frame for `payload` to `out`.
pub fn encode_json(payload: &[u8], out: &mut Vec<u8>) -> Result<(), FrameError> {
    let len = u32::try_from(payload.len() + 1).map_err(|_| FrameError::BadLength(u32::MAX))?;
    if payload.len() > MAX_PAYLOAD {
        return Err(FrameError::BadLength(len));
    }
    out.extend_from_slice(&len.to_be_bytes());
    out.push(KIND_JSON);
    out.extend_from_slice(payload);
    Ok(())
}

enum State {
    Header {
        bytes: [u8; 5],
        filled: usize,
    },
    Payload {
        kind: u8,
        payload: Zeroizing<Vec<u8>>,
        needed: usize,
    },
}

const EMPTY_HEADER: State = State::Header {
    bytes: [0; 5],
    filled: 0,
};

/// Turns a byte stream into frames.
pub struct Decoder {
    state: State,
    ready: VecDeque<Frame>,
    ready_bytes: usize,
    failed: Option<FrameError>,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Decoder {
            state: EMPTY_HEADER,
            ready: VecDeque::new(),
            ready_bytes: 0,
            failed: None,
        }
    }

    /// Consumes as much of `input` as the budget allows and returns how many
    /// bytes it took. If that's less than `input.len()`, pop frames and push
    /// the rest. After the first error the decoder stays failed, and frames it
    /// still held are dropped (and wiped): the stream can't be trusted.
    pub fn push(&mut self, input: &[u8]) -> Result<usize, FrameError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let mut consumed = 0;
        while consumed < input.len() {
            if self.ready.len() >= MAX_READY_FRAMES || self.ready_bytes >= MAX_READY_BYTES {
                break;
            }
            let rest = &input[consumed..];
            match &mut self.state {
                State::Header { bytes, filled } => {
                    let take = (5 - *filled).min(rest.len());
                    bytes[*filled..*filled + take].copy_from_slice(&rest[..take]);
                    *filled += take;
                    consumed += take;
                    if *filled == 5 {
                        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                        let kind = bytes[4];
                        let payload_len =
                            usize::try_from(len).unwrap_or(usize::MAX).wrapping_sub(1);
                        if len == 0 || payload_len > MAX_PAYLOAD {
                            return Err(self.fail(FrameError::BadLength(len)));
                        }
                        if kind != KIND_JSON {
                            return Err(self.fail(FrameError::UnknownKind(kind)));
                        }
                        self.state = State::Payload {
                            kind,
                            payload: Zeroizing::new(Vec::with_capacity(payload_len)),
                            needed: payload_len,
                        };
                        self.finish_if_complete();
                    }
                }
                State::Payload {
                    payload, needed, ..
                } => {
                    let take = (*needed - payload.len()).min(rest.len());
                    payload.extend_from_slice(&rest[..take]);
                    consumed += take;
                    self.finish_if_complete();
                }
            }
        }
        Ok(consumed)
    }

    /// The next complete frame, if any.
    pub fn pop(&mut self) -> Option<Frame> {
        let frame = self.ready.pop_front()?;
        self.ready_bytes -= frame.payload.len();
        Some(frame)
    }

    /// True between frames; false if EOF now would cut a frame short.
    pub fn is_at_boundary(&self) -> bool {
        matches!(self.state, State::Header { filled: 0, .. })
    }

    fn finish_if_complete(&mut self) {
        if let State::Payload {
            payload, needed, ..
        } = &self.state
            && payload.len() == *needed
        {
            let done = std::mem::replace(&mut self.state, EMPTY_HEADER);
            if let State::Payload { kind, payload, .. } = done {
                self.ready_bytes += payload.len();
                self.ready.push_back(Frame { kind, payload });
            }
        }
    }

    fn fail(&mut self, error: FrameError) -> FrameError {
        self.failed = Some(error);
        self.ready.clear();
        self.ready_bytes = 0;
        self.state = EMPTY_HEADER;
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds `input` in `chunk`-sized pieces, popping whenever push stops.
    fn frames(input: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        let mut decoder = Decoder::new();
        let mut out = Vec::new();
        for mut piece in input.chunks(chunk) {
            while !piece.is_empty() {
                let consumed = decoder.push(piece).unwrap();
                piece = &piece[consumed..];
                out.extend(std::iter::from_fn(|| decoder.pop()).map(|f| f.payload.to_vec()));
            }
        }
        assert!(decoder.is_at_boundary());
        out
    }

    #[test]
    fn round_trips_in_any_chunking() {
        let mut stream = Vec::new();
        let messages: Vec<Vec<u8>> = vec![
            b"{}".to_vec(),
            vec![b'x'; 70_000],
            b"[1,2,3]".to_vec(),
            Vec::new(),
        ];
        for m in &messages {
            encode_json(m, &mut stream).unwrap();
        }
        for chunk in [1, 2, 5, 7, 4096, stream.len()] {
            assert_eq!(frames(&stream, chunk), messages, "chunk {chunk}");
        }
    }

    #[test]
    fn budget_applies_backpressure() {
        // 200 empty frames in one chunk: push stops at the frame budget.
        let mut stream = Vec::new();
        for _ in 0..200 {
            encode_json(b"", &mut stream).unwrap();
        }
        let mut d = Decoder::new();
        let consumed = d.push(&stream).unwrap();
        assert!(consumed < stream.len());
        assert_eq!(std::iter::from_fn(|| d.pop()).count(), MAX_READY_FRAMES);
        assert_eq!(frames(&stream, stream.len()).len(), 200);

        // Three maximum-size frames: the byte budget stops after two.
        let mut stream = Vec::new();
        for _ in 0..3 {
            encode_json(&vec![b'x'; MAX_PAYLOAD], &mut stream).unwrap();
        }
        let mut d = Decoder::new();
        assert_eq!(d.push(&stream).unwrap(), 2 * (MAX_PAYLOAD + 5));
        assert_eq!(frames(&stream, 1 << 16).len(), 3);
    }

    #[test]
    fn failure_drops_held_frames() {
        let mut stream = Vec::new();
        encode_json(b"{}", &mut stream).unwrap();
        stream.extend_from_slice(&[0, 0, 0, 1, 0x02]);
        let mut d = Decoder::new();
        assert!(d.push(&stream).is_err());
        assert!(d.pop().is_none(), "frames before the bad one are dropped");
    }

    #[test]
    fn rejects_bad_frames_and_stays_failed() {
        let mut d = Decoder::new();
        assert_eq!(d.push(&[0, 0, 0, 0, 1]), Err(FrameError::BadLength(0)));
        assert_eq!(d.push(b"{}"), Err(FrameError::BadLength(0)));

        let mut d = Decoder::new();
        let too_long = u32::try_from(MAX_PAYLOAD + 2).unwrap().to_be_bytes();
        assert!(matches!(
            d.push(&[too_long[0], too_long[1], too_long[2], too_long[3], 1]),
            Err(FrameError::BadLength(_))
        ));

        let mut d = Decoder::new();
        assert_eq!(
            d.push(&[0, 0, 0, 1, 0x02]),
            Err(FrameError::UnknownKind(0x02))
        );
    }

    #[test]
    fn reports_a_cut_frame() {
        let mut stream = Vec::new();
        encode_json(b"{\"a\":1}", &mut stream).unwrap();
        let mut d = Decoder::new();
        d.push(&stream[..stream.len() - 1]).unwrap();
        assert!(!d.is_at_boundary());
        assert!(d.pop().is_none());
    }

    #[test]
    fn payloads_are_exactly_sized() {
        let mut stream = Vec::new();
        encode_json(&[7u8; 1000], &mut stream).unwrap();
        let mut d = Decoder::new();
        d.push(&stream).unwrap();
        let frame = d.pop().unwrap();
        assert_eq!(frame.payload.capacity(), 1000);
    }

    #[test]
    fn encode_rejects_oversized() {
        let mut out = Vec::new();
        assert!(encode_json(&vec![0u8; MAX_PAYLOAD + 1], &mut out).is_err());
        assert!(out.is_empty());
        assert!(encode_json(&vec![0u8; MAX_PAYLOAD], &mut out).is_ok());
    }
}
