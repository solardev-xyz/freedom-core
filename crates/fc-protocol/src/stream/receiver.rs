//! The side that receives bodies: main (design 0007, Frames and Main's
//! side).
//!
//! **What it holds, per request** main has sent and not yet seen end:
//! - pending, until its reply; a reply that is a head with a body opens
//!   its stream, any other reply ends it;
//! - an open stream: its account (`received`, `returned`), whether `end`
//!   arrived, and its ring;
//! - after a local cancel, a retirement record until the terminal frame or
//!   the reply arrives: data for it is dropped as it is read.
//!
//! **The ring.** One buffer of exactly the window (128 KiB) per stream,
//! allocated at its first data. Every data frame is copied into it, so
//! what main holds for a stream never depends on frame sizes. `end` only
//! records EOF; the ring goes once the consumer has drained it after EOF,
//! and at once on `abort` or a local cancel. A pull copies up to 64 KiB
//! into a fresh chunk the consumer owns, and credits those bytes. Main's
//! writer merges the credit it hasn't written yet per stream, and drops it
//! on a local cancel, so its queue of credit and cancels stays bounded by
//! the live streams; the sum never passes what arrived, which fits a `u32`.
//!
//! **Checks**, each a protocol error: data beyond the window
//! (`received − returned > 128 KiB`); a data or terminal frame for a
//! stream that isn't open (before its head, after a head without a body or
//! an error reply, after its terminal); a frame for an ID above the highest
//! request sent; a reply that isn't pending.

use std::collections::BTreeMap;

use super::{Abort, ID_LEN, MAX_PULL, StreamError, StreamFrame, WINDOW, check_length};
use crate::frame::{FrameError, KIND_DATA, KIND_STREAM_CREDIT};
use crate::message::check_id;

/// What a reply did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replied {
    /// Hand it to the request's caller. With a body, the stream is open.
    Deliver,
    /// The request was retired: drop it. With a body, the stream is
    /// retiring until its terminal arrives.
    Retired,
}

/// What a stream frame did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// `len` bytes of stream `id` are in its ring.
    Data { id: u64, len: usize },
    /// Stream `id` is complete. `drained`: nothing is left to pull, and its
    /// record and ring are gone; otherwise the last pull ends it.
    End { id: u64, drained: bool },
    /// Stream `id` was truncated: error the body. Its ring is gone.
    Abort { id: u64, abort: Abort },
    /// The stream is retiring: the frame was dropped.
    Dropped { id: u64 },
}

/// A pull's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pulled {
    /// The bytes, in a chunk of their own.
    pub chunk: Vec<u8>,
    /// The credit to send for them: this many bytes of the window, back to
    /// the service. None once `end` has arrived, when nothing more can
    /// come.
    pub credit: Option<u32>,
    /// The chunk is the body's last: its record and ring are gone.
    pub eof: bool,
}

/// What a local cancel did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retire {
    /// Send `cancel`, and no more credit. The request is retiring.
    SendCancel,
    /// Its `end` had arrived: the bytes left are dropped, and nothing is
    /// sent.
    Freed,
    /// Not pending, not open: nothing to do.
    Nothing,
}

/// A request's state, as main holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Sent; no reply yet.
    Pending,
    /// Retired before its reply.
    RetiredPending,
    /// Its stream is open.
    Open,
    /// Its `end` arrived; bytes are left to pull.
    Eof,
    /// Retired while its stream was open: waiting for the terminal.
    Retiring,
}

/// A request's record, for diagnostics and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamInfo {
    pub state: StreamState,
    /// Whether its ring is allocated.
    pub ring: bool,
    /// Bytes in the ring.
    pub buffered: usize,
    /// Data bytes that arrived.
    pub received: u64,
    /// Bytes credited back.
    pub returned: u64,
}

enum Entry {
    Pending,
    RetiredPending,
    Open(Inflow),
    Retiring,
}

#[derive(Default)]
struct Inflow {
    ring: Option<Ring>,
    received: u64,
    returned: u64,
    eof: bool,
}

impl Inflow {
    fn buffered(&self) -> usize {
        self.ring.as_ref().map_or(0, |ring| ring.len)
    }
}

/// Main's side of every stream on one connection, for one generation of
/// the service.
#[derive(Default)]
pub struct Receiver {
    highest: u64,
    entries: BTreeMap<u64, Entry>,
    failed: Option<StreamError>,
}

impl Receiver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Main sent request `id`. Its ID must be above every earlier one; an
    /// error here is main's own bug, not the connection's.
    pub fn request(&mut self, id: u64) -> Result<(), StreamError> {
        self.alive()?;
        check_id(id).map_err(|_| StreamError::BadId(id))?;
        if id <= self.highest {
            return Err(StreamError::RequestOrder {
                id,
                highest: self.highest,
            });
        }
        self.highest = id;
        self.entries.insert(id, Entry::Pending);
        Ok(())
    }

    /// The reply to request `id` arrived; `opens` if it is a head that says
    /// `body: true`.
    pub fn reply(&mut self, id: u64, opens: bool) -> Result<Replied, StreamError> {
        self.alive()?;
        let replied = match self.entries.get_mut(&id) {
            Some(entry @ Entry::Pending) => {
                if opens {
                    *entry = Entry::Open(Inflow::default());
                    return Ok(Replied::Deliver);
                }
                Replied::Deliver
            }
            Some(entry @ Entry::RetiredPending) => {
                if opens {
                    *entry = Entry::Retiring;
                    return Ok(Replied::Retired);
                }
                Replied::Retired
            }
            _ => return Err(self.fail(StreamError::UnsolicitedResponse(id))),
        };
        self.entries.remove(&id);
        Ok(replied)
    }

    /// A stream frame from the service.
    pub fn receive(&mut self, frame: StreamFrame<'_>) -> Result<Delivery, StreamError> {
        self.alive()?;
        let id = frame.id();
        if let StreamFrame::Credit { .. } = frame {
            return Err(self.fail(StreamError::Frame(FrameError::Direction(
                KIND_STREAM_CREDIT,
            ))));
        }
        if let StreamFrame::Data { bytes, .. } = frame
            && let Err(error) = check_length(KIND_DATA, ID_LEN.saturating_add(bytes.len()))
        {
            return Err(self.fail(StreamError::Frame(error)));
        }
        if id > self.highest {
            return Err(self.fail(StreamError::Unknown(id)));
        }
        let flow = match self.entries.get_mut(&id) {
            Some(Entry::Open(flow)) if !flow.eof => flow,
            Some(Entry::Retiring) => {
                if !matches!(frame, StreamFrame::Data { .. }) {
                    self.entries.remove(&id);
                }
                return Ok(Delivery::Dropped { id });
            }
            _ => return Err(self.fail(StreamError::NotOpen(id))),
        };
        match frame {
            StreamFrame::Data { bytes, .. } => {
                let len = bytes.len();
                let in_window = u64::try_from(len)
                    .ok()
                    .and_then(|len| flow.received.checked_add(len))
                    .filter(|received| received.saturating_sub(flow.returned) <= WINDOW as u64);
                let Some(received) = in_window else {
                    return Err(self.fail(StreamError::Overrun(id)));
                };
                if !flow.ring.get_or_insert_with(Ring::new).push(bytes) {
                    return Err(self.fail(StreamError::Overrun(id)));
                }
                flow.received = received;
                Ok(Delivery::Data { id, len })
            }
            StreamFrame::End { .. } => {
                flow.eof = true;
                let drained = flow.buffered() == 0;
                if drained {
                    self.entries.remove(&id);
                }
                Ok(Delivery::End { id, drained })
            }
            StreamFrame::Abort { abort, .. } => {
                self.entries.remove(&id);
                Ok(Delivery::Abort { id, abort })
            }
            StreamFrame::Credit { .. } => Err(self.fail(StreamError::Frame(
                FrameError::Direction(KIND_STREAM_CREDIT),
            ))),
        }
    }

    /// The consumer of stream `id` pulls up to `max` bytes (at most 64 KiB).
    /// `None` if the stream has no record: never opened, ended or retired.
    pub fn pull(&mut self, id: u64, max: usize) -> Option<Pulled> {
        let Some(Entry::Open(flow)) = self.entries.get_mut(&id) else {
            return None;
        };
        let n = max.min(MAX_PULL).min(flow.buffered());
        let chunk = flow
            .ring
            .as_mut()
            .map_or_else(Vec::new, |ring| ring.pull(n));
        let credit = match u32::try_from(n) {
            Ok(n) if n > 0 && !flow.eof => {
                flow.returned += u64::from(n);
                Some(n)
            }
            _ => None,
        };
        let eof = flow.eof && flow.buffered() == 0;
        if eof {
            self.entries.remove(&id);
        }
        Some(Pulled { chunk, credit, eof })
    }

    /// A local cancel of request `id`: its bytes are dropped at once.
    pub fn cancel(&mut self, id: u64) -> Retire {
        match self.entries.get_mut(&id) {
            Some(entry @ Entry::Pending) => {
                *entry = Entry::RetiredPending;
                Retire::SendCancel
            }
            Some(entry @ Entry::Open(_)) => {
                if matches!(entry, Entry::Open(Inflow { eof: true, .. })) {
                    self.entries.remove(&id);
                    return Retire::Freed;
                }
                *entry = Entry::Retiring;
                Retire::SendCancel
            }
            _ => Retire::Nothing,
        }
    }

    /// Request `id`'s record, if it has one.
    pub fn info(&self, id: u64) -> Option<StreamInfo> {
        let info = |state| StreamInfo {
            state,
            ring: false,
            buffered: 0,
            received: 0,
            returned: 0,
        };
        Some(match self.entries.get(&id)? {
            Entry::Pending => info(StreamState::Pending),
            Entry::RetiredPending => info(StreamState::RetiredPending),
            Entry::Retiring => info(StreamState::Retiring),
            Entry::Open(flow) => StreamInfo {
                state: if flow.eof {
                    StreamState::Eof
                } else {
                    StreamState::Open
                },
                ring: flow.ring.is_some(),
                buffered: flow.buffered(),
                received: flow.received,
                returned: flow.returned,
            },
        })
    }

    /// Requests with a record: pending, open or retiring. Retiring ones
    /// count against main's outstanding requests.
    pub fn outstanding(&self) -> usize {
        self.entries.len()
    }

    /// The bytes main's rings take, in all.
    pub fn ring_bytes(&self) -> usize {
        self.entries
            .values()
            .map(|entry| match entry {
                Entry::Open(Inflow {
                    ring: Some(ring), ..
                }) => ring.buf.len(),
                _ => 0,
            })
            .sum()
    }

    /// The protocol error the connection failed with, if it did.
    pub fn failed(&self) -> Option<StreamError> {
        self.failed
    }

    fn alive(&self) -> Result<(), StreamError> {
        self.failed.map_or(Ok(()), Err)
    }

    /// Fails the connection: every record and ring goes, and every later
    /// frame reports the error.
    fn fail(&mut self, error: StreamError) -> StreamError {
        self.failed = Some(error);
        self.entries.clear();
        error
    }
}

/// A stream's bytes in main: one buffer of exactly the window.
struct Ring {
    buf: Box<[u8]>,
    start: usize,
    len: usize,
}

impl Ring {
    fn new() -> Self {
        Ring {
            buf: vec![0; WINDOW].into_boxed_slice(),
            start: 0,
            len: 0,
        }
    }

    /// Copies `bytes` in, if they fit.
    fn push(&mut self, bytes: &[u8]) -> bool {
        let cap = self.buf.len();
        if bytes.len() > cap - self.len {
            return false;
        }
        let tail = (self.start + self.len) % cap;
        let (first, rest) = bytes.split_at(bytes.len().min(cap - tail));
        self.buf[tail..tail + first.len()].copy_from_slice(first);
        self.buf[..rest.len()].copy_from_slice(rest);
        self.len += bytes.len();
        true
    }

    /// Copies up to `n` bytes out, into a chunk of exactly their size.
    fn pull(&mut self, n: usize) -> Vec<u8> {
        let cap = self.buf.len();
        let n = n.min(self.len);
        let mut chunk = Vec::with_capacity(n);
        let first = n.min(cap - self.start);
        chunk.extend_from_slice(&self.buf[self.start..self.start + first]);
        chunk.extend_from_slice(&self.buf[..n - first]);
        self.start = (self.start + n) % cap;
        self.len -= n;
        chunk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ring_wraps_and_keeps_order() {
        let mut ring = Ring::new();
        let bytes: Vec<u8> = (0..WINDOW).map(|i| (i % 251) as u8).collect();
        assert!(ring.push(&bytes[..100_000]));
        assert_eq!(ring.pull(90_000), bytes[..90_000]);
        assert!(ring.push(&bytes[100_000..]));
        assert!(ring.push(&bytes[..90_000]), "exactly full");
        assert_eq!(ring.len, WINDOW);
        assert!(!ring.push(&[1]), "nothing past the window");
        let out = ring.pull(WINDOW);
        assert_eq!(out.capacity(), WINDOW);
        assert_eq!(out[..WINDOW - 90_000], bytes[90_000..]);
        assert_eq!(out[WINDOW - 90_000..], bytes[..90_000]);
        assert!(ring.pull(1).is_empty());
    }
}
