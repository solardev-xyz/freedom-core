//! The side that receives bodies without holding them: `freedom-cored`, for
//! the requests it sends main (design 0009, Streams in the core).
//!
//! Main's [`super::Receiver`] copies every data frame into a ring of its
//! own and credits what its consumer pulls. The core holds no ring: each
//! data frame's bytes go straight to the stream's consumer (a verified
//! request's piece), which holds them in room it reserved for the stream's
//! whole window before asking. The consumer says when bytes have left it,
//! and only then is that credit sent, so credit is granted only for room
//! already reserved, by the side that holds the bytes.
//!
//! **What it holds, per request** the core has sent and not yet seen
//! end: pending until its reply; an open stream's account (`received`,
//! `returned`); after a local cancel, a retirement record until the
//! terminal frame or the reply arrives, while data for it is dropped as it
//! is read.
//!
//! **Checks**, each a protocol error, as main's: data beyond the window
//! (`received − returned > 128 KiB`); a data or terminal frame for a stream
//! that isn't open; a frame for an ID above the highest request sent; a
//! reply that isn't pending; a credit frame, which names the other side's
//! requests and goes to the [`super::Sender`].
//!
//! **Credit from the consumer** is the core's own accounting: crediting
//! more than the stream holds is refused ([`Overcredit`]) without failing
//! the connection.

use std::collections::BTreeMap;

use super::{Abort, ID_LEN, Replied, Retire, StreamError, StreamFrame, WINDOW, check_length};
use crate::frame::{FrameError, KIND_DATA, KIND_STREAM_CREDIT};
use crate::message::check_id;

/// What a stream frame did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arrived {
    /// `len` bytes of stream `id`: the frame's bytes go to its consumer.
    Data { id: u64, len: usize },
    /// Stream `id` is complete. Its record is gone.
    End { id: u64 },
    /// Stream `id` was truncated: error the body.
    Abort { id: u64, abort: Abort },
    /// The stream is retiring: the frame was dropped.
    Dropped { id: u64 },
}

/// A consumer credited more than its stream holds: the core's own bug, and
/// nothing changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("credit of {credit} for stream {id}, which holds {held}")]
pub struct Overcredit {
    pub id: u64,
    pub credit: usize,
    pub held: u64,
}

/// A request's state, as the core holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundState {
    /// Sent; no reply yet.
    Pending,
    /// Retired before its reply.
    RetiredPending,
    /// Its stream is open.
    Open,
    /// Retired while its stream was open: waiting for the terminal.
    Retiring,
}

/// A request's record, for diagnostics and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundInfo {
    pub state: InboundState,
    /// Data bytes that arrived.
    pub received: u64,
    /// Bytes credited back.
    pub returned: u64,
}

#[derive(Debug)]
enum Entry {
    Pending,
    RetiredPending,
    Open { received: u64, returned: u64 },
    Retiring,
}

/// The core's side of the streams it receives on one connection.
#[derive(Debug, Default)]
pub struct Inbound {
    highest: u64,
    entries: BTreeMap<u64, Entry>,
    failed: Option<StreamError>,
}

impl Inbound {
    pub fn new() -> Self {
        Self::default()
    }

    /// The core sent request `id`. Its ID must be above every earlier one
    /// it sent; an error here is the core's own bug.
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
                    *entry = Entry::Open {
                        received: 0,
                        returned: 0,
                    };
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

    /// A data, end or abort frame from main.
    pub fn receive(&mut self, frame: &StreamFrame<'_>) -> Result<Arrived, StreamError> {
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
        let (received, returned) = match self.entries.get_mut(&id) {
            Some(Entry::Open { received, returned }) => (received, *returned),
            Some(Entry::Retiring) => {
                if !matches!(frame, StreamFrame::Data { .. }) {
                    self.entries.remove(&id);
                }
                return Ok(Arrived::Dropped { id });
            }
            _ => return Err(self.fail(StreamError::NotOpen(id))),
        };
        match frame {
            StreamFrame::Data { bytes, .. } => {
                let len = bytes.len();
                let in_window = u64::try_from(len)
                    .ok()
                    .and_then(|len| received.checked_add(len))
                    .filter(|r| r.saturating_sub(returned) <= WINDOW as u64);
                let Some(next) = in_window else {
                    return Err(self.fail(StreamError::Overrun(id)));
                };
                *received = next;
                Ok(Arrived::Data { id, len })
            }
            StreamFrame::End { .. } => {
                self.entries.remove(&id);
                Ok(Arrived::End { id })
            }
            StreamFrame::Abort { abort, .. } => {
                let abort = abort.clone();
                self.entries.remove(&id);
                Ok(Arrived::Abort { id, abort })
            }
            StreamFrame::Credit { .. } => Err(self.fail(StreamError::Frame(
                FrameError::Direction(KIND_STREAM_CREDIT),
            ))),
        }
    }

    /// Stream `id`'s consumer has let go of `n` more bytes: the credit to
    /// send for them, or none when nothing more can come (its end or abort
    /// arrived, it is retiring, or it isn't the core's).
    pub fn credit(&mut self, id: u64, n: usize) -> Result<Option<u32>, Overcredit> {
        if self.failed.is_some() {
            return Ok(None);
        }
        let Some(Entry::Open { received, returned }) = self.entries.get_mut(&id) else {
            return Ok(None);
        };
        let held = *received - *returned;
        let fits = u64::try_from(n).ok().filter(|&n| n <= held);
        let Some(n64) = fits else {
            return Err(Overcredit {
                id,
                credit: n,
                held,
            });
        };
        let Ok(credit) = u32::try_from(n64) else {
            // Within the window, so it fits a u32: unreachable.
            return Ok(None);
        };
        if credit == 0 {
            return Ok(None);
        }
        *returned += n64;
        Ok(Some(credit))
    }

    /// A local cancel of request `id`: its frames are dropped as they come.
    pub fn cancel(&mut self, id: u64) -> Retire {
        match self.entries.get_mut(&id) {
            Some(entry @ Entry::Pending) => {
                *entry = Entry::RetiredPending;
                Retire::SendCancel
            }
            Some(entry @ Entry::Open { .. }) => {
                *entry = Entry::Retiring;
                Retire::SendCancel
            }
            _ => Retire::Nothing,
        }
    }

    /// Request `id`'s record, if it has one.
    pub fn info(&self, id: u64) -> Option<InboundInfo> {
        let info = |state| InboundInfo {
            state,
            received: 0,
            returned: 0,
        };
        Some(match self.entries.get(&id)? {
            Entry::Pending => info(InboundState::Pending),
            Entry::RetiredPending => info(InboundState::RetiredPending),
            Entry::Retiring => info(InboundState::Retiring),
            Entry::Open { received, returned } => InboundInfo {
                state: InboundState::Open,
                received: *received,
                returned: *returned,
            },
        })
    }

    /// Requests with a record: pending, open or retiring.
    pub fn outstanding(&self) -> usize {
        self.entries.len()
    }

    /// The protocol error the connection failed with, if it did.
    pub fn failed(&self) -> Option<StreamError> {
        self.failed
    }

    fn alive(&self) -> Result<(), StreamError> {
        self.failed.map_or(Ok(()), Err)
    }

    /// Fails the connection: every record goes, and every later frame
    /// reports the error.
    pub(crate) fn fail(&mut self, error: StreamError) -> StreamError {
        if self.failed.is_none() {
            self.failed = Some(error);
        }
        self.entries.clear();
        self.failed.unwrap_or(error)
    }
}
