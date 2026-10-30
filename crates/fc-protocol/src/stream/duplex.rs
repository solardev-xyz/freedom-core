//! Both ends of the streams on one connection: `freedom-cored`'s, at
//! protocol 2 (design 0009, Streams in the core).
//!
//! A stream is the body of a response, sent by whichever side answers the
//! request, and its ID is the request's, in the requester's ID space. So
//! the core holds two sets of streams on one connection:
//! - **the bodies it sends** in answer to main's requests (`dweb.verify`):
//!   a [`Sender`], whose IDs are main's;
//! - **the bodies it receives** in answer to its own requests
//!   (`shell.dweb_get`): an [`Inbound`], whose IDs are the core's.
//!
//! The same number may name a stream in each at once. A stream frame's
//! kind says which: data, end and abort reaching the core name one of its
//! own requests, and credit names one it answered. A frame the wrong set
//! doesn't hold is a protocol error there, and the connection fails as a
//! whole: neither side takes or writes anything more.
//!
//! **The writer.** Credit the core owes main for what its consumers let go
//! of is control, written ahead of the sender's frames, merged per stream
//! while unwritten, and dropped when the core cancels the request or the
//! stream's terminal arrives. So what waits to be written of it is bounded
//! by the open streams.

use std::collections::{BTreeMap, VecDeque};

use super::{
    Arrived, Cancel, Credited, Inbound, Overcredit, Replied, Retire, Sender, StreamError,
    StreamFrame, Written, put_header,
};
use crate::frame::KIND_STREAM_CREDIT;

/// What a stream frame from main did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// Credit for a body the core sends.
    Credited(Credited),
    /// Data, end or abort of a body the core receives.
    Arrived(Arrived),
}

/// The frame [`Duplex::next_frame`] wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrote {
    /// Credit for stream `id`, one of the core's own requests: `n` bytes.
    Credit { id: u64, n: u32 },
    /// A frame of a body the core sends, or a response's head or reply.
    Sent(Written),
}

/// The core's streams on one connection, in both directions.
#[derive(Default)]
pub struct Duplex {
    sender: Sender,
    inbound: Inbound,
    /// Credit owed and unwritten, per stream, and the order it came in.
    owed: BTreeMap<u64, u32>,
    order: VecDeque<u64>,
    failed: Option<StreamError>,
}

impl Duplex {
    pub fn new() -> Self {
        Self::default()
    }

    /// A duplex whose sender's writer holds at most `data_cap` queued body
    /// bytes ([`Sender::with_data_cap`]).
    pub fn with_data_cap(data_cap: usize) -> Self {
        Self {
            sender: Sender::with_data_cap(data_cap),
            ..Self::default()
        }
    }

    /// The bodies the core sends: main's requests, their heads, replies and
    /// bodies.
    pub fn sender(&self) -> &Sender {
        &self.sender
    }

    /// For the core's producers: heads, replies and bodies. Main's
    /// requests, cancels and credit go through the duplex
    /// ([`Duplex::request`], [`Duplex::cancel`], [`Duplex::receive`]), so a
    /// protocol error in them fails both directions.
    pub fn sender_mut(&mut self) -> &mut Sender {
        &mut self.sender
    }

    /// The bodies the core receives: its own requests and their replies.
    pub fn inbound(&self) -> &Inbound {
        &self.inbound
    }

    // ---- main's requests, which the core answers --------------------------

    /// Main sent request `id` ([`Sender::request`]).
    pub fn request(&mut self, id: u64) -> Result<(), StreamError> {
        self.alive()?;
        let result = self.sender.request(id);
        result.map_err(|error| self.fail(error))
    }

    /// Main cancelled its request `id` ([`Sender::cancel`]).
    pub fn cancel(&mut self, id: u64) -> Result<Cancel, StreamError> {
        self.alive()?;
        let result = self.sender.cancel(id);
        result.map_err(|error| self.fail(error))
    }

    // ---- the core's requests, which main answers ---------------------------

    /// The core sent request `id` ([`Inbound::request`]): an error is the
    /// core's own bug, and the connection is fine.
    pub fn ask(&mut self, id: u64) -> Result<(), StreamError> {
        self.alive()?;
        self.inbound.request(id)
    }

    /// Main's reply to the core's request `id` arrived ([`Inbound::reply`]).
    pub fn answered(&mut self, id: u64, opens: bool) -> Result<Replied, StreamError> {
        self.alive()?;
        let result = self.inbound.reply(id, opens);
        result.map_err(|error| self.fail(error))
    }

    /// A stream frame from main, by its kind: credit to the sender; data,
    /// end and abort to the inbound streams.
    pub fn receive(&mut self, frame: StreamFrame<'_>) -> Result<Received, StreamError> {
        self.alive()?;
        let result = match frame {
            StreamFrame::Credit { .. } => self.sender.receive(frame).map(Received::Credited),
            _ => self.inbound.receive(&frame).map(Received::Arrived),
        };
        // Credit owed for a stream whose terminal came would cross it: it
        // goes, so what is owed is bounded by the open streams.
        if let Ok(Received::Arrived(Arrived::End { id } | Arrived::Abort { id, .. })) = &result {
            self.owed.remove(id);
        }
        result.map_err(|error| self.fail(error))
    }

    /// Stream `id`'s consumer has let go of `n` more bytes: their credit is
    /// owed to main, written ahead of the sender's frames. Nothing is owed
    /// once the stream has ended or retired.
    pub fn release(&mut self, id: u64, n: usize) -> Result<(), Overcredit> {
        if self.failed.is_some() {
            return Ok(());
        }
        let Some(credit) = self.inbound.credit(id, n)? else {
            return Ok(());
        };
        match self.owed.get_mut(&id) {
            // Within the window, so the sum fits.
            Some(owed) => *owed = owed.saturating_add(credit),
            None => {
                self.owed.insert(id, credit);
                self.order.push_back(id);
            }
        }
        Ok(())
    }

    /// The core cancels its own request `id`: what is owed for it is
    /// dropped, and its frames are dropped as they come.
    pub fn withdraw(&mut self, id: u64) -> Retire {
        self.owed.remove(&id);
        self.inbound.cancel(id)
    }

    /// Appends the next frame to write to `out` and says what it was, or
    /// returns `None` when there is nothing to write: credit first, then the
    /// sender's control entries, then its streams.
    pub fn next_frame(&mut self, out: &mut Vec<u8>) -> Option<Wrote> {
        if self.failed.is_some() {
            return None;
        }
        if let Some(credit) = self.next_credit(out) {
            return Some(credit);
        }
        self.sender.next_frame(out).map(Wrote::Sent)
    }

    /// As [`Duplex::next_frame`], with a head's or a reply's JSON handed
    /// over rather than copied ([`Sender::next_frame_owned`]).
    pub fn next_frame_owned(&mut self, out: &mut Vec<u8>) -> Option<(Wrote, Option<Vec<u8>>)> {
        if self.failed.is_some() {
            return None;
        }
        if let Some(credit) = self.next_credit(out) {
            return Some((credit, None));
        }
        self.sender
            .next_frame_owned(out)
            .map(|(w, json)| (Wrote::Sent(w), json))
    }

    /// The oldest credit owed, written.
    fn next_credit(&mut self, out: &mut Vec<u8>) -> Option<Wrote> {
        while let Some(id) = self.order.pop_front() {
            // None when a withdrawal dropped it.
            if let Some(n) = self.owed.remove(&id) {
                put_header(out, KIND_STREAM_CREDIT, id, 4);
                out.extend_from_slice(&n.to_be_bytes());
                return Some(Wrote::Credit { id, n });
            }
        }
        None
    }

    /// Credit owed and unwritten: one entry per stream at most.
    pub fn owed(&self) -> usize {
        self.owed.len()
    }

    /// The protocol error the connection failed with, if it did.
    pub fn failed(&self) -> Option<StreamError> {
        self.failed
    }

    fn alive(&self) -> Result<(), StreamError> {
        self.failed.map_or(Ok(()), Err)
    }

    /// Fails the connection as a whole: both sides drop what they hold and
    /// take nothing more.
    fn fail(&mut self, error: StreamError) -> StreamError {
        let error = *self.failed.get_or_insert(error);
        self.sender.fail(error);
        self.inbound.fail(error);
        self.owed.clear();
        self.order.clear();
        error
    }
}
