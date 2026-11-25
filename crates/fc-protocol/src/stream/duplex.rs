//! Both ends of the streams on one connection: `freedom-cored`'s, at
//! protocol 2 (design 0009, Streams in the core; design 0015's Swarm
//! thread: [`Duplex::swarm`]), and a service's that takes main's bodies
//! (design 0014, COL-3: [`Duplex::service`]).
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
//! while unwritten, and dropped when the core cancels the request, the
//! stream's terminal arrives or the stream breaks the length its head gave
//! it ([`Duplex::answered_sized`]): its amount and its place in the
//! writer's order together, in one step. So what waits to be written of
//! it, every record included, is bounded by the open streams.

use std::collections::BTreeMap;

use super::{
    Arrived, Cancel, Codes, Credited, Inbound, Overcredit, Replied, Retire, Sender, StreamError,
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
pub struct Duplex {
    sender: Sender,
    inbound: Inbound,
    /// Credit owed and unwritten, per stream: its place in `order`, and the
    /// bytes.
    owed: BTreeMap<u64, (u64, u32)>,
    /// The streams owed credit, by when their credit came. Each entry is a
    /// stream in `owed`, and each stream in `owed` has one: both change
    /// together ([`Duplex::owe`], [`Duplex::drop_owed`],
    /// [`Duplex::next_credit`]).
    order: BTreeMap<u64, u64>,
    next_place: u64,
    failed: Option<StreamError>,
}

impl Default for Duplex {
    fn default() -> Self {
        Self::new()
    }
}

impl Duplex {
    /// The core's streams: its verified bodies end only with 0009's codes,
    /// and main's pieces only with a piece's ([`Codes`]).
    pub fn new() -> Self {
        Self::with_data_cap(super::WRITER_DATA_CAP)
    }

    /// A duplex whose sender's writer holds at most `data_cap` queued body
    /// bytes ([`Sender::with_data_cap`]).
    pub fn with_data_cap(data_cap: usize) -> Self {
        Self::with_sender(Sender::with_data_cap(data_cap).with_codes(Codes::CoreBody))
    }

    /// A service connection's streams, for a service that takes main's
    /// bodies (design 0014, COL-3): the bodies it sends keep 0007's five
    /// codes, as every service's do, and main's end only with a piece's
    /// ([`Codes`]). Its sender's writer holds at most `data_cap` queued body
    /// bytes.
    pub fn service(data_cap: usize) -> Self {
        Self::with_sender(Sender::with_data_cap(data_cap).with_codes(Codes::Service))
    }

    /// The Swarm thread's streams (design 0015, Streams): the `swarm.body`
    /// uploads it sends main end only with an upload's codes
    /// ([`Codes::CoreUpload`]), and main's bodies with their own request's
    /// ([`Duplex::ask_with`]): a part's, or a `shell.swarm_api` body's,
    /// which may also end `too_large`. Its sender's writer holds at most
    /// `data_cap` queued body bytes: 4 uploads' 128 KiB windows, 512 KiB.
    pub fn swarm(data_cap: usize) -> Self {
        Self::with_sender(Sender::with_data_cap(data_cap).with_codes(Codes::CoreUpload))
    }

    fn with_sender(sender: Sender) -> Self {
        Self {
            sender,
            inbound: Inbound::new(),
            owed: BTreeMap::new(),
            order: BTreeMap::new(),
            next_place: 0,
            failed: None,
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
        self.ask_with(id, Codes::Piece)
    }

    /// The core sent request `id`, whose stream main ends only with
    /// `codes` ([`Inbound::request_with`]): [`Codes::SwarmPiece`] for a
    /// `shell.swarm_api` body (design 0015). As [`Duplex::ask`] otherwise.
    pub fn ask_with(&mut self, id: u64, codes: Codes) -> Result<(), StreamError> {
        self.alive()?;
        self.inbound.request_with(id, codes)
    }

    /// Main's reply to the core's request `id` arrived ([`Inbound::reply`]).
    pub fn answered(&mut self, id: u64, opens: bool) -> Result<Replied, StreamError> {
        self.alive()?;
        let result = self.inbound.reply(id, opens);
        result.map_err(|error| self.fail(error))
    }

    /// Main's reply to the core's request `id` arrived: a head that opens a
    /// body of exactly `len` bytes ([`Inbound::reply_sized`], design 0014).
    pub fn answered_sized(&mut self, id: u64, len: u64) -> Result<Replied, StreamError> {
        self.alive()?;
        let result = self.inbound.reply_sized(id, len);
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
        // Credit owed for a stream whose terminal came would cross it, and a
        // stream that broke its length takes no more: it goes, so what is
        // owed is bounded by the open streams.
        if let Ok(Received::Arrived(
            Arrived::End { id } | Arrived::Abort { id, .. } | Arrived::Mismatch { id, .. },
        )) = &result
        {
            self.drop_owed(*id);
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
        self.owe(id, credit);
        Ok(())
    }

    /// Adds `credit` to what is owed for stream `id`, in its place, or at
    /// the end of the order when nothing was owed.
    fn owe(&mut self, id: u64, credit: u32) {
        match self.owed.get_mut(&id) {
            // Within the window, so the sum fits.
            Some((_, owed)) => *owed = owed.saturating_add(credit),
            None => {
                let place = self.next_place;
                self.next_place = place.wrapping_add(1);
                self.owed.insert(id, (place, credit));
                self.order.insert(place, id);
            }
        }
    }

    /// Drops what is owed for stream `id`, and its place in the order.
    fn drop_owed(&mut self, id: u64) {
        if let Some((place, _)) = self.owed.remove(&id) {
            self.order.remove(&place);
        }
    }

    /// The core cancels its own request `id`: what is owed for it is
    /// dropped, and its frames are dropped as they come.
    pub fn withdraw(&mut self, id: u64) -> Retire {
        self.drop_owed(id);
        self.inbound.cancel(id)
    }

    /// The connection ended: nothing more comes for the core's own
    /// requests. Their records go ([`Inbound::close`]), and the credit owed
    /// for them, so the writer writes nothing of them; the sender's streams
    /// stay as they are, for the answers still owed to main (design 0014,
    /// COL-3: a service's teardown).
    pub fn close_inbound(&mut self) {
        self.inbound.close();
        self.owed.clear();
        self.order.clear();
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
        let (_, id) = self.order.pop_first()?;
        let (_, n) = self.owed.remove(&id)?;
        put_header(out, KIND_STREAM_CREDIT, id, 4);
        out.extend_from_slice(&n.to_be_bytes());
        Some(Wrote::Credit { id, n })
    }

    /// Streams owed credit that isn't written yet: the records the writer's
    /// order holds, one per stream at most, and none for a stream that has
    /// ended or been withdrawn.
    pub fn owed(&self) -> usize {
        self.order.len()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::{Abort, AbortCode, InboundState};

    /// Both records of owed credit move together.
    fn check(d: &Duplex) {
        assert_eq!(d.owed.len(), d.order.len());
        assert!(d.order.len() <= d.inbound.outstanding());
        for (place, id) in &d.order {
            assert_eq!(d.owed.get(id).map(|(p, _)| p), Some(place), "{id}");
        }
    }

    /// A stream whose credit is owed, unwritten, when it goes: by its end,
    /// its abort, or the core's withdrawal. The writer is never polled, so
    /// nothing is taken off the order by writing it.
    #[test]
    fn owed_credit_leaves_no_record_behind_its_stream() {
        let mut d = Duplex::new();
        for id in 1..=30_000u64 {
            d.ask(id).unwrap();
            check(&d);
            d.answered(id, true).unwrap();
            d.receive(StreamFrame::Data { id, bytes: &[7] }).unwrap();
            d.release(id, 1).unwrap();
            assert_eq!(d.owed(), 1);
            check(&d);
            match id % 3 {
                0 => {
                    d.receive(StreamFrame::End { id }).unwrap();
                }
                1 => {
                    d.receive(StreamFrame::Abort {
                        id,
                        abort: Abort::new(AbortCode::BodyStreamError, "the node's body failed"),
                    })
                    .unwrap();
                }
                _ => {
                    assert_eq!(d.withdraw(id), Retire::SendCancel);
                    check(&d);
                    d.receive(StreamFrame::End { id }).unwrap();
                }
            }
            check(&d);
            assert_eq!((d.owed(), d.order.len(), d.owed.len()), (0, 0, 0), "{id}");
        }
        assert_eq!(d.inbound.outstanding(), 0);
        let mut out = Vec::new();
        assert_eq!(d.next_frame(&mut out), None);
    }

    /// Design 0014: a body held to its head's length fails alone when it
    /// breaks it. Past the length it retires, with what was owed for it
    /// dropped; short at its end its record goes. A body as long as its
    /// head ends as any other, and the other streams go on.
    #[test]
    fn a_body_that_breaks_its_length_fails_alone() {
        let mut d = Duplex::service(1 << 20);
        for id in 1..=4u64 {
            d.ask(id).unwrap();
        }
        assert_eq!(d.answered_sized(1, 3), Ok(Replied::Deliver));
        assert_eq!(d.answered_sized(2, 3), Ok(Replied::Deliver));
        assert_eq!(d.answered_sized(3, 3), Ok(Replied::Deliver));
        assert_eq!(d.answered(4, true), Ok(Replied::Deliver));
        for id in 1..=4u64 {
            d.receive(StreamFrame::Data { id, bytes: &[7, 7] }).unwrap();
            d.release(id, 1).unwrap();
        }
        assert_eq!(d.owed(), 4);
        // 1: one byte past its length.
        assert_eq!(
            d.receive(StreamFrame::Data {
                id: 1,
                bytes: &[7, 7]
            }),
            Ok(Received::Arrived(Arrived::Mismatch {
                id: 1,
                declared: 3,
                received: 4,
                retire: Retire::SendCancel,
            }))
        );
        check(&d);
        assert_eq!(d.owed(), 3);
        assert_eq!(
            d.inbound().info(1).map(|info| info.state),
            Some(InboundState::Retiring)
        );
        assert_eq!(d.release(1, 1), Ok(()));
        assert_eq!(d.withdraw(1), Retire::Nothing);
        assert_eq!(
            d.receive(StreamFrame::Data { id: 1, bytes: &[7] }),
            Ok(Received::Arrived(Arrived::Dropped { id: 1 }))
        );
        assert_eq!(
            d.receive(StreamFrame::Abort {
                id: 1,
                abort: Abort::cancelled(),
            }),
            Ok(Received::Arrived(Arrived::Dropped { id: 1 }))
        );
        assert_eq!(d.inbound().info(1), None);
        // 2: one byte short at its end.
        assert_eq!(
            d.receive(StreamFrame::End { id: 2 }),
            Ok(Received::Arrived(Arrived::Mismatch {
                id: 2,
                declared: 3,
                received: 2,
                retire: Retire::Nothing,
            }))
        );
        check(&d);
        assert_eq!((d.owed(), d.inbound().info(2)), (2, None));
        // 3: exactly its length; 4: no length at all.
        d.receive(StreamFrame::Data { id: 3, bytes: &[7] }).unwrap();
        assert_eq!(
            d.receive(StreamFrame::End { id: 3 }),
            Ok(Received::Arrived(Arrived::End { id: 3 }))
        );
        d.receive(StreamFrame::Data {
            id: 4,
            bytes: &[7; 100],
        })
        .unwrap();
        assert_eq!(
            d.receive(StreamFrame::End { id: 4 }),
            Ok(Received::Arrived(Arrived::End { id: 4 }))
        );
        check(&d);
        assert_eq!((d.owed(), d.inbound().outstanding()), (0, 0));
        assert_eq!(d.failed(), None);
    }

    /// The connection's end (0014, COL-3): every request of the core's
    /// goes, pending, open with credit owed, or retiring, and nothing of
    /// them is written; main's request keeps its queued reply.
    #[test]
    fn closing_the_inbound_half_leaves_the_senders_answers() {
        let mut d = Duplex::service(1 << 20);
        d.request(1).unwrap();
        d.sender_mut().reply(1, b"{}".to_vec()).unwrap();
        d.ask(1).unwrap();
        for id in 2..=3u64 {
            d.ask(id).unwrap();
            d.answered(id, true).unwrap();
            d.receive(StreamFrame::Data { id, bytes: &[7, 7] }).unwrap();
            d.release(id, 1).unwrap();
        }
        assert_eq!(d.withdraw(3), Retire::SendCancel);
        assert_eq!(d.ask(4), Ok(()));
        assert_eq!((d.inbound.outstanding(), d.owed()), (4, 1));
        d.close_inbound();
        check(&d);
        assert_eq!((d.inbound.outstanding(), d.owed()), (0, 0));
        for id in 1..=4 {
            assert_eq!(d.inbound().info(id), None, "{id}");
        }
        // Nothing more is owed for what the consumer lets go of.
        assert_eq!(d.release(2, 1), Ok(()));
        assert_eq!(d.owed(), 0);
        let mut out = Vec::new();
        assert_eq!(
            d.next_frame(&mut out),
            Some(Wrote::Sent(Written::Reply { id: 1 }))
        );
        out.clear();
        assert_eq!(d.next_frame(&mut out), None);
        assert_eq!(d.failed(), None);
    }

    /// Design 0015: each of the core's requests carries its stream's codes.
    /// `too_large` ends only a `shell.swarm_api` body; a part's stream, or
    /// any other piece, ending with it is a protocol error. A retiring
    /// stream keeps its codes. An abort for no record of the core's is
    /// checked against every code some stream of its takes, so one no
    /// stream takes is refused as such, before its ID is.
    #[test]
    fn each_request_carries_its_streams_codes() {
        let too_large = || Abort::new(AbortCode::TooLarge, "past max_bytes");
        let mut d = Duplex::swarm(512 << 10);
        d.ask_with(1, Codes::SwarmPiece).unwrap();
        d.ask(2).unwrap();
        d.ask_with(3, Codes::SwarmPiece).unwrap();
        for id in 1..=2 {
            d.answered(id, true).unwrap();
            d.receive(StreamFrame::Data { id, bytes: &[7] }).unwrap();
        }
        assert_eq!(
            d.receive(StreamFrame::Abort {
                id: 1,
                abort: too_large()
            }),
            Ok(Received::Arrived(Arrived::Abort {
                id: 1,
                abort: too_large()
            }))
        );
        // Retiring, before its head: its codes hold, and take `too_large`.
        assert_eq!(d.withdraw(3), Retire::SendCancel);
        assert_eq!(d.answered(3, true), Ok(Replied::Retired));
        assert_eq!(
            d.receive(StreamFrame::Abort {
                id: 3,
                abort: too_large()
            }),
            Ok(Received::Arrived(Arrived::Dropped { id: 3 }))
        );
        assert_eq!(
            d.receive(StreamFrame::Abort {
                id: 2,
                abort: too_large()
            }),
            Err(StreamError::AbortCode(2))
        );
        assert_eq!(d.failed(), Some(StreamError::AbortCode(2)));

        // A retiring part keeps a part's codes.
        let mut d = Duplex::swarm(512 << 10);
        d.ask(4).unwrap();
        d.answered(4, true).unwrap();
        assert_eq!(d.withdraw(4), Retire::SendCancel);
        assert_eq!(
            d.receive(StreamFrame::Abort {
                id: 4,
                abort: too_large()
            }),
            Err(StreamError::AbortCode(4))
        );

        // No record: a code some stream takes is checked by its ID; one no
        // stream takes is refused as such.
        let mut d = Duplex::swarm(512 << 10);
        d.ask(5).unwrap();
        assert_eq!(
            d.receive(StreamFrame::Abort {
                id: 9,
                abort: too_large()
            }),
            Err(StreamError::Unknown(9))
        );
        let mut d = Duplex::swarm(512 << 10);
        d.ask(5).unwrap();
        assert_eq!(
            d.receive(StreamFrame::Abort {
                id: 9,
                abort: Abort::new(AbortCode::Internal, "x")
            }),
            Err(StreamError::AbortCode(9))
        );
        // The dweb thread's duplex: a piece never ends `too_large`.
        let mut d = Duplex::new();
        d.ask(6).unwrap();
        d.answered(6, true).unwrap();
        assert_eq!(
            d.receive(StreamFrame::Abort {
                id: 6,
                abort: too_large()
            }),
            Err(StreamError::AbortCode(6))
        );
    }

    /// Design 0015: the Swarm thread's uploads end only with an upload's
    /// codes.
    #[test]
    fn the_swarm_threads_uploads_keep_to_their_codes() {
        for code in AbortCode::ALL {
            let mut d = Duplex::swarm(512 << 10);
            d.request(1).unwrap();
            d.sender_mut().head(1, b"{}".to_vec(), true).unwrap();
            let sent = d.sender_mut().abort(1, &Abort::new(code, "x"));
            assert_eq!(sent.is_ok(), Codes::CoreUpload.allows(code), "{code:?}");
        }
    }

    /// Many streams owed at once, some gone before the writer runs: what it
    /// writes is the rest, in the order their credit came, merged.
    #[test]
    fn the_writer_takes_the_rest_in_order() {
        let mut d = Duplex::new();
        for id in 1..=100u64 {
            d.ask(id).unwrap();
            d.answered(id, true).unwrap();
            d.receive(StreamFrame::Data { id, bytes: &[1, 2] }).unwrap();
        }
        // Credit comes newest stream first, each stream twice.
        for id in (1..=100u64).rev() {
            d.release(id, 1).unwrap();
        }
        for id in (1..=100u64).rev() {
            d.release(id, 1).unwrap();
        }
        check(&d);
        for id in (1..=100u64).filter(|id| id % 4 == 0) {
            d.receive(StreamFrame::End { id }).unwrap();
        }
        for id in (1..=100u64).filter(|id| id % 4 == 1) {
            d.withdraw(id);
        }
        check(&d);
        assert_eq!(d.owed(), 50);
        let mut wrote = Vec::new();
        let mut out = Vec::new();
        while let Some(w) = d.next_frame(&mut out) {
            wrote.push(w);
            check(&d);
        }
        let want: Vec<Wrote> = (1..=100u64)
            .rev()
            .filter(|id| id % 4 > 1)
            .map(|id| Wrote::Credit { id, n: 2 })
            .collect();
        assert_eq!(wrote, want);
        assert_eq!((d.owed(), d.order.len(), d.owed.len()), (0, 0, 0));
    }
}
