//! The engine's streams (design 0015, "Streams", "Deadlines and cancel"
//! and "Bounds"; SWM-4's D4, D9 and D13): main's parts and streamed node
//! replies into the thread, the thread's `swarm.body` answers out of it,
//! the hashing pool's results, and the idle bound that ends an upload whose
//! streams stopped.
//!
//! - **Into the thread.** A part or a streamed node reply holds one of the
//!   incoming streams' slots from before it goes until main's terminal for
//!   its stream ([`Engine::stream_end`]), or, if the reply opens none, until
//!   the reply; a node reply also holds its call's slot as long. Each data
//!   frame goes to the machine, whose credit goes back to main as the
//!   machine lets the bytes go: a read's at once, a part's only as its
//!   bytes go out on the upload's body ("credit goes in only when it can go
//!   out"). A streamed read's charge, whose bytes are now the result's,
//!   stays until the request's answer has been written ("The swarm
//!   thread's memory").
//! - **Cancelled,** a stream retires: its frames are dropped as they come,
//!   and its slots and charge stay until main's terminal, which must come
//!   within the idle bound, or the connection ends.
//! - **Out of the thread.** Main's `swarm.body { for }` names a call of the
//!   thread's whose body streams ([`Engine::body_request`]); the machine
//!   answers it, its head, then its bytes within main's credit, then one
//!   terminal ([`Effect::Body`]). Main's credit for it comes until main has
//!   answered the call (its credits come first on the one connection), or
//!   cancelled the body: then its route closes (D4), and a credit after it
//!   is main breaking the protocol, refused by the event loop, or here for
//!   one it had routed before the route closed.
//! - **Each input first ends the requests whose deadline has come**, as
//!   the engine's others do: a frame or a result that comes at or after a
//!   request's deadline finds it cancelled.
//! - **The idle bound** (D13): while a request has a part or a call whose
//!   body streams out, each of main's frames for them (a part's head,
//!   bytes or end, the body's ask, its credit) moves its bound on. Past it,
//!   the thread cancels the call whose body streams (else the part), and
//!   the machine reads it as `failed: error` (a part with its head, as
//!   `stalled`): the upload ends, its history row with it.

use super::*;
use fc_swarm_provider::machine::{Abort, BodyAbort, JobDone};

impl Ask {
    /// The codes main may end the stream its answer opens with: a part's,
    /// or a streamed node reply's; `None` for an answer that opens none.
    pub(super) fn opens(&self) -> Option<Codes> {
        match &self.need {
            Need::Part(_) => Some(Codes::SwarmPart),
            Need::Node(call) if call.stream() => Some(Codes::SwarmPiece),
            _ => None,
        }
    }

    /// A node call whose body streams through `swarm.body`.
    pub(super) fn streams_body(&self) -> bool {
        matches!(&self.need, Need::Node(call) if matches!(call.body, Some(Body::Stream { .. })))
    }

    /// Whether the upload's idle bound watches it (D13): a part, or a call
    /// whose body hasn't had its terminal, out at main and still the
    /// machine's.
    pub(super) fn watched(&self) -> bool {
        let out = matches!(self.stage, Stage::Sent(_) | Stage::Open(_));
        let upload =
            matches!(self.need, Need::Part(_)) || (self.streams_body() && !self.body_ended);
        out && upload && !self.cancelled && !self.closed
    }
}

impl Engine {
    /// Incoming streams' slots held, for the tests.
    #[cfg(any(test, feature = "testhooks"))]
    pub fn streams_held(&self) -> usize {
        self.streams_open
    }

    /// Main's data on request `core`'s stream.
    pub fn stream_data(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        core: u64,
        bytes: Vec<u8>,
    ) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        // The duplex takes data only for an open stream it holds, and drops
        // a retiring one's: the engine holds every one it hands on.
        let (id, ask_id) = *self.open.get(&core).ok_or(Fault("swarm_stream"))?;
        self.progress(now, id, ask_id);
        self.deliver(io, now, id, ask_id, Event::Data(bytes))?;
        self.settle(io, now, id)?;
        self.drive(io, now)
    }

    /// Main's terminal for request `core`'s stream: its end, or its abort.
    pub fn stream_end(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        core: u64,
        abort: Option<Abort>,
    ) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        let (id, ask_id) = *self.open.get(&core).ok_or(Fault("swarm_stream"))?;
        let ask = self.take_ask(id, ask_id).ok_or(Fault("swarm_stream"))?;
        io.forget(StreamKey::Piece(core));
        let event = match abort {
            None => Event::End,
            Some(abort) => Event::Abort(abort),
        };
        let ended = event == Event::End;
        if !ask.closed && !ask.cancelled {
            self.progress(now, id, ask_id);
            self.deliver(io, now, id, ask_id, event)?;
        }
        // A read's bytes are its result's now: its charge stays until the
        // answer has been written. Anything else's goes with the step.
        if ended && matches!(ask.need, Need::Node(_)) {
            self.keep_for_answer(id, ask.held);
        } else {
            self.release(ask.held);
        }
        self.settle(io, now, id)?;
        self.drive(io, now)
    }

    /// Main's terminal for a stream the thread had cancelled: dropped, and
    /// what it held goes.
    pub fn stream_retired(&mut self, io: &mut impl Io, now: Ms, core: u64) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        let Some((id, ask_id)) = self.open.get(&core).copied() else {
            return Err(Fault("swarm_stream"));
        };
        let ask = self.take_ask(id, ask_id).ok_or(Fault("swarm_stream"))?;
        io.forget(StreamKey::Piece(core));
        self.release(ask.held);
        self.settle(io, now, id)?;
        self.drive(io, now)
    }

    /// Main's `swarm.body` `body`, its params as main sent them: the body
    /// of one of the thread's calls whose body streams. Params that don't
    /// read, or a `for` that names no call of the thread's main hasn't
    /// answered, are refused (`invalid_argument`); a call that can't take a
    /// body is the machine's to refuse (main broke the protocol).
    pub fn body_request(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        body: u64,
        params: Option<&str>,
    ) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        let call = match stream::body_params(params) {
            Ok(parent) => self
                .sent
                .get(&parent)
                .copied()
                .ok_or("swarm.body names no call of the core's main hasn't answered"),
            Err(message) => Err(message),
        };
        let (id, ask_id) = match call {
            Ok(call) => call,
            Err(message) => {
                io.body_refuse(body, ErrorBody::new(ErrorCode::InvalidArgument, message));
                self.close_body(io, body);
                return Ok(());
            }
        };
        let closed = self
            .slots
            .get(&id)
            .and_then(|slot| slot.asks.get(&ask_id))
            .is_some_and(|ask| ask.closed);
        if closed {
            // The thread already ended the call (its idle bound): the body
            // gets its one terminal at once.
            io.body(body, BodyOut::Abort(BodyAbort::Cancelled));
            self.close_body(io, body);
            return Ok(());
        }
        self.bodies.insert(body, (id, ask_id));
        self.body_of.insert((id, ask_id), body);
        self.progress(now, id, ask_id);
        self.deliver(io, now, id, ask_id, Event::BodyOpen)?;
        self.settle(io, now, id)?;
        self.drive(io, now)
    }

    /// Main's credit for `swarm.body` `body`. One for a body whose route
    /// the thread closed (main answered its call, or cancelled it), routed
    /// here before it closed, is main breaking the protocol (D4).
    pub fn body_credit(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        body: u64,
        bytes: usize,
    ) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        let Some((id, ask_id)) = self.bodies.get(&body).copied() else {
            if self.closed_bodies.contains(&body) {
                return Err(Fault("stream_closed"));
            }
            return Ok(());
        };
        let open = self
            .slots
            .get(&id)
            .and_then(|slot| slot.asks.get(&ask_id))
            .is_some_and(|ask| !ask.closed);
        if open {
            self.progress(now, id, ask_id);
            self.deliver(io, now, id, ask_id, Event::BodyCredit(bytes))?;
            self.settle(io, now, id)?;
        }
        self.drive(io, now)
    }

    /// Main's credit for `swarm.body` `body` past the body's terminal: late,
    /// as credit crossing the terminal is, unless the thread had closed its
    /// route (D4).
    pub fn late_credit(&self, body: u64) -> Result<(), Fault> {
        if self.closed_bodies.contains(&body) {
            return Err(Fault("stream_closed"));
        }
        Ok(())
    }

    /// Main cancelled `swarm.body` `body` (its sender has written its
    /// `cancelled`): no credit for it follows, so its route goes (D4). The
    /// machine's later parts of it are dropped; main answers the call.
    pub fn body_cancelled(&mut self, io: &mut impl Io, now: Ms, body: u64) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        self.bodies.remove(&body);
        self.close_body(io, body);
        self.drive(io, now)
    }

    /// The hashing pool's result for request `id`'s ask `ask` (D9).
    pub fn hashed(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        id: u64,
        ask: AskId,
        done: JobDone,
    ) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        let Some(slot) = self.slots.get_mut(&id) else {
            return Ok(());
        };
        slot.hashing = slot.hashing.saturating_sub(1);
        self.deliver(io, now, id, ask, Event::Hashed(done))?;
        self.settle(io, now, id)?;
        self.drive(io, now)
    }

    // -----------------------------------------------------------------------
    // Within the engine.

    /// Takes an ask out, and what it holds but its charge: its call's slot,
    /// its stream's, its close's bound and its stream's record.
    pub(super) fn take_ask(&mut self, id: u64, ask_id: AskId) -> Option<Ask> {
        let ask = self.slots.get_mut(&id)?.asks.remove(&ask_id)?;
        self.closes.remove(&(id, ask_id));
        if ask.api {
            self.api_open = self.api_open.saturating_sub(1);
        }
        if ask.stream {
            self.streams_open = self.streams_open.saturating_sub(1);
        }
        if let Stage::Open(core) = ask.stage {
            self.open.remove(&core);
            self.retiring.remove(&core);
        }
        Some(ask)
    }

    /// Main's head for request `core` opened its stream: the ask holds on,
    /// or, cancelled meanwhile (`deliver` false), retires until main's
    /// terminal.
    pub(super) fn opened(&mut self, now: Ms, id: u64, ask_id: AskId, core: u64, deliver: bool) {
        let Some(ask) = self
            .slots
            .get_mut(&id)
            .and_then(|slot| slot.asks.get_mut(&ask_id))
        else {
            return;
        };
        ask.stage = Stage::Open(core);
        self.open.insert(core, (id, ask_id));
        if !deliver {
            self.retiring
                .insert(core, now.saturating_add(self.bounds.idle_ms));
        }
    }

    /// Incoming streams' slots go to the asks that wait, in order.
    pub(super) fn pump_streams(&mut self) -> bool {
        let mut moved = false;
        while self.streams_open < self.bounds.streams {
            let Some((id, ask_id)) = self.stream_queue.pop_front() else {
                break;
            };
            let Some(ask) = self
                .slots
                .get_mut(&id)
                .and_then(|slot| slot.asks.get_mut(&ask_id))
                .filter(|ask| ask.stage == Stage::Streams)
            else {
                continue;
            };
            self.streams_open += 1;
            ask.stream = true;
            ask.stage = Stage::Outbox;
            self.outbox.push_back((id, ask_id));
            moved = true;
        }
        moved
    }

    /// The machine let go of `bytes` of its ask's stream.
    pub(super) fn credit(&mut self, io: &mut impl Io, id: u64, ask_id: AskId, bytes: usize) {
        let open = self
            .slots
            .get(&id)
            .and_then(|slot| slot.asks.get(&ask_id))
            .filter(|ask| !ask.cancelled);
        if let Some(Ask {
            stage: Stage::Open(core),
            ..
        }) = open
        {
            io.credit(*core, bytes);
        }
    }

    /// The next part of a call's body, to main's `swarm.body` for it.
    pub(super) fn body_out(&mut self, io: &mut impl Io, id: u64, ask_id: AskId, out: BodyOut) {
        let Some(body) = self.body_of.get(&(id, ask_id)).copied() else {
            // The machine writes a body only once main asked for it.
            crate::log::warn("swarm body without its swarm.body", serde_json::json!({}));
            return;
        };
        if matches!(out, BodyOut::End | BodyOut::Abort(_)) {
            self.body_of.remove(&(id, ask_id));
            if let Some(ask) = self
                .slots
                .get_mut(&id)
                .and_then(|slot| slot.asks.get_mut(&ask_id))
            {
                ask.body_ended = true;
            }
        }
        io.body(body, out);
    }

    /// Main has answered request `id`'s call `ask_id`: the route of the
    /// body it asked for, if any, goes (D4). Its credits came first.
    pub(super) fn answered_call(&mut self, io: &mut impl Io, id: u64, ask_id: AskId) {
        let body = self
            .bodies
            .iter()
            .find(|(_, call)| **call == (id, ask_id))
            .map(|(body, _)| *body);
        if let Some(body) = body {
            self.bodies.remove(&body);
            self.close_body(io, body);
        }
    }

    /// Main sends no credit for `swarm.body` `body` any more: its route
    /// closes (D4), here and at the event loop.
    pub(super) fn close_body(&mut self, io: &mut impl Io, body: u64) {
        io.forget(StreamKey::Body(body));
        if self.closed_bodies.len() >= crate::transport::CLOSED_BODIES {
            self.closed_bodies.pop_front();
        }
        self.closed_bodies.push_back(body);
    }

    /// Request `id` has gone: its bodies' records with it, and the routes
    /// of those main hasn't let go of.
    pub(super) fn forget_bodies(&mut self, io: &mut impl Io, id: u64) {
        self.body_of.retain(|(request, _), _| *request != id);
        let bodies: Vec<u64> = self
            .bodies
            .iter()
            .filter(|(_, (request, _))| *request == id)
            .map(|(body, _)| *body)
            .collect();
        for body in bodies {
            self.bodies.remove(&body);
            self.close_body(io, body);
        }
    }

    /// A read's charge, kept until its request's answer has been written.
    pub(super) fn keep_for_answer(&mut self, id: u64, amount: usize) {
        match self.slots.get_mut(&id) {
            Some(slot) if !(slot.answered && slot.written) => slot.base += amount,
            _ => self.release(amount),
        }
    }

    /// Main made progress on request `id`'s upload (its ask `ask_id`): its
    /// idle bound moves on, if it watches one.
    pub(super) fn progress(&mut self, now: Ms, id: u64, ask_id: AskId) {
        let idle_ms = self.bounds.idle_ms;
        let Some(slot) = self.slots.get_mut(&id) else {
            return;
        };
        let watched = slot.asks.get(&ask_id).is_some_and(Ask::watched);
        if watched || slot.idle.is_some() {
            slot.idle = Some(now.saturating_add(idle_ms));
        }
    }

    /// Request `id`'s idle bound runs while it has an upload's stream out,
    /// and stops when it has none.
    pub(super) fn watch(&mut self, now: Ms, id: u64) {
        let idle_ms = self.bounds.idle_ms;
        let Some(slot) = self.slots.get_mut(&id) else {
            return;
        };
        if !slot.asks.values().any(Ask::watched) {
            slot.idle = None;
        } else if slot.idle.is_none() {
            slot.idle = Some(now.saturating_add(idle_ms));
        }
    }

    /// Request `id`'s upload made no progress for the idle bound (D13):
    /// its call whose body streams (else its part) is cancelled at main,
    /// and the machine reads it as `failed: error`, or a part whose head
    /// came as `stalled`. Main's answer to it is dropped when it comes.
    pub(super) fn stall(&mut self, io: &mut impl Io, now: Ms, id: u64) -> Result<(), Fault> {
        let idle_ms = self.bounds.idle_ms;
        let Some(slot) = self.slots.get_mut(&id) else {
            return Ok(());
        };
        slot.idle = None;
        let target = slot
            .asks
            .iter()
            .filter(|(_, ask)| ask.watched())
            .min_by_key(|(_, ask)| !ask.streams_body())
            .map(|(ask_id, _)| *ask_id);
        let Some(ask_id) = target else {
            return Ok(());
        };
        let Some(ask) = slot.asks.get_mut(&ask_id) else {
            return Ok(());
        };
        ask.cancelled = true;
        ask.closed = true;
        let event = match ask.stage {
            Stage::Open(core) => {
                io.cancel(core);
                self.retiring.insert(core, now.saturating_add(idle_ms));
                Event::Abort(Abort::Stalled)
            }
            Stage::Sent(core) => {
                io.cancel(core);
                Event::Failed(Failed::Error)
            }
            _ => return Ok(()),
        };
        crate::log::info("swarm upload idle", serde_json::json!({}));
        self.deliver(io, now, id, ask_id, event)?;
        self.settle(io, now, id)?;
        self.drive(io, now)
    }
}
