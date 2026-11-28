//! The engine's store ops (design 0015, "Methods main calls"; SWM-4's D2,
//! D3, D6, D7 and D13): `swarm.identities`, `swarm.history` and
//! `swarm.manifest`, each request one of fc-swarm-provider's
//! [`ops::Op`]s, run against the swarm thread's stores.
//!
//! - **At the door:** the three need the Swarm stores moved (`not_moved`,
//!   `data.store: "swarm_stores"`, D3), and `swarm.manifest`, whose
//!   projections write the Swarm grants, needs those moved too
//!   (`data.store: "swarm"`, D2). The params are read strictly
//!   (`invalid_argument`); an op only main makes, from the chrome, is
//!   `forbidden` (D7).
//! - **Admission** ("Budgets"): the ops that ask main or the vault
//!   ([`ops::Call::gated`]: `swarm.manifest`'s `check`, and the identity
//!   ops that read owners) take a place among the 64 running and the 256
//!   waiting, past which they are the protocol error `busy`, and reserve
//!   the request's base before they start. The others take no place: they
//!   run at once, in the thread's order.
//! - **The stores** are the thread's own, synchronous: the feed store
//!   through SW-1's keeper, the manifest store with its files
//!   ([`Io::save_manifests`]), the history's statements
//!   ([`Io::history_rows`], [`Io::history_run`], and for `add`'s insert
//!   [`Io::history_insert`]), and the Swarm grants
//!   through the shared handle and its writer ([`GrantsWriter`], D2). A
//!   projection that widened or narrowed a site's grant sends
//!   `approval.changed` after the op's answer ([`Io::changed`]).
//! - **Asks:** a key's owner and the user's accounts from the vault
//!   ([`VaultAsk::Owner`], [`VaultAsk::Accounts`]); a check's manifest from
//!   main, D6's `shell.swarm_manifest { for, url }`, its reply's room
//!   reserved first, bounded 60 s in all (D13): past it the core cancels
//!   it and the check reads it as `{ failed }`.
//! - **SW-1's hold:** a change the keeper defers is answered to the op
//!   when the hold ends ([`Asker::Op`]); an op that waits for a hold's end
//!   (a manifest transaction that would revoke a held site's feed grant)
//!   is tried again at each.
//! - **D13**, for these requests with no total deadline: a wait for a
//!   place, its base or a fetch's charge ends `busy` after 60 s.
//! - **Cancel:** main's cancel ends the op `cancelled`; a fetch out is
//!   cancelled at main and keeps its charge until main's answer; a change
//!   already handed to the keeper is still made, its answer dropped.
//! - **A user's Swarm grant change** (D17), which the event loop writes
//!   and then tells the thread ([`Engine::grant_changed`]), detaches the
//!   projection from the site's manifest record as the reference's
//!   `detachManagedLater` does (`ops::detach`): nothing is answered, and
//!   only a disconnect that narrowed a grant sends `approval.changed`.
//!   It keeps its place among the site's `swarm.manifest` ops, as the
//!   reference's per-site lock and its store's one queue of changes order
//!   them: it waits for the site's ops that came before it (a check whose
//!   fetch is out holds the record it read, and its decision would put the
//!   projection back), and the site's ops that come after it wait for it
//!   ([`OpPhase::Blocked`]). While SW-1's hold would defer a feed-store
//!   change it makes (a disconnect's revoke of a held site's feed grant),
//!   it waits for the hold's end, as a manifest op does.

use super::*;
use fc_swarm_provider::ops::{Caller, Fetch, Op, Refused, Step, Waiting};
use fc_swarm_provider::stores::manifests::{Effect as Projected, Projection};

/// `shell.swarm_manifest`'s body at most: the manifest's 8 KiB and a byte,
/// so the check sees one past its bound (`permission-manifests.js:20`).
pub const MANIFEST_MOST: usize = 8 * 1024 + 1;

/// `b64(MANIFEST_MOST)`.
const MANIFEST_B64: usize = MANIFEST_MOST.div_ceil(3) * 4;

/// A manifest fetch's room in the swarm thread's memory: its reply as it is
/// reassembled (`b64(m) + 16 KiB`), the base64 text and the decoded bytes.
pub const MANIFEST_CHARGE: usize = MANIFEST_MOST + 2 * MANIFEST_B64 + ENVELOPE;

/// What the engine hands an op back.
#[derive(Debug)]
pub(super) enum OpInput {
    /// Its change, which SW-1's hold deferred, made or refused.
    Changed(Result<ChangeAnswer, ChangeError>),
    /// A hold ended: an op waiting for one tries again.
    Retry,
}

/// A store op the engine holds, until it has answered and nothing of it is
/// open.
pub(super) struct OpSlot {
    op: Op,
    /// It takes a place in the admission gate.
    gated: bool,
    phase: OpPhase,
    arrived: Ms,
    placed: bool,
    pub(super) base: usize,
    pub(super) answered: bool,
    pub(super) written: bool,
    asks: BTreeMap<AskId, OpAsk>,
    waiting: Option<Waiting>,
    /// The sites whose Swarm grant a projection widened or narrowed, for
    /// `approval.changed` after the answer.
    changed: Vec<JsString>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpPhase {
    /// Waiting for a place.
    Waiting,
    /// Placed, waiting for its base.
    Base,
    Running,
    /// Placed and given its base, waiting for a user's grant change of its
    /// site that came before it to detach (D17).
    Blocked,
    /// Answered.
    Ended,
}

/// A user's change of a site's Swarm grant, waiting to detach (D17).
#[derive(Debug, Clone)]
pub(super) struct Detach {
    /// Its place among the store ops (their tickets' order).
    seq: u64,
    key: JsString,
    projection: Projection,
}

struct OpAsk {
    need: ops::Need,
    stage: OpStage,
    /// What it holds of the pool.
    held: usize,
    /// A fetch's bound in all, once sent.
    due: Option<Ms>,
    /// The op holds it no more (its bound, or the op's end): main's answer
    /// is dropped when it comes.
    closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpStage {
    /// Asked of the vault under this tag.
    Vault(u64),
    /// Waiting for its charge since then.
    Memory(Ms),
    /// Waiting for the gate.
    Outbox,
    /// Sent to main as the core's request.
    Sent(u64),
}

impl Engine {
    /// Store op request `id` of `method` (`swarm.identities`,
    /// `swarm.history` or `swarm.manifest`) from `caller`, its params as
    /// main sent them ([module docs](self)).
    pub fn op(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        id: u64,
        method: &'static str,
        params: Option<&str>,
        caller: Caller,
    ) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        if method == ops::MANIFEST && !self.grants_moved {
            io.answer(id, grants_not_moved());
            return Ok(());
        }
        if !self.shared.stores_moved {
            io.answer(id, stores_not_moved());
            return Ok(());
        }
        let call = match params.and_then(|text| fc_json::parse(text).ok()) {
            Some(value) => ops::Call::parse(method, &value, caller),
            None => Err(Refused::Invalid("params must be a JSON object".to_owned())),
        };
        let call = match call {
            Ok(call) => call,
            Err(Refused::Invalid(why)) => {
                io.answer(
                    id,
                    Answer::Error(ErrorBody::new(
                        ErrorCode::InvalidArgument,
                        bounded_text(&why),
                    )),
                );
                return Ok(());
            }
            Err(Refused::Forbidden(name)) => {
                io.answer(
                    id,
                    Answer::Error(ErrorBody::new(
                        ErrorCode::Forbidden,
                        format!("{name} is main's own op"),
                    )),
                );
                return Ok(());
            }
        };
        let gated = call.gated();
        if gated
            && self.running >= self.bounds.running
            && self.admission.len() >= self.bounds.waiting
        {
            io.answer(id, protocol_busy());
            return Ok(());
        }
        self.next_ticket += 1;
        let ticket = Ticket(self.next_ticket);
        self.ops.insert(
            id,
            OpSlot {
                op: Op::new(call, ticket),
                gated,
                phase: OpPhase::Waiting,
                arrived: now,
                placed: false,
                base: 0,
                answered: false,
                written: false,
                asks: BTreeMap::new(),
                waiting: None,
                changed: Vec::new(),
            },
        );
        if gated {
            self.admission.push_back(id);
        } else {
            self.op_start(io, now, id)?;
        }
        self.drive(io, now)
    }

    /// A gated op's place: it reserves its base, then starts.
    pub(super) fn op_admitted(&mut self, io: &mut impl Io, now: Ms, id: u64) -> Result<(), Fault> {
        let Some(op) = self.ops.get_mut(&id) else {
            return Ok(());
        };
        if op.phase != OpPhase::Waiting {
            return Ok(());
        }
        op.placed = true;
        self.running += 1;
        if self.memory.reserve(Waiter::Base(id), REQUEST_CHARGE) {
            op.base = REQUEST_CHARGE;
            self.op_start(io, now, id)
        } else {
            op.phase = OpPhase::Base;
            Ok(())
        }
    }

    /// Runs the op as far as it goes, once no user's grant change of its
    /// site that came before it waits to detach (D17).
    pub(super) fn op_start(&mut self, io: &mut impl Io, now: Ms, id: u64) -> Result<(), Fault> {
        let blocked = self
            .ops
            .get(&id)
            .is_some_and(|op| self.detach_before(op.op.manifest_key(), op.op.ticket().0));
        let Engine { ops, shared, .. } = self;
        let Some(op) = ops.get_mut(&id) else {
            return Ok(());
        };
        if !matches!(
            op.phase,
            OpPhase::Waiting | OpPhase::Base | OpPhase::Blocked
        ) {
            return Ok(());
        }
        if blocked {
            op.phase = OpPhase::Blocked;
            return Ok(());
        }
        op.phase = OpPhase::Running;
        let OpSlot { op, changed, .. } = op;
        let step = with_stores(shared, io, changed, |stores| op.start(stores));
        self.op_step(io, now, id, step);
        Ok(())
    }

    /// What the engine handed the op back.
    pub(super) fn op_input(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        id: u64,
        input: OpInput,
    ) -> Result<(), Fault> {
        let Engine { ops, shared, .. } = self;
        let Some(op) = ops.get_mut(&id) else {
            return Ok(());
        };
        if op.phase != OpPhase::Running {
            return Ok(());
        }
        let OpSlot { op, changed, .. } = op;
        let step = with_stores(shared, io, changed, |stores| match input {
            OpInput::Changed(answer) => op.changed(answer, stores),
            OpInput::Retry => op.retry(stores),
        });
        self.op_step(io, now, id, step);
        Ok(())
    }

    /// Every op waiting for a hold's end tries again.
    pub(super) fn retry_ops(&mut self) {
        let waiting: Vec<u64> = self
            .ops
            .iter()
            .filter(|(_, op)| op.phase == OpPhase::Running && op.waiting == Some(Waiting::Hold))
            .map(|(id, _)| *id)
            .collect();
        for id in waiting {
            self.op_ready.push_back((id, OpInput::Retry));
        }
    }

    /// The op's next step: its asks sent, its wait noted, or its answer.
    fn op_step(&mut self, io: &mut impl Io, now: Ms, id: u64, step: Step) {
        match step {
            Step::Asks(asks) => {
                if let Some(op) = self.ops.get_mut(&id) {
                    op.waiting = Some(Waiting::Answers);
                }
                for ask in asks {
                    self.op_ask(io, now, id, ask);
                }
            }
            Step::Wait(waiting) => {
                let Some(op) = self.ops.get_mut(&id) else {
                    return;
                };
                op.waiting = Some(waiting);
                if waiting == Waiting::Change {
                    self.tickets.insert(op.op.ticket(), Asker::Op(id));
                }
            }
            Step::Done(outcome) => {
                let answer = match outcome {
                    ops::Outcome::Result(value) => Answer::Result(wire::result_typed(&value)),
                    ops::Outcome::Thrown(thrown) => {
                        Answer::Result(wire::thrown_typed(&thrown_value(&thrown)))
                    }
                    ops::Outcome::Cancelled => cancelled(),
                };
                self.op_end(io, id, answer);
            }
            Step::Ended => {}
        }
    }

    /// One of the op's asks: the vault's, or main's fetch once its charge
    /// is reserved.
    fn op_ask(&mut self, io: &mut impl Io, now: Ms, id: u64, ask: ops::Ask) {
        let Some(op) = self.ops.get_mut(&id) else {
            return;
        };
        let stage = match &ask.need {
            ops::Need::Owner(key) => {
                self.next_vault += 1;
                io.vault(self.next_vault, VaultAsk::Owner(*key));
                self.vaults.insert(self.next_vault, (id, ask.id));
                OpStage::Vault(self.next_vault)
            }
            ops::Need::Accounts => {
                self.next_vault += 1;
                io.vault(self.next_vault, VaultAsk::Accounts);
                self.vaults.insert(self.next_vault, (id, ask.id));
                OpStage::Vault(self.next_vault)
            }
            ops::Need::Manifest { .. } => {
                if self
                    .memory
                    .reserve(Waiter::Ask(id, ask.id), MANIFEST_CHARGE)
                {
                    self.outbox.push_back((id, ask.id));
                    OpStage::Outbox
                } else {
                    OpStage::Memory(now)
                }
            }
        };
        let held = if stage == OpStage::Outbox {
            MANIFEST_CHARGE
        } else {
            0
        };
        op.asks.insert(
            ask.id,
            OpAsk {
                need: ask.need,
                stage,
                held,
                due: None,
                closed: false,
            },
        );
    }

    /// A fetch's charge is reserved: it waits for the gate.
    pub(super) fn op_charged(&mut self, id: u64, ask_id: AskId) {
        let Some(ask) = self
            .ops
            .get_mut(&id)
            .and_then(|op| op.asks.get_mut(&ask_id))
            .filter(|ask| matches!(ask.stage, OpStage::Memory(_)))
        else {
            return;
        };
        ask.held = MANIFEST_CHARGE;
        ask.stage = OpStage::Outbox;
        self.outbox.push_back((id, ask_id));
    }

    /// Sends the op's fetch, `shell.swarm_manifest { for, url }` (D6), if
    /// the gate takes it.
    pub(super) fn op_send(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        id: u64,
        ask_id: AskId,
    ) -> Result<bool, Fault> {
        let bound = self.bounds.wait_ms;
        let Some(ask) = self
            .ops
            .get_mut(&id)
            .and_then(|op| op.asks.get_mut(&ask_id))
            .filter(|ask| ask.stage == OpStage::Outbox)
        else {
            return Ok(true);
        };
        let ops::Need::Manifest { url } = &ask.need else {
            return Ok(true);
        };
        let outgoing = Outgoing {
            method: "shell.swarm_manifest",
            params: wire::manifest_params(id, url),
            reply_bound: MANIFEST_B64 + ENVELOPE,
            opens: None,
        };
        match io.send(outgoing) {
            Sent::Id(core) => {
                ask.stage = OpStage::Sent(core);
                ask.due = Some(now.saturating_add(bound));
                self.sent.insert(core, (id, ask_id));
            }
            Sent::Wait => {
                self.outbox.push_front((id, ask_id));
                self.blocked = true;
                return Ok(false);
            }
            // Over one frame, or the core is exiting: the fetch failed, as
            // one main couldn't make.
            Sent::Refused => {
                let held = ask.held;
                if let Some(op) = self.ops.get_mut(&id) {
                    op.asks.remove(&ask_id);
                }
                self.release(held);
                self.op_answered(io, now, id, ask_id, ops::Event::Manifest(Fetch::Failed));
            }
        }
        Ok(true)
    }

    /// Main's terminal answer to the op's fetch, sent as the core's request
    /// whose `sent` record was `(id, ask_id)`.
    pub(super) fn op_response(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        id: u64,
        ask_id: AskId,
        outcome: Result<&str, &str>,
    ) -> Result<(), Fault> {
        let Some(ask) = self.ops.get_mut(&id).and_then(|op| op.asks.remove(&ask_id)) else {
            return Err(Fault("swarm_unsolicited"));
        };
        let fetched = match outcome {
            Ok(text) => Some(wire::manifest_reply(text).ok_or(Fault("swarm_reply"))?),
            Err(text) => match wire::refusal(text) {
                Some(Refusal::Cancelled) if ask.closed => None,
                _ => return Err(Fault("swarm_reply")),
            },
        };
        // Its reply consumed: its charge goes.
        self.release(ask.held);
        if let Some(fetched) = fetched.filter(|_| !ask.closed) {
            self.op_answered(io, now, id, ask_id, ops::Event::Manifest(fetched));
        }
        self.op_retire(id);
        Ok(())
    }

    /// The vault's answer to the op's ask under its tag.
    pub(super) fn op_vaulted(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        id: u64,
        ask_id: AskId,
        answer: VaultAnswer,
    ) -> Result<(), Fault> {
        let asked = self.ops.get_mut(&id).and_then(|op| op.asks.remove(&ask_id));
        if asked.is_none() {
            return Ok(());
        }
        let event = match answer {
            VaultAnswer::Event(Event::Owner(owner)) => ops::Event::Owner(owner),
            VaultAnswer::Accounts(accounts) => ops::Event::Accounts(accounts),
            // Never: the vault answers an owner's ask with an owner.
            VaultAnswer::Event(_) => ops::Event::Owner(Err(JsString::from("Internal error"))),
        };
        self.op_answered(io, now, id, ask_id, event);
        self.op_retire(id);
        Ok(())
    }

    /// Hands the op an answer to its ask.
    fn op_answered(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        id: u64,
        ask_id: AskId,
        event: ops::Event,
    ) {
        let Engine { ops, shared, .. } = self;
        let Some(op) = ops.get_mut(&id) else {
            return;
        };
        if op.phase != OpPhase::Running {
            return;
        }
        let OpSlot { op, changed, .. } = op;
        let step = with_stores(shared, io, changed, |stores| {
            op.answer(ask_id, event, stores)
        });
        self.op_step(io, now, id, step);
    }

    /// Main cancelled op `id`, or a bound ended it: it answers `answer`.
    pub(super) fn op_cancel(&mut self, io: &mut impl Io, id: u64, answer: Answer) {
        let Some(op) = self.ops.get_mut(&id) else {
            return;
        };
        if op.answered {
            return;
        }
        // The op ends: what comes for it later is dropped.
        let _ = op.op.cancel();
        let (phase, base) = (op.phase, op.base);
        if matches!(phase, OpPhase::Waiting | OpPhase::Base) {
            self.admission.retain(|waiting| *waiting != id);
        }
        if phase == OpPhase::Base && base == 0 {
            let granted = self.memory.withdraw(Waiter::Base(id));
            self.grant(granted);
        }
        self.op_end(io, id, answer);
    }

    /// The op answers: its place goes, its asks are let go of (a fetch out
    /// is cancelled at main, keeping its charge until main's answer), the
    /// grants it changed are told after its answer, and it goes once
    /// nothing of it is open.
    fn op_end(&mut self, io: &mut impl Io, id: u64, answer: Answer) {
        let Some(op) = self.ops.get_mut(&id) else {
            return;
        };
        if op.answered {
            return;
        }
        op.answered = true;
        op.phase = OpPhase::Ended;
        // A detach may have waited for it (D17).
        self.detach_due |= !self.detaches.is_empty();
        io.answer(id, answer);
        for key in std::mem::take(&mut op.changed) {
            io.changed(key.as_str());
        }
        if op.placed {
            op.placed = false;
            self.running = self.running.saturating_sub(1);
        }
        self.tickets.retain(|_, asker| *asker != Asker::Op(id));
        let mut released = 0;
        let mut withdrawn = Vec::new();
        op.asks.retain(|ask_id, ask| match ask.stage {
            OpStage::Sent(core) => {
                if !ask.closed {
                    ask.closed = true;
                    ask.due = None;
                    io.cancel(core);
                }
                true
            }
            OpStage::Vault(tag) => {
                self.vaults.remove(&tag);
                false
            }
            OpStage::Memory(_) => {
                withdrawn.push(*ask_id);
                false
            }
            OpStage::Outbox => {
                released += ask.held;
                false
            }
        });
        for ask_id in withdrawn {
            let granted = self.memory.withdraw(Waiter::Ask(id, ask_id));
            self.grant(granted);
        }
        self.release(released);
        self.op_retire(id);
    }

    /// An op that has answered and holds no ask goes, and its base once its
    /// answer has been written.
    fn op_retire(&mut self, id: u64) {
        let Some(op) = self.ops.get(&id) else {
            return;
        };
        if !op.answered || !op.asks.is_empty() {
            return;
        }
        let Some(op) = self.ops.remove(&id) else {
            return;
        };
        if op.base == 0 {
            return;
        }
        if op.written {
            self.release(op.base);
        } else {
            self.unwritten.insert(id, op.base);
        }
    }

    /// D13's waits: an op waiting for a place, its base or a fetch's charge
    /// for the wait's bound ends `busy`. Whether one ended.
    pub(super) fn op_deadlines(&mut self, io: &mut impl Io, now: Ms) -> Result<bool, Fault> {
        let wait = self.bounds.wait_ms;
        let due: Vec<u64> = self
            .ops
            .iter()
            .filter(|(_, op)| !op.answered && op.due(wait).is_some_and(|due| due <= now))
            .map(|(id, _)| *id)
            .collect();
        for id in &due {
            self.op_cancel(io, *id, protocol_busy());
        }
        Ok(!due.is_empty())
    }

    /// The ops' fetches past their bound in all (D13): cancelled at main,
    /// read by the check as `{ failed }`.
    pub(super) fn op_tick(&mut self, io: &mut impl Io, now: Ms) -> Result<(), Fault> {
        let expired: Vec<(u64, AskId, u64)> = self
            .ops
            .iter()
            .flat_map(|(id, op)| {
                op.asks
                    .iter()
                    .filter_map(move |(ask_id, ask)| match ask.stage {
                        OpStage::Sent(core) if ask.due.is_some_and(|due| due <= now) => {
                            Some((*id, *ask_id, core))
                        }
                        _ => None,
                    })
            })
            .collect();
        for (id, ask_id, core) in expired {
            if let Some(ask) = self
                .ops
                .get_mut(&id)
                .and_then(|op| op.asks.get_mut(&ask_id))
            {
                ask.due = None;
                ask.closed = true;
            }
            io.cancel(core);
            crate::log::info("swarm manifest fetch past its bound", serde_json::json!({}));
            self.op_answered(io, now, id, ask_id, ops::Event::Manifest(Fetch::Failed));
        }
        Ok(())
    }

    /// When the next of the ops' bounds falls due.
    pub(super) fn op_next_due(&self) -> Option<Ms> {
        let wait = self.bounds.wait_ms;
        self.ops
            .values()
            .filter_map(|op| {
                let fetches = op.asks.values().filter_map(|ask| ask.due).min();
                let waits = op.due(wait).filter(|_| !op.answered);
                fetches.into_iter().chain(waits).min()
            })
            .min()
    }
}

impl Engine {
    /// D17: the event loop wrote a user's change of site `key`'s Swarm
    /// grant (a revoke, a rule, the messaging grant), and the manifest
    /// store detaches `projection` from the site's record once the site's
    /// `swarm.manifest` ops that came before it have answered and SW-1's
    /// hold defers nothing it makes ([module docs](self)). Nothing is
    /// answered. Before the stores move, main holds the manifest store.
    pub fn grant_changed(
        &mut self,
        io: &mut impl Io,
        now: Ms,
        key: &str,
        projection: Projection,
    ) -> Result<(), Fault> {
        self.deadlines(io, now)?;
        if self.shared.stores_moved {
            self.next_ticket += 1;
            self.detaches.push_back(Detach {
                seq: self.next_ticket,
                key: JsString::from(key),
                projection,
            });
            self.detach_due = true;
        }
        self.drive(io, now)
    }

    /// Whether a `swarm.manifest` op of site `key` that came before `seq`
    /// hasn't answered.
    fn manifest_op_before(&self, key: &JsString, seq: u64) -> bool {
        self.ops
            .values()
            .any(|op| !op.answered && op.op.ticket().0 < seq && op.op.manifest_key() == Some(key))
    }

    /// Whether a user's grant change of site `key` that came before
    /// `ticket` waits to detach.
    fn detach_before(&self, key: Option<&JsString>, ticket: u64) -> bool {
        key.is_some_and(|key| {
            self.detaches
                .iter()
                .any(|detach| detach.seq < ticket && detach.key == *key)
        })
    }

    /// Each waiting detach that can go now, in order (each site's in its
    /// own order); then the ops that waited for one start, in theirs.
    /// Whether anything moved.
    pub(super) fn pump_detaches(&mut self, io: &mut impl Io, now: Ms) -> Result<bool, Fault> {
        let mut moved = false;
        let mut waiting: Vec<JsString> = Vec::new();
        let mut at = 0;
        while let Some(detach) = self.detaches.get(at).cloned() {
            if waiting.contains(&detach.key) || self.manifest_op_before(&detach.key, detach.seq) {
                waiting.push(detach.key);
                at += 1;
                continue;
            }
            let Engine { shared, .. } = self;
            let mut changed = Vec::new();
            let done = with_stores(shared, io, &mut changed, |stores| {
                ops::detach(stores, &detach.key, detach.projection)
            });
            if !done {
                // SW-1's hold defers its feed-store change: tried again at
                // the hold's end.
                waiting.push(detach.key);
                at += 1;
                continue;
            }
            self.detaches.remove(at);
            moved = true;
            // A disconnect that narrowed a grant (one given again since the
            // user's revoke) tells main, as a projection does.
            for key in changed {
                io.changed(key.as_str());
            }
        }
        let mut blocked: Vec<(u64, u64)> = self
            .ops
            .iter()
            .filter(|(_, op)| op.phase == OpPhase::Blocked)
            .map(|(id, op)| (op.op.ticket().0, *id))
            .collect();
        blocked.sort_unstable();
        for (ticket, id) in blocked {
            let key = self
                .ops
                .get(&id)
                .and_then(|op| op.op.manifest_key().cloned());
            if self.detach_before(key.as_ref(), ticket) {
                continue;
            }
            moved = true;
            self.op_start(io, now, id)?;
        }
        Ok(moved)
    }
}

impl OpSlot {
    /// When a wait of its ends `busy` (D13): 60 s after it came while it
    /// waits for a place or its base, or after a fetch began to wait for
    /// its charge.
    fn due(&self, wait: Ms) -> Option<Ms> {
        match self.phase {
            OpPhase::Waiting | OpPhase::Base if self.gated => {
                Some(self.arrived.saturating_add(wait))
            }
            OpPhase::Running => self
                .asks
                .values()
                .filter_map(|ask| match ask.stage {
                    OpStage::Memory(since) => Some(since.saturating_add(wait)),
                    _ => None,
                })
                .min(),
            _ => None,
        }
    }
}

/// `not_moved` for `swarm.manifest` while main writes the Swarm grants
/// (D2): its projections write them.
fn grants_not_moved() -> Answer {
    Answer::Error(
        ErrorBody::new(
            ErrorCode::NotMoved,
            "main still writes the Swarm grants (they aren't in grant_moved)",
        )
        .with_data(serde_json::json!({ "store": "swarm" })),
    )
}

/// What a store op threw, in today's shape: `{ name, message, code? }`.
fn thrown_value(thrown: &fc_swarm_provider::stores::Thrown) -> Value {
    let mut members = vec![
        (JsString::from("name"), Value::str(thrown.name.as_str())),
        (JsString::from("message"), Value::str(&thrown.message)),
    ];
    if let Some(code) = thrown.code {
        members.push((JsString::from("code"), Value::str(code)));
    }
    Value::Object(members)
}

/// Runs `f` with the swarm thread's stores, at the wall clock; the sites
/// whose Swarm grant a projection widened or narrowed are noted in
/// `changed`.
fn with_stores<R>(
    shared: &mut Shared,
    io: &mut impl Io,
    changed: &mut Vec<JsString>,
    f: impl FnOnce(&mut ops::Stores<'_>) -> R,
) -> R {
    let now_ms = io.wall_ms();
    let mut grants = GrantsWorld {
        grants: &shared.grants,
        writer: shared.grants_writer.as_deref_mut(),
        changed,
        now_ms,
    };
    let mut files = OpIo { io };
    let mut stores = ops::Stores {
        now_ms,
        keeper: &mut shared.keeper,
        manifests: &mut shared.manifests,
        grants: &mut grants,
        io: &mut files,
    };
    f(&mut stores)
}

/// The Swarm grants as a manifest's projections read and write them (D2).
struct GrantsWorld<'a> {
    grants: &'a Mutex<SwarmStore>,
    writer: Option<&'a mut (dyn GrantsWriter + 'static)>,
    changed: &'a mut Vec<JsString>,
    now_ms: u64,
}

impl GrantsWorld<'_> {
    fn store(&self) -> MutexGuard<'_, SwarmStore> {
        self.grants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl ops::Grants for GrantsWorld<'_> {
    fn connected(&self, key: &JsString) -> bool {
        self.store().entry(key.as_str()).is_some()
    }

    fn messaging(&self, key: &JsString) -> bool {
        self.store().has_messaging(key.as_str())
    }

    fn auto_approve(
        &self,
        key: &JsString,
        capability: fc_swarm_provider::stores::manifests::Capability,
    ) -> bool {
        self.store().flag(key.as_str(), flag_of(capability))
    }

    /// `swarm-permissions.js`'s change with `source: 'manifest'`, written
    /// as main's own (design 0012): a connection for a site without one,
    /// a disconnect, a rule, the messaging grant.
    fn apply(&mut self, key: &JsString, effect: Projected) -> Result<(), JsString> {
        let Some(writer) = self.writer.as_deref_mut() else {
            // The door lets no manifest op in before the grants move.
            return Err(JsString::from("Internal error"));
        };
        let site = key.as_str();
        let now = self.now_ms;
        let mut change = |store: &mut SwarmStore| -> Applied<()> {
            let effect = match effect {
                Projected::Connect if store.entry(site).is_some() => GrantEffect::Unchanged,
                Projected::Connect => store.connect(site, now).effect,
                Projected::Disconnect => store.revoke(site).effect,
                Projected::Flag {
                    capability,
                    enabled,
                } => store.set_flag(site, flag_of(capability), enabled).effect,
                Projected::Messaging(true) => store.grant_messaging(site, now).effect,
                Projected::Messaging(false) => store.revoke_messaging(site).effect,
                // The feed store's, which the op makes through the keeper.
                Projected::FeedGrant(_) | Projected::CreateIdentity => GrantEffect::Unchanged,
            };
            Applied { value: (), effect }
        };
        let written = writer.write(self.grants, &mut change);
        if matches!(
            written.effect,
            GrantEffect::Widening | GrantEffect::Narrowing
        ) {
            self.changed.push(key.clone());
        }
        match written.error {
            Some(text) => Err(text),
            None => Ok(()),
        }
    }

    fn settle(&mut self) -> Result<(), JsString> {
        match self
            .writer
            .as_deref_mut()
            .and_then(|w| w.settle(self.grants))
        {
            Some(text) => Err(text),
            None => Ok(()),
        }
    }
}

fn flag_of(capability: fc_swarm_provider::stores::manifests::Capability) -> SwarmFlag {
    use fc_swarm_provider::stores::manifests::Capability as C;
    match capability {
        C::Publish => SwarmFlag::Publish,
        C::Feeds => SwarmFlag::Feeds,
        C::Signing => SwarmFlag::Signing,
        C::Messaging => SwarmFlag::Messaging,
    }
}

/// The stores' files and the history's database, through the engine's Io.
struct OpIo<'a, I: Io> {
    io: &'a mut I,
}

impl<I: Io> ops::Io for OpIo<'_, I> {
    fn write_feeds(&mut self, text: &str) -> Result<(), JsString> {
        self.io.write_feeds(text)
    }

    fn read_manifests(&mut self) -> Option<Vec<u8>> {
        self.io.read_manifests()
    }

    fn read_manifests_backup(&mut self) -> Option<Vec<u8>> {
        self.io.read_manifests_backup()
    }

    fn save_manifests(&mut self, save: &Save) -> Result<(), JsString> {
        self.io.save_manifests(save)
    }

    fn random(&mut self) -> Option<[u8; 24]> {
        self.io.random()
    }

    fn query(&mut self, statement: &Statement) -> Result<Vec<Row>, JsString> {
        self.io.history_rows(statement)
    }

    fn run(&mut self, statement: &Statement) -> Result<usize, JsString> {
        self.io.history_run(statement)
    }

    fn insert(&mut self, statement: &Statement) -> Result<i64, JsString> {
        self.io.history_insert(statement)
    }
}

impl std::fmt::Debug for OpSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpSlot")
            .field("phase", &self.phase)
            .field("asks", &self.asks.len())
            .finish_non_exhaustive()
    }
}
