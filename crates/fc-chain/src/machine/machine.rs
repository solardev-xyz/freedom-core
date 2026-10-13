//! The machine a driver runs (design 0005): `chain.configure`,
//! `chain.availability`, `chain.request`, `chain.fee_quote`,
//! `chain.broadcast` and `cancel` in; `shell.*` requests, cancels and
//! replies out. Time comes in through the executor's timers.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Waker};

use fc_naming::session::exec::{Effect, Fired, Sleep, Task};

use super::bounds::Bounds;
use super::budget;
use super::config::{Chain, ChainConfig};
use super::ctx::{Ctx, Req};
use super::error::{ChainError, Protocol, Thrown};
use super::io::{Answer, Delivered, Ms, Request};
use super::logs::RangeEntry;
use super::quote::fee_quote;
use super::read::{ReadAnswer, ReadOptions, read};
use super::route::RouteState;
use super::send::{BroadcastOutcome, Ended, SendState, broadcast, ended_from};
use crate::fee::FeeQuote;
use crate::methods::is_read_method;
use crate::text::unsupported_read_method_text;

/// A request from main.
#[derive(Debug, Clone, PartialEq)]
pub enum Call {
    /// `chain.request`.
    Read {
        chain_id: u64,
        method: String,
        /// The caller's params, as JSON.
        params: String,
        options: ReadOptions,
    },
    /// `chain.fee_quote`.
    FeeQuote { chain_id: u64 },
    /// `chain.broadcast`.
    Broadcast { chain_id: u64, raw: String },
}

impl Call {
    fn chain_id(&self) -> u64 {
        match self {
            Self::Read { chain_id, .. }
            | Self::FeeQuote { chain_id }
            | Self::Broadcast { chain_id, .. } => *chain_id,
        }
    }

    fn is_broadcast(&self) -> bool {
        matches!(self, Self::Broadcast { .. })
    }
}

/// A request's result.
#[derive(Debug, Clone, PartialEq)]
pub enum Success {
    /// `{ result, source, verified, trust? }`: `result` is the answer's raw
    /// JSON, `None` for `undefined`; `trust` is JSON with endpoint
    /// references (`{"ref":"<endpoint>"}`) main substitutes with hosts.
    Read {
        result: Option<String>,
        source: &'static str,
        verified: bool,
        trust: Option<String>,
    },
    /// Today's quote.
    FeeQuote(FeeQuote),
    /// `{ hash, source, outcome }`: `sent` or `uncertain`.
    Broadcast {
        hash: Option<String>,
        source: &'static str,
        outcome: BroadcastOutcome,
    },
}

/// A request's one terminal reply.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub id: u64,
    pub result: Result<Success, ChainError>,
    /// A broadcast failure's outcome: `rejected` or `not_sent`.
    pub outcome: Option<BroadcastOutcome>,
    pub settled: Ms,
    /// The chain's generation the request ran under.
    pub generation: u64,
}

/// An effect, with the request that made it.
#[derive(Debug, Clone, PartialEq)]
pub struct Emitted {
    pub effect: Effect<Request>,
    /// The chain request whose I/O it is (`None` for a cancel).
    pub request: Option<u64>,
    /// The generation that request runs under: main answers a request whose
    /// generation is no longer current with `not_sent`.
    pub generation: Option<u64>,
}

/// The router's state tables, as the replay records them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StateTables {
    /// Adaptive routes by key, in insertion order. The keys hold origins:
    /// for diagnostics and tests only, never logged.
    pub adaptive: Vec<(String, RouteState)>,
    /// `(chain, in_flight, waiting)` for each chain with either.
    pub myotis_slots: Vec<(u64, usize, usize)>,
    pub colibri_in_flight: usize,
    pub colibri_routes: Vec<(String, usize)>,
    pub log_range: Vec<(String, RangeEntry)>,
    pub log_index_cool_until: Vec<(u64, Ms)>,
    pub log_index_pair_cool_until: Vec<(String, Ms)>,
}

enum Done {
    Read(Result<ReadAnswer, Thrown>),
    Fee(Result<FeeQuote, Thrown>),
    Broadcast(Ended),
}

struct Running {
    id: u64,
    chain_id: u64,
    generation: u64,
    task: Task<'static, Done>,
    deadline: Sleep<Request, Delivered>,
    /// A broadcast's attempts, for the outcome table.
    send: Option<Rc<RefCell<SendState>>>,
}

struct Waiting {
    id: u64,
    call: Call,
    deadline: Sleep<Request, Delivered>,
    deadline_at: Ms,
}

pub struct Machine {
    ctx: Rc<Ctx>,
    running: Vec<Running>,
    waiting: VecDeque<Waiting>,
    replies: Vec<Reply>,
    next_id: u64,
    /// Each chain's generation, kept when a chain is removed so that a
    /// re-added chain keeps counting.
    generations: BTreeMap<u64, u64>,
    /// The generation of each request whose effects may not be taken yet.
    origins: BTreeMap<u64, u64>,
}

fn started(mut sleep: Sleep<Request, Delivered>) -> Sleep<Request, Delivered> {
    let mut cx = Context::from_waker(Waker::noop());
    let _ = Pin::new(&mut sleep).poll(&mut cx);
    sleep
}

fn ready(sleep: &mut Sleep<Request, Delivered>) -> bool {
    let mut cx = Context::from_waker(Waker::noop());
    Pin::new(sleep).poll(&mut cx).is_ready()
}

/// What a reply takes, serialized: its result or message and an envelope.
fn reply_bytes(result: &Result<Success, ChainError>) -> usize {
    const ENVELOPE: usize = 256;
    ENVELOPE
        + match result {
            Ok(Success::Read { result, trust, .. }) => {
                result.as_ref().map_or(0, String::len) + trust.as_ref().map_or(0, String::len)
            }
            Ok(Success::FeeQuote(quote)) => quote.to_json().len(),
            Ok(Success::Broadcast { .. }) | Err(ChainError::Protocol(_)) => 0,
            Err(ChainError::Thrown(thrown)) => {
                thrown.message.to_json().len()
                    + thrown
                        .props
                        .iter()
                        .map(|(k, v)| k.len() + v.json().map_or(0, str::len))
                        .sum::<usize>()
            }
        }
}

impl Machine {
    pub fn new(now: Ms, bounds: Bounds) -> Self {
        Self {
            ctx: Rc::new(Ctx::new(now, bounds)),
            running: Vec::new(),
            waiting: VecDeque::new(),
            replies: Vec::new(),
            next_id: 1,
            generations: BTreeMap::new(),
            origins: BTreeMap::new(),
        }
    }

    pub fn now(&self) -> Ms {
        self.ctx.now()
    }

    pub fn bounds(&self) -> Bounds {
        self.ctx.bounds
    }

    /// `chain.configure`: replaces every chain's snapshot. A chain whose
    /// snapshot changed advances its generation, and its running requests
    /// end at once (deviation `config-change`). Returns each configured
    /// chain's generation.
    pub fn configure(&mut self, chains: &[ChainConfig]) -> BTreeMap<u64, u64> {
        let bounds = self.ctx.bounds;
        let mut changed = Vec::new();
        let endpoints = |state: &super::ctx::State| -> Vec<(u64, String)> {
            state
                .chains
                .values()
                .flat_map(|(chain, _)| chain.urls().into_iter().map(|u| (chain.chain_id, u)))
                .collect()
        };
        {
            let mut state = self.ctx.state.borrow_mut();
            let old = endpoints(&state);
            let mut next: BTreeMap<u64, (Rc<Chain>, u64)> = BTreeMap::new();
            for config in chains {
                let chain = Chain::new(config, &bounds);
                let generation = self.generations.entry(config.chain_id).or_insert(0);
                let same = state
                    .chains
                    .get(&config.chain_id)
                    .is_some_and(|(old, _)| **old == chain);
                if !same {
                    *generation += 1;
                    changed.push(config.chain_id);
                }
                next.insert(config.chain_id, (Rc::new(chain), *generation));
            }
            for chain_id in state.chains.keys() {
                if !next.contains_key(chain_id) {
                    if let Some(generation) = self.generations.get_mut(chain_id) {
                        *generation += 1;
                    }
                    changed.push(*chain_id);
                }
            }
            state.chains = next;
            let new = endpoints(&state);
            state.logs.retire(&old, &new, bounds.retired_endpoints);
        }
        let mut i = 0;
        while i < self.running.len() {
            if changed.contains(&self.running[i].chain_id) {
                self.end(i, Protocol::Reconfigured);
            } else {
                i += 1;
            }
        }
        self.ctx
            .state
            .borrow()
            .chains
            .iter()
            .map(|(id, (_, generation))| (*id, *generation))
            .collect()
    }

    /// `chain.availability`: Myotis's readiness for a chain, as the router
    /// samples it.
    pub fn availability(&mut self, chain_id: u64, ready: bool) {
        self.ctx.state.borrow_mut().ready.insert(chain_id, ready);
    }

    /// A request from main, with what is left of the caller's deadline.
    /// Returns its id; the reply comes from [`Machine::take_replies`].
    pub fn submit(&mut self, call: Call, deadline_ms: Option<Ms>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        // Refusals before any I/O, as the router throws them.
        if let Call::Read { method, .. } = &call
            && !is_read_method(method)
        {
            let error = Thrown::error(&unsupported_read_method_text(method));
            self.reply(id, Err(ChainError::Thrown(error)), None, 0);
            return id;
        }
        let chain_id = call.chain_id();
        let configured = self.ctx.state.borrow().chains.contains_key(&chain_id);
        if !configured {
            let error = Thrown::error(&format!("Unsupported chain ID: {chain_id}"));
            let outcome = call.is_broadcast().then_some(BroadcastOutcome::NotSent);
            self.reply(id, Err(ChainError::Thrown(error)), outcome, 0);
            return id;
        }
        let bounds = self.ctx.bounds;
        let deadline_ms = deadline_ms.map_or(bounds.deadline_ms, |d| d.min(bounds.deadline_ms));
        let deadline_at = self.now().saturating_add(deadline_ms);
        let room = self.running.len() < bounds.running;
        let busy =
            !self.ctx.budget.borrow().admits() || (!room && self.waiting.len() >= bounds.waiting);
        if busy {
            let outcome = call.is_broadcast().then_some(BroadcastOutcome::NotSent);
            self.reply(id, Err(ChainError::Protocol(Protocol::Busy)), outcome, 0);
            return id;
        }
        if room {
            self.start(id, call, deadline_at);
        } else {
            let deadline = started(self.ctx.rt.sleep(deadline_ms));
            self.waiting.push_back(Waiting {
                id,
                call,
                deadline,
                deadline_at,
            });
        }
        id
    }

    fn start(&mut self, id: u64, call: Call, deadline_at: Ms) {
        let chain_id = call.chain_id();
        let found = self.ctx.state.borrow().chains.get(&chain_id).cloned();
        let Some((chain, generation)) = found else {
            let error = Thrown::error(&format!("Unsupported chain ID: {chain_id}"));
            let outcome = call.is_broadcast().then_some(BroadcastOutcome::NotSent);
            self.reply(id, Err(ChainError::Thrown(error)), outcome, 0);
            return;
        };
        let now = self.now();
        let deadline = started(self.ctx.rt.sleep(deadline_at.saturating_sub(now)));
        let req = Rc::new(Req::new(Rc::clone(&self.ctx), chain));
        let mut send = None;
        let task: Task<'static, Done> = match call {
            Call::Read {
                method,
                params,
                options,
                ..
            } => Task::new(async move { Done::Read(read(&req, &method, &params, &options).await) }),
            Call::FeeQuote { .. } => Task::new(async move { Done::Fee(fee_quote(&req).await) }),
            Call::Broadcast { raw, .. } => {
                let state = Rc::new(RefCell::new(SendState::default()));
                send = Some(Rc::clone(&state));
                let stop_at = deadline_at.saturating_sub(self.ctx.bounds.reconcile_ms);
                Task::new(async move {
                    if stop_at <= req.now() {
                        // No room left to attempt and reconcile.
                        return Done::Broadcast(Ended::Failed {
                            error: Thrown::error("The broadcast's deadline left no room"),
                            outcome: BroadcastOutcome::NotSent,
                        });
                    }
                    Done::Broadcast(broadcast(&req, &raw, &state, stop_at, deadline_at).await)
                })
            }
        };
        self.origins.insert(id, generation);
        self.running.push(Running {
            id,
            chain_id,
            generation,
            task,
            deadline,
            send,
        });
    }

    fn reply(
        &mut self,
        id: u64,
        result: Result<Success, ChainError>,
        outcome: Option<BroadcastOutcome>,
        generation: u64,
    ) {
        let bounds = self.ctx.bounds;
        let bytes = reply_bytes(&result);
        let (result, outcome) = if bytes > bounds.message_bytes {
            (Err(ChainError::Protocol(Protocol::TooLarge)), outcome)
        } else {
            (result, outcome)
        };
        let bytes = reply_bytes(&result);
        self.ctx.budget.borrow_mut().add_output(bytes);
        self.replies.push(Reply {
            id,
            result,
            outcome,
            settled: self.now(),
            generation,
        });
    }

    /// Ends running request `i` from outside: a read or a fee quote with
    /// `code`; a broadcast through the outcome table. Its I/O is cancelled;
    /// verifier work keeps its slot until main's terminal reply.
    fn end(&mut self, i: usize, code: Protocol) {
        let running = self.running.remove(i);
        let Running {
            id,
            generation,
            task,
            send,
            ..
        } = running;
        drop(task);
        self.ctx.budget.borrow_mut().forget(id);
        match send {
            Some(state) => match ended_from(&state.borrow()) {
                Some(ended) => self.broadcast_reply(id, ended, generation),
                None => self.reply(
                    id,
                    Err(ChainError::Protocol(code)),
                    Some(BroadcastOutcome::NotSent),
                    generation,
                ),
            },
            None => self.reply(id, Err(ChainError::Protocol(code)), None, generation),
        }
    }

    fn broadcast_reply(&mut self, id: u64, ended: Ended, generation: u64) {
        match ended {
            Ended::Reported {
                hash,
                source,
                outcome,
            } => self.reply(
                id,
                Ok(Success::Broadcast {
                    hash,
                    source,
                    outcome,
                }),
                None,
                generation,
            ),
            Ended::Failed { error, outcome } => self.reply(
                id,
                Err(ChainError::Thrown(error)),
                Some(outcome),
                generation,
            ),
        }
    }

    fn finish(&mut self, i: usize) {
        let mut running = self.running.remove(i);
        let done = running.task.take();
        let Running { id, generation, .. } = running;
        self.ctx.budget.borrow_mut().forget(id);
        match done {
            Some(Done::Read(Ok(answer))) => {
                let result = answer.result.as_ref().map(|text| text.json().to_owned());
                drop(answer.result);
                self.reply(
                    id,
                    Ok(Success::Read {
                        result,
                        source: answer.source,
                        verified: answer.verified,
                        trust: answer.trust,
                    }),
                    None,
                    generation,
                );
            }
            Some(Done::Read(Err(error)) | Done::Fee(Err(error))) => {
                self.reply(id, Err(ChainError::Thrown(error)), None, generation);
            }
            Some(Done::Fee(Ok(quote))) => {
                self.reply(id, Ok(Success::FeeQuote(quote)), None, generation);
            }
            Some(Done::Broadcast(ended)) => self.broadcast_reply(id, ended, generation),
            None => {}
        }
    }

    /// `cancel` from main: a read or fee quote ends `cancelled` at once; a
    /// broadcast through the outcome table. False when the request has
    /// already replied.
    pub fn cancel(&mut self, id: u64) -> bool {
        if let Some(i) = self.running.iter().position(|r| r.id == id) {
            self.end(i, Protocol::Cancelled);
            return true;
        }
        if let Some(i) = self.waiting.iter().position(|w| w.id == id) {
            let waiting = self.waiting.remove(i);
            if let Some(waiting) = waiting {
                let outcome = waiting
                    .call
                    .is_broadcast()
                    .then_some(BroadcastOutcome::NotSent);
                self.reply(
                    id,
                    Err(ChainError::Protocol(Protocol::Cancelled)),
                    outcome,
                    0,
                );
            }
            return true;
        }
        false
    }

    /// Polls every request until nothing more happens at this instant.
    pub fn poll(&mut self) {
        // Each pass either changes something or ends the loop; the bound
        // only guards against a bug.
        for _ in 0..100_000 {
            let before = self.ctx.progress();
            let mut changed = self.ctx.poll_held();
            let mut i = 0;
            while i < self.running.len() {
                let id = self.running[i].id;
                self.ctx.current.set(id);
                self.ctx.rt.set_owner(id);
                let finished = self.running[i].task.poll();
                self.ctx.current.set(0);
                self.ctx.rt.set_owner(0);
                if self.ctx.budget.borrow().over(id) {
                    self.end(i, Protocol::Budget);
                    changed = true;
                } else if finished {
                    self.finish(i);
                    changed = true;
                } else if ready(&mut self.running[i].deadline) {
                    self.end(i, Protocol::Deadline);
                    changed = true;
                } else {
                    i += 1;
                }
            }
            changed |= self.admit_waiting();
            if !changed && self.ctx.progress() == before {
                break;
            }
        }
    }

    /// Waiting requests: an expired one replies `deadline`; others start
    /// while there is room.
    fn admit_waiting(&mut self) -> bool {
        let mut changed = false;
        let mut i = 0;
        while i < self.waiting.len() {
            if ready(&mut self.waiting[i].deadline)
                && let Some(waiting) = self.waiting.remove(i)
            {
                let outcome = waiting
                    .call
                    .is_broadcast()
                    .then_some(BroadcastOutcome::NotSent);
                self.reply(
                    waiting.id,
                    Err(ChainError::Protocol(Protocol::Deadline)),
                    outcome,
                    0,
                );
                changed = true;
                continue;
            }
            i += 1;
        }
        while self.running.len() < self.ctx.bounds.running
            && let Some(waiting) = self.waiting.pop_front()
        {
            self.start(waiting.id, waiting.call, waiting.deadline_at);
            changed = true;
        }
        changed
    }

    /// The replies made since the last call; the driver's backlog counts
    /// them from now on.
    pub fn take_replies(&mut self) -> Vec<Reply> {
        self.ctx.budget.borrow_mut().take_output();
        std::mem::take(&mut self.replies)
    }

    /// The driver's replies not yet written: they count in the total
    /// (`memory-budgets`).
    pub fn set_output_backlog(&mut self, bytes: usize) {
        self.ctx.budget.borrow_mut().set_backlog(bytes);
    }

    /// The effects since the last call.
    pub fn take_effects(&mut self) -> Vec<Emitted> {
        let effects = self.ctx.rt.take_effects();
        let emitted = effects
            .into_iter()
            .map(|effect| {
                let (request, generation) = match &effect {
                    Effect::Request { owner, .. } if *owner != 0 => {
                        (Some(*owner), self.origins.get(owner).copied())
                    }
                    _ => (None, None),
                };
                Emitted {
                    effect,
                    request,
                    generation,
                }
            })
            .collect();
        let live: Vec<u64> = self.running.iter().map(|r| r.id).collect();
        self.origins.retain(|id, _| live.contains(id));
        emitted
    }

    /// Main's terminal reply to I/O request `id`. It counts against its
    /// request's budget (`memory-budgets`); one that crosses it is dropped,
    /// and the request ends at the next poll. False when nothing waits for
    /// it (cancelled, or unknown).
    pub fn complete(&mut self, id: u64, answer: Answer) -> bool {
        let owner = self.ctx.rt.owner_of(id).unwrap_or(0);
        let request = if self.running.iter().any(|r| r.id == owner) {
            owner
        } else {
            0
        };
        match budget::charge(&self.ctx.budget, request, answer.bytes()) {
            Ok(charge) => self.ctx.rt.complete(id, Delivered { answer, charge }),
            Err(_) => false,
        }
    }

    /// Schedules a driver event at `at` (see the executor).
    pub fn schedule(&self, at: Ms, token: u64) {
        self.ctx.rt.schedule(at, token);
    }

    pub fn next_due(&self) -> Option<Ms> {
        self.ctx.rt.next_due()
    }

    pub fn fire_next(&self, until: Ms) -> Option<Fired> {
        self.ctx.rt.fire_next(until)
    }

    /// Running and waiting requests.
    pub fn running(&self) -> usize {
        self.running.len()
    }

    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }

    /// What running requests hold (`memory-budgets`).
    pub fn held(&self) -> usize {
        self.ctx.budget.borrow().held()
    }

    /// The state tables.
    pub fn state_tables(&self) -> StateTables {
        let state = self.ctx.state.borrow();
        StateTables {
            adaptive: state.adaptive.routes().to_vec(),
            myotis_slots: state
                .myotis
                .iter()
                .filter(|(_, s)| s.in_flight > 0 || !s.waiters.is_empty())
                .map(|(chain, s)| (*chain, s.in_flight, s.waiters.len()))
                .collect(),
            colibri_in_flight: state.colibri.in_flight,
            colibri_routes: state.colibri.routes.clone(),
            log_range: state.logs.range.clone(),
            log_index_cool_until: state.logs.index_cool_until.clone(),
            log_index_pair_cool_until: state.logs.pair_cool_until.clone(),
        }
    }
}
