//! The machine a driver runs (design 0005): `chain.configure`,
//! `chain.availability`, `chain.request`, `chain.fee_quote`,
//! `chain.fee_reference`, `chain.broadcast`, `chain.html` (design 0006)
//! and `cancel` in; `shell.*`
//! requests, cancels and replies out. Time comes in through the executor's
//! timers.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Waker};

use fc_naming::session::exec::{Effect, Fired, Sleep, Task};

use super::bounds::Bounds;
use super::budget::{self, Charge};
use super::config::{Chain, ChainConfig};
use super::ctx::{Ctx, Req};
use super::error::{ChainError, Protocol, Thrown};
use super::html::{HtmlAnswer, html};
use super::io::{Answer, Delivered, Ms, Request, Transport};
use super::logs::RangeEntry;
use super::quote::{FeeReference, fee_quote, fee_reference};
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
    /// `chain.fee_reference`: the evidence for main's fee check (design
    /// 0005, A).
    FeeReference { chain_id: u64 },
    /// `chain.broadcast`.
    Broadcast { chain_id: u64, raw: String },
    /// `chain.html` (design 0006): the `web3:` handler's `html()` read of
    /// `contract`, the address as `ethers.getAddress` gives it (the driver
    /// checks it), interactive for `origin`, and today's checks of the
    /// document.
    Html {
        chain_id: u64,
        contract: String,
        origin: String,
    },
}

impl Call {
    fn chain_id(&self) -> u64 {
        match self {
            Self::Read { chain_id, .. }
            | Self::FeeQuote { chain_id }
            | Self::FeeReference { chain_id }
            | Self::Broadcast { chain_id, .. }
            | Self::Html { chain_id, .. } => *chain_id,
        }
    }

    fn is_broadcast(&self) -> bool {
        matches!(self, Self::Broadcast { .. })
    }

    /// The bytes it holds while queued and running, as the budget counts
    /// them: its strings.
    fn bytes(&self) -> usize {
        match self {
            Self::Read {
                method,
                params,
                options,
                ..
            } => {
                method.capacity()
                    + params.capacity()
                    + options.origin.as_ref().map_or(0, String::capacity)
                    + options
                        .exclude_sources
                        .iter()
                        .chain(&options.include_sources)
                        .map(String::capacity)
                        .sum::<usize>()
            }
            Self::FeeQuote { .. } | Self::FeeReference { .. } => 0,
            Self::Broadcast { raw, .. } => raw.capacity(),
            Self::Html {
                contract, origin, ..
            } => contract.capacity() + origin.capacity(),
        }
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
    /// `chain.fee_reference`'s `{ header, lowest_priority, quote }`.
    FeeReference(FeeReference),
    /// `{ hash, source, outcome }`: `sent` or `uncertain`.
    Broadcast {
        hash: Option<String>,
        source: &'static str,
        outcome: BroadcastOutcome,
    },
    /// `chain.html`'s document (design 0006): its UTF-8, its hash
    /// (`keccak256(utf8(html))`), the read's `source`, `verified` and
    /// `trust` (with endpoint references), and the gate's class.
    Html {
        html: String,
        hash: [u8; 32],
        source: &'static str,
        verified: bool,
        trust: Option<String>,
        class: fc_dweb::Class,
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
    Reference(FeeReference),
    Broadcast(Ended),
    Html(Result<HtmlAnswer, Thrown>),
}

struct Running {
    id: u64,
    chain_id: u64,
    generation: u64,
    task: Task<'static, Done>,
    deadline: Sleep<Request, Delivered>,
    /// A broadcast's attempts, for the outcome table.
    send: Option<Rc<RefCell<SendState>>>,
    /// The call's own strings, charged from its admission.
    _input: Charge,
}

struct Waiting {
    id: u64,
    call: Call,
    deadline: Sleep<Request, Delivered>,
    deadline_at: Ms,
    /// The call's own strings, charged from its admission.
    input: Charge,
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

/// A reply's frame around its result or message.
const ENVELOPE: usize = 256;

/// A document's hash in a reply: `"0x"` and 64 digits, quoted.
const HASH_JSON: usize = 68;

/// A fee reference's reply besides its quote: its keys, and a header's and
/// a priority fee's decimals (at most 78 digits each).
const REFERENCE_JSON: usize = 512;

/// A document's bytes in a reply, as base64.
fn base64_len(bytes: usize) -> usize {
    bytes.div_ceil(3).saturating_mul(4)
}

/// What a reply takes on the wire, serialized: its result or message and
/// an envelope. Measured, never written.
fn reply_wire_bytes(result: &Result<Success, ChainError>) -> usize {
    ENVELOPE
        + match result {
            Ok(Success::Read { result, trust, .. }) => {
                result.as_ref().map_or(0, String::len) + trust.as_ref().map_or(0, String::len)
            }
            Ok(Success::FeeQuote(quote)) => quote.json_len(),
            Ok(Success::FeeReference(reference)) => {
                REFERENCE_JSON + reference.quote.as_ref().map_or(0, FeeQuote::json_len)
            }
            Ok(Success::Broadcast { hash, .. }) => hash.as_ref().map_or(0, String::len),
            Ok(Success::Html { html, trust, .. }) => {
                base64_len(html.len()) + HASH_JSON + trust.as_ref().map_or(0, String::len)
            }
            Err(ChainError::Protocol(_)) => 0,
            Err(ChainError::Thrown(thrown)) => thrown.json_len(),
        }
}

/// What a queued reply holds on the heap until the driver takes it: the
/// output it is counted as (`memory-budgets`).
fn reply_heap_bytes(result: &Result<Success, ChainError>) -> usize {
    ENVELOPE
        + match result {
            Ok(Success::Read { result, trust, .. }) => {
                result.as_ref().map_or(0, String::capacity)
                    + trust.as_ref().map_or(0, String::capacity)
            }
            Ok(Success::FeeQuote(quote)) => quote.heap_bytes(),
            Ok(Success::FeeReference(reference)) => reference.heap_bytes(),
            Ok(Success::Broadcast { hash, .. }) => hash.as_ref().map_or(0, String::capacity),
            Ok(Success::Html { html, trust, .. }) => {
                html.capacity() + trust.as_ref().map_or(0, String::capacity)
            }
            Err(ChainError::Protocol(_)) => 0,
            Err(ChainError::Thrown(thrown)) => thrown.heap_bytes(),
        }
}

/// What a request receives for a reply nobody reads: a transport failure,
/// never a proof that nothing was sent; it is never polled anyway (its
/// request has ended, or is over its budget and ends first).
fn unread() -> Delivered {
    Delivered {
        answer: Answer::Failed(Transport::Network),
        charge: Charge::none(),
        discarded: true,
    }
}

/// Reading main's reply would cross its request's budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverBudget;

/// Bytes reserved against a request's budget for main's reply to one of
/// its I/O requests, before the driver allocates them
/// ([`Machine::reserve_reply`]). Released when dropped, or carried into the
/// answer's charge ([`Machine::complete_reserved`]).
#[derive(Debug)]
pub struct Reservation(Charge);

impl Reservation {
    /// The bytes it holds.
    pub fn bytes(&self) -> usize {
        self.0.bytes()
    }

    /// Makes it `bytes`, before what they cover is allocated: a shrink is
    /// released, a growth charged. `Err` when the growth crosses the
    /// request's bound or the total's: the request is over.
    pub fn settle(&mut self, bytes: usize) -> Result<(), OverBudget> {
        self.0.settle(bytes).map_err(|()| OverBudget)
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
        let chain_id = call.chain_id();
        // A reply made at once is computed under the chain's current
        // generation, so main's fence doesn't take it for an overtaken one
        // (design 0005, Generations); 0 for a chain not configured.
        let current = self.generation_of(chain_id);
        // Refusals before any I/O, as the router throws them.
        if let Call::Read { method, .. } = &call
            && !is_read_method(method)
        {
            let error = Thrown::error(&unsupported_read_method_text(method));
            self.reply(id, Err(ChainError::Thrown(error)), None, current);
            return id;
        }
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
        // Admission judges what the call brings: its strings, held while it
        // waits and runs (`memory-budgets`).
        let bytes = call.bytes();
        let fits = self.ctx.budget.borrow().admits(bytes);
        let busy = !fits || (!room && self.waiting.len() >= bounds.waiting);
        let input = if busy {
            None
        } else {
            budget::charge(&self.ctx.budget, id, bytes).ok()
        };
        let Some(input) = input else {
            self.ctx.budget.borrow_mut().forget(id);
            let outcome = call.is_broadcast().then_some(BroadcastOutcome::NotSent);
            self.reply(
                id,
                Err(ChainError::Protocol(Protocol::Busy)),
                outcome,
                current,
            );
            return id;
        };
        if room {
            self.start(id, call, deadline_at, input);
        } else {
            let deadline = started(self.ctx.rt.sleep(deadline_ms));
            self.waiting.push_back(Waiting {
                id,
                call,
                deadline,
                deadline_at,
                input,
            });
        }
        id
    }

    /// The chain's current generation (0 for one not configured).
    fn generation_of(&self, chain_id: u64) -> u64 {
        self.ctx
            .state
            .borrow()
            .chains
            .get(&chain_id)
            .map_or(0, |(_, generation)| *generation)
    }

    fn start(&mut self, id: u64, call: Call, deadline_at: Ms, input: Charge) {
        let chain_id = call.chain_id();
        let found = self.ctx.state.borrow().chains.get(&chain_id).cloned();
        let Some((chain, generation)) = found else {
            let error = Thrown::error(&format!("Unsupported chain ID: {chain_id}"));
            let outcome = call.is_broadcast().then_some(BroadcastOutcome::NotSent);
            drop(input);
            self.ctx.budget.borrow_mut().forget(id);
            self.reply(id, Err(ChainError::Thrown(error)), outcome, 0);
            return;
        };
        let now = self.now();
        // An expired call starts nothing: no poll, no I/O.
        if deadline_at <= now {
            let outcome = call.is_broadcast().then_some(BroadcastOutcome::NotSent);
            drop(input);
            self.ctx.budget.borrow_mut().forget(id);
            self.reply(
                id,
                Err(ChainError::Protocol(Protocol::Deadline)),
                outcome,
                generation,
            );
            return;
        }
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
            Call::FeeReference { .. } => {
                Task::new(async move { Done::Reference(fee_reference(&req).await) })
            }
            Call::Html {
                contract, origin, ..
            } => Task::new(async move { Done::Html(html(&req, &contract, origin).await) }),
            Call::Broadcast { raw, .. } => {
                let stop_at = deadline_at.saturating_sub(self.ctx.bounds.reconcile_ms);
                if stop_at <= now {
                    // No room to attempt and reconcile before the deadline:
                    // nothing is sent.
                    self.reply(
                        id,
                        Err(ChainError::Protocol(Protocol::Deadline)),
                        Some(BroadcastOutcome::NotSent),
                        generation,
                    );
                    return;
                }
                let state = Rc::new(RefCell::new(SendState::default()));
                send = Some(Rc::clone(&state));
                Task::new(async move {
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
            _input: input,
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
        // The reply's error leaves its request's charge, and the quorum's
        // evidence, behind: the reply counts as output from here on, at
        // what it holds (its message's UTF-16 units included).
        let result = match result {
            Err(ChainError::Thrown(mut thrown)) => {
                thrown.charge = None;
                thrown.quorum = None;
                Err(ChainError::Thrown(thrown))
            }
            other => other,
        };
        let result = if reply_wire_bytes(&result) > bounds.message_bytes {
            Err(ChainError::Protocol(Protocol::TooLarge))
        } else {
            result
        };
        self.ctx
            .budget
            .borrow_mut()
            .add_output(reply_heap_bytes(&result));
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
        let (id, generation) = (running.id, running.generation);
        match done {
            Some(Done::Read(Ok(answer))) => {
                // The reply's copy of the result, reserved before it is
                // made, while the request still holds the original.
                let len = answer.result.as_ref().map_or(0, |text| text.json().len());
                let Ok(copy) = budget::charge(&self.ctx.budget, id, len) else {
                    drop((answer, running));
                    self.ctx.budget.borrow_mut().forget(id);
                    self.reply(
                        id,
                        Err(ChainError::Protocol(Protocol::Budget)),
                        None,
                        generation,
                    );
                    return;
                };
                let result = answer.result.as_ref().map(|text| text.json().to_owned());
                drop((copy, running));
                self.ctx.budget.borrow_mut().forget(id);
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
            Some(Done::Html(Ok(answer))) => {
                let HtmlAnswer {
                    html,
                    hash,
                    source,
                    verified,
                    trust,
                    class,
                    charge,
                } = answer;
                // The document leaves the request's charge for the reply,
                // which counts it as output until it is written.
                drop((charge, running));
                self.ctx.budget.borrow_mut().forget(id);
                self.reply(
                    id,
                    Ok(Success::Html {
                        html,
                        hash,
                        source,
                        verified,
                        trust,
                        class,
                    }),
                    None,
                    generation,
                );
            }
            Some(Done::Read(Err(error)) | Done::Fee(Err(error)) | Done::Html(Err(error))) => {
                drop(running);
                self.ctx.budget.borrow_mut().forget(id);
                self.reply(id, Err(ChainError::Thrown(error)), None, generation);
            }
            Some(Done::Fee(Ok(quote))) => {
                drop(running);
                self.ctx.budget.borrow_mut().forget(id);
                self.reply(id, Ok(Success::FeeQuote(quote)), None, generation);
            }
            Some(Done::Reference(reference)) => {
                drop(running);
                self.ctx.budget.borrow_mut().forget(id);
                self.reply(id, Ok(Success::FeeReference(reference)), None, generation);
            }
            Some(Done::Broadcast(ended)) => {
                drop(running);
                self.ctx.budget.borrow_mut().forget(id);
                self.broadcast_reply(id, ended, generation);
            }
            None => {
                drop(running);
                self.ctx.budget.borrow_mut().forget(id);
            }
        }
    }

    /// `cancel` from main: a read, a fee quote or a fee reference ends
    /// `cancelled` at once; a
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
                let generation = self.generation_of(waiting.call.chain_id());
                drop(waiting.input);
                self.ctx.budget.borrow_mut().forget(id);
                self.reply(
                    id,
                    Err(ChainError::Protocol(Protocol::Cancelled)),
                    outcome,
                    generation,
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
                // A request over its budget is never polled again: its
                // futures make no more I/O and change no shared state.
                if self.ctx.budget.borrow().over(id) {
                    self.end(i, Protocol::Budget);
                    changed = true;
                    continue;
                }
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
                let generation = self.generation_of(waiting.call.chain_id());
                drop(waiting.input);
                self.ctx.budget.borrow_mut().forget(waiting.id);
                self.reply(
                    waiting.id,
                    Err(ChainError::Protocol(Protocol::Deadline)),
                    outcome,
                    generation,
                );
                changed = true;
                continue;
            }
            i += 1;
        }
        while self.running.len() < self.ctx.bounds.running
            && let Some(waiting) = self.waiting.pop_front()
        {
            self.start(waiting.id, waiting.call, waiting.deadline_at, waiting.input);
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

    /// The bytes of the frames the driver has taken and not yet written,
    /// replies and requests alike: they count in the total
    /// (`memory-budgets`).
    pub fn set_output_backlog(&mut self, bytes: usize) {
        self.ctx.budget.borrow_mut().set_backlog(bytes);
    }

    /// The effects since the last call.
    pub fn take_effects(&mut self) -> Vec<Emitted> {
        let effects = self.ctx.rt.take_effects();
        // The requests leave the machine: their charges end here, and the
        // driver's backlog counts them until written.
        self.ctx.take_pending();
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

    /// The request that made I/O request `id`, while it runs: only then
    /// does anyone read main's reply to it.
    fn reader_of(&self, id: u64) -> Option<u64> {
        let owner = self.ctx.rt.owner_of(id)?;
        self.running.iter().any(|r| r.id == owner).then_some(owner)
    }

    /// Whether request `id` is running: only then can its I/O still be
    /// wanted. A driver retires the I/O it holds back for a request that
    /// isn't, however its reply has gone.
    pub fn runs(&self, id: u64) -> bool {
        self.running.iter().any(|r| r.id == id)
    }

    /// Whether a running request waits for main's reply to I/O request
    /// `id`. Main's reply to anything else (an I/O request cancelled, or
    /// one whose request has ended) is read no further: the driver
    /// completes it with [`Machine::complete_unread`].
    pub fn wants(&self, id: u64) -> bool {
        self.reader_of(id).is_some()
    }

    /// Reserves `bytes` against the budget of the request that made I/O
    /// request `id`, before the driver allocates them to read main's reply
    /// (`memory-budgets`: received messages once handed over, and what
    /// reading them makes). `Err` when that crosses its bound or the
    /// total's: the request is over, and ends with `budget` before it is
    /// polled again (a broadcast through its outcome table, the attempt
    /// still possibly sent); the driver completes `id` with
    /// [`Machine::complete_unread`]. Nothing is charged for a reply nobody
    /// wants.
    pub fn reserve_reply(&self, id: u64, bytes: usize) -> Result<Reservation, OverBudget> {
        let Some(owner) = self.reader_of(id) else {
            return Ok(Reservation(Charge::none()));
        };
        budget::charge(&self.ctx.budget, owner, bytes)
            .map(Reservation)
            .map_err(|_| OverBudget)
    }

    /// Main's terminal reply to I/O request `id`. It counts against its
    /// request's budget (`memory-budgets`); one that crosses it is dropped,
    /// and the request ends at the next poll. One whose request has ended
    /// is dropped at once. Either way a verifier operation still completes,
    /// freeing its slot. False when nothing waits for it (cancelled, or
    /// unknown), or when it crossed the budget.
    pub fn complete(&mut self, id: u64, answer: Answer) -> bool {
        match self.reserve_reply(id, 0) {
            Ok(reservation) => self.complete_reserved(id, answer, reservation),
            Err(OverBudget) => {
                drop(answer);
                self.complete_unread(id);
                false
            }
        }
    }

    /// Main's terminal reply to I/O request `id`, read within
    /// `reservation` ([`Machine::reserve_reply`]): the reservation becomes
    /// the answer's charge, settled to what the answer holds. Otherwise as
    /// [`Machine::complete`].
    pub fn complete_reserved(
        &mut self,
        id: u64,
        answer: Answer,
        mut reservation: Reservation,
    ) -> bool {
        // Main enforces `max_bytes`; an answer over the cap anyway is the
        // `too_large` failure it should have been (`response-caps`).
        let answer = match answer {
            Answer::Rpc { body, .. } if body.len() > self.ctx.bounds.answer_bytes => {
                Answer::Failed(Transport::TooLarge)
            }
            answer => answer,
        };
        if self.reader_of(id).is_none() {
            // Its caller has ended: nobody will read the payload, which is
            // dropped now rather than held uncharged. Main's terminal reply
            // still completes the operation, so a verifier's slot is freed
            // at the next poll.
            drop((answer, reservation));
            return self.ctx.rt.complete(id, unread());
        }
        match reservation.0.settle(answer.bytes()) {
            Ok(()) => self.ctx.rt.complete(
                id,
                Delivered {
                    answer,
                    charge: reservation.0,
                    discarded: false,
                },
            ),
            Err(()) => {
                // Over its request's budget: the payload is dropped, but
                // main's one terminal reply still completes the operation,
                // so a verifier's slot is freed. The request ends with
                // `budget` (a broadcast through its outcome table) before
                // it is polled again.
                drop((answer, reservation));
                self.ctx.rt.complete(id, unread());
                false
            }
        }
    }

    /// Main's terminal reply to I/O request `id`, unread: nobody wants it
    /// ([`Machine::wants`]), or reading it would cross its request's budget
    /// ([`Machine::reserve_reply`]). It completes the operation, freeing a
    /// verifier's slot, and delivers nothing that could be taken for proof
    /// that nothing was sent.
    pub fn complete_unread(&mut self, id: u64) -> bool {
        self.ctx.rt.complete(id, unread())
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
