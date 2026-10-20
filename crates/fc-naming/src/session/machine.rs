//! The machine a driver runs: sessions, their deduplication and lifecycle
//! restarts (`resolveWithCache`, `resolveAcrossStableLifecycle`), and the
//! prefetches it keeps alive.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Waker};

use super::ens::{self, Answer, Config, Ctx, Request, Store, Thrown};
use super::exec::{Effect, Fired, Io, Ms, Sleep, Task};
use super::random::Random;
use crate::jsjson::JsValue;

/// What the machine shares with its sessions beyond [`Ctx`]: the
/// prefetches it keeps running.
pub struct Shared {
    ctx: Rc<Ctx>,
    /// Each with the session that handed it off.
    prefetches: RefCell<Vec<(u64, Io<Request, Answer>)>>,
}

impl Shared {
    /// `prefetchOnFirstData`: asks main to prefetch the first answer's URI.
    /// The wave owns the request until its outcome; dropping it cancels.
    pub(crate) fn start_prefetch(&self, resolved: &[u8]) -> Option<Io<Request, Answer>> {
        let uri = ens::prefetch_uri(resolved)?;
        let mut io = self.ctx.rt.request(Request::Prefetch { uri });
        // The first poll emits the request.
        let mut cx = Context::from_waker(Waker::noop());
        if Pin::new(&mut io).poll(&mut cx).is_ready() {
            return None;
        }
        Some(io)
    }

    /// After `agreed_data` the prefetch survives its session in the
    /// machine's set (design 0004, Prefetch). Deviation `prefetch-set`:
    /// past the bound, the oldest is cancelled.
    pub(crate) fn keep_prefetch(&self, mut io: Io<Request, Answer>) {
        // A session that spent its budget hands nothing off: dropping the
        // prefetch cancels it.
        if self.ctx.over_budget() {
            return;
        }
        let limit = self.ctx.bounds().prefetches;
        let mut cx = Context::from_waker(Waker::noop());
        // A prefetch that already finished has nothing left to keep.
        if Pin::new(&mut io).poll(&mut cx).is_ready() {
            return;
        }
        let mut prefetches = self.prefetches.borrow_mut();
        // Finished ones have left the set before it is counted.
        prefetches.retain_mut(|(_, kept)| Pin::new(kept).poll(&mut cx).is_pending());
        prefetches.push((self.ctx.session.get(), io));
        while prefetches.len() > limit {
            prefetches.remove(0);
        }
    }

    fn poll(&self) {
        let mut cx = Context::from_waker(Waker::noop());
        self.prefetches
            .borrow_mut()
            .retain_mut(|(_, io)| Pin::new(io).poll(&mut cx).is_pending());
    }

    /// A session that spent its budget keeps nothing running: dropping its
    /// prefetches cancels them.
    fn cancel_prefetches(&self, session: u64) {
        self.prefetches
            .borrow_mut()
            .retain(|(owner, _)| *owner != session);
    }
}

/// A resolution's outcome.
pub type Outcome = Result<JsValue, Thrown>;

/// Design 0004's generations. Each only ever advances within a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Generations {
    /// Advanced by a configuration whose ENS part changed.
    pub ens: u64,
    /// Advanced by a configuration whose Tezos part changed.
    pub tezos: u64,
    /// Advanced by `naming.availability` and `reset: "providers"`.
    pub lifecycle: u64,
}

/// A caller's options (design 0004, Generations and Admission).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CallOptions {
    /// Lifecycle attempts used before main resubmitted this request.
    pub attempts_used: u32,
    /// The caller's deadline from its admission; the bound's when `None`.
    pub deadline_ms: Option<Ms>,
}

/// A waiting caller: its lifecycle attempts and its own deadline.
struct Caller {
    id: u64,
    attempts: u32,
    deadline: Sleep<Request, Answer>,
}

/// How an attempt ended.
enum Attempt {
    Done(Outcome),
    /// It crossed a lifecycle change: its result is discarded.
    Crossed,
}

/// Starts one attempt of a session's work.
type Start = Rc<dyn Fn() -> Task<'static, Attempt>>;

/// The generation that scopes a session (design 0004, Generations).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    Ens,
    Tezos,
}

/// An effect, with the generations of the attempt that made it: a request
/// carries them for main's fence; a cancel has the current ones.
#[derive(Debug, Clone, PartialEq)]
pub struct Emitted {
    pub effect: Effect<Request>,
    pub generations: Generations,
    /// When the session that made it ends: no request outlives that.
    pub deadline: Ms,
}

struct Session {
    /// The in-flight key; empty once retired (nothing joins it).
    key: String,
    callers: Vec<Caller>,
    task: Task<'static, Attempt>,
    /// The attempts the session has run, which bound it without callers.
    attempts: u32,
    /// The generations its current attempt runs under.
    generations: Generations,
    /// The session's own deadline (`overall-deadline`).
    deadline: Sleep<Request, Answer>,
    /// Starts another attempt; `None` where nothing restarts (Tezos).
    restart: Option<Start>,
    /// The name in "changed repeatedly" errors.
    subject: String,
    scope: Scope,
    /// Tags the current attempt's requests ([`Machine::take_effects`]).
    owner: u64,
    /// When its deadline ends it.
    ends: Ms,
    /// Its budget's key (deviation `memory-budgets`).
    id: u64,
    /// Where its result is cached, to take it back.
    cached: Cached,
    /// Frees what it holds when it ends, however it ends.
    _held: Held,
}

/// A session's result cache and key.
enum Cached {
    Ens(Store, String),
    Tezos(String),
}

/// A session's place in the budget, released when the session is dropped.
struct Held {
    ctx: Rc<Ctx>,
    session: u64,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.ctx.budget.borrow_mut().release(self.session);
    }
}

/// What a session keeps of its name and key: `dedup` is its in-flight key.
fn input_bytes(dedup: &str) -> usize {
    dedup.len().saturating_mul(super::budget::INPUT_COPIES)
}

/// What a request holds while it is made: its payload strings.
fn request_bytes(request: &Request) -> usize {
    match request {
        Request::Rpc { endpoint, body } => endpoint.len() + body.len(),
        Request::Gateway { url, body } => url.len() + body.as_ref().map_or(0, String::len),
        Request::Prefetch { uri } => uri.len(),
        Request::Tezos {
            endpoint,
            path,
            body,
            ..
        } => endpoint.len() + path.len() + body.as_ref().map_or(0, String::len),
        Request::Verified(op) => match op {
            super::ens::VerifiedOp::MyotisRecord { name, address, .. } => {
                name.as_ref().map_or(0, String::len) + address.as_ref().map_or(0, String::len)
            }
            super::ens::VerifiedOp::MyotisCall { data, .. } => data.len(),
            super::ens::VerifiedOp::ColibriResolve {
                name, call_data, ..
            } => name.len() + call_data.len(),
            super::ens::VerifiedOp::ColibriReverse { .. } => 0,
        },
    }
}

/// What an answer can come to hold: its body parsed as JSON (a bound from
/// counting its values, with the body's own bytes and any replacement of
/// invalid UTF-8), or the verifier's outcome.
fn answer_bytes(answer: &Answer) -> usize {
    use super::budget::PARSED_FACTOR;
    match answer {
        Answer::Rpc { body, .. } | Answer::Gateway { body, .. } | Answer::Tezos { body, .. } => {
            let text = String::from_utf8_lossy(body);
            let decoded = match &text {
                std::borrow::Cow::Owned(owned) => owned.len(),
                std::borrow::Cow::Borrowed(_) => 0,
            };
            body.len()
                .saturating_add(decoded)
                .saturating_add(super::budget::parsed_bound(&text))
        }
        Answer::Verified(super::ens::Verified::Result(value)) => {
            value.stringify().len().saturating_mul(PARSED_FACTOR)
        }
        Answer::Verified(super::ens::Verified::Revert(data)) => data.len(),
        Answer::Verified(super::ens::Verified::Failure(class)) => class.len(),
        Answer::Failed(_) | Answer::Done => 0,
    }
}

/// Whether a JSON-RPC body the core wrote asks for a head or a block, which
/// only the anchor does.
fn is_anchor_body(body: &str) -> bool {
    body.contains(r#""method":"eth_blockNumber""#)
        || body.contains(r#""method":"eth_getBlockByNumber""#)
}

/// One caller's terminal reply.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub caller: u64,
    pub outcome: Outcome,
    pub settled: Ms,
    /// The generations the result was computed under.
    pub generations: Generations,
    /// The lifecycle attempts this caller used.
    pub attempts: u32,
}

/// What a reply costs: its own copy of the outcome (each caller gets one),
/// or its serialized form, whichever is larger. A result's tree can hold
/// far more than it serializes to (nested arrays in a Tezos record, say),
/// so its size on the heap counts, not its length on the wire.
fn reply_bytes(outcome: &Outcome) -> usize {
    let (tree, wire) = match outcome {
        Ok(value) => (value.held(), value.stringify().len()),
        Err(thrown) => {
            let message = JsValue::string(thrown.message.clone());
            (message.held(), message.stringify().len())
        }
    };
    // The copy's own slot, too.
    tree.saturating_add(32).max(wire)
}

/// The replies made and not yet taken: each counts in the budget's total
/// from when it is made until the driver has written it
/// (`memory-budgets`).
struct Replies {
    ctx: Rc<Ctx>,
    list: Vec<Reply>,
}

impl Replies {
    fn push(&mut self, reply: Reply) {
        self.ctx
            .budget
            .borrow_mut()
            .add_output(reply_bytes(&reply.outcome));
        self.list.push(reply);
    }

    fn extend(&mut self, replies: impl IntoIterator<Item = Reply>) {
        for reply in replies {
            self.push(reply);
        }
    }

    fn sort_by_key<K: Ord>(&mut self, key: impl FnMut(&Reply) -> K) {
        self.list.sort_by_key(key);
    }

    /// Handed to the driver, whose backlog counts them from now on.
    fn take(&mut self) -> Vec<Reply> {
        self.ctx.budget.borrow_mut().take_output();
        std::mem::take(&mut self.list)
    }
}

pub struct Machine {
    ctx: Rc<Ctx>,
    shared: Rc<Shared>,
    sessions: Vec<Session>,
    replies: Replies,
    next_caller: u64,
    ens_generation: u64,
    tezos_generation: u64,
    /// Retired RPC and Tezos endpoints, oldest first (`endpoint-retention`).
    retired_rpc: std::collections::VecDeque<String>,
    retired_tezos: std::collections::VecDeque<String>,
    /// The generations of each attempt that may still have untaken
    /// requests, when its session ends, and its session's budget key, by
    /// owner.
    origins: std::collections::BTreeMap<u64, (Generations, Ms, u64)>,
    next_owner: u64,
    /// The anchor's head and block requests (`eth_blockNumber`,
    /// `eth_getBlockByNumber`): their answers are read for a number or a
    /// hash at once, so their charge is taken back as they are read (#73).
    anchor_requests: RefCell<std::collections::BTreeSet<u64>>,
    /// Those answers' charges, until read or cancelled: by request id, the
    /// session and the bytes.
    anchor_charges: AnchorCharges,
}

type AnchorCharges = Rc<RefCell<std::collections::BTreeMap<u64, (u64, usize)>>>;

/// Deviation `endpoint-retention`: endpoints that left the configuration
/// join `retired` (most recent last), re-added ones leave it, and past
/// `bound` the oldest are returned for their state to be dropped.
fn retire(
    retired: &mut std::collections::VecDeque<String>,
    old: &[String],
    new: &[String],
    bound: usize,
) -> Vec<String> {
    for endpoint in old {
        if !new.contains(endpoint) && !retired.contains(endpoint) {
            retired.push_back(endpoint.clone());
        }
    }
    retired.retain(|endpoint| !new.contains(endpoint));
    let mut dropped = Vec::new();
    while retired.len() > bound {
        dropped.extend(retired.pop_front());
    }
    dropped
}

/// `resolveAcrossStableLifecycle`'s attempts, per caller (design 0004,
/// Generations).
pub const MAX_LIFECYCLE_ATTEMPTS: u32 = 3;

type Resolve = Rc<dyn Fn(Rc<Ctx>, Rc<Shared>) -> Pin<Box<dyn Future<Output = Outcome>>>>;

/// Deviation `reply-size`, for every reply: a result or thrown message too
/// large for one reply (an input echoed back, say) becomes `result too
/// large`.
fn sized(outcome: Outcome, bounds: &super::bounds::Bounds) -> Outcome {
    match outcome {
        Ok(value) if !bounds.reply_fits(value.stringify().len()) => Err(Thrown::too_large()),
        Err(thrown)
            if !bounds.reply_fits(JsValue::string(thrown.message.clone()).stringify().len()) =>
        {
            Err(Thrown::too_large())
        }
        other => other,
    }
}

/// A sleep that has registered its timer: [`Sleep`] starts counting when
/// it is first polled.
fn started(mut sleep: Sleep<Request, Answer>) -> Sleep<Request, Answer> {
    let mut cx = Context::from_waker(Waker::noop());
    let _ = Pin::new(&mut sleep).poll(&mut cx);
    sleep
}

fn ready(sleep: &mut Sleep<Request, Answer>) -> bool {
    let mut cx = Context::from_waker(Waker::noop());
    Pin::new(sleep).poll(&mut cx).is_ready()
}

impl Machine {
    pub fn new(now: Ms, config: Config, random: Box<dyn Random>) -> Self {
        let ctx = Rc::new(Ctx::new(now, config, random));
        // An anchor answer's charge goes as a future takes the answer: it
        // reads a number or a hash from it at once, and drops the rest.
        let anchor_charges = AnchorCharges::default();
        {
            let weak = Rc::downgrade(&ctx);
            let charges = Rc::clone(&anchor_charges);
            ctx.rt.set_consumed(move |id| {
                let released = charges.borrow_mut().remove(&id);
                if let (Some(ctx), Some((session, bytes))) = (weak.upgrade(), released) {
                    ctx.budget.borrow_mut().uncharge(session, bytes);
                }
            });
        }
        // A request counts against the session making it as it is made: one
        // that crosses the budget is never emitted (`memory-budgets`).
        let weak = Rc::downgrade(&ctx);
        ctx.rt.set_admit(move |request| {
            weak.upgrade()
                .is_none_or(|ctx| ctx.charge(request_bytes(request)))
        });
        let shared = Rc::new(Shared {
            ctx: Rc::clone(&ctx),
            prefetches: RefCell::new(Vec::new()),
        });
        let replies = Replies {
            ctx: Rc::clone(&ctx),
            list: Vec::new(),
        };
        Self {
            ctx,
            shared,
            sessions: Vec::new(),
            replies,
            next_caller: 1,
            ens_generation: 0,
            tezos_generation: 0,
            retired_rpc: std::collections::VecDeque::new(),
            retired_tezos: std::collections::VecDeque::new(),
            origins: std::collections::BTreeMap::new(),
            next_owner: 1,
            anchor_requests: RefCell::new(std::collections::BTreeSet::new()),
            anchor_charges,
        }
    }

    /// A new attempt's owner, under `generations`, in a session that ends
    /// at `ends`.
    fn owner(&mut self, generations: Generations, ends: Ms, session: u64) -> u64 {
        let owner = self.next_owner;
        self.next_owner += 1;
        self.origins.insert(owner, (generations, ends, session));
        owner
    }

    /// The current generations.
    pub fn generations(&self) -> Generations {
        Generations {
            ens: self.ens_generation,
            tezos: self.tezos_generation,
            lifecycle: self.ctx.state.borrow().lifecycle,
        }
    }

    pub fn now(&self) -> Ms {
        self.ctx.rt.now()
    }

    /// A caller answered at once (a cache hit, an invalid input, busy):
    /// it used no attempt, so it keeps the `attempts` it came with.
    fn reply(&mut self, outcome: Outcome, attempts: u32) -> u64 {
        let caller = self.next_caller;
        self.next_caller += 1;
        let settled = self.now();
        let bounds = self.ctx.bounds();
        let mut outcome = sized(outcome, &bounds);
        // It is a copy like any reply: with no room for it in the total,
        // `busy` instead, as for a session that can't start
        // (`memory-budgets`).
        let held = self.ctx.budget.borrow().held();
        if held.saturating_add(reply_bytes(&outcome)) > bounds.total_bytes {
            outcome = Err(Thrown::protocol("busy"));
        }
        let generations = self.generations();
        self.replies.push(Reply {
            caller,
            outcome,
            settled,
            generations,
            attempts,
        });
        caller
    }

    /// A new waiting caller with its own deadline, counting the attempt it
    /// joins.
    fn caller(&mut self, options: CallOptions) -> Caller {
        let id = self.next_caller;
        self.next_caller += 1;
        let ms = options.deadline_ms.unwrap_or(self.ctx.bounds().deadline_ms);
        Caller {
            id,
            attempts: options.attempts_used.saturating_add(1),
            deadline: started(self.ctx.rt.sleep(ms)),
        }
    }

    /// Starts a session with its first caller.
    fn start(
        &mut self,
        key: String,
        caller: Caller,
        start: Start,
        restarts: bool,
        subject: String,
        cached: Cached,
    ) -> u64 {
        let scope = match cached {
            Cached::Ens(..) => Scope::Ens,
            Cached::Tezos(_) => Scope::Tezos,
        };
        let id = caller.id;
        let task = start();
        let deadline_ms = self.ctx.bounds().deadline_ms;
        let deadline = started(self.ctx.rt.sleep(deadline_ms));
        let ends = self.now().saturating_add(deadline_ms);
        let generations = self.generations();
        let session = self.next_owner;
        self.next_owner += 1;
        // Its name's copies, reserved at admission.
        self.ctx
            .budget
            .borrow_mut()
            .charge(session, input_bytes(&key), &self.ctx.bounds());
        let owner = self.owner(generations, ends, session);
        self.sessions.push(Session {
            key,
            callers: vec![caller],
            task,
            attempts: 1,
            generations,
            deadline,
            restart: restarts.then_some(start),
            subject,
            scope,
            owner,
            ends,
            id: session,
            cached,
            _held: Held {
                ctx: Rc::clone(&self.ctx),
                session,
            },
        });
        id
    }

    /// A finished session's replies (results or errors), serialized for each caller, count
    /// against its budget until written (`memory-budgets`). Over it, the
    /// callers get `budget` instead, and the result it cached goes.
    fn charge_replies(&self, i: usize, outcome: Outcome) -> Outcome {
        let session = &self.sessions[i];
        // Each caller gets its own copy; an error's message can be as large
        // as its name, so it counts too.
        let bytes = reply_bytes(&outcome).saturating_mul(session.callers.len());
        let bounds = self.ctx.bounds();
        if self
            .ctx
            .budget
            .borrow_mut()
            .charge(session.id, bytes, &bounds)
        {
            return outcome;
        }
        if let Ok(value) = &outcome {
            self.take_back(i, value);
        }
        self.shared.cancel_prefetches(session.id);
        Err(Thrown::budget())
    }

    /// Takes a session's result back out of the cache, if it is still the
    /// cached one.
    fn take_back(&self, i: usize, value: &JsValue) {
        let session = &self.sessions[i];
        let now = self.now();
        match &session.cached {
            Cached::Ens(store, key) => {
                let mut state = self.ctx.state.borrow_mut();
                let cache = match store {
                    Store::Content => &mut state.content,
                    Store::Address => &mut state.address,
                    Store::Reverse => &mut state.reverse,
                };
                if cache.get(key, now) == Some(value) {
                    cache.delete(key);
                }
            }
            Cached::Tezos(name) => {
                let mut results = self.ctx.tezos.results.borrow_mut();
                if results.get(name, now) == Some(value) {
                    results.delete(name);
                }
            }
        }
    }

    fn cached(&self, store: Store, key: &str) -> Option<JsValue> {
        let state = self.ctx.state.borrow();
        let cache = match store {
            Store::Content => &state.content,
            Store::Address => &state.address,
            Store::Reverse => &state.reverse,
        };
        cache.get(key, self.now()).cloned()
    }

    /// `resolveWithCache` after normalization: a cache hit replies at
    /// once; otherwise the caller joins or starts the in-flight session.
    fn lookup(
        &mut self,
        store: Store,
        label: &str,
        key: String,
        subject: String,
        resolve: Resolve,
        options: CallOptions,
    ) -> u64 {
        let used = options.attempts_used;
        // A caller whose allowance is spent fails as it would at a restart
        // (design 0004, Generations: one budget).
        if used >= MAX_LIFECYCLE_ATTEMPTS {
            let message =
                format!("Myotis availability changed repeatedly while resolving {subject}");
            return self.reply(Err(Thrown::new(message)), used);
        }
        if let Some(busy) = self.admit_caller(used) {
            return busy;
        }
        if let Some(result) = self.cached(store, &key) {
            return self.reply(Ok(result), used);
        }
        let dedup = format!("{label}:{key}");
        if let Some(busy) = self.admit(&dedup, used) {
            return busy;
        }
        let caller = self.caller(options);
        if let Some(session) = self.sessions.iter_mut().find(|s| s.key == dedup) {
            let id = caller.id;
            session.callers.push(caller);
            return id;
        }
        let key_for_cache = key.clone();
        let ctx = Rc::clone(&self.ctx);
        let shared = Rc::clone(&self.shared);
        // One attempt of `resolveAcrossStableLifecycle`: a result that
        // crossed a lifecycle change is discarded.
        let start: Start = Rc::new(move || {
            let (ctx, shared, resolve, key) = (
                Rc::clone(&ctx),
                Rc::clone(&shared),
                Rc::clone(&resolve),
                key.clone(),
            );
            Task::new(async move {
                let epoch = ctx.state.borrow().lifecycle;
                let result = resolve(Rc::clone(&ctx), shared).await;
                if epoch == ctx.state.borrow().lifecycle {
                    return Attempt::Done(result);
                }
                if let Ok(value) = &result {
                    // The stale result went into the cache; take it out
                    // unless a newer one replaced it.
                    let now = ctx.rt.now();
                    let mut state = ctx.state.borrow_mut();
                    let cache = match store {
                        Store::Content => &mut state.content,
                        Store::Address => &mut state.address,
                        Store::Reverse => &mut state.reverse,
                    };
                    if cache.get(&key, now) == Some(value) {
                        cache.delete(&key);
                    }
                }
                Attempt::Crossed
            })
        });
        let cached = Cached::Ens(store, key_for_cache);
        self.start(dedup, caller, start, true, subject, cached)
    }

    /// Admission (design 0004): `Some(busy reply)` when joining or starting
    /// the session `dedup` would cross a limit.
    fn admit(&mut self, dedup: &str, attempts: u32) -> Option<u64> {
        let bounds = self.ctx.bounds();
        let full = match self.sessions.iter().find(|s| s.key == dedup) {
            Some(session) => session.callers.len() >= bounds.callers_per_session,
            // Starting one needs room for its first caller too.
            // A new session reserves its name's copies first, and none
            // starts while the total is saturated (`memory-budgets`).
            None => {
                self.sessions.len() >= bounds.sessions
                    || bounds.callers_per_session == 0
                    || !self
                        .ctx
                        .budget
                        .borrow_mut()
                        .admits(input_bytes(dedup), &bounds)
            }
        };
        full.then(|| self.reply(Err(Thrown::protocol("busy")), attempts))
    }

    /// Admission's caller limit, checked first: every caller counts, one
    /// answered from the cache included (design 0004, Admission).
    fn admit_caller(&mut self, attempts: u32) -> Option<u64> {
        let waiting: usize = self.sessions.iter().map(|s| s.callers.len()).sum();
        (waiting >= self.ctx.bounds().callers)
            .then(|| self.reply(Err(Thrown::protocol("busy")), attempts))
    }

    /// `trim()` and `fastNormalize`, or the caller's immediate error.
    fn normalized(&mut self, name: &str, attempts: u32) -> Result<String, u64> {
        let trimmed = crate::js_trim(name);
        if trimmed.is_empty() {
            return Err(self.reply(Err(Thrown::new("ENS name is empty")), attempts));
        }
        ens::fast_normalize(trimmed).map_err(|error| self.reply(Err(error), attempts))
    }

    /// `resolveEnsContent(name)`: a caller id; its reply comes from
    /// [`Machine::take_replies`].
    pub fn resolve_content(&mut self, name: &str) -> u64 {
        self.resolve_content_with(name, CallOptions::default())
    }

    /// [`Machine::resolve_content`] for a caller with its own options.
    pub fn resolve_content_with(&mut self, name: &str, options: CallOptions) -> u64 {
        let normalized = match self.normalized(name, options.attempts_used) {
            Ok(normalized) => normalized,
            Err(caller) => return caller,
        };
        let name = normalized.clone();
        self.lookup(
            Store::Content,
            "content",
            normalized.clone(),
            normalized,
            Rc::new(move |ctx, shared| {
                let name = name.clone();
                Box::pin(async move { ens::content(&ctx, &shared, &name).await })
            }),
            options,
        )
    }

    /// `resolveEnsAddress(name, chainId)`.
    pub fn resolve_address(&mut self, name: &str, chain_id: f64) -> u64 {
        self.resolve_address_with(name, chain_id, CallOptions::default())
    }

    /// [`Machine::resolve_address`] for a caller with its own options.
    pub fn resolve_address_with(&mut self, name: &str, chain_id: f64, options: CallOptions) -> u64 {
        if let Err(error) = ens::coin_type(chain_id) {
            return self.reply(Err(error), options.attempts_used);
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let chain = chain_id as u64;
        let normalized = match self.normalized(name, options.attempts_used) {
            Ok(normalized) => normalized,
            Err(caller) => return caller,
        };
        let key = ens::chain_key(&normalized, chain);
        let name = normalized.clone();
        self.lookup(
            Store::Address,
            "addr",
            key,
            normalized,
            Rc::new(move |ctx, shared| {
                let name = name.clone();
                Box::pin(async move { ens::address(&ctx, &shared, &name, chain).await })
            }),
            options,
        )
    }

    /// `resolveEnsReverse(address, chainId)`.
    pub fn resolve_reverse(&mut self, address: &str, chain_id: f64) -> u64 {
        self.resolve_reverse_with(address, chain_id, CallOptions::default())
    }

    /// [`Machine::resolve_reverse`] for a caller with its own options.
    pub fn resolve_reverse_with(
        &mut self,
        address: &str,
        chain_id: f64,
        options: CallOptions,
    ) -> u64 {
        let valid = address.len() == 42
            && address.starts_with("0x")
            && address[2..].bytes().all(|b| b.is_ascii_hexdigit());
        if !valid {
            let result = JsValue::Object(vec![
                ("success".into(), JsValue::Bool(false)),
                ("address".into(), JsValue::string(address)),
                ("reason".into(), JsValue::string("INVALID_ADDRESS")),
                (
                    "error".into(),
                    JsValue::string(format!("Invalid address: {address}")),
                ),
            ]);
            return self.reply(Ok(result), options.attempts_used);
        }
        if let Err(error) = ens::coin_type(chain_id) {
            return self.reply(Err(error), options.attempts_used);
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let chain = chain_id as u64;
        let normalized = match self.normalized(address, options.attempts_used) {
            Ok(normalized) => normalized,
            Err(caller) => return caller,
        };
        let key = ens::chain_key(&normalized, chain);
        let subject = normalized.clone();
        self.lookup(
            Store::Reverse,
            "reverse",
            key,
            normalized,
            Rc::new(move |ctx, shared| {
                let address = subject.clone();
                Box::pin(async move { ens::reverse(&ctx, &shared, &address, chain).await })
            }),
            options,
        )
    }

    /// Polls every session and prefetch once; finished sessions reply to
    /// all their callers.
    pub fn poll(&mut self) {
        self.shared.poll();
        let now = self.now();
        let bounds = self.ctx.bounds();
        let mut i = 0;
        while i < self.sessions.len() {
            let generations = self.sessions[i].generations;
            // The attempt first: a result that arrives with a deadline wins,
            // as the race it replaces let it. Its requests carry its owner,
            // and what it charges goes to its session.
            let id = self.sessions[i].id;
            self.ctx.rt.set_owner(self.sessions[i].owner);
            self.ctx.session.set(id);
            let finished = self.sessions[i].task.poll();
            self.ctx.rt.set_owner(0);
            self.ctx.session.set(0);
            let spent = self.ctx.budget.borrow().over(id);
            if finished {
                match self.sessions[i].task.take() {
                    Some(Attempt::Done(outcome)) => {
                        let outcome = if spent {
                            // It may have cached, or handed off a
                            // prefetch, before crossing in this very poll.
                            if let Ok(value) = &outcome {
                                self.take_back(i, value);
                            }
                            self.shared.cancel_prefetches(id);
                            Err(Thrown::budget())
                        } else {
                            self.charge_replies(i, sized(outcome, &bounds))
                        };
                        let session = self.sessions.remove(i);
                        self.replies
                            .extend(session.callers.into_iter().map(|caller| Reply {
                                caller: caller.id,
                                outcome: outcome.clone(),
                                settled: now,
                                generations,
                                attempts: caller.attempts,
                            }));
                        continue;
                    }
                    Some(Attempt::Crossed) if spent => {}
                    Some(Attempt::Crossed) => {
                        if self.restart(i, now) {
                            // The new attempt starts in this poll.
                            continue;
                        }
                        self.sessions.remove(i);
                        continue;
                    }
                    None => {}
                }
            }
            // Its budget spent, the session ends: dropping the attempt
            // cancels its I/O, and nothing is cached (`memory-budgets`).
            if spent {
                self.shared.cancel_prefetches(id);
                let session = self.sessions.remove(i);
                self.replies
                    .extend(session.callers.into_iter().map(|caller| Reply {
                        caller: caller.id,
                        outcome: Err(Thrown::budget()),
                        settled: now,
                        generations,
                        attempts: caller.attempts,
                    }));
                continue;
            }
            let session = &mut self.sessions[i];
            // The session's deadline ends it: dropping the attempt cancels
            // its I/O, and nothing is cached (`overall-deadline`).
            if ready(&mut session.deadline) {
                let session = self.sessions.remove(i);
                self.replies
                    .extend(session.callers.into_iter().map(|caller| Reply {
                        caller: caller.id,
                        outcome: Err(Thrown::protocol("deadline")),
                        settled: now,
                        generations,
                        attempts: caller.attempts,
                    }));
                continue;
            }
            // A caller's own deadline detaches it; the session runs on.
            let mut replies = Vec::new();
            session.callers.retain_mut(|caller| {
                if !ready(&mut caller.deadline) {
                    return true;
                }
                replies.push(Reply {
                    caller: caller.id,
                    outcome: Err(Thrown::protocol("deadline")),
                    settled: now,
                    generations,
                    attempts: caller.attempts,
                });
                false
            });
            self.replies.extend(replies);
            i += 1;
        }
        self.replies.sort_by_key(|r| r.caller);
        self.shared.poll();
    }

    /// After an attempt crossed a lifecycle change. Per-caller allowances:
    /// a caller that has used its attempts fails; the session restarts while
    /// any caller has some left, or on its own attempts without callers.
    /// False when it ends instead.
    fn restart(&mut self, i: usize, now: Ms) -> bool {
        let current = self.generations();
        let session = &mut self.sessions[i];
        let message = format!(
            "Myotis availability changed repeatedly while resolving {}",
            session.subject
        );
        let generations = session.generations;
        // Sized and charged like any reply: past the budget, `budget`
        // instead, and the session, now over, ends (at its next poll, or now
        // if this was its last attempt).
        let exhausted = session
            .callers
            .iter()
            .filter(|caller| caller.attempts >= MAX_LIFECYCLE_ATTEMPTS)
            .count();
        let mut outcome = sized(Err(Thrown::new(message)), &self.ctx.bounds());
        let bytes = reply_bytes(&outcome).saturating_mul(exhausted);
        if exhausted > 0
            && !self
                .ctx
                .budget
                .borrow_mut()
                .charge(session.id, bytes, &self.ctx.bounds())
        {
            // Spent: it keeps nothing running, whether it restarts or ends
            // here.
            self.shared.cancel_prefetches(session.id);
            outcome = Err(Thrown::budget());
        }
        let session = &mut self.sessions[i];
        let mut replies = Vec::new();
        session.callers.retain(|caller| {
            if caller.attempts < MAX_LIFECYCLE_ATTEMPTS {
                return true;
            }
            replies.push(Reply {
                caller: caller.id,
                outcome: outcome.clone(),
                settled: now,
                generations,
                attempts: caller.attempts,
            });
            false
        });
        self.replies.extend(replies);
        let session = &mut self.sessions[i];
        let again = !session.callers.is_empty() || session.attempts < MAX_LIFECYCLE_ATTEMPTS;
        let Some(start) = session.restart.as_ref().filter(|_| again) else {
            return false;
        };
        session.task = start();
        session.attempts = session.attempts.saturating_add(1);
        for caller in &mut session.callers {
            caller.attempts = caller.attempts.saturating_add(1);
        }
        session.generations = current;
        let (ends, id) = (session.ends, session.id);
        let owner = self.owner(current, ends, id);
        self.sessions[i].owner = owner;
        true
    }

    /// `cancel` from main: the caller is detached and replied `cancelled`;
    /// its session runs on (design 0004, Admission). False when the caller
    /// is not waiting (its reply already went).
    pub fn cancel(&mut self, caller: u64) -> bool {
        let now = self.now();
        for session in &mut self.sessions {
            if let Some(at) = session.callers.iter().position(|c| c.id == caller) {
                let caller = session.callers.remove(at);
                let generations = session.generations;
                self.replies.push(Reply {
                    caller: caller.id,
                    outcome: Err(Thrown::protocol("cancelled")),
                    settled: now,
                    generations,
                    attempts: caller.attempts,
                });
                return true;
            }
        }
        false
    }

    /// `naming.configure`: the whole snapshot is replaced, and a part that
    /// changed advances its generation. `reset_providers` is today's
    /// `invalidateCachedProvider`. The machine's bounds stay.
    pub fn configure(&mut self, mut config: Config, reset_providers: bool) -> Generations {
        let (ens_changed, tezos_changed) = {
            let mut state = self.ctx.state.borrow_mut();
            config.bounds = state.config.bounds;
            let bound = config.bounds.retired_endpoints;
            for endpoint in retire(&mut self.retired_rpc, &state.config.rpc, &config.rpc, bound) {
                state.pool.forget(&endpoint);
            }
            for endpoint in retire(
                &mut self.retired_tezos,
                &state.config.tezos,
                &config.tezos,
                bound,
            ) {
                self.ctx
                    .tezos
                    .discovery
                    .borrow_mut()
                    .retain(|(e, _, _)| *e != endpoint);
            }
            let old = &state.config;
            let ens_changed = old.rpc != config.rpc
                || old.direct != config.direct
                || old.order != config.order
                || old.prefer_verified != config.prefer_verified
                || old.quorum != config.quorum
                || old.myotis_enabled != config.myotis_enabled
                || old.prover != config.prover;
            let tezos_changed = old.tezos != config.tezos;
            state.config = config;
            (ens_changed, tezos_changed)
        };
        if ens_changed {
            self.ens_generation += 1;
        }
        if tezos_changed {
            self.tezos_generation += 1;
        }
        // Sessions of a scope that changed end now: their I/O is cancelled
        // and nothing of theirs runs again, so they write no shared state.
        // Their callers' replies carry the generations they ran under,
        // which main discards, resubmitting with the attempts left.
        let now = self.now();
        let bounds = self.ctx.bounds();
        let mut i = 0;
        while i < self.sessions.len() {
            let crossed = match self.sessions[i].scope {
                Scope::Ens => ens_changed,
                Scope::Tezos => tezos_changed,
            };
            if !crossed {
                i += 1;
                continue;
            }
            let session = self.sessions.remove(i);
            let message = format!(
                "Name resolution configuration changed while resolving {}",
                session.subject
            );
            let mut outcome = sized(Err(Thrown::new(message)), &bounds);
            // Charged like any reply: past the budget, `budget` instead.
            // Either carries the generations main discards it for.
            let bytes = reply_bytes(&outcome).saturating_mul(session.callers.len());
            if !self
                .ctx
                .budget
                .borrow_mut()
                .charge(session.id, bytes, &bounds)
            {
                self.shared.cancel_prefetches(session.id);
                outcome = Err(Thrown::budget());
            }
            self.replies
                .extend(session.callers.into_iter().map(|caller| Reply {
                    caller: caller.id,
                    outcome: outcome.clone(),
                    settled: now,
                    generations: session.generations,
                    attempts: caller.attempts,
                }));
        }
        if reset_providers {
            self.invalidate_providers();
        }
        self.generations()
    }

    /// `invalidateEnsContent(name)`: whether the content cache held it.
    pub fn invalidate_content(&mut self, name: &str) -> bool {
        let trimmed = crate::js_trim(name);
        if trimmed.is_empty() {
            return false;
        }
        let Ok(key) = ens::fast_normalize(trimmed) else {
            return false;
        };
        self.ctx.state.borrow_mut().content.delete(&key)
    }

    pub fn take_replies(&mut self) -> Vec<Reply> {
        self.replies.take()
    }

    /// The driver's replies not yet written: they count in the sessions'
    /// total (`memory-budgets`), so sessions can't fill the room they hold.
    pub fn set_output_backlog(&mut self, bytes: usize) {
        self.ctx.budget.borrow_mut().set_backlog(bytes);
    }

    /// The effects since the last call, each with its attempt's
    /// generations.
    pub fn take_effects(&mut self) -> Vec<Emitted> {
        let current = (
            self.generations(),
            self.now().saturating_add(self.ctx.bounds().deadline_ms),
            0,
        );
        let emitted = self
            .ctx
            .rt
            .take_effects()
            .into_iter()
            .map(|effect| {
                match &effect {
                    Effect::Request {
                        id,
                        request: Request::Rpc { body, .. },
                        ..
                    } if is_anchor_body(body) => {
                        self.anchor_requests.borrow_mut().insert(*id);
                    }
                    Effect::Cancel { id, .. } => {
                        self.anchor_requests.borrow_mut().remove(id);
                        // An anchor answer delivered but never read: its
                        // future was dropped, so its charge goes now.
                        let released = self.anchor_charges.borrow_mut().remove(id);
                        if let Some((session, bytes)) = released {
                            self.ctx.budget.borrow_mut().uncharge(session, bytes);
                        }
                    }
                    _ => {}
                }
                let (generations, deadline, _) = match &effect {
                    Effect::Request { owner, .. } => {
                        self.origins.get(owner).copied().unwrap_or(current)
                    }
                    Effect::Cancel { .. } => current,
                };
                Emitted {
                    effect,
                    generations,
                    deadline,
                }
            })
            .collect();
        // Only running attempts can make more requests.
        let live: Vec<u64> = self.sessions.iter().map(|s| s.owner).collect();
        self.origins.retain(|owner, _| live.contains(owner));
        emitted
    }

    /// Answers request `id`. The answer counts against its session's
    /// budget (`memory-budgets`), at what its parse can hold.
    /// - **An answer charged over `answer_charge_bytes`** is refused: its
    ///   request fails as `too_large`, the endpoint's doing (a provider
    ///   failure), and the session goes on with its other requests. One
    ///   endpoint's answer so can't spend a lookup's budget (#73).
    /// - **One that crosses the session's budget or the total** is dropped,
    ///   and the session ends at the next poll.
    /// - **The anchor's answers** are charged until the poll that reads
    ///   them, which keeps only a number or a hash.
    pub fn complete(&self, id: u64, answer: Answer) -> bool {
        // An anchor request leaves the set on every path; only an answer
        // charged and taken moves on to `anchor_charges`.
        let anchor = self.anchor_requests.borrow_mut().remove(&id);
        let session = self
            .ctx
            .rt
            .owner_of(id)
            .and_then(|owner| self.origins.get(&owner))
            .map_or(0, |origin| origin.2);
        if session == 0 {
            return self.ctx.rt.complete(id, answer);
        }
        // A second answer to a request is refused before it is charged: the
        // executor wouldn't take it, and a charge that crossed a budget
        // would still end the session.
        if !self.ctx.rt.awaits(id) {
            return false;
        }
        let bounds = self.ctx.bounds();
        let bytes = answer_bytes(&answer);
        let refused = matches!(
            answer,
            Answer::Rpc { .. } | Answer::Gateway { .. } | Answer::Tezos { .. }
        ) && bytes > bounds.answer_charge_bytes;
        if refused {
            return self
                .ctx
                .rt
                .complete(id, Answer::Failed(super::rpc::Transport::TooLarge));
        }
        if !self.ctx.budget.borrow_mut().charge(session, bytes, &bounds) {
            return false;
        }
        if !self.ctx.rt.complete(id, answer) {
            return false;
        }
        if anchor {
            self.anchor_charges
                .borrow_mut()
                .insert(id, (session, bytes));
        }
        true
    }

    pub fn schedule(&self, at: Ms, token: u64) {
        self.ctx.rt.schedule(at, token);
    }

    pub fn next_due(&self) -> Option<Ms> {
        self.ctx.rt.next_due()
    }

    pub fn fire_next(&self, until: Ms) -> Option<Fired> {
        self.ctx.rt.fire_next(until)
    }

    pub fn running(&self) -> usize {
        self.sessions.len()
    }

    /// The bytes running sessions hold (`memory-budgets`).
    pub fn held(&self) -> usize {
        self.ctx.budget.borrow().total()
    }

    /// `resolveTezosDomain(name)`: its own cache and in-flight table, and
    /// no lifecycle restarts.
    pub fn resolve_tezos(&mut self, name: &str) -> u64 {
        self.resolve_tezos_with(name, CallOptions::default())
    }

    /// [`Machine::resolve_tezos`] for a caller with its own options.
    pub fn resolve_tezos_with(&mut self, name: &str, options: CallOptions) -> u64 {
        let Some(normalized) = super::tezos::normalize(name) else {
            return self.reply(Ok(super::tezos::invalid()), options.attempts_used);
        };
        // The same allowance: main resubmits a reply a configuration change
        // overtook only with attempts left.
        if options.attempts_used >= MAX_LIFECYCLE_ATTEMPTS {
            let message =
                format!("Tezos configuration changed repeatedly while resolving {normalized}");
            return self.reply(Err(Thrown::new(message)), options.attempts_used);
        }
        if let Some(busy) = self.admit_caller(options.attempts_used) {
            return busy;
        }
        let now = self.now();
        let cached = self
            .ctx
            .tezos
            .results
            .borrow()
            .get(&normalized, now)
            .cloned();
        if let Some(result) = cached {
            return self.reply(Ok(result), options.attempts_used);
        }
        // The reference deletes a stale entry here, so a fresh one is
        // appended, not updated in place.
        self.ctx.tezos.results.borrow_mut().delete(&normalized);
        let dedup = format!("tezos:{normalized}");
        if let Some(busy) = self.admit(&dedup, options.attempts_used) {
            return busy;
        }
        let caller = self.caller(options);
        if let Some(session) = self.sessions.iter_mut().find(|s| s.key == dedup) {
            let id = caller.id;
            session.callers.push(caller);
            return id;
        }
        let cache_key = normalized.clone();
        let ctx = Rc::clone(&self.ctx);
        let subject = normalized.clone();
        let start: Start = Rc::new(move || {
            let (ctx, name) = (Rc::clone(&ctx), normalized.clone());
            Task::new(
                async move { Attempt::Done(super::tezos::resolve(&ctx, &ctx.tezos, &name).await) },
            )
        });
        self.start(
            dedup,
            caller,
            start,
            false,
            subject,
            Cached::Tezos(cache_key),
        )
    }

    /// `invalidateTezosDomain(name?)`: one result, or every result and
    /// discovery.
    pub fn invalidate_tezos(&mut self, name: Option<&str>) {
        match name {
            Some(name) => {
                let key = crate::js_trim(name).to_lowercase();
                self.ctx.tezos.results.borrow_mut().delete(&key);
            }
            None => {
                self.ctx.tezos.results.borrow_mut().clear();
                self.ctx.tezos.discovery.borrow_mut().clear();
            }
        }
    }

    /// The wall clock at monotonic zero, in milliseconds since the epoch.
    pub fn set_wall_clock(&mut self, epoch_ms: f64) {
        self.ctx.wall_offset.set(epoch_ms);
    }

    /// `naming.availability`, today's Myotis transition listener: the
    /// caches and the in-flight table go and the lifecycle advances; the
    /// anchor, the shuffle and quarantine stay.
    pub fn availability(&mut self, ready: bool) {
        {
            let mut state = self.ctx.state.borrow_mut();
            state.myotis_ready = ready;
            state.myotis_epoch += 1;
            state.content.clear();
            state.address.clear();
            state.reverse.clear();
            state.lifecycle += 1;
        }
        // Tezos has its own in-flight table, which ENS events leave alone.
        for session in &mut self.sessions {
            if session.scope == Scope::Ens {
                session.key.clear();
            }
        }
    }

    /// Whether Myotis is enabled (`naming.availability`'s `enabled`), which
    /// `tryMyotisPath` reads; it is live state, not a configuration change,
    /// so no generation advances.
    pub fn set_myotis_enabled(&mut self, enabled: bool) {
        self.ctx.state.borrow_mut().config.myotis_enabled = enabled;
    }

    /// Myotis' readiness when the machine starts.
    pub fn set_myotis_ready(&mut self, ready: bool) {
        self.ctx.state.borrow_mut().myotis_ready = ready;
    }

    /// `invalidateCachedProvider` (`reset: "providers"`): the pool, the
    /// anchor and the caches go; the lifecycle advances, so running
    /// sessions restart, and new lookups don't join them.
    pub fn invalidate_providers(&mut self) {
        {
            let mut state = self.ctx.state.borrow_mut();
            state.pool.reset();
            state.anchor = None;
            state.content.clear();
            state.address.clear();
            state.reverse.clear();
            state.lifecycle += 1;
        }
        // Tezos has its own in-flight table, which ENS events leave alone.
        for session in &mut self.sessions {
            if session.scope == Scope::Ens {
                session.key.clear();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn retirement_keeps_the_most_recent_and_forgets_the_rest() {
        let mut retired = std::collections::VecDeque::new();
        // a leaves, then b: with room for one, a's state goes.
        assert!(retire(&mut retired, &list(&["a", "b", "c"]), &list(&["b", "c"]), 1).is_empty());
        assert_eq!(
            retire(&mut retired, &list(&["b", "c"]), &list(&["c"]), 1),
            list(&["a"])
        );
        assert_eq!(retired, list(&["b"]));
        // Re-added, b is configured again and no longer retired.
        assert!(retire(&mut retired, &list(&["c"]), &list(&["b", "c"]), 1).is_empty());
        assert!(retired.is_empty());
        // Retired again, it is the most recent.
        retire(&mut retired, &list(&["b", "c"]), &list(&["c", "d"]), 2);
        retire(&mut retired, &list(&["c", "d"]), &list(&["d"]), 2);
        assert_eq!(retired, list(&["b", "c"]));
    }

    fn four_endpoints() -> Config {
        Config {
            rpc: (0..4).map(|i| format!("https://e{i}.example")).collect(),
            direct: None,
            order: vec!["quorum".into()],
            prefer_verified: false,
            quorum: crate::jsjson::parse(r#"{"k":3,"m":2,"anchor":"latest"}"#).unwrap(),
            myotis_enabled: false,
            prover: None,
            tezos: Vec::new(),
            bounds: Default::default(),
        }
    }

    fn machine(config: Config) -> Machine {
        Machine::new(
            0,
            config,
            Box::new(super::super::random::Mulberry32::new(7)),
        )
    }

    /// An anchor answer refused as too large is never charged, and its
    /// request id is forgotten with it (#132 review).
    #[test]
    fn a_refused_anchor_answer_leaves_no_bookkeeping() {
        let mut machine = machine(four_endpoints());
        let pad = vec!["[]"; 20_000].join(",");
        let huge = format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x1312d00","pad":[{pad}]}}"#);
        for round in 0..3 {
            machine.resolve_content(&format!("leak{round}.eth"));
            let mut turns = 0;
            while turns == 0 || machine.running() > 0 {
                machine.poll();
                for emitted in machine.take_effects() {
                    if let Effect::Request {
                        id,
                        request: Request::Rpc { body, .. },
                        ..
                    } = emitted.effect
                    {
                        assert!(is_anchor_body(&body));
                        let answer = Answer::Rpc {
                            status: 200,
                            body: huge.as_bytes().to_vec(),
                        };
                        assert!(machine.complete(id, answer));
                    }
                }
                machine.take_replies();
                turns += 1;
                assert!(turns < 10);
            }
            assert_eq!(machine.held(), 0);
            assert!(machine.anchor_requests.borrow().is_empty());
            assert!(machine.anchor_charges.borrow().is_empty());
            // Past the endpoints' quarantine.
            machine.fire_next((round + 1) * 60_001);
        }
    }

    /// An anchor answer delivered but never read (its lookup ended first)
    /// is uncharged as its request is cancelled (#132 review).
    #[test]
    fn an_anchor_answer_never_read_goes_with_its_cancel() {
        let mut config = four_endpoints();
        let mut machine = machine(config.clone());
        machine.resolve_content("vitalik.eth");
        machine.poll();
        let mut delivered = 0;
        for emitted in machine.take_effects() {
            if let Effect::Request { id, .. } = emitted.effect {
                let answer = Answer::Rpc {
                    status: 200,
                    body: br#"{"jsonrpc":"2.0","id":1,"result":"0x1312d00"}"#.to_vec(),
                };
                assert!(machine.complete(id, answer));
                delivered += 1;
            }
        }
        assert_eq!(delivered, 4);
        assert_eq!(machine.anchor_charges.borrow().len(), 4);
        assert!(machine.held() > 0);
        // A real configuration change ends the lookup before it reads them.
        config.prefer_verified = true;
        machine.configure(config, false);
        let cancelled = machine
            .take_effects()
            .into_iter()
            .filter(|emitted| matches!(emitted.effect, Effect::Cancel { .. }))
            .count();
        assert_eq!(cancelled, 4);
        machine.take_replies();
        assert_eq!(machine.running(), 0);
        assert_eq!(machine.held(), 0);
        assert!(machine.anchor_requests.borrow().is_empty());
        assert!(machine.anchor_charges.borrow().is_empty());
    }

    fn head(pad: usize) -> Answer {
        let pad = "x".repeat(pad);
        Answer::Rpc {
            status: 200,
            body: format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x1312d00","pad":"{pad}"}}"#)
                .into_bytes(),
        }
    }

    /// A lookup's first anchor request, with what the machine holds.
    fn first_request(machine: &mut Machine) -> (u64, usize) {
        machine.resolve_content("vitalik.eth");
        machine.poll();
        let id = machine
            .take_effects()
            .into_iter()
            .find_map(|emitted| match emitted.effect {
                Effect::Request { id, .. } => Some(id),
                Effect::Cancel { .. } => None,
            })
            .unwrap();
        (id, machine.held())
    }

    /// A second answer to one request isn't taken and holds nothing, even
    /// one whose charge would cross the session's budget or the total
    /// (#132 review).
    #[test]
    fn a_second_answer_is_refused_before_it_is_charged() {
        let tight = |session: bool| {
            let mut config = four_endpoints();
            if session {
                config.bounds.session_bytes = 4096;
            } else {
                config.bounds.total_bytes = 4096;
                config.bounds.resume_bytes = 3000;
            }
            config
        };
        for config in [four_endpoints(), tight(true), tight(false)] {
            let mut machine = machine(config);
            let (id, _) = first_request(&mut machine);
            assert!(machine.complete(id, head(0)));
            let held = machine.held();
            // Under the answer allowance, and under 4,096 alone.
            assert!(answer_bytes(&head(1200)) < 4096);
            for pad in [0, 1200] {
                assert!(!machine.complete(id, head(pad)));
                assert_eq!(machine.held(), held);
                assert_eq!(machine.anchor_charges.borrow().len(), 1);
            }
            // The first answer is read, and the lookup goes on.
            machine.poll();
            assert!(machine.anchor_charges.borrow().is_empty());
            assert_eq!(machine.running(), 1);
            assert!(machine.take_replies().is_empty());
        }
    }
}
