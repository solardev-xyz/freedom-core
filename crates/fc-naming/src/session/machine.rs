//! The machine a driver runs: sessions, their deduplication and lifecycle
//! restarts (`resolveWithCache`, `resolveAcrossStableLifecycle`), and the
//! prefetches it keeps alive.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Waker};

use super::ens::{self, Answer, Config, Ctx, Request, Store, Thrown};
use super::exec::{Effect, Fired, Io, Ms, Task};
use super::random::Random;
use crate::jsjson::JsValue;

/// What the machine shares with its sessions beyond [`Ctx`]: the
/// prefetches it keeps running.
pub struct Shared {
    ctx: Rc<Ctx>,
    prefetches: RefCell<Vec<(u64, Io<Request, Answer>)>>,
    next_prefetch: Cell<u64>,
}

impl Shared {
    /// `prefetchOnFirstData`: asks main to prefetch the first answer's URI.
    /// The handle lets the wave abort it.
    pub(crate) fn start_prefetch(&self, resolved: &[u8]) -> Option<u64> {
        let uri = ens::prefetch_uri(resolved)?;
        let mut io = self.ctx.rt.request(Request::Prefetch { uri });
        // The first poll emits the request.
        let mut cx = Context::from_waker(Waker::noop());
        if Pin::new(&mut io).poll(&mut cx).is_ready() {
            return None;
        }
        let id = self.next_prefetch.get();
        self.next_prefetch.set(id + 1);
        self.prefetches.borrow_mut().push((id, io));
        Some(id)
    }

    /// Dropping the request cancels it.
    pub(crate) fn abort_prefetch(&self, id: u64) {
        self.prefetches
            .borrow_mut()
            .retain(|(handle, _)| *handle != id);
    }

    fn poll(&self) {
        let mut cx = Context::from_waker(Waker::noop());
        self.prefetches
            .borrow_mut()
            .retain_mut(|(_, io)| Pin::new(io).poll(&mut cx).is_pending());
    }
}

/// A resolution's outcome.
pub type Outcome = Result<JsValue, Thrown>;

struct Session {
    /// The in-flight key; empty once retired (nothing joins it).
    key: String,
    callers: Vec<u64>,
    task: Task<'static, Outcome>,
}

/// One caller's terminal reply.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub caller: u64,
    pub outcome: Outcome,
    pub settled: Ms,
}

pub struct Machine {
    ctx: Rc<Ctx>,
    shared: Rc<Shared>,
    sessions: Vec<Session>,
    replies: Vec<Reply>,
    next_caller: u64,
}

const MAX_LIFECYCLE_RESTARTS: u32 = 3;

type Resolve = Rc<dyn Fn(Rc<Ctx>, Rc<Shared>) -> Pin<Box<dyn Future<Output = Outcome>>>>;

impl Machine {
    pub fn new(now: Ms, config: Config, random: Box<dyn Random>) -> Self {
        let ctx = Rc::new(Ctx::new(now, config, random));
        let shared = Rc::new(Shared {
            ctx: Rc::clone(&ctx),
            prefetches: RefCell::new(Vec::new()),
            next_prefetch: Cell::new(1),
        });
        Self {
            ctx,
            shared,
            sessions: Vec::new(),
            replies: Vec::new(),
            next_caller: 1,
        }
    }

    pub fn now(&self) -> Ms {
        self.ctx.rt.now()
    }

    fn reply(&mut self, outcome: Outcome) -> u64 {
        let caller = self.next_caller;
        self.next_caller += 1;
        let settled = self.now();
        self.replies.push(Reply {
            caller,
            outcome,
            settled,
        });
        caller
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
    ) -> u64 {
        if let Some(result) = self.cached(store, &key) {
            return self.reply(Ok(result));
        }
        let dedup = format!("{label}:{key}");
        let caller = self.next_caller;
        self.next_caller += 1;
        if let Some(session) = self.sessions.iter_mut().find(|s| s.key == dedup) {
            session.callers.push(caller);
            return caller;
        }
        let ctx = Rc::clone(&self.ctx);
        let shared = Rc::clone(&self.shared);
        let task = Task::new(async move {
            for _attempt in 1..=MAX_LIFECYCLE_RESTARTS {
                let epoch = ctx.state.borrow().lifecycle;
                let result = resolve(Rc::clone(&ctx), Rc::clone(&shared)).await;
                if epoch == ctx.state.borrow().lifecycle {
                    return result;
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
            }
            Err(Thrown::new(format!(
                "Myotis availability changed repeatedly while resolving {subject}"
            )))
        });
        self.sessions.push(Session {
            key: dedup,
            callers: vec![caller],
            task,
        });
        caller
    }

    /// `trim()` and `fastNormalize`, or the caller's immediate error.
    fn normalized(&mut self, name: &str) -> Result<String, u64> {
        let trimmed = crate::js_trim(name);
        if trimmed.is_empty() {
            return Err(self.reply(Err(Thrown::new("ENS name is empty"))));
        }
        ens::fast_normalize(trimmed).map_err(|error| self.reply(Err(error)))
    }

    /// `resolveEnsContent(name)`: a caller id; its reply comes from
    /// [`Machine::take_replies`].
    pub fn resolve_content(&mut self, name: &str) -> u64 {
        let normalized = match self.normalized(name) {
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
        )
    }

    /// `resolveEnsAddress(name, chainId)`.
    pub fn resolve_address(&mut self, name: &str, chain_id: f64) -> u64 {
        if let Err(error) = ens::coin_type(chain_id) {
            return self.reply(Err(error));
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let chain = chain_id as u64;
        let normalized = match self.normalized(name) {
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
        )
    }

    /// `resolveEnsReverse(address, chainId)`.
    pub fn resolve_reverse(&mut self, address: &str, chain_id: f64) -> u64 {
        let valid = address.len() == 42
            && address.starts_with("0x")
            && address[2..].bytes().all(|b| b.is_ascii_hexdigit());
        if !valid {
            let result = JsValue::Object(vec![
                ("success".into(), JsValue::Bool(false)),
                ("address".into(), JsValue::String(address.into())),
                ("reason".into(), JsValue::String("INVALID_ADDRESS".into())),
                (
                    "error".into(),
                    JsValue::String(format!("Invalid address: {address}")),
                ),
            ]);
            return self.reply(Ok(result));
        }
        if let Err(error) = ens::coin_type(chain_id) {
            return self.reply(Err(error));
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let chain = chain_id as u64;
        let normalized = match self.normalized(address) {
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
        )
    }

    /// Polls every session and prefetch once; finished sessions reply to
    /// all their callers.
    pub fn poll(&mut self) {
        self.shared.poll();
        let now = self.now();
        let mut finished = Vec::new();
        for (i, session) in self.sessions.iter_mut().enumerate() {
            if session.task.poll() {
                finished.push(i);
            }
        }
        for i in finished.into_iter().rev() {
            let mut session = self.sessions.remove(i);
            if let Some(outcome) = session.task.take() {
                for caller in session.callers {
                    self.replies.push(Reply {
                        caller,
                        outcome: outcome.clone(),
                        settled: now,
                    });
                }
            }
        }
        self.replies.sort_by_key(|r| r.caller);
        self.shared.poll();
    }

    pub fn take_replies(&mut self) -> Vec<Reply> {
        std::mem::take(&mut self.replies)
    }

    pub fn take_effects(&self) -> Vec<Effect<Request>> {
        self.ctx.rt.take_effects()
    }

    pub fn complete(&self, id: u64, answer: Answer) -> bool {
        self.ctx.rt.complete(id, answer)
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
        for session in &mut self.sessions {
            session.key.clear();
        }
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
        for session in &mut self.sessions {
            session.key.clear();
        }
    }
}
