//! The machine a driver runs: sessions, their deduplication and lifecycle
//! restarts (`resolveWithCache`, `resolveAcrossStableLifecycle`), and the
//! prefetches it keeps alive.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Waker};

use super::ens::{self, Answer, Config, Ctx, Request, Thrown};
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

    /// `resolveEnsContent(name)`: a caller id; its reply comes from
    /// [`Machine::take_replies`].
    pub fn resolve_content(&mut self, name: &str) -> u64 {
        let trimmed = crate::js_trim(name);
        if trimmed.is_empty() {
            return self.reply(Err(Thrown {
                message: "ENS name is empty".into(),
            }));
        }
        let normalized = match ens::fast_normalize(trimmed) {
            Ok(normalized) => normalized,
            Err(error) => return self.reply(Err(error)),
        };
        let cached = self
            .ctx
            .state
            .borrow()
            .content
            .get(&normalized, self.now())
            .cloned();
        if let Some(result) = cached {
            return self.reply(Ok(result));
        }
        let key = format!("content:{normalized}");
        let caller = self.next_caller;
        self.next_caller += 1;
        if let Some(session) = self.sessions.iter_mut().find(|s| s.key == key) {
            session.callers.push(caller);
            return caller;
        }
        let ctx = Rc::clone(&self.ctx);
        let shared = Rc::clone(&self.shared);
        let task = Task::new(async move {
            for _attempt in 1..=MAX_LIFECYCLE_RESTARTS {
                let epoch = ctx.state.borrow().lifecycle;
                let result = ens::content(&ctx, &shared, &normalized).await;
                if epoch == ctx.state.borrow().lifecycle {
                    return result;
                }
                if let Ok(value) = &result {
                    // The stale result went into the cache; take it out
                    // unless a newer one replaced it.
                    let now = ctx.rt.now();
                    let mut state = ctx.state.borrow_mut();
                    if state.content.get(&normalized, now) == Some(value) {
                        state.content.delete(&normalized);
                    }
                }
            }
            Err(Thrown {
                message: format!(
                    "Myotis availability changed repeatedly while resolving {normalized}"
                ),
            })
        });
        self.sessions.push(Session {
            key,
            callers: vec![caller],
            task,
        });
        caller
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

    /// `invalidateCachedProvider` (`reset: "providers"`): the pool, the
    /// anchor and the caches go; the lifecycle advances, so running
    /// sessions restart, and new lookups don't join them.
    pub fn invalidate_providers(&mut self) {
        {
            let mut state = self.ctx.state.borrow_mut();
            state.pool.reset();
            state.anchor = None;
            state.content.clear();
            state.lifecycle += 1;
        }
        for session in &mut self.sessions {
            session.key.clear();
        }
    }
}
