//! A page's connect in the daemon (design 0012, "fc-eip1193 and
//! approval.request"; APR-5c-1): the core's own requests to main for it,
//! `approval.request` and `approval.recheck`, and main's answers.
//!
//! - **`approval.request { request, prompt, page, kind, view, choices }`**
//!   asks main to open a prompt on the record of page request `request`
//!   (its 0001 id). `prompt` is 16 bytes from the OS's RNG, never reused
//!   ([`fc_eip1193::Prompts`]). Main's answer is checked there: another
//!   prompt's id, a handle an earlier answer named, or anything but one of
//!   the three forms fails the request (`not_authorized`, `mismatch`), with
//!   nothing written.
//! - **`approval.recheck { request, page }`** asks main, just before a
//!   connected key's last use is marked, whether the document still holds
//!   its key.
//! - **The clock** (`fc_eip1193::Budget`): 120 s from the loop's receipt,
//!   stopped while the request's `approval.request` is open. Past it, a
//!   request still waiting (for main's recheck, or for room to ask) answers
//!   `-32603` with the core's text, and the core cancels its own request to
//!   main (*inferred*). A prompt open has no deadline (0011).
//! - **Room:** main holds at most 256 of the core's requests, every
//!   thread's together, and a prompt can stay open for as long as the user
//!   takes. So at most [`MAX_OPEN_PROMPTS`] `approval.request`s are open at
//!   once (*inferred*), and the rest wait their turn, their clocks running.
//! - **A cancel** of the page request answers 0001's `cancelled` and
//!   cancels the core's request to main; main's late answer is dropped.

use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use fc_eip1193::connect::{Ask, Connected, Decided};
use fc_eip1193::{Answer, Budget, Connect, Crossed, PromptId, Prompts, Recheck};
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::message::{self, PageContext};
use zeroize::Zeroizing;

use crate::requests::{self, Dispatch, Owner, Requests, Start};
use crate::transport::{self, Allowance};
use crate::vault::{Out, Vault};

/// The most `approval.request`s open at main at once (*inferred*): room
/// is left for the naming, chain and dweb threads' requests.
pub const MAX_OPEN_PROMPTS: usize = 64;

/// The page's answer when its time ran out outside its prompt.
const DEADLINE: &str = r#"{"error":{"code":-32603,"message":"The request's deadline passed"}}"#;

/// See the module documentation.
pub struct Connects {
    prompts: Prompts,
    requests: Arc<Requests>,
    out: Sender<transport::Out>,
    allowance: Arc<Allowance>,
    /// Where the budgets' milliseconds count from.
    base: Instant,
    /// The page requests waiting, by their 0001 id.
    open: BTreeMap<u64, Open>,
    /// The core's requests to main: the page request each serves.
    asked: BTreeMap<u64, u64>,
    /// Page requests whose request to main waits for room, in order.
    queued: VecDeque<u64>,
    /// `approval.request`s open at main.
    prompting: usize,
}

struct Open {
    key: String,
    /// The request's `PageContext`, as JSON.
    page: String,
    budget: Budget,
    step: Pending,
    /// The core's request to main, once sent.
    asked: Option<u64>,
}

enum Pending {
    Recheck(Connected),
    Prompt { ask: Ask, id: PromptId },
}

impl Connects {
    /// `wake` is called when a request that waited for room may go.
    pub fn new(
        requests: Arc<Requests>,
        out: Sender<transport::Out>,
        wake: impl Fn() + Send + Clone + 'static,
    ) -> Connects {
        let allowance = Allowance::new(MAX_OPEN_PROMPTS, 4 << 20);
        allowance.on_room(wake.clone());
        requests.on_room(Owner::Eip1193, wake);
        Connects {
            prompts: Prompts::new(),
            requests,
            out,
            allowance,
            base: Instant::now(),
            open: BTreeMap::new(),
            asked: BTreeMap::new(),
            queued: VecDeque::new(),
            prompting: 0,
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Page request `id`'s connect, for `key`, received by the loop at
    /// `received`.
    pub fn start(
        &mut self,
        id: u64,
        connect: Connect,
        key: &str,
        page: &PageContext,
        received: Instant,
    ) -> Vec<Out> {
        let Ok(page) = serde_json::to_string(page) else {
            return vec![error(id, internal())];
        };
        let step = match connect {
            Connect::Connected(connected) => Pending::Recheck(connected),
            Connect::Ask(ask) => match self.issue() {
                Some(prompt) => Pending::Prompt { ask, id: prompt },
                None => return vec![error(id, internal())],
            },
        };
        let waited = u64::try_from(received.elapsed().as_millis()).unwrap_or(u64::MAX);
        let overall = crate::testhooks::eip1193_overall(fc_eip1193::OVERALL_MS);
        let budget = Budget::with_left(self.now_ms(), overall.saturating_sub(waited));
        self.open.insert(
            id,
            Open {
                key: key.to_owned(),
                page,
                budget,
                step,
                asked: None,
            },
        );
        self.queued.push_back(id);
        self.pump()
    }

    /// A new prompt id from the OS's RNG, drawn again should it name one
    /// issued before.
    fn issue(&mut self) -> Option<PromptId> {
        use rand_core::TryRng as _;
        for _ in 0..4 {
            let mut bytes = [0u8; 16];
            crate::rng::OsRng.try_fill_bytes(&mut bytes).ok()?;
            if let Some(id) = self.prompts.issue(bytes) {
                return Some(id);
            }
        }
        None
    }

    /// Sends what waits for room, in order, while there is room.
    pub fn pump(&mut self) -> Vec<Out> {
        let mut outs = Vec::new();
        let mut kept = VecDeque::new();
        while let Some(id) = self.queued.pop_front() {
            let Some(open) = self.open.get(&id) else {
                continue;
            };
            let prompt = matches!(open.step, Pending::Prompt { .. });
            if prompt && self.prompting >= MAX_OPEN_PROMPTS {
                kept.push_back(id);
                continue;
            }
            let (method, params) = match &open.step {
                Pending::Recheck(_) => (
                    "approval.recheck",
                    format!(r#"{{"request":{id},"page":{}}}"#, open.page),
                ),
                Pending::Prompt { ask, id: prompt } => (
                    "approval.request",
                    format!(
                        r#"{{"request":{id},"prompt":"{}","page":{},"kind":"{}","view":{},"choices":{}}}"#,
                        prompt.hex(),
                        open.page,
                        ask.kind(),
                        ask.view(),
                        ask.choices()
                    ),
                ),
            };
            let sent = self.requests.send(
                Owner::Eip1193,
                &self.allowance,
                &self.out,
                || requests::request_frame(method, params.as_bytes(), None),
                || Start::Anytime,
            );
            match sent {
                Dispatch::Sent(core) => {
                    let now = self.now_ms();
                    self.asked.insert(core, id);
                    if let Some(open) = self.open.get_mut(&id) {
                        open.asked = Some(core);
                        if prompt {
                            open.budget.prompt_opened(now);
                            self.prompting += 1;
                        }
                    }
                }
                Dispatch::Full | Dispatch::NoRoom => {
                    kept.push_back(id);
                    kept.extend(self.queued.drain(..));
                    break;
                }
                Dispatch::TooLarge | Dispatch::Late => {
                    self.open.remove(&id);
                    outs.push(error(
                        id,
                        ErrorBody::new(ErrorCode::TooLarge, "the prompt is over one frame"),
                    ));
                }
                // The core is exiting: nothing more goes.
                Dispatch::Closed | Dispatch::WriterGone => {
                    self.open.remove(&id);
                }
            }
        }
        self.queued = kept;
        outs
    }

    /// Main answered the core's request `core`: `outcome` spans its result
    /// or its error in `message`. One for a request already ended
    /// (cancelled, or past its time) is dropped.
    pub fn answered(
        &mut self,
        core: u64,
        outcome: Result<Range<usize>, Range<usize>>,
        message: &[u8],
        vault: &mut Vault,
    ) -> Vec<Out> {
        let Some(id) = self.asked.remove(&core) else {
            return Vec::new();
        };
        let Some(mut open) = self.open.remove(&id) else {
            return Vec::new();
        };
        let text = outcome
            .ok()
            .and_then(|span| message.get(span))
            .and_then(|bytes| std::str::from_utf8(bytes).ok());
        let mut outs = match open.step {
            Pending::Recheck(connected) => match text.ok_or(Crossed).and_then(Recheck::parse) {
                Ok(recheck) => {
                    let rechecked = connected.answer(recheck.live);
                    let mut outs = vec![reply(id, &rechecked.answer)];
                    if rechecked.touch {
                        outs.extend(vault.eip1193_touch(&open.key));
                    }
                    outs
                }
                Err(Crossed) => vec![error(id, crossed())],
            },
            Pending::Prompt { ask, id: prompt } => {
                self.prompting = self.prompting.saturating_sub(1);
                open.budget.prompt_closed(self.now_ms());
                let decided = text
                    .ok_or(Crossed)
                    .and_then(|text| self.prompts.accept(&prompt, text))
                    .and_then(|decision| ask.decide(decision));
                match decided {
                    Ok(Decided::Answer(answer)) => vec![reply(id, &answer)],
                    Ok(Decided::Grant(grant)) => {
                        let (written, events) =
                            vault.eip1193_connect(&open.key, grant.account, grant.chain_id);
                        let mut outs = vec![reply(id, &grant.answer(written))];
                        outs.extend(events);
                        outs
                    }
                    Err(Crossed) => vec![error(id, crossed())],
                }
            }
        };
        outs.extend(self.pump());
        outs
    }

    /// Main cancelled page request `id`.
    pub fn cancel(&mut self, id: u64) -> Vec<Out> {
        if !self.open.contains_key(&id) {
            return Vec::new();
        }
        let mut outs = self.end(id);
        outs.push(error(id, ErrorBody::new(ErrorCode::Cancelled, "Cancelled")));
        outs.extend(self.pump());
        outs
    }

    /// Ends page request `id` without main's answer: its request to main,
    /// if sent, is cancelled.
    fn end(&mut self, id: u64) -> Vec<Out> {
        let Some(open) = self.open.remove(&id) else {
            return Vec::new();
        };
        self.queued.retain(|queued| *queued != id);
        let Some(core) = open.asked else {
            return Vec::new();
        };
        self.asked.remove(&core);
        if matches!(open.step, Pending::Prompt { .. }) {
            self.prompting = self.prompting.saturating_sub(1);
        }
        let cancel = format!(r#"{{"type":"cancel","id":{core}}}"#);
        vec![Out::Send(Zeroizing::new(cancel.into_bytes()))]
    }

    /// Whether `open`'s clock runs. Its budget alone says so: the budget
    /// stops while the request's prompt is open.
    fn running(open: &Open) -> bool {
        !open.budget.stopped()
    }

    /// When the next request's time runs out.
    pub fn next_wakeup(&self) -> Option<Instant> {
        let now = self.now_ms();
        self.open
            .values()
            .filter(|open| Self::running(open))
            .map(|open| open.budget.left(now))
            .min()
            .map(|left| Instant::now() + Duration::from_millis(left))
    }

    /// Ends each request whose time has run out.
    pub fn tick(&mut self) -> Vec<Out> {
        let now = self.now_ms();
        let due: Vec<u64> = self
            .open
            .iter()
            .filter(|(_, open)| Self::running(open) && open.budget.left(now) == 0)
            .map(|(id, _)| *id)
            .collect();
        if due.is_empty() {
            return Vec::new();
        }
        let mut outs = Vec::new();
        for id in due {
            outs.extend(self.end(id));
            outs.push(raw_reply(id, DEADLINE));
        }
        outs.extend(self.pump());
        outs
    }
}

fn reply(id: u64, answer: &Answer) -> Out {
    raw_reply(id, answer.as_str())
}

/// `eip1193.request`'s result: the answer's JSON as it stands.
fn raw_reply(id: u64, answer: &str) -> Out {
    let head = format!(r#"{{"type":"response","id":{id},"result":"#);
    let mut payload = Zeroizing::new(Vec::with_capacity(head.len() + answer.len() + 1));
    payload.extend_from_slice(head.as_bytes());
    payload.extend_from_slice(answer.as_bytes());
    payload.push(b'}');
    Out::Send(payload)
}

fn error(id: u64, body: ErrorBody) -> Out {
    let mut payload = Zeroizing::new(Vec::with_capacity(256));
    if message::write_error(&mut *payload, id, &body).is_err() {
        payload.clear();
    }
    Out::Send(payload)
}

fn internal() -> ErrorBody {
    ErrorBody::new(ErrorCode::Internal, "Internal error")
}

/// An answer that isn't main's decision on the request's prompt, or a
/// recheck that isn't one: the request fails, nothing written.
fn crossed() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::NotAuthorized,
        "main's answer isn't the decision on this request's prompt",
    )
    .with_data(serde_json::json!({ "reason": "mismatch" }))
}
