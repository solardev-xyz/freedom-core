//! A page's connect, chain switch and signature in the daemon (design 0012,
//! "fc-eip1193 and approval.request"; APR-5c, APR-5d-1): the core's own
//! requests to main for them, `approval.request`, `approval.recheck` and
//! `eip1193.select_chain`, and main's answers.
//!
//! - **`approval.request { request, prompt, page, kind, view, choices }`**
//!   asks main to open a prompt on the record of page request `request`
//!   (its 0001 id). `prompt` is 16 bytes from the OS's RNG, never reused
//!   ([`fc_eip1193::Prompts`]). Main's answer is checked there: another
//!   prompt's id, a handle an earlier answer named, or anything but one of
//!   the three forms fails the request (`not_authorized`, `mismatch`), with
//!   nothing written.
//! - **A signature** (APR-5d-1) is asked as `eth.sign`. On main's approve,
//!   checked as above and against the key's grant again, the core mints the
//!   page-kind token itself for the request's document and that answer's
//!   handle, and spends it at once on the signature
//!   ([`Vault::eip1193_sign`]): the token never leaves the core, and serves
//!   that request alone.
//! - **A signature the site's rule answers** (APR-5d-2) asks main to
//!   unlock the vault first while it is locked (`vault.unlock`, an
//!   `approval.request` like any prompt), then main's recheck just before
//!   the effect: custody, the rule gone or the document gone refuses it with
//!   nothing signed, and a rule past its rate by then asks the user
//!   instead. Then it signs under `{ standing }`, which the core decides
//!   again with its own grant and counts in Q9's rate, and marks the key's
//!   last use.
//! - **A device's account** (a Ledger, a phone or a Safe, until 0016): on
//!   main's approve the core mints the token, and the answer returns it to
//!   main, `{ device }`, for the device to sign through main.
//! - **`approval.recheck { request, page }`** asks main, just before a
//!   connected key's last use is marked, a switch's chain is written or a
//!   rule's signature is made, whether the document still holds its key,
//!   and whether the agent holds its tab.
//! - **`eip1193.select_chain { request, page, chain_id }`** (APR-5c-2,
//!   *inferred*) asks main, once a chain switch's grant has its chain, to
//!   select the chain for the window of page request `request` and send
//!   `chainChanged` as the reference does (main holds the windows and the
//!   documents). Main answers `{}` once it has; anything else fails the
//!   request (`mismatch`), the grant's chain already written. The page's
//!   answer, `null`, goes only after it, as the reference sends the events
//!   before its answer.
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
//!   cancels the core's request to main. A cancelled prompt leaves a
//!   tombstone until main's terminal answer (0001: exactly one per
//!   request): the answer is checked, so a handle it names is seen, and
//!   nothing else comes of it. Each tombstone holds one of main's 256
//!   slots for the core's requests until then ([`requests::MAX_OUTSTANDING`]),
//!   so there are never more than that.

use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use fc_eip1193::connect::{Ask, Connected, Decided};
use fc_eip1193::{
    Answer, Budget, Connect, Crossed, PromptId, Prompts, Recheck, Switch, send, sign,
};
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::message::{self, PageContext};
use std::borrow::Cow;
use zeroize::Zeroizing;

use crate::requests::{self, Dispatch, Owner, Requests, Start};
use crate::transport::{self, Allowance};
use crate::vault::{Out, Vault};

/// The most `approval.request`s open at main at once (*inferred*): room
/// is left for the naming, chain and dweb threads' requests.
pub const MAX_OPEN_PROMPTS: usize = 64;

/// The bit that marks a page send's own chain reads' tags (design 0012,
/// APR-5e-1): the event loop routes their replies here, and a phone
/// payment's elsewhere (`phone.rs` counts its tags up from 1).
pub const SEND_TAG: u64 = 1 << 63;

/// The fee evidence's own deadline (`fee-check.js`'s
/// `EVIDENCE_DEADLINE_MS`), within what is left of the request's time.
const EVIDENCE_DEADLINE_MS: u64 = 15_000;

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
    /// The core's requests to main: what each serves.
    asked: BTreeMap<u64, Asked>,
    /// Page requests whose request to main waits for room, in order.
    queued: VecDeque<u64>,
    /// `approval.request`s open at main.
    prompting: usize,
    /// A send's chain reads, by tag: its page request, and which read.
    reads: BTreeMap<u64, (u64, Part)>,
    /// The next chain read's tag, below [`SEND_TAG`].
    next_tag: u64,
}

/// Which of a send's chain reads a tag names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// `eth_estimateGas`.
    Estimate,
    /// The fee quote.
    Quote,
    /// New fee evidence, for the fee check.
    Reference,
}

/// A send waiting on its chain reads: each `None` until it replies, then
/// its result (`None` for a failure).
struct Quoting {
    prepare: send::Prepare,
    estimate: Option<Option<fc_json::JsValue>>,
    quote: Option<Option<fc_json::JsValue>>,
    /// Waiting on new fee evidence.
    reference: bool,
}

struct Open {
    key: String,
    /// The request's `PageContext`, as JSON.
    page: String,
    /// The request's `PageContext`, which a signature's token binds.
    context: PageContext,
    budget: Budget,
    step: Pending,
    /// The core's request to main, once sent.
    asked: Option<u64>,
}

/// What one of the core's requests to main serves.
enum Asked {
    /// A page request, by its 0001 id.
    Request(u64),
    /// A prompt whose page request ended first: main's answer is only
    /// checked.
    Ended(PromptId),
}

enum Pending {
    Recheck(Connected),
    Prompt {
        ask: Asking,
        id: PromptId,
    },
    /// A chain switch, waiting on main's recheck.
    Switch(Switch),
    /// A chain switch whose grant has its chain, waiting on main's
    /// selection.
    Select(Switch),
    /// A signature the site's rule answers, waiting on main's recheck
    /// (APR-5d-2).
    Rule(sign::Ask),
    /// A send waiting on the core's own chain reads (APR-5e-1): its
    /// estimate, its fee quote and, when the chain's evidence is stale, new
    /// evidence. No request to main is open for it.
    Quote(Quoting),
    /// An approved send waiting on new fee evidence for the check at its
    /// approval (APR-5e-1).
    Judge(send::Judge),
}

/// What a prompt asks.
enum Asking {
    /// A connect's `eth.connect`.
    Connect(Ask),
    /// A signature's `eth.sign` (APR-5d-1).
    Sign(sign::Ask),
    /// A rule's signature asking for the vault's unlock (APR-5d-2).
    Unlock(sign::Ask),
    /// A send's `eth.send` (APR-5e-1).
    Send(send::Ask),
}

impl Asking {
    fn kind(&self) -> &'static str {
        match self {
            Asking::Connect(ask) => ask.kind(),
            Asking::Sign(ask) => ask.kind(),
            Asking::Unlock(ask) => ask.unlock_kind(),
            Asking::Send(ask) => ask.kind(),
        }
    }

    fn view(&self) -> Cow<'_, str> {
        match self {
            Asking::Connect(ask) => Cow::Borrowed(ask.view()),
            Asking::Sign(ask) => Cow::Borrowed(ask.view()),
            Asking::Unlock(ask) => Cow::Owned(ask.unlock_view()),
            Asking::Send(ask) => Cow::Borrowed(ask.view()),
        }
    }

    fn choices(&self) -> &str {
        match self {
            Asking::Connect(ask) => ask.choices(),
            Asking::Sign(ask) => ask.choices(),
            Asking::Unlock(ask) => ask.unlock_choices(),
            Asking::Send(ask) => ask.choices(),
        }
    }
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
            reads: BTreeMap::new(),
            next_tag: 1,
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
        let step = match connect {
            Connect::Connected(connected) => Pending::Recheck(connected),
            Connect::Ask(ask) => match self.issue() {
                Some(prompt) => Pending::Prompt {
                    ask: Asking::Connect(ask),
                    id: prompt,
                },
                None => return vec![error(id, internal())],
            },
        };
        self.open_request(id, step, key, page, received)
    }

    /// Page request `id`'s signature, up to its prompt, for `key`
    /// (APR-5d-1): the user is asked.
    pub fn sign(
        &mut self,
        id: u64,
        ask: sign::Ask,
        key: &str,
        page: &PageContext,
        received: Instant,
    ) -> Vec<Out> {
        let Some(prompt) = self.issue() else {
            return vec![error(id, internal())];
        };
        let step = Pending::Prompt {
            ask: Asking::Sign(ask),
            id: prompt,
        };
        self.open_request(id, step, key, page, received)
    }

    /// Page request `id`'s signature that the site's rule answers, for
    /// `key` (APR-5d-2): the vault's unlock first if `locked`, then main's
    /// recheck.
    pub fn rule(
        &mut self,
        id: u64,
        ask: sign::Ask,
        locked: bool,
        key: &str,
        page: &PageContext,
        received: Instant,
    ) -> Vec<Out> {
        let step = if locked {
            let Some(prompt) = self.issue() else {
                return vec![error(id, internal())];
            };
            Pending::Prompt {
                ask: Asking::Unlock(ask),
                id: prompt,
            }
        } else {
            Pending::Rule(ask)
        };
        self.open_request(id, step, key, page, received)
    }

    /// Page request `id`'s chain switch, past its checks, for `key`
    /// (APR-5c-2): main's recheck first.
    pub fn switch(
        &mut self,
        id: u64,
        switch: Switch,
        key: &str,
        page: &PageContext,
        received: Instant,
    ) -> Vec<Out> {
        self.open_request(id, Pending::Switch(switch), key, page, received)
    }

    fn open_request(
        &mut self,
        id: u64,
        step: Pending,
        key: &str,
        page: &PageContext,
        received: Instant,
    ) -> Vec<Out> {
        if let Err(step) = self.insert(id, step, key, page, received) {
            if let Pending::Prompt { id: prompt, .. } = step {
                self.prompts.forget(&prompt);
            }
            return vec![error(id, internal())];
        }
        self.queued.push_back(id);
        self.pump()
    }

    /// Page request `id`, waiting with `step`, its 120 s counted from
    /// `received`. The step back if its `PageContext` can't be written.
    fn insert(
        &mut self,
        id: u64,
        step: Pending,
        key: &str,
        page: &PageContext,
        received: Instant,
    ) -> Result<(), Pending> {
        let context = page.clone();
        let Ok(page) = serde_json::to_string(page) else {
            return Err(step);
        };
        let waited = u64::try_from(received.elapsed().as_millis()).unwrap_or(u64::MAX);
        let overall = crate::testhooks::eip1193_overall(fc_eip1193::OVERALL_MS);
        let budget = Budget::with_left(self.now_ms(), overall.saturating_sub(waited));
        self.open.insert(
            id,
            Open {
                key: key.to_owned(),
                page,
                context,
                budget,
                step,
                asked: None,
            },
        );
        Ok(())
    }

    /// Page request `id`'s send, past its checks, for `key` (APR-5e-1):
    /// the core's own estimate and fee quote, and new fee evidence when
    /// the chain's is stale.
    pub fn send(
        &mut self,
        id: u64,
        prepare: send::Prepare,
        key: &str,
        page: &PageContext,
        received: Instant,
        vault: &mut Vault,
    ) -> Vec<Out> {
        let step = Pending::Quote(Quoting {
            prepare,
            estimate: None,
            quote: None,
            reference: false,
        });
        if self.insert(id, step, key, page, received).is_err() {
            return vec![error(id, internal())];
        }
        self.reads_for(id, vault)
    }

    /// The chain reads of page request `id`'s send, now waiting on them.
    fn reads_for(&mut self, id: u64, vault: &mut Vault) -> Vec<Out> {
        let now = self.now_ms();
        let Some(Open {
            budget,
            step: Pending::Quote(quoting),
            ..
        }) = self.open.get_mut(&id)
        else {
            return Vec::new();
        };
        let (chain_id, params) = (
            quoting.prepare.chain_id(),
            quoting.prepare.estimate_params(),
        );
        let left = budget.left(now);
        let evidence = budget.step(now, EVIDENCE_DEADLINE_MS);
        let stale = !vault.eip1193_fee_fresh(chain_id);
        quoting.reference = stale;
        let mut outs = vec![
            self.chain_read(
                id,
                Part::Estimate,
                chain_id,
                "eth_estimateGas",
                params,
                left,
            ),
            self.chain_read(
                id,
                Part::Quote,
                chain_id,
                crate::chain::INTERNAL_FEE_QUOTE,
                String::new(),
                left,
            ),
        ];
        if stale {
            outs.push(self.evidence_read(id, chain_id, evidence, vault));
        }
        outs
    }

    /// One of a send's chain reads, for the chain thread.
    fn chain_read(
        &mut self,
        id: u64,
        part: Part,
        chain_id: u64,
        method: &'static str,
        params: String,
        deadline_ms: u64,
    ) -> Out {
        let tag = SEND_TAG | self.next_tag;
        self.next_tag = (self.next_tag + 1) & !SEND_TAG;
        self.reads.insert(tag, (id, part));
        Out::ChainRead(crate::phone::ChainRead {
            tag,
            chain_id,
            method,
            params,
            deadline_ms,
        })
    }

    /// New fee evidence for `chain_id`: its reply becomes the approvals'
    /// evidence, as a `chain.fee_reference` main asked for does.
    fn evidence_read(
        &mut self,
        id: u64,
        chain_id: u64,
        deadline_ms: u64,
        vault: &mut Vault,
    ) -> Out {
        let read = self.chain_read(
            id,
            Part::Reference,
            chain_id,
            crate::chain::INTERNAL_FEE_REFERENCE,
            String::new(),
            deadline_ms,
        );
        if let Out::ChainRead(read) = &read {
            vault.fee_asked(read.tag, Some(&format!(r#"{{"chain_id":{chain_id}}}"#)));
        }
        read
    }

    /// The chain thread answered one of a send's reads (`payload`, its
    /// whole response). Fee evidence is the approvals' whatever became of
    /// its request.
    pub fn chain_read_done(&mut self, tag: u64, payload: &[u8], vault: &mut Vault) -> Vec<Out> {
        let Some((id, part)) = self.reads.remove(&tag) else {
            return Vec::new();
        };
        if part == Part::Reference {
            vault.fee_answered(tag, payload);
        }
        let Some(open) = self.open.get_mut(&id) else {
            return Vec::new();
        };
        match (&mut open.step, part) {
            (Pending::Quote(quoting), _) => {
                match part {
                    Part::Estimate => quoting.estimate = Some(read_result(payload, true)),
                    Part::Quote => quoting.quote = Some(read_result(payload, false)),
                    Part::Reference => quoting.reference = false,
                }
                let (Some(estimate), Some(quote), false) =
                    (&quoting.estimate, &quoting.quote, quoting.reference)
                else {
                    return Vec::new();
                };
                let prepare = quoting.prepare.clone();
                let quoted = prepare.quoted(estimate.as_ref(), quote.as_ref());
                let verdict = quoted
                    .as_ref()
                    .map(|quoted| vault.eip1193_fee_check(&quoted.tx(&prepare), None).0);
                let ask = prepare.ask(quoted, verdict.as_deref());
                self.prompt_for(id, Asking::Send(ask))
            }
            (Pending::Judge(_), Part::Reference) => self.judge_for(id, vault),
            _ => Vec::new(),
        }
    }

    /// Page request `id`, open, asks main `asking` next.
    fn prompt_for(&mut self, id: u64, asking: Asking) -> Vec<Out> {
        let Some(prompt) = self.issue() else {
            self.open.remove(&id);
            return vec![error(id, internal())];
        };
        let Some(open) = self.open.get_mut(&id) else {
            self.prompts.forget(&prompt);
            return Vec::new();
        };
        open.step = Pending::Prompt {
            ask: asking,
            id: prompt,
        };
        open.asked = None;
        self.queued.push_back(id);
        self.pump()
    }

    /// Page request `id`'s approved send, open with its [`Pending::Judge`]:
    /// the fee check at its approval on the chain's evidence now, then the
    /// grant, then the token minted for that answer's page and handle.
    fn judge_for(&mut self, id: u64, vault: &mut Vault) -> Vec<Out> {
        let Some(Open {
            step: Pending::Judge(judge),
            ..
        }) = self.open.get(&id)
        else {
            return Vec::new();
        };
        let judge = judge.clone();
        let (verdict, again) = vault.eip1193_fee_check(&judge.tx(), Some(judge.acknowledged()));
        match judge.judged(&verdict, again, |key| vault.dapp_entry(key)) {
            send::Judged::Answer(answer) => {
                self.open.remove(&id);
                vec![reply(id, &answer)]
            }
            send::Judged::Ask(ask) => self.prompt_for(id, Asking::Send(ask)),
            send::Judged::Send(prepared) => {
                let Some(open) = self.open.remove(&id) else {
                    return Vec::new();
                };
                let minted = vault.eip1193_send_token(&open.context, &prepared);
                let answer = prepared.answer(
                    minted
                        .as_ref()
                        .map(|token| token.as_str())
                        .map_err(String::as_str),
                );
                vec![reply(id, &answer)]
            }
        }
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
                // A send's own reads go to the chain thread, never here.
                Pending::Quote(_) | Pending::Judge(_) => continue,
                Pending::Recheck(_) | Pending::Switch(_) | Pending::Rule(_) => (
                    "approval.recheck",
                    format!(r#"{{"request":{id},"page":{}}}"#, open.page),
                ),
                Pending::Select(switch) => (
                    "eip1193.select_chain",
                    format!(
                        r#"{{"request":{id},"page":{},"chain_id":{}}}"#,
                        open.page,
                        switch.chain_id()
                    ),
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
                    self.asked.insert(core, Asked::Request(id));
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
                    self.drop_unsent(id);
                    outs.push(error(
                        id,
                        ErrorBody::new(ErrorCode::TooLarge, "the prompt is over one frame"),
                    ));
                }
                // The core is exiting: nothing more goes.
                Dispatch::Closed | Dispatch::WriterGone => {
                    self.drop_unsent(id);
                }
            }
        }
        self.queued = kept;
        let (live, handles) = self.prompts.retained();
        let ended = self
            .asked
            .values()
            .filter(|asked| matches!(asked, Asked::Ended(_)))
            .count();
        crate::testhooks::eip1193_retained(live, handles, ended);
        outs
    }

    /// Page request `id`, never sent, is dropped: its prompt id retired.
    fn drop_unsent(&mut self, id: u64) {
        if let Some(Open {
            step: Pending::Prompt { id: prompt, .. },
            ..
        }) = self.open.remove(&id)
        {
            self.prompts.forget(&prompt);
        }
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
        let text = outcome
            .ok()
            .and_then(|span| message.get(span))
            .and_then(|bytes| std::str::from_utf8(bytes).ok());
        let id = match self.asked.remove(&core) {
            Some(Asked::Request(id)) => id,
            // Its page request ended: the answer spends its handle, and
            // decides nothing.
            Some(Asked::Ended(prompt)) => {
                match text {
                    Some(text) => {
                        let _ = self.prompts.accept(&prompt, text);
                    }
                    None => self.prompts.forget(&prompt),
                }
                return self.pump();
            }
            None => return Vec::new(),
        };
        let Some(mut open) = self.open.remove(&id) else {
            return Vec::new();
        };
        let mut outs = match open.step {
            // No request to main is open for these.
            Pending::Quote(_) | Pending::Judge(_) => vec![error(id, internal())],
            Pending::Recheck(connected) => match text.ok_or(Crossed).and_then(Recheck::parse) {
                Ok(recheck) => {
                    let rechecked = connected.answer(recheck.live);
                    let mut outs = vec![reply(id, &rechecked.answer)];
                    if rechecked.touch {
                        outs.extend(vault.eip1193_touch(&open.key, None));
                    }
                    outs
                }
                Err(Crossed) => vec![error(id, crossed())],
            },
            // A switch: the document gone answers 4100 with nothing
            // changed; otherwise the grant takes the chain, then main
            // selects it.
            Pending::Switch(switch) => match text.ok_or(Crossed).and_then(Recheck::parse) {
                Ok(recheck) => match switch.rechecked(recheck.live) {
                    Some(answer) => vec![reply(id, &answer)],
                    None => {
                        let events = vault.eip1193_touch(&open.key, Some(switch.chain_id()));
                        open.step = Pending::Select(switch);
                        open.asked = None;
                        self.open.insert(id, open);
                        self.queued.push_back(id);
                        events
                    }
                },
                Err(Crossed) => vec![error(id, crossed())],
            },
            Pending::Select(switch) => match text.ok_or(Crossed).and_then(Switch::selected) {
                Ok(()) => vec![reply(id, &switch.answer())],
                Err(Crossed) => vec![error(id, crossed())],
            },
            // A rule's signature, just before its effect: custody, the rule
            // judged again with the core's own grant and main's custody,
            // and the document.
            Pending::Rule(ask) => match text.ok_or(Crossed).and_then(Recheck::parse) {
                Ok(recheck) => {
                    let now = ask.query().map_or(sign::RuleNow::NotCovered, |query| {
                        vault.eip1193_rule(&open.key, Some(recheck.agent), &query)
                    });
                    match ask.rechecked(&recheck, now) {
                        sign::Rechecked::Answer(answer) => vec![reply(id, &answer)],
                        sign::Rechecked::Sign(approved) => {
                            let mut page = open.context.clone();
                            page.agent = Some(recheck.agent);
                            let signed = vault.eip1193_sign(&page, &approved);
                            let answer = approved.answer(
                                signed
                                    .as_deref()
                                    .map_err(|(locked, message)| (*locked, message.as_str())),
                            );
                            let mut outs = vec![reply(id, &answer)];
                            if signed.is_ok() {
                                outs.extend(vault.eip1193_touch(&open.key, None));
                            }
                            outs
                        }
                        // Past its rate by now: the user is asked.
                        sign::Rechecked::Prompt => match self.issue() {
                            Some(prompt) => {
                                open.step = Pending::Prompt {
                                    ask: Asking::Sign(ask),
                                    id: prompt,
                                };
                                open.asked = None;
                                self.open.insert(id, open);
                                self.queued.push_back(id);
                                Vec::new()
                            }
                            None => vec![error(id, internal())],
                        },
                    }
                }
                Err(Crossed) => vec![error(id, crossed())],
            },
            Pending::Prompt { ask, id: prompt } => {
                self.prompting = self.prompting.saturating_sub(1);
                open.budget.prompt_closed(self.now_ms());
                // Main's error is terminal too: the prompt is retired.
                let decided = match text {
                    Some(text) => self.prompts.accept(&prompt, text),
                    None => {
                        self.prompts.forget(&prompt);
                        Err(Crossed)
                    }
                };
                match ask {
                    Asking::Connect(ask) => match decided.and_then(|decision| ask.decide(decision))
                    {
                        Ok(Decided::Answer(answer)) => vec![reply(id, &answer)],
                        Ok(Decided::Grant(grant)) => {
                            let (written, events) =
                                vault.eip1193_connect(&open.key, grant.account, grant.chain_id);
                            let mut outs = vec![reply(id, &grant.answer(written))];
                            outs.extend(events);
                            outs
                        }
                        Err(Crossed) => vec![error(id, crossed())],
                    },
                    // A signature: the key must still expose the account
                    // shown, then the token is minted for this answer and
                    // spent on the signature.
                    Asking::Sign(ask) => match decided
                        .and_then(|decision| ask.decide(decision, |key| vault.dapp_entry(key)))
                    {
                        Ok(sign::Decided::Answer(answer)) => vec![reply(id, &answer)],
                        Ok(sign::Decided::Sign(approved)) => {
                            let signed = vault.eip1193_sign(&open.context, &approved);
                            let answer = approved.answer(
                                signed
                                    .as_deref()
                                    .map_err(|(locked, message)| (*locked, message.as_str())),
                            );
                            let mut outs = vec![reply(id, &answer)];
                            // "Always allow": Q9's limited rule, once signed.
                            if signed.is_ok() && approved.always_allow() {
                                outs.extend(
                                    vault.eip1193_allow_signing(&open.key, approved.account()),
                                );
                            }
                            outs
                        }
                        // A device's account: the token goes back to main
                        // with the approved request.
                        Ok(sign::Decided::Device(approved)) => {
                            let minted = vault.eip1193_device(&open.context, &approved);
                            let answer = approved.answer(
                                minted
                                    .as_ref()
                                    .map(|token| token.as_str())
                                    .map_err(String::as_str),
                            );
                            vec![reply(id, &answer)]
                        }
                        Err(Crossed) => vec![error(id, crossed())],
                    },
                    // A send (APR-5e-1): rejected or closed answers 4001;
                    // approved with no fee quoted, the quote again; approved
                    // with one, the fee check at approval on the chain's
                    // evidence, new evidence first when it is stale.
                    Asking::Send(ask) => match decided.and_then(|decision| ask.decide(decision)) {
                        Ok(send::Decided::Answer(answer)) => vec![reply(id, &answer)],
                        Ok(send::Decided::Requote(prepare)) => {
                            open.step = Pending::Quote(Quoting {
                                prepare,
                                estimate: None,
                                quote: None,
                                reference: false,
                            });
                            open.asked = None;
                            self.open.insert(id, open);
                            self.reads_for(id, vault)
                        }
                        Ok(send::Decided::Judge(judge)) => {
                            let chain_id = judge.chain_id();
                            open.step = Pending::Judge(judge);
                            open.asked = None;
                            let now = self.now_ms();
                            let evidence = open.budget.step(now, EVIDENCE_DEADLINE_MS);
                            self.open.insert(id, open);
                            if vault.eip1193_fee_fresh(chain_id) {
                                self.judge_for(id, vault)
                            } else {
                                vec![self.evidence_read(id, chain_id, evidence, vault)]
                            }
                        }
                        Err(Crossed) => vec![error(id, crossed())],
                    },
                    // The unlock a rule's signature asked for: then main's
                    // recheck.
                    Asking::Unlock(ask) => {
                        match decided.and_then(|decision| ask.unlocked(decision)) {
                            Ok(Some(answer)) => vec![reply(id, &answer)],
                            Ok(None) => {
                                open.step = Pending::Rule(ask);
                                open.asked = None;
                                self.open.insert(id, open);
                                self.queued.push_back(id);
                                Vec::new()
                            }
                            Err(Crossed) => vec![error(id, crossed())],
                        }
                    }
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
    /// if sent, is cancelled, and a prompt's leaves its tombstone.
    fn end(&mut self, id: u64) -> Vec<Out> {
        self.queued.retain(|queued| *queued != id);
        let Some(core) = self.open.get(&id).and_then(|open| open.asked) else {
            self.drop_unsent(id);
            return Vec::new();
        };
        let Some(open) = self.open.remove(&id) else {
            return Vec::new();
        };
        match open.step {
            Pending::Prompt { id: prompt, .. } => {
                self.asked.insert(core, Asked::Ended(prompt));
                self.prompting = self.prompting.saturating_sub(1);
            }
            Pending::Recheck(_)
            | Pending::Switch(_)
            | Pending::Select(_)
            | Pending::Rule(_)
            | Pending::Quote(_)
            | Pending::Judge(_) => {
                self.asked.remove(&core);
            }
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

/// A send's chain read's result, from its whole response: the node's
/// result for a read (`nested`), the call's own for the fee quote; `None`
/// for an error or none.
fn read_result(payload: &[u8], nested: bool) -> Option<fc_json::JsValue> {
    let response: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let mut result = response.get("result")?;
    if nested {
        result = result.get("result")?;
    }
    fc_json::parse(&result.to_string()).ok()
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
