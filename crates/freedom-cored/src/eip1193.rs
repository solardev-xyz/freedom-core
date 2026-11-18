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
//! - **Names over IPNS** (APR-5f): for a document whose key is a DNS name
//!   served over IPNS (`PageContext.transport_key`), each of the
//!   reference's name checks of a name-revalidated method is a lookup on
//!   the core's own naming ([`NameCheck`], on the naming thread), within
//!   the request's clock. A name that no longer serves the IPNS key ends
//!   the document's binding ([`fc_eip1193::names`]): the request answers as
//!   a keyless document's would, with nothing written or signed, and so do
//!   the document's later name-revalidated requests. After main's recheck
//!   the core checks the name once more, before the effect (a connected
//!   key's account and last use, a switch's chain, a rule's signature):
//!   the reference has no wait there, so the name could move during it
//!   (*inferred*). A binding another request ended meanwhile refuses then
//!   with nothing resolved, as the reference reads `holdsKey`.

use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use fc_eip1193::connect::{Ask, Connected, Decided, Grant};
use fc_eip1193::names::{self, Binding, Document, Ended};
use fc_eip1193::{
    Answer, Budget, Connect, Crossed, Decision, PromptId, Prompts, Recheck, Request, Step, Switch,
    send, sign,
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

/// A page request's name check (APR-5f), for the naming thread: the name
/// of `binding` resolved within `deadline_ms`, and the verdict sent back
/// under `tag`, the page request's id.
pub struct NameCheck {
    pub tag: u64,
    pub binding: Binding,
    pub deadline_ms: u64,
}

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
    /// The documents whose name binding has ended (APR-5f).
    ended: Ended,
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
    held: Held,
    step: Pending,
    /// The core's request to main, once sent.
    asked: Option<u64>,
}

/// What a page request holds through its steps.
struct Held {
    key: String,
    /// The request's `PageContext`, as JSON.
    page: String,
    /// The request's `PageContext`, which a signature's token binds.
    context: PageContext,
    budget: Budget,
    /// The document's name binding (APR-5f), when its key is a DNS name
    /// over IPNS: each of the request's name checks resolves it.
    binding: Option<Binding>,
    /// What the request answers once its document no longer holds the
    /// name: a keyless document's answer.
    keyless: Answer,
}

impl Held {
    fn document(&self) -> Document {
        let context = &self.context;
        Document::new(
            &context.origin,
            context.transport_key.as_deref().unwrap_or(""),
            context.frame,
            context.navigation,
        )
    }
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
    /// The page's name being resolved by the core's naming (APR-5f): what
    /// follows once it still serves the document's IPNS key.
    Name(Then),
}

/// What follows one of the reference's name checks once it passes
/// (APR-5f). A request without a name binding goes straight on.
enum Then {
    /// The checks before the grant is first read, `left` of them still to
    /// come, then the request's start.
    Start { request: Box<Request>, left: u8 },
    /// `eth_accounts`' last check: its answer, which reveals the account.
    Answer(Answer),
    /// A connected key: main's recheck.
    Recheck(Connected),
    /// A connected key past main's recheck: its account answered and its
    /// last use marked.
    Touch(Answer),
    /// A connect approved: the grant written.
    Grant(Grant),
    /// A chain switch past its checks: main's recheck.
    Switch(Switch),
    /// A chain switch past main's recheck: the grant's chain written, then
    /// main's selection.
    Chain(Switch),
    /// A signature, what is signed prepared: its prompt, or its rule's
    /// path.
    Prepared(sign::Ask),
    /// A signature's prompt approved: the grant and the account checked
    /// again, then the token minted and spent.
    Approved(sign::Ask, Decision),
    /// A rule's signature, the vault unlocked: main's recheck.
    Rule(sign::Ask),
    /// A rule's signature past main's recheck: signed under `{ standing }`
    /// with the custody main's recheck gave.
    Ruled {
        approved: sign::Approved,
        agent: bool,
    },
    /// A signature made: its answer, and what is written with it.
    Signed {
        answer: Answer,
        always_allow: Option<u32>,
        touch: bool,
    },
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
            ended: Ended::new(),
            reads: BTreeMap::new(),
            next_tag: 1,
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Page request `id`, a name-revalidated method of a document whose
    /// key is a DNS name over IPNS (APR-5f): `left` name checks before its
    /// start, which reads the key's grant, as the reference checks before
    /// and after the agent's route.
    #[allow(clippy::too_many_arguments)]
    pub fn named(
        &mut self,
        id: u64,
        request: Request,
        page: &PageContext,
        binding: Binding,
        left: u8,
        received: Instant,
        vault: &mut Vault,
    ) -> Vec<Out> {
        let keyless = names::keyless(&request.method);
        let Some(held) = self.held(page, Some(binding), keyless, received) else {
            return vec![error(id, internal())];
        };
        let then = Then::Start {
            request: Box::new(request),
            left,
        };
        self.go(id, held, Pending::Name(then), vault)
    }

    /// Page request `id`'s connect, chain switch or signature (APR-5c,
    /// APR-5d), from fc-eip1193's start: `not_moved` before the dApp store
    /// moves (*inferred*), then main's recheck, its prompt, or the
    /// signature's grant, account, view and rule. For a name-keyed
    /// document, the name is checked at each of the reference's points
    /// (APR-5f).
    pub fn run(
        &mut self,
        id: u64,
        method: &str,
        step: Step,
        page: &PageContext,
        received: Instant,
        vault: &mut Vault,
    ) -> Vec<Out> {
        let binding = Binding::of(&page.origin, page.transport_key.as_deref());
        let Some(held) = self.held(page, binding, names::keyless(method), received) else {
            return vec![error(id, internal())];
        };
        let mut outs = self.step(id, held, step, vault);
        outs.extend(self.pump());
        outs
    }

    fn held(
        &self,
        page: &PageContext,
        binding: Option<Binding>,
        keyless: Answer,
        received: Instant,
    ) -> Option<Held> {
        let text = serde_json::to_string(page).ok()?;
        let waited = u64::try_from(received.elapsed().as_millis()).unwrap_or(u64::MAX);
        let overall = crate::testhooks::eip1193_overall(fc_eip1193::OVERALL_MS);
        Some(Held {
            key: page.origin.clone(),
            page: text,
            context: page.clone(),
            budget: Budget::with_left(self.now_ms(), overall.saturating_sub(waited)),
            binding,
            keyless,
        })
    }

    /// What the request's start gives.
    fn step(&mut self, id: u64, held: Held, step: Step, vault: &mut Vault) -> Vec<Out> {
        match step {
            // `eth_accounts`: the account goes only after one more check.
            Step::Answer(answer) if held.binding.is_some() && names::reveals_account(&answer) => {
                self.go(id, held, Pending::Name(Then::Answer(answer)), vault)
            }
            Step::Answer(answer) => vec![reply(id, &answer)],
            // A read and a send are served.rs's own.
            Step::Read(_) | Step::Send(_) => vec![error(id, internal())],
            Step::Connect(_) | Step::Switch(_) | Step::Sign(_) if !vault.dapp_moved() => {
                vec![not_moved(id)]
            }
            Step::Connect(Connect::Connected(connected)) => {
                self.go(id, held, Pending::Name(Then::Recheck(connected)), vault)
            }
            Step::Connect(Connect::Ask(ask)) => self.prompt(id, held, Asking::Connect(ask), vault),
            Step::Switch(switch) => self.go(id, held, Pending::Name(Then::Switch(switch)), vault),
            // The grant, the account, what is signed and the rule, judged
            // with the core's own grant; the core's view of typed data is
            // `typed_data.hash`'s, as the reference asked the core for it.
            Step::Sign(sign) => {
                let agent = held.context.agent;
                let asked = sign.ask(
                    agent,
                    |key| vault.dapp_entry(key),
                    |query| vault.eip1193_rule(&held.key, agent, query),
                    crate::signing::page_typed_data_view,
                );
                match asked {
                    Err(answer) => vec![reply(id, &answer)],
                    Ok(ask) => self.go(id, held, Pending::Name(Then::Prepared(ask)), vault),
                }
            }
        }
    }

    /// The request asks main `ask`, under a new prompt id.
    fn prompt(&mut self, id: u64, held: Held, ask: Asking, vault: &mut Vault) -> Vec<Out> {
        match self.issue() {
            Some(prompt) => self.go(id, held, Pending::Prompt { ask, id: prompt }, vault),
            None => vec![error(id, internal())],
        }
    }

    /// The request's next step: a name check goes to the naming thread
    /// (or, without a binding, on at once), any other request to main
    /// waits for room.
    fn go(&mut self, id: u64, held: Held, step: Pending, vault: &mut Vault) -> Vec<Out> {
        let Pending::Name(then) = step else {
            self.open.insert(
                id,
                Open {
                    held,
                    step,
                    asked: None,
                },
            );
            self.queued.push_back(id);
            return self.pump();
        };
        let Some(binding) = held.binding.clone() else {
            return self.proceed(id, held, then, vault);
        };
        // A transport key that isn't `ipns://<key>`, or a binding that has
        // ended: the check fails, with nothing resolved.
        if !binding.resolvable() || self.ended.has(&held.document()) {
            return vec![reply(id, &held.keyless)];
        }
        let left = held.budget.left(self.now_ms());
        if left == 0 {
            return vec![raw_reply(id, DEADLINE)];
        }
        self.open.insert(
            id,
            Open {
                held,
                step: Pending::Name(then),
                asked: None,
            },
        );
        vec![Out::NameCheck(NameCheck {
            tag: id,
            binding,
            deadline_ms: left,
        })]
    }

    /// The naming thread's verdict on page request `tag`'s name check
    /// (APR-5f). A name that no longer serves the document's IPNS key, or
    /// a resolution that failed, ends the binding, as `recheckName` does:
    /// the request answers as a keyless document's would, and so does each
    /// later name-revalidated request of the document. A verdict for a
    /// request that ended is dropped.
    pub fn name_checked(&mut self, tag: u64, holds: bool, vault: &mut Vault) -> Vec<Out> {
        if !matches!(
            self.open.get(&tag),
            Some(Open {
                step: Pending::Name(_),
                ..
            })
        ) {
            return Vec::new();
        }
        let Some(Open {
            held,
            step: Pending::Name(then),
            ..
        }) = self.open.remove(&tag)
        else {
            return Vec::new();
        };
        // A verdict at the request's deadline, the lookup's own timeout
        // included, is the deadline's: it ends no binding.
        if held.budget.left(self.now_ms()) == 0 {
            let mut outs = vec![raw_reply(tag, DEADLINE)];
            outs.extend(self.pump());
            return outs;
        }
        let document = held.document();
        if !holds {
            self.ended.end(&document);
        }
        // Another check of the same document may have ended its binding
        // while this one's answer waited.
        let mut outs = if holds && !self.ended.has(&document) {
            self.proceed(tag, held, then, vault)
        } else {
            vec![reply(tag, &held.keyless)]
        };
        outs.extend(self.pump());
        outs
    }

    /// What follows a name check that passed.
    fn proceed(&mut self, id: u64, held: Held, then: Then, vault: &mut Vault) -> Vec<Out> {
        match then {
            Then::Start { request, left } if left > 1 => {
                let then = Then::Start {
                    request,
                    left: left - 1,
                };
                self.go(id, held, Pending::Name(then), vault)
            }
            Then::Start { request, .. } => {
                let step =
                    fc_eip1193::start(&request, Some(&held.key), |key| vault.dapp_entry(key));
                self.step(id, held, step, vault)
            }
            Then::Answer(answer) => vec![reply(id, &answer)],
            Then::Recheck(connected) => self.go(id, held, Pending::Recheck(connected), vault),
            Then::Touch(answer) => {
                let mut outs = vec![reply(id, &answer)];
                outs.extend(vault.eip1193_touch(&held.key, None));
                outs
            }
            Then::Grant(grant) => {
                let (written, events) =
                    vault.eip1193_connect(&held.key, grant.account, grant.chain_id);
                let mut outs = vec![reply(id, &grant.answer(written))];
                outs.extend(events);
                outs
            }
            Then::Switch(switch) => self.go(id, held, Pending::Switch(switch), vault),
            Then::Chain(switch) => {
                let mut outs = vault.eip1193_touch(&held.key, Some(switch.chain_id()));
                outs.extend(self.go(id, held, Pending::Select(switch), vault));
                outs
            }
            Then::Prepared(ask) if !ask.ruled() => self.prompt(id, held, Asking::Sign(ask), vault),
            // The site's rule answers it (APR-5d-2): the vault's unlock
            // first while it is locked, then the name again and main's
            // recheck.
            Then::Prepared(ask) if !vault.unlocked() => {
                self.prompt(id, held, Asking::Unlock(ask), vault)
            }
            Then::Prepared(ask) => self.go(id, held, Pending::Name(Then::Rule(ask)), vault),
            Then::Approved(ask, decision) => self.decided(id, held, &ask, decision, vault),
            Then::Rule(ask) => self.go(id, held, Pending::Rule(ask), vault),
            Then::Ruled { approved, agent } => {
                let mut page = held.context.clone();
                page.agent = Some(agent);
                let signed = vault.eip1193_sign(&page, &approved);
                let answer = approved.answer(
                    signed
                        .as_deref()
                        .map_err(|(locked, message)| (*locked, message.as_str())),
                );
                if signed.is_err() {
                    return vec![reply(id, &answer)];
                }
                let then = Then::Signed {
                    answer,
                    always_allow: None,
                    touch: true,
                };
                self.go(id, held, Pending::Name(then), vault)
            }
            Then::Signed {
                answer,
                always_allow,
                touch,
            } => {
                let mut outs = vec![reply(id, &answer)];
                // "Always allow": Q9's limited rule, once signed.
                if let Some(account) = always_allow {
                    outs.extend(vault.eip1193_allow_signing(&held.key, account));
                }
                if touch {
                    outs.extend(vault.eip1193_touch(&held.key, None));
                }
                outs
            }
        }
    }

    /// Page request `id`'s send, past its checks (APR-5e-1): the core's
    /// own estimate and fee quote, and new fee evidence when the chain's is
    /// stale. A name-keyed document's send checks no name yet: its checks
    /// are a later step's.
    pub fn send(
        &mut self,
        id: u64,
        prepare: send::Prepare,
        page: &PageContext,
        received: Instant,
        vault: &mut Vault,
    ) -> Vec<Out> {
        let binding = Binding::of(&page.origin, page.transport_key.as_deref());
        let keyless = names::keyless("eth_sendTransaction");
        let Some(held) = self.held(page, binding, keyless, received) else {
            return vec![error(id, internal())];
        };
        let step = Pending::Quote(Quoting {
            prepare,
            estimate: None,
            quote: None,
            reference: false,
        });
        self.open.insert(
            id,
            Open {
                held,
                step,
                asked: None,
            },
        );
        self.reads_for(id, vault)
    }

    /// The chain reads of page request `id`'s send, now waiting on them.
    fn reads_for(&mut self, id: u64, vault: &mut Vault) -> Vec<Out> {
        let now = self.now_ms();
        let Some(Open {
            held,
            step: Pending::Quote(quoting),
            ..
        }) = self.open.get_mut(&id)
        else {
            return Vec::new();
        };
        let budget = &held.budget;
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
            send::Judged::Ask(ask) => self.prompt_for(id, Asking::Send(*ask)),
            send::Judged::Send(prepared) => {
                let Some(open) = self.open.remove(&id) else {
                    return Vec::new();
                };
                // The token goes from the minter's wiping buffer straight
                // into the reply's, as a `{ device }` answer's.
                match vault.eip1193_send_token(&open.held.context, &prepared) {
                    Ok(token) => match prepared.answer(&token) {
                        Ok(answer) => vec![send_reply(id, &answer)],
                        Err(answer) => vec![reply(id, &answer)],
                    },
                    Err(message) => vec![reply(id, &send::Prepared::refused(&message))],
                }
            }
        }
    }

    /// A signature's prompt decided: the key must still expose the account
    /// shown, then the token is minted for this answer and spent on the
    /// signature, whose answer waits for the name's last check.
    fn decided(
        &mut self,
        id: u64,
        held: Held,
        ask: &sign::Ask,
        decision: Decision,
        vault: &mut Vault,
    ) -> Vec<Out> {
        match ask.decide(decision, |key| vault.dapp_entry(key)) {
            Ok(sign::Decided::Answer(answer)) => vec![reply(id, &answer)],
            Ok(sign::Decided::Sign(approved)) => {
                let signed = vault.eip1193_sign(&held.context, &approved);
                let answer = approved.answer(
                    signed
                        .as_deref()
                        .map_err(|(locked, message)| (*locked, message.as_str())),
                );
                if signed.is_err() {
                    return vec![reply(id, &answer)];
                }
                let then = Then::Signed {
                    answer,
                    always_allow: approved.always_allow().then(|| approved.account()),
                    touch: false,
                };
                self.go(id, held, Pending::Name(then), vault)
            }
            // A device's account: the token goes back to main with the
            // approved request, from the minter's wiping buffer straight
            // into the reply's.
            Ok(sign::Decided::Device(approved)) => {
                match vault.eip1193_device(&held.context, &approved) {
                    Ok(token) => match approved.answer(&token) {
                        Ok(answer) => vec![device_reply(id, &answer)],
                        Err(answer) => vec![reply(id, &answer)],
                    },
                    Err(message) => vec![reply(id, &sign::DeviceApproval::refused(&message))],
                }
            }
            Err(Crossed) => vec![error(id, crossed())],
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
            let page = &open.held.page;
            let (method, params) = match &open.step {
                // A send's own reads go to the chain thread, never here.
                Pending::Quote(_) | Pending::Judge(_) => continue,
                Pending::Recheck(_) | Pending::Switch(_) | Pending::Rule(_) => (
                    "approval.recheck",
                    format!(r#"{{"request":{id},"page":{page}}}"#),
                ),
                Pending::Select(switch) => (
                    "eip1193.select_chain",
                    format!(
                        r#"{{"request":{id},"page":{page},"chain_id":{}}}"#,
                        switch.chain_id()
                    ),
                ),
                Pending::Prompt { ask, id: prompt } => (
                    "approval.request",
                    format!(
                        r#"{{"request":{id},"prompt":"{}","page":{page},"kind":"{}","view":{},"choices":{}}}"#,
                        prompt.hex(),
                        ask.kind(),
                        ask.view(),
                        ask.choices()
                    ),
                ),
                // A name check is the naming thread's, never queued here.
                Pending::Name(_) => continue,
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
                            open.held.budget.prompt_opened(now);
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
        let Some(Open { mut held, step, .. }) = self.open.remove(&id) else {
            return Vec::new();
        };
        let mut outs = match step {
            // No request to main is open for these.
            Pending::Quote(_) | Pending::Judge(_) => vec![error(id, internal())],
            Pending::Recheck(connected) => match text.ok_or(Crossed).and_then(Recheck::parse) {
                Ok(recheck) => {
                    let rechecked = connected.answer(recheck.live);
                    // The account goes, and its last use is marked, only
                    // once the name still serves the key after main's
                    // recheck (APR-5f): a binding another request ended
                    // meanwhile refuses with nothing resolved, as
                    // `holdsKey` does, and otherwise the core resolves the
                    // name again, since the reference has no wait there.
                    if rechecked.touch {
                        let then = Then::Touch(rechecked.answer);
                        self.go(id, held, Pending::Name(then), vault)
                    } else {
                        vec![reply(id, &rechecked.answer)]
                    }
                }
                Err(Crossed) => vec![error(id, crossed())],
            },
            // A switch: the document gone answers 4100 with nothing
            // changed; otherwise the name again (APR-5f), then the grant
            // takes the chain and main selects it.
            Pending::Switch(switch) => match text.ok_or(Crossed).and_then(Recheck::parse) {
                Ok(recheck) => match switch.rechecked(recheck.live) {
                    Some(answer) => vec![reply(id, &answer)],
                    None => self.go(id, held, Pending::Name(Then::Chain(switch)), vault),
                },
                Err(Crossed) => vec![error(id, crossed())],
            },
            Pending::Select(switch) => match text.ok_or(Crossed).and_then(Switch::selected) {
                Ok(()) => vec![reply(id, &switch.answer())],
                Err(Crossed) => vec![error(id, crossed())],
            },
            // A rule's signature, just before its effect: custody, the rule
            // judged again with the core's own grant and main's custody,
            // the document, then the name again (APR-5f).
            Pending::Rule(ask) => match text.ok_or(Crossed).and_then(Recheck::parse) {
                Ok(recheck) => {
                    let now = ask.query().map_or(sign::RuleNow::NotCovered, |query| {
                        vault.eip1193_rule(&held.key, Some(recheck.agent), &query)
                    });
                    match ask.rechecked(&recheck, now) {
                        sign::Rechecked::Answer(answer) => vec![reply(id, &answer)],
                        sign::Rechecked::Sign(approved) => {
                            let then = Then::Ruled {
                                approved,
                                agent: recheck.agent,
                            };
                            self.go(id, held, Pending::Name(then), vault)
                        }
                        // Past its rate by now: the user is asked.
                        sign::Rechecked::Prompt => self.prompt(id, held, Asking::Sign(ask), vault),
                    }
                }
                Err(Crossed) => vec![error(id, crossed())],
            },
            Pending::Prompt { ask, id: prompt } => {
                self.prompting = self.prompting.saturating_sub(1);
                held.budget.prompt_closed(self.now_ms());
                // Main's error is terminal too: the prompt is retired.
                let decided = match text {
                    Some(text) => self.prompts.accept(&prompt, text),
                    None => {
                        self.prompts.forget(&prompt);
                        Err(Crossed)
                    }
                };
                match ask {
                    // A connect approved: the name again, then the grant.
                    Asking::Connect(ask) => match decided.and_then(|decision| ask.decide(decision))
                    {
                        Ok(Decided::Answer(answer)) => vec![reply(id, &answer)],
                        Ok(Decided::Grant(grant)) => {
                            self.go(id, held, Pending::Name(Then::Grant(grant)), vault)
                        }
                        Err(Crossed) => vec![error(id, crossed())],
                    },
                    // A signature approved: the name again, then the grant
                    // and the account, the token and the signature.
                    Asking::Sign(ask) => {
                        match decided.and_then(|d| ask.approves(&d).map(|approves| (d, approves))) {
                            Ok((decision, true)) => {
                                let then = Then::Approved(ask, decision);
                                self.go(id, held, Pending::Name(then), vault)
                            }
                            Ok((decision, false)) => self.decided(id, held, &ask, decision, vault),
                            Err(Crossed) => vec![error(id, crossed())],
                        }
                    }
                    // A send (APR-5e-1): rejected or closed answers 4001;
                    // approved with no fee quoted, the quote again; approved
                    // with one, the fee check at approval on the chain's
                    // evidence, new evidence first when it is stale.
                    Asking::Send(ask) => match decided.and_then(|decision| ask.decide(decision)) {
                        Ok(send::Decided::Answer(answer)) => vec![reply(id, &answer)],
                        Ok(send::Decided::Requote(prepare)) => {
                            let step = Pending::Quote(Quoting {
                                prepare,
                                estimate: None,
                                quote: None,
                                reference: false,
                            });
                            self.open.insert(
                                id,
                                Open {
                                    held,
                                    step,
                                    asked: None,
                                },
                            );
                            self.reads_for(id, vault)
                        }
                        Ok(send::Decided::Judge(judge)) => {
                            let chain_id = judge.chain_id();
                            let now = self.now_ms();
                            let evidence = held.budget.step(now, EVIDENCE_DEADLINE_MS);
                            self.open.insert(
                                id,
                                Open {
                                    held,
                                    step: Pending::Judge(judge),
                                    asked: None,
                                },
                            );
                            if vault.eip1193_fee_fresh(chain_id) {
                                self.judge_for(id, vault)
                            } else {
                                vec![self.evidence_read(id, chain_id, evidence, vault)]
                            }
                        }
                        Err(Crossed) => vec![error(id, crossed())],
                    },
                    // The unlock a rule's signature asked for: the name
                    // again, then main's recheck.
                    Asking::Unlock(ask) => {
                        match decided.and_then(|decision| ask.unlocked(decision)) {
                            Ok(Some(answer)) => vec![reply(id, &answer)],
                            Ok(None) => self.go(id, held, Pending::Name(Then::Rule(ask)), vault),
                            Err(Crossed) => vec![error(id, crossed())],
                        }
                    }
                }
            }
            // Main never answers a name check; the core asked it nothing.
            Pending::Name(then) => {
                self.open.insert(
                    id,
                    Open {
                        held,
                        step: Pending::Name(then),
                        asked: None,
                    },
                );
                Vec::new()
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
    /// if sent, is cancelled, and a prompt's leaves its tombstone. A name
    /// check's lookup is cancelled, and its verdict never comes.
    fn end(&mut self, id: u64) -> Vec<Out> {
        self.queued.retain(|queued| *queued != id);
        let Some(open) = self.open.get(&id) else {
            return Vec::new();
        };
        if matches!(open.step, Pending::Name(_)) {
            self.open.remove(&id);
            return vec![Out::NameCancel(id)];
        }
        let Some(core) = open.asked else {
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
            | Pending::Judge(_)
            | Pending::Name(_) => {
                self.asked.remove(&core);
            }
        }
        let cancel = format!(r#"{{"type":"cancel","id":{core}}}"#);
        vec![Out::Send(Zeroizing::new(cancel.into_bytes()))]
    }

    /// Whether `open`'s clock runs. Its budget alone says so: the budget
    /// stops while the request's prompt is open.
    fn running(open: &Open) -> bool {
        !open.held.budget.stopped()
    }

    /// When the next request's time runs out.
    pub fn next_wakeup(&self) -> Option<Instant> {
        let now = self.now_ms();
        self.open
            .values()
            .filter(|open| Self::running(open))
            .map(|open| open.held.budget.left(now))
            .min()
            .map(|left| Instant::now() + Duration::from_millis(left))
    }

    /// Ends each request whose time has run out.
    pub fn tick(&mut self) -> Vec<Out> {
        let now = self.now_ms();
        let due: Vec<u64> = self
            .open
            .iter()
            .filter(|(_, open)| Self::running(open) && open.held.budget.left(now) == 0)
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

/// `not_moved` for a page request that would write the dApp store before
/// it moves.
pub fn not_moved(id: u64) -> Out {
    error(
        id,
        ErrorBody::new(
            ErrorCode::NotMoved,
            "main still writes this permission file (it isn't in grant_moved)",
        )
        .with_data(serde_json::json!({ "store": "dapp" })),
    )
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

/// A `{ device }` answer's reply: one wiping buffer sized for the whole
/// reply before anything is written, so that the token, written from the
/// minter's buffer, leaves no copy behind in a grown one (as
/// `approval.issue`'s reply).
fn device_reply(id: u64, answer: &sign::DeviceAnswer<'_>) -> Out {
    let head = format!(r#"{{"type":"response","id":{id},"result":"#);
    let size = head.len() + answer.len() + 1;
    let mut payload = Zeroizing::new(Vec::with_capacity(size));
    payload.extend_from_slice(head.as_bytes());
    answer.write_into(&mut payload);
    payload.push(b'}');
    debug_assert_eq!(payload.capacity(), size, "no reallocation");
    Out::Send(payload)
}

/// A `{ send }` answer's reply, written as [`device_reply`] writes a
/// `{ device }` answer's: one wiping buffer sized for the whole reply
/// first, so the token leaves no copy behind in a grown one.
fn send_reply(id: u64, answer: &send::SendAnswer<'_>) -> Out {
    let head = format!(r#"{{"type":"response","id":{id},"result":"#);
    let size = head.len() + answer.len() + 1;
    let mut payload = Zeroizing::new(Vec::with_capacity(size));
    payload.extend_from_slice(head.as_bytes());
    answer.write_into(&mut payload);
    payload.push(b'}');
    debug_assert_eq!(payload.capacity(), size, "no reallocation");
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
