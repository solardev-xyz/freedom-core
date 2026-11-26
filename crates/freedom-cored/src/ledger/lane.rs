//! The device lane (design 0016, "The device lane", "`shell.ledger_apdu`",
//! "Deadlines, cancel and unplugging"; LDG-2's L2): every Ledger operation
//! the core runs goes through it, one at a time, browser-wide, each APDU
//! carried to the device as one `shell.ledger_apdu` through main.
//!
//! - **One operation at a time.** Each belongs to one core request, its
//!   parent, whose envelope ID each of its APDUs names in `for`, and
//!   carries what the parent does with its end (`T`: L3's and L4's). It
//!   runs from its first APDU to its end, one APDU out at a time; then the
//!   next one starts.
//! - **The queue:** at most [`MAX_WAITING`] wait, in order, and one more is
//!   refused `LEDGER_BUSY` at once ([`LaneEnd::Busy`]). Discovery doesn't
//!   wait ([`Turn::Now`], deviation `discovery-busy`): while an operation
//!   runs or waits, it is refused `LEDGER_BUSY` at once.
//! - **The queue's limit** ([`MAX_QUEUE_WAIT`], 5 minutes): the core may
//!   not keep a device request queued past it (0016's *The device lane*,
//!   as #520 amends it: main's watchdog gives a request no
//!   `shell.ledger_apdu` has named 5 minutes and 15 s). One whose first
//!   APDU hasn't gone by then ends `LEDGER_BUSY`
//!   ([`LaneEnd::QueueLimit`]), the device busy with another request all
//!   that time.
//! - **Each APDU's deadline** goes with it as `deadline_ms`: 15 s, or 5
//!   minutes for the one the user confirms (fc-ledger's
//!   [`Exchange::confirm`], the row's *Waits for the user*;
//!   [`device_apdu_ms`]). Main enforces it on the exchange and answers
//!   `{ failed: "unresponsive" }` or `{ failed: "timeout" }`, which
//!   fc-ledger maps to `LEDGER_UNRESPONSIVE` and `LEDGER_TIMEOUT`. The
//!   core's own timer is [`MARGIN`], 1 s, longer: past it with no answer,
//!   the lane ends the operation with the same code itself
//!   ([`LaneEnd::NoAnswer`]) and cancels the APDU.
//! - **A wait in the queue and the 5 minutes** (D7's open part, 0016's
//!   question 5, the user's to decide) are [`QUEUE_WAIT`], one place. As
//!   0016 is written ([`QueueWait::Counts`]), the wait counts against the
//!   operation's 5 minutes: the core's timer on the APDU the user confirms
//!   is shorter by the time the operation waited for its first APDU. The
//!   proposal ([`QueueWait::Apart`]) caps the wait on its own and gives
//!   the confirmation its full 5 minutes. Either way no request waits past
//!   [`MAX_QUEUE_WAIT`], and `deadline_ms` is the same.
//! - **Cancel** ([`Lane::cancel`], the parent's, 0001): a waiting operation
//!   leaves the queue with nothing sent, and one that runs ends there: its
//!   APDU out at main, if one is, is cancelled (`{ "type": "cancel" }`)
//!   and watched through [`Requests::cancelled`], so main's answer is due
//!   within 60 s. Before the first APDU, between two and during the user's
//!   wait alike, the parent ends [`Outcome::Cancelled`] and nothing of the
//!   operation's is returned.
//! - **Late answers:** an APDU the lane no longer waits for (cancelled, or
//!   past its time) keeps its ID until main's answer, which is read as
//!   strictly as any and dropped. An answer is only ever taken for the
//!   APDU its ID names, never by another operation.
//! - **Unplugged:** main's `{ failed: "disconnected" }` at any APDU ends the
//!   operation `LEDGER_DISCONNECTED`, and the next one starts with its own
//!   first APDU, on a handle main opens anew.
//! - **What the device answers** is fc-ledger's to check: a status, an
//!   answer it can't read, a signature that doesn't recover to the account
//!   over the operation's own digest (the previous operation's among them,
//!   `LEDGER_BAD_SIGNATURE`) each ends the operation with its code. Main's
//!   refusal of an APDU (`invalid_argument` with its `rule`, logged) ends
//!   it `LEDGER_UNKNOWN`.
//! - **A reply that breaks `shell.ledger_apdu`'s rules** ([`super::reply`]),
//!   or main's `cancelled` for an APDU the lane didn't cancel, is a
//!   protocol error ([`Protocol`]): the event loop ends the connection.
//! - **The clock is the caller's:** each call takes `now`, and first ends
//!   whatever is due by then, so an answer past its APDU's time is late
//!   however the calls interleave, and a fixed clock drives the tests.
//!
//! **The event loop holds the lane** (L3 and L4 wire it): main's answers to
//! [`Owner::Ledger`]'s requests go to [`Lane::answered`], a parent's cancel
//! to [`Lane::cancel`]; it waits no longer than [`Lane::next_wakeup`], and
//! calls [`Lane::tick`] then and whenever the lane's `wake` says an APDU or
//! a cancel waiting for room may go.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use fc_ledger::{Exchange, Failure, LedgerCode, Operation, Signed, Step};
use fc_protocol::methods::{DEVICE_CONFIRM_MS, device_apdu_ms};

use super::reply::{self, Answered, Asked, Fault};
use crate::requests::{self, Dispatch, Expect, Owner, RequestFrame, Requests, Start};
use crate::transport::{self, Allowance};

/// The lane's request to main (design 0016, "`shell.ledger_apdu`").
pub const METHOD: &str = "shell.ledger_apdu";

/// The most operations that wait behind the one that runs (design 0016,
/// "The device lane"). One more is refused `LEDGER_BUSY`.
pub const MAX_WAITING: usize = 8;

/// The longest an operation waits for its first APDU to go: 5 minutes,
/// under either answer to question 5 ([`QueueWait`]). As 0016 is written
/// this is the operation's 5 minutes, all spent; under the proposal, the
/// wait's own cap. Main's watchdog gives a device request no
/// `shell.ledger_apdu` has named this and 0001's 15 s margin.
pub const MAX_QUEUE_WAIT: Duration = Duration::from_millis(DEVICE_CONFIRM_MS);

/// How much longer the core's own timer on an APDU is than the
/// `deadline_ms` main enforces (design 0016, "Deadlines, cancel and
/// unplugging"), so that main's `{ failed }` comes first.
pub const MARGIN: Duration = Duration::from_secs(1);

/// Design 0016's question 5 (D7's open part, the user's to decide):
/// whether a wait in the device queue counts against the 5 minutes the
/// user has to confirm. Either way no operation waits past
/// [`MAX_QUEUE_WAIT`] for its first APDU, and each APDU's `deadline_ms`
/// is the same: the answer decides only the core's own timer on the APDU
/// the user confirms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueWait {
    /// 0016 as written ("The device lane"): the wait counts against the
    /// operation's 5 minutes. The APDU the user confirms has its 5 minutes
    /// and the [`MARGIN`] less the time the operation waited for its first
    /// APDU, so a signature that waited 4 minutes has 1 left.
    Counts,
    /// Question 5's proposal: the wait is capped on its own at 5 minutes,
    /// and every confirmation has its full 5, so a request may take 10 in
    /// all. Only the lane's tests run it until the user answers.
    #[cfg_attr(not(test), allow(dead_code))]
    Apart,
}

/// The lane's answer to question 5: 0016's current text. The user's other
/// answer is this one line.
pub const QUEUE_WAIT: QueueWait = QueueWait::Counts;

impl QueueWait {
    /// What the APDU the user confirms loses of its time when its
    /// operation waited `waited` for its first APDU.
    fn spent(self, waited: Duration) -> Duration {
        match self {
            QueueWait::Counts => waited,
            QueueWait::Apart => Duration::ZERO,
        }
    }
}

/// How an operation takes its turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Turn {
    /// It waits in the queue, in order, while another runs: a signature,
    /// `ledger.add`, a Ledger owner's signature.
    Wait,
    /// Only while the lane is idle: discovery (`ledger.accounts`), refused
    /// `LEDGER_BUSY` at once while another operation runs or waits
    /// (deviation `discovery-busy`).
    Now,
}

/// How the lane itself ended an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneEnd {
    /// Refused as it came: [`MAX_WAITING`] wait already, or a discovery
    /// while the lane was busy. `LEDGER_BUSY`.
    Busy,
    /// Its first APDU hadn't gone [`MAX_QUEUE_WAIT`] after it came:
    /// `LEDGER_BUSY` (as built; 0016 names no code for it).
    QueueLimit,
    /// No answer by the core's own timer: `LEDGER_UNRESPONSIVE`, or
    /// `LEDGER_TIMEOUT` for the APDU the user confirms. The APDU is
    /// cancelled.
    NoAnswer { confirm: bool },
    /// An APDU after its first couldn't be handed to main within 15 s and
    /// the margin (main's gate or the lane's share of the writer full), or
    /// the core is exiting: `LEDGER_UNKNOWN`.
    Unsent,
}

impl LaneEnd {
    pub fn code(self) -> LedgerCode {
        match self {
            LaneEnd::Busy | LaneEnd::QueueLimit => LedgerCode::Busy,
            LaneEnd::NoAnswer { confirm: false } => LedgerCode::Unresponsive,
            LaneEnd::NoAnswer { confirm: true } => LedgerCode::Timeout,
            LaneEnd::Unsent => LedgerCode::Unknown,
        }
    }
}

/// How an operation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Its own end, fc-ledger's: the result, every check passed, or the
    /// failure (a status, main's `{ failed }` or refusal, an answer it
    /// can't read, a signature that doesn't recover).
    Done(Result<Signed, Failure>),
    /// The lane ended it.
    Lane(LaneEnd),
    /// The parent's cancel: nothing is returned.
    Cancelled,
}

impl Outcome {
    /// Its `LEDGER_*` code, `device_failed`'s `data.ledger`; `None` once
    /// signed or cancelled.
    pub fn code(&self) -> Option<LedgerCode> {
        match self {
            Outcome::Done(Ok(_)) | Outcome::Cancelled => None,
            Outcome::Done(Err(failure)) => Some(failure.code),
            Outcome::Lane(end) => Some(end.code()),
        }
    }
}

/// An operation's end, for its parent.
#[derive(Debug)]
pub struct Ended<T> {
    pub parent: u64,
    pub then: T,
    pub outcome: Outcome,
}

/// Main broke `shell.ledger_apdu`'s rules: the connection ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// A reply the reader refuses ([`super::reply`]).
    Reply(Fault),
    /// `cancelled` for an APDU the lane didn't cancel.
    Uncancelled,
    /// An answer to no APDU of the lane's: the gate routes it only the
    /// lane's own, so never.
    Unasked,
}

impl Protocol {
    /// Its category, for the protocol error's log line.
    pub fn category(self) -> &'static str {
        match self {
            Protocol::Reply(fault) => fault.category(),
            Protocol::Uncancelled => "ledger_uncancelled",
            Protocol::Unasked => "ledger_unasked",
        }
    }
}

/// The lane's share of the writer: an APDU, at most 260 bytes as hex in
/// its envelope, and the cancels behind it.
const QUEUED_FRAMES: usize = 16;
const QUEUED_BYTES: usize = 16 << 10;

struct Waiting<T> {
    parent: u64,
    operation: Operation,
    then: T,
    came: Instant,
}

struct Running<T> {
    parent: u64,
    operation: Operation,
    then: T,
    came: Instant,
    /// How long it waited for its first APDU to go, once it went.
    waited: Option<Duration>,
    /// Its first `E0 1A` has gone: only a `6D00` to that one may carry
    /// `hash_only` (Q23).
    defined: bool,
    at: At,
}

/// Where the running operation's APDU is.
enum At {
    /// Yielded at `since`, waiting for room at main's gate or in the
    /// lane's share of the writer.
    Unsent { exchange: Exchange, since: Instant },
    /// Out at main as the core's request `core`, until `due` on the core's
    /// own timer.
    Out {
        core: u64,
        asked: Asked,
        confirm: bool,
        due: Instant,
    },
}

impl<T> Running<T> {
    /// When the lane ends it unless something comes first, and how.
    fn deadline(&self) -> (Instant, LaneEnd) {
        match &self.at {
            At::Unsent { .. } if self.waited.is_none() => {
                (after(self.came, MAX_QUEUE_WAIT), LaneEnd::QueueLimit)
            }
            At::Unsent { since, .. } => (after(*since, apdu_time(false)), LaneEnd::Unsent),
            At::Out { due, confirm, .. } => (*due, LaneEnd::NoAnswer { confirm: *confirm }),
        }
    }
}

/// See the module documentation.
pub struct Lane<T> {
    requests: Arc<Requests>,
    out: Sender<transport::Out>,
    allowance: Arc<Allowance>,
    policy: QueueWait,
    running: Option<Running<T>>,
    waiting: VecDeque<Waiting<T>>,
    /// The lane's APDUs it no longer waits for that main hasn't answered,
    /// each with what it asked: their answers are read and dropped.
    late: BTreeMap<u64, Asked>,
    /// Cancels waiting for room in the lane's share of the writer.
    cancels: VecDeque<u64>,
}

impl<T> Lane<T> {
    /// `wake` is called when an APDU or a cancel that waited for room may
    /// go: the event loop then calls [`Lane::tick`].
    pub fn new(
        requests: Arc<Requests>,
        out: Sender<transport::Out>,
        wake: impl Fn() + Send + Clone + 'static,
    ) -> Self {
        let allowance = Allowance::new(QUEUED_FRAMES, QUEUED_BYTES);
        allowance.on_room(wake.clone());
        requests.on_room(Owner::Ledger, wake);
        Lane {
            requests,
            out,
            allowance,
            policy: QUEUE_WAIT,
            running: None,
            waiting: VecDeque::new(),
            late: BTreeMap::new(),
            cancels: VecDeque::new(),
        }
    }

    /// The lane under the other answer to question 5 too.
    #[cfg(test)]
    fn with_policy(mut self, policy: QueueWait) -> Self {
        self.policy = policy;
        self
    }

    /// Parent request `parent`'s operation, built from what it authorized
    /// (fc-ledger refused what a Ledger can't carry already): it starts now
    /// if the lane is idle, waits its turn, or is refused `LEDGER_BUSY`.
    /// One operation per parent: main's request IDs never repeat (0001).
    pub fn submit(
        &mut self,
        parent: u64,
        operation: Operation,
        then: T,
        turn: Turn,
        now: Instant,
    ) -> Vec<Ended<T>> {
        let mut ended = self.due(now);
        let refused = match turn {
            Turn::Now => self.running.is_some() || !self.waiting.is_empty(),
            Turn::Wait => self.waiting.len() >= MAX_WAITING,
        };
        if refused {
            ended.push(Ended {
                parent,
                then,
                outcome: Outcome::Lane(LaneEnd::Busy),
            });
        } else {
            self.waiting.push_back(Waiting {
                parent,
                operation,
                then,
                came: now,
            });
            self.next(now, &mut ended);
        }
        ended
    }

    /// Main answered the lane's request `core`: `outcome` is the text of
    /// its `result` (`Ok`) or its `error` (`Err`).
    pub fn answered(
        &mut self,
        core: u64,
        outcome: Result<&str, &str>,
        now: Instant,
    ) -> Result<Vec<Ended<T>>, Protocol> {
        let mut ended = self.due(now);
        if let Some(asked) = self.late.remove(&core) {
            // Answered: nothing left to cancel. Read, then dropped.
            self.cancels.retain(|waiting| *waiting != core);
            reply::read(outcome, asked).map_err(Protocol::Reply)?;
            return Ok(ended);
        }
        let asked = match self.running.as_ref().map(|running| &running.at) {
            Some(At::Out {
                core: out, asked, ..
            }) if *out == core => *asked,
            _ => return Err(Protocol::Unasked),
        };
        let answered = reply::read(outcome, asked).map_err(Protocol::Reply)?;
        let Some(reply) = answered.reply() else {
            return Err(Protocol::Uncancelled);
        };
        if let Answered::Refused(rule) = &answered {
            crate::log::warn(
                "ledger APDU refused by main",
                serde_json::json!({ "rule": rule.as_str() }),
            );
        }
        let Some(mut running) = self.running.take() else {
            return Err(Protocol::Unasked);
        };
        match running.operation.answer(reply) {
            Step::Send(exchange) => {
                running.at = At::Unsent {
                    exchange,
                    since: now,
                };
                self.running = Some(running);
                self.send(now, &mut ended);
            }
            Step::Done(result) => ended.push(Ended {
                parent: running.parent,
                then: running.then,
                outcome: Outcome::Done(result),
            }),
        }
        self.next(now, &mut ended);
        Ok(ended)
    }

    /// Main cancelled parent request `parent` (0001): its operation ends
    /// [`Outcome::Cancelled`], wherever it is. One the lane doesn't hold is
    /// ignored, as every owner ignores the cancels of IDs it doesn't hold.
    pub fn cancel(&mut self, parent: u64, now: Instant) -> Vec<Ended<T>> {
        let mut ended = self.due(now);
        if let Some(waiting) = self
            .waiting
            .iter()
            .position(|waiting| waiting.parent == parent)
            .and_then(|at| self.waiting.remove(at))
        {
            ended.push(Ended {
                parent,
                then: waiting.then,
                outcome: Outcome::Cancelled,
            });
        } else if self
            .running
            .as_ref()
            .is_some_and(|running| running.parent == parent)
        {
            self.end_running(Outcome::Cancelled, now, &mut ended);
            self.next(now, &mut ended);
        }
        ended
    }

    /// What is due by `now`, and what waited for room.
    pub fn tick(&mut self, now: Instant) -> Vec<Ended<T>> {
        let mut ended = self.due(now);
        self.flush(now);
        if matches!(
            self.running.as_ref().map(|running| &running.at),
            Some(At::Unsent { .. })
        ) {
            self.send(now, &mut ended);
            self.next(now, &mut ended);
        }
        ended
    }

    /// When the next deadline falls: a waiting operation's limit, or the
    /// running one's.
    pub fn next_wakeup(&self) -> Option<Instant> {
        let waiting = self
            .waiting
            .iter()
            .map(|waiting| after(waiting.came, MAX_QUEUE_WAIT));
        let running = self.running.as_ref().map(|running| running.deadline().0);
        waiting.chain(running).min()
    }

    /// Ends what is due by `now`: each waiting operation past the queue's
    /// limit, and the running one past its deadline, whose APDU out is
    /// cancelled. Then the next one starts.
    fn due(&mut self, now: Instant) -> Vec<Ended<T>> {
        let mut ended = Vec::new();
        let mut kept = VecDeque::with_capacity(self.waiting.len());
        for waiting in self.waiting.drain(..) {
            if now >= after(waiting.came, MAX_QUEUE_WAIT) {
                ended.push(Ended {
                    parent: waiting.parent,
                    then: waiting.then,
                    outcome: Outcome::Lane(LaneEnd::QueueLimit),
                });
            } else {
                kept.push_back(waiting);
            }
        }
        self.waiting = kept;
        if let Some((at, end)) = self.running.as_ref().map(Running::deadline)
            && now >= at
        {
            self.end_running(Outcome::Lane(end), now, &mut ended);
        }
        self.next(now, &mut ended);
        ended
    }

    /// While none runs, the next waiting operation starts: its first APDU
    /// goes.
    fn next(&mut self, now: Instant, ended: &mut Vec<Ended<T>>) {
        while self.running.is_none() {
            let Some(Waiting {
                parent,
                mut operation,
                then,
                came,
            }) = self.waiting.pop_front()
            else {
                return;
            };
            match operation.start() {
                Step::Send(exchange) => {
                    self.running = Some(Running {
                        parent,
                        operation,
                        then,
                        came,
                        waited: None,
                        defined: false,
                        at: At::Unsent {
                            exchange,
                            since: now,
                        },
                    });
                    self.send(now, ended);
                }
                Step::Done(result) => ended.push(Ended {
                    parent,
                    then,
                    outcome: Outcome::Done(result),
                }),
            }
        }
    }

    /// The running operation's APDU, if it waits to go, goes to main:
    /// `{ for, apdu, deadline_ms }`, its reply's bound the largest
    /// answer's. One that can't go for good ends the operation.
    fn send(&mut self, now: Instant, ended: &mut Vec<Ended<T>>) {
        let Some(running) = self.running.as_mut() else {
            return;
        };
        let At::Unsent { exchange, .. } = &running.at else {
            return;
        };
        let confirm = exchange.confirm;
        let [_, ins, ..] = exchange.apdu.header();
        let definition = ins == INS_DEFINITION;
        let asked = if definition && !running.defined {
            Asked::FirstDefinition
        } else {
            Asked::Other
        };
        let parent = running.parent;
        let apdu = exchange.apdu.as_bytes();
        let dispatch = self.requests.send_with(
            Owner::Ledger,
            &self.allowance,
            &self.out,
            || apdu_frame(parent, apdu, confirm),
            || Start::Anytime,
            Expect {
                reply_bound: Some(reply::REPLY_BOUND),
                streams: false,
            },
        );
        match dispatch {
            Dispatch::Sent(core) => {
                let waited = *running
                    .waited
                    .get_or_insert_with(|| now.saturating_duration_since(running.came));
                let spent = if confirm {
                    self.policy.spent(waited)
                } else {
                    Duration::ZERO
                };
                running.defined |= definition;
                running.at = At::Out {
                    core,
                    asked,
                    confirm,
                    due: after(now, apdu_time(confirm).saturating_sub(spent)),
                };
            }
            // Main's gate, or the lane's share of the writer, wakes it.
            Dispatch::Full | Dispatch::NoRoom => {}
            Dispatch::TooLarge | Dispatch::Late | Dispatch::Closed | Dispatch::WriterGone => {
                self.end_running(Outcome::Lane(LaneEnd::Unsent), now, ended);
            }
        }
    }

    /// The running operation ends with `outcome`: its APDU out at main, if
    /// one is, is cancelled.
    fn end_running(&mut self, outcome: Outcome, now: Instant, ended: &mut Vec<Ended<T>>) {
        let Some(running) = self.running.take() else {
            return;
        };
        if let At::Out { core, asked, .. } = running.at {
            self.late.insert(core, asked);
            self.cancels.push_back(core);
            self.flush(now);
        }
        ended.push(Ended {
            parent: running.parent,
            then: running.then,
            outcome,
        });
    }

    /// The cancels that wait for room go, each watched from then on: main's
    /// answer is due within 60 s ([`Requests::cancelled`]).
    fn flush(&mut self, now: Instant) {
        while let Some(&core) = self.cancels.front() {
            let cancel = format!(r#"{{"type":"cancel","id":{core}}}"#);
            let Some(frame) = transport::frame(cancel.as_bytes()) else {
                self.cancels.pop_front();
                continue;
            };
            let Some(hold) = self.allowance.take(frame.len()) else {
                return;
            };
            self.cancels.pop_front();
            // False once main has answered: that answer is on its way, and
            // there is nothing to cancel.
            if self.requests.cancelled(core, now)
                && self
                    .out
                    .send(transport::Out::Frame { frame, hold })
                    .is_err()
            {
                return;
            }
        }
    }

    /// Operations waiting behind the running one.
    #[cfg(test)]
    fn waiting(&self) -> usize {
        self.waiting.len()
    }
}

/// `INS` of an `E0 1A`, a typed-data definition.
const INS_DEFINITION: u8 = 0x1a;

/// The core's own time for an APDU's answer: its `deadline_ms` and the
/// margin.
fn apdu_time(confirm: bool) -> Duration {
    Duration::from_millis(device_apdu_ms(confirm)).saturating_add(MARGIN)
}

/// `at` and `span` later; never sooner than `at`.
fn after(at: Instant, span: Duration) -> Instant {
    at.checked_add(span).unwrap_or(at)
}

/// A `shell.ledger_apdu`'s frame: `{"for":<parent>,"apdu":"<hex>",
/// "deadline_ms":<15000 or 300000>}`, the APDU's hex in lower case.
fn apdu_frame(parent: u64, apdu: &[u8], confirm: bool) -> Option<RequestFrame> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut params = Vec::with_capacity(64 + 2 * apdu.len());
    params.extend_from_slice(br#"{"for":"#);
    params.extend_from_slice(parent.to_string().as_bytes());
    params.extend_from_slice(br#","apdu":""#);
    for byte in apdu {
        params.push(HEX[usize::from(byte >> 4)]);
        params.push(HEX[usize::from(byte & 0x0f)]);
    }
    params.extend_from_slice(br#"","deadline_ms":"#);
    params.extend_from_slice(device_apdu_ms(confirm).to_string().as_bytes());
    params.push(b'}');
    requests::request_frame(METHOD, &params, None)
}

#[cfg(test)]
mod tests;
