//! The swarm thread (design 0015, "In the core"; SWM-4): the [`Engine`] on
//! its own thread, beside naming's, chain's and dweb's. The event loop
//! starts it once a hello settles protocol 2, and forwards it, in the
//! order the reader read them, `swarm.request` with its `PageContext`,
//! main's cancels, main's answers to the thread's own requests
//! ([`Owner::Swarm`]'s), and the naming thread's verdicts on its name
//! checks (tagged [`NAME_TAG`]).
//!
//! - **Its requests to main** (`shell.swarm_ready`, `shell.swarm_api`,
//!   `shell.swarm_subscribe`, `shell.swarm_unsubscribe`, `approval.recheck`)
//!   go through the core's one gate, each with its reply's bound (D4).
//!   Main's answer is read strictly ([`wire`]); one the thread can't read,
//!   or one a machine reads as main breaking the protocol, ends the
//!   connection (D5), as the reader's own do.
//! - **Its cancels** are watched (D13): the gate names one main hasn't
//!   answered within 60 s, and the event loop ends the connection.
//! - **Its name checks** (D1) go to the naming thread under a tag of its
//!   own; the verdict comes back through the event loop. A failed check
//!   ends the document's binding in the record the loop's page requests
//!   share ([`crate::eip1193::Bindings`]), for both families.
//! - **Its shares of the writer** are two, as the chain thread's: its
//!   requests, cancels and small answers within
//!   [`transport::MAX_QUEUED_SWARM_CONTROL_BYTES`], ahead of its large
//!   answers within [`transport::MAX_QUEUED_SWARM_BYTES`]. What waits for
//!   room waits here; the allowances and the gate wake the thread. Each
//!   answer's hold carries a notice ([`Written`]), so a request's base
//!   charge goes only once the writer has written its answer (design 0015,
//!   "The swarm thread's memory").
//! - **Its waker** is the chain thread's: room in its shares of the
//!   writer, or a free slot at main, marks its mailbox through a weak
//!   reference, so dropping the event loop's [`Handle`] ends the thread.
//! - **Its mining lane** ([`super::lane`]) is a thread of its own, started
//!   with the first batch: it sends each batch's answer to this thread's
//!   mailbox through a weak reference, as the waker does. A stuck batch's
//!   thread is left, and the next batch goes to a fresh one.
//! - **Stopping:** when the event loop has gone (shutdown, EOF or a
//!   protocol error), the thread hands the writer the frames it had made.
//!   A panic is reported ([`transport::DeathNotice`]).
//! - **The clocks** (D14): deadlines run on the thread's monotonic clock;
//!   the machines' `Date.now()` is the wall clock, which the test hooks fix
//!   (`test.swarm_world`, D11).

use std::collections::VecDeque;
use std::ops::Range;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fc_approval::stores::SwarmStore;
use fc_eip1193::names::Binding;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::message::{self, PageContext};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use fc_swarm_provider::mining::{Batch, Ran};

use super::engine::{Answer, Bounds, Engine, Fault, Io, Ms, NAME_TAG, Outgoing, Sent, Shared};
use super::{lane, wire};
use crate::eip1193::Verdict;
use crate::naming;
use crate::requests::{self, Dispatch, Expect, Owner, Requests, Start};
use crate::serve::Event;
use crate::transport::{self, Allowance, Credit, Link, Out, Reply};

/// The methods this thread serves (design 0015, SWM-4's D5).
pub const METHODS: &[&str] = &["swarm.request"];

pub fn handles(method: &str) -> bool {
    METHODS.contains(&method)
}

/// The test hooks' methods this thread answers (D11), with the `testhooks`
/// feature and its hook only.
#[cfg(feature = "testhooks")]
pub const TEST_METHODS: &[&str] = &["test.swarm_world"];

/// What the event loop forwards.
pub enum In {
    /// `swarm.request` `id`, its params as main sent them.
    Request {
        id: u64,
        params: Option<Box<RawValue>>,
        page: Option<PageContext>,
    },
    Cancel {
        id: u64,
    },
    /// Main's terminal answer to one of this thread's requests: the message
    /// as it was read, and where its `result` or its `error` lies.
    Response {
        id: u64,
        message: Zeroizing<Vec<u8>>,
        outcome: Result<Range<usize>, Range<usize>>,
    },
    /// The naming thread's verdict on a name check (D1).
    Name {
        tag: u64,
        verdict: Verdict,
    },
    /// The writer has written `swarm.request` `id`'s answer, or dropped it.
    Written(u64),
    /// Room in the writer, or a free slot at main.
    Drained,
    /// Mining lane thread `lane`'s answer for a batch.
    Mined {
        lane: u64,
        ran: Ran,
    },
    /// `test.swarm_world` (D11).
    #[cfg(feature = "testhooks")]
    World {
        id: u64,
        params: Option<Box<RawValue>>,
    },
}

/// A message, with the reader's credit for the frame it came in, held
/// until it is handled.
type Mail = (In, Option<Credit>);

/// The event loop's side of the swarm thread. The wake-ups hold only weak
/// references, so dropping this ends the thread.
pub struct Handle {
    tx: Arc<Sender<Mail>>,
}

impl Handle {
    /// False once the thread has gone.
    pub fn send(&self, message: In, credit: Option<Credit>) -> bool {
        self.tx.send((message, credit)).is_ok()
    }
}

/// What wakes the thread: room in its shares of the writer, or a free slot
/// at main.
fn waker(tx: &Arc<Sender<Mail>>) -> impl Fn() + Send + Sync + 'static {
    let wake: Weak<Sender<Mail>> = Arc::downgrade(tx);
    move || {
        if let Some(tx) = wake.upgrade() {
            let _ = tx.send((In::Drained, None));
        }
    }
}

/// Hung on an answer's hold: the thread hears once the writer has written
/// the answer (or dropped it at the end), and frees its request's base.
struct Written {
    tx: Weak<Sender<Mail>>,
    id: u64,
}

impl Drop for Written {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.upgrade() {
            let _ = tx.send((In::Written(self.id), None));
        }
    }
}

/// What the swarm thread starts with.
pub struct Spawn {
    pub out: Sender<Out>,
    pub events: Sender<Event>,
    pub requests: Arc<Requests>,
    pub link: Arc<Link>,
    /// The naming thread, for the name checks (D1).
    pub naming: naming::Handle,
    /// The Swarm grants, shared with the event loop (D2), and whether they
    /// have moved (`grant_moved: swarm`).
    pub grants: Arc<Mutex<SwarmStore>>,
    pub grants_moved: bool,
    /// The ended name bindings, shared with the event loop's page requests
    /// (D1).
    pub bindings: crate::eip1193::Bindings,
}

/// Starts the swarm thread. It writes to `out`, sends its requests through
/// `requests`, and reports a protocol error from main, or its own end, to
/// the event loop.
pub fn spawn(start: Spawn) -> std::io::Result<Handle> {
    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(tx);
    let bulk = Allowance::new(usize::MAX, transport::MAX_QUEUED_SWARM_BYTES);
    bulk.on_room(waker(&tx));
    let control = Allowance::new(usize::MAX, transport::MAX_QUEUED_SWARM_CONTROL_BYTES);
    control.on_room(waker(&tx));
    start.requests.on_room(Owner::Swarm, waker(&tx));
    let written = Arc::downgrade(&tx);
    let Spawn {
        out,
        events,
        requests,
        link,
        naming,
        grants,
        grants_moved,
        bindings,
    } = start;
    std::thread::Builder::new()
        .name("swarm".into())
        .spawn(move || {
            let _notice = transport::DeathNotice::new(events.clone(), "swarm");
            let wire = Wire {
                out,
                link,
                requests,
                bulk,
                control,
                naming,
                written,
                small: VecDeque::new(),
                large: VecDeque::new(),
                clock: None,
                stop: None,
                lane: None,
            };
            let thread = Thread {
                engine: Engine::new(
                    crate::testhooks::swarm_bounds(Bounds::default()),
                    Shared::new(grants, bindings),
                    grants_moved,
                ),
                wire,
                started: Instant::now(),
            };
            let event = match run(&rx, thread) {
                Stop::Protocol(category) => Event::ProtocolError(category),
                Stop::Writer => Event::WriterFailed,
                // The event loop has gone: nothing to report to.
                Stop::Gone => return,
            };
            let _ = events.send(event);
        })?;
    Ok(Handle { tx })
}

/// Why the thread stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// Main broke the protocol (a fixed category, never input text).
    Protocol(&'static str),
    /// The writer has gone.
    Writer,
    /// The event loop has gone.
    Gone,
}

type Flow = Result<(), Stop>;

fn fault(f: Fault) -> Stop {
    Stop::Protocol(f.0)
}

/// The thread's loop, until it has to stop.
fn run(rx: &Receiver<Mail>, mut thread: Thread) -> Stop {
    let stop = loop {
        if let Err(stop) = thread.turn() {
            break stop;
        }
        let wait = thread
            .engine
            .next_due()
            .map_or(Duration::from_secs(3600), |at| {
                Duration::from_millis(at.saturating_sub(thread.now()))
            });
        let flow = match rx.recv_timeout(wait) {
            // The frame's credit goes once its message is handled.
            Ok((message, _credit)) => thread.handle(message),
            Err(RecvTimeoutError::Timeout) => Ok(()),
            Err(RecvTimeoutError::Disconnected) => Err(Stop::Gone),
        };
        if let Err(stop) = flow {
            break stop;
        }
    };
    thread.wire.close();
    stop
}

struct Thread {
    engine: Engine,
    wire: Wire,
    started: Instant,
}

impl Thread {
    /// Milliseconds on the thread's monotonic clock.
    fn now(&self) -> Ms {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// The deadlines due, and what can be written; then whatever stopped
    /// the thread meanwhile.
    fn turn(&mut self) -> Flow {
        let now = self.now();
        if self.engine.next_due().is_some_and(|at| at <= now) {
            self.engine.tick(&mut self.wire, now).map_err(fault)?;
        }
        self.wire.flush()
    }

    fn handle(&mut self, message: In) -> Flow {
        let now = self.now();
        let flow = match message {
            In::Request { id, params, page } => {
                let params = wire::request_params(params.as_deref().map(RawValue::get));
                self.engine.request(&mut self.wire, now, id, params, page)
            }
            In::Cancel { id } => self.engine.cancel(&mut self.wire, now, id),
            In::Response {
                id,
                message,
                outcome,
            } => {
                let text = |span: Range<usize>| {
                    message
                        .get(span)
                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                        .ok_or(Stop::Protocol("swarm_reply"))
                };
                let outcome = match outcome {
                    Ok(span) => Ok(text(span)?),
                    Err(span) => Err(text(span)?),
                };
                self.engine.response(&mut self.wire, now, id, outcome)
            }
            In::Name { tag, verdict } => self.engine.named(&mut self.wire, now, tag, verdict),
            In::Written(id) => self.engine.written(&mut self.wire, now, id),
            In::Drained => self.engine.room(&mut self.wire, now),
            In::Mined { lane, ran } => self.engine.mined(&mut self.wire, now, lane, ran),
            #[cfg(feature = "testhooks")]
            In::World { id, params } => {
                self.world(id, params.as_deref().map(RawValue::get));
                Ok(())
            }
        };
        flow.map_err(fault)?;
        self.wire.flush()
    }

    /// `test.swarm_world { reset?, clock?, grants?, tags?, mining? }`
    /// (D11): one core plays every case, its world set between them.
    /// `reset` starts the read budgets, the tags' owners and the mining
    /// lane's cache and budgets afresh (the lane's only while it is idle,
    /// and never once mining is off); `clock` fixes the machines'
    /// `Date.now()`, which the lane's new-topic budget reads too; `grants`
    /// replaces the Swarm grants in memory (the file's form); `tags` sets
    /// tags' owners (`[[uid, key], …]`). It answers `{ memory, requests }`:
    /// the pool's charges and the requests the thread holds, as they stand;
    /// with `mining: true`, also `mining: { waiting, running, off, lane }`,
    /// the lane's.
    #[cfg(feature = "testhooks")]
    fn world(&mut self, id: u64, params: Option<&str>) {
        use fc_swarm_provider::budgets::ReadBudgets;
        use fc_swarm_provider::machine::TagOwners;

        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WorldParams {
            #[serde(default)]
            reset: bool,
            clock: Option<u64>,
            grants: Option<Box<RawValue>>,
            tags: Option<Vec<(u64, String)>>,
            #[serde(default)]
            mining: bool,
        }
        let parsed = params.and_then(|p| serde_json::from_str::<WorldParams>(p).ok());
        let Some(world) = parsed else {
            self.wire.answer(
                id,
                Answer::Error(ErrorBody::new(
                    ErrorCode::InvalidArgument,
                    "test.swarm_world's params",
                )),
            );
            return;
        };
        if world.reset {
            self.engine.mining_mut().reset();
        }
        let shared = self.engine.shared_mut();
        if world.reset {
            shared.budgets = ReadBudgets::new();
            shared.tags = TagOwners::new();
        }
        if let Some(grants) = world.grants {
            let store = SwarmStore::load(grants.get().as_bytes()).unwrap_or_default();
            *shared
                .grants
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = store;
        }
        for (uid, key) in world.tags.unwrap_or_default() {
            shared.tags.set(uid, fc_json::JsString::from(key));
        }
        if world.clock.is_some() {
            self.wire.clock = world.clock;
        }
        // What the thread holds now, so a test sees every charge freed.
        let mut held = serde_json::json!({
            "memory": self.engine.memory_used(),
            "requests": self.engine.requests(),
        });
        if world.mining {
            held["mining"] = self.engine.mining_mut().state();
        }
        self.wire.answer(id, Answer::Result(held.to_string()));
    }
}

/// The engine's [`Io`]: the gate, the writer and the naming thread.
struct Wire {
    out: Sender<Out>,
    link: Arc<Link>,
    requests: Arc<Requests>,
    /// The share of the writer for large answers.
    bulk: Arc<Allowance>,
    /// The share for requests, cancels and small answers.
    control: Arc<Allowance>,
    naming: naming::Handle,
    /// The thread's own mailbox, for the answers' written notices and the
    /// mining lane's answers.
    written: Weak<Sender<Mail>>,
    /// Control frames that wait for room, with the answer each one is, if
    /// it is one.
    small: VecDeque<(Zeroizing<Vec<u8>>, Option<u64>)>,
    /// Large answers that wait for room.
    large: VecDeque<(Reply, u64)>,
    /// The machines' fixed `Date.now()`, from the test hooks (D11).
    clock: Option<u64>,
    /// Why the thread must stop, found while acting for the engine.
    stop: Option<Stop>,
    /// The mining lane's thread, once a batch has gone.
    lane: Option<lane::Thread>,
}

/// An answer this size or under (its frame) goes with the control frames.
const SMALL_ANSWER: usize = 64 * 1024;

impl Wire {
    /// Hands the writer what its shares have room for: control frames
    /// first, then the large answers.
    fn flush(&mut self) -> Flow {
        if let Some(stop) = self.stop {
            return Err(stop);
        }
        while let Some((frame, _)) = self.small.front() {
            let Some(hold) = self.control.take(frame.len()) else {
                return Ok(());
            };
            let Some((frame, answer)) = self.small.pop_front() else {
                break;
            };
            let hold = self.notice(hold, answer);
            self.out
                .send(Out::Frame { frame, hold })
                .map_err(|_| Stop::Writer)?;
        }
        while let Some((reply, _)) = self.large.front() {
            let Some(hold) = self.bulk.take(reply.len()) else {
                return Ok(());
            };
            let Some((reply, id)) = self.large.pop_front() else {
                break;
            };
            let hold = self.notice(hold, Some(id));
            self.out
                .send(reply.into_out(hold))
                .map_err(|_| Stop::Writer)?;
        }
        Ok(())
    }

    /// The hold, with answer `id`'s written notice on it.
    fn notice(&self, hold: transport::Hold, answer: Option<u64>) -> transport::Hold {
        match answer {
            Some(id) => hold.guard(Written {
                tx: self.written.clone(),
                id,
            }),
            None => hold,
        }
    }

    /// Hands the writer everything made, past the allowances: the event
    /// loop has gone, and the writer's drain is bounded by time.
    fn close(&mut self) {
        while let Some((frame, answer)) = self.small.pop_front() {
            let hold = self.notice(self.control.force(frame.len()), answer);
            let _ = self.out.send(Out::Frame { frame, hold });
        }
        while let Some((reply, id)) = self.large.pop_front() {
            let hold = self.notice(self.bulk.force(reply.len()), Some(id));
            let _ = self.out.send(reply.into_out(hold));
        }
    }
}

impl Io for Wire {
    fn send(&mut self, outgoing: Outgoing) -> Sent {
        let Outgoing {
            method,
            params,
            reply_bound,
        } = outgoing;
        let dispatch = self.requests.send_with(
            Owner::Swarm,
            &self.control,
            &self.out,
            || requests::request_frame(method, &params, None),
            || Start::Anytime,
            Expect {
                reply_bound: Some(reply_bound),
                streams: false,
            },
        );
        match dispatch {
            Dispatch::Sent(id) => Sent::Id(id),
            // The gate's room, or the writer's, wakes the thread.
            Dispatch::Full | Dispatch::NoRoom => Sent::Wait,
            Dispatch::TooLarge | Dispatch::Closed | Dispatch::Late => Sent::Refused,
            Dispatch::WriterGone => {
                self.stop = Some(Stop::Writer);
                Sent::Refused
            }
        }
    }

    fn cancel(&mut self, core: u64) {
        // Watched from now on (D13); one main has answered needs none.
        if !self.requests.cancelled(core, Instant::now()) {
            return;
        }
        let cancel = format!(r#"{{"type":"cancel","id":{core}}}"#);
        if let Some(frame) = transport::frame(cancel.as_bytes()) {
            self.small.push_back((frame, None));
        }
    }

    fn name_check(&mut self, tag: u64, binding: Binding, deadline_ms: u64) {
        // The naming thread outlives this one: the event loop drops this
        // thread first.
        let _ = self.naming.send(
            naming::In::Check {
                tag,
                binding,
                deadline_ms,
            },
            None,
        );
    }

    fn name_cancel(&mut self, tag: u64) {
        let _ = self.naming.send(naming::In::CancelCheck { tag }, None);
    }

    fn answer(&mut self, id: u64, answer: Answer) {
        let mut payload = Zeroizing::new(Vec::new());
        match &answer {
            Answer::Result(result) => {
                payload.reserve(result.len() + 48);
                payload.extend_from_slice(br#"{"type":"response","id":"#);
                payload.extend_from_slice(id.to_string().as_bytes());
                payload.extend_from_slice(br#","result":"#);
                payload.extend_from_slice(result.as_bytes());
                payload.push(b'}');
            }
            Answer::Error(error) => {
                if message::write_error(&mut *payload, id, error).is_err() {
                    return;
                }
            }
        }
        // Over one frame for a main that didn't offer fragments, or over
        // the cap: `too_large` in its place.
        let reply = Reply::new(&self.link, id, payload).or_else(|| {
            let mut refused = Zeroizing::new(Vec::with_capacity(128));
            let error = ErrorBody::new(ErrorCode::TooLarge, "the answer is over the message cap");
            message::write_error(&mut *refused, id, &error).ok()?;
            transport::frame(&refused).map(Reply::Whole)
        });
        match reply {
            Some(Reply::Whole(frame)) if frame.len() <= SMALL_ANSWER => {
                self.small.push_back((frame, Some(id)));
            }
            Some(reply) => self.large.push_back((reply, id)),
            None => {}
        }
    }

    fn wall_ms(&self) -> u64 {
        self.clock.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        })
    }

    fn mine(&mut self, lane: u64, batch: Batch) {
        if self
            .lane
            .as_ref()
            .is_none_or(|thread| thread.generation() != lane)
        {
            // A stuck thread's handle goes with it: the thread ends once
            // its batch returns, its answer dropped.
            let mailbox = self.written.clone();
            let started = lane::spawn(lane, move |lane, ran| {
                mailbox
                    .upgrade()
                    .is_some_and(|tx| tx.send((In::Mined { lane, ran }, None)).is_ok())
            });
            self.lane = match started {
                Ok(thread) => Some(thread),
                Err(_) => {
                    // The watchdog ends the job, as a stuck batch's.
                    crate::log::warn("swarm mining lane didn't start", serde_json::json!({}));
                    None
                }
            };
        }
        if let Some(thread) = &self.lane {
            let _ = thread.run(batch);
        }
    }
}

// The name checks' tags are the thread's own, apart from a page's EIP-1193
// checks (their request's id, below 2^53) and the chain reads' bit.
const _: () = assert!(NAME_TAG & crate::eip1193::SEND_TAG == 0);
const _: () = assert!(NAME_TAG > fc_protocol::message::MAX_ID);
