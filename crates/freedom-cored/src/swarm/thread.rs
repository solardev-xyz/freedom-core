//! The swarm thread (design 0015, "In the core"; SWM-4): the [`Engine`] on
//! its own thread, beside naming's, chain's and dweb's. The event loop
//! starts it once a hello settles protocol 2, and forwards it, in the
//! order the reader read them, `swarm.request` with its `PageContext`,
//! `swarm.body`, main's own Swarm methods and the chrome's with their
//! caller ([`In::Own`]: `swarm.publish`, `swarm.feed`, `swarm.stamps`,
//! `swarm.upload_status`, `swarm.identities`, `swarm.history`,
//! `swarm.manifest`), main's cancels, main's answers to the thread's own
//! requests ([`Owner::Swarm`]'s), the stream frames routed to it (D4), and
//! the naming thread's verdicts on its name checks (tagged [`NAME_TAG`]).
//!
//! - **Its requests to main** (`shell.swarm_ready`, `shell.swarm_api`,
//!   `shell.swarm_part`, `shell.swarm_subscribe`, `shell.swarm_unsubscribe`,
//!   `shell.swarm_manifest`, `approval.recheck`) go through the core's one
//!   gate, each with its reply's bound (D4).
//! - **Its events:** `approval.changed { store: "swarm", key }` after the
//!   answer of a store op whose manifest projection widened or narrowed a
//!   site's Swarm grant (D2), which it writes itself ([`GrantsFile`]).
//! - **Its streams are one [`Duplex`]** ([`Duplex::swarm`]), as the dweb
//!   thread's are: the `swarm.body` answers it sends main, under main's
//!   request IDs, ending only with an upload's codes; and the parts and
//!   node bodies main streams to it, under the core's own, each request
//!   registered with its stream's codes before main can answer it (a
//!   part's, [`Codes::SwarmPart`], whose `body_stream_error` may name its
//!   file's error code; a node body's, [`Codes::SwarmPiece`], which may end
//!   `too_large`), and routed to this thread (D4). A part's head gives its
//!   exact length: one that breaks it, or any frame the duplex refuses, is
//!   main breaking the protocol, which ends the connection. Main's credit
//!   for a `swarm.body` is routed here from its request until the thread
//!   lets the route go (the engine's rule, D4).
//! - **Its hashing pool** (D9) is its own: two threads for `readData`'s
//!   leaf checks ([`crate::pool::swarm`]), whose results wake it.
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
//!   requests, cancels, small answers and the duplex's frames (credit
//!   first, then the bodies' heads and bytes, within main's windows: 4
//!   bodies' 128 KiB) within [`transport::MAX_QUEUED_SWARM_CONTROL_BYTES`],
//!   ahead of its large answers within [`transport::MAX_QUEUED_SWARM_BYTES`]. What waits for
//!   room waits here; the allowances and the gate wake the thread. While
//!   an answer waits, the thread takes no new request: each waits with its
//!   frame's credit, so the reader stops reading main once its credits are
//!   spent, as the vault loop's backpressure (design 0001;
//!   [`Thread::accept`]). Each
//!   answer's hold carries a notice ([`Written`]), so a request's base
//!   charge goes only once the writer has written its answer (design 0015,
//!   "The swarm thread's memory").
//! - **Its waker** is the chain thread's: room in its shares of the
//!   writer, a free slot at main, or a hashing result marks its mailbox
//!   through a weak reference, so dropping the event loop's [`Handle`] ends
//!   the thread.
//! - **Its mining lane** ([`super::lane`]) is a thread of its own, started
//!   with the first batch: it sends each batch's answer to this thread's
//!   mailbox through a weak reference, as the waker does. A stuck batch's
//!   thread is left, and the next batch goes to a fresh one.
//! - **Stopping:** when the event loop has gone (shutdown, EOF or a
//!   protocol error), the thread hands the writer the frames it had made,
//!   drops the bodies still queued (main fails them as it closes), and
//!   stops and joins its hashing pool. A panic is reported
//!   ([`transport::DeathNotice`]).
//! - **The clocks** (D14): deadlines, a mining job's 15 s and the lane's
//!   watchdog run on the thread's monotonic clock; the machines'
//!   `Date.now()` (and the lane's new-topic budget) is the wall clock. The
//!   test hooks' clock (`test.swarm_world`, D11) drives both: it fixes
//!   `Date.now()`, and moving it past the furthest point it has reached
//!   moves the monotonic clock as far, the work that falls due done before
//!   the hook's answer. Without the hooks the monotonic clock is the
//!   thread's `Instant` alone.
//! - **The stores** (D3; [`super::stores`]): loaded as the thread starts,
//!   once the hello named `swarm_stores` in `store_moved`, and written by
//!   the thread alone, synchronously, as the engine asks.
//! - **The vault** (D15): its asks go to the event loop, which holds it
//!   ([`Event::SwarmVault`]); the answer comes back here ([`In::Vault`]).

use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fc_approval::stores::SwarmStore;
use fc_eip1193::names::Binding;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::frame::Frame;
use fc_protocol::message::{self, CallerKind, PageContext};
use fc_protocol::stream::{
    Arrived, Credited, Duplex, Received, Replied, Retire, SendError, StreamFrame,
};
use fc_swarm_provider::machine::shell::ShellMethod;
use fc_swarm_provider::machine::{AskId, BodyOut, Job};
use fc_swarm_provider::mining::{Batch, Ran};
use fc_swarm_provider::ops::Caller;
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use super::engine::{
    Answer, Bounds, Cancelled, Engine, Fault, GrantWritten, GrantsWriter, Io, Ms, NAME_TAG,
    Outgoing, Sent, Shared, VaultAnswer, VaultAsk,
};
use super::stores::{Files, Place};
use super::{lane, stream, wire};
use crate::eip1193::Verdict;
use crate::naming;
use crate::pool::{self, SwarmHashing};
use crate::requests::{self, Dispatch, Expect, Owner, Requests, Start};
use crate::serve::Event;
use crate::transport::{
    self, Allowance, Credit, Link, Out, Reply, StreamEntry, StreamKey, StreamMark, StreamRoutes,
};

/// The methods this thread serves (design 0015, SWM-4's D5): a page's
/// request, main's ask for the body of one of the thread's calls, main's
/// own node methods (the shell parents) and the stores' ops.
pub const METHODS: &[&str] = &[
    "swarm.request",
    "swarm.body",
    "swarm.publish",
    "swarm.feed",
    "swarm.stamps",
    "swarm.upload_status",
    "swarm.identities",
    "swarm.history",
    "swarm.manifest",
];

/// The `swarm.body` answers the duplex's sender holds unwritten, across
/// every body: the 4 uploads' 128 KiB windows (design 0015, Streams).
pub const WRITER_DATA_CAP: usize = transport::SWARM_BODIES * fc_protocol::stream::WINDOW;

pub fn handles(method: &str) -> bool {
    METHODS.contains(&method)
}

/// The test hooks' methods this thread answers (D11), with the `testhooks`
/// feature and its hook only.
#[cfg(feature = "testhooks")]
pub const TEST_METHODS: &[&str] = &["test.swarm_world", "test.swarm_feed_change"];

/// What the event loop forwards.
pub enum In {
    /// `swarm.request` `id`, its params as main sent them.
    Request {
        id: u64,
        params: Option<Box<RawValue>>,
        page: Option<PageContext>,
        /// Set by the event loop as it reads main's cancel of the request.
        cancelled: Cancelled,
    },
    /// `swarm.body` `id`, its params as main sent them: its stream's route
    /// is the thread's from now on (D4).
    Body {
        id: u64,
        params: Option<Box<RawValue>>,
    },
    /// One of main's own Swarm methods, or the chrome's (`swarm.publish`,
    /// `swarm.feed`, `swarm.stamps`, `swarm.upload_status`,
    /// `swarm.identities`, `swarm.history`, `swarm.manifest`), request `id`
    /// from `caller`, its params as main sent them.
    Own {
        id: u64,
        method: &'static str,
        params: Option<Box<RawValue>>,
        caller: CallerKind,
        /// Set by the event loop as it reads main's cancel of the request.
        cancelled: Cancelled,
    },
    /// A stream's entry of frames, coalesced under the reader's stream cap:
    /// taken here, and charged until handled.
    Stream(StreamMark),
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
    /// The vault's answer to the ask under `tag`: an owner, a signature, or
    /// the user's accounts.
    Vault {
        tag: u64,
        answer: Box<VaultAnswer>,
    },
    /// The writer has written `swarm.request` `id`'s answer, or dropped it.
    Written(u64),
    /// Room in the writer, a free slot at main, or a hashing result.
    Drained,
    /// Mining lane thread `lane`'s answer for a batch.
    Mined {
        lane: u64,
        ran: Box<Ran>,
    },
    /// `test.swarm_world` (D11).
    #[cfg(feature = "testhooks")]
    World {
        id: u64,
        params: Option<Box<RawValue>>,
    },
    /// `test.swarm_feed_change` (D11).
    #[cfg(feature = "testhooks")]
    FeedChange {
        id: u64,
        params: Option<Box<RawValue>>,
    },
}

/// A message, with the reader's credit for the frame it came in, held
/// until it is handled.
type Mail = (In, Option<Credit>);

// A stream mark's slot here is within what the reader charges its entry.
const _: () = assert!(transport::stream_slot_fits(std::mem::size_of::<Mail>()));

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

/// What wakes the thread: room in its shares of the writer, a free slot at
/// main, or a result in the hashing pool.
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
    /// The Swarm grants, shared with the event loop (D2), and once they
    /// have moved (`grant_moved: swarm`) their file, which a manifest's
    /// projections write ([`crate::grants::write_swarm`]).
    pub grants: Arc<Mutex<SwarmStore>>,
    pub grants_file: Option<PathBuf>,
    /// The ended name bindings, shared with the event loop's page requests
    /// (D1).
    pub bindings: crate::eip1193::Bindings,
    /// Where the Swarm stores are, once the hello named `swarm_stores` in
    /// `store_moved` (D3); `None` before.
    pub stores: Option<Place>,
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
    let hashing = pool::swarm(waker(&tx), start.events.clone())?;
    let written = Arc::downgrade(&tx);
    let Spawn {
        out,
        events,
        requests,
        link,
        naming,
        grants,
        grants_file,
        bindings,
        stores,
    } = start;
    let grants_moved = grants_file.is_some();
    std::thread::Builder::new()
        .name("swarm".into())
        .spawn(move || {
            let _notice = transport::DeathNotice::new(events.clone(), "swarm");
            let mut wire = Wire {
                routes: Arc::clone(requests.routes()),
                events: events.clone(),
                files: None,
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
                duplex: Duplex::swarm(WRITER_DATA_CAP),
                made: None,
                unpushed: BTreeMap::new(),
                #[cfg(feature = "testhooks")]
                most_waiting: 0,
                hashing: Some(hashing),
                lane: None,
            };
            let mut shared = Shared::new(grants, bindings);
            if let Some(path) = grants_file {
                shared.grants_writer = Some(Box::new(GrantsFile { path }));
            }
            // The stores load as the thread starts (D3), off the event loop.
            if let Some(place) = stores {
                let loaded = Files::load(place, wire.wall_ms());
                shared.keeper = fc_swarm_provider::machine::keeper::Keeper::new(loaded.feeds);
                shared.manifests = loaded.manifests;
                shared.stores_moved = true;
                wire.files = Some(loaded.files);
            }
            let thread = Thread {
                engine: Engine::new(
                    crate::testhooks::swarm_bounds(Bounds::default()),
                    shared,
                    grants_moved,
                ),
                wire,
                started: Instant::now(),
                held: VecDeque::new(),
                #[cfg(feature = "testhooks")]
                parked: VecDeque::new(),
                #[cfg(feature = "testhooks")]
                skew: Skew::default(),
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

fn read(frame: &Frame) -> Result<StreamFrame<'_>, Fault> {
    StreamFrame::from_frame(frame).map_err(|e| Fault(e.category()))
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
        // A vault answer the test hooks park is polled for its release.
        #[cfg(feature = "testhooks")]
        let wait = if thread.parked.is_empty() {
            wait
        } else {
            wait.min(Duration::from_millis(10))
        };
        let flow = match rx.recv_timeout(wait) {
            // The frame's credit goes once its message is handled, or with
            // it once a held request is.
            Ok(mail) => thread.accept(mail),
            Err(RecvTimeoutError::Timeout) => Ok(()),
            Err(RecvTimeoutError::Disconnected) => Err(Stop::Gone),
        };
        if let Err(stop) = flow.and_then(|()| thread.release_held()) {
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
    /// New requests held, with their frames' credit, while answers wait for
    /// the writer (and what must stay behind them): see [`Thread::accept`].
    held: VecDeque<Mail>,
    /// Vault answers the test hooks hold back (`FREEDOM_CORED_TEST_SWARM_HOLD`,
    /// D11), in order, until the hook's release.
    #[cfg(feature = "testhooks")]
    parked: VecDeque<(u64, VaultAnswer)>,
    /// How far the test hooks' clock has moved the monotonic clock (D14).
    #[cfg(feature = "testhooks")]
    skew: Skew,
}

/// The test hooks' hold on the monotonic clock (D14): the furthest the
/// fixed `Date.now()` has reached, and how far moving past it has moved
/// the monotonic clock.
#[cfg(feature = "testhooks")]
#[derive(Debug, Default, Clone, Copy)]
struct Skew {
    furthest: Option<u64>,
    by: Ms,
}

#[cfg(feature = "testhooks")]
impl Skew {
    /// The test clock is set to `clock`: past its furthest point, the
    /// monotonic clock moves as far; back, or forward again up to that
    /// point, it stays (a monotonic clock doesn't follow a wall clock set
    /// back). The first setting only pins it.
    fn set(&mut self, clock: u64) {
        if let Some(furthest) = self.furthest {
            self.by = self.by.saturating_add(clock.saturating_sub(furthest));
        }
        self.furthest = Some(self.furthest.map_or(clock, |f| f.max(clock)));
    }
}

impl Thread {
    /// Milliseconds on the thread's monotonic clock.
    fn now(&self) -> Ms {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        elapsed.saturating_add(self.skew())
    }

    /// How far the test hooks' clock has moved the monotonic clock.
    #[cfg(feature = "testhooks")]
    fn skew(&self) -> Ms {
        self.skew.by
    }

    #[cfg(not(feature = "testhooks"))]
    fn skew(&self) -> Ms {
        0
    }

    /// The hashing pool's results, the deadlines due, and what can be
    /// written; then whatever stopped the thread meanwhile.
    fn turn(&mut self) -> Flow {
        #[cfg(feature = "testhooks")]
        if !self.parked.is_empty() && crate::testhooks::swarm_hold_released() {
            while let Some((tag, answer)) = self.parked.pop_front() {
                let now = self.now();
                self.engine
                    .vaulted(&mut self.wire, now, tag, answer)
                    .map_err(fault)?;
            }
        }
        while let Some((id, ask, done)) = self.wire.hashing.as_mut().and_then(SwarmHashing::take) {
            let now = self.now();
            self.engine
                .hashed(&mut self.wire, now, id, ask, done)
                .map_err(fault)?;
        }
        let now = self.now();
        if self.engine.next_due().is_some_and(|at| at <= now) {
            self.engine.tick(&mut self.wire, now).map_err(fault)?;
        }
        self.wire.flush()
    }

    /// A message from the event loop: handled now, or held. While answers
    /// of the thread's wait for the writer past its allowances, it takes no
    /// new request (a page's `swarm.request`, main's own methods and the
    /// chrome's): each waits here with its frame's credit, so once the
    /// reader's credits are spent it stops reading main, which is
    /// backpressure on main, as the vault loop's own (design 0001). The
    /// answers already made, and those of the work in flight, are all that
    /// waits. What must stay behind a held request waits behind it too: a
    /// cancel for it, and the test hooks' requests while any request is
    /// held. Everything else (main's answers, streams, bodies, the vault's
    /// and naming's answers, room) is handled at once.
    fn accept(&mut self, mail: Mail) -> Flow {
        if self.holds(&mail.0) {
            self.held.push_back(mail);
            return Ok(());
        }
        let (message, _credit) = mail;
        self.handle(message)
    }

    fn holds(&self, message: &In) -> bool {
        match message {
            In::Request { .. } | In::Own { .. } => {
                !self.held.is_empty() || self.wire.answers_waiting()
            }
            In::Cancel { id } => self.held.iter().any(|(held, _)| match held {
                In::Request { id: request, .. } | In::Own { id: request, .. } => request == id,
                _ => false,
            }),
            #[cfg(feature = "testhooks")]
            In::World { .. } | In::FeedChange { .. } => !self.held.is_empty(),
            _ => false,
        }
    }

    /// The held messages, in order, while no answer waits for the writer.
    fn release_held(&mut self) -> Flow {
        while !self.wire.answers_waiting() {
            let Some((message, _credit)) = self.held.pop_front() else {
                break;
            };
            self.handle(message)?;
        }
        Ok(())
    }

    fn handle(&mut self, message: In) -> Flow {
        let now = self.now();
        let flow = match message {
            In::Request {
                id,
                params,
                page,
                cancelled,
            } => {
                let params = wire::request_params(params.as_deref().map(RawValue::get));
                self.engine
                    .request_cancellable(&mut self.wire, now, id, params, page, cancelled)
            }
            In::Body { id, params } => {
                self.wire
                    .duplex
                    .request(id)
                    .map_err(|e| Stop::Protocol(e.category()))?;
                let params = params.as_deref().map(RawValue::get);
                self.engine.body_request(&mut self.wire, now, id, params)
            }
            In::Stream(mark) => match mark.take() {
                Some(taken) => self.stream(now, taken.entry()),
                None => Ok(()),
            },
            // Every cancel main sends reaches this thread: a body's goes to
            // its sender, which writes its `cancelled`; a request's to the
            // engine; any other changes nothing.
            In::Cancel { id } if self.wire.duplex.sender().is_live(id) => {
                self.wire
                    .duplex
                    .cancel(id)
                    .map_err(|e| Stop::Protocol(e.category()))?;
                self.engine.body_cancelled(&mut self.wire, now, id)
            }
            In::Cancel { id } => self.engine.cancel(&mut self.wire, now, id),
            In::Own {
                id,
                method,
                params,
                caller,
                cancelled,
            } => {
                let params = params.as_deref().map(RawValue::get);
                match ShellMethod::from_name(method) {
                    Some(shell) => self.engine.shell_cancellable(
                        &mut self.wire,
                        now,
                        id,
                        shell,
                        params,
                        cancelled,
                    ),
                    None => {
                        // The chrome's or main's: an op only main makes is
                        // refused to the chrome (D7).
                        let caller = match caller {
                            CallerKind::Chrome => Caller::Chrome,
                            _ => Caller::Shell,
                        };
                        self.engine
                            .op(&mut self.wire, now, id, method, params, caller)
                    }
                }
            }
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
            In::Vault { tag, answer } => self.vaulted(now, tag, *answer),
            In::Written(id) => self.engine.written(&mut self.wire, now, id),
            In::Drained => self.engine.room(&mut self.wire, now),
            In::Mined { lane, ran } => self.engine.mined(&mut self.wire, now, lane, *ran),
            #[cfg(feature = "testhooks")]
            In::World { id, params } => self.world(id, params.as_deref().map(RawValue::get)),
            #[cfg(feature = "testhooks")]
            In::FeedChange { id, params } => {
                match feed_change_params(params.as_deref().map(RawValue::get)) {
                    Some(change) => self.engine.feed_change(&mut self.wire, now, id, change),
                    None => {
                        self.wire.answer(
                            id,
                            Answer::Error(ErrorBody::new(
                                ErrorCode::InvalidArgument,
                                "test.swarm_feed_change's params",
                            )),
                        );
                        Ok(())
                    }
                }
            }
        };
        flow.map_err(fault)?;
        self.wire.flush()
    }

    /// The vault's answer under `tag`, to the engine; or, while the test
    /// hooks hold that kind back, parked until their release (D11).
    fn vaulted(&mut self, now: Ms, tag: u64, answer: VaultAnswer) -> Result<(), Fault> {
        #[cfg(feature = "testhooks")]
        {
            use fc_swarm_provider::machine::Event;
            let kind = match &answer {
                VaultAnswer::Event(Event::Owner(_)) | VaultAnswer::Accounts(_) => "owner",
                VaultAnswer::Event(_) => "sign",
            };
            if !self.parked.is_empty() || crate::testhooks::swarm_hold_parks(kind) {
                self.parked.push_back((tag, answer));
                return Ok(());
            }
        }
        self.engine.vaulted(&mut self.wire, now, tag, answer)
    }

    /// A stream's entry from main: a part's or a node body's data in frames
    /// the duplex takes (at most 64 KiB each), then its terminal; or a
    /// `swarm.body`'s credit, summed.
    fn stream(&mut self, now: Ms, entry: &StreamEntry) -> Result<(), Fault> {
        match entry {
            StreamEntry::Piece { id, data, terminal } => {
                for bytes in data.chunks(fc_protocol::stream::MAX_DATA) {
                    self.frame(now, StreamFrame::Data { id: *id, bytes })?;
                }
                match terminal {
                    Some(frame) => self.frame(now, read(frame)?),
                    None => Ok(()),
                }
            }
            // Past a `u32`, credit is past any window: refused as such.
            StreamEntry::Credit { id, bytes } => self.frame(
                now,
                StreamFrame::Credit {
                    id: *id,
                    bytes: u32::try_from(*bytes).unwrap_or(u32::MAX),
                },
            ),
        }
    }

    /// One stream frame from main, through the duplex, to the engine.
    fn frame(&mut self, now: Ms, parsed: StreamFrame<'_>) -> Result<(), Fault> {
        let terminal = matches!(parsed, StreamFrame::End { .. } | StreamFrame::Abort { .. });
        let stream_id = parsed.id();
        let (credit, data) = match &parsed {
            StreamFrame::Credit { bytes, .. } => (Some(*bytes), None),
            StreamFrame::Data { bytes, .. } => (None, Some(*bytes)),
            _ => (None, None),
        };
        let received = self
            .wire
            .duplex
            .receive(parsed)
            .map_err(|e| Fault(e.category()))?;
        let wire = &mut self.wire;
        match received {
            Received::Credited(Credited::Taken(id)) => {
                let bytes = credit.map_or(0, |n| n as usize);
                self.engine.body_credit(wire, now, id, bytes)
            }
            // Crossed the body's terminal: late, unless main had answered
            // the body's call, or cancelled the body (D4).
            Received::Credited(Credited::Late) => self.engine.late_credit(stream_id),
            Received::Arrived(Arrived::Data { id, .. }) => match data {
                Some(bytes) => self.engine.stream_data(wire, now, id, bytes.to_vec()),
                None => Ok(()),
            },
            Received::Arrived(Arrived::End { id }) => self.engine.stream_end(wire, now, id, None),
            Received::Arrived(Arrived::Abort { id, abort }) => {
                let abort = stream::abort_of(&abort).ok_or(Fault("swarm_abort"))?;
                self.engine.stream_end(wire, now, id, Some(abort))
            }
            // A stream the thread cancelled: its data goes, and its
            // terminal lets go of what it held.
            Received::Arrived(Arrived::Dropped { id }) if terminal => {
                self.engine.stream_retired(wire, now, id)
            }
            Received::Arrived(Arrived::Dropped { .. }) => Ok(()),
            // A part that isn't the length its head gave: main broke the
            // protocol, as the machine reads one (`PartLength`).
            Received::Arrived(Arrived::Mismatch { .. }) => Err(Fault("swarm_part_length")),
        }
    }

    /// `test.swarm_world { reset?, clock?, grants?, tags?, feeds?, reload?,
    /// mining? }` (D11): one core plays every case, its world set between
    /// them. `reset` starts the read budgets, the tags' owners and the
    /// mining lane's cache and budgets afresh (the lane's only while it is
    /// idle, and never once mining is off), and the stores: once they have
    /// moved, `swarm-feeds.json` removed and the publish history a new,
    /// empty database (before the move, the feed store empty in memory);
    /// `clock` fixes the machines' `Date.now()`, which the lane's new-topic
    /// budget and the stores' reads below (a v1 migration, the history's
    /// sweep) read too, and moving it past the furthest point it has
    /// reached moves the monotonic clock as far (D14), the deadlines, jobs'
    /// 15 s and watchdog that fall due handled before the answer; `grants`
    /// replaces the Swarm grants in memory (the file's form); `tags` sets
    /// tags' owners (`[[uid, key], …]`); `feeds` replaces `swarm-feeds.json`
    /// with the text and loads it as a start does (before the move, the
    /// store in memory); `reload` reads the feed store and the manifest
    /// store again from their files and opens the history again, as a start
    /// does. It answers `{ memory,
    /// requests, streams }`: the pool's charges, the requests the thread
    /// holds and the incoming streams' slots taken, as they stand, and
    /// `answers_waiting_most`, the most bytes of answers that have waited
    /// for the writer at once; with
    /// `mining: true`, also `mining: { waiting, running, off, lane, batches
    /// }`, the lane's.
    #[cfg(feature = "testhooks")]
    fn world(&mut self, id: u64, params: Option<&str>) -> Result<(), Fault> {
        use fc_swarm_provider::budgets::ReadBudgets;
        use fc_swarm_provider::machine::TagOwners;
        use fc_swarm_provider::stores::feeds::FeedStore;

        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WorldParams {
            #[serde(default)]
            reset: bool,
            clock: Option<u64>,
            grants: Option<Box<RawValue>>,
            tags: Option<Vec<(u64, String)>>,
            feeds: Option<String>,
            #[serde(default)]
            reload: bool,
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
            return Ok(());
        };
        use fc_swarm_provider::machine::keeper::Keeper;
        // The clock first: the stores read below (a v1 migration, the
        // history's sweep) read it.
        if let Some(clock) = world.clock {
            self.wire.clock = Some(clock);
            self.skew.set(clock);
        }
        let wall = self.wire.wall_ms();
        if world.reset {
            self.engine.mining_mut().reset();
        }
        let shared = self.engine.shared_mut();
        if world.reset {
            shared.budgets = ReadBudgets::new();
            shared.tags = TagOwners::new();
            shared.keeper = Keeper::new(match self.wire.files.as_mut() {
                Some(files) => {
                    files.reset_history(wall);
                    files.reset_feeds(None, wall)
                }
                None => FeedStore::empty(),
            });
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
        if let Some(text) = world.feeds {
            shared.keeper = Keeper::new(match self.wire.files.as_mut() {
                Some(files) => files.reset_feeds(Some(&text), wall),
                None => FeedStore::load(Some(text.as_bytes()), 0, |_| false).store,
            });
        }
        if world.reload
            && let Some(files) = self.wire.files.as_mut()
        {
            let (feeds, manifests) = files.reload(wall);
            shared.keeper = Keeper::new(feeds);
            shared.manifests = manifests;
        }
        // What fell due as the clock moved, before the answer.
        let now = self.now();
        if self.engine.next_due().is_some_and(|at| at <= now) {
            self.engine.tick(&mut self.wire, now)?;
        }
        // What the thread holds now, so a test sees every charge freed.
        let mut held = serde_json::json!({
            "memory": self.engine.memory_used(),
            "requests": self.engine.requests(),
            "streams": self.engine.streams_held(),
            "answers_waiting_most": self.wire.most_waiting,
        });
        if world.mining {
            held["mining"] = self.engine.mining_mut().state();
        }
        self.wire.answer(id, Answer::Result(held.to_string()));
        Ok(())
    }
}

/// `test.swarm_feed_change`'s params (D11): a feed store operation by its
/// reference name and its arguments, as `swarm.identities` will name them:
/// `{ op, key?, data?, options?, index?, identityId?, name?, reference? }`.
#[cfg(feature = "testhooks")]
fn feed_change_params(
    params: Option<&str>,
) -> Option<fc_swarm_provider::stores::feeds::FeedChange> {
    use fc_json::{JsString, JsValue};
    use fc_swarm_provider::stores::feeds::{FeedChange, Source};
    let params = fc_json::parse(params?).ok()?;
    let member = |name: &str| params.get(name).cloned().unwrap_or(JsValue::Undefined);
    let text = |name: &str| match params.get(name) {
        Some(JsValue::String(s)) => Some(s.clone()),
        _ => None,
    };
    let key = || text("key");
    let source = Source::User;
    Some(match text("op")?.as_str() {
        "setOriginEntry" => FeedChange::SetOriginEntry {
            key: key()?,
            data: member("data"),
        },
        "allocatePublisherKeyIndex" => FeedChange::AllocatePublisherKeyIndex,
        "createAppScopedIdentity" => FeedChange::CreateAppScopedIdentity {
            key: key()?,
            options: member("options"),
            source,
        },
        "createAppScopedIdentityAt" => FeedChange::CreateAppScopedIdentityAt {
            key: key()?,
            index: member("index"),
            options: member("options"),
            source,
        },
        "ensureAntWalletIdentity" => FeedChange::EnsureAntWalletIdentity {
            key: key()?,
            options: member("options"),
            source,
        },
        "activateIdentity" => FeedChange::ActivateIdentity {
            key: key()?,
            identity_id: member("identityId"),
            source,
        },
        "grantFeedAccess" => FeedChange::GrantFeedAccess {
            key: key()?,
            source,
        },
        "revokeFeedAccess" => FeedChange::RevokeFeedAccess {
            key: key()?,
            source,
        },
        "setFeed" => FeedChange::SetFeed {
            key: key()?,
            name: text("name").unwrap_or_else(|| JsString::from("")),
            data: member("data"),
        },
        "updateFeedReference" => FeedChange::UpdateFeedReference {
            key: key()?,
            name: text("name")?,
            reference: member("reference"),
        },
        _ => return None,
    })
}

/// The engine's [`Io`]: the gate, the writer and the naming thread.
struct Wire {
    out: Sender<Out>,
    /// The event loop, for the vault's asks (D15).
    events: Sender<Event>,
    /// The Swarm stores' files, once they have moved (D3).
    files: Option<Files>,
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
    /// Large answers that wait for room, and the events behind one.
    large: VecDeque<(Reply, Option<u64>)>,
    /// The machines' fixed `Date.now()`, from the test hooks (D11).
    clock: Option<u64>,
    /// Why the thread must stop, found while acting for the engine.
    stop: Option<Stop>,
    /// The mining lane's thread, once a batch has gone.
    lane: Option<lane::Thread>,
    /// The thread's streams, both ways.
    duplex: Duplex,
    /// The stream routes, for the routes the thread lets go of (D4).
    routes: Arc<StreamRoutes>,
    /// A frame the duplex made that the writer had no room for yet.
    made: Option<Zeroizing<Vec<u8>>>,
    /// Body bytes the duplex's cap didn't take yet, by `swarm.body` ID.
    unpushed: BTreeMap<u64, Unpushed>,
    /// `None` once stopped.
    hashing: Option<SwarmHashing>,
    /// The most bytes of answers that have waited here for the writer at
    /// once, for the test hooks (`test.swarm_world`'s `answers_waiting_most`).
    #[cfg(feature = "testhooks")]
    most_waiting: usize,
}

/// A body's bytes the duplex's sender didn't take yet, and whether its end
/// follows them.
#[derive(Default)]
struct Unpushed {
    bytes: VecDeque<u8>,
    end: bool,
}

/// An answer this size or under (its frame) goes with the control frames.
const SMALL_ANSWER: usize = 64 * 1024;

impl Wire {
    /// Hands the writer what its shares have room for: control frames
    /// first, then the duplex's (credit, then the bodies), then the large
    /// answers.
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
        loop {
            self.push_unpushed();
            let mut wrote = false;
            loop {
                let frame = match self.made.take() {
                    Some(frame) => frame,
                    None => {
                        let mut frame = Zeroizing::new(Vec::new());
                        if self.duplex.next_frame(&mut frame).is_none() {
                            break;
                        }
                        frame
                    }
                };
                let Some(hold) = self.control.take(frame.len()) else {
                    self.made = Some(frame);
                    return Ok(());
                };
                self.out
                    .send(Out::Frame { frame, hold })
                    .map_err(|_| Stop::Writer)?;
                wrote = true;
            }
            // Frames written free the sender's cap for bytes that waited.
            if !wrote || self.unpushed.is_empty() {
                break;
            }
        }
        while let Some((reply, _)) = self.large.front() {
            let Some(hold) = self.bulk.take(reply.len()) else {
                return Ok(());
            };
            let Some((reply, id)) = self.large.pop_front() else {
                break;
            };
            let hold = self.notice(hold, id);
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

    /// Hands the writer everything made, past the allowances, and stops the
    /// pool: the event loop has gone, and the writer's drain is bounded by
    /// time. The bodies still queued are dropped: main fails them as it
    /// closes.
    fn close(&mut self) {
        while let Some((frame, answer)) = self.small.pop_front() {
            let hold = self.notice(self.control.force(frame.len()), answer);
            let _ = self.out.send(Out::Frame { frame, hold });
        }
        if let Some(frame) = self.made.take() {
            let hold = self.control.force(frame.len());
            let _ = self.out.send(Out::Frame { frame, hold });
        }
        while let Some((reply, id)) = self.large.pop_front() {
            let hold = self.notice(self.bulk.force(reply.len()), id);
            let _ = self.out.send(reply.into_out(hold));
        }
        if let Some(hashing) = self.hashing.take() {
            hashing.shutdown();
        }
    }

    /// Body bytes that waited for the sender's cap, as far as it takes
    /// them; a body whose bytes have all gone gets its end.
    fn push_unpushed(&mut self) {
        let sender = self.duplex.sender_mut();
        self.unpushed.retain(|&id, u| {
            let pushed = match sender.push(id, u.bytes.make_contiguous()) {
                Ok(n) => n,
                // Cancelled or aborted meanwhile: its bytes go.
                Err(_) => return false,
            };
            u.bytes.drain(..pushed);
            if !u.bytes.is_empty() {
                return true;
            }
            if u.end {
                settled(id, sender.finish(id));
            }
            false
        });
    }
}

/// What a call on the duplex's sender did. Main's cancel came first when
/// the body is gone: the machine's part after it is dropped, as the cancel
/// settled the body. Anything else is the core's own bug, logged.
fn settled(id: u64, result: Result<(), SendError>) {
    match result {
        Ok(()) | Err(SendError::Gone) => {}
        Err(error) => crate::log::warn(
            "swarm body refused",
            serde_json::json!({ "id": id, "error": error.name() }),
        ),
    }
}

impl Io for Wire {
    fn send(&mut self, outgoing: Outgoing) -> Sent {
        let Outgoing {
            method,
            params,
            reply_bound,
            opens,
        } = outgoing;
        let dispatch = self.requests.send_with(
            Owner::Swarm,
            &self.control,
            &self.out,
            || requests::request_frame(method, &params, None),
            || Start::Anytime,
            Expect {
                reply_bound: Some(reply_bound),
                streams: opens.is_some(),
            },
        );
        match dispatch {
            Dispatch::Sent(id) => {
                // Before main's answer can be handled: this thread handles
                // it, after this.
                if let Some(codes) = opens
                    && let Err(error) = self.duplex.ask_with(id, codes)
                {
                    crate::log::warn(
                        "swarm stream not registered",
                        serde_json::json!({ "error": error.category() }),
                    );
                }
                Sent::Id(id)
            }
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
        // A stream retires: what is owed for it goes, and its frames are
        // dropped as they come.
        let retire = self.duplex.withdraw(core);
        // Watched from now on (D13); one main has answered needs none,
        // unless its stream is still open.
        let watched = self.requests.cancelled(core, Instant::now());
        if !watched && retire != Retire::SendCancel {
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
            Some(reply) => self.large.push_back((reply, Some(id))),
            None => {}
        }
        #[cfg(feature = "testhooks")]
        {
            let waiting = self.waiting_bytes();
            self.most_waiting = self.most_waiting.max(waiting);
        }
    }

    fn wall_ms(&self) -> u64 {
        self.clock.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        })
    }

    fn replied(&mut self, core: u64, head: Option<Option<u64>>) -> Result<bool, Fault> {
        let replied = match head {
            None => self.duplex.answered(core, false),
            Some(None) => self.duplex.answered(core, true),
            Some(Some(len)) => self.duplex.answered_sized(core, len),
        };
        match replied.map_err(|e| Fault(e.category()))? {
            Replied::Deliver => Ok(true),
            Replied::Retired => Ok(false),
        }
    }

    fn credit(&mut self, core: u64, bytes: usize) {
        if let Err(overcredit) = self.duplex.release(core, bytes) {
            // A machine credited more than its stream holds: the core's own
            // bug, refused without failing the connection.
            crate::log::warn(
                "swarm stream overcredited",
                serde_json::json!({ "credit": overcredit.credit, "held": overcredit.held }),
            );
        }
    }

    fn body(&mut self, body: u64, out: BodyOut) {
        let sender = self.duplex.sender_mut();
        match out {
            BodyOut::Head { bytes } => {
                settled(
                    body,
                    sender.head(body, stream::body_head(body, bytes), true),
                );
            }
            BodyOut::Data(bytes) => {
                if let Some(u) = self.unpushed.get_mut(&body) {
                    u.bytes.extend(bytes);
                    return;
                }
                let pushed = match sender.push(body, &bytes) {
                    Ok(n) => n,
                    Err(error) => return settled(body, Err(error)),
                };
                if pushed < bytes.len() {
                    let mut u = Unpushed::default();
                    u.bytes.extend(&bytes[pushed..]);
                    self.unpushed.insert(body, u);
                }
            }
            BodyOut::End => {
                if let Some(u) = self.unpushed.get_mut(&body) {
                    u.end = true;
                    return;
                }
                settled(body, sender.finish(body));
            }
            // Its abort if the body is open, else its one answer in place of
            // the head.
            BodyOut::Abort(why) => {
                self.unpushed.remove(&body);
                let (abort, error) = stream::body_abort(why);
                let Some(reply) = stream::body_error(body, &error) else {
                    return;
                };
                if let Err(error) = sender.settle(body, reply, &abort) {
                    settled(body, Err(error));
                }
            }
        }
    }

    fn body_refuse(&mut self, body: u64, error: ErrorBody) {
        if let Some(reply) = stream::body_error(body, &error) {
            settled(body, self.duplex.sender_mut().reply(body, reply));
        }
    }

    fn forget(&mut self, key: StreamKey) {
        match key {
            // No frame of the core's request's stream can come: a piece's
            // route goes.
            StreamKey::Piece(_) => self.routes.forget(key),
            // Main sends no credit for the body any more: one that comes is
            // a protocol error (D4).
            StreamKey::Body(_) => self.routes.close(key),
        }
    }

    fn hash(&mut self, id: u64, ask: AskId, job: Job) {
        if let Some(hashing) = self.hashing.as_mut() {
            hashing.submit((id, ask, job));
        }
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
                mailbox.upgrade().is_some_and(|tx| {
                    let ran = Box::new(ran);
                    tx.send((In::Mined { lane, ran }, None)).is_ok()
                })
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

    fn write_feeds(&mut self, text: &str) -> Result<(), fc_json::JsString> {
        self.files_mut()?.write_feeds(text)
    }

    fn save_manifests(
        &mut self,
        save: &fc_swarm_provider::stores::manifests::Save,
    ) -> Result<(), fc_json::JsString> {
        self.files_mut()?.save_manifests(save)
    }

    fn history(
        &mut self,
        statements: &[fc_swarm_provider::stores::history::Statement],
    ) -> Result<(), fc_json::JsString> {
        let now = self.wall_ms();
        self.files_mut()?.history(statements, now)
    }

    fn history_insert(
        &mut self,
        statement: &fc_swarm_provider::stores::history::Statement,
    ) -> Result<i64, fc_json::JsString> {
        let now = self.wall_ms();
        self.files_mut()?.history_insert(statement, now)
    }

    fn vault(&mut self, tag: u64, ask: VaultAsk) {
        // The event loop outlives this thread: it drops the thread first.
        let _ = self.events.send(Event::SwarmVault {
            tag,
            ask: Box::new(ask),
        });
    }

    fn read_manifests(&mut self) -> Option<Vec<u8>> {
        self.files.as_mut()?.read_manifests()
    }

    fn read_manifests_backup(&mut self) -> Option<Vec<u8>> {
        self.files.as_mut()?.read_manifests_backup()
    }

    fn random(&mut self) -> Option<[u8; 24]> {
        let mut bytes = [0u8; 24];
        match getrandom::fill(&mut bytes) {
            Ok(()) => Some(bytes),
            Err(_) => {
                crate::log::error("swarm: the OS randomness failed", serde_json::json!({}));
                None
            }
        }
    }

    fn history_rows(
        &mut self,
        statement: &fc_swarm_provider::stores::history::Statement,
    ) -> Result<Vec<fc_swarm_provider::stores::history::Row>, fc_json::JsString> {
        let now = self.wall_ms();
        self.files_mut()?.history_rows(statement, now)
    }

    fn history_run(
        &mut self,
        statement: &fc_swarm_provider::stores::history::Statement,
    ) -> Result<usize, fc_json::JsString> {
        let now = self.wall_ms();
        self.files_mut()?.history_run(statement, now)
    }

    fn changed(&mut self, key: &str) {
        let mut payload = Zeroizing::new(Vec::new());
        if message::write_event(
            &mut *payload,
            "approval.changed",
            &serde_json::json!({ "store": "swarm", "key": key }),
        )
        .is_err()
        {
            return;
        }
        let Some(frame) = transport::frame(&payload) else {
            return;
        };
        // After every answer queued before it: behind a large answer that
        // waits, else with the control frames, in order.
        if self.large.is_empty() {
            self.small.push_back((frame, None));
        } else {
            self.large.push_back((Reply::Whole(frame), None));
        }
    }
}

/// `swarm-permissions.json`, which a permission manifest's projections
/// write from the swarm thread (D2), under the shared store's lock.
struct GrantsFile {
    path: PathBuf,
}

/// What a caller reads when the Swarm grants' write fails: a fixed text,
/// never the OS's.
const GRANTS_WRITE_FAILED: &str = "The Swarm grants could not be written";

impl GrantsWriter for GrantsFile {
    fn write(
        &mut self,
        grants: &Mutex<SwarmStore>,
        change: &mut dyn FnMut(&mut SwarmStore) -> fc_approval::stores::Applied<()>,
    ) -> GrantWritten {
        use crate::grants::WriteFailure;
        use fc_approval::stores::Effect;
        let mut effect = Effect::Unchanged;
        let written = crate::grants::write_swarm(grants, &self.path, |store| {
            let applied = change(store);
            effect = applied.effect;
            applied
        });
        match written {
            Ok(written) => GrantWritten {
                effect: written.effect,
                error: None,
            },
            // A narrowing stands in memory all the same, as the event
            // loop's does.
            Err(WriteFailure::Io { applied }) => GrantWritten {
                effect: if applied { effect } else { Effect::Unchanged },
                error: Some(fc_json::JsString::from(GRANTS_WRITE_FAILED)),
            },
            Err(WriteFailure::Bounds(_) | WriteFailure::NotMoved) => GrantWritten {
                effect: Effect::Unchanged,
                error: Some(fc_json::JsString::from(GRANTS_WRITE_FAILED)),
            },
        }
    }
}

impl Wire {
    /// Whether an answer of the thread's waits here for room in the
    /// writer's allowances (an event queued behind one waits with it).
    fn answers_waiting(&self) -> bool {
        !self.large.is_empty() || self.small.iter().any(|(_, answer)| answer.is_some())
    }

    /// The bytes of the answers waiting here.
    #[cfg(feature = "testhooks")]
    fn waiting_bytes(&self) -> usize {
        let small: usize = self
            .small
            .iter()
            .filter(|(_, answer)| answer.is_some())
            .map(|(frame, _)| frame.len())
            .sum();
        let large: usize = self.large.iter().map(|(reply, _)| reply.len()).sum();
        small + large
    }

    /// The stores' files: the engine asks for a write only once they have
    /// moved (its door), so their absence is the core's own bug, answered
    /// as a failed write.
    fn files_mut(&mut self) -> Result<&mut Files, fc_json::JsString> {
        self.files.as_mut().ok_or_else(|| {
            crate::log::warn("swarm store write before the move", serde_json::json!({}));
            fc_json::JsString::from(super::stores::HISTORY_FAILED)
        })
    }
}

// The name checks' tags are the thread's own, apart from a page's EIP-1193
// checks (their request's id, below 2^53) and the chain reads' bit.
const _: () = assert!(NAME_TAG & crate::eip1193::SEND_TAG == 0);
const _: () = assert!(NAME_TAG > fc_protocol::message::MAX_ID);

#[cfg(all(test, feature = "testhooks"))]
mod tests {
    use super::Skew;

    /// The test clock moves the monotonic clock only past its furthest
    /// point: the first setting pins it, and a clock set back, then forward
    /// again up to that point, leaves it.
    #[test]
    fn the_test_clock_moves_the_monotonic_clock_past_its_furthest() {
        let mut skew = Skew::default();
        skew.set(1_000_000);
        assert_eq!(skew.by, 0);
        skew.set(1_000_500);
        assert_eq!(skew.by, 500);
        skew.set(940_500);
        skew.set(1_000_500);
        assert_eq!(skew.by, 500, "back, then forward to the furthest");
        skew.set(1_001_500);
        assert_eq!(skew.by, 1_500);
    }
}
