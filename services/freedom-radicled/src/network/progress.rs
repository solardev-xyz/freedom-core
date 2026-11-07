//! A clone's progress (design 0008, "Progress"): libradicle's events, held
//! in a bounded queue per clone, and written to main as `rad.progress`
//! events, `{ id, event }`, where `event` is the progress JSON text
//! libradicle's `json::progress` writes, as the add-on hands it to its
//! callback today.
//!
//! **The callback never blocks** ([`Feed::push`]): it folds the event into
//! its clone's [`Queue`] and returns. The hub's one thread ([`Hub`]) writes
//! the queued events to the connection, oldest first, one at a time; the
//! connection holds at most one event waiting for its writer (the
//! service's connection takes `max_events` 1), so what a clone hasn't had
//! written waits in its own queue, under its bounds.
//!
//! **The queue, per clone** ([`Queue`]):
//! - **`resolving`, `connecting` and `fetching`:** only the latest unwritten
//!   one is kept;
//! - **`peer-failed`:** up to [`FAILURES`] (8) unwritten events are kept as
//!   they are. A failure past them, while 8 wait, starts one summary event,
//!   `{"phase":"peer-failed","summary":{"count":N,"reasons":[…]}}`, and
//!   every failure while the summary waits folds into it: its count grows,
//!   and it keeps the [`REASONS`] (4) most recent reasons. Once written, a
//!   later failure is kept as it is again, while fewer than 8 wait;
//! - **the terminal event** (`done`, `failed` or `cancelled`) has a slot of
//!   its own, is never dropped, and is written after everything queued
//!   before it;
//! - the others are written in the order they were last queued: a phase
//!   event that replaces the latest, and a summary a failure folds into,
//!   take their place as of then.
//!
//! So a clone holds at most 10 unwritten events beside its terminal, and
//! the connection one more, for every clone.
//!
//! **Each event is at most 4 KiB** ([`MAX_ENVELOPE`]), measured as the whole
//! envelope the connection writes for it (`{"type":"event","event":
//! "rad.progress","data":{"id":…,"event":"…"}}`), its escaping included: a
//! NUL in a reason is 6 bytes in the event's JSON and 7 in the envelope's.
//! One that would be larger is cut down before it is queued:
//! 1. a summary drops its oldest reasons, while more than one is left;
//! 2. then the one reason left, or a single event's reason, is cut to the
//!    longest prefix, at a UTF-8 character boundary and ending with `…`,
//!    with which the envelope fits.
//!
//! The phase and the count are never cut. A phase event too large however
//! it is cut (libradicle's addresses and node IDs are far shorter) is
//! dropped. Reasons longer than [`MAX_ENVELOPE`] bytes are truncated to it
//! first, which changes no outcome (no such prefix fits): no step measures
//! more than that of any reason.
//!
//! **Progress stops at the final answer:** an event is queued at the
//! connection only while nothing of its request is
//! ([`Connection::event_for`]). The clone's work waits until its queue is
//! written ([`Feed::flush`]) before it answers, and the connection writes
//! every queued event before any reply, so the terminal event comes before
//! the answer. Once the request is answered otherwise (its deadline, the
//! stop), or the connection has ended, its queue is dropped, and what
//! libradicle emits after that with it.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

use fc_protocol::message::write_event;
use fc_service::conn::{Connection, EventError};
use fc_service::log;
use libradicle::Progress;
use serde::Serialize;
use serde_json::json;

/// The event's name (0008, "Methods").
pub const EVENT: &str = "rad.progress";

/// The most bytes an event's envelope takes, encoded.
pub const MAX_ENVELOPE: usize = 4096;

/// The unwritten peer failures a clone keeps as they are.
pub const FAILURES: usize = 8;

/// The reasons a summary keeps: the most recent.
pub const REASONS: usize = 4;

/// The events the connection holds for its writer: one. What a clone hasn't
/// had written waits in its own queue.
pub const CONNECTION_EVENTS: usize = 1;

/// What a cut reason ends with.
const CUT: char = '…';

/// How long the hub waits before it tries again, while the connection's
/// one event waits for its writer.
const RETRY: Duration = Duration::from_millis(5);

/// `rad.progress`'s data.
#[derive(Serialize)]
struct Data<'a> {
    id: u64,
    event: &'a str,
}

/// The summary event.
#[derive(Serialize)]
struct Summary<'a> {
    phase: &'static str,
    summary: Folded<'a>,
}

#[derive(Serialize)]
struct Folded<'a> {
    count: u64,
    reasons: &'a [String],
}

/// Counts what is written to it.
struct Count(usize);

impl io::Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The bytes the connection writes for `event` about request `id`: the
/// envelope's JSON, as `write_event` encodes it.
pub fn envelope_len(id: u64, event: &str) -> usize {
    let mut count = Count(0);
    // A counter takes every write, and the data always serializes.
    let _ = write_event(&mut count, EVENT, &Data { id, event });
    count.0
}

/// libradicle's JSON text of `progress`, as the add-on hands it on.
pub fn text(progress: &Progress) -> String {
    libradicle::json::to_string(|w| libradicle::json::progress(w, progress))
}

/// A summary's text.
fn summary_text(count: u64, reasons: &[String]) -> String {
    serde_json::to_string(&Summary {
        phase: "peer-failed",
        summary: Folded { count, reasons },
    })
    .unwrap_or_default()
}

/// `text`'s first `max` bytes at most, at a character boundary.
fn prefix(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// An event with `reason`, cut so that its envelope fits: the reason cut
/// to the longest prefix, ending with `…`, with which it does, and the
/// event's text; `None` if none does. `event` makes the text for a reason.
fn cut(id: u64, reason: &str, event: impl Fn(&str) -> String) -> Option<(String, String)> {
    let reason = prefix(reason, MAX_ENVELOPE);
    let ends: Vec<usize> = reason
        .char_indices()
        .map(|(at, _)| at)
        .chain(std::iter::once(reason.len()))
        .collect();
    let with = |n: usize| {
        let mut cut = String::with_capacity(ends[n] + CUT.len_utf8());
        cut.push_str(&reason[..ends[n]]);
        cut.push(CUT);
        let text = event(&cut);
        (envelope_len(id, &text) <= MAX_ENVELOPE).then_some((cut, text))
    };
    // A longer prefix never takes fewer bytes: the largest that fits.
    with(0)?;
    let (mut fits, mut over) = (0, ends.len());
    while over - fits > 1 {
        let mid = fits + (over - fits) / 2;
        if with(mid).is_some() {
            fits = mid;
        } else {
            over = mid;
        }
    }
    with(fits)
}

/// An event with `reason`, whole if its envelope fits, else cut.
fn fitted(id: u64, reason: &str, event: impl Fn(&str) -> String) -> Option<String> {
    if reason.len() <= MAX_ENVELOPE {
        let text = event(reason);
        if envelope_len(id, &text) <= MAX_ENVELOPE {
            return Some(text);
        }
    }
    cut(id, reason, event).map(|(_, text)| text)
}

/// A summary of `count` failures with `reasons`, the most recent last, as
/// it fits: its oldest reasons dropped while more than one is left, then
/// the one left cut. `reasons` keeps what it holds.
fn fit_summary(id: u64, count: u64, reasons: &mut Vec<String>) -> Option<String> {
    loop {
        let text = summary_text(count, reasons);
        if envelope_len(id, &text) <= MAX_ENVELOPE {
            return Some(text);
        }
        if reasons.len() <= 1 {
            break;
        }
        reasons.remove(0);
    }
    let last = reasons.pop()?;
    let (reason, text) = cut(id, &last, |r| summary_text(count, &[r.to_owned()]))?;
    reasons.push(reason);
    Some(text)
}

/// A clone's summary of failures, as queued.
struct Folding {
    /// Its place in the order.
    seq: u64,
    count: u64,
    /// The most recent last, each as kept.
    reasons: Vec<String>,
    /// Its text, fitted.
    text: String,
}

/// Which of a queue's places an event is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    Latest,
    Failure,
    Summary,
    Terminal,
}

/// A clone's unwritten events (see the module's doc), each as the `event`
/// text a `rad.progress` carries, its envelope fitted.
pub struct Queue {
    /// The request's ID, which the envelope holds.
    id: u64,
    /// The next place in the order.
    next: u64,
    latest: Option<(u64, String)>,
    failures: VecDeque<(u64, String)>,
    summary: Option<Folding>,
    terminal: Option<String>,
    /// The request has its answer, or the connection ended: nothing more
    /// is queued.
    closed: bool,
}

impl Queue {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            next: 0,
            latest: None,
            failures: VecDeque::new(),
            summary: None,
            terminal: None,
            closed: false,
        }
    }

    fn seq(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    /// Folds `progress` in (see the module's doc).
    pub fn push(&mut self, progress: Progress) {
        if self.closed {
            return;
        }
        let id = self.id;
        match progress {
            Progress::Resolving { .. }
            | Progress::Connecting { .. }
            | Progress::Fetching { .. } => {
                let event = text(&progress);
                if envelope_len(id, &event) > MAX_ENVELOPE {
                    log::warn(
                        "a progress event too large to send was dropped",
                        json!({ "id": id, "phase": progress.phase() }),
                    );
                    return;
                }
                let seq = self.seq();
                self.latest = Some((seq, event));
            }
            Progress::PeerFailed {
                nid,
                index,
                total,
                reason,
            } => {
                if self.summary.is_some() || self.failures.len() >= FAILURES {
                    return self.fold(&reason);
                }
                let event = fitted(id, &reason, |r| {
                    text(&Progress::PeerFailed {
                        nid: nid.clone(),
                        index,
                        total,
                        reason: r.to_owned(),
                    })
                });
                match event {
                    Some(event) => {
                        let seq = self.seq();
                        self.failures.push_back((seq, event));
                    }
                    None => log::warn(
                        "a progress event too large to send was dropped",
                        json!({ "id": id, "phase": "peer-failed" }),
                    ),
                }
            }
            Progress::Failed { reason } => {
                let event = fitted(id, &reason, |r| {
                    text(&Progress::Failed {
                        reason: r.to_owned(),
                    })
                })
                .unwrap_or_else(|| {
                    text(&Progress::Failed {
                        reason: CUT.to_string(),
                    })
                });
                self.terminal = Some(event);
            }
            Progress::Done | Progress::Cancelled => self.terminal = Some(text(&progress)),
        }
    }

    /// A failure past the kept ones: into the summary waiting, or a new
    /// one.
    fn fold(&mut self, reason: &str) {
        let seq = self.seq();
        let id = self.id;
        let summary = self.summary.get_or_insert_with(|| Folding {
            seq,
            count: 0,
            reasons: Vec::new(),
            text: String::new(),
        });
        summary.seq = seq;
        summary.count += 1;
        summary
            .reasons
            .push(prefix(reason, MAX_ENVELOPE).to_owned());
        if summary.reasons.len() > REASONS {
            summary.reasons.remove(0);
        }
        // The count and the phase alone always fit.
        summary.text = fit_summary(id, summary.count, &mut summary.reasons)
            .unwrap_or_else(|| summary_text(summary.count, &[]));
    }

    /// The event to write next, and its place: the oldest of the latest
    /// phase event, the failures and the summary; once none is left, the
    /// terminal event.
    pub fn front(&self) -> Option<(Slot, &str)> {
        let latest = self.latest.as_ref().map(|(seq, t)| (*seq, Slot::Latest, t));
        let failure = self
            .failures
            .front()
            .map(|(seq, t)| (*seq, Slot::Failure, t));
        let summary = self
            .summary
            .as_ref()
            .map(|s| (s.seq, Slot::Summary, &s.text));
        [latest, failure, summary]
            .into_iter()
            .flatten()
            .min_by_key(|(seq, _, _)| *seq)
            .map(|(_, slot, text)| (slot, text.as_str()))
            .or_else(|| self.terminal.as_deref().map(|t| (Slot::Terminal, t)))
    }

    /// Takes the event in `slot`: written.
    pub fn pop(&mut self, slot: Slot) {
        match slot {
            Slot::Latest => self.latest = None,
            Slot::Failure => {
                self.failures.pop_front();
            }
            Slot::Summary => self.summary = None,
            Slot::Terminal => self.terminal = None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.front().is_none()
    }

    /// Nothing more is queued or written, and what was is dropped.
    pub fn close(&mut self) {
        self.closed = true;
        self.latest = None;
        self.failures.clear();
        self.summary = None;
        self.terminal = None;
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// How many events wait, the terminal included.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        usize::from(self.latest.is_some())
            + self.failures.len()
            + usize::from(self.summary.is_some())
            + usize::from(self.terminal.is_some())
    }

    /// The bytes the waiting events take, as their envelopes would: what
    /// the queue holds, at most 4 KiB an event.
    #[cfg(test)]
    pub fn held(&self) -> usize {
        let id = self.id;
        let len = |text: &String| envelope_len(id, text);
        self.latest.iter().map(|(_, t)| len(t)).sum::<usize>()
            + self.failures.iter().map(|(_, t)| len(t)).sum::<usize>()
            + self.summary.iter().map(|s| len(&s.text)).sum::<usize>()
            + self.terminal.iter().map(len).sum::<usize>()
    }
}

/// Where a feed's events go: the connection, or a test's record.
pub trait Sink: Send + Sync {
    /// Queues `event` about request `id`, as [`Connection::event_for`]
    /// does.
    fn send(&self, id: u64, event: &str) -> Result<(), EventError>;
}

impl Sink for Connection {
    fn send(&self, id: u64, event: &str) -> Result<(), EventError> {
        self.event_for(id, EVENT, &Data { id, event })
    }
}

/// What one write of a feed's did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wrote {
    /// An event went, and more wait.
    More,
    /// Nothing waits now: written, or dropped with its closed queue.
    Done,
    /// The connection's event waits for its writer: the same event again
    /// later.
    Full,
}

struct FeedState {
    queue: Queue,
    /// Whether the hub holds it: it does while it has events, or is being
    /// written.
    listed: bool,
}

/// One clone's progress: its queue, written by the hub, and waited for by
/// its work (see the module's doc).
pub struct Feed {
    id: u64,
    state: Mutex<FeedState>,
    /// Notified as its queue empties or closes.
    drained: Condvar,
    sink: Box<dyn Sink>,
    hub: Weak<HubInner>,
}

impl Feed {
    fn lock(&self) -> MutexGuard<'_, FeedState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// libradicle's callback: folds `progress` into the queue, and has the
    /// hub write it. Never waits but for the queue's lock.
    pub fn push(self: &Arc<Self>, progress: Progress) {
        let list = {
            let mut state = self.lock();
            if state.queue.is_closed() {
                return;
            }
            state.queue.push(progress);
            let list = !state.listed && !state.queue.is_empty();
            if list {
                state.listed = true;
            }
            list
        };
        if list {
            match self.hub.upgrade() {
                Some(hub) => hub.list(self.clone()),
                // No hub: nothing writes it.
                None => self.close(),
            }
        }
    }

    /// Waits until every event queued is written, or the queue is closed:
    /// the request has its answer, or the connection ended. Then nothing
    /// more is queued.
    pub fn flush(&self) {
        let mut state = self.lock();
        while !state.queue.is_closed() && !state.queue.is_empty() {
            state = self.drained.wait(state).unwrap_or_else(|p| p.into_inner());
        }
        state.queue.close();
    }

    /// Drops what waits, and anything later.
    fn close(&self) {
        let mut state = self.lock();
        state.queue.close();
        state.listed = false;
        drop(state);
        self.drained.notify_all();
    }

    /// Writes its next event, if the connection takes it (see [`Wrote`]).
    fn write_one(&self) -> Wrote {
        let mut state = self.lock();
        let Some((slot, event)) = state.queue.front() else {
            state.listed = false;
            drop(state);
            self.drained.notify_all();
            return Wrote::Done;
        };
        match self.sink.send(self.id, event) {
            Ok(()) => {
                state.queue.pop(slot);
                if !state.queue.is_empty() {
                    return Wrote::More;
                }
                state.listed = false;
                drop(state);
                self.drained.notify_all();
                Wrote::Done
            }
            Err(EventError::Full) => Wrote::Full,
            // Answered, or the connection ended: progress stops.
            Err(EventError::Answered | EventError::Closed) => {
                state.queue.close();
                state.listed = false;
                drop(state);
                self.drained.notify_all();
                Wrote::Done
            }
            // Never for a fitted event: it is dropped alone.
            Err(EventError::Encode) => {
                state.queue.pop(slot);
                Wrote::More
            }
        }
    }

    /// How many events wait (for tests).
    #[cfg(test)]
    pub fn waiting(&self) -> (usize, usize) {
        let state = self.lock();
        (state.queue.len(), state.queue.held())
    }
}

struct HubState {
    /// The feeds with events to write, in turn.
    listed: VecDeque<Arc<Feed>>,
    stopped: bool,
}

struct HubInner {
    state: Mutex<HubState>,
    /// Wakes the hub's thread: a feed listed, or the stop.
    wake: Condvar,
}

impl HubInner {
    fn lock(&self) -> MutexGuard<'_, HubState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn list(&self, feed: Arc<Feed>) {
        let mut state = self.lock();
        if state.stopped {
            drop(state);
            return feed.close();
        }
        state.listed.push_back(feed);
        drop(state);
        self.wake.notify_one();
    }
}

/// The thread that writes every clone's progress (see the module's doc).
pub struct Hub {
    inner: Arc<HubInner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Hub {
    /// Starts the hub's thread.
    pub fn start() -> io::Result<Self> {
        let inner = Arc::new(HubInner {
            state: Mutex::new(HubState {
                listed: VecDeque::new(),
                stopped: false,
            }),
            wake: Condvar::new(),
        });
        let thread = {
            let inner = inner.clone();
            std::thread::Builder::new()
                .name("progress".into())
                .spawn(move || run(&inner))?
        };
        Ok(Self {
            inner,
            thread: Mutex::new(Some(thread)),
        })
    }

    /// A feed for request `id`'s progress, written through `sink`.
    pub fn feed(&self, id: u64, sink: impl Sink + 'static) -> Arc<Feed> {
        Arc::new(Feed {
            id,
            state: Mutex::new(FeedState {
                queue: Queue::new(id),
                listed: false,
            }),
            drained: Condvar::new(),
            sink: Box::new(sink),
            hub: Arc::downgrade(&self.inner),
        })
    }

    /// Stops the thread: every feed it holds is closed, and so is any
    /// listed later.
    pub fn stop(&self) {
        self.inner.lock().stopped = true;
        self.inner.wake.notify_all();
        let thread = self.thread.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(thread) = thread {
            let _ = thread.join();
        }
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The hub's thread: writes one event of each listed feed in turn, while
/// the connection takes them; while it doesn't, tries again after
/// [`RETRY`].
fn run(inner: &HubInner) {
    let mut state = inner.lock();
    loop {
        if state.stopped {
            let listed = std::mem::take(&mut state.listed);
            drop(state);
            for feed in listed {
                feed.close();
            }
            return;
        }
        let Some(feed) = state.listed.pop_front() else {
            state = inner.wake.wait(state).unwrap_or_else(|p| p.into_inner());
            continue;
        };
        drop(state);
        let wrote = feed.write_one();
        state = inner.lock();
        match wrote {
            // Its turn again after the others'.
            Wrote::More => state.listed.push_back(feed),
            Wrote::Done => {}
            Wrote::Full => {
                // First again, once the connection has room.
                state.listed.push_front(feed);
                if !state.stopped {
                    state = match inner.wake.wait_timeout(state, RETRY) {
                        Ok((state, _)) => state,
                        Err(poisoned) => poisoned.into_inner().0,
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
