#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;

use super::*;

const NID: &str = "z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";

/// Each character an envelope escapes or widens: a NUL is 6 bytes in the
/// event's JSON and 7 in the envelope's, a backslash and a quote 4 each.
fn mixed(n: usize) -> String {
    "\u{0}\\\"\u{e9}\u{1f680}x".repeat(n)
}

fn connecting(index: usize) -> Progress {
    Progress::Connecting {
        nid: NID.into(),
        addr: format!("seed.example:{index}"),
        index,
        total: 99,
    }
}

fn fetching(index: usize) -> Progress {
    Progress::Fetching {
        nid: NID.into(),
        index,
        total: 99,
    }
}

fn failed(index: usize, reason: &str) -> Progress {
    Progress::PeerFailed {
        nid: NID.into(),
        index,
        total: 99,
        reason: reason.into(),
    }
}

/// Everything the queue holds, written in order.
fn drain(queue: &mut Queue) -> Vec<String> {
    let mut out = Vec::new();
    while let Some((slot, text)) = queue.front() {
        out.push(text.to_owned());
        queue.pop(slot);
    }
    out
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap()
}

fn phase(text: &str) -> String {
    json(text)["phase"].as_str().unwrap().to_owned()
}

/// A cut reason: well formed (it is a `String`), ending with `…`.
fn assert_cut(reason: &str) {
    assert!(reason.ends_with(CUT), "{reason:?}");
}

/// 0008, "Progress": a producer far faster than any writer, with nothing
/// written: the queue never holds more than the latest phase event, 8
/// failures and a summary, and the terminal, each envelope within 4 KiB,
/// and the summary counts every failure past the 8.
#[test]
fn a_fast_producer_is_held_to_ten_events_and_the_terminal() {
    let reason = mixed(400);
    let mut queue = Queue::new(7);
    let mut most = (0, 0);
    for n in 1..=600 {
        queue.push(connecting(n));
        queue.push(fetching(n));
        queue.push(failed(n, &reason));
        if n % 50 == 0 || n < 12 {
            most.0 = most.0.max(queue.len());
            most.1 = most.1.max(queue.held());
        }
    }
    queue.push(Progress::Done);
    assert_eq!(queue.len(), 11);
    assert!(most.0 <= 10, "{most:?}");
    assert!(queue.held() <= 11 * MAX_ENVELOPE, "{}", queue.held());
    let written = drain(&mut queue);
    let phases: Vec<String> = written.iter().map(|t| phase(t)).collect();
    assert_eq!(phases[..8], ["peer-failed"; 8]);
    // The latest phase event came before the last failures folded into the
    // summary, which is then the newest.
    assert_eq!(phases[8..], ["fetching", "peer-failed", "done"]);
    let summary = json(&written[9]);
    assert_eq!(summary["summary"]["count"], 600 - 8);
    for text in &written {
        assert!(envelope_len(7, text) <= MAX_ENVELOPE, "{text}");
    }
    let reasons = summary["summary"]["reasons"].as_array().unwrap();
    assert!(!reasons.is_empty() && reasons.len() <= REASONS);
    for reason in reasons {
        assert_cut(reason.as_str().unwrap());
    }
    for single in &written[..8] {
        let reason = json(single)["reason"].as_str().unwrap().to_owned();
        assert_cut(&reason);
        for part in ["\u{0}", "\\", "\"", "\u{e9}", "\u{1f680}"] {
            assert!(reason.contains(part), "{reason:?}");
        }
    }
}

/// Many short failures: the summary keeps counting, and its reasons are
/// the 4 most recent, whole.
#[test]
fn a_summary_counts_every_failure_and_keeps_the_four_most_recent_reasons() {
    let mut queue = Queue::new(1);
    for n in 1..=20_000 {
        queue.push(failed(n, &format!("r{n}")));
    }
    let written = drain(&mut queue);
    assert_eq!(written.len(), 9);
    let summary = json(&written[8]);
    assert_eq!(summary["summary"]["count"], 20_000 - 8);
    assert_eq!(
        summary["summary"]["reasons"],
        serde_json::json!(["r19997", "r19998", "r19999", "r20000"])
    );
    assert_eq!(
        written[8],
        r#"{"phase":"peer-failed","summary":{"count":19992,"reasons":["r19997","r19998","r19999","r20000"]}}"#
    );
}

/// Only the latest unwritten phase event is kept, in its place as of when
/// it was queued; failures keep theirs; a failure while a summary waits
/// folds into it, which moves it last; once the summary is written, a
/// failure is kept as it is again.
#[test]
fn the_queue_writes_in_the_order_events_were_last_queued() {
    let mut queue = Queue::new(1);
    queue.push(Progress::Resolving { candidates: 3 });
    queue.push(connecting(1));
    queue.push(fetching(1));
    queue.push(failed(1, "one"));
    queue.push(connecting(2));
    let order: Vec<String> = drain(&mut queue).iter().map(|t| phase(t)).collect();
    assert_eq!(order, ["peer-failed", "connecting"]);

    for n in 1..=8 {
        queue.push(failed(n, "kept"));
    }
    queue.push(failed(9, "folded"));
    queue.push(connecting(10));
    queue.push(failed(10, "folded too"));
    // Written: 8 kept failures, then the latest phase event, then the
    // summary its last failure moved after it.
    let (slot, _) = queue.front().unwrap();
    assert_eq!(slot, Slot::Failure);
    queue.pop(slot);
    queue.push(failed(11, "still folded"));
    let written = drain(&mut queue);
    let order: Vec<String> = written.iter().map(|t| phase(t)).collect();
    assert_eq!(order[..7], ["peer-failed"; 7]);
    assert_eq!(order[7..], ["connecting", "peer-failed"]);
    assert_eq!(json(&written[8])["summary"]["count"], 3);
    // Written, the summary leaves room for single failures again.
    queue.push(failed(12, "single"));
    assert_eq!(drain(&mut queue), [text(&failed(12, "single"))]);
}

/// The terminal event is never dropped, and comes after everything queued
/// before it.
#[test]
fn the_terminal_event_comes_last() {
    let mut queue = Queue::new(1);
    queue.push(failed(1, "one"));
    queue.push(Progress::Cancelled);
    queue.push(fetching(2));
    let written = drain(&mut queue);
    let order: Vec<String> = written.iter().map(|t| phase(t)).collect();
    assert_eq!(order, ["peer-failed", "fetching", "cancelled"]);
    queue.push(Progress::Failed {
        reason: mixed(1000),
    });
    let written = drain(&mut queue);
    assert_eq!(written.len(), 1);
    assert_cut(json(&written[0])["reason"].as_str().unwrap());
    assert!(envelope_len(1, &written[0]) <= MAX_ENVELOPE);
}

/// An event that fits is libradicle's own text, as the add-on hands it on.
#[test]
fn an_event_that_fits_is_libradicles_text() {
    let mut queue = Queue::new(3);
    let events = [
        Progress::Resolving { candidates: 2 },
        connecting(1),
        failed(1, "a \"quoted\" \\ reason\u{0}"),
        Progress::Done,
    ];
    let mut written = Vec::new();
    for event in events.clone() {
        queue.push(event);
        written.extend(drain(&mut queue));
    }
    let expected: Vec<String> = events.iter().map(text).collect();
    assert_eq!(written, expected);
    assert_eq!(
        written[1],
        format!(
            r#"{{"nid":"{NID}","addr":"seed.example:1","index":1,"total":99,"phase":"connecting"}}"#
        )
    );
}

/// A reason is cut to the longest prefix, at a character boundary and
/// ending with `…`, with which the whole envelope fits: one character more
/// wouldn't. The request's ID counts, as the envelope holds it.
#[test]
fn a_reason_is_cut_to_the_longest_prefix_that_fits() {
    for (id, reason) in [
        (1, mixed(300)),
        (9_007_199_254_740_991, mixed(300)),
        (1, "\u{1f680}".repeat(2000)),
        (1, "x".repeat(10_000)),
        (12, "\u{0}".repeat(5000)),
    ] {
        let mut queue = Queue::new(id);
        queue.push(failed(1, &reason));
        let written = drain(&mut queue);
        let kept = json(&written[0])["reason"].as_str().unwrap().to_owned();
        assert_cut(&kept);
        let stem = kept.strip_suffix(CUT).unwrap();
        assert!(reason.starts_with(stem));
        assert!(envelope_len(id, &written[0]) <= MAX_ENVELOPE);
        let next = reason[stem.len()..].chars().next().unwrap();
        let longer = text(&failed(1, &format!("{stem}{next}{CUT}")));
        assert!(envelope_len(id, &longer) > MAX_ENVELOPE, "{id}");
    }
    // A wider ID leaves less room.
    let cut = |id| {
        let mut queue = Queue::new(id);
        queue.push(failed(1, &"x".repeat(5000)));
        drain(&mut queue)[0].len()
    };
    assert_eq!(cut(1) - cut(1_000_000), 6);
}

/// A summary too large drops its oldest reasons first, while more than one
/// is left; then the one left is cut.
#[test]
fn a_summary_drops_its_oldest_reasons_then_cuts_the_last() {
    let mut queue = Queue::new(5);
    for n in 1..=8 {
        queue.push(failed(n, "kept"));
    }
    for n in 9..=12 {
        queue.push(failed(n, &format!("{n}:{}", "y".repeat(1500))));
    }
    let written = drain(&mut queue);
    let summary = json(&written[8]);
    assert_eq!(summary["summary"]["count"], 4);
    let reasons: Vec<&str> = summary["summary"]["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    // Two of 1,503 bytes fit with the rest; the two oldest are dropped.
    assert_eq!(reasons.len(), 2);
    assert!(reasons[0].starts_with("11:") && reasons[1].starts_with("12:"));
    assert!(!reasons[1].ends_with(CUT));

    for n in 1..=8 {
        queue.push(failed(n, "kept"));
    }
    queue.push(failed(9, "short"));
    queue.push(failed(10, &mixed(500)));
    let written = drain(&mut queue);
    let summary = json(&written[8]);
    let reasons = summary["summary"]["reasons"].as_array().unwrap();
    assert_eq!(reasons.len(), 1);
    assert_cut(reasons[0].as_str().unwrap());
    assert!(envelope_len(5, &written[8]) <= MAX_ENVELOPE);
    assert_eq!(summary["summary"]["count"], 2);
}

/// A closed queue drops what it held, and anything later.
#[test]
fn a_closed_queue_holds_nothing() {
    let mut queue = Queue::new(1);
    queue.push(failed(1, "one"));
    queue.push(Progress::Done);
    queue.close();
    queue.push(fetching(2));
    assert!(queue.is_empty());
    assert_eq!(queue.len(), 0);
}

/// What a test's sink does with each event.
const OPEN: u8 = 0;
const FULL: u8 = 1;
const ANSWERED: u8 = 2;
const CLOSED: u8 = 3;

/// A connection's events as a test sees them: each envelope, exactly as
/// encoded, in order.
#[derive(Clone, Default)]
struct Record {
    mode: Arc<AtomicU8>,
    sent: Arc<Mutex<Vec<(u64, String)>>>,
}

impl Record {
    fn set(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }

    fn sent(&self) -> Vec<String> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|(_, e)| e.clone())
            .collect()
    }
}

impl Sink for Record {
    fn send(&self, id: u64, event: &str) -> Result<(), EventError> {
        match self.mode.load(Ordering::SeqCst) {
            OPEN => {
                let mut envelope = Vec::new();
                write_event(&mut envelope, EVENT, &Data { id, event }).unwrap();
                let envelope = String::from_utf8(envelope).unwrap();
                assert_eq!(envelope.len(), envelope_len(id, event));
                self.sent.lock().unwrap().push((id, envelope));
                Ok(())
            }
            FULL => Err(EventError::Full),
            ANSWERED => Err(EventError::Answered),
            _ => Err(EventError::Closed),
        }
    }
}

fn eventually(done: impl Fn() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(10);
    while !done() {
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    true
}

/// A paused writer: the feed holds what the queue's bounds allow, and
/// nothing more; once the writer goes on, the hub writes it all, in
/// order, the terminal last, and the clone's flush returns.
#[test]
fn a_paused_writer_holds_a_feed_to_its_bounds_then_it_is_written_in_order() {
    let hub = Hub::start().unwrap();
    let record = Record::default();
    record.set(FULL);
    let feed = hub.feed(4, record.clone());
    let reason = mixed(400);
    for n in 1..=300 {
        feed.push(connecting(n));
        feed.push(fetching(n));
        feed.push(failed(n, &reason));
        let (len, held) = feed.waiting();
        assert!(len <= 10 && held <= 10 * MAX_ENVELOPE, "{len} {held}");
    }
    feed.push(Progress::Done);
    let (len, held) = feed.waiting();
    assert!(len == 11 && held <= 11 * MAX_ENVELOPE, "{len} {held}");
    record.set(OPEN);
    feed.flush();
    let sent = record.sent();
    assert_eq!(sent.len(), 11);
    let events: Vec<String> = sent
        .iter()
        .map(|e| json(e)["data"]["event"].as_str().unwrap().to_owned())
        .collect();
    let phases: Vec<String> = events.iter().map(|t| phase(t)).collect();
    assert_eq!(phases.last().unwrap(), "done");
    assert_eq!(json(&sent[0])["data"]["id"], 4);
    assert!(sent.iter().all(|e| e.len() <= MAX_ENVELOPE));
    // Nothing after the flush.
    feed.push(fetching(400));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(record.sent().len(), 11);
}

/// Once the request has its answer, or the connection ends, progress
/// stops: the feed drops what it held and anything later, and the clone's
/// flush returns.
#[test]
fn a_feed_stops_once_its_request_is_answered_or_the_connection_ends() {
    let hub = Hub::start().unwrap();
    for mode in [ANSWERED, CLOSED] {
        let record = Record::default();
        record.set(FULL);
        let feed = hub.feed(1, record.clone());
        feed.push(failed(1, "one"));
        feed.push(Progress::Done);
        record.set(mode);
        assert!(eventually(|| feed.waiting().0 == 0));
        feed.flush();
        feed.push(fetching(2));
        assert_eq!(feed.waiting().0, 0);
        assert!(record.sent().is_empty());
    }
}

/// The hub's stop closes every feed it holds, and any listed later: no
/// flush waits on it.
#[test]
fn the_hubs_stop_closes_its_feeds() {
    let hub = Hub::start().unwrap();
    let record = Record::default();
    record.set(FULL);
    let held = hub.feed(1, record.clone());
    held.push(Progress::Done);
    hub.stop();
    held.flush();
    let later = hub.feed(2, record.clone());
    later.push(Progress::Done);
    later.flush();
    assert_eq!(later.waiting().0, 0);
    assert!(record.sent().is_empty());
}

/// Two clones share the writer: each gets its turn, each its own order.
#[test]
fn feeds_take_turns() {
    let hub = Hub::start().unwrap();
    let record = Record::default();
    record.set(FULL);
    let (a, b) = (hub.feed(1, record.clone()), hub.feed(2, record.clone()));
    for feed in [&a, &b] {
        feed.push(failed(1, "one"));
        feed.push(failed(2, "two"));
        feed.push(Progress::Done);
    }
    record.set(OPEN);
    a.flush();
    b.flush();
    let sent = record.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 6);
    for id in [1, 2] {
        let phases: Vec<String> = sent
            .iter()
            .filter(|(of, _)| *of == id)
            .map(|(_, e)| phase(json(e)["data"]["event"].as_str().unwrap()))
            .collect();
        assert_eq!(phases, ["peer-failed", "peer-failed", "done"]);
    }
    // Interleaved: neither waited for the other's last.
    let ids: Vec<u64> = sent.iter().map(|(id, _)| *id).collect();
    assert_ne!(ids, [1, 1, 1, 2, 2, 2]);
}
