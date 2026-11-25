//! The mining lane through the binary (design 0015, "Messaging and GSOC
//! mining" > "Mining, in the core", SWM-4's tests; SWM-4 PR 8): the real
//! core, the test as main answering the swarm thread's requests, and the
//! lane's test hooks: a delay before each batch, a block file a batch
//! consumes (a stuck batch), and the test clock, which drives the swarm
//! thread's monotonic clock as well as `Date.now()` (D14), so a job's 15 s
//! and the watchdog's second pass when the test moves the clock on. One
//! smoke test watches a stuck batch on the real clock, and `vault.lock`'s
//! gate is real time.
//!
//! Each search here is a GSOC subscription by topic, which asks main
//! nothing between its readiness and its search, so the order in which the
//! requests' first `approval.recheck` reaches main is the order in which
//! the lane ended their searches. The topics' signers, bee-js's, lie at
//! known candidates: `chat` at index 143 and `room` at 6,477 (the `gsoc`
//! vectors), `fast-<n>` within the first batch of 256, `long-608` at
//! 30,612, and every `long-<n>` of [`LONG`] past 10,000 (found with
//! `fc_swarm::gsoc::mine`; the tests check the ones whose signer they
//! read).
//!
//! - a forced-slow job ends `gsoc_mining_timeout` within one batch of its
//!   15 s on the test clock, and the next job succeeds; then recovery: a
//!   cancel, a stuck batch at its second on the test clock (the next job on
//!   a fresh lane gives bee-js's signer, the stuck thread's late answer
//!   dropped), and a second stuck batch turning mining off; and a stuck
//!   batch watched on the real clock;
//! - a cancel: a lone waiter's stops its job within one batch and the next
//!   starts; a join's leaves the job running for the other waiter;
//! - saturation: a site's 17th waiting job and the 257th in all are
//!   `busy`, and nothing is mined for them; another site is admitted
//!   within its own 16 while there is room;
//! - fairness: gsoc-miner.test.js's order cases, round-robin and a join
//!   taking a turn of its own;
//! - `vault.lock` answered within 0009's gate while the lane mines.

// The tests print what they measure.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

mod common;
mod swarm_world;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fc_swarm_provider::machine::Outcome;
use fc_swarm_provider::value::Value as Typed;
use serde_json::{Value, json};
use swarm_world::{Main, SUBSCRIPTION_ID, page};

const A: &str = "https://a.example";
const B: &str = "https://b.example";
const C: &str = "https://c.example";

/// The test clock's `Date.now()`, which the new-topic budget reads.
const CLOCK: u64 = 1_767_225_600_123;

/// A job's time from its dispatch (`MINE_TIMEOUT_MS`).
const JOB: Duration = Duration::from_millis(fc_swarm_provider::mining::JOB_MS);

/// How far the test clock moves at a time while a batch is out: under the
/// watchdog's second.
const STEP: Duration = Duration::from_millis(500);

/// 64 topics `long-<n>` whose signer lies past candidate 10,000 (some 50
/// batches each), with the candidate it is.
#[rustfmt::skip]
const LONG: [(u32, u32); 64] = [
    (4, 11008), (16, 19363), (26, 15216), (39, 21979), (42, 11478), (52, 10819), (58, 10051),
    (84, 10516), (86, 10361), (95, 12980), (98, 10011), (115, 14916), (122, 11293), (139, 20376),
    (180, 12750), (199, 10095), (247, 13549), (260, 15334), (261, 12887), (267, 22165),
    (280, 18024), (286, 14788), (288, 11972), (335, 11101), (338, 10171), (354, 15188),
    (366, 16365), (380, 16677), (382, 11529), (383, 12491), (449, 10565), (453, 10197),
    (468, 17277), (484, 12378), (485, 15522), (489, 16425), (496, 13261), (514, 12590),
    (515, 10464), (518, 18361), (521, 10638), (529, 14457), (535, 18421), (537, 16237),
    (556, 11733), (578, 21476), (608, 30612), (609, 10183), (611, 11595), (613, 10281),
    (618, 13665), (622, 22292), (624, 13129), (633, 12692), (639, 14624), (658, 10746),
    (685, 10157), (694, 23075), (695, 11440), (703, 10118), (709, 17376), (715, 15302),
    (725, 11066), (738, 10895),
];

/// `swarm.request`'s params: a GSOC subscription by `topic`.
fn subscribe(topic: &str) -> String {
    let topic = serde_json::to_string(topic).unwrap();
    format!(
        r#"{{"method":{{"string":"swarm_subscribe"}},"params":{{"object":[["kind",{{"string":"gsoc"}}],["topic",{{"string":{topic}}}]]}}}}"#
    )
}

/// The Swarm grants: each site connected, with the messaging grant.
fn grants(sites: &[&str]) -> Value {
    let mut grants = serde_json::Map::new();
    for site in sites {
        grants.insert(
            (*site).to_owned(),
            json!({
                "origin": site, "connectedAt": 1, "lastUsed": 1,
                "autoApprove": { "publish": false, "feeds": false, "signing": false, "messaging": false },
                "messaging": { "grantedAt": 1 },
            }),
        );
    }
    Value::Object(grants)
}

/// bee-js's signer's SOC address for `topic`, as the subscription's key.
fn address(topic: &str) -> String {
    let job = fc_swarm_provider::methods::messaging::gsoc_job(topic);
    let signer = fc_swarm::gsoc::mine(&job.target, &job.identifier, job.proximity).unwrap();
    signer
        .soc_address()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The candidate bee-js's signer for `topic` is.
fn index(topic: &str) -> u32 {
    let job = fc_swarm_provider::methods::messaging::gsoc_job(topic);
    fc_swarm::gsoc::mine(&job.target, &job.identifier, job.proximity)
        .unwrap()
        .index()
}

/// What a request's answer says: its key (a subscription), or its error's
/// reason and message, or `cancelled`.
#[derive(Debug, Clone, PartialEq)]
enum Got {
    Key(String),
    Error(String, String),
    Cancelled,
}

fn got(message: &Value) -> Got {
    let member = |value: &Typed, name: &str| -> Option<String> {
        match value.get(name) {
            Typed::String(s) => Some(s.as_str().to_owned()),
            _ => None,
        }
    };
    match swarm_world::outcome(message) {
        Outcome::Result(value) => Got::Key(member(&value, "key").unwrap()),
        Outcome::Error(failure) => Got::Error(
            failure
                .data
                .as_ref()
                .and_then(|data| member(data, "reason"))
                .unwrap_or_default(),
            failure.message.as_str().to_owned(),
        ),
        Outcome::Cancelled => Got::Cancelled,
        other => panic!("{other:?}"),
    }
}

/// The test as main: it answers the swarm thread's requests as they come,
/// and records what the lane did.
struct Lane {
    main: Main,
    block: PathBuf,
    _dir: tempfile::TempDir,
    /// Requests whose search ended, in order: their first recheck.
    mined: Vec<u64>,
    /// When each request's readiness was answered: its search's submission.
    ready_at: BTreeMap<u64, Instant>,
    /// When each request's search ended.
    mined_at: BTreeMap<u64, Instant>,
    /// The page requests' answers, with when each was read.
    answers: BTreeMap<u64, (Value, Instant)>,
    /// The page requests sent.
    requests: BTreeSet<u64>,
    /// Main's other requests' answers, with when each was read.
    responses: BTreeMap<u64, (Value, Instant)>,
    /// The test clock, as last set.
    clock: u64,
}

impl Lane {
    /// A core with `env`'s hooks and the block file's path, its grants
    /// `sites`', its clock [`CLOCK`].
    fn new(env: &[(&str, &str)], sites: &[&str]) -> Lane {
        let dir = tempfile::tempdir().unwrap();
        let block = dir.path().join("block");
        let block_var = block.to_str().unwrap().to_owned();
        let mut env = env.to_vec();
        env.push(("FREEDOM_CORED_TEST_SWARM_MINE_BLOCK", &block_var));
        let main = swarm_world::main_with(&["swarm"], &env);
        let mut lane = Lane {
            main,
            block,
            _dir: dir,
            mined: Vec::new(),
            ready_at: BTreeMap::new(),
            mined_at: BTreeMap::new(),
            answers: BTreeMap::new(),
            requests: BTreeSet::new(),
            responses: BTreeMap::new(),
            clock: CLOCK,
        };
        lane.world(json!({ "reset": true, "clock": CLOCK, "grants": grants(sites) }));
        lane
    }

    /// A GSOC subscription by `topic` from `site`, its readiness answered:
    /// its search has been submitted once this returns.
    fn send(&mut self, site: &str, topic: &str) -> u64 {
        let id = self.main.request(&page(site), &subscribe(topic));
        self.requests.insert(id);
        self.until(Duration::from_secs(10), "its readiness", |lane| {
            lane.ready_at.contains_key(&id) || lane.answers.contains_key(&id)
        });
        id
    }

    /// Main's request `method` of the core, its ID.
    fn ask(&mut self, method: &str, params: Value, caller: &str) -> u64 {
        let id = self.main.id();
        self.main.core.send(&json!({
            "type": "request", "id": id, "method": method, "params": params,
            "context": { "caller": caller },
        }));
        id
    }

    /// `test.swarm_world`, answered while the thread's requests are.
    fn world(&mut self, params: Value) -> Value {
        let id = self.ask("test.swarm_world", params, "shell");
        self.until(Duration::from_secs(10), "test.swarm_world", |lane| {
            lane.responses.contains_key(&id)
        });
        let (answer, _) = self.responses.remove(&id).unwrap();
        assert!(answer["result"].is_object(), "{answer}");
        answer["result"].clone()
    }

    /// The lane's state: `{ waiting, running, off, lane, batches }`.
    fn state(&mut self) -> Value {
        self.world(json!({ "mining": true }))["mining"].clone()
    }

    /// Moves the test clock on by `by`: `Date.now()` and the swarm thread's
    /// monotonic clock, what falls due handled before the hook answers.
    fn advance(&mut self, by: Duration) {
        self.clock += u64::try_from(by.as_millis()).unwrap();
        self.world(json!({ "clock": self.clock }));
    }

    /// The batches the lane has handed out.
    fn batches(&mut self) -> u64 {
        self.state()["batches"].as_u64().unwrap()
    }

    /// Moves the test clock on by [`STEP`] each time the lane hands out a
    /// new batch, until request `id` is answered: how far it moved. A step
    /// comes only after a new batch, so no batch is out for a second on the
    /// core's clock; each new batch of the job went out after every step so
    /// far, so before its 15 s on that clock.
    fn advance_until_answered(&mut self, id: u64) -> Duration {
        let mut advanced = Duration::ZERO;
        let mut seen = self.batches();
        loop {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if self.answers.contains_key(&id) {
                    return advanced;
                }
                let batches = self.batches();
                // The answer is written before what follows it.
                if self.answers.contains_key(&id) {
                    return advanced;
                }
                if batches > seen {
                    seen = batches;
                    break;
                }
                assert!(Instant::now() < deadline, "no new batch");
                self.step(Duration::from_millis(5));
            }
            assert!(advanced < JOB, "a batch past the job's 15 s: {advanced:?}");
            self.advance(STEP);
            advanced += STEP;
        }
    }

    fn cancel(&mut self, id: u64) {
        self.main.core.send(&json!({ "type": "cancel", "id": id }));
    }

    /// Handles what the core sends until `done`, for at most `within`.
    fn until(&mut self, within: Duration, what: &str, done: impl Fn(&Lane) -> bool) {
        let deadline = Instant::now() + within;
        while !done(self) {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "not within {within:?}: {what}");
            self.step(left.min(Duration::from_millis(100)));
        }
    }

    /// Request `id`'s answer, waited for at most `within`.
    fn answer(&mut self, id: u64, within: Duration) -> Got {
        self.until(within, "the answer", |lane| lane.answers.contains_key(&id));
        got(&self.answers[&id].0)
    }

    /// When request `id`'s answer was read.
    fn answered_at(&self, id: u64) -> Instant {
        self.answers[&id].1
    }

    /// Handles one message, if one comes within `within`.
    fn step(&mut self, within: Duration) {
        let Ok(Some(message)) = self.main.core.recv_or_closed(within) else {
            return;
        };
        let arrived = self.main.core.arrived();
        match message["type"].as_str().unwrap() {
            "request" => self.serve(&message),
            "response" => {
                let id = message["id"].as_u64().unwrap();
                if self.requests.contains(&id) {
                    let first = self.answers.insert(id, (message, arrived));
                    assert!(first.is_none(), "one answer");
                } else {
                    self.responses.insert(id, (message, arrived));
                }
            }
            // The core cancels its own requests only at a request's end.
            "cancel" | "event" => {}
            other => panic!("{other}: {message}"),
        }
    }

    /// Main's answer to one of the swarm thread's requests.
    fn serve(&mut self, message: &Value) {
        let id = message["id"].as_u64().unwrap();
        let params = &message["params"];
        let answer = match message["method"].as_str().unwrap() {
            "shell.swarm_ready" => {
                assert_eq!(params["check"], "subscribe");
                self.ready_at
                    .insert(params["for"].as_u64().unwrap(), Instant::now());
                json!({ "ok": true })
            }
            "approval.recheck" => {
                let request = params["request"].as_u64().unwrap();
                if !self.mined.contains(&request) {
                    self.mined.push(request);
                    self.mined_at.insert(request, Instant::now());
                }
                json!({ "live": true, "agent": false })
            }
            "shell.swarm_subscribe" => json!({ "id": SUBSCRIPTION_ID }),
            "shell.swarm_unsubscribe" => json!({}),
            "shell.prefetch" => return,
            other => panic!("the thread asked {other}: {message}"),
        };
        self.main.answer(id, answer);
    }

    /// The thread holds nothing: no charge and no request.
    fn settled(&mut self) {
        for _ in 0..400 {
            let held = self.world(json!({}));
            if held == json!({ "memory": 0, "requests": 0 }) {
                return;
            }
            self.step(Duration::from_millis(5));
        }
        panic!("the thread still holds {}", self.world(json!({})));
    }

    /// Waits until the lane thread has blocked a batch on the block file.
    fn blocked(&mut self) {
        let held = self.block.with_extension("held");
        self.until(Duration::from_secs(10), "a blocked batch", |_| {
            held.exists()
        });
        std::fs::remove_file(&held).unwrap();
    }
}

fn timed_out() -> Got {
    Got::Error(
        "gsoc_mining_timeout".into(),
        "GSOC mining failed: timed out after 15000 ms".into(),
    )
}

fn stuck() -> Got {
    Got::Error(
        "gsoc_mining_failed".into(),
        "GSOC mining failed: mining lane stuck".into(),
    )
}

fn off() -> Got {
    Got::Error(
        "gsoc_mining_failed".into(),
        "GSOC mining failed: mining is off until the core restarts".into(),
    )
}

fn busy() -> Got {
    Got::Error("busy".into(), "busy".into())
}

/// A forced-slow job (100 ms before each batch, so `long-608`'s 120
/// batches would take 12 s, and the test clock moved on half a second at
/// each batch) ends `gsoc_mining_timeout` within one batch of its 15 s on
/// the core's clock, and the next job then runs and gives bee-js's signer.
/// Then recovery, each followed by a job that runs and gives bee-js's
/// signer: a lone waiter's cancel; a stuck batch, whose job ends
/// `gsoc_mining_failed` as the test clock passes its second, and whose
/// late answer, once the test lets the stuck thread go, is dropped; and a
/// second stuck batch, which turns mining off for the job waiting and for
/// every later one.
#[test]
fn a_slow_job_times_out_and_the_lane_recovers() {
    let mut lane = Lane::new(
        &[("FREEDOM_CORED_TEST_SWARM_MINE_DELAY_MS", "100")],
        &[A, B],
    );
    assert!(index("long-608") > 120 * 256 - 256, "120 batches");

    // The slow job, and one behind it.
    let slow = lane.send(A, "long-608");
    let next = lane.send(B, "chat");
    let advanced = lane.advance_until_answered(slow);
    assert_eq!(got(&lane.answers[&slow].0), timed_out());
    // Its clock is the real time since its dispatch and the test clock's
    // steps: at least 15 s when it ended.
    let real = lane.answered_at(slow) - lane.ready_at[&slow];
    eprintln!("[mining] the slow job ended after {advanced:?} on the test clock and {real:?}");
    assert!(advanced + real >= JOB, "{advanced:?} + {real:?}");
    assert!(real < Duration::from_secs(12), "not its own end: {real:?}");
    assert_eq!(
        lane.answer(next, Duration::from_secs(10)),
        Got::Key(address("chat"))
    );
    assert_eq!(index("chat"), 143);

    // A cancel: the job stops within a batch, and the next runs.
    let cancelled = lane.send(A, "long-608");
    let after = lane.send(B, "fast-29");
    let at = Instant::now();
    lane.cancel(cancelled);
    assert_eq!(
        lane.answer(cancelled, Duration::from_secs(10)),
        Got::Cancelled
    );
    assert_eq!(
        lane.answer(after, Duration::from_secs(10)),
        Got::Key(address("fast-29"))
    );
    let stopped = lane.mined_at[&after] - at;
    eprintln!("[mining] the next job's search ended {stopped:?} after the cancel");
    assert!(stopped < Duration::from_secs(5), "{stopped:?}");

    // A stuck batch: under its second on the core's clock it is out; past
    // it, its job fails as the clock moves, and the next runs on a fresh
    // lane.
    std::fs::write(&lane.block, b"").unwrap();
    let blocked = lane.send(A, "room");
    let behind = lane.send(B, "fast-31");
    lane.blocked();
    lane.advance(Duration::from_millis(400));
    assert!(!lane.answers.contains_key(&blocked), "under its second");
    assert_eq!(lane.state()["running"], true);
    lane.advance(Duration::from_millis(600));
    assert!(lane.answers.contains_key(&blocked), "at its second");
    assert_eq!(got(&lane.answers[&blocked].0), stuck());
    assert_eq!(
        lane.answer(behind, Duration::from_secs(10)),
        Got::Key(address("fast-31"))
    );
    assert_eq!(lane.state()["lane"], 1, "a fresh lane thread");
    // The stuck thread goes on: its answer is dropped, and the lane works.
    std::fs::write(lane.block.with_extension("release"), b"").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let fine = lane.send(A, "fast-46");
    assert_eq!(
        lane.answer(fine, Duration::from_secs(10)),
        Got::Key(address("fast-46"))
    );
    std::fs::remove_file(lane.block.with_extension("release")).unwrap();

    // The second stuck batch turns mining off, until the core restarts.
    std::fs::write(&lane.block, b"").unwrap();
    let blocked = lane.send(A, "fast-69");
    let waiting = lane.send(B, "fast-81");
    lane.blocked();
    lane.advance(Duration::from_millis(400));
    lane.advance(Duration::from_millis(600));
    assert_eq!(got(&lane.answers[&blocked].0), stuck());
    assert_eq!(got(&lane.answers[&waiting].0), off());
    let state = lane.state();
    assert_eq!(
        (&state["off"], &state["waiting"]),
        (&json!(true), &json!(0))
    );
    for topic in ["fast-85", "chat"] {
        let later = lane.send(A, topic);
        assert_eq!(
            lane.answer(later, Duration::from_secs(10)),
            off(),
            "{topic}"
        );
    }
    // Nothing is held, and a reset doesn't turn it on.
    lane.world(json!({ "reset": true }));
    let later = lane.send(B, "fast-102");
    assert_eq!(lane.answer(later, Duration::from_secs(10)), off());
    lane.settled();
    std::fs::write(lane.block.with_extension("release"), b"").unwrap();
}

/// The smoke test on the real clock: with the test clock still, a stuck
/// batch's job ends `gsoc_mining_failed` once its second has passed in real
/// time, and the next job runs on a fresh lane thread and gives bee-js's
/// signer.
#[test]
fn a_stuck_batch_is_watched_in_real_time() {
    let mut lane = Lane::new(&[], &[A, B]);
    std::fs::write(&lane.block, b"").unwrap();
    let blocked = lane.send(A, "room");
    let behind = lane.send(B, "chat");
    lane.blocked();
    assert_eq!(lane.answer(blocked, Duration::from_secs(10)), stuck());
    let took = lane.answered_at(blocked) - lane.ready_at[&blocked];
    eprintln!("[mining] on the real clock, the stuck batch's job ended after {took:?}");
    assert!(took >= Duration::from_secs(1), "{took:?}");
    assert_eq!(
        lane.answer(behind, Duration::from_secs(10)),
        Got::Key(address("chat"))
    );
    assert_eq!(lane.state()["lane"], 1);
    lane.settled();
    std::fs::write(lane.block.with_extension("release"), b"").unwrap();
}

/// A cancel ends only its own wait (100 ms before each batch). A lone
/// waiter's stops its job within one batch, and the next job starts; with
/// two waiters (a join), one cancel leaves the job running for the other,
/// which gets bee-js's signer.
#[test]
fn a_cancel_ends_only_its_own_wait() {
    const DELAY: Duration = Duration::from_millis(100);
    let mut lane = Lane::new(
        &[("FREEDOM_CORED_TEST_SWARM_MINE_DELAY_MS", "100")],
        &[A, B, C],
    );
    // A lone waiter: long-608 would take 12 s.
    let lone = lane.send(A, "long-608");
    let next = lane.send(B, "fast-29");
    std::thread::sleep(3 * DELAY);
    let state = lane.state();
    assert_eq!(
        (&state["running"], &state["waiting"]),
        (&json!(true), &json!(1))
    );
    let at = Instant::now();
    lane.cancel(lone);
    assert_eq!(lane.answer(lone, Duration::from_secs(10)), Got::Cancelled);
    assert_eq!(
        lane.answer(next, Duration::from_secs(10)),
        Got::Key(address("fast-29"))
    );
    let stopped = lane.mined_at[&next] - at;
    eprintln!("[mining] after a lone waiter's cancel, the next search ended in {stopped:?}");
    // Two batches, at most; long-608 had some 11 s to run.
    assert!(stopped < Duration::from_secs(5), "{stopped:?}");
    assert_eq!(lane.mined, [next]);

    // A join: room's 26 batches run on for B, and C's job waits behind.
    let joined = lane.send(A, "room");
    let other = lane.send(B, "room");
    let behind = lane.send(C, "fast-31");
    assert_eq!(
        lane.state()["waiting"],
        1,
        "a join of a running job queues nothing"
    );
    std::thread::sleep(2 * DELAY);
    lane.cancel(joined);
    assert_eq!(lane.answer(joined, Duration::from_secs(10)), Got::Cancelled);
    assert_eq!(
        lane.answer(other, Duration::from_secs(10)),
        Got::Key(address("room"))
    );
    assert_eq!(
        lane.answer(behind, Duration::from_secs(10)),
        Got::Key(address("fast-31"))
    );
    assert_eq!(lane.mined, [next, other, behind]);
    assert_eq!(index("room"), 6477);
    lane.settled();
}

/// Saturation (300 ms before each batch, so one job runs throughout, and
/// 300 requests may run): one site's 17th waiting job is `busy`, a join
/// from a site whose queue is full is `busy`, another site is still
/// admitted within its own 16, and the 257th waiting job in all is
/// `busy`; nothing is mined for them. The site's first 16 come a minute
/// earlier on the test clock (`Date.now()` set back, which leaves the
/// monotonic clock and the running job be), so its 17th, back at the
/// clock's furthest point, is past its new-topic budget, which a busy
/// refusal still spends.
#[test]
fn a_full_queue_is_busy() {
    let sites: Vec<String> = (0..14).map(|n| format!("https://s{n}.example")).collect();
    let (r, z) = ("https://r.example", "https://z.example");
    let mut all: Vec<&str> = vec![r, A, B, z];
    all.extend(sites.iter().map(String::as_str));
    let mut lane = Lane::new(
        &[
            ("FREEDOM_CORED_TEST_SWARM_MINE_DELAY_MS", "300"),
            ("FREEDOM_CORED_TEST_SWARM_RUNNING", "300"),
        ],
        &all,
    );
    let start = Instant::now();
    let running = lane.send(r, "long-608");
    let mut waiting = Vec::new();
    lane.world(json!({ "clock": CLOCK - 60_000 }));
    for n in 0..16 {
        waiting.push(lane.send(A, &format!("sat-a-{n}")));
    }
    assert_eq!(lane.state()["waiting"], 16);
    // A's 17th, a minute on: its budget has room, its queue none.
    lane.world(json!({ "clock": CLOCK }));
    let state = lane.state();
    assert_eq!(
        (&state["running"], &state["lane"]),
        (&json!(true), &json!(0)),
        "the running job runs on"
    );
    let full = lane.send(A, "sat-a-16");
    assert_eq!(lane.answer(full, Duration::from_secs(10)), busy());
    // B's own job is admitted; A's join of it is busy.
    waiting.push(lane.send(B, "sat-b-0"));
    let join = lane.send(A, "sat-b-0");
    assert_eq!(lane.answer(join, Duration::from_secs(10)), busy());
    for n in 1..16 {
        waiting.push(lane.send(B, &format!("sat-b-{n}")));
    }
    for site in &sites {
        for n in 0..16 {
            waiting.push(lane.send(site, &format!("sat-{site}-{n}")));
        }
    }
    let state = lane.state();
    assert_eq!(
        (&state["waiting"], &state["running"]),
        (&json!(256), &json!(true))
    );
    // The 257th.
    let late = lane.send(z, "sat-z-0");
    assert_eq!(lane.answer(late, Duration::from_secs(10)), busy());
    assert_eq!(lane.state()["waiting"], 256, "nothing mined for them");
    assert!(lane.mined.is_empty());
    assert!(start.elapsed() < JOB, "all within the running job's time");
    eprintln!(
        "[mining] 256 jobs waiting and three busy in {:?}",
        start.elapsed()
    );
    // Each waiting job goes with its request, unmined; then the running.
    for &id in waiting.iter().rev().chain([&running]) {
        lane.cancel(id);
    }
    for &id in waiting.iter().chain([&running]) {
        assert_eq!(lane.answer(id, Duration::from_secs(10)), Got::Cancelled);
    }
    assert!(
        lane.mined.is_empty(),
        "nothing was mined but the running job"
    );
    lane.settled();
    // The running job stops at its batch's answer, and none follows it.
    let at = Instant::now();
    let idle =
        |state: &Value| state["waiting"] == 0 && state["running"] == false && state["lane"] == 0;
    loop {
        let state = lane.state();
        if idle(&state) {
            break;
        }
        assert!(at.elapsed() < Duration::from_secs(2), "{state}");
        lane.step(Duration::from_millis(20));
    }
    assert!(lane.mined.is_empty());
}

/// gsoc-miner.test.js's order cases (50 ms before each batch, so `room`,
/// the first job, runs 1.3 s while the others queue): "queued jobs are
/// served round-robin across owners, not FIFO", and "a joined job runs at
/// the joiner's turn, once, and leaves both queues".
#[test]
fn turns_go_round_robin_and_a_join_takes_a_turn_of_its_own() {
    let mut lane = Lane::new(
        &[("FREEDOM_CORED_TEST_SWARM_MINE_DELAY_MS", "50")],
        &[A, B, C],
    );
    // a1 runs; A queues two more, B two, and C, the reference's owner-less
    // caller, one.
    let a1 = lane.send(A, "room");
    let a2 = lane.send(A, "fast-29");
    let a3 = lane.send(A, "fast-31");
    let b1 = lane.send(B, "fast-46");
    let b2 = lane.send(B, "fast-69");
    let n1 = lane.send(C, "fast-81");
    let state = lane.state();
    assert_eq!(
        (&state["running"], &state["waiting"]),
        (&json!(true), &json!(5))
    );
    assert!(lane.mined.is_empty(), "a1 still runs");
    for id in [a1, a2, a3, b1, b2, n1] {
        assert!(matches!(
            lane.answer(id, Duration::from_secs(10)),
            Got::Key(_)
        ));
    }
    // A never gets two turns in a row, and none waits for more than one job
    // of each other site: n1, queued last, is third.
    assert_eq!(lane.mined, [a1, b1, a2, n1, b2, a3]);
    for (id, topic) in [(a2, "fast-29"), (b1, "fast-46"), (n1, "fast-81")] {
        assert_eq!(got(&lane.answers[&id].0), Got::Key(address(topic)));
    }

    // A queues a backlog ending in T; B joins T, twice, and A joins its own.
    lane.world(json!({ "reset": true }));
    lane.mined.clear();
    let a1 = lane.send(A, "room");
    let a2 = lane.send(A, "fast-85");
    let a3 = lane.send(A, "fast-102");
    let t = lane.send(A, "fast-103");
    let tb = lane.send(B, "fast-103");
    let tb2 = lane.send(B, "fast-103");
    let ta2 = lane.send(A, "fast-103");
    let state = lane.state();
    assert_eq!(
        (&state["running"], &state["waiting"]),
        (&json!(true), &json!(3)),
        "a join adds no job"
    );
    assert!(lane.mined.is_empty(), "a1 still runs");
    for id in [a1, a2, a3, t, tb, tb2, ta2] {
        assert!(matches!(
            lane.answer(id, Duration::from_secs(10)),
            Got::Key(_)
        ));
    }
    // B's turn comes next and runs T, once, for every waiter; then A's.
    assert_eq!(lane.mined, [a1, t, tb, tb2, ta2, a2, a3]);
    for id in [t, tb, tb2, ta2] {
        assert_eq!(got(&lane.answers[&id].0), Got::Key(address("fast-103")));
    }
    lane.settled();
}

/// Percentiles of `samples`, in ms: p50, p99 and the largest.
fn spread(samples: &[Duration]) -> (f64, f64, f64) {
    let mut v: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1e3).collect();
    v.sort_by(f64::total_cmp);
    let at = |p: f64| v[((v.len() as f64 * p).ceil() as usize).clamp(1, v.len()) - 1];
    (at(0.5), at(0.99), at(1.0))
}

/// `vault.lock` every 20 ms while the lane mines 64 long searches (some
/// 3,600 batches, one after another, on its own core), for 2 s or until
/// the last search ends (1.2 s at SWM-2's macOS batch time), with at least
/// 25 locks sent while it mines: answered within 0009's gate, 50 ms at
/// p99. The lane's batch time is measured over the whole run.
#[test]
fn vault_lock_is_answered_while_the_lane_mines() {
    let sites: Vec<String> = (0..4).map(|n| format!("https://v{n}.example")).collect();
    let all: Vec<&str> = sites.iter().map(String::as_str).collect();
    let mut lane = Lane::new(&[], &all);
    let start = Instant::now();
    let mut ids = Vec::new();
    for (k, (n, _)) in LONG.iter().enumerate() {
        ids.push(lane.send(&sites[k / 16], &format!("long-{n}")));
    }
    assert!(lane.state()["running"] == json!(true));
    let window = Instant::now();
    let mut locks = Vec::new();
    let mut next = window;
    while window.elapsed() < Duration::from_secs(2) && lane.mined.len() < LONG.len() {
        if Instant::now() >= next {
            let id = lane.ask("vault.lock", json!({}), "chrome");
            locks.push((id, Instant::now()));
            next += Duration::from_millis(20);
        }
        lane.step(Duration::from_millis(1));
    }
    let mined_in_window = lane.mined.len();
    let window = window.elapsed();
    assert!(
        locks.len() >= 25,
        "{} locks while the lane mined",
        locks.len()
    );
    lane.until(Duration::from_secs(10), "the last locks", |lane| {
        locks.iter().all(|(id, _)| lane.responses.contains_key(id))
    });
    let samples: Vec<Duration> = locks
        .iter()
        .map(|(id, sent)| {
            let (answer, arrived) = &lane.responses[id];
            assert_eq!(answer["result"], json!({}), "{answer}");
            *arrived - *sent
        })
        .collect();
    let (p50, p99, max) = spread(&samples);
    // The lane mines on: its batch time over the whole run.
    lane.until(Duration::from_secs(60), "every search", |lane| {
        lane.mined.len() == LONG.len()
    });
    let mining = lane.mined_at.values().max().copied().unwrap() - lane.ready_at[&ids[0]];
    let batches: u32 = LONG.iter().map(|(_, index)| index / 256 + 1).sum();
    eprintln!(
        "[mining] vault.lock while mining for {window:?} ({mined_in_window} of 64 searches done): \
         n {} p50 {p50:.1} ms p99 {p99:.1} ms max {max:.1} ms; {batches} batches in {mining:?}, \
         {:.3} ms a batch",
        samples.len(),
        mining.as_secs_f64() * 1e3 / f64::from(batches)
    );
    assert!(p99 <= 50.0, "0009's gate: p99 {p99:.1} ms");
    for id in ids {
        assert!(matches!(
            lane.answer(id, Duration::from_secs(10)),
            Got::Key(_)
        ));
    }
    assert_eq!(index("long-4"), 11008);
    lane.settled();
    eprintln!("[mining] the run took {:?}", start.elapsed());
}
