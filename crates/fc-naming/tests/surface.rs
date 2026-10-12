//! The machine's protocol surface (design 0004, Admission and Generations):
//! caller cancellation and deadlines, per-caller lifecycle allowances,
//! configuration snapshots and their generations, and content
//! invalidation. A small world answers every request with what the
//! `quorum-agree` scenario recorded for its method.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use fc_naming::jsjson::{self, JsValue};
use fc_naming::session::bounds::Bounds;
use fc_naming::session::ens::{Answer, Config, Request};
use fc_naming::session::exec::{Effect, Fired};
use fc_naming::session::machine::{CallOptions, Emitted, Generations, Machine, Reply};
use fc_naming::session::random::{Mulberry32, Random};
use fc_naming::session::rpc::Transport;

const ENDPOINTS: [&str; 4] = [
    "https://a.rpc.example",
    "https://b.rpc.example",
    "https://c.rpc.example",
    "https://d.rpc.example",
];

/// The answer body `quorum-agree` recorded for each JSON-RPC method.
fn recorded() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/naming-replay.json"
    ))
    .unwrap();
    let vectors = jsjson::parse(&text).unwrap();
    let scenario = vectors
        .get("scenarios")
        .and_then(JsValue::as_array)
        .unwrap()
        .iter()
        .find(|s| s.get("id").and_then(JsValue::as_str) == Some("quorum-agree"))
        .unwrap()
        .clone();
    let mut answers = BTreeMap::new();
    for exchange in scenario.get("io").and_then(JsValue::as_array).unwrap() {
        let (Some(method), Some(body)) = (
            exchange.get("method").and_then(JsValue::as_str),
            exchange
                .get("answer")
                .and_then(|a| a.get("body"))
                .and_then(JsValue::as_str),
        ) else {
            continue;
        };
        answers
            .entry(method.to_owned())
            .or_insert_with(|| body.to_owned());
    }
    answers
}

fn config() -> Config {
    Config {
        rpc: ENDPOINTS.iter().map(|e| (*e).to_owned()).collect(),
        direct: None,
        order: vec!["quorum".into()],
        prefer_verified: false,
        quorum: jsjson::parse(
            r#"{"k":3,"m":2,"timeoutMs":5000,"anchor":"latest","anchorTtlMs":30000}"#,
        )
        .unwrap(),
        myotis_enabled: false,
        prover: None,
        tezos: vec!["https://t1.tez.example".into()],
        bounds: Bounds::default(),
    }
}

/// What main is due to deliver.
enum Pending {
    /// A Myotis availability change.
    Change,
    Configure(Box<Config>),
    Answer(u64, Answer),
}

/// A request the machine made, as main saw it.
struct Sent {
    id: u64,
    prefetch: bool,
    generations: Generations,
    endpoint: Option<String>,
    verified: bool,
}

/// Main, answering every RPC request 10 ms after it is made (a failure
/// for endpoints in `failing`).
struct World {
    machine: Machine,
    answers: BTreeMap<String, String>,
    pending: BTreeMap<u64, Pending>,
    next_token: u64,
    replies: Vec<Reply>,
    /// Availability changes to make at these times.
    changes: Vec<u64>,
    /// Configurations to apply at these times.
    configures: Vec<(u64, Config)>,
    failing: Vec<String>,
    sent: Vec<Sent>,
    /// When the machine cancelled requests.
    cancelled: Vec<u64>,
    /// Which requests it cancelled.
    cancelled_ids: Vec<u64>,
    /// What the sessions held before the poll that made each caller's
    /// reply.
    held_before_reply: BTreeMap<u64, usize>,
    /// The most the sessions held at once.
    peak: usize,
    /// What the sessions held before each poll.
    before_polls: Vec<usize>,
    /// Delivers everything due at one time before polling.
    batch: bool,
}

impl World {
    fn new(config: Config) -> Self {
        Self::with_random(config, Box::new(Mulberry32::new(7)))
    }

    fn with_random(config: Config, random: Box<dyn Random>) -> Self {
        Self {
            machine: Machine::new(0, config, random),
            answers: recorded(),
            pending: BTreeMap::new(),
            next_token: 1,
            replies: Vec::new(),
            changes: Vec::new(),
            configures: Vec::new(),
            failing: Vec::new(),
            sent: Vec::new(),
            cancelled: Vec::new(),
            cancelled_ids: Vec::new(),
            held_before_reply: BTreeMap::new(),
            peak: 0,
            before_polls: Vec::new(),
            batch: false,
        }
    }

    fn deliver(&mut self, at: u64, pending: Pending) {
        let token = self.next_token;
        self.next_token += 1;
        self.pending.insert(token, pending);
        self.machine.schedule(at, token);
    }

    /// Runs until `until`, collecting replies.
    fn run(&mut self, until: u64) {
        for at in std::mem::take(&mut self.changes) {
            self.deliver(at, Pending::Change);
        }
        for (at, config) in std::mem::take(&mut self.configures) {
            self.deliver(at, Pending::Configure(Box::new(config)));
        }
        loop {
            let held = self.machine.held();
            self.before_polls.push(held);
            self.machine.poll();
            self.peak = self.peak.max(self.machine.held());
            for reply in self.machine.take_replies() {
                self.held_before_reply.entry(reply.caller).or_insert(held);
                self.replies.push(reply);
            }
            for Emitted {
                effect,
                generations,
                ..
            } in self.machine.take_effects()
            {
                let (id, at, request) = match effect {
                    Effect::Request {
                        id, at, request, ..
                    } => (id, at, request),
                    Effect::Cancel { id, at } => {
                        self.cancelled.push(at);
                        self.cancelled_ids.push(id);
                        continue;
                    }
                };
                let endpoint = match &request {
                    Request::Rpc { endpoint, .. } => Some(endpoint.clone()),
                    _ => None,
                };
                self.sent.push(Sent {
                    id,
                    prefetch: matches!(request, Request::Prefetch { .. }),
                    generations,
                    endpoint: endpoint.clone(),
                    verified: matches!(request, Request::Verified(_)),
                });
                let Request::Rpc { endpoint, body } = request else {
                    continue;
                };
                let answer = if self.failing.contains(&endpoint) {
                    Answer::Failed(Transport::Network)
                } else {
                    let sent = jsjson::parse(&body).unwrap();
                    let method = sent.get("method").and_then(JsValue::as_str).unwrap();
                    Answer::Rpc {
                        status: 200,
                        body: self.answers[method].clone().into_bytes(),
                    }
                };
                self.deliver(at + 10, Pending::Answer(id, answer));
            }
            self.peak = self.peak.max(self.machine.held());
            let fired = self.machine.fire_next(until);
            if self.batch && fired.is_some() {
                let now = self.machine.now();
                while self.machine.next_due() == Some(now) {
                    if let Some(Fired::External(token)) = self.machine.fire_next(now) {
                        self.handle(token);
                    }
                }
            }
            match fired {
                None => return,
                Some(Fired::Timer) => {}
                Some(Fired::External(token)) => self.handle(token),
            }
        }
    }

    /// Delivers one of main's events.
    fn handle(&mut self, token: u64) {
        match self.pending.remove(&token) {
            Some(Pending::Change) => self.machine.availability(false),
            Some(Pending::Configure(config)) => {
                self.machine.configure(*config, false);
            }
            Some(Pending::Answer(id, answer)) => {
                self.machine.complete(id, answer);
                self.peak = self.peak.max(self.machine.held());
            }
            None => {}
        }
    }

    fn reply(&self, caller: u64) -> &Reply {
        self.replies
            .iter()
            .find(|r| r.caller == caller)
            .unwrap_or_else(|| panic!("caller {caller} has no reply"))
    }
}

fn protocol(reply: &Reply) -> Option<&'static str> {
    reply.outcome.as_ref().err().and_then(|e| e.code)
}

#[test]
fn a_cancelled_caller_is_detached_and_the_session_runs_on() {
    let mut world = World::new(config());
    let a = world.machine.resolve_content("vitalik.eth");
    let b = world.machine.resolve_content("vitalik.eth");
    assert!(world.machine.cancel(a));
    // Its reply has gone: a second cancel finds nothing.
    assert!(!world.machine.cancel(a));
    world.run(10_000);
    assert_eq!(protocol(world.reply(a)), Some("cancelled"));
    assert_eq!(world.reply(a).settled, 0);
    let b = world.reply(b);
    assert!(b.outcome.is_ok());
    assert_eq!(b.attempts, 1);
    // The session cached its result.
    let c = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert!(world.reply(c).outcome.is_ok());
    assert_eq!(world.reply(c).attempts, 0);
}

#[test]
fn a_caller_deadline_detaches_only_that_caller() {
    let mut world = World::new(config());
    let a = world.machine.resolve_content_with(
        "vitalik.eth",
        CallOptions {
            deadline_ms: Some(5),
            ..CallOptions::default()
        },
    );
    let b = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert_eq!(protocol(world.reply(a)), Some("deadline"));
    assert_eq!(world.reply(a).settled, 5);
    assert!(world.reply(b).outcome.is_ok());
    assert!(world.reply(b).settled > 5);
}

#[test]
fn the_session_deadline_ends_it_and_caches_nothing() {
    let mut config = config();
    config.bounds.deadline_ms = 25;
    let mut world = World::new(config);
    let a = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert_eq!(protocol(world.reply(a)), Some("deadline"));
    assert_eq!(world.reply(a).settled, 25);
    assert_eq!(world.machine.running(), 0);
    // Nothing was cached: the next lookup starts a session.
    world.machine.resolve_content("vitalik.eth");
    assert_eq!(world.machine.running(), 1);
}

#[test]
fn lifecycle_allowances_are_per_caller() {
    let mut world = World::new(config());
    // A fresh caller, and one main resubmitted after two attempts.
    let fresh = world.machine.resolve_content("vitalik.eth");
    let resubmitted = world.machine.resolve_content_with(
        "vitalik.eth",
        CallOptions {
            attempts_used: 2,
            ..CallOptions::default()
        },
    );
    // A lifecycle change during the first attempt.
    world.changes.push(5);
    world.run(10_000);
    let failed = world.reply(resubmitted);
    assert_eq!(
        failed.outcome.as_ref().err().map(|e| e.message.as_str()),
        Some("Myotis availability changed repeatedly while resolving vitalik.eth")
    );
    assert_eq!(failed.attempts, 3);
    let done = world.reply(fresh);
    assert!(done.outcome.is_ok());
    assert_eq!(done.attempts, 2);
    // It was computed under the lifecycle after the change.
    assert_eq!(done.generations.lifecycle, 1);
    assert!(done.settled > failed.settled);
}

#[test]
fn without_callers_a_session_uses_its_own_attempts() {
    let mut world = World::new(config());
    let a = world.machine.resolve_content("vitalik.eth");
    world.machine.cancel(a);
    // Three attempts (0–30 ms, then 30–40 and 40–50 on the cached anchor),
    // each crossing a change: the session restarts on its own attempts,
    // then ends without a result.
    world.changes.extend([5, 35, 45]);
    let mut running = Vec::new();
    for until in [32, 42, 48, 10_000] {
        world.run(until);
        running.push(world.machine.running());
    }
    assert_eq!(running, [1, 1, 1, 0]);
    world.machine.resolve_content("vitalik.eth");
    assert_eq!(world.machine.running(), 1, "nothing was cached");
}

#[test]
fn configure_advances_the_generation_of_what_changed() {
    let mut world = World::new(config());
    assert_eq!(world.machine.generations(), Generations::default());
    // The same snapshot changes nothing.
    assert_eq!(
        world.machine.configure(config(), false),
        Generations::default()
    );
    let mut tezos = config();
    tezos.tezos.push("https://t2.tez.example".into());
    let generations = world.machine.configure(tezos.clone(), false);
    assert_eq!((generations.ens, generations.tezos), (0, 1));
    let mut ens = tezos.clone();
    ens.rpc.pop();
    let generations = world.machine.configure(ens.clone(), false);
    assert_eq!((generations.ens, generations.tezos), (1, 1));
    // `reset: "providers"` advances the lifecycle, as invalidateCachedProvider.
    let generations = world.machine.configure(ens.clone(), true);
    assert_eq!(
        generations,
        Generations {
            ens: 1,
            tezos: 1,
            lifecycle: 1
        }
    );
    // The machine's bounds stay whatever the snapshot carries.
    let mut lowered = ens;
    lowered.bounds.deadline_ms = 1;
    world.machine.configure(lowered, false);
    let a = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert!(world.reply(a).outcome.is_ok());
}

#[test]
fn invalidate_content_reports_whether_it_held_the_name() {
    let mut world = World::new(config());
    assert!(!world.machine.invalidate_content("vitalik.eth"));
    let a = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert!(world.reply(a).outcome.is_ok());
    // Trimmed and normalized as resolveWithCache does.
    assert!(world.machine.invalidate_content("  VITALIK.eth "));
    assert!(!world.machine.invalidate_content("vitalik.eth"));
    assert!(!world.machine.invalidate_content(""));
    assert!(!world.machine.invalidate_content("   "));
}

#[test]
fn replies_carry_generations_and_attempts() {
    let mut world = World::new(config());
    let mut tezos = config();
    tezos.tezos.clear();
    world.machine.configure(tezos, false);
    let a = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    let reply = world.reply(a);
    assert_eq!(
        (reply.generations, reply.attempts),
        (
            Generations {
                ens: 0,
                tezos: 1,
                lifecycle: 0
            },
            1
        )
    );
    // An immediate reply used no attempt.
    let b = world.machine.resolve_content("");
    let immediate = world.machine.take_replies();
    assert_eq!((immediate[0].caller, immediate[0].attempts), (b, 0));
}

/// What one caller's reply costs the session: its own copy of the value
/// (the tree and its slot) or its serialized form, whichever is larger.
fn reply_size(value: &JsValue) -> usize {
    (value.held() + 32).max(value.stringify().len())
}

fn message(reply: &Reply) -> Option<&str> {
    reply.outcome.as_ref().err().map(|e| e.message.as_str())
}

#[test]
fn a_spent_allowance_fails_at_once_and_counts_carry_over() {
    let mut world = World::new(config());
    // Main resubmits only with attempts left. A spent or absurd count fails
    // as a restart would, with no I/O and no overflow.
    for used in [3, u32::MAX] {
        let caller = world.machine.resolve_content_with(
            "vitalik.eth",
            CallOptions {
                attempts_used: used,
                ..CallOptions::default()
            },
        );
        world.run(0);
        let reply = world.reply(caller);
        assert_eq!(
            message(reply),
            Some("Myotis availability changed repeatedly while resolving vitalik.eth")
        );
        assert_eq!(reply.attempts, used);
    }
    let tezos = world.machine.resolve_tezos_with(
        "alice.tez",
        CallOptions {
            attempts_used: 3,
            ..CallOptions::default()
        },
    );
    world.run(0);
    assert_eq!(
        message(world.reply(tezos)),
        Some("Tezos configuration changed repeatedly while resolving alice.tez")
    );
    assert_eq!(world.reply(tezos).attempts, 3);
    assert!(world.sent.is_empty());
    // A cache hit, a busy reply or an invalid input keeps the count the
    // caller came with, so a resubmission can't regain its allowance.
    let first = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert!(world.reply(first).outcome.is_ok());
    let resubmitted = CallOptions {
        attempts_used: 2,
        ..CallOptions::default()
    };
    let hit = world
        .machine
        .resolve_content_with("vitalik.eth", resubmitted);
    let invalid = world.machine.resolve_content_with("", resubmitted);
    world.run(10_000);
    assert!(world.reply(hit).outcome.is_ok());
    assert_eq!(world.reply(hit).attempts, 2);
    assert_eq!(world.reply(invalid).attempts, 2);
}

/// An ENS change: a quorum timeout of 4 s instead of 5.
fn changed() -> Config {
    let mut changed = config();
    changed.quorum =
        jsjson::parse(r#"{"k":3,"m":2,"timeoutMs":4000,"anchor":"latest","anchorTtlMs":30000}"#)
            .unwrap();
    changed
}

#[test]
fn a_configuration_change_ends_its_scopes_sessions() {
    let mut world = World::new(config());
    let a = world.machine.resolve_content("vitalik.eth");
    world.machine.resolve_tezos("alice.tez");
    world.configures.push((5, changed()));
    world.run(6);
    // The ENS session ended at the change, its requests cancelled. Its
    // reply carries the generation it ran under, which main discards.
    let reply = world.reply(a);
    assert_eq!((reply.settled, reply.generations.ens), (5, 0));
    assert_eq!(
        message(reply),
        Some("Name resolution configuration changed while resolving vitalik.eth")
    );
    assert!(world.cancelled.contains(&5));
    // The Tezos session runs on; an ENS lookup now starts afresh.
    assert_eq!(world.machine.running(), 1);
    let before = world.sent.len();
    let b = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert!(world.reply(b).outcome.is_ok());
    assert_eq!(world.reply(b).generations.ens, 1);
    // Every RPC request since is the new session's.
    assert!(
        world.sent[before..]
            .iter()
            .filter(|s| s.endpoint.is_some())
            .all(|s| s.generations.ens == 1)
    );
}

#[test]
fn an_ended_session_writes_nothing_shared() {
    let mut world = World::new(config());
    let a = world.machine.resolve_content("vitalik.eth");
    world.configures.push((5, changed()));
    world.run(10_000);
    assert_eq!(world.reply(a).generations.ens, 0);
    // Neither a result nor an anchor was kept: main's resubmission starts
    // a session that probes the heads again.
    let sent = world.sent.len();
    let b = world.machine.resolve_content_with(
        "vitalik.eth",
        CallOptions {
            attempts_used: world.reply(a).attempts,
            ..CallOptions::default()
        },
    );
    assert_eq!(world.machine.running(), 1);
    world.run(20_000);
    assert_eq!(world.reply(b).generations.ens, 1);
    assert!(world.sent.len() > sent + ENDPOINTS.len());
}

#[test]
fn a_late_answer_to_an_ended_session_leaves_a_newer_result_cached() {
    let mut world = World::new(config());
    world.machine.resolve_content("vitalik.eth");
    // A configuration change and a lifecycle change while its first
    // answers are outstanding (they arrive at 10 ms).
    world.configures.push((5, changed()));
    world.changes.push(5);
    world.run(6);
    // A lookup under the new generations resolves and caches...
    let b = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert!(world.reply(b).outcome.is_ok());
    // ...and the old session's late answers changed nothing: a hit.
    world.machine.resolve_content("vitalik.eth");
    assert_eq!(world.machine.running(), 0);
}

/// Mulberry32, counting its draws.
struct Counting(Mulberry32, std::rc::Rc<std::cell::Cell<usize>>);

impl Random for Counting {
    fn next_f64(&mut self) -> f64 {
        self.1.set(self.1.get() + 1);
        self.0.next_f64()
    }
}

#[test]
fn an_ended_session_draws_no_randomness() {
    let draws = std::rc::Rc::new(std::cell::Cell::new(0));
    let random = Counting(Mulberry32::new(7), std::rc::Rc::clone(&draws));
    let mut world = World::with_random(config(), Box::new(random));
    world.failing = ENDPOINTS.iter().map(|e| (*e).to_owned()).collect();
    world.machine.resolve_content("vitalik.eth");
    // Its failing heads would have sent it to the fallback's selection.
    let mut moved = config();
    moved.rpc.reverse();
    world.configures.push((5, moved));
    world.run(6);
    let at_change = draws.get();
    world.run(10_000);
    assert_eq!(draws.get(), at_change);
}

#[test]
fn late_failures_leave_forgotten_endpoints_alone() {
    let mut config = config();
    config.bounds.retired_endpoints = 0;
    let mut world = World::new(config.clone());
    world.failing = ENDPOINTS.iter().map(|e| (*e).to_owned()).collect();
    world.machine.resolve_content("vitalik.eth");
    // Every endpoint is replaced (and, with nothing retained, forgotten)
    // before its failing head answer arrives at 10 ms.
    let mut moved = config.clone();
    moved.rpc = ["e", "f", "g", "h"]
        .iter()
        .map(|h| format!("https://{h}.rpc.example"))
        .collect();
    world.configures.push((5, moved));
    world.run(10_000);
    // Re-added, they carry no quarantine: the next lookup probes all four.
    world.failing.clear();
    world.machine.configure(config, false);
    let before = world.sent.len();
    let b = world.machine.resolve_content("vitalik.eth");
    world.run(20_000);
    assert!(world.reply(b).outcome.is_ok());
    let probed: std::collections::BTreeSet<&str> = world.sent[before..]
        .iter()
        .filter_map(|s| s.endpoint.as_deref())
        .collect();
    assert_eq!(probed.len(), ENDPOINTS.len());
}

#[test]
fn enabling_myotis_is_live_state_not_a_configuration_change() {
    let mut config = config();
    config.order = vec!["myotis".into(), "quorum".into()];
    let mut world = World::new(config);
    world.machine.set_myotis_ready(true);
    let a = world.machine.resolve_content("vitalik.eth");
    world.run(200_000);
    assert!(world.reply(a).outcome.is_ok());
    assert!(!world.sent.iter().any(|s| s.verified), "Myotis is disabled");
    world.machine.set_myotis_enabled(true);
    assert_eq!(world.machine.generations(), Generations::default());
    world.machine.resolve_content("nick.eth");
    world.run(200_001);
    assert!(world.sent.iter().any(|s| s.verified), "Myotis is tried now");
}

#[test]
fn a_thrown_message_too_large_to_reply_is_result_too_large() {
    let mut config = config();
    config.bounds.reply_bytes = 100;
    let mut world = World::new(config);
    // The "changed repeatedly" message echoes the name: over the bound, it
    // becomes `result too large`, as an oversized result does.
    let long = format!("{}.eth", "a".repeat(100));
    let spent = CallOptions {
        attempts_used: 3,
        ..CallOptions::default()
    };
    let over = world.machine.resolve_content_with(&long, spent);
    let under = world.machine.resolve_content_with("nick.eth", spent);
    world.run(0);
    assert_eq!(message(world.reply(over)), Some("result too large"));
    assert_eq!(
        message(world.reply(under)),
        Some("Myotis availability changed repeatedly while resolving nick.eth")
    );
}

/// The most a quorum lookup of `name` holds at once, unbounded.
fn peak_of(name: &str) -> usize {
    let mut world = World::new(config());
    world.machine.resolve_content(name);
    world.run(10_000);
    world.peak
}

#[test]
fn a_session_over_its_budget_ends_and_caches_nothing() {
    let peak = peak_of("vitalik.eth");
    assert!(peak > 0);
    let mut bounded = config();
    bounded.bounds.session_bytes = peak / 2;
    let mut world = World::new(bounded);
    let a = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert_eq!(message(world.reply(a)), Some("budget"));
    // Its I/O was cancelled and what it held is free.
    assert!(!world.cancelled.is_empty());
    assert_eq!(world.machine.held(), 0);
    // Nothing was cached: the next lookup starts a session.
    world.machine.resolve_content("vitalik.eth");
    assert_eq!(world.machine.running(), 1);
}

#[test]
fn every_callers_reply_counts_against_the_session() {
    let peak = peak_of("vitalik.eth");
    let mut alone = World::new(config());
    let a = alone.machine.resolve_content("vitalik.eth");
    alone.run(10_000);
    let reply = reply_size(alone.reply(a).outcome.as_ref().unwrap());
    for (room, outcome) in [(3 * reply, None), (3 * reply - 1, Some("budget"))] {
        let mut bounded = config();
        bounded.bounds.session_bytes = peak + room;
        let mut world = World::new(bounded);
        let callers: Vec<u64> = (0..3)
            .map(|_| world.machine.resolve_content("vitalik.eth"))
            .collect();
        world.run(10_000);
        for caller in &callers {
            assert_eq!(message(world.reply(*caller)), outcome);
        }
        // A result whose replies don't fit is taken back from the cache.
        world.machine.resolve_content("vitalik.eth");
        assert_eq!(world.machine.running(), usize::from(outcome.is_some()));
    }
}

#[test]
fn crossing_the_total_fails_a_session_and_holds_new_ones_back() {
    let peak = peak_of("vitalik.eth").max(peak_of("nick.eth"));
    let mut bounded = config();
    // Two sessions in step cross it about halfway; the survivor alone fits.
    bounded.bounds.total_bytes = peak;
    bounded.bounds.resume_bytes = 1;
    let mut world = World::new(bounded);
    let a = world.machine.resolve_content("vitalik.eth");
    let b = world.machine.resolve_content("nick.eth");
    // Run until one of them has failed on the total.
    let mut at = 0;
    while !world.replies.iter().any(|r| message(r) == Some("budget")) {
        at += 1;
        world.run(at);
        assert!(at < 10_000, "neither crossed the total");
    }
    // While the other runs, the total stays over the resume mark: a new
    // session is busy, and only then does one start again.
    assert_eq!(world.machine.running(), 1, "the other runs on");
    let c = world.machine.resolve_content("alice.eth");
    world.run(at);
    assert_eq!(protocol(world.reply(c)), Some("busy"));
    world.run(10_000);
    assert_eq!(world.machine.held(), 0);
    let outcomes: Vec<Option<&str>> = [a, b].iter().map(|c| message(world.reply(*c))).collect();
    assert!(outcomes.contains(&Some("budget")));
    world.machine.resolve_content("alice.eth");
    assert_eq!(world.machine.running(), 1);
}

/// A 32-byte ABI word holding `n`.
fn word(n: usize) -> String {
    format!("{n:064x}")
}

/// An `OffchainLookup` from the Universal Resolver whose `count` URLs all
/// point at one `len`-byte string: it decodes to `count * len` bytes.
fn aliased_lookup(count: usize, len: usize) -> String {
    let sender = format!("{:0>64}", "eeeeeeee14d718c2b47d9923deab1335e144eeee");
    let url = "u".repeat(len);
    let padded = format!(
        "{:0<width$}",
        hex(url.as_bytes()),
        width = len.div_ceil(32) * 64
    );
    // urls: the count, then `count` offsets to one string after them.
    let mut urls = word(count);
    for _ in 0..count {
        urls += &word(count * 32);
    }
    urls += &word(len);
    urls += &padded;
    let urls_at = 5 * 32;
    let call_data_at = urls_at + urls.len() / 2;
    let extra_at = call_data_at + 64;
    // Left-aligned in its word: the callback selector, and one byte each
    // of call data and extra data.
    let left = |hex: &str| format!("{hex:0<64}");
    let (callback, call_data, extra) = (left("deadbeef"), left("01"), left("09"));
    let (urls_word, call_data_word, extra_word) =
        (word(urls_at), word(call_data_at), word(extra_at));
    let one = word(1);
    format!(
        "0x556f1830{sender}{urls_word}{call_data_word}{callback}{extra_word}{urls}{one}{call_data}{one}{extra}"
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn answers_count_against_the_session() {
    let mut bounded = config();
    bounded.bounds.session_bytes = 20_000;
    let mut world = World::new(bounded);
    // Every answer grows by 30 KB of a member JSON-RPC readers ignore.
    let pad = format!(r#","pad":"{}"}}"#, "x".repeat(30_000));
    for body in world.answers.values_mut() {
        body.pop();
        body.push_str(&pad);
    }
    let a = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert_eq!(message(world.reply(a)), Some("budget"));
}

#[test]
fn an_aliasing_decode_counts_against_the_session() {
    let mut bounded = config();
    bounded.bounds.session_bytes = 50_000;
    let mut world = World::new(bounded);
    // Each leg's call answers with a lookup that decodes to 100 KB from a
    // few KB.
    let revert = aliased_lookup(100, 1000);
    assert!(revert.len() < 20_000);
    world.answers.insert(
        "eth_call".into(),
        format!(r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":3,"message":"execution reverted","data":"{revert}"}}}}"#),
    );
    let a = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert_eq!(message(world.reply(a)), Some("budget"));
}

#[test]
fn a_new_sessions_name_counts_at_admission() {
    let mut bounded = config();
    bounded.bounds.session_bytes = 1000;
    let mut world = World::new(bounded);
    // 8 copies of `content:<204 bytes>` is more than 1,000: never started.
    let long = world
        .machine
        .resolve_content(&format!("{}.eth", "a".repeat(200)));
    world.run(0);
    assert_eq!(protocol(world.reply(long)), Some("busy"));
    assert_eq!(world.machine.running(), 0);
    world.machine.resolve_content("vitalik.eth");
    assert_eq!(world.machine.running(), 1);
}

#[test]
fn a_request_that_crosses_the_budget_is_never_sent() {
    // The name's copies, then room for two of the four head probes.
    let name = 8 * "content:vitalik.eth".len();
    let probe = ENDPOINTS[0].len()
        + r#"{"method":"eth_blockNumber","params":[],"id":1,"jsonrpc":"2.0"}"#.len();
    let mut bounded = config();
    bounded.bounds.session_bytes = name + 2 * probe + probe / 2;
    let mut world = World::new(bounded);
    let a = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert_eq!(message(world.reply(a)), Some("budget"));
    assert_eq!(
        world.sent.len(),
        2,
        "the probes past the budget were never sent"
    );
    assert_eq!(world.machine.held(), 0);
}

#[test]
fn spent_in_its_finishing_poll_a_session_caches_nothing() {
    // Answers that arrive together are delivered before the poll that
    // finishes the session: whatever that poll charges crosses.
    let mut unbounded = World::new(config());
    unbounded.batch = true;
    unbounded.machine.resolve_content("vitalik.eth");
    unbounded.run(10_000);
    let before_last = *unbounded
        .before_polls
        .iter()
        .rev()
        .find(|held| **held > 0)
        .unwrap();
    let mut bounded = config();
    bounded.bounds.session_bytes = before_last;
    let mut world = World::new(bounded);
    world.batch = true;
    let a = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert_eq!(message(world.reply(a)), Some("budget"));
    // Nothing of it was kept: the next lookup starts a session.
    world.machine.resolve_content("vitalik.eth");
    assert_eq!(world.machine.running(), 1);
}

#[test]
fn answers_count_as_their_parsed_tree() {
    // 2 KB more per answer: about 30 KB of bodies in all, which raw would
    // fit 200,000 bytes, but parsed (32 per byte) can't.
    let mut bounded = config();
    bounded.bounds.session_bytes = 200_000;
    let mut world = World::new(bounded);
    let pad = format!(r#","pad":"{}"}}"#, "x".repeat(2_000));
    for body in world.answers.values_mut() {
        body.pop();
        body.push_str(&pad);
    }
    let a = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert_eq!(message(world.reply(a)), Some("budget"));
}

#[test]
fn every_callers_error_counts_against_the_session() {
    // No method can resolve: each caller's error carries the name.
    let mut failing = config();
    failing.order = vec!["myotis".into()];
    let name = format!("{}.eth", "a".repeat(2_000));
    let mut alone = World::new(failing.clone());
    let a = alone.machine.resolve_content(&name);
    alone.run(10_000);
    let error = message(alone.reply(a)).unwrap().to_owned();
    assert!(error.contains(&name));
    // As it is sent: a JSON string.
    let reply = reply_size(&JsValue::String(error.clone()));
    let peak = alone.peak.max(8 * format!("content:{name}").len());
    for (room, outcome) in [(3 * reply, error.as_str()), (3 * reply - 1, "budget")] {
        let mut bounded = failing.clone();
        bounded.bounds.session_bytes = peak + room;
        let mut world = World::new(bounded);
        let callers: Vec<u64> = (0..3)
            .map(|_| world.machine.resolve_content(&name))
            .collect();
        world.run(10_000);
        for caller in &callers {
            assert_eq!(message(world.reply(*caller)), Some(outcome));
        }
    }
}

#[test]
fn replies_hold_their_room_until_written() {
    let mut bounded = config();
    bounded.bounds.total_bytes = 200_000;
    bounded.bounds.resume_bytes = 100_000;
    let mut world = World::new(bounded);
    // Main's backlog fills the total: a new lookup is busy.
    world.machine.set_output_backlog(200_000);
    let busy = world.machine.resolve_content("vitalik.eth");
    world.run(0);
    assert_eq!(protocol(world.reply(busy)), Some("busy"));
    // Room for the name, not for the lookup: it ends with `budget`.
    world.machine.set_output_backlog(199_000);
    let squeezed = world.machine.resolve_content("vitalik.eth");
    assert_eq!(world.machine.running(), 1);
    world.run(10_000);
    assert_eq!(message(world.reply(squeezed)), Some("budget"));
    // Written, the room is back.
    world.machine.set_output_backlog(0);
    let fits = world.machine.resolve_content("vitalik.eth");
    world.run(20_000);
    assert!(world.reply(fits).outcome.is_ok());
}

#[test]
fn a_configuration_changes_replies_count_against_the_session() {
    let name = format!("{}.eth", "a".repeat(2_000));
    let reply = reply_size(&JsValue::String(format!(
        "Name resolution configuration changed while resolving {name}"
    )));
    let callers = |world: &mut World| -> Vec<u64> {
        (0..3)
            .map(|_| world.machine.resolve_content(&name))
            .collect()
    };
    // What the session holds when the change comes: nothing happens
    // between its requests at 0 and their answers at 10.
    let mut probe = World::new(config());
    callers(&mut probe);
    probe.run(4);
    let held = probe.machine.held();
    for (room, expected) in [
        (
            3 * reply,
            format!("Name resolution configuration changed while resolving {name}"),
        ),
        (3 * reply - 1, "budget".to_owned()),
    ] {
        let mut bounded = config();
        bounded.bounds.session_bytes = held + room;
        let mut world = World::new(bounded);
        let ids = callers(&mut world);
        world.configures.push((5, changed()));
        world.run(6);
        for id in ids {
            let reply = world.reply(id);
            assert_eq!(message(reply), Some(expected.as_str()));
            // Either way it carries the generation main discards it for.
            assert_eq!(reply.generations.ens, 0);
        }
    }
}

#[test]
fn an_exhausted_callers_reply_counts_against_the_session() {
    let start = |bound: Option<usize>| {
        let mut bounded = config();
        if let Some(bound) = bound {
            bounded.bounds.session_bytes = bound;
        }
        let mut world = World::new(bounded);
        world.machine.resolve_content("vitalik.eth");
        let exhausted = world.machine.resolve_content_with(
            "vitalik.eth",
            CallOptions {
                attempts_used: 2,
                ..CallOptions::default()
            },
        );
        world.changes.push(5);
        world.run(10_000);
        (world, exhausted)
    };
    let text = "Myotis availability changed repeatedly while resolving vitalik.eth";
    let (probe, exhausted) = start(None);
    let held = probe.held_before_reply[&exhausted];
    let size = reply_size(&JsValue::String(text.to_owned()));
    for (room, expected) in [(size, text), (size - 1, "budget")] {
        let (world, exhausted) = start(Some(held + room));
        assert_eq!(message(world.reply(exhausted)), Some(expected));
    }
}

#[test]
fn a_reply_budget_failure_cancels_the_sessions_prefetch() {
    // Every answer arrives before the poll that finishes the session, so it
    // hands off its prefetch and charges its replies in one poll.
    let run = |bound: Option<usize>| {
        let mut bounded = config();
        if let Some(bound) = bound {
            bounded.bounds.session_bytes = bound;
        }
        let mut world = World::new(bounded);
        world.batch = true;
        let ids: Vec<u64> = (0..3)
            .map(|_| world.machine.resolve_content("vitalik.eth"))
            .collect();
        world.run(10_000);
        (world, ids)
    };
    let (probe, ids) = run(None);
    let result = probe.reply(ids[0]).outcome.as_ref().unwrap();
    let uri = result.get("uri").and_then(JsValue::as_str).unwrap();
    let reply = reply_size(result);
    // Room for the prefetch request, not for the third caller's reply.
    let bound = probe.held_before_reply[&ids[0]] + uri.len() + 3 * reply - 1;
    let (world, ids) = run(Some(bound));
    for id in &ids {
        assert_eq!(message(world.reply(*id)), Some("budget"));
    }
    let prefetches: Vec<u64> = world
        .sent
        .iter()
        .filter(|s| s.prefetch)
        .map(|s| s.id)
        .collect();
    assert!(!prefetches.is_empty(), "the prefetch was handed off");
    for id in prefetches {
        assert!(world.cancelled_ids.contains(&id), "prefetch {id} survives");
    }
}

/// What `tezos-agree` recorded for `alice.tez`, by request path.
fn tezos_answers() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/naming-replay.json"
    ))
    .unwrap();
    let vectors = jsjson::parse(&text).unwrap();
    let scenario = match vectors.get("scenarios") {
        Some(JsValue::Array(all)) => all
            .iter()
            .find(|s| s.get("id").and_then(JsValue::as_str) == Some("tezos-agree"))
            .unwrap()
            .clone(),
        _ => panic!("no scenarios"),
    };
    let Some(JsValue::Array(io)) = scenario.get("io") else {
        panic!("no io");
    };
    let mut answers = BTreeMap::new();
    for exchange in io {
        let path = exchange.get("path").and_then(JsValue::as_str);
        let body = exchange
            .get("answer")
            .and_then(|a| a.get("body"))
            .and_then(JsValue::as_str);
        if let (Some(path), Some(body)) = (path, body) {
            answers
                .entry(path.to_owned())
                .or_insert_with(|| body.to_owned());
        }
    }
    answers
}

/// `alice.tez` for `callers` callers, its record's `td:ttl` replaced by
/// `ttl` (JSON): what each caller is answered.
fn structured_ttl_lookup(callers: usize, ttl: &str, bounds: Bounds) -> Vec<Reply> {
    let answers = tezos_answers();
    let mut config = config();
    config.tezos = vec!["t1".into()];
    config.bounds = bounds;
    let mut machine = Machine::new(0, config, Box::new(Mulberry32::new(7)));
    for _ in 0..callers {
        machine.resolve_tezos("alice.tez");
    }
    let mut replies = Vec::new();
    for _ in 0..16 {
        machine.poll();
        replies.extend(machine.take_replies());
        for emitted in machine.take_effects() {
            if let Effect::Request {
                id,
                request: Request::Tezos { path, .. },
                ..
            } = emitted.effect
            {
                // "600", hex-encoded in the record's metadata.
                let body = answers[&path].replace("363030", &hex(ttl.as_bytes()));
                machine.complete(
                    id,
                    Answer::Tezos {
                        status: 200,
                        body: body.into_bytes(),
                    },
                );
            }
        }
    }
    replies
}

#[test]
fn each_callers_copy_of_a_result_counts_as_the_tree_it_is() {
    // A small record whose tree is large: 200 chains of 100 nested arrays.
    let chain = format!("{}0{}", "[".repeat(100), "]".repeat(100));
    let ttl = format!("[{}]", vec![chain; 200].join(","));
    // One caller's copy fits a session.
    let one = structured_ttl_lookup(1, &ttl, Bounds::default());
    let result = one[0].outcome.as_ref().unwrap();
    assert_eq!(result.get("type").and_then(JsValue::as_str), Some("ok"));
    let (tree, wire) = (result.held(), result.stringify().len());
    assert!(
        tree > 16 * wire,
        "the tree ({tree}) dwarfs the wire ({wire})"
    );
    // Thirty-two copies don't, though they serialize to a fraction of it.
    assert!(32 * wire < Bounds::default().session_bytes);
    assert!(32 * tree > Bounds::default().session_bytes);
    let many = structured_ttl_lookup(32, &ttl, Bounds::default());
    assert_eq!(many.len(), 32);
    for reply in &many {
        assert_eq!(message(reply), Some("budget"));
    }
}

#[test]
fn an_exhausted_callers_reply_is_sized_too() {
    let name = format!("{}.eth", "a".repeat(990_000));
    let mut world = World::new(config());
    world.changes.push(5);
    let caller = world.machine.resolve_content_with(
        &name,
        CallOptions {
            attempts_used: 2,
            ..CallOptions::default()
        },
    );
    world.run(10_000);
    let reply = world.reply(caller);
    // Over the reply cap: "result too large", attempts kept.
    assert_eq!(message(reply), Some("result too large"));
    assert_eq!(reply.attempts, 3);
}

#[test]
fn a_budget_failure_at_the_last_restart_cancels_the_sessions_prefetches() {
    // Every attempt resolves, prefetch included, and crosses a lifecycle
    // change: the third ends the caller's allowance.
    let run = |bound: usize| {
        let mut bounded = config();
        bounded.bounds.session_bytes = bound;
        let mut world = World::new(bounded);
        world.batch = true;
        world.changes.extend([5, 35, 45]);
        let caller = world.machine.resolve_content("vitalik.eth");
        world.run(10_000);
        (world, caller)
    };
    let repeated = "Myotis availability changed repeatedly while resolving vitalik.eth";
    let (unbounded, caller) = run(Bounds::default().session_bytes);
    assert_eq!(message(unbounded.reply(caller)), Some(repeated));
    // The least room the final reply fits in.
    let (mut lo, mut hi) = (0, Bounds::default().session_bytes);
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        let (world, caller) = run(mid);
        if message(world.reply(caller)) == Some(repeated) {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    // One byte less: the final reply crosses, and the session ends there.
    let (world, caller) = run(lo);
    let reply = world.reply(caller);
    assert_eq!((message(reply), reply.attempts), (Some("budget"), 3));
    let prefetches: Vec<u64> = world
        .sent
        .iter()
        .filter(|s| s.prefetch)
        .map(|s| s.id)
        .collect();
    assert_eq!(prefetches.len(), 3, "each attempt handed one off");
    for id in prefetches {
        assert!(world.cancelled_ids.contains(&id), "prefetch {id} survives");
    }
}

#[test]
fn an_immediate_reply_needs_room_in_the_total_too() {
    let mut world = World::new(config());
    let first = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    let size = reply_size(world.reply(first).outcome.as_ref().unwrap());
    let total = Bounds::default().total_bytes;
    // A cache hit with one byte too little room is busy, with its attempts.
    world.machine.set_output_backlog(total - size + 1);
    let short = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert_eq!(protocol(world.reply(short)), Some("busy"));
    assert_eq!(world.reply(short).attempts, 0);
    world.machine.set_output_backlog(total - size);
    let fits = world.machine.resolve_content("vitalik.eth");
    world.run(10_000);
    assert!(world.reply(fits).outcome.is_ok());
    // Cache hits waiting together, before the driver takes any: those past
    // the room are busy.
    world.machine.set_output_backlog(total - 10 * size);
    let hits: Vec<u64> = (0..20)
        .map(|_| world.machine.resolve_content("vitalik.eth"))
        .collect();
    world.run(10_000);
    let answered = hits
        .iter()
        .filter(|id| world.reply(**id).outcome.is_ok())
        .count();
    assert_eq!(answered, 10);
    assert!(
        hits[10..]
            .iter()
            .all(|id| protocol(world.reply(*id)) == Some("busy"))
    );
}

/// Applies `edit` to the value at `path` (keys and indices) in `value`.
fn edit_at(value: &mut JsValue, path: &[Result<usize, &str>], edit: &mut dyn FnMut(&mut JsValue)) {
    match path.split_first() {
        None => edit(value),
        Some((Err(key), rest)) => match value {
            JsValue::Object(props) => {
                let (_, child) = props.iter_mut().find(|(k, _)| k == key).unwrap();
                edit_at(child, rest, edit);
            }
            _ => panic!("no object at {key}"),
        },
        Some((Ok(index), rest)) => match value {
            JsValue::Array(items) => edit_at(&mut items[*index], rest, edit),
            _ => panic!("no array at {index}"),
        },
    }
}

/// Answers every Tezos request from `answers` until nothing is left to
/// answer: the replies, how many registry scripts were fetched, and the
/// most the sessions held.
fn drive_tezos(
    machine: &mut Machine,
    answers: &BTreeMap<String, String>,
) -> (Vec<Reply>, usize, usize) {
    let (mut replies, mut scripts, mut peak) = (Vec::new(), 0, 0);
    for _ in 0..16 {
        machine.poll();
        peak = peak.max(machine.held());
        replies.extend(machine.take_replies());
        for emitted in machine.take_effects() {
            if let Effect::Request {
                id,
                request: Request::Tezos { path, .. },
                ..
            } = emitted.effect
            {
                if path.contains("/contracts/") {
                    scripts += 1;
                }
                machine.complete(
                    id,
                    Answer::Tezos {
                        status: 200,
                        body: answers[&path].clone().into_bytes(),
                    },
                );
                peak = peak.max(machine.held());
            }
        }
    }
    (replies, scripts, peak)
}

#[test]
fn a_cached_discoverys_copy_counts_against_the_session_that_takes_it() {
    // The registry's record type carries an extra tree: 600 chains of 100
    // nested arrays, kept in the discovery each session copies.
    let mut answers = tezos_answers();
    let registry = answers
        .keys()
        .find(|p| p.contains("/contracts/KT1RgRg"))
        .unwrap()
        .clone();
    let mut script = jsjson::parse(&answers[&registry]).unwrap();
    let chain = format!("{}0{}", "[".repeat(100), "]".repeat(100));
    let extra = jsjson::parse(&format!("[{}]", vec![chain; 600].join(","))).unwrap();
    let copy = extra.held();
    let mut extra = Some(extra);
    // code[0].args[0].args[0].args[1]
    let path = [
        Err("code"),
        Ok(0),
        Err("args"),
        Ok(0),
        Err("args"),
        Ok(0),
        Err("args"),
        Ok(1),
    ];
    edit_at(&mut script, &path, &mut |record_type| match record_type {
        JsValue::Object(props) => props.push(("extra".into(), extra.take().unwrap())),
        _ => panic!("the record type is an object"),
    });
    answers.insert(registry, script.stringify());
    let run = |backlog: usize| {
        let mut config = config();
        config.tezos = vec!["t1".into()];
        let mut machine = Machine::new(0, config, Box::new(Mulberry32::new(7)));
        machine.resolve_tezos("alice.tez");
        let (primed, scripts, _) = drive_tezos(&mut machine, &answers);
        assert!(primed[0].outcome.is_ok(), "{:?}", primed[0].outcome);
        assert!(scripts > 0, "the first lookup discovers");
        machine.set_output_backlog(backlog);
        machine.resolve_tezos("bob.tez");
        drive_tezos(&mut machine, &answers)
    };
    // With room, the discovery comes from the cache, and its copy counts.
    let (replies, scripts, peak) = run(0);
    assert!(replies[0].outcome.is_ok(), "{:?}", replies[0].outcome);
    assert_eq!(scripts, 0, "the discovery comes from the cache");
    assert!(peak >= copy, "held {peak} for a copy of {copy}");
    // Without room for the copy, the session ends with `budget`.
    let total = Bounds::default().total_bytes;
    let (replies, _, _) = run(total - copy / 2);
    assert_eq!(message(&replies[0]), Some("budget"));
}
