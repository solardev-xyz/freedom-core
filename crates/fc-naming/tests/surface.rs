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
use fc_naming::session::machine::{CallOptions, Generations, Machine, Reply};
use fc_naming::session::random::Mulberry32;

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

/// Main, answering every RPC request 10 ms after it is made.
struct World {
    machine: Machine,
    answers: BTreeMap<String, String>,
    pending: BTreeMap<u64, (u64, Answer)>,
    next_token: u64,
    replies: Vec<Reply>,
    /// Availability changes to make at these times.
    changes: Vec<u64>,
}

impl World {
    fn new(config: Config) -> Self {
        Self {
            machine: Machine::new(0, config, Box::new(Mulberry32::new(7))),
            answers: recorded(),
            pending: BTreeMap::new(),
            next_token: 1,
            replies: Vec::new(),
            changes: Vec::new(),
        }
    }

    /// Runs until `until`, collecting replies.
    fn run(&mut self, until: u64) {
        for at in std::mem::take(&mut self.changes) {
            let token = self.next_token;
            self.next_token += 1;
            self.pending.insert(token, (u64::MAX, Answer::Done));
            self.machine.schedule(at, token);
        }
        loop {
            self.machine.poll();
            self.replies.extend(self.machine.take_replies());
            for effect in self.machine.take_effects() {
                if let Effect::Request {
                    id,
                    at,
                    request: Request::Rpc { body, .. },
                } = effect
                {
                    let sent = jsjson::parse(&body).unwrap();
                    let method = sent.get("method").and_then(JsValue::as_str).unwrap();
                    let answer = Answer::Rpc {
                        status: 200,
                        body: self.answers[method].clone().into_bytes(),
                    };
                    let token = self.next_token;
                    self.next_token += 1;
                    self.pending.insert(token, (id, answer));
                    self.machine.schedule(at + 10, token);
                }
            }
            match self.machine.fire_next(until) {
                None => return,
                Some(Fired::Timer) => {}
                Some(Fired::External(token)) => match self.pending.remove(&token) {
                    Some((u64::MAX, _)) => self.machine.availability(false),
                    Some((id, answer)) => {
                        self.machine.complete(id, answer);
                    }
                    None => {}
                },
            }
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
