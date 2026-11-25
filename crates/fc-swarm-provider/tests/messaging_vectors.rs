//! The Messaging machines against vectors/swarm.json (design 0015, SWM-3
//! part 3d): every `methods` case of `getMessagingIdentity`, `sendPss`,
//! `sendGsoc` and `subscribe` but the ones [`LEFT_OUT`] names; the
//! `stamps.select` cases messaging alone reaches (`message-4096`:
//! `selectMessageBatch`'s full mutable batch); the `gsoc` signers through
//! the mining lane; and the `errors` cases at messaging's three node calls.
//!
//! **What the core sees.** Each step went through main's page dispatcher,
//! which recorded what it handed the service. Before the hand-off main made
//! its own writes (the messaging grant a grant-mode prompt asked for, an
//! "always allow" rule), and the case's `at_execute` changes apply (the
//! messaging grant revoked, custody, the rule off, the name moved). A
//! subscribe-proxy case's session gives main's answer to the subscribe
//! check.
//!
//! **Main, the node and the lane.** A scripted swarm thread answers the
//! core's asks: the publish readiness from the case; the reachability and
//! subscribe checks from the node and the session; the node calls from the
//! case's declarative `node` under main's rules (common's fake node); and
//! the mining asks through one [`Lane`] per case, the lane thread running
//! each batch at once, so a case's later steps see its cache and its
//! new-topic budget.
//!
//! **What is checked,** each step: the result or error (the case's `core`
//! where a deviation changes it; for a subscription, the kind and key main
//! opens, and the socket it opens among the case's `websockets`); the
//! core's node calls against the grammar's honest scenario, exactly, query,
//! headers and bodies included (so a GSOC SOC's `sig` is bee-js's own);
//! the calls against the row's ready check, forms, counts and binds; each
//! ask's charge; each mining job's frozen identifier and target, computed
//! here from the topic; one ready check for each `readiness` event or
//! probe request; and no store written.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use common::*;
use fc_json::JsString;
use fc_json::index::{Index, KeyOrder, Kind, Value as V};
use fc_swarm_provider::machine::{
    Approval, AskId, Body, Call, Effect, Event, Form, MineJob, Mined, Need, NodeCall, Outcome,
    ReadyCheck, Request, Subscription, whole_charge,
};
use fc_swarm_provider::mining::{JOB_CHARGE, Lane, Submitted};
use fc_swarm_provider::value::{Bytes, Source, Value};

/// The methods this part's machines answer.
const FOUR: [&str; 4] = [
    "swarm_getMessagingIdentity",
    "swarm_sendPss",
    "swarm_sendGsoc",
    "swarm_subscribe",
];

/// Cases of the four methods this test doesn't play, each with why. The
/// test fails on any case of the four it neither plays nor names here.
const LEFT_OUT: &[(&str, &str)] = &[(
    "subscribe-no-page",
    "`executeSwarmMethod` called with no page (`page: false`) refuses a subscription with no \
     document target; the core's `swarm.request` is always a page's (0011), and main binds \
     the socket it opens to the requesting document",
)];

/// `swarm_unsubscribe` never reaches the core (design 0015, "Methods main
/// calls"): its steps are main's, and a case of it alone isn't one of the
/// four's.
const UNSUBSCRIBE: &str = "swarm_unsubscribe";

/// The deviations a case of the four marks, and what the core answers.
fn core_answer(deviation: &str, core: V<'_, '_>) -> Want {
    match shared_answer(deviation, core) {
        Some(want) => want,
        None => panic!("a deviation this part doesn't answer: {deviation}"),
    }
}

fn row_of(method: &str) -> &'static str {
    match method {
        "swarm_getMessagingIdentity" => "getMessagingIdentity",
        "swarm_sendPss" => "sendPss",
        "swarm_sendGsoc" => "sendGsoc",
        "swarm_subscribe" => "subscribe",
        other => panic!("{other}"),
    }
}

// ---------------------------------------------------------------------------
// The scripted swarm thread.

/// The swarm thread for one case: the world, the node, main's answers to
/// the ready checks, and the mining lane.
struct Thread {
    world: TestWorld,
    node: Node,
    readiness: Result<(), JsString>,
    /// Main's answer to the subscribe check before its probe (question 4).
    subscribe_check: Option<Result<(), JsString>>,
    lane: Lane<(usize, AskId)>,
    /// The step's number, so a waiter's token is the case's own.
    step: usize,
    // What the step did.
    ready: Vec<(ReadyCheck, usize)>,
    calls: Vec<Logged>,
    mines: Vec<MineJob>,
    most_open: usize,
    cancels_after_outcome: usize,
}

impl Thread {
    fn new(case: V<'_, '_>) -> Thread {
        let subscribe_check = case.get("session").map(|s| {
            let check = get(s, "subscribe_check");
            if get(check, "ok").kind() == Kind::True {
                Ok(())
            } else {
                Err(js(get(check, "reason")))
            }
        });
        // The node reads no key file: messaging signs with no vault key.
        let keys_text = text_of("keys.json");
        let keys_index = Index::new(&keys_text).unwrap();
        let keys = keys(&keys_index);
        Thread {
            world: TestWorld::of(case),
            node: Node::of(case, &keys),
            readiness: publish_readiness(case),
            subscribe_check,
            lane: Lane::new(),
            step: 0,
            ready: Vec::new(),
            calls: Vec::new(),
            mines: Vec::new(),
            most_open: 0,
            cancels_after_outcome: 0,
        }
    }

    /// Main's answer to a ready check.
    fn ready_answer(&self, check: ReadyCheck) -> Result<(), JsString> {
        match check {
            ReadyCheck::Publish => self.readiness.clone(),
            ReadyCheck::Reachable => self.node.reachable(),
            ReadyCheck::Subscribe => match &self.subscribe_check {
                Some(Err(reason)) => Err(reason.clone()),
                _ => self.node.reachable(),
            },
        }
    }

    /// Main's answer to a node call: the node's under main's rules, and a
    /// rule's change to the world as its request arrives.
    fn node_answer(&mut self, call: &NodeCall) -> Vec<Event> {
        if self.node.stopped {
            return vec![Event::Failed(fc_swarm_provider::machine::Failed::Stopped)];
        }
        if let Some(rule) = self.node.matching(call.method(), &call.path) {
            let changes = rule.world.clone();
            let key = JsString::from("");
            for (what, value) in changes {
                self.world.apply(&key, &what, &value);
            }
        }
        let spec = if call.method() == "POST" {
            let body = match &call.body {
                Some(Body::Base64(bytes)) => bytes.clone(),
                None => Vec::new(),
                other => panic!("a messaging call streams no body: {other:?}"),
            };
            self.node.upload(call.method(), &call.path, &body)
        } else {
            self.node.reply(call.method(), &call.path)
        };
        forward(&spec, call).1
    }

    /// The lane's answer for `waiter`, the lane thread running each batch
    /// at once.
    fn mined(&mut self, origin: &JsString, job: MineJob, waiter: AskId) -> Mined {
        let now = self.world.now;
        let token = (self.step, waiter);
        if let Submitted::Done(mined) = self.lane.submit(now, origin, job, token) {
            return mined;
        }
        loop {
            let work = self.lane.work(now);
            let mut answers = work.answers;
            if let Some(batch) = work.batch {
                answers.extend(self.lane.ran(now, batch.run()));
            } else if answers.is_empty() {
                panic!("the lane idles with the waiter waiting");
            }
            if let Some((_, mined)) = answers.into_iter().find(|(w, _)| *w == token) {
                return mined;
            }
        }
    }

    fn run(&mut self, call: &Call) -> Outcome {
        self.ready.clear();
        self.calls.clear();
        self.mines.clear();
        self.most_open = 0;
        self.cancels_after_outcome = 0;
        let mut request = Request::start(call, &mut self.world).expect("a messaging method");
        let origin = request.origin().clone();
        let mut open = BTreeSet::new();
        let mut queue: VecDeque<Effect> =
            take_effects(&mut request, &mut open, &mut self.most_open).into();
        while request.outcome().is_none() {
            let effect = queue
                .pop_front()
                .expect("the request waits with nothing asked");
            let Effect::Ask(ask) = effect else {
                panic!("a messaging machine asks only: {effect:?}");
            };
            let events = match ask.need {
                Need::Ready(check) => {
                    assert_eq!(ask.charge, 0);
                    self.ready.push((check, self.calls.len()));
                    vec![Event::Ready(self.ready_answer(check))]
                }
                Need::Node(node_call) => {
                    assert!(!node_call.stream());
                    assert_eq!(
                        ask.charge,
                        whole_charge(node_call.form),
                        "{}",
                        node_call.path
                    );
                    let events = self.node_answer(&node_call);
                    let body = events.iter().find_map(|e| match e {
                        Event::Reply(r) if r.ok() => Some(r.body.clone()),
                        _ => None,
                    });
                    self.calls.push(Logged {
                        call: node_call,
                        charge: ask.charge,
                        body,
                    });
                    events
                }
                Need::Mine(job) => {
                    assert_eq!(ask.charge, JOB_CHARGE);
                    self.mines.push(job);
                    vec![Event::Mined(self.mined(&origin, job, ask.id))]
                }
                other => panic!("an ask messaging never makes: {other:?}"),
            };
            for event in events {
                assert!(request.outcome().is_none());
                request.answer(&mut self.world, ask.id, event);
                open.remove(&ask.id);
                for effect in take_effects(&mut request, &mut open, &mut self.most_open) {
                    match effect {
                        Effect::Cancel(_) => self.cancels_after_outcome += 1,
                        Effect::Credit { .. } => panic!("no stream to credit"),
                        other => queue.push_back(other),
                    }
                }
            }
        }
        assert!(queue.is_empty(), "asks left after the outcome: {queue:?}");
        request.outcome().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// Checks.

/// How main approved the step's request: a send a standing rule answered
/// reads custody first and shows no prompt; anything else is the user's.
fn approval_of(method: &str, step: V<'_, '_>) -> Option<Approval> {
    let events: Vec<_> = step
        .get("events")
        .map(|e| e.children().collect())
        .unwrap_or_default();
    let prompted = events.iter().any(|e| e.get("prompt").is_some());
    let ruled = events
        .iter()
        .any(|e| e.get("custody").is_some_and(|c| c.kind() == Kind::False));
    match method {
        "swarm_sendPss" | "swarm_sendGsoc" if ruled && !prompted => Some(Approval::Auto),
        "swarm_sendPss" | "swarm_sendGsoc" => Some(Approval::User),
        _ => None,
    }
}

/// A param's message bytes, as `normalizePayloadParam` reads them.
fn message_of(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::String(s) => Some(s.as_str().as_bytes().to_vec()),
        Value::Bytes(Bytes {
            source: Source::Inline(bytes),
            ..
        }) => Some(bytes.clone()),
        _ => None,
    }
}

/// The frozen GSOC derivation, written out here: keccak256 of the topic's
/// UTF-8 and of `freedom-gsoc-v1:` and the topic, at proximity 12.
fn gsoc_job_of(topic: &JsString) -> MineJob {
    let text = topic.as_str();
    MineJob {
        target: fc_evm::keccak256(format!("freedom-gsoc-v1:{text}").as_bytes()),
        identifier: fc_evm::keccak256(text.as_bytes()),
        proximity: 12,
    }
}

/// The signer bee-js mines for a topic, by `fc_swarm::gsoc::mine`.
fn mined_signer(
    topic: &JsString,
    cache: &mut BTreeMap<String, (String, String)>,
) -> (String, String) {
    cache
        .entry(topic.as_str().to_owned())
        .or_insert_with(|| {
            let job = gsoc_job_of(topic);
            let signer = fc_swarm::gsoc::mine(&job.target, &job.identifier, 12).unwrap();
            (hex(&signer.owner()), hex(&signer.soc_address()))
        })
        .clone()
}

/// The core's calls against the honest scenario's, exactly: form, method,
/// path, query, the row's headers, the body (an empty one as none, as the
/// recording leaves it out).
fn check_calls(id: &str, scenario: V<'_, '_>, calls: &[Logged], earlier: bool) {
    let main_headers = ["accept", "accept-encoding"];
    let wants: Vec<_> = get(scenario, "calls").children().collect();
    if earlier {
        assert!(calls.len() <= wants.len(), "{id}");
    } else {
        assert_eq!(wants.len(), calls.len(), "{id}: calls");
    }
    for (at, (want, logged)) in wants.iter().zip(calls).enumerate() {
        let call = &logged.call;
        let what = format!("{id}: call {at} {}", call.path);
        assert!(get(*want, "form").is_str(call.form.as_str()), "{what}");
        assert!(get(*want, "method").is_str(call.method()), "{what}");
        assert!(get(*want, "path").is_str(&call.path), "{what}");
        let pairs = |v: Option<V<'_, '_>>| -> Vec<(String, String)> {
            v.map(|q| {
                q.children()
                    .map(|pair| {
                        let mut it = pair.children();
                        (string(it.next().unwrap()), string(it.next().unwrap()))
                    })
                    .collect()
            })
            .unwrap_or_default()
        };
        assert_eq!(pairs(want.get("query")), call.query, "{what}: query");
        let headers: Vec<_> = pairs(want.get("headers"))
            .into_iter()
            .filter(|(k, _)| !main_headers.contains(&k.as_str()))
            .collect();
        assert_eq!(headers, call.headers, "{what}: headers");
        let body = match &call.body {
            None => None,
            Some(Body::Base64(bytes)) if bytes.is_empty() => None,
            Some(Body::Base64(bytes)) => Some(bytes.clone()),
            Some(other) => panic!("{what}: {other:?}"),
        };
        match (want.get("body"), body) {
            (None, None) => {}
            (Some(w), Some(got)) => {
                assert_eq!(number(get(w, "bytes")) as usize, got.len(), "{what}");
                match (w.get("base64"), w.get("sha256")) {
                    (Some(b), _) => assert_eq!(b64(&string(b)), got, "{what}: body"),
                    (None, Some(d)) => assert_eq!(sha(&got), string(d), "{what}: body"),
                    _ => panic!("{what}: a body spec"),
                }
            }
            (w, got) => panic!("{what}: body {:?} against {got:?}", w.map(|w| w.raw())),
        }
        assert!(call.feed.is_none() && call.tree.is_none(), "{what}");
        assert_eq!(call.max_bytes, call.form.cap(), "{what}: max_bytes");
    }
}

/// The values each row binds (design 0015, "The operation grammar"):
/// `sendPss`'s topic, targets, recipient and message; `sendGsoc`'s
/// identifier and `span ‖ message`, and its owner bee-js's mined signer.
fn check_binds(
    id: &str,
    row: &str,
    params: &Value,
    calls: &[Logged],
    signers: &mut BTreeMap<String, (String, String)>,
) {
    for logged in calls {
        let call = &logged.call;
        let segments: Vec<&str> = call.path.split('/').collect();
        let body = match &call.body {
            Some(Body::Base64(bytes)) => bytes.clone(),
            _ => Vec::new(),
        };
        match (row, call.form) {
            (_, Form::Stamps) => assert_eq!(call.path, "/stamps", "{id}"),
            ("getMessagingIdentity", Form::Addresses) => assert_eq!(call.path, "/addresses"),
            ("sendPss", Form::PssSend) => {
                let topic = params.get("topic").as_js_string().unwrap();
                assert_eq!(
                    segments[3],
                    hex(&fc_evm::keccak256(topic.as_str().as_bytes()))
                );
                let targets = params.get("targets").as_js_string().unwrap();
                assert_eq!(segments[4], targets.as_str().to_lowercase(), "{id}: <x>");
                let recipient = params.get("recipient").as_js_string().unwrap();
                let recipient = recipient
                    .as_str()
                    .strip_prefix("0x")
                    .unwrap_or(recipient.as_str());
                assert_eq!(
                    call.query,
                    [("recipient".to_owned(), recipient.to_lowercase())],
                    "{id}: recipient"
                );
                assert_eq!(
                    Some(body),
                    message_of(params.get("data")),
                    "{id}: the message"
                );
            }
            ("sendGsoc", Form::SocUp) => {
                let topic = params.get("topic").as_js_string().unwrap();
                let (owner, _) = mined_signer(topic, signers);
                assert_eq!(segments[2], owner, "{id}: the mined owner");
                assert_eq!(
                    segments[3],
                    hex(&fc_evm::keccak256(topic.as_str().as_bytes()))
                );
                let message = message_of(params.get("data")).unwrap();
                let mut want = (message.len() as u64).to_le_bytes().to_vec();
                want.extend_from_slice(&message);
                assert_eq!(body, want, "{id}: span ‖ message");
            }
            (row, form) => panic!("{id}: {form:?} under {row}"),
        }
    }
}

/// How many ready checks the reference made: each publish readiness and
/// each probe request.
fn ready_checks(step: V<'_, '_>) -> usize {
    let events = step
        .get("events")
        .map(|e| {
            e.children()
                .filter(|e| e.get("readiness").is_some())
                .count()
        })
        .unwrap_or(0);
    let probes = step
        .get("requests")
        .map(|r| r.children().filter(|r| r.get("ready").is_some()).count())
        .unwrap_or(0);
    events + probes
}

/// A subscription against the reference's: its kind and key, and the
/// socket main opens among the case's `websockets`.
fn check_subscription(id: &str, case: V<'_, '_>, step: V<'_, '_>, got: &Subscription) {
    let result = get(step, "result");
    assert!(get(result, "kind").is_str(got.kind.as_str()), "{id}: kind");
    assert!(get(result, "key").is_str(&hex(&got.key)), "{id}: key");
    let host = case.get("session").map_or_else(
        || "127.0.0.1:1633".to_owned(),
        |s| {
            string(get(s, "node_url"))
                .trim_start_matches("http://")
                .to_owned()
        },
    );
    let url = format!(
        "ws://{host}/{}/subscribe/{}",
        got.kind.as_str(),
        hex(&got.key)
    );
    let sockets: Vec<String> = get(case, "websockets").children().map(string).collect();
    assert_eq!(sockets, [url], "{id}: the socket main opens");
    // The answer as main reads it.
    let value = got.to_value();
    assert_eq!(
        value.get("subscribe").get("key"),
        &Value::str(&hex(&got.key)),
        "{id}"
    );
}

struct Vectors {
    text: String,
    grammar: String,
}

fn vectors() -> Vectors {
    Vectors {
        text: text_of("swarm.json"),
        grammar: text_of("swarm-grammar.json"),
    }
}

#[test]
fn messaging_methods() {
    let v = vectors();
    let index = Index::new(&v.text).unwrap();
    let grammar_index = Index::new(&v.grammar).unwrap();
    let grammar = grammar_index.root();
    let scenarios = scenarios(grammar);
    let mut signers = BTreeMap::new();

    let mut played = 0usize;
    let mut main_answered = 0usize;
    let mut unsubscribe_steps = 0usize;
    let mut scenarios_used = BTreeSet::new();
    let mut left_out_seen = BTreeSet::new();
    let mut deviations = BTreeSet::new();
    let mut mined = 0usize;
    for case in get(index.root(), "methods").children() {
        let id = string(get(case, "id"));
        let steps: Vec<_> = get(case, "steps").children().collect();
        let methods: Vec<Option<String>> =
            steps.iter().map(|s| s.get("method").map(string)).collect();
        if !methods
            .iter()
            .any(|m| m.as_ref().is_some_and(|m| FOUR.contains(&m.as_str())))
        {
            continue;
        }
        if let Some((_, why)) = LEFT_OUT.iter().find(|(l, _)| *l == id) {
            assert!(!why.is_empty());
            left_out_seen.insert(id.clone());
            continue;
        }
        assert!(
            methods.iter().all(|m| m
                .as_ref()
                .is_some_and(|m| FOUR.contains(&m.as_str()) || m == UNSUBSCRIBE)),
            "{id}: a case that mixes in another piece's method"
        );
        let deviation = case.get("deviation").map(string);
        let want = match &deviation {
            Some(d) => {
                deviations.insert(d.clone());
                core_answer(d, get(case, "core"))
            }
            None => {
                assert!(case.get("core").is_none(), "{id}");
                Want::Reference
            }
        };
        let origin = js(get(case, "origin"));
        let mut thread = Thread::new(case);
        for (k, step) in steps.iter().enumerate() {
            let sid = if steps.len() > 1 {
                format!("{id}/{k}")
            } else {
                id.clone()
            };
            thread.step = k;
            if let Some(clock) = step.get("clock") {
                thread.world.now = number(clock) as u64;
            }
            let name = methods[k].clone().unwrap();
            if name == UNSUBSCRIBE {
                // Main's own: it ends the subscription it opened.
                unsubscribe_steps += 1;
                continue;
            }
            let Some(handoff) = handoff(*step, &origin, &mut thread.world) else {
                assert_eq!(
                    step.get("requests").map_or(0, |r| r.children().count()),
                    0,
                    "{sid}"
                );
                main_answered += 1;
                continue;
            };
            if let Some(change) = case.get("at_execute") {
                thread.world.change(&handoff.key, change);
            }
            let call = Call {
                method: handoff.method.clone(),
                params: handoff.params.clone(),
                key: handoff.key.clone(),
                approval: approval_of(&name, *step),
            };
            let outcome = thread.run(&call);
            played += 1;

            let last = k + 1 == steps.len();
            match (&outcome, want) {
                (Outcome::Subscribe(got), Want::Reference) => {
                    check_subscription(&sid, case, *step, got)
                }
                (Outcome::Subscribe(got), other) => panic!("{sid}: {got:?} where {other:?}"),
                _ => check_outcome(&sid, want, last, case, *step, &outcome),
            }
            if want == Want::Exact && last {
                // The core's own answer: main opens no socket.
                let core = get(case, "core");
                if let Some(sockets) = core.get("websockets") {
                    assert_eq!(sockets.children().count(), 0, "{sid}");
                    assert!(matches!(outcome, Outcome::Error(_)), "{sid}");
                }
            }

            let row = row_of(&name);
            let shape = common::Ran {
                outcome: outcome.clone(),
                ready: thread.ready.clone(),
                calls: thread.calls.clone(),
                cancels_after_outcome: thread.cancels_after_outcome,
                most_open: thread.most_open,
            };
            check_row_shape(&sid, grammar, row, &shape);
            check_binds(&sid, row, &handoff.params, &thread.calls, &mut signers);
            let earlier = last && want == Want::Exact;
            match scenarios.get(&sid) {
                Some(scenario) => {
                    assert!(get(*scenario, "row").is_str(row), "{sid}");
                    let check = get(get(*scenario, "ready"), "check");
                    assert!(
                        thread.ready.iter().all(|(c, _)| check.is_str(c.as_str())),
                        "{sid}: the ready check"
                    );
                    check_calls(&sid, *scenario, &thread.calls, earlier);
                    scenarios_used.insert(sid.clone());
                }
                None => assert!(
                    thread.calls.is_empty(),
                    "{sid}: calls, and no honest scenario"
                ),
            }
            assert_eq!(
                thread.ready.len(),
                ready_checks(*step),
                "{sid}: ready checks"
            );
            // Each mining job is the topic's frozen search.
            for job in &thread.mines {
                let topic = handoff.params.get("topic").as_js_string().unwrap();
                assert_eq!(*job, gsoc_job_of(topic), "{sid}: the job");
                mined += 1;
            }
            // A subscription answered `{ subscribe }` derived its key: a
            // GSOC topic's is the mined address.
            if let Outcome::Subscribe(got) = &outcome
                && got.kind == fc_swarm_provider::machine::SubscriptionKind::Gsoc
                && let Some(topic) = handoff.params.get("topic").as_js_string()
            {
                let (_, address) = mined_signer(topic, &mut signers);
                assert_eq!(hex(&got.key), address, "{sid}");
            }
            // The effect's guard refused where the reference's did.
            let refused = step.get("events").and_then(|e| {
                e.children()
                    .filter_map(|e| e.get("effect"))
                    .find_map(|e| e.get("refused"))
            });
            if let Some(refused) = refused {
                let Outcome::Error(failure) = &outcome else {
                    panic!("{sid}: the guard refused, the core answered {outcome:?}")
                };
                assert_eq!(
                    failure_value(failure).stringify().unwrap(),
                    refused.stringify(KeyOrder::Property),
                    "{sid}: the guard's refusal"
                );
            }
        }
        // No store is written: the feeds and the history stay as they were.
        let after = get(case, "after");
        assert!(
            after.get("feeds").is_none_or(|f| f.kind() == Kind::Null),
            "{id}"
        );
        assert_eq!(get(after, "history").children().count(), 0, "{id}");
    }
    let left_out: BTreeSet<String> = LEFT_OUT.iter().map(|(id, _)| (*id).to_owned()).collect();
    assert_eq!(left_out_seen, left_out, "every case left out exists");
    for (sid, scenario) in &scenarios {
        let from = string(get(*scenario, "from"));
        let Some(case_id) = from.strip_prefix("methods/") else {
            continue;
        };
        let row = string(get(*scenario, "row"));
        if !FOUR.iter().any(|m| row_of(m) == row) || left_out.contains(case_id) {
            continue;
        }
        assert!(
            scenarios_used.contains(sid),
            "{sid}: an honest scenario no step played"
        );
    }
    for d in ["subscribe-proxy", "transport-error-text"] {
        assert!(deviations.contains(d), "{d}: no case played");
    }
    assert!(mined > 0);
    assert_eq!(
        (played, main_answered, unsubscribe_steps),
        (108, 8, 2),
        "steps played, main's own, unsubscribes"
    );
    // Every honest scenario of the four rows.
    assert_eq!(scenarios_used.len(), 56);
}
