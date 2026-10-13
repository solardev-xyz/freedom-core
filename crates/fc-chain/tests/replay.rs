//! Replays `vectors/chain-replay.json` through the chain machine (design
//! 0005, Replay). The driver plays main: it configures the machine from each
//! scenario's world, starts the calls when the reference started them, and
//! answers each I/O request with the answer the reference's matching
//! exchange or verifier operation got, at the time it got it.
//!
//! Compared exactly: every I/O request (endpoint, body, operation, time)
//! and its cancel; every result and error (key order, code, message,
//! data); settle times; and the state tables each step records.
//!
//! Scenarios the machine doesn't serve yet are skipped by ID prefix through
//! [`NOT_YET`], never silently; scenarios a deviation changes are listed in
//! [`DEVIATIONS`] with the difference they must show.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use fc_chain::JsString;
use fc_chain::MyotisOperation;
use fc_chain::machine::{
    Answer, Bounds, BroadcastOutcome, Call, CapReader, ChainConfig, ChainError, ColibriClass,
    ColibriReply, Effect, Emitted, Fired, Machine, MyotisClass, MyotisReply, Prop, Protocol,
    Prover, QuorumConfig, Ranker, ReadOptions, Reply, Request, RpcEndpoint, StateTables, Success,
    Thrown, Transport, VerifiedOp,
};
use fc_json::index::{Index, Kind};
use serde_json::{Map, Value as Json};

fn vectors() -> Json {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/chain-replay.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn str_of<'a>(value: &'a Json, key: &str) -> &'a str {
    value.get(key).and_then(Json::as_str).unwrap_or("")
}

fn num(value: &Json, key: &str) -> u64 {
    value.get(key).and_then(Json::as_u64).unwrap_or(0)
}

/// A repeat form's text.
fn expand(repeat: &Json) -> String {
    let count = usize::try_from(num(repeat, "count")).unwrap();
    format!(
        "{}{}{}",
        str_of(repeat, "head"),
        str_of(repeat, "unit").repeat(count),
        str_of(repeat, "tail")
    )
}

/// A text field, or its repeat form.
fn text_field(entry: &Json, name: &str) -> Option<String> {
    if let Some(text) = entry.get(name).and_then(Json::as_str) {
        return Some(text.to_owned());
    }
    entry.get(format!("{name}_repeat")).map(expand)
}

/// `new URL(url).host`, `''` when it doesn't parse.
fn host_of(url: &str) -> String {
    url::Url::parse(url).map_or_else(
        |_| String::new(),
        |u| match u.port() {
            Some(port) => format!("{}:{port}", u.host_str().unwrap_or("")),
            None => u.host_str().unwrap_or("").to_owned(),
        },
    )
}

// ---------------------------------------------------------------------------
// JSON comparison: two value texts are the same value as JSON.parse makes
// it, key order and -0 included.

fn same_value(a: fc_json::index::Value<'_, '_>, b: fc_json::index::Value<'_, '_>) -> bool {
    if a.kind() != b.kind() {
        return false;
    }
    match a.kind() {
        Kind::Null | Kind::True | Kind::False => true,
        Kind::Number => a.number().to_bits() == b.number().to_bits(),
        Kind::String => a.units().eq(b.units()),
        Kind::Array => {
            let (x, y): (Vec<_>, Vec<_>) = (a.children().collect(), b.children().collect());
            x.len() == y.len() && x.iter().zip(&y).all(|(p, q)| same_value(*p, *q))
        }
        Kind::Object => {
            let (x, y) = (a.properties(), b.properties());
            x.len() == y.len()
                && x.iter()
                    .zip(&y)
                    .all(|((ka, va), (kb, vb))| ka.units().eq(kb.units()) && same_value(*va, *vb))
        }
    }
}

fn same_json(a: &str, b: &str) -> bool {
    match (Index::new(a), Index::new(b)) {
        (Ok(a), Ok(b)) => same_value(a.root(), b.root()),
        _ => false,
    }
}

/// A trust label's endpoint references as main publishes them: hosts, with
/// `''` dropped from `agreed`, `dissented` and `queried`.
fn publish_trust(trust: &str) -> String {
    let value = fc_json::parse(trust).unwrap();
    let host = |item: &fc_json::JsValue| {
        item.get("ref")
            .and_then(fc_json::JsValue::as_str)
            .map(host_of)
    };
    let fc_json::JsValue::Object(members) = &value else {
        return trust.to_owned();
    };
    let members = members
        .iter()
        .map(|(key, item)| {
            let item = match (key.as_str(), &item) {
                ("agreed" | "dissented" | "queried", fc_json::JsValue::Array(list)) => {
                    fc_json::JsValue::Array(
                        list.iter()
                            .filter_map(|entry| match host(entry) {
                                Some(h) if h.is_empty() => None,
                                Some(h) => Some(fc_json::JsValue::String(h)),
                                None => Some(entry.clone()),
                            })
                            .collect(),
                    )
                }
                ("prover", entry) => host(entry).map_or(item.clone(), fc_json::JsValue::String),
                _ => item.clone(),
            };
            (key.clone(), item)
        })
        .collect();
    fc_json::JsValue::Object(members).stringify()
}

// ---------------------------------------------------------------------------
// Main's side: the configuration it sends, and the answers it relays.

const MYOTIS_NETWORKS: [u64; 2] = [1, 100];
const DEFAULT_READ_ORDER: [&str; 4] = ["myotis", "colibri", "quorum", "direct"];
const DEFAULT_NON_MYOTIS_READ_ORDER: [&str; 3] = ["colibri", "quorum", "direct"];
const LOG_INDEX: &str = "https://gnosis.blockscout.com/api";

fn strings(value: Option<&Json>) -> Option<Vec<String>> {
    value.and_then(Json::as_array).map(|items| {
        items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect()
    })
}

/// `isUserConfiguredRpc(chainId, url)`.
fn user_configured(world: &Json, entry: &Json, chain: &str, url: &str) -> bool {
    let sources = entry.get("sources").and_then(Json::as_array);
    let source = sources.into_iter().flatten().find(|source| {
        !source.get("keyed").and_then(Json::as_bool).unwrap_or(false)
            && source
                .get("coverage")
                .and_then(|c| c.get(chain))
                .and_then(Json::as_str)
                == Some(url)
    });
    let Some(source) = source else { return false };
    let list = world.get("sourceList").and_then(Json::as_array);
    list.into_iter().flatten().any(|meta| {
        meta.get("id") == source.get("id")
            && !meta.get("builtin").and_then(Json::as_bool).unwrap_or(false)
            && !meta.get("removed").and_then(Json::as_bool).unwrap_or(false)
            && !meta.get("keyed").and_then(Json::as_bool).unwrap_or(false)
    })
}

/// The snapshot main sends for a world's registry.
fn configs(world: &Json) -> Vec<ChainConfig> {
    let Some(chains) = world.get("chains").and_then(Json::as_object) else {
        return Vec::new();
    };
    chains
        .iter()
        .map(|(id, entry)| {
            let chain_id: u64 = id.parse().unwrap();
            let network = entry.get("network").cloned().unwrap_or(Json::Null);
            let access = network.get("access");
            let myotis = MYOTIS_NETWORKS.contains(&chain_id);
            let defaults: &[&str] = if myotis {
                &DEFAULT_READ_ORDER
            } else {
                &DEFAULT_NON_MYOTIS_READ_ORDER
            };
            let read_order = strings(access.and_then(|a| a.get("readOrder")))
                .unwrap_or_else(|| defaults.iter().map(|s| (*s).to_owned()).collect());
            let broadcast_order = strings(access.and_then(|a| a.get("broadcastOrder")))
                .unwrap_or_else(|| {
                    if myotis {
                        vec!["myotis".into(), "direct".into()]
                    } else {
                        vec!["direct".into()]
                    }
                });
            let quorum = network.get("quorum");
            let raw = |key: &str| quorum.and_then(|q| q.get(key)).map(Json::to_string);
            let rpc = strings(entry.get("rpc"))
                .unwrap_or_default()
                .into_iter()
                .map(|url| RpcEndpoint {
                    user_configured: user_configured(world, entry, id, &url),
                    endpoint: url,
                })
                .collect();
            let prover = strings(entry.get("prover"))
                .unwrap_or_default()
                .into_iter()
                .next()
                .map(|endpoint| Prover {
                    endpoint,
                    zk: network.get("zkProof") != Some(&Json::Bool(false)),
                });
            ChainConfig {
                chain_id,
                display_name: match chain_id {
                    1 => "Ethereum".into(),
                    100 => "Gnosis".into(),
                    _ => format!("Chain {chain_id}"),
                },
                read_order,
                broadcast_order,
                quorum: QuorumConfig {
                    k: raw("k"),
                    m: raw("m"),
                    timeout_ms: raw("timeoutMs"),
                },
                rpc,
                prover,
                myotis,
                blockscout: (chain_id == 100).then(|| LOG_INDEX.to_owned()),
            }
        })
        .collect()
}

/// A Myotis payload as main sends it: top-level keys in snake_case, in the
/// payload's order.
fn snake(payload: &str) -> String {
    let Ok(index) = Index::new(payload) else {
        return payload.to_owned();
    };
    let root = index.root();
    if root.kind() != Kind::Object {
        return payload.to_owned();
    }
    let parts: Vec<String> = root
        .properties()
        .into_iter()
        .map(|(key, value)| {
            let name = String::from_utf16_lossy(&key.units().collect::<Vec<u16>>());
            let mut snake = String::new();
            for c in name.chars() {
                if c.is_ascii_uppercase() {
                    snake.push('_');
                    snake.push(c.to_ascii_lowercase());
                } else {
                    snake.push(c);
                }
            }
            format!(
                "{}:{}",
                JsString::from(snake.as_str()).to_json(),
                value.stringify(fc_json::index::KeyOrder::Property)
            )
        })
        .collect();
    format!("{{{}}}", parts.join(","))
}

/// `assertMyotisAnswer` and `nativeResult(payload, 'txHash', 'result')`, as
/// main's broadcast executor reads the client's answer.
fn broadcast_hash(payload: &Json) -> Option<String> {
    let get = |key: &str| payload.get(key).filter(|v| !v.is_null());
    let truthy = |value: Option<&Json>| match value {
        None | Some(Json::Null) | Some(Json::Bool(false)) => false,
        Some(Json::String(s)) => !s.is_empty(),
        Some(Json::Number(n)) => n.as_f64() != Some(0.0),
        Some(_) => true,
    };
    let status = payload.get("status").and_then(Json::as_str);
    if status == Some("revert") || status == Some("infeasible") {
        return None;
    }
    if truthy(payload.get("error")) && payload.get("code").and_then(Json::as_f64) == Some(-32602.0)
    {
        return None;
    }
    if !truthy(Some(payload))
        || truthy(payload.get("error"))
        || matches!(status, Some("error" | "unavailable"))
    {
        return None;
    }
    get("txHash").or_else(|| get("result")).map(Json::to_string)
}

/// `isCapacityFailure`'s text, which main classes a Colibri failure by.
fn capacity(message: &str) -> bool {
    regex::Regex::new(
        r"(?i-u)out of gas|execution (?:gas|resource) limit|exceeds? (?:the )?(?:gas|execution) limit",
    )
    .unwrap()
    .is_match(message)
}

fn is_hex_data(text: &str) -> bool {
    text.strip_prefix("0x")
        .is_some_and(|d| d.len() % 2 == 0 && d.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A recorded thrown error's message.
fn thrown_message(thrown: &Json) -> String {
    serde_json::from_str::<String>(str_of(thrown, "message_json")).unwrap_or_default()
}

fn thrown_prop<'a>(thrown: &'a Json, key: &str) -> Option<&'a Json> {
    thrown
        .get("props")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
        .find(|entry| str_of(entry, "key") == key)
}

/// Main's reply for a recorded verifier operation.
fn verified_answer(record: &Json, before: Option<String>, after: Option<String>) -> Option<Answer> {
    let answer = record.get("answer")?;
    let host = str_of(record, "host");
    let op = str_of(record, "op");
    if host == "colibri" {
        if let Some(result) = text_field(answer, "result_json") {
            return Some(Answer::Colibri(ColibriReply::Result(result)));
        }
        let thrown = answer.get("thrown")?;
        let code = thrown_prop(thrown, "code")
            .and_then(|e| e.get("json"))
            .and_then(Json::as_str);
        let data = thrown_prop(thrown, "data")
            .and_then(|e| e.get("json"))
            .and_then(Json::as_str)
            .and_then(|t| serde_json::from_str::<String>(t).ok());
        if code == Some("3")
            && let Some(data) = data.filter(|d| is_hex_data(d))
        {
            return Some(Answer::Colibri(ColibriReply::Revert { data }));
        }
        let class = if capacity(&thrown_message(thrown)) {
            ColibriClass::Capacity
        } else {
            ColibriClass::Error
        };
        return Some(Answer::Colibri(ColibriReply::Failure(class)));
    }
    if op == "broadcast" {
        if let Some(payload) = text_field(answer, "payload_json") {
            let value: Json = serde_json::from_str(&payload).unwrap_or(Json::Null);
            return Some(Answer::Myotis(match broadcast_hash(&value) {
                Some(hash) => MyotisReply::Sent { hash },
                None => MyotisReply::Uncertain,
            }));
        }
        let thrown = answer.get("thrown")?;
        return Some(Answer::Myotis(match str_of(answer, "class") {
            "rejected" => MyotisReply::Rejected {
                reason: thrown_message(thrown),
            },
            "uncertain" | "uncertain_dispatched" => MyotisReply::Uncertain,
            class => MyotisReply::Failure(myotis_class(class)),
        }));
    }
    if let Some(payload) = text_field(answer, "payload_json") {
        return Some(Answer::Myotis(MyotisReply::Read {
            payload: snake(&payload),
            block_before: before,
            block_after: after,
        }));
    }
    Some(Answer::Myotis(MyotisReply::Failure(myotis_class(str_of(
        answer, "class",
    )))))
}

fn myotis_class(class: &str) -> MyotisClass {
    match class {
        "not_running" => MyotisClass::NotRunning,
        "not_ready" => MyotisClass::NotReady,
        "state_changed" => MyotisClass::StateChanged,
        "queue_full" => MyotisClass::QueueFull,
        "queue_deadline" => MyotisClass::QueueDeadline,
        "caller_deadline" => MyotisClass::CallerDeadline,
        _ => MyotisClass::Error,
    }
}

/// The recorded params of a verifier operation the machine asked for.
fn verified_params(op: &VerifiedOp) -> (&'static str, &'static str, u64, String) {
    match op {
        VerifiedOp::MyotisRead {
            chain_id,
            operation,
        } => {
            let (name, params) = match operation {
                MyotisOperation::Account { address } => (
                    "account",
                    format!("{{\"address\":{}}}", address.as_deref().unwrap_or("null")),
                ),
                MyotisOperation::Code { address } => (
                    "code",
                    format!("{{\"address\":{}}}", address.as_deref().unwrap_or("null")),
                ),
                MyotisOperation::Storage { address, slot } => (
                    "storage",
                    format!(
                        "{{\"address\":{},\"slot\":{}}}",
                        address.as_deref().unwrap_or("null"),
                        slot.as_deref().unwrap_or("null")
                    ),
                ),
                MyotisOperation::CallTx { tx } => {
                    ("call_tx", format!("{{\"tx\":{tx},\"block\":\"latest\"}}"))
                }
                MyotisOperation::EstimateTx { tx } => (
                    "estimate_tx",
                    format!("{{\"tx\":{tx},\"block\":\"latest\"}}"),
                ),
                MyotisOperation::Fee => ("fee", "{}".into()),
            };
            ("myotis", name, *chain_id, params)
        }
        VerifiedOp::MyotisBroadcast { chain_id, raw } => (
            "myotis",
            "broadcast",
            *chain_id,
            format!("{{\"raw\":{}}}", JsString::from(raw.as_str()).to_json()),
        ),
        VerifiedOp::Colibri {
            chain_id,
            method,
            params,
            deadline_ms,
        } => (
            "colibri",
            "request",
            *chain_id,
            format!(
                "{{\"method\":{},\"params\":{params},\"deadline_ms\":{deadline_ms}}}",
                JsString::from(method.as_str()).to_json()
            ),
        ),
    }
}

/// A body with its JSON-RPC id as the vectors normalize it.
fn normalized_body(body: &str) -> String {
    let prefix = "{\"jsonrpc\":\"2.0\",\"id\":";
    match body.strip_prefix(prefix) {
        Some(rest) => {
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            format!("{prefix}0{}", &rest[digits..])
        }
        None => body.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// The driver.

struct Exchange {
    entry: Json,
    used: bool,
    /// The machine's I/O id that this record answers.
    request: Option<u64>,
    /// When the machine cancelled it, before its answer.
    cancelled: Option<u64>,
    delivered: bool,
}

enum Token {
    /// The world answers I/O request `id`.
    Deliver(u64, Answer),
    /// A scripted event: Myotis readiness or a registry change.
    Event(Json),
    /// A call starts (`at` into its step).
    Start(usize),
    /// A caller aborts (`abort_at` after its start).
    Abort(usize),
}

/// One call of the current step.
struct Slot {
    call: Json,
    request: Option<u64>,
    /// When the driver submitted it first.
    submitted: Option<u64>,
    reply: Option<Reply>,
    /// Main sends a read or fee quote again once after `reconfigured`.
    resent: bool,
}

struct Driver {
    /// Every record of the scenario's I/O, Blockscout's hops included.
    records: Vec<Json>,
    machine: Machine,
    world: Json,
    io: Vec<Exchange>,
    statuses: Vec<(Json, bool)>,
    tokens: BTreeMap<u64, Token>,
    next_token: u64,
    step: usize,
    slots: Vec<Slot>,
    /// Machine request id → (step, call).
    owners: BTreeMap<u64, (usize, usize)>,
    /// Requests the reference never made, by kind.
    extra: Vec<String>,
    /// Answer reconciliation lookups (deviation `broadcast-outcome`).
    reconcile: bool,
    /// The scenario's deviation, if any: requests the reference never made
    /// are then listed, not failures, and compared with its list.
    expect: Option<&'static Expected>,
    mismatches: Vec<String>,
    /// The step's calls start one after another (Ant's scan loops).
    sequential: bool,
    /// Answers due in this very tick, in the order the reference's
    /// microtasks settle them: `(depth, sequence, io id, answer)`.
    pending: Vec<(u8, u64, u64, Answer)>,
    sequence: u64,
    /// A call started: the timers due now fire before time moves on (the
    /// harness's `tickAsync(0)`), whatever the calls' state.
    flush: bool,
}

impl Driver {
    fn token(&mut self, at: u64, token: Token) {
        let id = self.next_token;
        self.next_token += 1;
        self.tokens.insert(id, token);
        self.machine.schedule(at, id);
    }

    fn apply_world(&mut self) {
        let configs = configs(&self.world);
        self.machine.configure(&configs);
        for chain in MYOTIS_NETWORKS {
            let ready = self
                .world
                .get("myotis")
                .and_then(|m| m.get(chain.to_string()))
                .and_then(|m| m.get("ready"))
                == Some(&Json::Bool(true));
            self.machine.availability(chain, ready);
        }
        for config in &configs {
            if !MYOTIS_NETWORKS.contains(&config.chain_id) {
                let ready = self
                    .world
                    .get("myotis")
                    .and_then(|m| m.get(config.chain_id.to_string()))
                    .and_then(|m| m.get("ready"))
                    == Some(&Json::Bool(true));
                self.machine.availability(config.chain_id, ready);
            }
        }
    }

    /// Starts call `i` of the current step now.
    fn start(&mut self, i: usize) {
        let call = self.slots[i].call.clone();
        if let Some(abort) = call.get("abort_at").and_then(Json::as_u64) {
            let at = self.machine.now() + abort;
            self.token(at, Token::Abort(i));
        }
        let request = self.machine.submit(call_of(&call), None);
        self.owners.insert(request, (self.step, i));
        self.slots[i].request = Some(request);
        self.slots[i].submitted = Some(self.machine.now());
        self.flush = true;
    }

    /// Takes the machine's replies. True when a call started (a resend,
    /// or the next of a sequence): the machine must run before time moves.
    fn collect_replies(&mut self) -> bool {
        let mut started = false;
        for reply in self.machine.take_replies() {
            let Some(&(step, i)) = self.owners.get(&reply.id) else {
                continue;
            };
            if step != self.step {
                continue;
            }
            // Main's driver sends a read or a fee quote again once after a
            // configuration change (design 0005, Generations).
            if reply.result == Err(ChainError::Protocol(Protocol::Reconfigured))
                && !self.slots[i].resent
                && !self.slots[i]
                    .call
                    .get("fn")
                    .is_some_and(|f| f == "broadcastRawTransaction")
            {
                self.slots[i].resent = true;
                let request = self.machine.submit(call_of(&self.slots[i].call), None);
                self.owners.insert(request, (step, i));
                self.slots[i].request = Some(request);
                started = true;
                continue;
            }
            self.slots[i].reply = Some(reply);
            if self.sequential && i + 1 < self.slots.len() && self.slots[i + 1].request.is_none() {
                self.start(i + 1);
                started = true;
            }
        }
        started
    }

    /// Runs the machine until `until`, or until `done` holds.
    fn drive(&mut self, until: u64, done: &dyn Fn(&Driver) -> bool) {
        loop {
            self.machine.poll();
            let started = self.collect_replies();
            self.process_effects();
            if started {
                continue;
            }
            // This tick's answers, one at a time, in the reference's order.
            if let Some(at) = self
                .pending
                .iter()
                .enumerate()
                .min_by_key(|(_, (depth, sequence, ..))| (*depth, *sequence))
                .map(|(at, _)| at)
            {
                let (_, _, id, answer) = self.pending.remove(at);
                self.deliver(id, answer);
                continue;
            }
            if self.flush {
                let now = self.machine.now();
                match self.machine.fire_next(now) {
                    None => self.flush = false,
                    Some(fired) => self.fired(fired),
                }
                continue;
            }
            if done(self) {
                return;
            }
            match self.machine.fire_next(until) {
                None => return,
                Some(fired) => self.fired(fired),
            }
        }
    }

    fn deliver(&mut self, id: u64, answer: Answer) {
        if let Some(exchange) = self.io.iter_mut().find(|e| e.request == Some(id))
            && exchange.cancelled.is_none()
        {
            exchange.delivered = true;
        }
        self.machine.complete(id, answer);
    }

    fn fired(&mut self, fired: Fired) {
        let Fired::External(token) = fired else {
            return;
        };
        match self.tokens.remove(&token) {
            Some(Token::Deliver(id, answer)) => self.deliver(id, answer),
            Some(Token::Event(event)) => self.event(&event),
            Some(Token::Start(i)) => self.start(i),
            Some(Token::Abort(i)) => {
                if let Some(request) = self.slots[i].request {
                    self.machine.cancel(request);
                }
            }
            None => {}
        }
    }

    /// Queues an answer due in this tick. `depth` orders the reference's
    /// microtasks: a failed fetch or a non-2xx status settles before a body
    /// `response.json()` must read.
    fn now_answer(&mut self, depth: u8, id: u64, answer: Answer) {
        self.sequence += 1;
        self.pending.push((depth, self.sequence, id, answer));
    }

    fn event(&mut self, event: &Json) {
        let world = self.world.as_object_mut().unwrap();
        if let Some(Json::Object(myotis)) = event.get("myotis") {
            let entry = world
                .entry("myotis")
                .or_insert_with(|| Json::Object(Map::new()));
            for (chain, change) in myotis {
                let slot = entry
                    .as_object_mut()
                    .unwrap()
                    .entry(chain.clone())
                    .or_insert_with(|| Json::Object(Map::new()));
                for (k, v) in change.as_object().unwrap() {
                    slot.as_object_mut().unwrap().insert(k.clone(), v.clone());
                }
                let ready = slot.get("ready") == Some(&Json::Bool(true));
                self.machine.availability(chain.parse().unwrap(), ready);
            }
        }
        if let Some(Json::Object(chains)) = event.get("chains") {
            let entry = world
                .entry("chains")
                .or_insert_with(|| Json::Object(Map::new()));
            for (chain, change) in chains {
                let slot = entry
                    .as_object_mut()
                    .unwrap()
                    .entry(chain.clone())
                    .or_insert_with(|| Json::Object(Map::new()));
                for (k, v) in change.as_object().unwrap() {
                    slot.as_object_mut().unwrap().insert(k.clone(), v.clone());
                }
            }
            let configs = configs(&self.world);
            self.machine.configure(&configs);
        }
    }

    /// Matches the machine's new I/O to the records and schedules their
    /// answers.
    fn process_effects(&mut self) {
        for Emitted {
            effect, request, ..
        } in self.machine.take_effects()
        {
            match effect {
                Effect::Cancel { id, at } => {
                    if let Some(exchange) = self.io.iter_mut().find(|e| e.request == Some(id))
                        && !exchange.delivered
                        && exchange.cancelled.is_none()
                    {
                        exchange.cancelled = Some(at);
                    }
                }
                Effect::Request {
                    id,
                    at,
                    request: io,
                    ..
                } => {
                    let owner = request.and_then(|r| self.owners.get(&r).copied());
                    self.answer(id, at, &io, owner);
                }
            }
        }
    }

    /// Answers one I/O request from the records.
    fn answer(&mut self, id: u64, at: u64, io: &Request, owner: Option<(usize, usize)>) {
        let Some((step, call)) = owner else {
            self.mismatches
                .push(format!("a request with no caller at {at}: {io:?}"));
            return;
        };
        let shifted = self.expect.is_some_and(|e| e.shifted);
        let matches = |entry: &Json| {
            (shifted || num(entry, "t") == at)
                && num(entry, "step") == step as u64
                && num(entry, "call") == call as u64
                && match io {
                    Request::Rpc { endpoint, body, .. } => {
                        str_of(entry, "kind") == "rpc"
                            && str_of(entry, "url") == endpoint
                            && text_field(entry, "body").as_deref()
                                == Some(normalized_body(body).as_str())
                    }
                    Request::Verified(op) => {
                        let (host, name, chain, params) = verified_params(op);
                        str_of(entry, "kind") == "verified-op"
                            && str_of(entry, "host") == host
                            && str_of(entry, "op") == name
                            && num(entry, "chain") == chain
                            && text_field(entry, "params_json")
                                .is_some_and(|recorded| same_json(&recorded, &params))
                    }
                    Request::Blockscout {
                        endpoint, query, ..
                    } => {
                        str_of(entry, "kind") == "blockscout-page"
                            && str_of(entry, "url") == format!("{endpoint}{query}")
                    }
                }
        };
        let found = self.io.iter().position(|e| !e.used && matches(&e.entry));
        let Some(index) = found else {
            // Main's status sample threw before the operation ran.
            if let Request::Verified(VerifiedOp::MyotisRead { .. }) = io
                && let Some(status) = self.statuses.iter_mut().find(|(s, used)| {
                    !used
                        && num(s, "t") == at
                        && num(s, "step") == step as u64
                        && num(s, "call") == call as u64
                        && s.get("answer").and_then(|a| a.get("thrown")).is_some()
                })
            {
                status.1 = true;
                self.now_answer(
                    0,
                    id,
                    Answer::Myotis(MyotisReply::Failure(MyotisClass::Error)),
                );
                return;
            }
            // A broadcast's reconciliation lookup, which the reference never
            // makes: the network doesn't know the hash.
            if self.reconcile {
                let reply = match io {
                    Request::Rpc { body, .. }
                        if body.contains("\"method\":\"eth_getTransactionByHash\"") =>
                    {
                        self.extra.push(describe_request(io, at));
                        Some(Answer::Rpc {
                            status: 200,
                            body: br#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_vec(),
                        })
                    }
                    Request::Verified(VerifiedOp::Colibri { method, .. })
                        if method == "eth_getTransactionByHash" =>
                    {
                        self.extra.push(describe_request(io, at));
                        Some(Answer::Colibri(ColibriReply::Result("null".into())))
                    }
                    _ => None,
                };
                if let Some(reply) = reply {
                    let depth = u8::from(matches!(reply, Answer::Rpc { .. }));
                    self.now_answer(depth, id, reply);
                    return;
                }
            }
            if self.expect.is_some() {
                self.extra.push(describe_request(io, at));
            } else {
                self.mismatches.push(format!(
                    "unmatched request at {at} (step {step} call {call}): {io:?}"
                ));
            }
            return;
        };
        self.io[index].used = true;
        self.io[index].request = Some(id);
        let entry = self.io[index].entry.clone();
        let end = entry.get("end").and_then(Json::as_u64);
        let answer = match str_of(&entry, "kind") {
            "blockscout-page" => self.page_answer(&entry),
            "rpc" => match str_of(&entry, "outcome") {
                "answered" => entry.get("answer").map(|answer| Answer::Rpc {
                    status: u16::try_from(num(answer, "status")).unwrap_or(0),
                    body: text_field(answer, "body").unwrap_or_default().into_bytes(),
                }),
                "failed" => Some(Answer::Failed(Transport::Network)),
                "refused" => Some(Answer::Failed(Transport::Refused)),
                _ => None,
            },
            _ => {
                let (before, after) = self.status_samples(&entry);
                if str_of(&entry, "outcome") == "answered" {
                    verified_answer(&entry, before, after)
                } else {
                    None
                }
            }
        };
        let (Some(answer), Some(end)) = (answer, end) else {
            return;
        };
        // A deviation that moves the request keeps the answer's delay.
        let end = at + end.saturating_sub(num(&entry, "t"));
        if end == at {
            let depth = match &answer {
                Answer::Rpc { status, .. } if (200..=299).contains(status) => 1,
                _ => 0,
            };
            self.now_answer(depth, id, answer);
        } else {
            self.token(end, Token::Deliver(id, answer));
        }
    }

    /// Main's reply for a Blockscout page: the last hop's answer, after the
    /// redirects it followed; or the failure that ended the page before an
    /// answer (`None` for one that ended on the page's own deadline or the
    /// caller's abort, which the machine sees on its own).
    fn page_answer(&self, page: &Json) -> Option<Answer> {
        let id = num(page, "id");
        let hop = self
            .records
            .iter()
            .rfind(|r| {
                str_of(r, "kind") == "blockscout"
                    && r.get("within").and_then(Json::as_u64) == Some(id)
                    && str_of(r, "outcome") == "answered"
            })
            .filter(|r| {
                let status = r.get("answer").map_or(0, |a| num(a, "status"));
                ![301, 302, 303, 307, 308].contains(&status)
            });
        if let Some(hop) = hop {
            let answer = hop.get("answer")?;
            let headers = answer
                .get("headers")
                .and_then(Json::as_object)
                .map(|h| {
                    h.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_owned()))
                        .collect()
                })
                .unwrap_or_default();
            return Some(Answer::Blockscout {
                status: u16::try_from(num(answer, "status")).unwrap_or(0),
                headers,
                body: text_field(answer, "body").unwrap_or_default().into_bytes(),
            });
        }
        let thrown = page.get("answer")?.get("thrown")?;
        let message = thrown_message(thrown);
        if message == "unreachable" {
            Some(Answer::Failed(Transport::Network))
        } else if message.starts_with("redirected") {
            Some(Answer::Failed(Transport::Refused))
        } else {
            None
        }
    }

    /// The optimistic block numbers main samples around a Myotis read: the
    /// call's status records just before and after the operation.
    fn status_samples(&mut self, op: &Json) -> (Option<String>, Option<String>) {
        if str_of(op, "host") != "myotis" {
            return (None, None);
        }
        let id = num(op, "id");
        let same =
            |s: &Json| num(s, "step") == num(op, "step") && num(s, "call") == num(op, "call");
        let block = |s: &Json| {
            let text = s.get("answer").and_then(|a| text_field(a, "status_json"))?;
            let status: Json = serde_json::from_str(&text).ok()?;
            status
                .get("optimisticBlockNumber")
                .filter(|v| !v.is_null())
                .map(Json::to_string)
        };
        let mut before = None;
        if let Some(i) = self
            .statuses
            .iter()
            .rposition(|(s, used)| !used && same(s) && num(s, "id") < id)
        {
            self.statuses[i].1 = true;
            before = block(&self.statuses[i].0);
        }
        let mut after = None;
        if let Some(i) = self
            .statuses
            .iter()
            .position(|(s, used)| !used && same(s) && num(s, "id") > id)
        {
            self.statuses[i].1 = true;
            after = block(&self.statuses[i].0);
        }
        (before, after)
    }
}

/// A request, as the deviation lists name it.
fn describe_request(io: &Request, at: u64) -> String {
    match io {
        Request::Rpc { endpoint, body, .. } => {
            let method = Index::new(body)
                .ok()
                .and_then(|index| {
                    index
                        .root()
                        .get("method")
                        .map(|m| String::from_utf16_lossy(&m.units().collect::<Vec<u16>>()))
                })
                .unwrap_or_default();
            format!("rpc {endpoint} {method} at {at}")
        }
        Request::Verified(op) => {
            let (host, name, _, _) = verified_params(op);
            let name = match op {
                VerifiedOp::Colibri { method, .. } => method.as_str(),
                _ => name,
            };
            format!("{host} {name} at {at}")
        }
        Request::Blockscout {
            endpoint, query, ..
        } => format!("blockscout {endpoint}{query} at {at}"),
    }
}

/// A recorded exchange, as the deviation lists name it.
fn describe_record(entry: &Json) -> String {
    match str_of(entry, "kind") {
        "rpc" => format!(
            "rpc {} {} at {}",
            str_of(entry, "url"),
            str_of(entry, "method"),
            num(entry, "t")
        ),
        _ => {
            let name = if str_of(entry, "host") == "colibri" {
                text_field(entry, "params_json")
                    .and_then(|p| serde_json::from_str::<Json>(&p).ok())
                    .and_then(|p| p.get("method").and_then(Json::as_str).map(str::to_owned))
                    .unwrap_or_default()
            } else {
                str_of(entry, "op").to_owned()
            };
            format!("{} {name} at {}", str_of(entry, "host"), num(entry, "t"))
        }
    }
}

/// A recorded call as main would send it.
fn call_of(call: &Json) -> Call {
    let chain_id = num(call, "chain");
    match str_of(call, "fn") {
        "getFeeQuote" => Call::FeeQuote { chain_id },
        "broadcastRawTransaction" => Call::Broadcast {
            chain_id,
            raw: str_of(call, "raw").to_owned(),
        },
        _ => {
            let mut options = if str_of(call, "profile") == "ant_scan" {
                ReadOptions::ant_scan()
            } else {
                ReadOptions::default()
            };
            options.include_trust |= call.get("include_trust") == Some(&Json::Bool(true));
            options.background |= call.get("background") == Some(&Json::Bool(true));
            if let Some(origin) = call.get("origin").and_then(Json::as_str) {
                options.origin = Some(origin.to_owned());
            }
            if let Some(extra) = call.get("options").and_then(Json::as_object) {
                for (key, value) in extra {
                    match key.as_str() {
                        "excludeSources" => options.exclude_sources = strings(Some(value)).unwrap(),
                        "includeSources" => options.include_sources = strings(Some(value)).unwrap(),
                        "directTimeoutMs" => options.direct_timeout_ms = value.as_f64(),
                        "quorumTimeoutMs" => options.quorum_timeout_ms = value.as_f64(),
                        "rankError" => {
                            options.ranker = Some(match value.as_str() {
                                Some("ant") => Ranker::Ant,
                                _ => Ranker::Request,
                            });
                        }
                        "rangeCapOf" => options.cap_reader = Some(CapReader::Ant),
                        other => panic!("unknown option {other}"),
                    }
                }
            }
            let params = if call.get("params_undefined").is_some() {
                "[]".to_owned()
            } else {
                text_field(call, "params_json").unwrap_or_else(|| "[]".into())
            };
            Call::Read {
                chain_id,
                method: str_of(call, "method").to_owned(),
                params,
                options,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Comparing what the machine replied with what the reference returned.

/// The reference's result object as JSON text, from its entries; `None`
/// when an entry is `undefined` (a missing `result`), which is returned
/// separately.
fn entries_json(entries: &[Json]) -> (String, bool) {
    let mut undefined_result = false;
    let parts: Vec<String> = entries
        .iter()
        .filter_map(|entry| {
            let key = str_of(entry, "key");
            if entry.get("undefined").is_some() {
                if key == "result" {
                    undefined_result = true;
                }
                return None;
            }
            let value = text_field(entry, "json")?;
            Some(format!("{}:{value}", JsString::from(key).to_json()))
        })
        .collect();
    (format!("{{{}}}", parts.join(",")), undefined_result)
}

/// Compares a reply with the reference's result; `None` when they agree.
fn compare(reply: &Reply, expected: &Json) -> Option<String> {
    let mut problems = Vec::new();
    let settled = num(expected, "settled");
    if reply.settled != settled {
        problems.push(format!("settled at {} instead of {settled}", reply.settled));
    }
    match (&reply.result, expected.get("value"), expected.get("thrown")) {
        (
            Ok(Success::Read {
                result,
                source,
                verified,
                trust,
            }),
            Some(Json::Array(entries)),
            _,
        ) => {
            let keys: Vec<&str> = entries.iter().map(|e| str_of(e, "key")).collect();
            let mut got_keys = vec!["result", "source", "verified"];
            if trust.is_some() {
                got_keys.push("trust");
            }
            if keys != got_keys {
                problems.push(format!("keys {got_keys:?} instead of {keys:?}"));
            }
            for entry in entries {
                let key = str_of(entry, "key");
                let want = text_field(entry, "json");
                let ok = match key {
                    "result" => match (result, &want) {
                        (None, None) => entry.get("undefined").is_some(),
                        (Some(got), Some(want)) => same_json(got, want),
                        _ => false,
                    },
                    "source" => want.as_deref() == Some(JsString::from(*source).to_json().as_str()),
                    "verified" => want.as_deref() == Some(if *verified { "true" } else { "false" }),
                    "trust" => match (trust, &want) {
                        (Some(trust), Some(want)) => same_json(&publish_trust(trust), want),
                        _ => false,
                    },
                    _ => false,
                };
                if !ok {
                    let got = match key {
                        "result" => format!("{result:?}"),
                        "source" => (*source).to_owned(),
                        "verified" => verified.to_string(),
                        "trust" => trust.as_deref().map(publish_trust).unwrap_or_default(),
                        _ => String::new(),
                    };
                    problems.push(format!(
                        "{key}: got {} want {}",
                        got.chars().take(300).collect::<String>(),
                        want.unwrap_or_else(|| "undefined".into())
                            .chars()
                            .take(300)
                            .collect::<String>()
                    ));
                }
            }
        }
        (Ok(Success::FeeQuote(quote)), Some(Json::Array(entries)), _) => {
            let (want, _) = entries_json(entries);
            if !same_json(&quote.to_json(), &want) {
                problems.push(format!("quote {} instead of {want}", quote.to_json()));
            }
        }
        (
            Ok(Success::Broadcast {
                hash,
                source,
                outcome,
            }),
            Some(Json::Array(entries)),
            _,
        ) => {
            // Today's `{ result, source }` is the design's `sent`.
            let (want, _) = entries_json(entries);
            let got = format!(
                "{{\"result\":{},\"source\":{}}}",
                hash.as_deref()
                    .map_or("null".into(), |h| JsString::from(h).to_json()),
                JsString::from(*source).to_json()
            );
            if *outcome != BroadcastOutcome::Sent || !same_json(&got, &want) {
                problems.push(format!("broadcast {outcome:?} {got} instead of {want}"));
            }
        }
        (Err(ChainError::Thrown(thrown)), _, Some(want)) => {
            if let Some(problem) = compare_thrown(thrown, want) {
                problems.push(problem);
            }
        }
        // The caller's abort is 0001's `cancel`: the machine replies
        // `cancelled` where today's request throws its `AbortError`.
        (Err(ChainError::Protocol(Protocol::Cancelled)), _, Some(want))
            if str_of(want, "class") == "DOMException" && str_of(want, "name") == "AbortError" => {}
        (result, _, _) => problems.push(format!(
            "{} instead of {}",
            describe(result),
            serde_json::to_string(expected)
                .unwrap()
                .chars()
                .take(400)
                .collect::<String>()
        )),
    }
    (!problems.is_empty()).then(|| problems.join("; "))
}

fn describe(result: &Result<Success, ChainError>) -> String {
    match result {
        Ok(Success::Read { result, source, .. }) => format!(
            "read {source} {}",
            result
                .as_deref()
                .unwrap_or("undefined")
                .chars()
                .take(200)
                .collect::<String>()
        ),
        Ok(other) => format!("{other:?}"),
        Err(ChainError::Thrown(thrown)) => format!(
            "thrown {} {:?} {:?}",
            thrown.class.constructor(),
            thrown
                .message
                .to_string_lossy()
                .chars()
                .take(300)
                .collect::<String>(),
            thrown.props
        ),
        Err(ChainError::Protocol(code)) => format!("protocol {}", code.as_str()),
    }
}

fn compare_thrown(thrown: &Thrown, want: &Json) -> Option<String> {
    let class = str_of(want, "class");
    let name = str_of(want, "name");
    let message = str_of(want, "message_json");
    let message_ok = same_json(&thrown.message.to_json(), message);
    let class_ok = thrown.class.constructor() == class && thrown.class.name() == name;
    let props: Vec<&Json> = want
        .get("props")
        .and_then(Json::as_array)
        .map(|p| p.iter().collect())
        .unwrap_or_default();
    let props_ok = props.len() == thrown.props.len()
        && props.iter().zip(&thrown.props).all(|(w, (key, value))| {
            str_of(w, "key") == *key
                && match value {
                    Prop::Undefined => w.get("undefined").is_some(),
                    Prop::Json(text) => text_field(w, "json").is_some_and(|t| same_json(text, &t)),
                }
        });
    if message_ok && class_ok && props_ok {
        return None;
    }
    Some(format!(
        "thrown {}/{} {} {:?} instead of {class}/{name} {message} {}",
        thrown.class.constructor(),
        thrown.class.name(),
        thrown
            .message
            .to_json()
            .chars()
            .take(300)
            .collect::<String>(),
        thrown.props,
        serde_json::to_string(&props).unwrap()
    ))
}

/// The machine's state tables as the replay records them (empty ones left
/// out).
fn tables_json(tables: &StateTables) -> Json {
    let mut out = Map::new();
    if !tables.adaptive.is_empty() {
        out.insert(
            "adaptive".into(),
            Json::Array(
                tables
                    .adaptive
                    .iter()
                    .map(|(key, s)| {
                        serde_json::json!([key, {
                            "timeoutCount": s.timeout_count,
                            "openUntil": s.open_until,
                            "sessionBlocked": s.session_blocked,
                        }])
                    })
                    .collect(),
            ),
        );
    }
    if !tables.myotis_slots.is_empty() {
        out.insert(
            "myotis_slots".into(),
            Json::Array(
                tables
                    .myotis_slots
                    .iter()
                    .map(|(chain, in_flight, waiting)| {
                        serde_json::json!([chain, { "in_flight": in_flight, "waiting": waiting }])
                    })
                    .collect(),
            ),
        );
    }
    if tables.colibri_in_flight > 0 {
        out.insert("colibri_in_flight".into(), tables.colibri_in_flight.into());
    }
    if !tables.colibri_routes.is_empty() {
        out.insert(
            "colibri_routes".into(),
            Json::Array(
                tables
                    .colibri_routes
                    .iter()
                    .map(|(key, n)| serde_json::json!([key, n]))
                    .collect(),
            ),
        );
    }
    if !tables.log_range.is_empty() {
        out.insert(
            "log_range".into(),
            Json::Array(
                tables
                    .log_range
                    .iter()
                    .map(|(key, e)| {
                        serde_json::json!([key, {
                            "refusedFrom": e.refused_from,
                            "capUntil": e.cap_until,
                            "slowFrom": e.slow_from,
                            "slowUntil": e.slow_until,
                            "coolUntil": e.cool_until,
                        }])
                    })
                    .collect(),
            ),
        );
    }
    if !tables.log_index_cool_until.is_empty() {
        out.insert(
            "log_index_cool_until".into(),
            Json::Array(
                tables
                    .log_index_cool_until
                    .iter()
                    .map(|(chain, at)| serde_json::json!([chain, at]))
                    .collect(),
            ),
        );
    }
    if !tables.log_index_pair_cool_until.is_empty() {
        out.insert(
            "log_index_pair_cool_until".into(),
            Json::Array(
                tables
                    .log_index_pair_cool_until
                    .iter()
                    .map(|(key, at)| serde_json::json!([key, at]))
                    .collect(),
            ),
        );
    }
    Json::Object(out)
}

/// What one scenario's replay gave.
#[derive(Default)]
struct Outcome {
    mismatches: Vec<String>,
    /// Each call's reply, by (step, call).
    replies: BTreeMap<(usize, usize), Reply>,
    /// Requests the reference never made.
    extra: Vec<String>,
    /// The reference's exchanges the machine never made.
    missing: Vec<String>,
}

const MAX_STEP_MS: u64 = 10 * 60_000;

fn replay(scenario: &Json, expect: Option<&'static Expected>) -> Outcome {
    let reconcile = expect.is_some_and(|e| e.deviation == "broadcast-outcome");
    let id = str_of(scenario, "id").to_owned();
    let world = scenario.get("world").cloned().unwrap_or(Json::Null);
    let io: Vec<Exchange> = scenario
        .get("io")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
        .filter(|e| match str_of(e, "kind") {
            "rpc" | "verified-op" => e.get("within").is_none(),
            // A Blockscout page is one `shell.blockscout`; its hops and DNS
            // lookups are main's.
            "blockscout-page" => true,
            _ => false,
        })
        .map(|e| Exchange {
            entry: e.clone(),
            used: false,
            request: None,
            cancelled: None,
            delivered: false,
        })
        .collect();
    let statuses = scenario
        .get("io")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
        .filter(|e| str_of(e, "kind") == "myotis-status")
        .map(|e| (e.clone(), false))
        .collect();
    let records = scenario
        .get("io")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    let mut driver = Driver {
        records,
        machine: Machine::new(0, Bounds::default()),
        world,
        io,
        statuses,
        tokens: BTreeMap::new(),
        next_token: 1,
        step: 0,
        slots: Vec::new(),
        owners: BTreeMap::new(),
        extra: Vec::new(),
        reconcile,
        expect,
        mismatches: Vec::new(),
        sequential: false,
        pending: Vec::new(),
        sequence: 0,
        flush: false,
    };
    driver.apply_world();
    let mut outcome = Outcome::default();
    let steps = scenario
        .get("steps")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    for (index, step) in steps.iter().enumerate() {
        let after = num(step, "after");
        if after > 0 {
            let until = driver.machine.now() + after;
            driver.drive(until, &|_| false);
        }
        if driver.machine.now() != num(step, "at") {
            driver.mismatches.push(format!(
                "{id} step {index} starts at {} instead of {}",
                driver.machine.now(),
                num(step, "at")
            ));
        }
        driver.step = index;
        if let Some(Json::Object(changes)) = step.get("world") {
            let world = driver.world.as_object_mut().unwrap();
            for (key, value) in changes {
                world.insert(key.clone(), value.clone());
            }
            driver.apply_world();
        }
        let start = driver.machine.now();
        for event in step
            .get("events")
            .and_then(Json::as_array)
            .into_iter()
            .flatten()
        {
            driver.token(start + num(event, "at"), Token::Event(event.clone()));
        }
        let calls = step
            .get("calls")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default();
        driver.sequential = step.get("driver").is_some();
        driver.slots = calls
            .iter()
            .map(|call| Slot {
                call: call.clone(),
                request: None,
                submitted: None,
                reply: None,
                resent: false,
            })
            .collect();
        if driver.sequential {
            driver.start(0);
        } else {
            for (i, call) in calls.iter().enumerate() {
                if let Some(at) = call.get("at").and_then(Json::as_u64) {
                    driver.token(start + at, Token::Start(i));
                }
            }
            for (i, call) in calls.iter().enumerate() {
                if call.get("at").is_none() {
                    driver.start(i);
                }
            }
        }
        let horizon = start + MAX_STEP_MS;
        driver.drive(horizon, &|d| d.slots.iter().all(|s| s.reply.is_some()));
        let results = step
            .get("results")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default();
        for (i, slot) in driver.slots.iter().enumerate() {
            let Some(reply) = &slot.reply else {
                driver
                    .mismatches
                    .push(format!("{id} step {index} call {i}: never settled"));
                continue;
            };
            outcome.replies.insert((index, i), reply.clone());
            if slot.submitted != Some(num(&slot.call, "started")) {
                driver.mismatches.push(format!(
                    "{id} step {index} call {i}: started at {:?} instead of {}",
                    slot.submitted,
                    num(&slot.call, "started")
                ));
            }
            let want =
                expect.and_then(|e| e.replies.iter().find(|(s, c, _, _)| *s == index && *c == i));
            match want {
                Some((_, _, settled, want)) => {
                    if let Some(problem) = compare_want(reply, *settled, want) {
                        driver
                            .mismatches
                            .push(format!("{id} step {index} call {i}: {problem}"));
                    }
                    // The deviation must change the reply.
                    if compare(reply, &results[i]).is_none() {
                        driver.mismatches.push(format!(
                            "{id} step {index} call {i}: matches the reference despite its deviation"
                        ));
                    }
                }
                None => {
                    if let Some(problem) = compare(reply, &results[i]) {
                        driver
                            .mismatches
                            .push(format!("{id} step {index} call {i}: {problem}"));
                    }
                }
            }
        }
        let tables = tables_json(&driver.machine.state_tables());
        let want = expect
            .and_then(|e| e.states.iter().find(|(s, _)| *s == index))
            .map_or_else(
                || step.get("state").cloned().unwrap_or(Json::Null),
                |(_, state)| serde_json::from_str(state).unwrap(),
            );
        if tables != want {
            driver.mismatches.push(format!(
                "{id} step {index}: state {} instead of {}",
                tables, want
            ));
        }
    }
    // Stragglers finish, so a late answer nobody waits for is consumed.
    let horizon = driver.machine.now() + MAX_STEP_MS;
    driver.drive(horizon, &|_| false);
    for exchange in &driver.io {
        let e = &exchange.entry;
        let what = describe_record(e);
        if !exchange.used {
            outcome.missing.push(what);
            continue;
        }
        // Cancellations: an exchange the reference aborted at T is cancelled
        // at T; one it let finish is never cancelled before its answer.
        let mut aborted = (str_of(e, "outcome") == "aborted").then(|| num(e, "end"));
        if let Some((_, at)) =
            expect.and_then(|x| x.cancels.iter().find(|(r, _)| *r == num(e, "id")))
        {
            aborted = *at;
        }
        // A cancel in the very tick the answer came raced it, as the
        // reference's abort of an exchange already answered did.
        let raced = aborted.is_none()
            && exchange.cancelled.is_some()
            && exchange.cancelled == e.get("end").and_then(Json::as_u64);
        if aborted != exchange.cancelled && !raced {
            driver.mismatches.push(format!(
                "{id}: {what} cancelled at {:?} instead of {aborted:?}",
                exchange.cancelled
            ));
        }
    }
    if let Some(expect) = expect {
        let want: Vec<String> = expect.extra.iter().map(|s| (*s).to_owned()).collect();
        if driver.extra != want {
            driver.mismatches.push(format!(
                "{id}: requests the reference never made {:?} instead of {want:?}",
                driver.extra
            ));
        }
        let want: Vec<String> = expect.missing.iter().map(|s| (*s).to_owned()).collect();
        if outcome.missing != want {
            driver.mismatches.push(format!(
                "{id}: the reference's requests never made {:?} instead of {want:?}",
                outcome.missing
            ));
        }
        outcome.missing.clear();
    }
    outcome.mismatches = driver.mismatches;
    outcome.extra = driver.extra;
    outcome
}

/// What a deviation's reply must be.
#[derive(Debug)]
enum Want {
    /// 0001's code: `cancelled`, `deadline`, `reconfigured`.
    Protocol(&'static str),
    /// Today's error with this message, the core's text.
    Thrown(&'static str),
    /// A read's result.
    Read(&'static str),
    /// A broadcast's `uncertain` outcome, from this broadcaster.
    Uncertain(&'static str),
}

fn compare_want(reply: &Reply, settled: u64, want: &Want) -> Option<String> {
    let ok = reply.settled == settled
        && match (want, &reply.result) {
            (Want::Protocol(code), Err(ChainError::Protocol(got))) => got.as_str() == *code,
            (Want::Thrown(message), Err(ChainError::Thrown(thrown))) => {
                thrown.message.to_string_lossy() == *message
            }
            (
                Want::Read(json),
                Ok(Success::Read {
                    result: Some(got), ..
                }),
            ) => same_json(got, json),
            (
                Want::Uncertain(source),
                Ok(Success::Broadcast {
                    outcome: BroadcastOutcome::Uncertain,
                    source: got,
                    hash: Some(_),
                }),
            ) => got == source,
            _ => false,
        };
    (!ok).then(|| {
        format!(
            "{} at {} instead of the deviation's {want:?} at {settled}",
            describe(&reply.result),
            reply.settled
        )
    })
}

/// A scenario a deviation changes, and how.
struct Expected {
    id: &'static str,
    deviation: &'static str,
    /// The replies it changes: `(step, call, settled, reply)`.
    replies: &'static [(usize, usize, u64, Want)],
    /// The state tables it changes, by step (JSON).
    states: &'static [(usize, &'static str)],
    /// Requests the machine makes that the reference didn't.
    extra: &'static [&'static str],
    /// The reference's requests the machine doesn't make.
    missing: &'static [&'static str],
    /// Exchanges cancelled at another time: `(record id, at)`.
    cancels: &'static [(u64, Option<u64>)],
    /// The deviation moves the reference's exchanges in time: they are
    /// matched whatever their start, with their delays kept.
    shifted: bool,
}

const EXPECTED: Expected = Expected {
    id: "",
    deviation: "",
    replies: &[],
    states: &[],
    extra: &[],
    missing: &[],
    cancels: &[],
    shifted: false,
};

// ---------------------------------------------------------------------------
// The scenarios.

/// Scenarios not replayed yet, by ID prefix, with what they need.
const NOT_YET: &[(&str, &str)] = &[];

/// Scenarios a deviation changes (design 0005, Deviations), each with the
/// difference it must show. The design's broadcast outcomes answer
/// `uncertain` where today throws an error; the core reconciles before
/// reporting it, and the driver answers its lookups with `null` (the
/// network doesn't know the hash).
const DEVIATIONS: &[Expected] = &[
    Expected {
        id: "router-myotis-broadcast-in-band-failure",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 0, Want::Uncertain("myotis"))],
        extra: &["colibri eth_getTransactionByHash at 0"],
        ..EXPECTED
    },
    Expected {
        id: "router-myotis-broadcast-uncertain",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 0, Want::Uncertain("myotis"))],
        extra: &["colibri eth_getTransactionByHash at 0"],
        ..EXPECTED
    },
    // Design 0005, Cancellation: a cancel ends a read at once. The reference
    // throws its AbortError only once Myotis's read settles; the slot stays
    // taken until then in both.
    Expected {
        id: "cancel-read-no-fallthrough",
        deviation: "cancellation",
        replies: &[(0, 0, 10, Want::Protocol("cancelled"))],
        states: &[(0, r#"{"myotis_slots":[[100,{"in_flight":1,"waiting":0}]]}"#)],
        ..EXPECTED
    },
    // A cancelled broadcast with an attempt that may have been sent is
    // uncertain, at once.
    Expected {
        id: "cancel-broadcast-no-fallthrough",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 10, Want::Uncertain("myotis"))],
        ..EXPECTED
    },
    Expected {
        id: "cancel-broadcast-later-timeout-wins",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 5000, Want::Uncertain("direct"))],
        extra: &[
            "rpc https://a.example eth_getTransactionByHash at 5000",
            "rpc https://b.example eth_getTransactionByHash at 5000",
        ],
        ..EXPECTED
    },
    Expected {
        id: "cancel-broadcast-no-second-rpc",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 10, Want::Uncertain("direct"))],
        ..EXPECTED
    },
    Expected {
        id: "boundary-broadcast-last-error-wins",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 0, Want::Uncertain("direct"))],
        extra: &[
            "rpc https://a.example eth_getTransactionByHash at 0",
            "rpc https://b.example eth_getTransactionByHash at 0",
        ],
        ..EXPECTED
    },
    Expected {
        id: "boundary-broadcast-lost-reply-then-already-known",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 5000, Want::Uncertain("direct"))],
        extra: &[
            "rpc https://a.example eth_getTransactionByHash at 5000",
            "rpc https://b.example eth_getTransactionByHash at 5000",
        ],
        ..EXPECTED
    },
    Expected {
        id: "boundary-broadcast-lost-reply-then-nonce-too-low",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 5000, Want::Uncertain("direct"))],
        extra: &[
            "rpc https://a.example eth_getTransactionByHash at 5000",
            "rpc https://b.example eth_getTransactionByHash at 5000",
        ],
        ..EXPECTED
    },
    Expected {
        id: "boundary-broadcast-refusal-after-ambiguous",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 0, Want::Uncertain("direct"))],
        extra: &[
            "rpc https://a.example eth_getTransactionByHash at 0",
            "rpc https://b.example eth_getTransactionByHash at 0",
        ],
        ..EXPECTED
    },
    Expected {
        id: "boundary-broadcast-other-hash-accepted",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 0, Want::Uncertain("direct"))],
        extra: &["rpc https://a.example eth_getTransactionByHash at 0"],
        ..EXPECTED
    },
    Expected {
        id: "boundary-broadcast-cancel-after-send",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 1000, Want::Uncertain("direct"))],
        ..EXPECTED
    },
    Expected {
        id: "boundary-broadcast-myotis-uncertain-in-band",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 0, Want::Uncertain("myotis"))],
        extra: &["rpc https://a.example eth_getTransactionByHash at 0"],
        ..EXPECTED
    },
    Expected {
        id: "boundary-broadcast-myotis-odd-payload",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 0, Want::Uncertain("myotis"))],
        extra: &["rpc https://a.example eth_getTransactionByHash at 0"],
        ..EXPECTED
    },
    // The change at 1000 ends the read (`reconfigured`) and cancels its
    // members; main sends it again under the new configuration, whose
    // quorum (a, b, c of a, b, c, e) hangs until 6000, when Direct asks e.
    Expected {
        id: "boundary-registry-change-mid-request",
        deviation: "config-change",
        replies: &[(0, 0, 6000, Want::Read(r#""0xnew""#))],
        extra: &[
            "rpc https://a.example eth_call at 1000",
            "rpc https://b.example eth_call at 1000",
            "rpc https://c.example eth_call at 1000",
        ],
        cancels: &[(0, Some(1000)), (1, Some(1000)), (2, Some(1000))],
        shifted: true,
        ..EXPECTED
    },
    Expected {
        id: "boundary-order-duplicates-and-unknown",
        deviation: "order-validation",
        replies: &[(
            0,
            0,
            0,
            Want::Thrown(
                "All chain sources failed for eth_call (colibri: No Colibri prover configured; direct: No RPC endpoint configured)",
            ),
        )],
        ..EXPECTED
    },
    // Nesting of 513 levels is refused (the reference agreed on it): every
    // member fails.
    Expected {
        id: "boundary-json-depth-513",
        deviation: "json-depth",
        replies: &[(
            0,
            0,
            0,
            Want::Thrown(
                "All chain sources failed for eth_call (quorum: RPC quorum did not reach 2 matching responses)",
            ),
        )],
        ..EXPECTED
    },
];

/// The score: scenarios replayed exactly (deviation scenarios with their
/// asserted difference included), and those not replayed yet.
const PASSING: usize = 297;
const NOT_REPLAYED: usize = 0;

#[test]
// The score is the test's report, printed with `--nocapture`.
#[allow(clippy::print_stderr)]
fn replays_match_the_reference() {
    let vectors = vectors();
    let scenarios = vectors.get("scenarios").and_then(Json::as_array).unwrap();
    let mut report = Vec::new();
    let mut passed = 0;
    let mut deviating = 0;
    let mut skipped: BTreeMap<&str, usize> = BTreeMap::new();
    for expect in DEVIATIONS {
        assert!(
            scenarios.iter().any(|s| str_of(s, "id") == expect.id),
            "no scenario {}",
            expect.id
        );
    }
    for scenario in scenarios {
        let id = str_of(scenario, "id");
        if let Some((prefix, _)) = NOT_YET.iter().find(|(p, _)| id.starts_with(p)) {
            *skipped.entry(prefix).or_default() += 1;
            continue;
        }
        let expect = DEVIATIONS.iter().find(|e| e.id == id);
        let outcome = replay(scenario, expect);
        if outcome.mismatches.is_empty() && outcome.missing.is_empty() {
            passed += 1;
            deviating += usize::from(expect.is_some());
        } else {
            report.push(format!(
                "== {id}\n{}\n{}",
                outcome.mismatches.join("\n"),
                outcome
                    .missing
                    .iter()
                    .map(|m| format!("never made: {m}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }
    }
    let skipped_total: usize = skipped.values().sum();
    eprintln!(
        "chain replay: {passed} passed ({deviating} of them with their deviation's difference), \
         {skipped_total} not yet replayed ({skipped:?}), {} failed",
        report.len()
    );
    assert!(report.is_empty(), "{}", report.join("\n"));
    assert_eq!((passed, skipped_total), (PASSING, NOT_REPLAYED));
}
