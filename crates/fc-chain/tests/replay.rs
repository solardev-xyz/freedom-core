//! Replays `vectors/chain-replay.json` through the chain machine (design
//! 0005, Replay). The driver plays main: it configures the machine from each
//! scenario's world, starts the calls when the reference started them, and
//! answers each I/O request with the answer the reference's matching
//! exchange or verifier operation got, at the time it got it.
//!
//! Compared exactly:
//! - every I/O request the core owns (`shell.rpc` endpoint and body,
//!   verifier operation and params, Blockscout page), its start, and its
//!   place in the reference's order: no request answers an earlier record
//!   than one already matched;
//! - every cancel: an exchange the reference aborted at T is cancelled at
//!   T, and no other is cancelled, except in the permitted races
//!   ([`Race`], counted in [`RACES`]). Main never delivers an answer the
//!   machine cancelled first;
//! - every result and error (key order, constructor, name, message, own
//!   properties, `-0` and UTF-16 strings), and its settle time;
//! - the state tables each step records.
//!
//! Scenarios the machine doesn't serve yet are skipped by ID prefix through
//! [`NOT_YET`], never silently; scenarios a deviation changes are listed in
//! [`DEVIATIONS`] with the difference they must show, stated whole.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use fc_chain::JsString;
use fc_chain::MyotisOperation;
use fc_chain::machine::{
    Answer, Bounds, BroadcastOutcome, Call, CapReader, ChainConfig, ChainError, ColibriClass,
    ColibriReply, Effect, Emitted, Fired, Machine, MyotisClass, MyotisRejection, MyotisReply, Prop,
    Protocol, Prover, QuorumConfig, Ranker, ReadOptions, Reply, Request, RpcEndpoint, StateTables,
    Success, Thrown, Transport, VerifiedOp,
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
                                Some(h) => Some(fc_json::JsValue::string(h)),
                                None => Some(entry.clone()),
                            })
                            .collect(),
                    )
                }
                ("prover", entry) => host(entry).map_or(item.clone(), fc_json::JsValue::string),
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

/// `isCapacityFailure(error)`, which main classes a Colibri failure by: an
/// error whose `failureKind` is `capacity`, or whose `safeErrorMessage`
/// (hex elided, whitespace collapsed, cut at 500 UTF-16 units) matches the
/// pattern.
fn capacity(thrown: &Json) -> bool {
    let kind = thrown_prop(thrown, "failureKind")
        .and_then(|e| e.get("json"))
        .and_then(Json::as_str);
    if kind == Some(r#""capacity""#) {
        return true;
    }
    let message_json = str_of(thrown, "message_json");
    let units: Vec<u16> = Index::new(message_json)
        .ok()
        .map(|index| index.root().units().collect())
        .unwrap_or_default();
    let safe = fc_chain::safe_error_message(str_of(thrown, "name"), &units);
    regex::Regex::new(
        r"(?i-u)out of gas|execution (?:gas|resource) limit|exceeds? (?:the )?(?:gas|execution) limit",
    )
    .unwrap()
    .is_match(&safe.to_string_lossy())
}

/// Main's `isColibriFault(error)` (freedom-browser 94b0af4e), which marks
/// a Colibri failure or revert `fault` (design 0005, The rest): not one the
/// worker host marked `colibriBystander`, and a `RuntimeError` by name or
/// the pattern on the raw message.
fn fault(thrown: &Json) -> bool {
    let bystander = thrown_prop(thrown, "colibriBystander")
        .and_then(|e| e.get("json"))
        .and_then(Json::as_str)
        .is_some_and(|json| !matches!(json, "false" | "null" | "0" | "-0" | r#""""#));
    if bystander {
        return false;
    }
    str_of(thrown, "name") == "RuntimeError"
        || regex::Regex::new(
            r"(?i-u)memory access out of bounds|(?:^|: )unreachable(?: executed)?$|retired after a trap|Colibri worker replaced",
        )
        .unwrap()
        .is_match(&thrown_message(thrown))
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
        // `{ undefined_keys: ["result"] }`: the adapter resolved `undefined`.
        if answer.get("result_undefined").and_then(Json::as_bool) == Some(true) {
            return Some(Answer::Colibri(ColibriReply::Undefined));
        }
        let thrown = answer.get("thrown")?;
        let code = thrown_prop(thrown, "code")
            .and_then(|e| e.get("json"))
            .and_then(Json::as_str);
        let data = thrown_prop(thrown, "data")
            .and_then(|e| e.get("json"))
            .and_then(Json::as_str)
            .and_then(|t| serde_json::from_str::<String>(t).ok());
        // A verified revert, with `capacity: true` when main's
        // `isCapacityFailure` also holds for the error, and `fault: true`
        // when its `isColibriFault` does.
        if code == Some("3")
            && let Some(data) = data.filter(|d| is_hex_data(d))
        {
            return Some(Answer::Colibri(ColibriReply::Revert {
                data,
                capacity: capacity(thrown),
                fault: fault(thrown),
            }));
        }
        let class = if capacity(thrown) {
            ColibriClass::Capacity
        } else {
            ColibriClass::Error
        };
        return Some(Answer::Colibri(ColibriReply::Failure {
            class,
            fault: fault(thrown),
        }));
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
                kind: MyotisRejection::Rejected,
            },
            "invalid_params" => MyotisReply::Rejected {
                reason: thrown_message(thrown),
                kind: MyotisRejection::InvalidParams,
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
    /// Its place in the reference's ledger.
    seq: usize,
    used: bool,
    /// The machine's I/O id that this record answers.
    request: Option<u64>,
    /// When the machine cancelled it, before its answer, and what the
    /// driver had just done.
    cancelled: Option<(u64, Cause)>,
    delivered: bool,
}

/// What the driver did last before the machine ran: what a cancel the
/// machine then made followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cause {
    /// A call started, or main sent it again.
    Start,
    /// An answer was delivered at `at` to the I/O of call `owner` that
    /// started at `started` (the reference's record's start, when it has
    /// one).
    Delivered {
        at: u64,
        owner: (u64, u64),
        started: Option<u64>,
    },
    /// One of the machine's own timers fired at `at`.
    Timer(u64),
    /// A scripted event, or a caller's abort.
    External,
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
    /// Machine I/O id → the (step, call) that made it.
    owner_of_io: BTreeMap<u64, (usize, usize)>,
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
    /// What the driver did last.
    cause: Cause,
    /// The ledger's latest entry matched so far: the machine's requests
    /// come in the reference's order.
    last_matched: Option<usize>,
    /// Answers the machine cancelled before main delivered them: main
    /// aborted them, and they never reach the machine.
    withheld: usize,
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
        self.cause = Cause::Start;
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
                self.cause = Cause::Start;
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
            // The poll's effects first: its cancels followed what the
            // driver did before it, not the calls its replies start.
            self.process_effects();
            let started = self.collect_replies();
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

    /// Main delivers an answer, unless the machine cancelled the exchange
    /// first: main aborted it then, and nothing reaches the machine.
    fn deliver(&mut self, id: u64, answer: Answer) {
        let now = self.machine.now();
        if let Some(exchange) = self.io.iter_mut().find(|e| e.request == Some(id)) {
            if exchange.cancelled.is_some() {
                self.withheld += 1;
                return;
            }
            exchange.delivered = true;
            let owner = (num(&exchange.entry, "step"), num(&exchange.entry, "call"));
            let started = Some(num(&exchange.entry, "t"));
            self.cause = Cause::Delivered {
                at: now,
                owner,
                started,
            };
        } else {
            let owner = self
                .owner_of_io
                .get(&id)
                .map_or((u64::MAX, u64::MAX), |&(s, c)| (s as u64, c as u64));
            self.cause = Cause::Delivered {
                at: now,
                owner,
                started: None,
            };
        }
        self.machine.complete(id, answer);
    }

    fn fired(&mut self, fired: Fired) {
        let Fired::External(token) = fired else {
            self.cause = Cause::Timer(self.machine.now());
            return;
        };
        match self.tokens.remove(&token) {
            Some(Token::Deliver(id, answer)) => self.deliver(id, answer),
            Some(Token::Event(event)) => {
                self.cause = Cause::External;
                self.event(&event);
            }
            Some(Token::Start(i)) => self.start(i),
            Some(Token::Abort(i)) => {
                self.cause = Cause::External;
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
                        exchange.cancelled = Some((at, self.cause));
                    }
                }
                Effect::Request {
                    id,
                    at,
                    request: io,
                    ..
                } => {
                    let owner = request.and_then(|r| self.owners.get(&r).copied());
                    if let Some(owner) = owner {
                        self.owner_of_io.insert(id, owner);
                    }
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
        let moved = self.expect.map_or(&[][..], |e| e.moved);
        let start_of = |entry: &Json| {
            let record = num(entry, "id");
            moved
                .iter()
                .find(|(r, _)| *r == record)
                .map_or_else(|| num(entry, "t"), |(_, t)| *t)
        };
        let matches = |entry: &Json| {
            start_of(entry) == at
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
        // The reference's order: no request answers a record earlier in
        // the ledger than one already matched.
        let seq = self.io[index].seq;
        if let Some(last) = self.last_matched.filter(|last| seq < *last) {
            self.mismatches.push(format!(
                "out of the reference's order: {} is ledger entry {seq}, made after entry {last}",
                describe_request(io, at)
            ));
        }
        self.last_matched = Some(self.last_matched.map_or(seq, |last| last.max(seq)));
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

/// A request, as the deviation lists name it: what it asks, whole, and
/// when.
fn describe_request(io: &Request, at: u64) -> String {
    match io {
        Request::Rpc { endpoint, body, .. } => {
            format!("rpc {endpoint} at {at} {}", normalized_body(body))
        }
        Request::Verified(op) => {
            let (host, name, chain, params) = verified_params(op);
            format!("{host} {name} chain {chain} at {at} {params}")
        }
        Request::Blockscout {
            endpoint, query, ..
        } => format!("blockscout {endpoint}{query} at {at}"),
    }
}

/// A recorded exchange, as the deviation lists name it: what it asked,
/// whole, and when.
fn describe_record(entry: &Json) -> String {
    let t = num(entry, "t");
    match str_of(entry, "kind") {
        "rpc" => format!(
            "rpc {} at {t} {}",
            str_of(entry, "url"),
            text_field(entry, "body").unwrap_or_default()
        ),
        "blockscout-page" => format!("blockscout {} at {t}", str_of(entry, "url")),
        _ => format!(
            "{} {} chain {} at {t} {}",
            str_of(entry, "host"),
            str_of(entry, "op"),
            num(entry, "chain"),
            text_field(entry, "params_json").unwrap_or_default()
        ),
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

/// The reference's route keys as the core keeps them: a target listing
/// more than one address is its SHA-256 (`memory-budgets`, design 0005,
/// Adaptive bypass), computed here on its own.
fn canonical_route_keys(state: &mut Json) {
    use sha2::{Digest as _, Sha256};
    for table in ["adaptive", "colibri_routes"] {
        let Some(entries) = state.get_mut(table).and_then(Json::as_array_mut) else {
            continue;
        };
        for entry in entries {
            let Some(key) = entry.get(0).and_then(Json::as_str) else {
                continue;
            };
            let mut parts: Vec<Json> = serde_json::from_str(key).unwrap();
            let Some(Json::String(target)) = parts.last_mut() else {
                continue;
            };
            if !target.contains(',') {
                continue;
            }
            *target = format!("sha256:{}", hex::encode(Sha256::digest(target.as_bytes())));
            entry[0] = Json::String(serde_json::to_string(&parts).unwrap());
        }
    }
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
    // The `tx-lookups` reference patch's table (design 0005, Main's #752).
    if !tables.colibri_faults.is_empty() {
        out.insert(
            "colibri_faults".into(),
            Json::Array(
                tables
                    .colibri_faults
                    .iter()
                    .map(|(key, record)| {
                        serde_json::json!([key, {
                            "faults": record.faults,
                            "strikes": record.strikes,
                            "coolUntil": record.cool_until,
                        }])
                    })
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
    /// The permitted races between a cancel and an answer.
    races: Vec<Race>,
    /// Answers main withheld: the machine had cancelled their exchange.
    withheld: usize,
}

/// A cancel that crossed an answer in the same tick: the reference's
/// exchange settled at that instant, and its abort, made then, changed
/// nothing; the machine's cancel came first, and main withheld the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Race {
    /// A quorum member, cancelled when another member's answer, delivered
    /// to the same call in that tick, settled the round.
    QuorumTail,
    /// A Blockscout page, cancelled by the scan's deadline in the tick its
    /// own fetch failed with `no answer within`.
    PageDeadline,
}

/// Whether a cancel at `at`, made after `cause`, is a permitted race with
/// the record `e` (one the reference let settle at `at`).
fn race(e: &Json, at: u64, cause: Cause) -> Option<Race> {
    if e.get("end").and_then(Json::as_u64) != Some(at) {
        return None;
    }
    let owner = (num(e, "step"), num(e, "call"));
    match (str_of(e, "kind"), str_of(e, "outcome"), cause) {
        (
            "rpc",
            "answered" | "failed",
            Cause::Delivered {
                at: when,
                owner: by,
                started,
            },
        ) if when == at && by == owner && started == Some(num(e, "t")) => Some(Race::QuorumTail),
        ("blockscout-page", "failed", Cause::Timer(when))
            if when == at
                && e.get("answer")
                    .and_then(|a| a.get("thrown"))
                    .is_some_and(|t| thrown_message(t).starts_with("no answer within")) =>
        {
            Some(Race::PageDeadline)
        }
        _ => None,
    }
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
        .enumerate()
        .filter(|(_, e)| match str_of(e, "kind") {
            "rpc" | "verified-op" => e.get("within").is_none(),
            // A Blockscout page is one `shell.blockscout`; its hops and DNS
            // lookups are main's.
            "blockscout-page" => true,
            _ => false,
        })
        .map(|(seq, e)| Exchange {
            entry: e.clone(),
            seq,
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
        owner_of_io: BTreeMap::new(),
        extra: Vec::new(),
        reconcile,
        expect,
        mismatches: Vec::new(),
        sequential: false,
        pending: Vec::new(),
        sequence: 0,
        flush: false,
        cause: Cause::Start,
        last_matched: None,
        withheld: 0,
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
                    if let Some(problem) = compare_want(reply, *settled, want, &slot.call) {
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
        let mut want = expect
            .and_then(|e| e.states.iter().find(|(s, _)| *s == index))
            .map_or_else(
                || step.get("state").cloned().unwrap_or(Json::Null),
                |(_, state)| serde_json::from_str(state).unwrap(),
            );
        canonical_route_keys(&mut want);
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
        // at T; one it let finish is never cancelled before its answer,
        // except in a permitted race ([`Race`]). A Blockscout page the
        // caller's abort ended records the `AbortError` it failed with.
        let abort_error = e
            .get("answer")
            .and_then(|a| a.get("thrown"))
            .is_some_and(|t| str_of(t, "name") == "AbortError");
        let mut aborted = (str_of(e, "outcome") == "aborted"
            || (str_of(e, "kind") == "blockscout-page" && abort_error))
            .then(|| num(e, "end"));
        if let Some((_, at)) =
            expect.and_then(|x| x.cancels.iter().find(|(r, _)| *r == num(e, "id")))
        {
            aborted = *at;
        }
        let cancelled = exchange.cancelled.map(|(at, _)| at);
        let race = aborted
            .is_none()
            .then(|| {
                exchange
                    .cancelled
                    .and_then(|(at, cause)| race(e, at, cause))
            })
            .flatten();
        if let Some(race) = race {
            outcome.races.push(race);
        } else if aborted != cancelled {
            driver.mismatches.push(format!(
                "{id}: {what} cancelled at {cancelled:?} ({:?}) instead of {aborted:?}",
                exchange.cancelled.map(|(_, cause)| cause)
            ));
        }
    }
    if let Some(expect) = expect {
        // `{hash}` stands for the broadcast's transaction hash.
        let hash = broadcast_raw(scenario).map(|raw| keccak_hash(&raw));
        let want: Vec<String> = expect
            .extra
            .iter()
            .map(|s| s.replace("{hash}", hash.as_deref().unwrap_or("{hash}")))
            .collect();
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
    outcome.withheld = driver.withheld;
    outcome
}

/// What a deviation's reply must be, whole: every field it doesn't change
/// is stated too.
#[derive(Debug)]
enum Want {
    /// 0001's code (`cancelled`, `deadline`, `reconfigured`) for a read or
    /// a fee quote: no broadcast outcome.
    Protocol(&'static str),
    /// An error: its constructor, `name`, message and own properties in
    /// order (each `(key, JSON)`); no broadcast outcome.
    Thrown {
        class: &'static str,
        name: &'static str,
        message: &'static str,
        props: &'static [(&'static str, &'static str)],
    },
    /// A read's answer: its result (JSON), source, `verified` and trust.
    Read {
        result: &'static str,
        source: &'static str,
        verified: bool,
        trust: Option<&'static str>,
    },
    /// A broadcast's `uncertain` outcome from this broadcaster, reporting
    /// the transaction's hash: keccak256 of the call's raw bytes.
    Uncertain(&'static str),
    /// A fee quote, whole, as JSON in the router's key order.
    Quote(&'static str),
}

/// keccak256 of a raw transaction's bytes, as `0x` and lowercase hex.
fn keccak_hash(raw: &str) -> String {
    use sha3::{Digest as _, Keccak256};
    let bytes = hex::decode(raw.trim_start_matches("0x")).unwrap();
    format!("0x{}", hex::encode(Keccak256::digest(bytes)))
}

/// The first broadcast's raw bytes in a scenario.
fn broadcast_raw(scenario: &Json) -> Option<String> {
    scenario
        .get("steps")?
        .as_array()?
        .iter()
        .filter_map(|step| step.get("calls").and_then(Json::as_array))
        .flatten()
        .find(|call| str_of(call, "fn") == "broadcastRawTransaction")
        .map(|call| str_of(call, "raw").to_owned())
}

fn compare_want(reply: &Reply, settled: u64, want: &Want, call: &Json) -> Option<String> {
    let shape = match (want, &reply.result) {
        (Want::Protocol(code), Err(ChainError::Protocol(got))) => {
            got.as_str() == *code && reply.outcome.is_none()
        }
        (
            Want::Thrown {
                class,
                name,
                message,
                props,
            },
            Err(ChainError::Thrown(thrown)),
        ) => {
            reply.outcome.is_none()
                && thrown.class.constructor() == *class
                && thrown.class.name() == *name
                && same_json(
                    &thrown.message.to_json(),
                    &JsString::from(*message).to_json(),
                )
                && thrown.props.len() == props.len()
                && thrown
                    .props
                    .iter()
                    .zip(props.iter())
                    .all(|((key, value), (k, v))| {
                        key == k && matches!(value, Prop::Json(text) if same_json(text, v))
                    })
        }
        (
            Want::Read {
                result,
                source,
                verified,
                trust,
            },
            Ok(Success::Read {
                result: Some(got),
                source: got_source,
                verified: got_verified,
                trust: got_trust,
            }),
        ) => {
            same_json(got, result)
                && got_source == source
                && got_verified == verified
                && match (got_trust, trust) {
                    (None, None) => true,
                    (Some(got), Some(want)) => same_json(&publish_trust(got), want),
                    _ => false,
                }
        }
        (
            Want::Uncertain(source),
            Ok(Success::Broadcast {
                outcome: BroadcastOutcome::Uncertain,
                source: got,
                hash: Some(hash),
            }),
        ) => reply.outcome.is_none() && got == source && *hash == keccak_hash(str_of(call, "raw")),
        (Want::Quote(want), Ok(Success::FeeQuote(quote))) => {
            reply.outcome.is_none() && quote.to_json() == *want
        }
        _ => false,
    };
    (!(shape && reply.settled == settled)).then(|| {
        format!(
            "{} {:?} at {} instead of the deviation's {want:?} at {settled}",
            describe(&reply.result),
            reply.outcome,
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
    /// Exchanges the deviation moves in time: `(record id, start)`. Their
    /// answers keep their delays.
    moved: &'static [(u64, u64)],
}

const EXPECTED: Expected = Expected {
    id: "",
    deviation: "",
    replies: &[],
    states: &[],
    extra: &[],
    missing: &[],
    cancels: &[],
    moved: &[],
};

// ---------------------------------------------------------------------------
// The scenarios.

/// Scenarios not replayed yet, by ID prefix, with what they need.
const NOT_YET: &[(&str, &str)] = &[];

/// Scenarios a deviation changes (design 0005, Deviations), each with the
/// difference it must show, whole. The design's broadcast outcomes answer
/// `uncertain` where today throws an error; the core reconciles before
/// reporting it, and the driver answers its lookups with `null` (the
/// network doesn't know the hash). In the requests the reference never
/// made, `{hash}` stands for the broadcast's transaction hash, keccak256
/// of its raw bytes.
const DEVIATIONS: &[Expected] = &[
    Expected {
        id: "router-myotis-broadcast-in-band-failure",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 0, Want::Uncertain("myotis"))],
        // A transaction lookup: Direct before Colibri, and its `null` is
        // final (design 0005, Colibri: transaction lookups).
        extra: &[
            r#"rpc https://rpc.example at 0 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
        ],
        ..EXPECTED
    },
    Expected {
        id: "router-myotis-broadcast-uncertain",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 0, Want::Uncertain("myotis"))],
        extra: &[
            r#"rpc https://rpc.example at 0 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
        ],
        ..EXPECTED
    },
    // A cancel ends a read at once. The reference throws its AbortError only
    // once Myotis's read settles; the slot stays taken until then in both.
    Expected {
        id: "cancel-read-no-fallthrough",
        deviation: "cancel-promptly",
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
            r#"rpc https://a.example at 5000 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
            r#"rpc https://b.example at 5000 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
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
            r#"rpc https://a.example at 0 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
            r#"rpc https://b.example at 0 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
        ],
        ..EXPECTED
    },
    Expected {
        id: "boundary-broadcast-lost-reply-then-already-known",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 5000, Want::Uncertain("direct"))],
        extra: &[
            r#"rpc https://a.example at 5000 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
            r#"rpc https://b.example at 5000 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
        ],
        ..EXPECTED
    },
    Expected {
        id: "boundary-broadcast-lost-reply-then-nonce-too-low",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 5000, Want::Uncertain("direct"))],
        extra: &[
            r#"rpc https://a.example at 5000 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
            r#"rpc https://b.example at 5000 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
        ],
        ..EXPECTED
    },
    Expected {
        id: "boundary-broadcast-refusal-after-ambiguous",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 0, Want::Uncertain("direct"))],
        extra: &[
            r#"rpc https://a.example at 0 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
            r#"rpc https://b.example at 0 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
        ],
        ..EXPECTED
    },
    Expected {
        id: "boundary-broadcast-other-hash-accepted",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 0, Want::Uncertain("direct"))],
        extra: &[
            r#"rpc https://a.example at 0 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
        ],
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
        extra: &[
            r#"rpc https://a.example at 0 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
        ],
        ..EXPECTED
    },
    Expected {
        id: "boundary-broadcast-myotis-odd-payload",
        deviation: "broadcast-outcome",
        replies: &[(0, 0, 0, Want::Uncertain("myotis"))],
        extra: &[
            r#"rpc https://a.example at 0 {"jsonrpc":"2.0","id":0,"method":"eth_getTransactionByHash","params":["{hash}"]}"#,
        ],
        ..EXPECTED
    },
    // The change at 1000 ends the read (`reconfigured`) and cancels its
    // members; main sends it again under the new configuration, whose
    // quorum (a, b, c of a, b, c, e) hangs until 6000, when Direct asks e.
    Expected {
        id: "boundary-registry-change-mid-request",
        deviation: "config-change",
        replies: &[(
            0,
            0,
            6000,
            Want::Read {
                result: r#""0xnew""#,
                source: "direct",
                verified: false,
                trust: None,
            },
        )],
        extra: &[
            r#"rpc https://a.example at 1000 {"jsonrpc":"2.0","id":0,"method":"eth_call","params":[{"to":"0xabc"},"latest"]}"#,
            r#"rpc https://b.example at 1000 {"jsonrpc":"2.0","id":0,"method":"eth_call","params":[{"to":"0xabc"},"latest"]}"#,
            r#"rpc https://c.example at 1000 {"jsonrpc":"2.0","id":0,"method":"eth_call","params":[{"to":"0xabc"},"latest"]}"#,
        ],
        cancels: &[(0, Some(1000)), (1, Some(1000)), (2, Some(1000))],
        moved: &[(4, 6000)],
        ..EXPECTED
    },
    Expected {
        id: "boundary-order-duplicates-and-unknown",
        deviation: "order-validation",
        replies: &[(
            0,
            0,
            0,
            Want::Thrown {
                class: "Error",
                name: "Error",
                message: "All chain sources failed for eth_call (colibri: No Colibri prover configured; direct: No RPC endpoint configured)",
                props: &[],
            },
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
            Want::Thrown {
                class: "Error",
                name: "Error",
                message: "All chain sources failed for eth_call (quorum: RPC quorum did not reach 2 matching responses)",
                props: &[],
            },
        )],
        ..EXPECTED
    },
    // A verified revert that is also a capacity failure: rebuilt as
    // `execution reverted` with its code and data, where the reference
    // rethrows the adapter's error with its own text. The route is blocked
    // alike, so the same call again never asks Colibri.
    // Colibri's own error, with no RPC error to prefer, reaches the caller
    // with the core's fixed text, which is main's too since #681 (design
    // 0005, Main's #752); the pinned router rethrows the adapter's.
    Expected {
        id: "tx-lookup-all-sources-fail",
        deviation: "adapter-error-text",
        replies: &[(
            1,
            0,
            0,
            Want::Thrown {
                class: "Error",
                name: "Error",
                message: "Colibri request failed",
                props: &[],
            },
        )],
        ..EXPECTED
    },
    Expected {
        id: "boundary-colibri-revert-capacity",
        deviation: "adapter-error-text",
        replies: &[(
            0,
            0,
            0,
            Want::Thrown {
                class: "Error",
                name: "Error",
                message: "execution reverted",
                props: &[("code", "3"), ("data", r#""0x""#)],
            },
        )],
        ..EXPECTED
    },
    // An endpoint listed twice is one member (#90): a and b disagree, so
    // the quorum misses and Direct reuses a's answer, unverified. The
    // reference counted a twice, verified. Its second exchange with a is
    // never made.
    Expected {
        id: "boundary-quorum-duplicate-endpoint",
        deviation: "endpoint-dedup",
        replies: &[(
            0,
            0,
            100,
            Want::Read {
                result: r#""0xdead""#,
                source: "direct",
                verified: false,
                trust: Some(
                    r#"{"level":"unverified","method":"direct","block":null,"agreed":["a.example"],"dissented":["b.example"],"queried":["a.example","b.example"],"quorum":{"k":2,"m":2,"achieved":false}}"#,
                ),
            },
        )],
        missing: &[
            r#"rpc https://a.example at 0 {"jsonrpc":"2.0","id":0,"method":"eth_call","params":[{"to":"0xabc"},"latest"]}"#,
        ],
        ..EXPECTED
    },
    // A quorum with m = 1 is one endpoint's answer (#91): the same
    // requests and result, labelled as Direct would label a's answer, and
    // the fee quote it makes unverified. The reference called all three
    // verified.
    Expected {
        id: "boundary-quorum-singleton-not-verified",
        deviation: "singleton-quorum",
        replies: &[
            (
                0,
                0,
                100,
                Want::Read {
                    result: r#""0x1""#,
                    source: "quorum",
                    verified: false,
                    trust: Some(
                        r#"{"level":"unverified","method":"quorum","block":null,"agreed":["a.example"],"dissented":[],"queried":["a.example","b.example","c.example"],"quorum":{"k":3,"m":1,"achieved":true}}"#,
                    ),
                },
            ),
            (
                1,
                0,
                200,
                Want::Read {
                    result: r#""0x1""#,
                    source: "quorum",
                    verified: false,
                    trust: Some(
                        r#"{"level":"user-configured","method":"quorum","block":null,"agreed":["a.example"],"dissented":[],"queried":["a.example","b.example","c.example"],"quorum":{"k":3,"m":1,"achieved":true}}"#,
                    ),
                },
            ),
            (
                2,
                0,
                400,
                Want::Quote(
                    r#"{"type":"eip1559","baseFee":"15","maxPriorityFeePerGas":"1","maxFeePerGas":"31","effectiveGasPrice":"16","source":"quorum","verified":false}"#,
                ),
            ),
        ],
        ..EXPECTED
    },
];

/// The score: scenarios replayed exactly (deviation scenarios with their
/// asserted difference included), and those not replayed yet.
const PASSING: usize = 331;
const NOT_REPLAYED: usize = 0;
/// The permitted races, counted: each is a cancel the machine made in the
/// tick the reference's exchange settled, after what [`race`] names. Main
/// withholds each quorum member's answer; a page's deadline failure is the
/// machine's own timer.
const RACES: &[(Race, usize)] = &[(Race::QuorumTail, 128), (Race::PageDeadline, 4)];

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
    let mut races: BTreeMap<Race, usize> = BTreeMap::new();
    let mut withheld = 0;
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
        for race in &outcome.races {
            *races.entry(*race).or_default() += 1;
        }
        withheld += outcome.withheld;
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
         {skipped_total} not yet replayed ({skipped:?}), {} failed; races {races:?}, \
         {withheld} answers withheld",
        report.len()
    );
    assert!(report.is_empty(), "{}", report.join("\n"));
    assert_eq!((passed, skipped_total), (PASSING, NOT_REPLAYED));
    assert_eq!(races.into_iter().collect::<Vec<_>>(), RACES);
    assert_eq!(withheld, RACES[0].1);
}
