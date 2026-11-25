//! The test as main for design 0015's `swarm.request` (SWM-4): the real
//! binary at protocol 2, the Swarm grants moved, and a scripted main that
//! answers the swarm thread's requests from a case of `vectors/swarm.json`
//! through fc-swarm-provider's own case harness ([`logic`]): its world (the
//! grants, custody, the name), its fake node under main's rules, its
//! readiness and its session.
//!
//! One core plays every case (D11): `test.swarm_world` sets the swarm
//! thread's world between them (its read budgets and tags' owners afresh,
//! its `Date.now()`, the grants), and answers what the thread holds, so
//! each step ends with no charge held and no request left.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use base64::Engine as _;
use fc_json::JsString;
use fc_json::index::Value as V;
use fc_swarm_provider::machine::{
    Abort, Body, Event, Failed, Failure, FeedRef, Form, NodeCall, Outcome, ReadyCheck,
    Subscription, SubscriptionKind, TreeRef,
};
use fc_swarm_provider::value::Value as Typed;
use serde_json::{Value, json};

use crate::common::{
    Core, KIND_ABORT, KIND_DATA, KIND_END, KIND_STREAM_CREDIT, Wire, dirs, spawn_env, stream_frame,
};

#[path = "../../../fc-swarm-provider/tests/common/mod.rs"]
pub mod logic;

use logic::{Logged, Node, TestWorld};

/// A name-keyed document's name: a DNS name served over IPNS.
pub const NAME: &str = "docs.example.org";
/// The IPNS key the name serves.
pub const IPNS_KEY: &str = "k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8";
/// `IPNS_KEY`'s contenthash, as ENS stores it.
const IPNS_CONTENTHASH: &str =
    "e5010172002408011220e4680b2f8c8d21090e6aa327f1bb342ab8e7d9238f1e35831a54d6a8f5c91124";
/// Another IPNS key's contenthash: the name moved.
const OTHER_CONTENTHASH: &str =
    "e5010172002408011220000000000000000000000000000000000000000000000000000000000000beef";

/// What main's node answers for one name check.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Name {
    /// The name serves the document's IPNS key.
    Serves,
    /// The name moved to another IPNS key.
    Moved,
    /// The node fails the call.
    Fails,
}

/// Main's naming node, for a name-keyed document's checks (design 0012,
/// APR-5f; 0015's D1): naming reads Direct from `n1`, uncached, so each
/// check is one `eth_call`, answered as scripted.
pub struct Naming {
    pub names: VecDeque<Name>,
    /// The `eth_call`s the core made.
    pub checks: usize,
    recorded: BTreeMap<String, String>,
}

impl Naming {
    pub fn new() -> Naming {
        Naming {
            names: VecDeque::new(),
            checks: 0,
            recorded: crate::common::naming_recorded(),
        }
    }
}

/// The `resolve` answer, ABI-encoded `(bytes, address)`, for `contenthash`.
fn resolve_body(contenthash: &str) -> String {
    let bytes = contenthash.len() / 2;
    let padded = bytes.div_ceil(32) * 32;
    let word = |n: usize| format!("{n:064x}");
    let inner = format!(
        "{}{}{contenthash}{}",
        word(32),
        word(bytes),
        "00".repeat(padded - bytes)
    );
    let result = format!(
        "0x{}{}{}{inner}",
        word(0x40),
        format_args!("{:0>64}", "2".repeat(40)),
        word(inner.len() / 2)
    );
    json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string()
}

/// A name-keyed document's `PageContext`: `navigation` numbers it.
pub fn named_page(navigation: u64) -> Value {
    json!({
        "origin": NAME, "top_origin": NAME, "frame": 1, "navigation": navigation,
        "agent": false, "transport_key": format!("ipns://{IPNS_KEY}"),
    })
}

/// The id main gives every subscription it opens: the reference's.
pub const SUBSCRIPTION_ID: &str = "59820d1a24fddf7bceaad40b518018f0";

const FORMS: [Form; 15] = [
    Form::Chunk,
    Form::Bytes,
    Form::FeedHead,
    Form::FeedLatest,
    Form::Tag,
    Form::Addresses,
    Form::Stamps,
    Form::Stamp,
    Form::BzzFile,
    Form::BzzTar,
    Form::BytesUp,
    Form::ChunkUp,
    Form::SocUp,
    Form::FeedManifest,
    Form::PssSend,
];

/// A stream's window (design 0007): 128 KiB.
pub const WINDOW: u64 = 128 * 1024;

/// The core, its temporary directories, and main's next request ID.
pub struct Main {
    pub core: Core,
    next: u64,
    _dir: tempfile::TempDir,
    /// Messages read while main waited for a stream's credit, for the next
    /// read.
    pub backlog: VecDeque<Value>,
    /// The credit the core gave each of its requests' streams main sends.
    pub credit: BTreeMap<u64, u64>,
}

/// A core whose Swarm grants have moved, with the test methods.
pub fn main() -> Main {
    main_with(&["swarm"], &[])
}

/// A core whose hello moves `grant_moved`, with the test methods and
/// `env`'s hooks.
pub fn main_with(grant_moved: &[&'static str], env: &[(&str, &str)]) -> Main {
    let (dir, data, locks) = dirs();
    let mut envs = vec![("FREEDOM_CORED_TEST_METHODS", "1")];
    envs.extend_from_slice(env);
    let mut core = spawn_env("serve", &data, &locks, &[], &envs);
    core.grant_moved = grant_moved.to_vec();
    // Fragments, as main offers them: a read's answer can pass a frame.
    let hello = core.hello_fragments();
    assert!(hello["result"].is_object(), "{hello}");
    let capabilities = hello["result"]["capabilities"].as_array().unwrap();
    assert!(capabilities.iter().any(|c| c == "swarm.request"));
    assert!(capabilities.iter().any(|c| c == "swarm.body"));
    Main {
        core,
        next: 1000,
        _dir: dir,
        backlog: VecDeque::new(),
        credit: BTreeMap::new(),
    }
}

/// A page's `PageContext` for key `key`.
pub fn page(key: &str) -> Value {
    json!({ "origin": key, "top_origin": key, "frame": 1, "navigation": 1 })
}

/// What a step did: its answer, main's answers to the thread, and what
/// the thread held after it.
#[derive(Debug)]
pub struct Played {
    pub outcome: Outcome,
    pub ready: Vec<(ReadyCheck, usize)>,
    pub calls: Vec<Logged>,
    pub opened: Vec<Subscription>,
    pub closed: Vec<String>,
    pub rechecks: usize,
    /// The thread's cancels of its own requests.
    pub cancels: usize,
}

impl Played {
    pub fn ran(&self) -> logic::Ran {
        logic::Ran {
            outcome: self.outcome.clone(),
            ready: self.ready.clone(),
            calls: self.calls.clone(),
            cancels_after_outcome: self.cancels,
            most_open: usize::from(!self.calls.is_empty()),
        }
    }
}

/// Main's side of a case: the world it reads, the node it reaches, its
/// readiness and its subscribe check.
pub struct Script {
    pub world: TestWorld,
    pub node: Node,
    pub readiness: Result<(), JsString>,
    pub subscribe_check: Option<Result<(), JsString>>,
    /// The key the step's request came under, for a node rule's world
    /// change.
    pub key: JsString,
    /// Main's naming node, for a name-keyed document.
    pub naming: Option<Naming>,
}

impl Main {
    pub fn id(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    /// `test.swarm_world { … }`: sent, its answer awaited (answering
    /// whatever the thread asks meanwhile is the caller's): `{ memory,
    /// requests, streams }`.
    pub fn world(&mut self, params: Value) -> Value {
        let id = self.id();
        self.core.send(&json!({
            "type": "request", "id": id, "method": "test.swarm_world", "params": params,
            "context": { "caller": "shell" },
        }));
        let response = self.recv();
        assert!(
            response["type"] == "response" && response["id"] == id,
            "{response}"
        );
        assert!(response["result"].is_object(), "{response}");
        response["result"].clone()
    }

    /// The next whole message: one read while main waited for credit
    /// first, then the next off the pipe, a fragmented one reassembled
    /// (main's bulk credit returned once read), the core's credit for a
    /// stream main sends noted on the way.
    pub fn recv(&mut self) -> Value {
        if let Some(message) = self.backlog.pop_front() {
            return message;
        }
        loop {
            match self.core.recv_wire() {
                Wire::Message(message) => return message,
                Wire::Begin { bytes, .. } => {
                    let mut payload = Vec::with_capacity(bytes);
                    loop {
                        match self.core.recv_wire() {
                            Wire::Fragment(part) => payload.extend_from_slice(&part),
                            Wire::Last(part) => {
                                payload.extend_from_slice(&part);
                                break;
                            }
                            other => panic!("inside a fragmented message: {other:?}"),
                        }
                    }
                    assert_eq!(payload.len(), bytes);
                    self.core.send_credit();
                    return serde_json::from_slice(&payload).unwrap();
                }
                Wire::Stream {
                    kind: KIND_STREAM_CREDIT,
                    id,
                    rest,
                } => {
                    let n = u32::from_be_bytes(rest[..4].try_into().unwrap());
                    *self.credit.entry(id).or_default() += u64::from(n);
                }
                Wire::Credit => {}
                other => panic!("an unexpected frame: {other:?}"),
            }
        }
    }

    /// Main streams `events` (data, then a terminal) as the body of the
    /// core's request `call`, within the credit the core gives it; a cancel
    /// of `call` read while main waits for credit ends the stream
    /// `cancelled`. Messages read meanwhile wait in the backlog.
    pub fn stream(&mut self, call: u64, events: &[Event]) {
        let mut sent = 0u64;
        for event in events {
            match event {
                Event::Data(bytes) => {
                    let len = bytes.len() as u64;
                    while sent + len > WINDOW + self.credit.get(&call).copied().unwrap_or(0) {
                        if self.wait_credit(call) {
                            self.abort(call, "cancelled");
                            return;
                        }
                    }
                    self.core.send_raw(&stream_frame(KIND_DATA, call, bytes));
                    sent += len;
                }
                Event::End => self.core.send_raw(&stream_frame(KIND_END, call, b"")),
                Event::Abort(abort) => self.abort(
                    call,
                    match abort {
                        Abort::Cancelled => "cancelled",
                        Abort::Stalled => "stalled",
                        Abort::BodyStreamError => "body_stream_error",
                        Abort::TooLarge => "too_large",
                        Abort::Unreadable(_) => panic!("a node body's abort"),
                    },
                ),
                other => panic!("not a stream's event: {other:?}"),
            }
        }
    }

    /// Reads until the core credits `call`'s stream: true if it cancels
    /// `call` first.
    fn wait_credit(&mut self, call: u64) -> bool {
        let before = self.credit.get(&call).copied().unwrap_or(0);
        loop {
            match self.core.recv_wire() {
                Wire::Stream {
                    kind: KIND_STREAM_CREDIT,
                    id,
                    rest,
                } => {
                    let n = u32::from_be_bytes(rest[..4].try_into().unwrap());
                    *self.credit.entry(id).or_default() += u64::from(n);
                    if id == call && self.credit[&call] > before {
                        return false;
                    }
                }
                Wire::Message(message) => {
                    let cancelled = message["type"] == "cancel" && message["id"] == call;
                    self.backlog.push_back(message);
                    if cancelled {
                        return true;
                    }
                }
                Wire::Credit => {}
                other => panic!("while main waits for credit: {other:?}"),
            }
        }
    }

    /// An abort frame for stream `id`.
    pub fn abort(&mut self, id: u64, code: &str) {
        let json = json!({ "code": code, "message": "aborted" }).to_string();
        self.core
            .send_raw(&stream_frame(KIND_ABORT, id, json.as_bytes()));
    }

    /// Sends `swarm.request` from `page` with `params` (the wire's JSON):
    /// its ID.
    pub fn request(&mut self, page: &Value, params: &str) -> u64 {
        let id = self.id();
        let frame = format!(
            r#"{{"type":"request","id":{id},"method":"swarm.request","params":{params},"context":{{"caller":"page","page":{page}}}}}"#
        );
        self.core
            .send_raw(&crate::common::raw_frame(0x01, frame.as_bytes()));
        id
    }

    /// Naming reads Direct from `n1` (APR-5f's test setup).
    pub fn configure_naming(&mut self) {
        let id = self.id();
        let configured = self.core.call(
            id,
            "naming.configure",
            json!({
                "reset": "none",
                "rpc": [{ "endpoint": "n1" }],
                "direct": { "endpoint": "n1", "user_configured": true },
                "prover": null,
                "policy": { "order": ["direct"], "prefer_verified": false },
                "quorum": { "k": 3, "m": 2, "timeout_ms": 5000, "anchor": "latest", "anchor_ttl_ms": 30000 },
                "myotis_enabled": false,
                "tezos": ["t1", "t2", "t3"],
            }),
        );
        assert!(configured["result"].is_object(), "{configured}");
    }

    /// Main's answer to naming's `shell.rpc`: a name check's `eth_call` as
    /// scripted, naming's other reads as the naming replay recorded them.
    pub fn serve_rpc(&mut self, naming: &mut Naming, message: &Value) {
        let params = &message["params"];
        assert_eq!(params["endpoint"], "n1", "{message}");
        let body: Value = serde_json::from_str(params["body"].as_str().unwrap()).unwrap();
        let text = match body["method"].as_str().unwrap() {
            "eth_call" => {
                naming.checks += 1;
                match naming
                    .names
                    .pop_front()
                    .unwrap_or_else(|| panic!("an unscripted name check: {message}"))
                {
                    Name::Serves => resolve_body(IPNS_CONTENTHASH),
                    Name::Moved => resolve_body(OTHER_CONTENTHASH),
                    Name::Fails => json!({ "jsonrpc": "2.0", "id": 1,
                        "error": { "code": -32000, "message": "header not found" } })
                    .to_string(),
                }
            }
            method => naming.recorded[method].clone(),
        };
        let mut answer: Value = serde_json::from_str(&text).unwrap();
        answer["id"] = body["id"].clone();
        let result = json!({
            "status": 200,
            "body": base64::engine::general_purpose::STANDARD.encode(answer.to_string()),
        });
        self.answer(message["id"].as_u64().unwrap(), result);
    }

    /// Main's answer to the core's request `id`.
    pub fn answer(&mut self, id: u64, result: Value) {
        self.core
            .send(&json!({ "type": "response", "id": id, "result": result }));
    }

    /// Main's error answer to the core's request `id`.
    pub fn refuse(&mut self, id: u64, error: Value) {
        self.core
            .send(&json!({ "type": "response", "id": id, "error": error }));
    }

    /// Plays one step: sends `swarm.request` and answers the thread's
    /// requests from `script` until its answer, then asks the thread what
    /// it holds, answering what it still asks meanwhile.
    pub fn play(&mut self, script: &mut Script, page: &Value, params: &str) -> Played {
        let request = self.request(page, params);
        let mut played = Played {
            outcome: Outcome::Cancelled,
            ready: Vec::new(),
            calls: Vec::new(),
            opened: Vec::new(),
            closed: Vec::new(),
            rechecks: 0,
            cancels: 0,
        };
        let mut probe = None;
        let mut pushes = BTreeSet::new();
        let held = loop {
            let message = self.recv();
            match message["type"].as_str().unwrap() {
                "request" => self.serve(script, request, &message, &mut played, &mut pushes),
                "cancel" => played.cancels += 1,
                "response" => {
                    let id = message["id"].as_u64().unwrap();
                    if id == request {
                        assert!(probe.is_none(), "one answer");
                        played.outcome = outcome(&message);
                        // What the thread holds once it has handled
                        // everything before this.
                        let world = self.id();
                        self.core.send(&json!({
                            "type": "request", "id": world, "method": "test.swarm_world",
                            "params": {}, "context": { "caller": "shell" },
                        }));
                        probe = Some(world);
                    } else if Some(id) == probe {
                        assert!(pushes.is_empty(), "the world pushed before it");
                        break message["result"].clone();
                    } else {
                        assert!(pushes.remove(&id), "an answer to nothing: {message}");
                    }
                }
                other => panic!("{other}: {message}"),
            }
        };
        // A request's base goes once the writer has written its answer,
        // which the writer's thread tells the swarm thread as it lets the
        // frame go: it can trail main's reading of the answer by a moment.
        let mut held = held;
        for _ in 0..200 {
            if held["memory"] == 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
            held = self.world(json!({}));
        }
        assert_eq!(held["memory"], 0, "no charge held after the step");
        assert_eq!(held["requests"], 0, "no request left after the step");
        assert_eq!(held["streams"], 0, "no stream left after the step");
        played
    }

    /// Main's answer to one of the thread's requests, from the script.
    fn serve(
        &mut self,
        script: &mut Script,
        request: u64,
        message: &Value,
        played: &mut Played,
        pushes: &mut BTreeSet<u64>,
    ) {
        let id = message["id"].as_u64().unwrap();
        let params = &message["params"];
        assert_eq!(message["context"]["caller"], "shell");
        match message["method"].as_str().unwrap() {
            "shell.rpc" => {
                let mut naming = script.naming.take().expect("a name-keyed document");
                self.serve_rpc(&mut naming, message);
                script.naming = Some(naming);
            }
            // Main prefetches an agreed answer on its own timer.
            "shell.prefetch" => {}
            "shell.swarm_ready" => {
                assert_eq!(params["for"], request);
                let check = match params["check"].as_str().unwrap() {
                    "publish" => ReadyCheck::Publish,
                    "reachable" => ReadyCheck::Reachable,
                    "subscribe" => ReadyCheck::Subscribe,
                    other => panic!("check {other}"),
                };
                played.ready.push((check, played.calls.len()));
                let answer = match check {
                    ReadyCheck::Publish => script.readiness.clone(),
                    ReadyCheck::Reachable => script.node.reachable(),
                    ReadyCheck::Subscribe => match &script.subscribe_check {
                        Some(Err(reason)) => Err(reason.clone()),
                        _ => script.node.reachable(),
                    },
                };
                match answer {
                    Ok(()) => self.answer(id, json!({ "ok": true })),
                    Err(reason) => {
                        self.answer(id, json!({ "ok": false, "reason": reason.as_str() }));
                    }
                }
            }
            "shell.swarm_api" => {
                assert_eq!(params["for"], request);
                let call = node_call(params);
                // A node rule's change to the world as its request arrives:
                // the grants go to the core before main's answer.
                if script.node.stopped {
                    self.answer(id, json!({ "failed": "stopped" }));
                    played.calls.push(Logged {
                        call,
                        charge: 0,
                        body: None,
                    });
                    return;
                }
                if let Some(rule) = script.node.matching(call.method(), &call.path) {
                    let changes = rule.world.clone();
                    if !changes.is_empty() {
                        for (what, value) in changes {
                            let key = script.key.clone();
                            script.world.apply(&key, &what, &value);
                        }
                        let world = self.id();
                        self.core.send(&json!({
                            "type": "request", "id": world, "method": "test.swarm_world",
                            "params": { "grants": grants_json(&script.world) },
                            "context": { "caller": "shell" },
                        }));
                        pushes.insert(world);
                    }
                }
                let spec = if call.method() == "POST" {
                    let body = match &call.body {
                        Some(Body::Base64(bytes)) => bytes.clone(),
                        None => Vec::new(),
                        other => panic!("a whole call's body: {other:?}"),
                    };
                    script.node.upload(call.method(), &call.path, &body)
                } else {
                    script.node.reply(call.method(), &call.path)
                };
                let (abort_page, events) = logic::forward(&spec, &call);
                if abort_page {
                    // The page gives up as the request reaches the node.
                    self.core.send(&json!({ "type": "cancel", "id": request }));
                }
                let body = match &events[0] {
                    Event::Reply(reply) if reply.ok() => Some(reply.body.clone()),
                    _ => None,
                };
                played.calls.push(Logged {
                    call,
                    charge: 0,
                    body,
                });
                match &events[0] {
                    // A streamed reply: its head, then its bytes within the
                    // core's credit (design 0015, Streams).
                    Event::Head(head) => {
                        self.answer(
                            id,
                            json!({
                                "status": head.status,
                                "status_text": head.status_text,
                                "headers": head.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
                            }),
                        );
                        self.stream(id, &events[1..]);
                    }
                    whole => {
                        assert_eq!(events.len(), 1, "a whole call's one answer");
                        self.answer(id, reply_json(whole));
                    }
                }
            }
            "approval.recheck" => {
                assert_eq!(params["request"], request);
                played.rechecks += 1;
                self.answer(
                    id,
                    json!({ "live": script.world.key_holds, "agent": script.world.custody }),
                );
            }
            "shell.swarm_subscribe" => {
                assert_eq!(params["for"], request);
                let kind = match params["kind"].as_str().unwrap() {
                    "gsoc" => SubscriptionKind::Gsoc,
                    "pss" => SubscriptionKind::Pss,
                    other => panic!("{other}"),
                };
                let key = logic::unhex(params["key"].as_str().unwrap());
                played.opened.push(Subscription {
                    kind,
                    key: key.try_into().unwrap(),
                });
                self.answer(id, json!({ "id": SUBSCRIPTION_ID }));
            }
            "shell.swarm_unsubscribe" => {
                played
                    .closed
                    .push(params["id"].as_str().unwrap().to_owned());
                self.answer(id, json!({}));
            }
            other => panic!("the thread asked {other}"),
        }
    }
}

/// `swarm.request`'s answer, as the page reads it: `{ result_typed }` and
/// `{ error_typed }` read back into fc-swarm-provider's values; 0001's
/// `cancelled` is the request's cancel.
pub fn outcome(message: &Value) -> Outcome {
    if let Some(error) = message.get("error") {
        assert_eq!(error["code"], "cancelled", "{message}");
        return Outcome::Cancelled;
    }
    let result = &message["result"];
    let read = |v: &Value| {
        Typed::from_typed(&fc_json::parse(&v.to_string()).unwrap()).unwrap_or_else(|e| {
            panic!("{e}: {v}");
        })
    };
    if let Some(value) = result.get("result_typed") {
        return Outcome::Result(read(value));
    }
    let failure = read(&result["error_typed"]);
    let Typed::Object(members) = failure else {
        panic!("{result}")
    };
    let mut code = None;
    let mut text = None;
    let mut data = None;
    for (key, value) in members {
        match (key.as_str(), value) {
            ("code", Typed::Number(n)) => code = Some(n as i32),
            ("message", Typed::String(s)) => text = Some(s),
            ("data", value) => data = Some(value),
            other => panic!("{other:?}"),
        }
    }
    Outcome::Error(Failure {
        code: code.unwrap(),
        message: text.unwrap(),
        data,
    })
}

/// The core's `shell.swarm_api` params, read back into the call.
pub fn node_call(params: &Value) -> NodeCall {
    let form = *FORMS
        .iter()
        .find(|f| params["form"] == f.as_str())
        .unwrap_or_else(|| panic!("{params}"));
    assert_eq!(params["method"], form.method());
    assert_eq!(params["stream"], form.streams());
    let pairs = |v: &Value| -> Vec<(String, String)> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|pair| {
                (
                    pair[0].as_str().unwrap().to_owned(),
                    pair[1].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    };
    let body = params.get("body").map(|body| match body.get("base64") {
        Some(text) => Body::Base64(
            base64::engine::general_purpose::STANDARD
                .decode(text.as_str().unwrap())
                .unwrap(),
        ),
        None => Body::Stream {
            bytes: body["stream"].as_u64().unwrap(),
        },
    });
    NodeCall {
        form,
        path: params["path"].as_str().unwrap().to_owned(),
        query: pairs(&params["query"]),
        headers: pairs(&params["headers"]),
        body,
        max_bytes: params["max_bytes"].as_u64().unwrap() as usize,
        feed: params.get("feed").map(|feed| FeedRef {
            owner: logic::unhex(feed["owner"].as_str().unwrap())
                .try_into()
                .unwrap(),
            index: feed["index"].as_u64().unwrap(),
        }),
        tree: params.get("tree").map(|tree| TreeRef {
            length: tree["length"].as_u64().unwrap(),
            depth: tree["depth"].as_u64().unwrap() as u8,
        }),
    }
}

/// Main's answer for a node's whole reply, or its failure before one.
pub fn reply_json(event: &Event) -> Value {
    match event {
        Event::Reply(reply) => json!({
            "status": reply.status,
            "status_text": reply.status_text,
            "headers": reply.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
            "body_base64": base64::engine::general_purpose::STANDARD.encode(&reply.body),
        }),
        Event::Failed(failed) => json!({
            "failed": match failed {
                Failed::Unreachable => "unreachable",
                Failed::Error => "error",
                Failed::Aborted => "aborted",
                Failed::TooLarge => "too_large",
                Failed::Busy => "busy",
                Failed::Stopped => "stopped",
            }
        }),
        other => panic!("not a whole call's answer: {other:?}"),
    }
}

/// `swarm-permissions.json` for the world's grants, rules and messaging
/// grants.
pub fn grants_json(world: &TestWorld) -> Value {
    let mut grants = serde_json::Map::new();
    for key in &world.grants {
        let rule = |flag: &str| world.rules.iter().any(|(k, f)| k == key && *f == flag);
        let mut entry = json!({
            "origin": key.as_str(), "connectedAt": 1, "lastUsed": 1,
            "autoApprove": {
                "publish": rule("publish"), "feeds": rule("feeds"),
                "signing": rule("signing"), "messaging": rule("messaging"),
            },
        });
        if world.messaging.contains(key) {
            entry["messaging"] = json!({ "grantedAt": 1 });
        }
        grants.insert(key.as_str().to_owned(), entry);
    }
    Value::Object(grants)
}

/// A typed value of the vectors as main sends it: the vectors' own forms
/// (`string_json`, `string_repeat`) expanded into `{ string }`.
pub fn wire_typed(v: V<'_, '_>) -> String {
    let (tag, content) = v.members().next().unwrap();
    match logic::string(tag).as_str() {
        "string_json" => format!(r#"{{"string":{}}}"#, logic::string(content)),
        "string_repeat" => {
            let unit = logic::string(content);
            let text = unit.repeat(logic::number(logic::get(v, "count")) as usize);
            format!(r#"{{"string":{}}}"#, serde_json::to_string(&text).unwrap())
        }
        "array" => {
            let items: Vec<String> = content
                .children()
                .map(|item| {
                    if item.get("hole").is_some() {
                        r#"{"hole":true}"#.to_owned()
                    } else {
                        wire_typed(item)
                    }
                })
                .collect();
            format!(r#"{{"array":[{}]}}"#, items.join(","))
        }
        "object" => {
            let pairs: Vec<String> = content
                .children()
                .map(|pair| {
                    let mut it = pair.children();
                    let (key, value) = (it.next().unwrap(), it.next().unwrap());
                    format!("[{},{}]", key.raw(), wire_typed(value))
                })
                .collect();
            format!(r#"{{"object":[{}]}}"#, pairs.join(","))
        }
        _ => v.raw().to_owned(),
    }
}

/// Whether a typed value carries a part main streams (SWM-4 PR 6).
pub fn has_part(v: V<'_, '_>) -> bool {
    v.raw().contains("\"part\":")
}
