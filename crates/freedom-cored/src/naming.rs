//! The naming thread (design 0004): fc-naming's session machine on its own
//! thread, so vault traffic never waits on naming work. The event loop
//! forwards `naming.*` requests, cancels and main's responses to `shell.*`
//! here; this thread writes its own replies and requests to the writer.
//!
//! The machine is sans-I/O: each of its requests becomes a `shell.*`
//! request to main, each answer goes back to it, and its timers run on this
//! thread's monotonic clock.

use std::collections::BTreeMap;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use fc_naming::jsjson::{self, JsValue};
use fc_naming::session::bounds::Bounds;
use fc_naming::session::ens::{Answer, Config, Direct, Request, Thrown, Verified, VerifiedOp};
use fc_naming::session::exec::Effect;
use fc_naming::session::machine::{CallOptions, Emitted, Generations, Machine, Reply};
use fc_naming::session::random::Random;
use fc_naming::session::rpc::Transport;
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::message::{self, Context};
use serde::Deserialize;
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use crate::serve::Event;
use crate::{log, transport};

/// The methods the naming thread answers.
pub const METHODS: &[&str] = &[
    "naming.configure",
    "naming.availability",
    "naming.resolve_content",
    "naming.resolve_address",
    "naming.resolve_reverse",
    "naming.resolve_tezos",
    "naming.invalidate_content",
    "naming.invalidate_tezos",
];

pub fn handles(method: &str) -> bool {
    METHODS.contains(&method)
}

/// What the event loop forwards.
pub enum In {
    Request {
        id: u64,
        method: &'static str,
        params: Option<Box<RawValue>>,
    },
    Cancel {
        id: u64,
    },
    /// Main's terminal reply to one of this thread's `shell.*` requests.
    Response {
        id: u64,
        outcome: Result<Box<RawValue>, ErrorBody>,
    },
}

/// The event loop's side of the naming thread.
pub struct Handle {
    tx: Sender<In>,
}

impl Handle {
    /// False once the thread has gone.
    pub fn send(&self, message: In) -> bool {
        self.tx.send(message).is_ok()
    }
}

/// Starts the naming thread. It writes to `out` and reports a protocol
/// error from main, or its own end, to the event loop.
pub fn spawn(
    out: SyncSender<Zeroizing<Vec<u8>>>,
    events: Sender<Event>,
) -> std::io::Result<Handle> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("naming".into())
        .spawn(move || {
            let event = match run(&rx, out) {
                Stop::Protocol(category) => Event::ProtocolError(category),
                Stop::Writer => Event::WriterFailed,
                // The event loop has gone: nothing to report to.
                Stop::Gone => return,
            };
            let _ = events.send(event);
        })?;
    Ok(Handle { tx })
}

/// Uniform values in `[0, 1)` from the OS generator: the shuffle needs no
/// reproducibility outside replays.
struct OsRandom;

impl Random for OsRandom {
    fn next_f64(&mut self) -> f64 {
        let mut bytes = [0u8; 8];
        // A failed read leaves zeros: a fixed but valid shuffle.
        let _ = getrandom::fill(&mut bytes);
        #[allow(clippy::cast_precision_loss)]
        let value = (u64::from_le_bytes(bytes) >> 11) as f64;
        value / (1u64 << 53) as f64
    }
}

/// A configuration with nothing in it, until main's first
/// `naming.configure`.
fn empty_config() -> Config {
    Config {
        rpc: Vec::new(),
        direct: None,
        order: Vec::new(),
        prefer_verified: false,
        quorum: JsValue::Null,
        myotis_enabled: false,
        prover: None,
        tezos: Vec::new(),
        bounds: Bounds::default(),
    }
}

/// Why the naming thread stopped.
enum Stop {
    /// Main broke the protocol (a fixed category, never input text).
    Protocol(&'static str),
    /// The writer is gone or main stopped reading.
    Writer,
    /// The event loop has gone.
    Gone,
}

type Flow = Result<(), Stop>;

/// The thread's loop, until it has to stop.
fn run(rx: &Receiver<In>, out: SyncSender<Zeroizing<Vec<u8>>>) -> Stop {
    let started = Instant::now();
    let mut machine = Machine::new(0, empty_config(), Box::new(OsRandom));
    #[allow(clippy::cast_precision_loss)]
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_millis() as f64);
    machine.set_wall_clock(wall);
    let mut naming = Naming {
        machine,
        out,
        callers: BTreeMap::new(),
        outgoing: BTreeMap::new(),
        by_io: BTreeMap::new(),
        next_id: 1,
    };
    let now = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    loop {
        if let Err(stop) = naming.advance(now()) {
            return stop;
        }
        let wait = naming
            .machine
            .next_due()
            .map_or(Duration::from_secs(3600), |at| {
                Duration::from_millis(at.saturating_sub(now()))
            });
        let flow = match rx.recv_timeout(wait) {
            Ok(message) => naming
                .advance(now())
                .and_then(|()| naming.handle(message))
                .and_then(|()| naming.flush()),
            Err(RecvTimeoutError::Timeout) => Ok(()),
            Err(RecvTimeoutError::Disconnected) => Err(Stop::Gone),
        };
        if let Err(stop) = flow {
            return stop;
        }
    }
}

/// What a `shell.*` request is for, to read main's answer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Rpc,
    Gateway,
    Tezos,
    Verified,
    Prefetch,
}

struct Outgoing {
    /// The machine's request id; `None` once the machine cancelled it (its
    /// one terminal reply is still due, and dropped).
    io: Option<u64>,
    kind: Kind,
}

struct Naming {
    machine: Machine,
    out: SyncSender<Zeroizing<Vec<u8>>>,
    /// The machine's callers, by the request ID main gave them.
    callers: BTreeMap<u64, u64>,
    /// This thread's `shell.*` requests, by their message ID.
    outgoing: BTreeMap<u64, Outgoing>,
    /// Message IDs by the machine's request id.
    by_io: BTreeMap<u64, u64>,
    next_id: u64,
}

impl Naming {
    /// Fires the timers due by `now`, polling after each as the executor
    /// requires, then moves the clock to `now`.
    fn advance(&mut self, now: u64) -> Flow {
        while self.machine.fire_next(now).is_some() {
            self.machine.poll();
            self.flush()?;
        }
        self.machine.poll();
        self.flush()
    }

    fn handle(&mut self, message: In) -> Flow {
        match message {
            In::Request { id, method, params } => {
                self.request(id, method, params.as_deref().map(RawValue::get))
            }
            In::Cancel { id } => {
                if let Some(caller) = self.callers.get(&id) {
                    self.machine.cancel(*caller);
                    self.machine.poll();
                }
                Ok(())
            }
            In::Response { id, outcome } => self.response(id, outcome),
        }
    }

    fn request(&mut self, id: u64, method: &str, params: Option<&str>) -> Flow {
        let params = params.unwrap_or("{}");
        macro_rules! parse {
            ($ty:ty) => {
                match serde_json::from_str::<$ty>(params) {
                    Ok(params) => params,
                    Err(_) => {
                        return self.error(
                            id,
                            ErrorBody::new(ErrorCode::InvalidArgument, "Invalid parameters"),
                        );
                    }
                }
            };
        }
        match method {
            "naming.configure" => {
                let snapshot = parse!(Snapshot);
                let Some(config) = snapshot.config() else {
                    return self.error(
                        id,
                        ErrorBody::new(ErrorCode::InvalidArgument, "Invalid configuration"),
                    );
                };
                let reset = snapshot.reset.as_deref() == Some("providers");
                let generations = self.machine.configure(config, reset);
                self.result(
                    id,
                    &serde_json::json!({ "ens": generations.ens, "tezos": generations.tezos }),
                )
            }
            "naming.availability" => {
                let params = parse!(AvailabilityParams);
                self.machine.set_myotis_enabled(params.enabled);
                self.machine.availability(params.ready);
                let lifecycle = self.machine.generations().lifecycle;
                self.result(id, &serde_json::json!({ "lifecycle": lifecycle }))
            }
            "naming.resolve_content" => {
                let params = parse!(NameParams);
                let caller = self
                    .machine
                    .resolve_content_with(&params.name, params.options());
                self.callers.insert(id, caller);
                Ok(())
            }
            "naming.resolve_tezos" => {
                let params = parse!(NameParams);
                let caller = self
                    .machine
                    .resolve_tezos_with(&params.name, params.options());
                self.callers.insert(id, caller);
                Ok(())
            }
            "naming.resolve_address" => {
                let params = parse!(AddressParams);
                let caller = self.machine.resolve_address_with(
                    &params.name,
                    params.chain_id,
                    params.options(),
                );
                self.callers.insert(id, caller);
                Ok(())
            }
            "naming.resolve_reverse" => {
                let params = parse!(ReverseParams);
                let caller = self.machine.resolve_reverse_with(
                    &params.address,
                    params.chain_id,
                    params.options(),
                );
                self.callers.insert(id, caller);
                Ok(())
            }
            "naming.invalidate_content" => {
                let params = parse!(InvalidateParams);
                let evicted = self
                    .machine
                    .invalidate_content(params.name.as_deref().unwrap_or(""));
                self.result(id, &serde_json::json!({ "evicted": evicted }))
            }
            "naming.invalidate_tezos" => {
                let params = parse!(InvalidateParams);
                self.machine.invalidate_tezos(params.name.as_deref());
                self.result(id, &serde_json::json!({}))
            }
            _ => self.error(
                id,
                ErrorBody::new(ErrorCode::UnknownMethod, "Unknown method"),
            ),
        }
    }

    /// Main's reply to a `shell.*` request. One for a request the machine
    /// cancelled is dropped; one for no request at all is a protocol error.
    fn response(&mut self, id: u64, outcome: Result<Box<RawValue>, ErrorBody>) -> Flow {
        let Some(outgoing) = self.outgoing.remove(&id) else {
            return Err(Stop::Protocol("unsolicited_response"));
        };
        let Some(io) = outgoing.io else {
            return Ok(());
        };
        self.by_io.remove(&io);
        let Some(answer) = answer(outgoing.kind, outcome) else {
            return Err(Stop::Protocol("malformed_shell_reply"));
        };
        self.machine.complete(io, answer);
        Ok(())
    }

    /// Sends the machine's requests, cancels and replies.
    fn flush(&mut self) -> Flow {
        for Emitted {
            effect,
            generations,
        } in self.machine.take_effects()
        {
            match effect {
                Effect::Request {
                    id: io, request, ..
                } => {
                    let id = self.next_id;
                    self.next_id += 1;
                    let (method, kind, params) = shell_request(&request, generations);
                    let mut payload = Zeroizing::new(Vec::with_capacity(256));
                    if message::write_request(&mut *payload, id, method, &params, &Context::shell())
                        .is_err()
                    {
                        return Err(Stop::Protocol("unwritable_request"));
                    }
                    self.outgoing.insert(id, Outgoing { io: Some(io), kind });
                    self.by_io.insert(io, id);
                    self.send(&payload)?;
                }
                Effect::Cancel { id: io, .. } => {
                    let Some(id) = self.by_io.remove(&io) else {
                        continue;
                    };
                    if let Some(outgoing) = self.outgoing.get_mut(&id) {
                        outgoing.io = None;
                    }
                    let payload = serde_json::json!({ "type": "cancel", "id": id });
                    self.send(payload.to_string().as_bytes())?;
                }
            }
        }
        for reply in self.machine.take_replies() {
            let Some((&id, _)) = self.callers.iter().find(|(_, c)| **c == reply.caller) else {
                continue;
            };
            self.callers.remove(&id);
            self.reply(id, &reply)?;
        }
        Ok(())
    }

    /// A resolution reply (design 0004, Replies).
    fn reply(&mut self, id: u64, reply: &Reply) -> Flow {
        let generations = generations_json(reply.generations);
        match &reply.outcome {
            Ok(value) => {
                let (result, undefined_keys) = with_placeholders(value);
                let Ok(result) = RawValue::from_string(result.stringify()) else {
                    return Err(Stop::Protocol("unwritable_result"));
                };
                self.result(
                    id,
                    &serde_json::json!({
                        "result": result,
                        "undefined_keys": undefined_keys,
                        "generations": generations,
                        "attempts": reply.attempts,
                    }),
                )
            }
            Err(Thrown {
                code: Some(code), ..
            }) => {
                let code = match *code {
                    "busy" => ErrorCode::Busy,
                    "deadline" => ErrorCode::Deadline,
                    "cancelled" => ErrorCode::Cancelled,
                    _ => ErrorCode::Internal,
                };
                self.error(id, ErrorBody::new(code, code_message(code)))
            }
            Err(thrown) => self.error(
                id,
                ErrorBody::new(ErrorCode::ResolutionFailed, "Resolution failed").with_data(
                    serde_json::json!({
                        "message": thrown.message,
                        "generations": generations,
                        "attempts": reply.attempts,
                    }),
                ),
            ),
        }
    }

    fn result(&mut self, id: u64, result: &serde_json::Value) -> Flow {
        let mut payload = Zeroizing::new(Vec::with_capacity(256));
        message::write_result(&mut *payload, id, result)
            .map_err(|_| Stop::Protocol("unwritable_result"))?;
        self.send(&payload)
    }

    fn error(&mut self, id: u64, error: ErrorBody) -> Flow {
        let mut payload = Zeroizing::new(Vec::with_capacity(256));
        message::write_error(&mut *payload, id, &error)
            .map_err(|_| Stop::Protocol("unwritable_result"))?;
        self.send(&payload)
    }

    /// Queues a frame. A full queue means main stopped reading: the event
    /// loop ends the process.
    fn send(&self, payload: &[u8]) -> Flow {
        let frame = transport::frame(payload).ok_or(Stop::Protocol("oversized_message"))?;
        match self.out.try_send(frame) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                log::error("main is not reading replies", serde_json::json!({}));
                Err(Stop::Writer)
            }
            Err(TrySendError::Disconnected(_)) => Err(Stop::Writer),
        }
    }
}

fn code_message(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::Busy => "Too many naming requests",
        ErrorCode::Deadline => "The resolution's deadline passed",
        ErrorCode::Cancelled => "Cancelled",
        _ => "Internal error",
    }
}

fn generations_json(generations: Generations) -> serde_json::Value {
    serde_json::json!({
        "ens": generations.ens,
        "tezos": generations.tezos,
        "lifecycle": generations.lifecycle,
    })
}

/// A result with its top-level `undefined` members as `null`
/// placeholders, and their keys (design 0004, Replies).
fn with_placeholders(value: &JsValue) -> (JsValue, Vec<String>) {
    let JsValue::Object(members) = value else {
        return (value.clone(), Vec::new());
    };
    let mut keys = Vec::new();
    let members = members
        .iter()
        .map(|(key, value)| {
            if matches!(value, JsValue::Undefined) {
                keys.push(key.clone());
                (key.clone(), JsValue::Null)
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect();
    (JsValue::Object(members), keys)
}

/// A machine request as a `shell.*` request: its method, how to read the
/// answer, and its params with the generations of its scopes.
fn shell_request(
    request: &Request,
    generations: Generations,
) -> (&'static str, Kind, serde_json::Value) {
    let deadline_ms = Bounds::default().deadline_ms;
    let ens = serde_json::json!({ "ens": generations.ens });
    match request {
        Request::Rpc { endpoint, body } => (
            "shell.rpc",
            Kind::Rpc,
            serde_json::json!({ "endpoint": endpoint, "body": body, "generations": ens, "deadline_ms": deadline_ms }),
        ),
        Request::Gateway { url, body } => (
            "shell.gateway",
            Kind::Gateway,
            serde_json::json!({
                "url": url,
                "method": if body.is_some() { "POST" } else { "GET" },
                "body": body,
                "generations": ens,
                "deadline_ms": deadline_ms,
            }),
        ),
        Request::Tezos {
            endpoint,
            post,
            path,
            body,
        } => (
            "shell.tezos",
            Kind::Tezos,
            serde_json::json!({
                "endpoint": endpoint,
                "method": if *post { "POST" } else { "GET" },
                "path": path,
                "body": body,
                "generations": { "tezos": generations.tezos },
                "deadline_ms": deadline_ms,
            }),
        ),
        Request::Verified(op) => {
            let mut params = verified_params(op);
            if let serde_json::Value::Object(map) = &mut params {
                map.insert(
                    "generations".into(),
                    serde_json::json!({ "lifecycle": generations.lifecycle }),
                );
                map.insert("deadline_ms".into(), deadline_ms.into());
            }
            ("shell.verified", Kind::Verified, params)
        }
        Request::Prefetch { uri } => (
            "shell.prefetch",
            Kind::Prefetch,
            serde_json::json!({ "uri": uri, "generations": ens, "deadline_ms": deadline_ms }),
        ),
    }
}

fn hex(bytes: &[u8]) -> String {
    fc_naming::session::rpc::hex(bytes)
}

/// A verified operation as design 0004's table writes it.
fn verified_params(op: &VerifiedOp) -> serde_json::Value {
    match op {
        VerifiedOp::MyotisRecord {
            method,
            name,
            address,
            coin_type,
        } => serde_json::json!({
            "myotis": "record",
            "method": method,
            "name": name,
            "address": address,
            "coin_type": coin_type,
        }),
        VerifiedOp::MyotisCall { to, data } => {
            serde_json::json!({ "myotis": "call", "to": hex(to), "data": hex(data) })
        }
        VerifiedOp::ColibriResolve {
            name,
            call_data,
            resolver,
        } => serde_json::json!({
            "colibri": "resolve",
            "name": name,
            "call_data": hex(call_data),
            "resolver": resolver,
        }),
        VerifiedOp::ColibriReverse { address, coin_type } => serde_json::json!({
            "colibri": "reverse",
            "address": address,
            "coin_type": coin_type,
        }),
    }
}

/// Main's terminal reply as the machine's answer; `None` when it is
/// malformed.
fn answer(kind: Kind, outcome: Result<Box<RawValue>, ErrorBody>) -> Option<Answer> {
    let result = match outcome {
        Ok(result) => result,
        Err(error) => {
            return Some(Answer::Failed(match error.code {
                ErrorCode::Timeout | ErrorCode::Deadline => Transport::Timeout,
                ErrorCode::Refused => Transport::Refused,
                ErrorCode::TooLarge => Transport::TooLarge,
                ErrorCode::Cancelled => Transport::Cancelled,
                ErrorCode::StaleGeneration => Transport::StaleGeneration,
                _ => Transport::Network,
            }));
        }
    };
    match kind {
        Kind::Rpc | Kind::Gateway | Kind::Tezos => {
            #[derive(Deserialize)]
            struct Http {
                status: u16,
                body: String,
            }
            let http: Http = serde_json::from_str(result.get()).ok()?;
            let body = base64::engine::general_purpose::STANDARD
                .decode(http.body)
                .ok()?;
            Some(match kind {
                Kind::Rpc => Answer::Rpc {
                    status: http.status,
                    body,
                },
                Kind::Gateway => Answer::Gateway {
                    status: http.status,
                    body,
                },
                _ => Answer::Tezos {
                    status: http.status,
                    body,
                },
            })
        }
        Kind::Prefetch => Some(Answer::Done),
        Kind::Verified => {
            let value = jsjson::parse(result.get()).ok()?;
            if let Some(class) = value.get("failure").and_then(JsValue::as_str) {
                return Some(Answer::Verified(Verified::Failure(class.to_owned())));
            }
            if let Some(revert) = value.get("revert").and_then(JsValue::as_str) {
                let data = fc_naming::session::rpc::hex_string(revert)?;
                return Some(Answer::Verified(Verified::Revert(data)));
            }
            Some(Answer::Verified(Verified::Result(adapter_keys(&value))))
        }
    }
}

/// The wire's snake_case keys as the adapters' own (camelCase), which the
/// machine reads.
fn adapter_keys(value: &JsValue) -> JsValue {
    let JsValue::Object(members) = value else {
        return value.clone();
    };
    JsValue::Object(
        members
            .iter()
            .map(|(key, value)| {
                let key = match key.as_str() {
                    "data_hex" => "dataHex",
                    "address_hex" => "addressHex",
                    "block_number" => "blockNumber",
                    "result_hex" => "resultHex",
                    "optimistic_block_number" => "optimisticBlockNumber",
                    "resolved_data" => "resolvedData",
                    "resolver_address" => "resolverAddress",
                    other => other,
                };
                (key.to_owned(), value.clone())
            })
            .collect(),
    )
}

#[derive(Deserialize)]
struct AvailabilityParams {
    ready: bool,
    enabled: bool,
}

/// What every resolution carries besides its subject.
#[derive(Deserialize)]
struct Common {
    /// Today's private-window handlers: the core logs no names anyway.
    #[serde(default)]
    #[allow(dead_code)]
    private: bool,
    #[serde(default)]
    attempts_used: u32,
    #[serde(default)]
    deadline_ms: Option<u64>,
}

impl Common {
    fn options(&self) -> CallOptions {
        CallOptions {
            attempts_used: self.attempts_used,
            deadline_ms: self.deadline_ms,
        }
    }
}

#[derive(Deserialize)]
struct NameParams {
    name: String,
    #[serde(flatten)]
    common: Common,
}

impl NameParams {
    fn options(&self) -> CallOptions {
        self.common.options()
    }
}

#[derive(Deserialize)]
struct AddressParams {
    name: String,
    #[serde(default = "mainnet")]
    chain_id: f64,
    #[serde(flatten)]
    common: Common,
}

impl AddressParams {
    fn options(&self) -> CallOptions {
        self.common.options()
    }
}

#[derive(Deserialize)]
struct ReverseParams {
    address: String,
    #[serde(default = "mainnet")]
    chain_id: f64,
    #[serde(flatten)]
    common: Common,
}

impl ReverseParams {
    fn options(&self) -> CallOptions {
        self.common.options()
    }
}

fn mainnet() -> f64 {
    1.0
}

#[derive(Deserialize)]
struct InvalidateParams {
    #[serde(default)]
    name: Option<String>,
}

/// `naming.configure`'s snapshot (design 0004, Configuration).
#[derive(Deserialize)]
struct Snapshot {
    #[serde(default)]
    reset: Option<String>,
    rpc: Vec<EndpointParam>,
    direct: Option<DirectParam>,
    prover: Option<ProverParam>,
    policy: Policy,
    /// Today's raw `network.quorum` values: the machine applies today's
    /// coercions and clamps where today's code reads them.
    quorum: Option<serde_json::Map<String, serde_json::Value>>,
    myotis_enabled: bool,
    tezos: Vec<String>,
}

#[derive(Deserialize)]
struct EndpointParam {
    endpoint: String,
}

#[derive(Deserialize)]
struct DirectParam {
    endpoint: String,
    user_configured: bool,
}

#[derive(Deserialize)]
struct ProverParam {
    endpoint: String,
    zk: bool,
}

#[derive(Deserialize)]
struct Policy {
    order: Vec<String>,
    prefer_verified: bool,
}

/// At most 64 RPC endpoints (design 0004, Configuration).
const MAX_RPC_ENDPOINTS: usize = 64;

impl Snapshot {
    fn config(&self) -> Option<Config> {
        if self.rpc.len() > MAX_RPC_ENDPOINTS {
            return None;
        }
        // `network.quorum`, with today's names for the keys.
        let quorum = match &self.quorum {
            None => JsValue::Null,
            Some(map) => {
                let renamed: serde_json::Map<String, serde_json::Value> = map
                    .iter()
                    .map(|(key, value)| {
                        let key = match key.as_str() {
                            "timeout_ms" => "timeoutMs",
                            "anchor_ttl_ms" => "anchorTtlMs",
                            other => other,
                        };
                        (key.to_owned(), value.clone())
                    })
                    .collect();
                jsjson::parse(&serde_json::Value::Object(renamed).to_string()).ok()?
            }
        };
        Some(Config {
            rpc: self.rpc.iter().map(|e| e.endpoint.clone()).collect(),
            direct: self.direct.as_ref().map(|d| Direct {
                endpoint: d.endpoint.clone(),
                user_configured: d.user_configured,
            }),
            order: self.policy.order.clone(),
            prefer_verified: self.policy.prefer_verified,
            quorum,
            myotis_enabled: self.myotis_enabled,
            prover: self.prover.as_ref().map(|p| (p.endpoint.clone(), p.zk)),
            tezos: self.tezos.clone(),
            bounds: Bounds::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_random_stays_in_range() {
        let mut random = OsRandom;
        for _ in 0..1000 {
            let value = random.next_f64();
            assert!((0.0..1.0).contains(&value));
        }
    }

    #[test]
    fn undefined_members_become_placeholders() {
        let value = jsjson::parse(r#"{"a":1,"b":null}"#).unwrap_or(JsValue::Null);
        let JsValue::Object(members) = &value else {
            return;
        };
        let mut members = members.clone();
        members.push(("ttl".into(), JsValue::Undefined));
        let (result, keys) = with_placeholders(&JsValue::Object(members));
        assert_eq!(result.stringify(), r#"{"a":1,"b":null,"ttl":null}"#);
        assert_eq!(keys, ["ttl"]);
    }

    #[test]
    fn snapshots_rename_quorum_keys() {
        let snapshot: Snapshot = serde_json::from_str(
            r#"{"rpc":[{"endpoint":"e1"}],"direct":null,"prover":null,
               "policy":{"order":["quorum"],"prefer_verified":false},
               "quorum":{"k":3,"m":2,"timeout_ms":5000,"anchor":"latest","anchor_ttl_ms":30000},
               "myotis_enabled":false,"tezos":["t1"]}"#,
        )
        .unwrap_or_else(|_| unreachable!());
        let config = snapshot.config().unwrap_or_else(empty_config);
        assert_eq!(config.rpc, ["e1"]);
        assert_eq!(
            config.quorum.stringify(),
            r#"{"k":3,"m":2,"timeoutMs":5000,"anchor":"latest","anchorTtlMs":30000}"#
        );
    }

    #[test]
    fn verified_replies_take_the_adapters_keys() {
        let value = jsjson::parse(r#"{"result_hex":"0x01","optimistic_block_number":7}"#)
            .unwrap_or(JsValue::Null);
        assert_eq!(
            adapter_keys(&value).stringify(),
            r#"{"resultHex":"0x01","optimisticBlockNumber":7}"#
        );
    }
}
