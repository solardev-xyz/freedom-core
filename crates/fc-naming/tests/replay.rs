//! Replays `vectors/naming-replay.json` through the session machine
//! (design 0004, Replay): the driver plays main, answering each request
//! with the answer the reference's matching exchange got.

use std::collections::BTreeMap;

use fc_naming::jsjson::{self, JsValue};
use fc_naming::session::bounds::Bounds;
use fc_naming::session::ens::{Answer, Config, Direct, Request, Verified, VerifiedOp};
use fc_naming::session::exec::{Effect, Fired};
use fc_naming::session::machine::{Machine, Reply};
use fc_naming::session::random::Mulberry32;
use fc_naming::session::rpc::Transport;

fn vectors() -> JsValue {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/naming-replay.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_default();
    jsjson::parse(&text).unwrap_or(JsValue::Null)
}

fn host_of(url: &str) -> String {
    url::Url::parse(url).map_or_else(
        |_| url.to_owned(),
        |u| match u.port() {
            Some(port) => format!("{}:{port}", u.host_str().unwrap_or("")),
            None => u.host_str().unwrap_or("").to_owned(),
        },
    )
}

fn num(value: Option<&JsValue>) -> u64 {
    match value {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Some(JsValue::Number(n)) => *n as u64,
        _ => 0,
    }
}

fn str_of(value: Option<&JsValue>) -> &str {
    value.and_then(JsValue::as_str).unwrap_or("")
}

/// The configuration main would send for a scenario's world.
fn config(world: &JsValue, system: &str) -> Config {
    let endpoints: Vec<String> = world
        .get("endpoints")
        .and_then(JsValue::as_array)
        .unwrap_or(&[])
        .iter()
        .filter_map(|e| e.as_str().map(str::to_owned))
        .collect();
    let network = world.get("network").cloned().unwrap_or(JsValue::Null);
    let verification = network
        .get("verification")
        .cloned()
        .unwrap_or(JsValue::Null);
    let order: Vec<String> = verification
        .get("order")
        .and_then(JsValue::as_array)
        .unwrap_or(&[])
        .iter()
        .filter_map(|m| m.as_str().map(str::to_owned))
        .collect();
    // `getDirectRpcCandidate(1)`.
    let direct = endpoints.first().map(|url| {
        let sources = world
            .get("sources")
            .and_then(JsValue::as_array)
            .unwrap_or(&[]);
        let source = sources.iter().find(|src| {
            !src.get("keyed").is_some_and(JsValue::truthy)
                && src
                    .get("coverage")
                    .and_then(|c| c.get("1"))
                    .and_then(JsValue::as_str)
                    == Some(url)
        });
        let meta = source.and_then(|src| {
            let id = src.get("id");
            world
                .get("sourceList")
                .and_then(JsValue::as_array)
                .unwrap_or(&[])
                .iter()
                .find(|m| m.get("id") == id)
        });
        let user_configured = meta.is_some_and(|m| {
            !m.get("builtin").is_some_and(JsValue::truthy)
                && !m.get("removed").is_some_and(JsValue::truthy)
                && !m.get("keyed").is_some_and(JsValue::truthy)
        });
        Direct {
            endpoint: url.clone(),
            user_configured,
        }
    });
    let colibri = world.get("colibri").cloned().unwrap_or(JsValue::Null);
    let prover = colibri.get("prover").and_then(JsValue::as_str).map(|url| {
        (
            url.to_owned(),
            network.get("zkProof") != Some(&JsValue::Bool(false)),
        )
    });
    let (rpc, tezos) = if system == "tezos" {
        (Vec::new(), endpoints)
    } else {
        (endpoints, Vec::new())
    };
    Config {
        rpc,
        tezos,
        direct,
        order,
        prefer_verified: verification.get("preferVerified") == Some(&JsValue::Bool(true)),
        quorum: network.get("quorum").cloned().unwrap_or(JsValue::Null),
        myotis_enabled: world.get("myotis").and_then(|m| m.get("enabled"))
            == Some(&JsValue::Bool(true)),
        prover,
        bounds: bounds(world),
    }
}

/// Design 0004's bounds, with the ones a deviation vector lowers
/// (`world.bounds`).
fn bounds(world: &JsValue) -> Bounds {
    let mut bounds = Bounds::default();
    let lowered = world.get("bounds");
    let get = |key: &str| {
        lowered
            .and_then(|b| b.get(key))
            .map(|v| usize::try_from(num(Some(v))).unwrap_or(usize::MAX))
    };
    if let Some(n) = get("ccipUrls") {
        bounds.ccip_urls = n;
    }
    if let Some(n) = get("answerBytes") {
        bounds.answer_bytes = n;
    }
    if let Some(n) = get("replyHex") {
        bounds.reply_hex = n;
    }
    if let Some(n) = get("prefetches") {
        bounds.prefetches = n;
    }
    if let Some(n) = get("messageBytes") {
        bounds.message_bytes = n;
    }
    if let Some(n) = get("replyBytes") {
        bounds.reply_bytes = n;
    }
    if let Some(n) = get("cacheBytes") {
        bounds.cache_bytes = n;
    }
    if let Some(n) = get("decodeBytes") {
        bounds.decode_bytes = n;
    }
    if let Some(n) = get("sessions") {
        bounds.sessions = n;
    }
    if let Some(n) = get("callers") {
        bounds.callers = n;
    }
    if let Some(n) = get("callersPerSession") {
        bounds.callers_per_session = n;
    }
    if let Some(n) = get("deadlineMs") {
        bounds.deadline_ms = n as u64;
    }
    bounds
}

/// Endpoint references back to what main publishes: Tezos' `trust.agreed`
/// as URLs, everything else as hosts; `undefined` as the vectors' marker.
fn publish(value: &JsValue, system: &str) -> JsValue {
    let marked = substitute(value);
    if system != "tezos" {
        return marked;
    }
    let agreed = value.get("trust").and_then(|t| t.get("agreed")).cloned();
    let JsValue::Object(members) = &marked else {
        return marked;
    };
    let urls = |refs: &[JsValue]| {
        JsValue::Array(
            refs.iter()
                .map(|r| r.get("ref").cloned().unwrap_or(JsValue::Null))
                .collect(),
        )
    };
    JsValue::Object(
        members
            .iter()
            .map(|(k, v)| match (k.as_str(), v, &agreed) {
                ("trust", JsValue::Object(trust), Some(JsValue::Array(refs))) => (
                    k.clone(),
                    JsValue::Object(
                        trust
                            .iter()
                            .map(|(tk, tv)| {
                                if tk == "agreed" {
                                    (tk.clone(), urls(refs))
                                } else {
                                    (tk.clone(), tv.clone())
                                }
                            })
                            .collect(),
                    ),
                ),
                _ => (k.clone(), v.clone()),
            })
            .collect(),
    )
}

/// Endpoint references back to hosts, as main substitutes them.
fn substitute(value: &JsValue) -> JsValue {
    match value {
        JsValue::Object(members) => {
            if let [(key, JsValue::String(url))] = members.as_slice()
                && key == "ref"
            {
                return JsValue::String(host_of(url));
            }
            JsValue::Object(
                members
                    .iter()
                    .map(|(k, v)| (k.clone(), substitute(v)))
                    .collect(),
            )
        }
        JsValue::Array(items) => JsValue::Array(items.iter().map(substitute).collect()),
        JsValue::Undefined => JsValue::Object(vec![("$undefined".into(), JsValue::Bool(true))]),
        other => other.clone(),
    }
}

/// Deviation `error-text`: where the reference's value is an ethers
/// composed message (it ends in ethers' version marker), the core's text is
/// its own; the field must still be present. Every other value must match.
fn same(got: &JsValue, want: &JsValue) -> bool {
    match (got, want) {
        (JsValue::Object(g), JsValue::Object(w)) => {
            g.len() == w.len()
                && g.iter().zip(w).all(|((gk, gv), (wk, wv))| {
                    gk == wk
                        // Deviation `error-text`: where the reference shows an
                        // ethers composed message, the core shows its short
                        // message, sanitized.
                        && (if gk == "error"
                            && let Some(text) = wv.as_str().filter(|t| t.contains("version=6."))
                        {
                            gv.as_str() == Some(
                                fc_naming::ethers::sanitize(fc_naming::ethers::short_of(text)).as_str(),
                            )
                        } else {
                            same(gv, wv)
                        })
                })
        }
        (JsValue::Array(g), JsValue::Array(w)) => {
            g.len() == w.len() && g.iter().zip(w).all(|(a, b)| same(a, b))
        }
        _ => got == want,
    }
}

struct Exchange {
    entry: JsValue,
    used: bool,
    /// The core's request this exchange answers.
    request: Option<u64>,
    /// When the core cancelled it, before its answer.
    cancelled: Option<u64>,
    /// Whether its answer reached the core.
    delivered: bool,
}

const STALL_MS: u64 = 10;

/// What a driver token stands for when it fires.
enum Token {
    /// ethers' stall is over: the world sees request `id` (exchange index).
    Stall(u64, usize),
    /// The world answers request `id`.
    Deliver(u64, Answer),
    /// A scripted Myotis availability transition.
    Availability(bool),
}

/// The driver: main, played from the recorded exchanges.
struct Driver {
    exchanges: Vec<Exchange>,
    tokens: BTreeMap<u64, Token>,
    next_token: u64,
    mismatches: Vec<String>,
}

impl Driver {
    fn token(&mut self, machine: &Machine, at: u64, token: Token) {
        let id = self.next_token;
        self.next_token += 1;
        self.tokens.insert(id, token);
        machine.schedule(at, id);
    }

    /// Runs the machine until `until`, or until every caller in `waiting`
    /// has replied.
    fn drive(
        &mut self,
        machine: &mut Machine,
        until: u64,
        mut waiting: Option<(&[u64], &mut Vec<Reply>)>,
    ) {
        loop {
            machine.poll();
            let replies = machine.take_replies();
            if let Some((_, collected)) = waiting.as_mut() {
                collected.extend(replies);
            }
            for effect in machine.take_effects() {
                if let Effect::Cancel { id, at } = effect {
                    if let Some(exchange) =
                        self.exchanges.iter_mut().find(|e| e.request == Some(id))
                        && !exchange.delivered
                    {
                        exchange.cancelled = Some(at);
                    }
                    continue;
                }
                if let Effect::Request { id, at, request } = effect {
                    let Some(index) = self.match_exchange(&request, at) else {
                        self.mismatches
                            .push(format!("unmatched request at {at}: {request:?}"));
                        continue;
                    };
                    self.exchanges[index].used = true;
                    self.exchanges[index].request = Some(id);
                    if matches!(request, Request::Rpc { .. }) {
                        // ethers' stall: the world sees the request 10 ms later.
                        self.token(machine, at + STALL_MS, Token::Stall(id, index));
                    } else {
                        self.schedule_answer(machine, index, id);
                    }
                }
            }
            if let Some((callers, collected)) = waiting.as_ref()
                && callers
                    .iter()
                    .all(|c| collected.iter().any(|r| r.caller == *c))
            {
                return;
            }
            match machine.fire_next(until) {
                None => return,
                Some(Fired::Timer) => {}
                Some(Fired::External(token)) => match self.tokens.remove(&token) {
                    Some(Token::Stall(id, index)) => self.schedule_answer(machine, index, id),
                    Some(Token::Deliver(id, answer)) => {
                        if let Some(exchange) =
                            self.exchanges.iter_mut().find(|e| e.request == Some(id))
                            && exchange.cancelled.is_none()
                        {
                            exchange.delivered = true;
                        }
                        machine.complete(id, answer);
                    }
                    Some(Token::Availability(ready)) => machine.availability(ready),
                    None => {}
                },
            }
        }
    }

    fn schedule_answer(&mut self, machine: &Machine, index: usize, id: u64) {
        let entry = self.exchanges[index].entry.clone();
        let Some(answer) = entry.get("answer") else {
            return;
        };
        let status = u16::try_from(num(answer.get("status"))).unwrap_or(0);
        let body = str_of(answer.get("body")).as_bytes().to_vec();
        let answer = match str_of(entry.get("kind")) {
            "rpc" => Answer::Rpc { status, body },
            "gateway" if answer.get("redirect").is_some() => Answer::Failed(Transport::Refused),
            "gateway" => Answer::Gateway { status, body },
            "tezos" => Answer::Tezos { status, body },
            // Main's `{}`: the prefetch ended (finished, failed or timed out).
            "prefetch" => Answer::Done,
            "verified-op" => Answer::Verified(if let Some(result) = answer.get("result") {
                Verified::Result(result.clone())
            } else if let Some(revert) = answer.get("revert") {
                Verified::Revert(
                    fc_naming::session::rpc::hex_string(str_of(Some(revert))).unwrap_or_default(),
                )
            } else {
                Verified::Failure(str_of(answer.get("failure")).to_owned())
            }),
            _ => return,
        };
        self.token(machine, num(entry.get("end")), Token::Deliver(id, answer));
    }

    fn match_exchange(&self, request: &Request, at: u64) -> Option<usize> {
        self.exchanges.iter().position(|exchange| {
            if exchange.used {
                return false;
            }
            let e = &exchange.entry;
            let kind = str_of(e.get("kind"));
            match request {
                Request::Rpc { endpoint, body } => {
                    let Ok(sent) = jsjson::parse(body) else {
                        return false;
                    };
                    kind == "rpc"
                        && str_of(e.get("host")) == host_of(endpoint)
                        && num(e.get("t")) == at + STALL_MS
                        && e.get("method") == sent.get("method")
                        && e.get("params") == sent.get("params")
                }
                // The method follows the body: a template without {data}
                // POSTs { sender, data }.
                Request::Gateway { url, body } => {
                    kind == "gateway"
                        && str_of(e.get("url")) == url
                        && str_of(e.get("method")) == if body.is_some() { "POST" } else { "GET" }
                        && e.get("body").and_then(JsValue::as_str) == body.as_deref()
                        && num(e.get("t")) == at
                }
                Request::Prefetch { uri } => {
                    kind == "prefetch" && str_of(e.get("uri")) == uri && num(e.get("t")) == at
                }
                Request::Verified(op) => {
                    kind == "verified-op" && num(e.get("t")) == at && verified_matches(op, e)
                }
                Request::Tezos {
                    endpoint,
                    post,
                    path,
                    body,
                } => {
                    kind == "tezos"
                        && str_of(e.get("host")) == host_of(endpoint)
                        && str_of(e.get("method")) == if *post { "POST" } else { "GET" }
                        && str_of(e.get("path")) == path
                        && e.get("body").and_then(JsValue::as_str) == body.as_deref()
                        && num(e.get("t")) == at
                }
            }
        })
    }
}

/// A verifier operation against a recorded one.
fn verified_matches(op: &VerifiedOp, e: &JsValue) -> bool {
    let p = e.get("params").cloned().unwrap_or(JsValue::Null);
    let text = |key: &str| {
        p.get(key)
            .and_then(JsValue::as_str)
            .map(str::to_ascii_lowercase)
    };
    let host = str_of(e.get("host"));
    let op_name = str_of(e.get("op"));
    match op {
        VerifiedOp::MyotisRecord {
            method,
            name,
            address,
            coin_type,
        } => {
            host == "myotis"
                && op_name == "record"
                && text("method").as_deref() == Some(*method)
                && text("name") == name.as_ref().map(|n| n.to_ascii_lowercase())
                && text("address") == address.as_ref().map(|a| a.to_ascii_lowercase())
                && text("coinType") == Some(coin_type.to_string())
        }
        VerifiedOp::MyotisCall { to, data } => {
            host == "myotis"
                && op_name == "call"
                && text("to") == Some(fc_naming::session::rpc::hex(to))
                && text("data") == Some(fc_naming::session::rpc::hex(data))
        }
        VerifiedOp::ColibriResolve {
            name,
            call_data,
            resolver,
        } => {
            host == "colibri"
                && op_name == "resolve"
                && text("name") == Some(name.to_ascii_lowercase())
                && text("callData") == Some(fc_naming::session::rpc::hex(call_data))
                && p.get("nameNft") == Some(&JsValue::Bool(*resolver == "name_nft"))
        }
        VerifiedOp::ColibriReverse { address, coin_type } => {
            host == "colibri"
                && op_name == "reverse"
                && text("address") == Some(address.to_ascii_lowercase())
                && text("coinType") == Some(coin_type.to_string())
        }
    }
}

fn replay(scenario: &JsValue) -> Result<Vec<String>, String> {
    let id = str_of(scenario.get("id"));
    let world = scenario.get("world").cloned().unwrap_or(JsValue::Null);
    #[allow(clippy::cast_possible_truncation)]
    let seed = num(scenario.get("seed")) as u32;
    let system = str_of(scenario.get("system"));
    let mut machine = Machine::new(0, config(&world, system), Box::new(Mulberry32::new(seed)));
    // The harness's epoch: Date.now() at virtual time 0.
    machine.set_wall_clock(1_760_000_000_000.0);
    machine.set_myotis_ready(
        world.get("myotis").and_then(|m| m.get("ready")) == Some(&JsValue::Bool(true)),
    );
    let exchanges = scenario
        .get("io")
        .and_then(JsValue::as_array)
        .unwrap_or(&[])
        .iter()
        .filter(|e| {
            matches!(
                str_of(e.get("kind")),
                "rpc" | "gateway" | "prefetch" | "verified-op" | "tezos"
            )
        })
        // Exchanges inside a verifier operation are main\'s business.
        .filter(|e| e.get("within").is_none())
        .map(|e| Exchange {
            entry: e.clone(),
            used: false,
            request: None,
            cancelled: None,
            delivered: false,
        })
        .collect();
    let mut driver = Driver {
        exchanges,
        tokens: BTreeMap::new(),
        next_token: 1,
        mismatches: Vec::new(),
    };

    for (index, step) in scenario
        .get("steps")
        .and_then(JsValue::as_array)
        .unwrap_or(&[])
        .iter()
        .enumerate()
    {
        // Time passes before the step, with everything due on the way.
        let until = machine.now() + num(step.get("after"));
        driver.drive(&mut machine, until, None);
        let start = machine.now();
        for event in step
            .get("events")
            .and_then(JsValue::as_array)
            .unwrap_or(&[])
        {
            let ready =
                event.get("myotis").and_then(|m| m.get("ready")) == Some(&JsValue::Bool(true));
            driver.token(
                &machine,
                start + num(event.get("at")),
                Token::Availability(ready),
            );
        }
        let calls: Vec<JsValue> = match step.get("calls").and_then(JsValue::as_array) {
            Some(calls) => calls.to_vec(),
            None => vec![step.get("call").cloned().unwrap_or(JsValue::Null)],
        };
        let mut callers = Vec::new();
        let mut immediate = Vec::new();
        for call in &calls {
            let args = call.get("args").and_then(JsValue::as_array).unwrap_or(&[]);
            let chain = match args.get(1) {
                Some(JsValue::Number(n)) => *n,
                _ => 1.0,
            };
            match str_of(call.get("fn")) {
                "resolveEnsContent" => callers.push(machine.resolve_content(str_of(args.first()))),
                "resolveEnsAddress" => {
                    callers.push(machine.resolve_address(str_of(args.first()), chain))
                }
                "resolveEnsReverse" => {
                    callers.push(machine.resolve_reverse(str_of(args.first()), chain))
                }
                "resolveTezosDomain" => callers.push(machine.resolve_tezos(str_of(args.first()))),
                "invalidateCachedProvider" => {
                    machine.invalidate_providers();
                    callers.push(u64::MAX);
                    immediate.push(Reply {
                        caller: u64::MAX,
                        outcome: Ok(JsValue::Object(vec![(
                            "$undefined".into(),
                            JsValue::Bool(true),
                        )])),
                        settled: machine.now(),
                    });
                }
                other => return Err(format!("{id}: `{other}` isn't supported yet")),
            }
        }
        let mut replies = immediate;
        let horizon = machine.now() + 600_000;
        driver.drive(&mut machine, horizon, Some((&callers, &mut replies)));
        let expected = step
            .get("results")
            .and_then(JsValue::as_array)
            .unwrap_or(&[]);
        for (i, caller) in callers.iter().enumerate() {
            let Some(reply) = replies.iter().find(|r| r.caller == *caller) else {
                driver
                    .mismatches
                    .push(format!("{id} step {index}: call {i} never settled"));
                continue;
            };
            let want = &expected[i];
            if num(want.get("settled")) != reply.settled {
                driver.mismatches.push(format!(
                    "{id} step {index}: settled at {} instead of {}",
                    reply.settled,
                    num(want.get("settled"))
                ));
            }
            match (&reply.outcome, want.get("value"), want.get("thrown")) {
                // A protocol error (`busy`, `deadline`), not a resolution.
                (Err(thrown), _, _) if want.get("protocol").is_some() || thrown.code.is_some() => {
                    let expected = want.get("protocol").and_then(JsValue::as_str);
                    if thrown.code != expected {
                        driver.mismatches.push(format!(
                            "{id} step {index}: protocol {:?} instead of {expected:?}",
                            thrown.code
                        ));
                    }
                }
                (Ok(value), Some(expected), _) => {
                    let got = publish(value, system);
                    if !same(&got, expected) {
                        driver.mismatches.push(format!(
                            "{id} step {index}: result\n   got {}\n  want {}",
                            got.stringify(),
                            expected.stringify()
                        ));
                    }
                }
                (Err(thrown), _, Some(expected)) => {
                    if thrown.message != str_of(Some(expected)) {
                        driver.mismatches.push(format!(
                            "{id} step {index}: thrown {:?} instead of {:?}",
                            thrown.message,
                            str_of(Some(expected))
                        ));
                    }
                }
                (outcome, _, _) => driver.mismatches.push(format!(
                    "{id} step {index}: {outcome:?} instead of {}",
                    want.stringify()
                )),
            }
        }
    }
    let horizon = machine.now() + 600_000;
    driver.drive(&mut machine, horizon, None);
    let unused: Vec<String> = driver
        .exchanges
        .iter()
        .filter(|e| !e.used)
        .map(|e| {
            format!(
                "{id}: the reference's request was never made: {}",
                e.entry.stringify().chars().take(220).collect::<String>()
            )
        })
        .collect();
    driver.mismatches.extend(unused);
    // Cancellations (design 0004, Replay). A prefetch is cancelled exactly
    // where the reference cancelled it. Any other exchange the reference
    // cancelled, the core cancels by then: earlier only where it stopped
    // waiting first, as when a Promise.all rejection abandons a sibling the
    // reference left to its own timer (`abandoned-exchanges`). Exchanges the
    // reference let finish may be cancelled for the same reason.
    for exchange in driver.exchanges.iter().filter(|e| e.used) {
        let e = &exchange.entry;
        let reference = (str_of(e.get("outcome")) == "cancelled").then(|| num(e.get("end")));
        let prefetch = str_of(e.get("kind")) == "prefetch";
        let ok = if prefetch {
            reference == exchange.cancelled
        } else {
            match (reference, exchange.cancelled) {
                (Some(by), Some(at)) => at <= by,
                (Some(_), None) => false,
                (None, _) => true,
            }
        };
        if !ok {
            driver.mismatches.push(format!(
                "{id}: cancelled at {:?} instead of {reference:?}: {}",
                exchange.cancelled,
                e.stringify().chars().take(200).collect::<String>()
            ));
        }
    }
    Ok(driver.mismatches)
}

/// Scenarios a declared deviation changes (design 0004, Deviations). They
/// must differ from the reference until their deviation vectors land.
const DEVIATIONS: &[(&str, &str)] = &[("node-errors-agree", "node-failures")];

#[test]
fn replays_match_the_reference() {
    let vectors = vectors();
    let scenarios = vectors
        .get("scenarios")
        .and_then(JsValue::as_array)
        .unwrap_or(&[]);
    assert!(!scenarios.is_empty(), "no replay vectors");
    let mut report = Vec::new();
    for scenario in scenarios {
        // Every recorded scenario replays.
        let id = str_of(scenario.get("id"));
        let deviation = DEVIATIONS
            .iter()
            .find(|(d, _)| *d == id)
            .map(|(_, why)| *why);
        match (replay(scenario), deviation) {
            (Ok(mismatches), None) if mismatches.is_empty() => {}
            (Ok(mismatches), Some(_)) if !mismatches.is_empty() => {}
            (Ok(_), Some(why)) => report.push(format!(
                "== {id}: matches the reference despite deviation `{why}`"
            )),
            (Ok(mismatches), None) => report.push(format!("== {id}\n{}", mismatches.join("\n"))),
            (Err(error), _) => report.push(format!("== {id}: {error}")),
        }
    }
    assert!(report.is_empty(), "{}", report.join("\n"));
}
