//! Replays `vectors/naming-replay.json` through the session machine
//! (design 0004, Replay): the driver plays main, answering each request
//! with the answer the reference's matching exchange got.

use std::collections::{BTreeMap, HashSet};

use fc_naming::jsjson::{self, JsValue};
use fc_naming::session::ens::{Answer, Config, Direct, Request};
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
fn config(world: &JsValue) -> Config {
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
    Config {
        rpc: endpoints,
        direct,
        order,
        prefer_verified: verification.get("preferVerified") == Some(&JsValue::Bool(true)),
        quorum: network.get("quorum").cloned().unwrap_or(JsValue::Null),
    }
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
                        && (if gk == "error"
                            && wv.as_str().is_some_and(|t| t.contains("version=6."))
                        {
                            gv.as_str().is_some()
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
}

const STALL_MS: u64 = 10;

/// What a scenario replay found.
#[derive(Default)]
struct Mismatches(Vec<String>);

impl Mismatches {
    fn push(&mut self, message: String) {
        self.0.push(message);
    }
}

fn replay(scenario: &JsValue) -> Result<Mismatches, String> {
    let id = str_of(scenario.get("id"));
    let world = scenario.get("world").cloned().unwrap_or(JsValue::Null);
    #[allow(clippy::cast_possible_truncation)]
    let seed = num(scenario.get("seed")) as u32;
    let mut machine = Machine::new(0, config(&world), Box::new(Mulberry32::new(seed)));
    let mut exchanges: Vec<Exchange> = scenario
        .get("io")
        .and_then(JsValue::as_array)
        .unwrap_or(&[])
        .iter()
        .filter(|e| matches!(str_of(e.get("kind")), "rpc" | "gateway" | "prefetch"))
        .map(|e| Exchange {
            entry: e.clone(),
            used: false,
        })
        .collect();
    let mut mismatches = Mismatches::default();
    // Scheduled deliveries: token → (request id, answer); stalls: token →
    // (request id, exchange index).
    let mut deliveries: BTreeMap<u64, (u64, Answer)> = BTreeMap::new();
    let mut stalls: BTreeMap<u64, (u64, usize)> = BTreeMap::new();
    let mut next_token = 1u64;
    let mut cancelled: HashSet<u64> = HashSet::new();

    for (index, step) in scenario
        .get("steps")
        .and_then(JsValue::as_array)
        .unwrap_or(&[])
        .iter()
        .enumerate()
    {
        // Time passes before the step, with everything due on the way.
        let after = num(step.get("after"));
        let until = machine.now() + after;
        drive(
            &mut machine,
            until,
            &mut exchanges,
            &mut deliveries,
            &mut stalls,
            &mut next_token,
            &mut cancelled,
            &mut mismatches,
            None,
        );
        let calls: Vec<JsValue> = match step.get("calls").and_then(JsValue::as_array) {
            Some(calls) => calls.to_vec(),
            None => vec![step.get("call").cloned().unwrap_or(JsValue::Null)],
        };
        let mut callers = Vec::new();
        for call in &calls {
            let args = call.get("args").and_then(JsValue::as_array).unwrap_or(&[]);
            match str_of(call.get("fn")) {
                "resolveEnsContent" => callers.push(machine.resolve_content(str_of(args.first()))),
                "resolveEnsAddress" => {
                    let chain = match args.get(1) {
                        Some(JsValue::Number(n)) => *n,
                        _ => 1.0,
                    };
                    callers.push(machine.resolve_address(str_of(args.first()), chain));
                }
                "resolveEnsReverse" => {
                    let chain = match args.get(1) {
                        Some(JsValue::Number(n)) => *n,
                        _ => 1.0,
                    };
                    callers.push(machine.resolve_reverse(str_of(args.first()), chain));
                }
                "invalidateCachedProvider" => {
                    machine.invalidate_providers();
                    callers.push(u64::MAX);
                }
                other => return Err(format!("{id}: `{other}` isn't supported yet")),
            }
        }
        let mut replies: Vec<Reply> = Vec::new();
        if callers.contains(&u64::MAX) {
            replies.push(Reply {
                caller: u64::MAX,
                outcome: Ok(JsValue::Object(vec![(
                    "$undefined".into(),
                    JsValue::Bool(true),
                )])),
                settled: machine.now(),
            });
        }
        let horizon = machine.now() + 600_000;
        drive(
            &mut machine,
            horizon,
            &mut exchanges,
            &mut deliveries,
            &mut stalls,
            &mut next_token,
            &mut cancelled,
            &mut mismatches,
            Some((&callers, &mut replies)),
        );
        let expected = step
            .get("results")
            .and_then(JsValue::as_array)
            .unwrap_or(&[]);
        for (i, caller) in callers.iter().enumerate() {
            let Some(reply) = replies.iter().find(|r| r.caller == *caller) else {
                mismatches.push(format!("{id} step {index}: call {i} never settled"));
                continue;
            };
            let want = &expected[i];
            if num(want.get("settled")) != reply.settled {
                mismatches.push(format!(
                    "{id} step {index}: settled at {} instead of {}",
                    reply.settled,
                    num(want.get("settled"))
                ));
            }
            match (&reply.outcome, want.get("value"), want.get("thrown")) {
                (Ok(value), Some(expected), _) => {
                    let got = substitute(value);
                    if !same(&got, expected) {
                        mismatches.push(format!(
                            "{id} step {index}: result\n   got {}\n  want {}",
                            got.stringify(),
                            expected.stringify()
                        ));
                    }
                }
                (Err(thrown), _, Some(expected)) => {
                    if thrown.message != str_of(Some(expected)) {
                        mismatches.push(format!(
                            "{id} step {index}: thrown {:?} instead of {:?}",
                            thrown.message,
                            str_of(Some(expected))
                        ));
                    }
                }
                (outcome, _, _) => mismatches.push(format!(
                    "{id} step {index}: {outcome:?} instead of {}",
                    want.stringify()
                )),
            }
        }
    }
    let horizon = machine.now() + 600_000;
    drive(
        &mut machine,
        horizon,
        &mut exchanges,
        &mut deliveries,
        &mut stalls,
        &mut next_token,
        &mut cancelled,
        &mut mismatches,
        None,
    );
    for exchange in exchanges.iter().filter(|e| !e.used) {
        mismatches.push(format!(
            "{id}: the reference's request was never made: {}",
            exchange
                .entry
                .stringify()
                .chars()
                .take(220)
                .collect::<String>()
        ));
    }
    Ok(mismatches)
}

#[allow(clippy::too_many_arguments)]
fn drive(
    machine: &mut Machine,
    until: u64,
    exchanges: &mut [Exchange],
    deliveries: &mut BTreeMap<u64, (u64, Answer)>,
    stalls: &mut BTreeMap<u64, (u64, usize)>,
    next_token: &mut u64,
    cancelled: &mut HashSet<u64>,
    mismatches: &mut Mismatches,
    mut waiting: Option<(&[u64], &mut Vec<Reply>)>,
) {
    loop {
        machine.poll();
        let replies = machine.take_replies();
        if let Some((_, collected)) = waiting.as_mut() {
            collected.extend(replies);
        }
        for effect in machine.take_effects() {
            match effect {
                Effect::Request { id, at, request } => {
                    let Some(index) = match_exchange(exchanges, &request, at) else {
                        mismatches.push(format!("unmatched request at {at}: {request:?}"));
                        continue;
                    };
                    exchanges[index].used = true;
                    let token = *next_token;
                    *next_token += 1;
                    if matches!(request, Request::Rpc { .. }) {
                        // ethers' stall: the world sees the request 10 ms later.
                        stalls.insert(token, (id, index));
                        machine.schedule(at + STALL_MS, token);
                    } else {
                        schedule_answer(machine, exchanges, index, id, token, deliveries);
                    }
                }
                Effect::Cancel { id, .. } => {
                    cancelled.insert(id);
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
            Some(Fired::External(token)) => {
                if let Some((id, index)) = stalls.remove(&token) {
                    let next = *next_token;
                    *next_token += 1;
                    schedule_answer(machine, exchanges, index, id, next, deliveries);
                } else if let Some((id, answer)) = deliveries.remove(&token) {
                    machine.complete(id, answer);
                }
            }
        }
    }
}

fn schedule_answer(
    machine: &Machine,
    exchanges: &[Exchange],
    index: usize,
    id: u64,
    token: u64,
    deliveries: &mut BTreeMap<u64, (u64, Answer)>,
) {
    let entry = &exchanges[index].entry;
    let Some(answer) = entry.get("answer") else {
        return;
    };
    let status = u16::try_from(num(answer.get("status"))).unwrap_or(0);
    let body = str_of(answer.get("body")).as_bytes().to_vec();
    let answer = match str_of(entry.get("kind")) {
        // No scenario retries yet: one exchange, no back-off draws.
        "rpc" => Answer::Rpc {
            status,
            body,
            draws: 0,
        },
        "gateway" if answer.get("redirect").is_some() => Answer::Failed(Transport::Refused),
        "gateway" => Answer::Gateway { status, body },
        _ => return,
    };
    deliveries.insert(token, (id, answer));
    machine.schedule(num(entry.get("end")), token);
}

fn match_exchange(exchanges: &[Exchange], request: &Request, at: u64) -> Option<usize> {
    exchanges.iter().position(|exchange| {
        if exchange.used {
            return false;
        }
        let e = &exchange.entry;
        match request {
            Request::Rpc { endpoint, body, .. } => {
                let Ok(sent) = jsjson::parse(body) else {
                    return false;
                };
                str_of(e.get("kind")) == "rpc"
                    && str_of(e.get("host")) == host_of(endpoint)
                    && num(e.get("t")) == at + STALL_MS
                    && e.get("method") == sent.get("method")
                    && e.get("params") == sent.get("params")
            }
            Request::Gateway { url, .. } => {
                str_of(e.get("kind")) == "gateway"
                    && str_of(e.get("url")) == url
                    && num(e.get("t")) == at
            }
            Request::Prefetch { uri } => {
                str_of(e.get("kind")) == "prefetch"
                    && str_of(e.get("uri")) == uri
                    && num(e.get("t")) == at
            }
        }
    })
}

/// Scenarios a declared deviation changes (design 0004, Deviations). They
/// must differ from the reference until their deviation vectors land.
const DEVIATIONS: &[(&str, &str)] = &[("node-errors-agree", "node-failures")];

/// The scenarios this machine covers so far.
const SUPPORTED: &[&str] = &[
    "quorum-agree",
    "quorum-slow-endpoint-head",
    "quorum-one-liar",
    "quorum-two-colluding",
    "ccip-fast-gateway",
    "ccip-slow-gateway-then-another-name",
    "ccip-gateway-errors-fall-through",
    "ccip-all-gateways-fail",
    "single-source-two-endpoints",
    "anchor-hash-split",
    "anchor-finalized",
    "node-errors-agree",
    "cache-boundary-verified",
    "cache-boundary-unverified",
    "quarantine-expiry-resets",
    "settings-invalidation",
    "direct-user-configured",
    "direct-builtin",
    "dedup-concurrent",
    "quarantine-doubles-on-overlapping-failures",
    "address-agree",
    "address-multicoin-base",
    "address-zero-is-no-address",
    "reverse-agree",
    "reverse-mismatch",
    "reverse-ens-empty-then-wns",
    "reverse-ens-and-wns-empty-then-gns",
    "reverse-wns-claim-fails-forward-then-gns-empty",
    "wns-content",
    "gns-content",
    "wns-address-on-l2",
];

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
        let id = str_of(scenario.get("id"));
        if !SUPPORTED.contains(&id) {
            continue;
        }
        let deviation = DEVIATIONS
            .iter()
            .find(|(d, _)| *d == id)
            .map(|(_, why)| *why);
        match (replay(scenario), deviation) {
            (Ok(mismatches), None) if mismatches.0.is_empty() => {}
            (Ok(mismatches), Some(_)) if !mismatches.0.is_empty() => {}
            (Ok(_), Some(why)) => report.push(format!(
                "== {id}: matches the reference despite deviation `{why}`"
            )),
            (Ok(mismatches), None) => report.push(format!("== {id}\n{}", mismatches.0.join("\n"))),
            (Err(error), _) => report.push(format!("== {id}: {error}")),
        }
    }
    assert!(report.is_empty(), "{}", report.join("\n"));
}
