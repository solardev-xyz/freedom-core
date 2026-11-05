//! Design 0006 end to end: `dweb.open`'s plans and `chain.html`'s
//! documents, the real binary with the test playing main. Main answers the
//! core's `shell.*` requests from scripts: naming's from the `quorum-agree`
//! replay scenario's recordings, chain data's from the documents below.
//! Design 0009's `dweb.verify`, at protocol 2 with streams, is in
//! the `verify` module.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use base64::Engine as _;
use common::{Core, Wire, dirs, fragmented, request, shell_request, spawn, spawn_env};
use serde_json::{Value, json};

const MIB: usize = 1 << 20;

fn b64(bytes: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Main's terminal reply to one of the core's requests: in fragments of
/// half a frame when it is over one, after which main waits for the core
/// to return its credit (design 0005, Frames). Whatever comes meanwhile is
/// returned.
fn answer_request(core: &mut Core, request: &Value, outcome: Value) -> Vec<Wire> {
    let mut message = json!({ "type": "response", "id": request["id"] });
    for (key, value) in outcome.as_object().unwrap() {
        message[key] = value.clone();
    }
    let len = message.to_string().len();
    if len < MIB {
        core.send(&message);
        return Vec::new();
    }
    for frame in fragmented(&message, len.div_ceil(MIB / 2)) {
        core.send_raw(&frame);
    }
    let mut seen = Vec::new();
    loop {
        match core.recv_wire() {
            Wire::Credit => return seen,
            wire => seen.push(wire),
        }
    }
}

/// Reads until the core's response to main's request `id`: the core's own
/// requests number from 1 too, so they are told apart by type.
fn response_to(core: &mut Core, id: u64) -> Value {
    loop {
        let message = core.recv();
        if message["type"] == "response" && message["id"] == id {
            return message;
        }
    }
}

fn transport_failure(code: &str) -> Value {
    json!({ "error": { "code": code, "message": "Transport failure" } })
}

// ---------------------------------------------------------------------------
// dweb.open

const REFERENCE: &str = "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeebeef";
/// What the recorded `vitalik.eth` content resolves to.
const VITALIK_CID: &str = "QmW81r84Aihiqqi2Jw6nM1LnpeMfRCenRxtjwHNkXVkZYa";

fn naming_core() -> (tempfile::TempDir, Core) {
    let (root, data, locks) = dirs();
    let mut core = spawn("serve", &data, &locks, &[]);
    let hello = core.hello();
    let capabilities = hello["result"]["capabilities"].as_array().unwrap();
    assert!(capabilities.contains(&json!("dweb.open")), "{hello}");
    assert!(!capabilities.contains(&json!("chain.html")), "{hello}");
    let configured = core.call(2, "naming.configure", common::naming_snapshot());
    assert_eq!(
        configured["result"],
        json!({ "ens": 1, "tezos": 1, "lifecycle": 0 })
    );
    (root, core)
}

/// `dweb.open`'s params for a GET with `headers`.
fn open_params(url: &str, backend: Value, headers: Value) -> Value {
    json!({
        "url": url,
        "method": "GET",
        "headers": headers,
        "backend": backend,
        "private": false,
        "deadline_ms": 120_000,
    })
}

fn open(core: &mut Core, id: u64, params: Value) {
    core.send(&shell_request(id, "dweb.open", params));
}

fn native() -> Value {
    json!({ "ipfs": "native", "up": true })
}

fn bundled() -> Value {
    json!({ "ant": "bundled", "up": true })
}

/// A word of an ABI encoding.
fn word(n: usize) -> String {
    format!("{n:064x}")
}

fn padded(bytes: &[u8]) -> String {
    let pad = bytes.len().div_ceil(32) * 32 - bytes.len();
    format!("{}{}", hex(bytes), "00".repeat(pad))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
    out
}

/// The Universal Resolver's answer to `resolve(name, contenthash(node))`:
/// `(bytes result, address resolver)`, the result ABI-encoding
/// `contenthash`, as the recorded answer is laid out.
fn ur_answer(contenthash: &[u8]) -> String {
    let inner = format!(
        "{}{}{}",
        word(32),
        word(contenthash.len()),
        padded(contenthash)
    );
    let resolver = format!("{:0>64}", "2222222222222222222222222222222222222222");
    let data = format!("0x{}{resolver}{}{inner}", word(64), word(inner.len() / 2));
    format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{data}"}}"#)
}

/// A Swarm contenthash for `reference`.
fn swarm_contenthash(reference: &str) -> Vec<u8> {
    let mut bytes = vec![0xe4, 0x01, 0x01, 0xfa, 0x01, 0x1b, 0x20];
    for pair in reference.as_bytes().chunks(2) {
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
    }
    bytes
}

/// Plays main for naming until the response to `id`: the anchor's
/// requests from the recordings, every `eth_call` with `call` (the
/// recorded one when `None`), prefetches finished, and Tezos endpoints
/// failing. Returns the response and the `shell.*` requests main saw.
fn serve_naming(core: &mut Core, id: u64, call: Option<&str>) -> (Value, Vec<Value>) {
    let answers = common::naming_recorded();
    let mut seen = Vec::new();
    loop {
        let message = core.recv();
        match message["type"].as_str() {
            Some("request") => {
                let outcome = match message["method"].as_str().unwrap() {
                    "shell.rpc" => {
                        let body: Value =
                            serde_json::from_str(message["params"]["body"].as_str().unwrap())
                                .unwrap();
                        let method = body["method"].as_str().unwrap();
                        let text = match (method, call) {
                            ("eth_call", Some(call)) => call.to_owned(),
                            _ => answers[method].clone(),
                        };
                        json!({ "result": { "status": 200, "body": b64(text) } })
                    }
                    "shell.prefetch" => json!({ "result": {} }),
                    "shell.tezos" => transport_failure("network"),
                    _ => panic!("unexpected {message}"),
                };
                answer_request(core, &message, outcome);
                seen.push(message);
            }
            Some("response") if message["id"] == id => return (message, seen),
            Some("cancel") => {}
            _ => panic!("unexpected {message}"),
        }
    }
}

#[test]
fn every_request_without_a_name_is_planned_as_fc_dweb_plans_it() {
    // The reference's own requests (vectors/dweb.json), through the binary:
    // fc-dweb's vector tests hold its plans to the pinned JS, and this holds
    // the daemon to fc-dweb.
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/dweb.json"
    ))
    .unwrap();
    let vectors: Value = serde_json::from_str(&text).unwrap();
    let (_root, mut core) = naming_core();
    let mut planned = 0;
    for (i, entry) in vectors["requests"].as_array().unwrap().iter().enumerate() {
        if !entry["js"]["resolve"].as_array().unwrap().is_empty() {
            continue;
        }
        let request = &entry["request"];
        let headers: Vec<(String, String)> =
            serde_json::from_value(request["headers"].clone()).unwrap();
        let backend = fc_dweb::Backend::from_value(
            &fc_naming::jsjson::parse(&request["backend"].to_string()).unwrap(),
        )
        .unwrap();
        let ours = fc_dweb::open(&fc_dweb::Request {
            url: request["url"].as_str().unwrap(),
            method: request["method"].as_str().unwrap(),
            headers: &headers,
            backend,
        })
        .unwrap();
        let fc_dweb::Opening::Plan(plan) = ours else {
            panic!("{}: a name", entry["id"]);
        };
        let id = 100 + i as u64;
        let mut params = request.clone();
        params["private"] = json!(true);
        params["deadline_ms"] = json!(1000);
        open(&mut core, id, params);
        let reply = core.response(id);
        let result = &reply["result"];
        let expected: Value = serde_json::from_str(&plan.to_json()).unwrap();
        assert_eq!(result["plan"], expected, "{}", entry["id"]);
        assert_eq!(
            result["generations"],
            json!({ "ens": 1, "tezos": 1, "lifecycle": 0 })
        );
        assert_eq!(result["attempts"], 0);
        planned += 1;
    }
    assert!(planned > 150, "{planned}");
}

#[test]
fn ens_names_are_looked_up_through_main() {
    let (_root, mut core) = naming_core();
    // An `ipfs:` name: the recorded lookup, a navigation to the native node.
    let navigation = json!([["Accept", "text/html"], ["Cookie", "a=1"]]);
    open(
        &mut core,
        3,
        open_params("ipfs://vitalik.eth/blog/", native(), navigation.clone()),
    );
    let (reply, seen) = serve_naming(&mut core, 3, None);
    assert!(
        seen.len() >= 7,
        "anchor and legs went through main: {seen:?}"
    );
    let result = &reply["result"];
    let fetch = &result["plan"]["fetch"];
    assert_eq!(fetch["node"], "ipfs", "{reply}");
    assert_eq!(fetch["path"], format!("/ipfs/{VITALIK_CID}/blog/"));
    // IPFS's strip-list: the cookie never reaches the node.
    assert_eq!(fetch["headers"], json!([["accept", "text/html"]]));
    assert_eq!(fetch["response"], json!(["strip_page_state", "small_text"]));
    assert_eq!(
        fetch["trust"],
        json!({ "name": "verified", "content": "node_asserted" })
    );
    assert_eq!(fetch["retry"]["attempts"], 1);
    assert_eq!(fetch["timers"]["queue_ms"], 15_000);
    assert_eq!(
        result["generations"],
        json!({ "ens": 1, "tezos": 1, "lifecycle": 0 })
    );
    assert_eq!(result["attempts"], 1);
    // The name again: the core's cache, no I/O, no attempt; an external
    // gateway now, whose label is unverified.
    let gateway = json!({ "ipfs": "gateway", "up": true });
    open(
        &mut core,
        4,
        open_params("ipfs://vitalik.eth/", gateway, json!([])),
    );
    let hit = core.recv();
    assert_eq!(hit["id"], 4, "no I/O for a cached name: {hit}");
    let fetch = &hit["result"]["plan"]["fetch"];
    assert_eq!(fetch["path"], format!("/ipfs/{VITALIK_CID}/"));
    assert_eq!(fetch["trust"]["content"], "unverified");
    assert_eq!(hit["result"]["attempts"], 0);
    // Its content asked for over `bzz:`: today's 404.
    open(
        &mut core,
        5,
        open_params("bzz://vitalik.eth/", bundled(), json!([])),
    );
    assert_eq!(
        core.response(5)["result"]["plan"],
        json!({ "error": {
            "status": 404,
            "code": 404,
            "message": "ENS name vitalik.eth resolves to ipfs, not Swarm",
        } })
    );
    // A `bzz:` name whose contenthash is Swarm's.
    let answer = ur_answer(&swarm_contenthash(REFERENCE));
    open(
        &mut core,
        6,
        open_params(
            "bzz://swarm.eth/docs/?q=1",
            bundled(),
            json!([["Accept", "*/*"], ["Range", "bytes=0-"], ["Origin", "x"]]),
        ),
    );
    let (reply, _) = serve_naming(&mut core, 6, Some(&answer));
    let fetch = &reply["result"]["plan"]["fetch"];
    assert_eq!(fetch["node"], "ant", "{reply}");
    assert_eq!(fetch["path"], format!("/bzz/{REFERENCE}/docs/?q=1"));
    assert_eq!(
        fetch["headers"],
        json!([
            ["accept", "*/*"],
            ["range", "bytes=0-"],
            ["swarm-chunk-retrieval-timeout", "30s"],
            ["swarm-redundancy-fallback-mode", "true"],
            ["swarm-redundancy-strategy", "3"],
        ])
    );
    assert_eq!(
        fetch["response"],
        json!(["canonicalize_redirect", "strip_page_state"])
    );
    assert_eq!(fetch["retry"]["attempts"], 10);
    assert_eq!(fetch["trust"]["name"], "verified");
    // An `ipns:` name: under ipns:, a dweb name resolves; other hosts go to
    // the node as they are, with no lookup.
    open(
        &mut core,
        7,
        open_params("ipns://docs.ipfs.tech/install/", native(), json!([])),
    );
    let direct = core.recv();
    assert_eq!(direct["id"], 7, "{direct}");
    assert_eq!(
        direct["result"]["plan"]["fetch"]["path"],
        "/ipns/docs.ipfs.tech/install/"
    );
    // A libp2p key's contenthash: the path names the key as today's
    // contenthash decoding does.
    let mut ipns = vec![0xe5, 0x01, 0x01, 0x72, 0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    ipns.extend([0x42; 32]);
    let decoded = fc_naming::parse_contenthash(&ipns).unwrap().decoded;
    let answer = ur_answer(&ipns);
    open(
        &mut core,
        8,
        open_params("ipns://keyed.eth/x", native(), json!([])),
    );
    let (reply, _) = serve_naming(&mut core, 8, Some(&answer));
    assert_eq!(
        reply["result"]["plan"]["fetch"]["path"],
        format!("/ipns/{decoded}/x"),
        "{reply}"
    );
    // The vault still answers.
    assert!(core.call(9, "vault.status", json!({}))["result"].is_object());
}

#[test]
fn a_tezos_name_whose_providers_fail_is_todays_502() {
    let (_root, mut core) = naming_core();
    open(
        &mut core,
        3,
        open_params("bzz://site.tez/", bundled(), json!([])),
    );
    let (reply, seen) = serve_naming(&mut core, 3, None);
    assert!(
        seen.iter().all(|r| r["method"] == "shell.tezos"),
        "{seen:?}"
    );
    assert_eq!(
        reply["result"]["plan"],
        json!({ "error": {
            "status": 502,
            "code": 502,
            "message": "Tezos Domains resolution failed for site.tez: all Tezos RPC providers failed",
        } }),
        "{reply}"
    );
}

#[test]
fn a_plan_is_cancelled_and_times_out_as_a_lookup_does() {
    let (_root, mut core) = naming_core();
    open(
        &mut core,
        3,
        open_params("bzz://site.eth/", bundled(), json!([])),
    );
    let first = core.recv();
    assert_eq!(first["method"], "shell.rpc", "{first}");
    core.send(&json!({ "type": "cancel", "id": 3 }));
    let reply = response_to(&mut core, 3);
    assert_eq!(reply["error"]["code"], "cancelled", "{reply}");
    // The caller's deadline, with main never answering.
    let mut params = open_params("bzz://other.eth/", bundled(), json!([]));
    params["deadline_ms"] = json!(300);
    let started = Instant::now();
    open(&mut core, 4, params);
    let reply = response_to(&mut core, 4);
    assert_eq!(reply["error"]["code"], "deadline", "{reply}");
    assert!(started.elapsed() >= Duration::from_millis(299));
    // A hash host needs no lookup, so it takes no deadline either.
    let mut params = open_params(&format!("bzz://{REFERENCE}/"), bundled(), json!([]));
    params["deadline_ms"] = json!(0);
    open(&mut core, 5, params);
    assert!(response_to(&mut core, 5)["result"]["plan"]["fetch"].is_object());
}

#[test]
fn a_configuration_change_overtakes_a_plan_which_main_plans_again() {
    let (_root, mut core) = naming_core();
    open(
        &mut core,
        3,
        open_params("ipfs://vitalik.eth/", native(), json!([])),
    );
    let first = core.recv();
    assert_eq!(first["method"], "shell.rpc", "{first}");
    // The ENS part changes while the name resolves.
    let mut changed = common::naming_snapshot();
    changed["rpc"] = json!([{ "endpoint": "e1" }, { "endpoint": "e2" }, { "endpoint": "e3" }]);
    core.send(&request(4, "naming.configure", changed));
    let mut replies = Vec::new();
    while replies.len() < 2 {
        let message = core.recv();
        if message["type"] == "response" {
            replies.push(message);
        }
    }
    let plan = replies.iter().find(|r| r["id"] == 3).unwrap();
    let configured = replies.iter().find(|r| r["id"] == 4).unwrap();
    assert_eq!(configured["result"]["ens"], 2);
    // The plan of an overtaken lookup: under the generations it ran under,
    // which main's fence finds older than its own.
    assert_eq!(
        plan["result"]["plan"]["error"]["message"],
        "ENS resolver error: Name resolution configuration changed while resolving vitalik.eth",
        "{plan}"
    );
    assert_eq!(plan["result"]["generations"]["ens"], 1);
    let used = plan["result"]["attempts"].as_u64().unwrap();
    // Main plans again, with the attempts used and the time left.
    let mut again = open_params("ipfs://vitalik.eth/", native(), json!([]));
    again["attempts_used"] = json!(used);
    again["deadline_ms"] = json!(100_000);
    open(&mut core, 5, again);
    let (reply, _) = serve_naming(&mut core, 5, None);
    assert_eq!(
        reply["result"]["plan"]["fetch"]["path"],
        format!("/ipfs/{VITALIK_CID}/")
    );
    assert_eq!(reply["result"]["generations"]["ens"], 2);
}

#[test]
fn dweb_open_is_mains_own() {
    let (_root, mut core) = naming_core();
    let params = open_params(&format!("bzz://{REFERENCE}/"), bundled(), json!([]));
    let refused = core.call(3, "dweb.open", params.clone());
    assert_eq!(refused["error"]["code"], "forbidden", "{refused}");
    let mut page = request(4, "dweb.open", params);
    page["context"] = json!({ "caller": "page", "page": { "origin": "https://a", "top_origin": "https://a", "frame": 1, "navigation": 1 } });
    core.send(&page);
    let reply = core.response(4);
    assert_eq!(reply["error"]["code"], "forbidden", "{reply}");
    let ok = core.call_shell(
        5,
        "dweb.open",
        open_params(&format!("bzz://{REFERENCE}/"), bundled(), json!([])),
    );
    assert!(ok["result"]["plan"]["fetch"].is_object(), "{ok}");
}

/// PR #62 security review, M1, measured: a hash host's plan with 7,000
/// distinct headers (63,000 units with their overhead, within the 64 KiB
/// bound), asked for while an unrelated lookup waits for its 50 ms
/// deadline. Grouping the headers by rescanning them per name took about
/// 135 ms of the naming thread in release and held that deadline back by
/// as much. Timing-based, so ignored; run it in release:
/// `cargo test --release -p freedom-cored --test dweb -- --ignored --nocapture many_headers`.
#[test]
#[ignore]
// The measurements are the test's report, printed with `--nocapture`.
#[allow(clippy::print_stderr)]
fn many_headers_dont_hold_up_another_lookups_deadline() {
    let (_root, mut core) = naming_core();
    let headers: Vec<[String; 2]> = (0..7_000)
        .map(|i| [format!("h{i:04}"), String::new()])
        .collect();
    let plan = open_params(&format!("bzz://{REFERENCE}/"), bundled(), json!(headers));
    // The lookup, waiting for main, which never answers.
    let lookup = Instant::now();
    core.send(&shell_request(
        3,
        "naming.resolve_content",
        json!({ "name": "vitalik.eth", "deadline_ms": 50 }),
    ));
    let first = core.recv();
    assert_eq!(first["method"], "shell.rpc", "{first}");
    open(&mut core, 4, plan.clone());
    let (mut deadline, mut planned) = (None, None);
    while deadline.is_none() || planned.is_none() {
        let message = core.recv();
        if message["type"] != "response" {
            continue;
        }
        if message["id"] == 3 {
            assert_eq!(message["error"]["code"], "deadline", "{message}");
            deadline = Some(lookup.elapsed());
        } else if message["id"] == 4 {
            assert!(message["result"]["plan"]["fetch"].is_object());
            planned = Some(lookup.elapsed());
        }
    }
    // The core's own CPU time for ten such plans.
    #[cfg(target_os = "linux")]
    let (ticks, start) = (core.cpu_ticks(), Instant::now());
    for id in 10..20 {
        open(&mut core, id, plan.clone());
        response_to(&mut core, id);
    }
    #[cfg(target_os = "linux")]
    eprintln!(
        "ten 7,000-header plans: {:?} wall, {} ms of the core's CPU",
        start.elapsed(),
        (core.cpu_ticks() - ticks) * 10
    );
    let (deadline, planned) = (deadline.unwrap(), planned.unwrap());
    eprintln!("the 50 ms lookup's deadline came at {deadline:?}; the plan at {planned:?}");
    assert!(
        deadline < Duration::from_millis(100),
        "the lookup's 50 ms deadline came at {deadline:?}"
    );
}

// ---------------------------------------------------------------------------
// chain.html

const CONTRACT: &str = "0x5555555555555555555555555555555555555555";

/// Chain 1 reading from `read`, with endpoints `rpc`.
fn chain_snapshot(read: &[&str], rpc: &[&str]) -> Value {
    json!({
        "chain_id": 1,
        "display_name": "Ethereum",
        "read_order": read,
        "broadcast_order": ["direct"],
        // The most a source may take: a debug build moves 8 MiB documents
        // slowly.
        "quorum": { "k": 3, "m": 2, "timeout_ms": 60_000 },
        "rpc": rpc.iter().map(|e| json!({ "endpoint": e, "user_configured": false })).collect::<Vec<_>>(),
        "prover": null,
        "myotis": false,
        "blockscout": null,
    })
}

fn chain_core(env: &[(&str, &str)], snapshot: Value) -> (tempfile::TempDir, Core) {
    let (root, data, locks) = dirs();
    let mut core = spawn_env("serve", &data, &locks, &[], env);
    core.hello_fragments();
    let configured = core.call(2, "chain.configure", json!({ "chains": [snapshot] }));
    assert_eq!(configured["result"]["generations"], json!({ "1": 1 }));
    (root, core)
}

fn html_params(deadline_ms: u64) -> Value {
    json!({
        "chain_id": 1,
        "contract": CONTRACT,
        "origin": format!("web3://{CONTRACT}:1"),
        "deadline_ms": deadline_ms,
    })
}

/// A JSON-RPC answer whose result is `html()`'s encoding of `document`.
fn html_answer(document: &[u8]) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}{}{}"}}"#,
        word(32),
        word(document.len()),
        padded(document)
    )
}

fn rpc_ok(text: &str) -> Value {
    json!({ "result": { "status": 200, "body": b64(text) } })
}

/// The core's next request to main.
fn next_request(core: &mut Core) -> Value {
    loop {
        let message = core.recv();
        if message["type"] == "request" {
            return message;
        }
    }
}

/// The core's reply to `id`, whole or reassembled from its fragments (its
/// credit then returned), reading `seen` first; with the other whole
/// messages passed over on the way.
fn reply_to(core: &mut Core, id: u64, seen: Vec<Wire>) -> (Value, Vec<Value>) {
    let mut seen = seen.into_iter();
    let mut passed = Vec::new();
    let mut payload = Vec::new();
    let mut declared = None;
    loop {
        let wire = seen.next().unwrap_or_else(|| core.recv_wire());
        match wire {
            Wire::Begin { id: begun, bytes } => {
                assert_eq!(begun, id);
                declared = Some(bytes);
            }
            Wire::Fragment(bytes) => payload.extend_from_slice(&bytes),
            Wire::Last(bytes) => {
                payload.extend_from_slice(&bytes);
                assert_eq!(Some(payload.len()), declared);
                core.send_credit();
                passed.extend(seen.filter_map(message_of));
                return (serde_json::from_slice(&payload).unwrap(), passed);
            }
            Wire::Message(message) if message["type"] == "response" && message["id"] == id => {
                passed.extend(seen.filter_map(message_of));
                return (message, passed);
            }
            Wire::Message(message) => passed.push(message),
            Wire::Credit | Wire::Stream { .. } => {}
        }
    }
}

fn message_of(wire: Wire) -> Option<Value> {
    match wire {
        Wire::Message(message) => Some(message),
        _ => None,
    }
}

#[test]
fn an_8_mib_document_through_a_quorum() {
    // The quorum alone: an interactive read caps a source at 2 s only when
    // another follows (design 0005, Deadlines).
    let (_root, mut core) = chain_core(&[], chain_snapshot(&["quorum"], &["a", "b", "c"]));
    // dweb.json's `size-max`: 8 MiB of `a`, a 16 MiB answer, made before
    // the clock runs.
    let document = vec![b'a'; 8 * MIB];
    let answer = rpc_ok(&html_answer(&document));
    core.send(&request(3, "chain.html", html_params(60_000)));
    let asked: Vec<Value> = (0..3).map(|_| next_request(&mut core)).collect();
    for (request, endpoint) in asked.iter().zip(["a", "b", "c"]) {
        assert_eq!(request["method"], "shell.rpc");
        assert_eq!(request["params"]["endpoint"], endpoint);
        let body: Value =
            serde_json::from_str(request["params"]["body"].as_str().unwrap()).unwrap();
        assert_eq!(
            body["params"],
            json!([{ "to": CONTRACT, "data": "0x33c34ac3" }, "latest"])
        );
    }
    let mut seen = answer_request(&mut core, &asked[0], answer.clone());
    seen.extend(answer_request(&mut core, &asked[1], answer));
    let (reply, others) = reply_to(&mut core, 3, seen);
    let result = &reply["result"];
    let html = base64::engine::general_purpose::STANDARD
        .decode(result["html_base64"].as_str().unwrap_or_else(|| {
            panic!(
                "{}",
                reply.to_string().chars().take(2000).collect::<String>()
            )
        }))
        .unwrap();
    assert_eq!(html, document);
    assert_eq!(
        result["hash"],
        "0xfce46356f0f67551c340dc92197d8b4bdb05af6edad8ecee3746785bb2e58b8e"
    );
    assert_eq!(result["source"], "quorum");
    assert_eq!(result["verified"], true);
    assert_eq!(result["trust"]["level"], "verified");
    assert_eq!(result["class"], "trusted");
    assert_eq!(result["generation"], 1);
    // The third member was cancelled once two agreed.
    let mut cancels: Vec<Value> = others
        .into_iter()
        .filter(|m| m["type"] == "cancel")
        .collect();
    while cancels.is_empty() {
        let message = core.recv();
        if message["type"] == "cancel" {
            cancels.push(message);
        }
    }
    assert_eq!(cancels[0]["id"], asked[2]["id"]);
    assert!(core.call(4, "vault.status", json!({}))["result"].is_object());
}

#[test]
fn a_document_that_isnt_served_is_todays_error() {
    let (_root, mut core) = chain_core(&[], chain_snapshot(&["direct"], &["a"]));
    // Main's own caller kind takes it too.
    core.send(&shell_request(3, "chain.html", html_params(60_000)));
    let rpc = next_request(&mut core);
    // One byte past the encoded bound, and no hex at all: 413 still.
    let over = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#,
        "zz".repeat(8 * MIB + 96)
    );
    let seen = answer_request(&mut core, &rpc, rpc_ok(&over));
    let (reply, _) = reply_to(&mut core, 3, seen);
    let error = &reply["error"];
    assert_eq!(error["code"], "chain_error", "{reply}");
    assert_eq!(
        error["data"],
        json!({
            "kind": "core",
            "constructor": "Error",
            "message": "html() response exceeds Freedom's 8 MiB limit",
            "props": { "code": "ONCHAIN_APP_TOO_LARGE" },
            "undefined_keys": [],
            "generation": 1,
        })
    );
    // A node's error passes through as one: `kind` tells it from the core's.
    core.send(&request(4, "chain.html", html_params(60_000)));
    let rpc = next_request(&mut core);
    let node =
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":"ONCHAIN_APP_TOO_LARGE","message":"no"}}"#;
    answer_request(&mut core, &rpc, rpc_ok(node));
    let (reply, _) = reply_to(&mut core, 4, Vec::new());
    assert_eq!(reply["error"]["data"]["kind"], "node", "{reply}");
    // A small document from one unverified endpoint: staged by main.
    core.send(&request(5, "chain.html", html_params(60_000)));
    let rpc = next_request(&mut core);
    answer_request(&mut core, &rpc, rpc_ok(&html_answer(b"<p>app</p>")));
    let (reply, _) = reply_to(&mut core, 5, Vec::new());
    assert_eq!(reply["result"]["class"], "untrusted", "{reply}");
    assert_eq!(reply["result"]["trust"]["agreed"], json!([{ "ref": "a" }]));
}

#[test]
fn cancel_deadline_and_a_configuration_change() {
    let (_root, mut core) = chain_core(&[], chain_snapshot(&["direct"], &["a"]));
    // A cancel: `cancelled` at once, its exchange cancelled.
    core.send(&request(3, "chain.html", html_params(60_000)));
    let rpc = next_request(&mut core);
    core.send(&json!({ "type": "cancel", "id": 3 }));
    let mut cancelled = None;
    let mut cancel = None;
    while cancelled.is_none() || cancel.is_none() {
        let message = core.recv();
        match message["type"].as_str() {
            Some("response") if message["id"] == 3 => cancelled = Some(message),
            Some("cancel") => cancel = Some(message),
            _ => {}
        }
    }
    let cancelled = cancelled.unwrap();
    assert_eq!(cancelled["error"]["code"], "cancelled", "{cancelled}");
    assert_eq!(cancelled["error"]["data"]["generation"], 1);
    assert_eq!(cancel.unwrap()["id"], rpc["id"]);
    core.send(&json!({ "type": "response", "id": rpc["id"], "error": { "code": "cancelled", "message": "Cancelled" } }));
    // The caller's deadline, with main never answering.
    let started = Instant::now();
    core.send(&request(4, "chain.html", html_params(300)));
    let held = next_request(&mut core);
    let reply = response_to(&mut core, 4);
    assert_eq!(reply["error"]["code"], "deadline", "{reply}");
    assert!(started.elapsed() >= Duration::from_millis(299));
    core.send(&json!({ "type": "response", "id": held["id"], "error": { "code": "cancelled", "message": "Cancelled" } }));
    // A configuration change ends it with `reconfigured`, under the
    // generation it ran under; main sends it again, once.
    core.send(&request(5, "chain.html", html_params(60_000)));
    let stale = next_request(&mut core);
    core.send(&request(
        6,
        "chain.configure",
        json!({ "chains": [chain_snapshot(&["direct"], &["b"])] }),
    ));
    let mut replies = Vec::new();
    while replies.len() < 2 {
        let message = core.recv();
        if message["type"] == "response" {
            replies.push(message);
        }
    }
    assert_eq!(replies[0]["id"], 5, "the ended request first: {replies:?}");
    assert_eq!(replies[0]["error"]["code"], "reconfigured");
    assert_eq!(replies[0]["error"]["data"]["generation"], 1);
    assert_eq!(replies[1]["result"]["generations"], json!({ "1": 2 }));
    core.send(&json!({ "type": "response", "id": stale["id"], "result": { "not_sent": true } }));
    core.send(&request(7, "chain.html", html_params(60_000)));
    let rpc = next_request(&mut core);
    assert_eq!(rpc["params"]["endpoint"], "b");
    assert_eq!(rpc["params"]["generation"], 2);
    answer_request(&mut core, &rpc, rpc_ok(&html_answer(b"x")));
    let (reply, _) = reply_to(&mut core, 7, Vec::new());
    assert_eq!(reply["result"]["generation"], 2, "{reply}");
}

#[test]
fn the_chain_budget_ends_it() {
    // The chain total at 24 MiB (a debug-only hook): an 8 MiB document's
    // answer, 22 MiB as base64, can't be read beside the rest.
    let (_root, mut core) = chain_core(
        &[("FREEDOM_CORED_TEST_CHAIN_TOTAL_BYTES", "25165824")],
        chain_snapshot(&["direct"], &["a"]),
    );
    core.send(&request(3, "chain.html", html_params(60_000)));
    let rpc = next_request(&mut core);
    let seen = answer_request(&mut core, &rpc, rpc_ok(&html_answer(&vec![b'a'; 8 * MIB])));
    let (reply, _) = reply_to(&mut core, 3, seen);
    assert_eq!(reply["error"]["code"], "budget", "{reply}");
    assert_eq!(reply["error"]["data"]["generation"], 1);
    // The budget is the request's: the next document is served.
    core.send(&request(4, "chain.html", html_params(60_000)));
    let rpc = next_request(&mut core);
    answer_request(&mut core, &rpc, rpc_ok(&html_answer(b"<p>small</p>")));
    let (reply, _) = reply_to(&mut core, 4, Vec::new());
    assert!(reply["result"]["html_base64"].is_string(), "{reply}");
}

// ---------------------------------------------------------------------------
// dweb.verify (design 0009): the dweb thread through the binary

/// Design 0009 end to end: `dweb.verify`, `dweb.forget` and
/// `shell.dweb_get`, the real binary at protocol 2 with the test playing
/// main. Main answers the core's pieces as the honest nodes of
/// vectors/dweb-verify.json do (Ant's chunks and files, the gateway's
/// blocks), with the changes a test makes, and reads the verified bodies
/// the core streams back.
mod verify {
    use std::collections::{BTreeMap, HashMap};

    use sha2::{Digest, Sha256};

    use super::common::{KIND_ABORT, KIND_DATA, KIND_END, KIND_STREAM_CREDIT, stream_frame};
    use super::*;

    const WINDOW: usize = 128 << 10;
    const MAX_DATA: usize = 64 << 10;
    const SITE_A: &str = "3c8b9184787f719e7184f51b5c595a950d8cec49c765dc0e5a8f1c253e54591c";
    const SITE_V1: &str = "bafybeiguwjmddvr4iiah6ekgvrovb5zfb6eg5c6loikxvxlxzlwea5dabm";
    /// file-524288-rs0's single-file manifest: `/file.bin`, 512 KiB.
    const FILE_512K: &str = "eee70ccdb4cff5547504369812f82dcb20d77ab263fe38ae77f4ca29b4e00e66";
    const INDEX_HTML: &[u8] = b"<!doctype html><title>site</title><p>index</p>\n";

    fn vectors(name: &str) -> Value {
        let path = format!("{}/../../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn unb64(v: &Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(v.as_str().unwrap())
            .unwrap()
    }

    /// The vectors' content: SHA-256(seed ‖ u64_be(i)), concatenated, cut.
    fn content(seed: &str, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n + 32);
        let mut i = 0u64;
        while out.len() < n {
            let mut h = Sha256::new();
            h.update(seed.as_bytes());
            h.update(i.to_be_bytes());
            out.extend_from_slice(&h.finalize());
            i += 1;
        }
        out.truncate(n);
        out
    }

    /// How main answers a piece.
    #[derive(Clone)]
    enum Answer {
        Whole(u16, Vec<(String, String)>, Vec<u8>),
        /// A stream: its head, its body, and, with `cut`, an abort with that
        /// code after that many bytes instead of its end.
        Stream {
            status: u16,
            headers: Vec<(String, String)>,
            body: Vec<u8>,
            cut: Option<(usize, &'static str)>,
        },
        /// Never answered until the core cancels it.
        Hold,
    }

    /// The honest nodes of dweb-verify.json: Ant's chunks and files, the
    /// gateway's blocks. Read once, for every test.
    struct Honest {
        chunks: HashMap<String, Vec<u8>>,
        files: HashMap<String, Vec<u8>>,
        blocks: HashMap<String, Vec<u8>>,
    }

    fn honest() -> &'static Honest {
        static HONEST: std::sync::OnceLock<Honest> = std::sync::OnceLock::new();
        HONEST.get_or_init(Honest::read)
    }

    /// The honest nodes, and the answers a test changes, by path prefix.
    /// Its gateway serves raw blocks only.
    struct World {
        honest: &'static Honest,
        changes: Vec<(String, Answer)>,
        /// Streams whose path starts so are cut after that many bytes, with
        /// that abort code.
        cuts: Vec<(String, usize, &'static str)>,
    }

    impl Honest {
        fn read() -> Self {
            let d = vectors("dweb-verify.json");
            let mut chunks = HashMap::new();
            for (a, w) in d["swarm"]["chunks"].as_object().unwrap() {
                chunks.insert(a.clone(), unb64(w));
            }
            let mut files = HashMap::new();
            for f in d["swarm"]["files"].as_array().unwrap() {
                let size = f["size"].as_u64().unwrap() as usize;
                let seed = f["seed"].as_str().unwrap();
                files.insert(f["root"].as_str().unwrap().to_owned(), content(seed, size));
            }
            for m in d["swarm"]["manifests"].as_array().unwrap() {
                for e in m["entries"].as_array().unwrap() {
                    if let (Some(r), Some(seed)) = (e["data_ref"].as_str(), e["seed"].as_str()) {
                        let size = e["size"].as_u64().unwrap() as usize;
                        files.insert(r.to_owned(), content(seed, size));
                    }
                }
            }
            let mut blocks = HashMap::new();
            for (c, b) in d["ipfs"]["blocks"].as_object().unwrap() {
                blocks.insert(c.clone(), unb64(b));
            }
            for dir in d["ipfs"]["directories"].as_array().unwrap() {
                for e in dir["entries"].as_array().unwrap() {
                    let size = e["size"].as_u64().unwrap() as usize;
                    let bytes = match (e["text"].as_str(), e["seed"].as_str()) {
                        (Some(t), _) => t.as_bytes().to_vec(),
                        (None, Some(seed)) => content(seed, size),
                        _ => continue,
                    };
                    for l in e["leaves"].as_array().unwrap() {
                        let from = l["from"].as_u64().unwrap() as usize;
                        let len = l["length"].as_u64().unwrap() as usize;
                        blocks
                            .entry(l["cid"].as_str().unwrap().to_owned())
                            .or_insert_with(|| bytes[from..from + len].to_vec());
                    }
                }
            }
            Self {
                chunks,
                files,
                blocks,
            }
        }
    }

    impl World {
        fn new() -> Self {
            Self {
                honest: honest(),
                changes: Vec::new(),
                cuts: Vec::new(),
            }
        }

        fn cut(mut self, prefix: &str, after: usize, code: &'static str) -> Self {
            self.cuts.push((prefix.to_owned(), after, code));
            self
        }

        fn change(mut self, prefix: &str, answer: Answer) -> Self {
            self.changes.push((prefix.to_owned(), answer));
            self
        }

        fn stream(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Answer {
            Answer::Stream {
                status,
                headers,
                body,
                cut: None,
            }
        }

        fn answer(&self, path: &str, headers: &[(String, String)]) -> Answer {
            let mut answer = self.honest(path, headers);
            if let Answer::Stream { cut, .. } = &mut answer
                && let Some((_, after, code)) = self.cuts.iter().find(|(p, ..)| path.starts_with(p))
            {
                *cut = Some((*after, *code));
            }
            answer
        }

        fn honest(&self, path: &str, headers: &[(String, String)]) -> Answer {
            if let Some((_, a)) = self.changes.iter().find(|(p, _)| path.starts_with(p)) {
                return a.clone();
            }
            // The gateway serves no CARs: a CAR request gets a 200 that
            // isn't one, as a gateway that ignores `format=car` answers.
            if path.contains("format=car") {
                let html = ("content-type".to_owned(), "text/html".to_owned());
                return Self::stream(200, vec![html], b"<p>not a CAR</p>".to_vec());
            }
            let not_found = || Answer::Whole(404, vec![], b"{}".to_vec());
            if let Some(a) = path.strip_prefix("/chunks/") {
                return match self.honest.chunks.get(a) {
                    Some(w) => Answer::Whole(200, vec![], w.clone()),
                    None => not_found(),
                };
            }
            if let Some(r) = path.strip_prefix("/bytes/") {
                let Some(file) = self.honest.files.get(r) else {
                    return Self::stream(404, vec![], vec![]);
                };
                let range = headers.iter().find(|(n, _)| n == "range").unwrap();
                let (a, b) = range
                    .1
                    .strip_prefix("bytes=")
                    .unwrap()
                    .split_once('-')
                    .unwrap();
                let (a, b): (usize, usize) = (a.parse().unwrap(), b.parse().unwrap());
                let b = b.min(file.len() - 1);
                let cr = format!("bytes {a}-{b}/{}", file.len());
                return Self::stream(
                    206,
                    vec![("content-range".into(), cr)],
                    file[a..=b].to_vec(),
                );
            }
            let cid = path
                .strip_prefix("/ipfs/")
                .unwrap()
                .split('?')
                .next()
                .unwrap();
            match self.honest.blocks.get(cid) {
                Some(b) => Self::stream(
                    200,
                    vec![("content-type".into(), "application/vnd.ipld.raw".into())],
                    b.clone(),
                ),
                None => Self::stream(404, vec![], vec![]),
            }
        }
    }

    /// A piece main is streaming: what is left of it, and the core's credit.
    struct Flow {
        body: Vec<u8>,
        at: usize,
        room: usize,
        cut: Option<(usize, &'static str)>,
    }

    /// What a `dweb.verify` got.
    #[derive(Default, Debug)]
    struct Got {
        result: Option<Value>,
        body: Vec<u8>,
        ended: bool,
        abort: Option<Value>,
    }

    impl Got {
        fn done(&self) -> bool {
            match &self.result {
                None => false,
                Some(m) if m.get("error").is_some() => true,
                Some(m) if m["result"]["body"] == true => self.ended || self.abort.is_some(),
                Some(_) => true,
            }
        }
    }

    /// The test as main: the core at protocol 2 and the world it reaches.
    struct Main {
        _dir: tempfile::TempDir,
        core: Core,
        world: World,
        next_id: u64,
        flows: BTreeMap<u64, Flow>,
        /// Every `shell.dweb_get` the core sent: its ID and params.
        asked: Vec<(u64, Value)>,
        held: Vec<u64>,
        /// The core's cancels of its pieces.
        cancels: Vec<u64>,
        got: BTreeMap<u64, Got>,
        /// Whether main credits the verified bodies as they come.
        credits_bodies: bool,
    }

    impl Main {
        fn new(world: World) -> Self {
            let (dir, data, locks) = dirs();
            let mut core = spawn("serve", &data, &locks, &[]);
            let hello = core.hello_streams();
            assert_eq!(hello["result"]["protocol"], 2, "{hello}");
            let caps = hello["result"]["capabilities"].as_array().unwrap();
            assert!(caps.contains(&json!("dweb.verify")), "{hello}");
            Self {
                _dir: dir,
                core,
                world,
                next_id: 2,
                flows: BTreeMap::new(),
                asked: Vec::new(),
                held: Vec::new(),
                cancels: Vec::new(),
                got: BTreeMap::new(),
                credits_bodies: true,
            }
        }

        /// Sends `method` with `params`; its ID.
        fn call(&mut self, method: &str, params: Value) -> u64 {
            let id = self.next_id;
            self.next_id += 1;
            self.core.send(&shell_request(id, method, params));
            self.got.insert(id, Got::default());
            id
        }

        fn verify(&mut self, params: Value) -> u64 {
            self.call("dweb.verify", params)
        }

        /// Writes what the core's credit allows of each piece, ending or
        /// cutting a piece once its bytes have gone. True if it wrote.
        fn send_pieces(&mut self) -> bool {
            let mut wrote = false;
            let mut ended = Vec::new();
            for (&id, f) in self.flows.iter_mut() {
                let stop = f.cut.map_or(f.body.len(), |(n, _)| n.min(f.body.len()));
                while f.at < stop && f.room > 0 {
                    let n = f.room.min(MAX_DATA).min(stop - f.at);
                    let frame = stream_frame(KIND_DATA, id, &f.body[f.at..f.at + n]);
                    self.core.send_raw(&frame);
                    f.at += n;
                    f.room -= n;
                    wrote = true;
                }
                if f.at == stop {
                    match f.cut {
                        Some((_, code)) => {
                            let abort = json!({ "code": code, "message": "cut" }).to_string();
                            self.core
                                .send_raw(&stream_frame(KIND_ABORT, id, abort.as_bytes()));
                        }
                        None => self.core.send_raw(&stream_frame(KIND_END, id, b"")),
                    }
                    ended.push(id);
                    wrote = true;
                }
            }
            for id in ended {
                self.flows.remove(&id);
            }
            wrote
        }

        fn respond(&mut self, id: u64, result: Value) {
            self.core
                .send(&json!({ "type": "response", "id": id, "result": result }));
        }

        /// A `shell.dweb_get`, answered as the world answers it.
        fn piece(&mut self, request: &Value) {
            let id = request["id"].as_u64().unwrap();
            let params = request["params"].clone();
            let path = params["path"].as_str().unwrap().to_owned();
            let headers: Vec<(String, String)> = params["headers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| (h[0].as_str().unwrap().into(), h[1].as_str().unwrap().into()))
                .collect();
            self.asked.push((id, params.clone()));
            let pairs = |h: &[(String, String)]| -> Value {
                h.iter()
                    .map(|(n, v)| json!([n, v]))
                    .collect::<Vec<_>>()
                    .into()
            };
            match self.world.answer(&path, &headers) {
                Answer::Whole(status, headers, body) => self.respond(
                    id,
                    json!({ "status": status, "headers": pairs(&headers), "body_base64": b64(body) }),
                ),
                Answer::Stream {
                    status,
                    headers,
                    body,
                    cut,
                } => {
                    assert_eq!(params["stream"], true, "{path}");
                    self.respond(
                        id,
                        json!({ "status": status, "headers": pairs(&headers), "body": true }),
                    );
                    self.flows.insert(
                        id,
                        Flow {
                            body,
                            at: 0,
                            room: WINDOW,
                            cut,
                        },
                    );
                }
                Answer::Hold => self.held.push(id),
            }
        }

        /// One frame from the core, handled as main handles it.
        fn take(&mut self, wire: Wire) {
            match wire {
                Wire::Message(m) if m["type"] == "request" => {
                    assert_eq!(m["method"], "shell.dweb_get", "{m}");
                    self.piece(&m);
                }
                Wire::Message(m) if m["type"] == "cancel" => {
                    let id = m["id"].as_u64().unwrap();
                    self.cancels.push(id);
                    if self.flows.remove(&id).is_some() {
                        let abort = json!({ "code": "cancelled", "message": "Cancelled" });
                        self.core.send_raw(&stream_frame(
                            KIND_ABORT,
                            id,
                            abort.to_string().as_bytes(),
                        ));
                    } else if let Some(at) = self.held.iter().position(|h| *h == id) {
                        self.held.remove(at);
                        self.respond(id, json!({ "failed": "aborted" }));
                    }
                }
                Wire::Message(m) if m["type"] == "response" => {
                    let id = m["id"].as_u64().unwrap();
                    let got = self.got.get_mut(&id).expect("a response to main's request");
                    assert!(got.result.is_none(), "a second response: {m}");
                    got.result = Some(m);
                }
                Wire::Stream { kind, id, rest } => match kind {
                    KIND_DATA => {
                        let got = self.got.get_mut(&id).expect("a body of main's request");
                        assert!(!got.ended && got.abort.is_none());
                        got.body.extend_from_slice(&rest);
                        if self.credits_bodies {
                            let n = u32::try_from(rest.len()).unwrap().to_be_bytes();
                            self.core
                                .send_raw(&stream_frame(KIND_STREAM_CREDIT, id, &n));
                        }
                    }
                    KIND_END => self.got.get_mut(&id).unwrap().ended = true,
                    KIND_ABORT => {
                        self.got.get_mut(&id).unwrap().abort =
                            Some(serde_json::from_slice(&rest).unwrap());
                    }
                    KIND_STREAM_CREDIT => {
                        let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
                        if let Some(f) = self.flows.get_mut(&id) {
                            f.room += n;
                        }
                    }
                    other => panic!("stream kind {other:#04x}"),
                },
                other => panic!("unexpected from the core: {other:?}"),
            }
        }

        /// Runs main until `done`, or until nothing has moved for `quiet`.
        fn run_until(&mut self, quiet: Duration, done: impl Fn(&Self) -> bool) -> bool {
            loop {
                if done(self) {
                    return true;
                }
                let wrote = self.send_pieces();
                let wait = if wrote {
                    Duration::from_millis(1)
                } else {
                    quiet
                };
                match self.core.recv_wire_within(wait) {
                    Some(wire) => self.take(wire),
                    None if !wrote => return done(self),
                    None => {}
                }
            }
        }

        /// Runs main until each of `ids` is answered whole.
        fn settle(&mut self, ids: &[u64]) {
            let ok = self.run_until(Duration::from_secs(20), |m| {
                ids.iter().all(|id| m.got[id].done())
            });
            assert!(
                ok,
                "{:?}",
                ids.iter().map(|id| &self.got[id]).collect::<Vec<_>>()
            );
        }

        fn result(&self, id: u64) -> &Value {
            &self.got[&id].result.as_ref().unwrap()["result"]
        }

        fn error_code(&self, id: u64) -> &Value {
            &self.got[&id].result.as_ref().unwrap()["error"]["code"]
        }
    }

    /// A verify plan for `root` and `path`, the backend's retry, timers,
    /// response and trust as dweb.open writes them (dweb-verify-plans.json).
    fn plan(root: Value, path: &str, headers: Value) -> Value {
        let node = if root.get("swarm").is_some() {
            "ant"
        } else {
            "ipfs"
        };
        let plans = vectors("dweb-verify-plans.json");
        let mut plan = plans["requests"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["plan"]["verify"]["node"] == node)
            .unwrap()["plan"]
            .clone();
        let v = &mut plan["verify"];
        v["root"] = root;
        v["path"] = path.into();
        v["query"] = "".into();
        v["headers"] = headers;
        plan
    }

    fn params(plan: Value, method: &str, car: Option<bool>) -> Value {
        let mut p = json!({
            "plan": plan, "method": method, "partition": null, "private": false, "deadline_ms": 360_000,
        });
        if let Some(car) = car {
            p["car"] = car.into();
        }
        p
    }

    fn swarm(path: &str) -> Value {
        params(
            plan(json!({ "swarm": SITE_A }), path, json!([])),
            "GET",
            None,
        )
    }

    fn ipfs(path: &str, car: bool) -> Value {
        params(
            plan(json!({ "ipfs": SITE_V1 }), path, json!([])),
            "GET",
            Some(car),
        )
    }

    #[test]
    fn gets_and_heads_for_swarm_and_ipfs() {
        let mut m = Main::new(World::new());
        let a = m.verify(swarm("/index.html"));
        let b = m.verify(swarm("/style.css"));
        let c = m.verify(ipfs("/index.html", false));
        let mut head = swarm("/style.css");
        head["method"] = "HEAD".into();
        let d = m.verify(head);
        let mut head = ipfs("/index.html", false);
        head["method"] = "HEAD".into();
        let e = m.verify(head);
        m.settle(&[a, b, c, d, e]);
        for id in [a, b, c] {
            assert_eq!(m.result(id)["status"], 200, "{:?}", m.got[&id]);
            assert_eq!(m.result(id)["body"], true);
            assert_eq!(m.result(id)["trust"]["content"], "verified");
            assert!(m.got[&id].ended, "{id}");
        }
        assert_eq!(m.got[&a].body, content("site-index", 300));
        assert_eq!(m.got[&b].body, content("site-style", 5000));
        assert_eq!(m.got[&c].body, INDEX_HTML);
        // A HEAD's head is the GET's, as the bundled node answers a HEAD
        // (Ant's has no `accept-ranges`), with no body and no stream.
        for (get, head) in [(b, d), (c, e)] {
            let (g, h) = (m.result(get), m.result(head));
            assert_eq!((&h["status"], &h["trust"]), (&g["status"], &g["trust"]));
            assert_eq!(h["body"], false);
            for header in h["headers"].as_array().unwrap() {
                assert!(g["headers"].as_array().unwrap().contains(header), "{h} {g}");
            }
            assert!(m.got[&head].body.is_empty() && !m.got[&head].ended);
        }
    }

    #[test]
    fn a_range_is_an_exact_206() {
        let mut m = Main::new(World::new());
        let ranged = plan(
            json!({ "swarm": SITE_A }),
            "/style.css",
            json!([["range", "bytes=100-199"]]),
        );
        let id = m.verify(params(ranged, "GET", None));
        m.settle(&[id]);
        assert_eq!(m.result(id)["status"], 206);
        assert_eq!(m.got[&id].body, content("site-style", 5000)[100..200]);
    }

    /// Amendment 1's vectors: for each node, the bundled node's own 404,
    /// proven, is a head with its trust and the node's body; the core's own
    /// 404 is an error plan. Each is exactly what dweb-verify-cases.json's
    /// `answers` writes.
    #[test]
    fn a_nodes_own_404_is_a_head_and_the_cores_is_an_error_plan() {
        let cases = vectors("dweb-verify-cases.json");
        let requests = cases["requests"].as_array().unwrap();
        for answer in cases["answers"].as_array().unwrap() {
            let case = requests.iter().find(|c| c["id"] == answer["case"]).unwrap();
            let mut world = World::new();
            for change in case["world"]["changes"].as_array().unwrap() {
                let body = unb64(&change["body"]["base64"]);
                let status = change["status"].as_u64().unwrap() as u16;
                world = match change["piece"].as_str().unwrap() {
                    "chunk" => {
                        let path = format!("/chunks/{}", change["address"].as_str().unwrap());
                        world.change(&path, Answer::Whole(status, vec![], body))
                    }
                    "car" => world.change("/ipfs/", World::stream(status, vec![], body)),
                    other => panic!("{other}"),
                };
            }
            let p = &case["plan"];
            let plan = plan(
                p["root"].clone(),
                p["path"].as_str().unwrap(),
                p["headers"].clone(),
            );
            let car = (p["node"] == "ipfs").then(|| case["world"]["gateway"]["car"] == true);
            let mut m = Main::new(world);
            let id = m.verify(params(plan, case["method"].as_str().unwrap(), car));
            m.settle(&[id]);
            assert_eq!(m.result(id), &answer["result"], "{}", answer["case"]);
            if let Some(body) = answer.get("body") {
                assert_eq!(
                    m.got[&id].body,
                    unb64(&body["base64"]),
                    "{}",
                    answer["case"]
                );
                assert!(m.got[&id].ended);
            }
        }
    }

    #[test]
    fn a_cancel_before_the_head_is_cancelled_and_frees_its_pieces() {
        let mut m = Main::new(World::new().change("/chunks/", Answer::Hold));
        let id = m.verify(swarm("/index.html"));
        assert!(m.run_until(Duration::from_secs(10), |m| !m.held.is_empty()));
        m.core.send(&json!({ "type": "cancel", "id": id }));
        m.settle(&[id]);
        assert_eq!(m.error_code(id), "cancelled");
        // Its piece was cancelled at main, and answered `aborted`.
        assert!(m.run_until(Duration::from_secs(10), |m| m.held.is_empty()));
        assert!(!m.cancels.is_empty());
        // The core goes on.
        m.world.changes.clear();
        let next = m.verify(swarm("/index.html"));
        m.settle(&[next]);
        assert_eq!(m.got[&next].body, content("site-index", 300));
    }

    #[test]
    fn a_cancel_mid_body_aborts_it_cancelled() {
        let mut m = Main::new(World::new());
        // The page reads nothing: the core sends one window of the body,
        // then waits for credit.
        m.credits_bodies = false;
        let id = m.verify(ipfs("/img/photo.jpg", false));
        m.run_until(Duration::from_secs(2), |m| m.got[&id].body.len() >= WINDOW);
        assert_eq!(m.result(id)["status"], 200);
        assert_eq!(m.got[&id].body.len(), WINDOW);
        m.core.send(&json!({ "type": "cancel", "id": id }));
        m.settle(&[id]);
        assert_eq!(m.got[&id].abort.as_ref().unwrap()["code"], "cancelled");
        assert!(!m.got[&id].ended);
        // Nothing of its pieces is left open at main.
        m.run_until(Duration::from_secs(2), |m| m.flows.is_empty());
        assert!(m.flows.is_empty() && m.held.is_empty());
        let next = m.verify(ipfs("/index.html", false));
        m.credits_bodies = true;
        m.settle(&[next]);
        assert_eq!(m.got[&next].body, INDEX_HTML);
    }

    #[test]
    fn dweb_forget_drops_the_partitions_structure() {
        let mut m = Main::new(World::new());
        let chunks = |m: &Main| {
            m.asked
                .iter()
                .filter(|(_, p)| p["path"].as_str().unwrap().starts_with("/chunks/"))
                .count()
        };
        let mut counts = Vec::new();
        for step in 0..3 {
            if step == 2 {
                let id = m.call("dweb.forget", json!({ "partition": null }));
                m.settle(&[id]);
                assert_eq!(m.result(id), &json!({}));
            }
            let before = chunks(&m);
            let id = m.verify(swarm("/index.html"));
            m.settle(&[id]);
            assert_eq!(m.got[&id].body, content("site-index", 300));
            counts.push(chunks(&m) - before);
        }
        // The second read the manifest from the partition's cache; once
        // forgotten, the third fetched it again.
        assert!(counts[1] < counts[0], "{counts:?}");
        assert_eq!(counts[2], counts[0], "{counts:?}");
        // Its params are read strictly.
        let bad = m.call("dweb.forget", json!({ "partition": null, "extra": 1 }));
        m.settle(&[bad]);
        assert_eq!(m.error_code(bad), "invalid_argument");
    }

    #[test]
    fn verify_params_are_read_strictly() {
        let mut m = Main::new(World::new());
        let mut wrong = Vec::new();
        // `car` is the IPFS plan's own: required there, refused for Ant.
        let mut p = swarm("/index.html");
        p["car"] = true.into();
        wrong.push(m.verify(p));
        let mut p = ipfs("/index.html", false);
        p.as_object_mut().unwrap().remove("car");
        wrong.push(m.verify(p));
        let mut p = swarm("/index.html");
        p["extra"] = 1.into();
        wrong.push(m.verify(p));
        m.settle(&wrong);
        for id in wrong {
            assert_eq!(m.error_code(id), "invalid_argument", "{:?}", m.got[&id]);
        }
    }

    #[test]
    fn a_stalled_piece_truncates_the_body_piece_failed() {
        // style.css's /bytes piece stalls after 1,000 bytes, inside its first
        // leaf: main's body idle timer ends it (as `stall-before-needed`).
        let world = World::new().cut("/bytes/", 1000, "stalled");
        let mut m = Main::new(world);
        let id = m.verify(swarm("/style.css"));
        m.settle(&[id]);
        assert_eq!(
            m.result(id)["status"],
            200,
            "{:?} {:?}",
            m.got[&id],
            m.asked
        );
        assert!(m.got[&id].body.is_empty());
        assert_eq!(
            m.got[&id].abort,
            Some(
                json!({ "code": "piece_failed", "message": "The external Swarm node stopped sending" })
            )
        );
    }

    #[test]
    fn a_wrong_car_true_falls_back_to_raw_blocks() {
        // The gateway serves no CARs, though main says it does: it answers
        // a CAR request with a 200 that isn't one.
        let mut m = Main::new(World::new());
        let id = m.verify(ipfs("/index.html", true));
        m.settle(&[id]);
        assert_eq!(m.result(id)["status"], 200);
        assert_eq!(m.got[&id].body, INDEX_HTML);
        // The CAR went first; each CAR was cancelled, and raw blocks carried
        // the walk.
        let path = |p: &Value| p["path"].as_str().unwrap().to_owned();
        assert!(path(&m.asked[0].1).contains("format=car"), "{:?}", m.asked);
        for (get, p) in &m.asked {
            if path(p).contains("format=car") {
                assert!(m.cancels.contains(get), "{:?}", m.asked);
            }
        }
        assert!(
            m.asked
                .iter()
                .any(|(_, p)| path(p).ends_with("?format=raw"))
        );
    }

    #[test]
    fn a_stream_frame_past_credit_is_a_protocol_error() {
        // The page reads nothing, so the core credits a piece only as its
        // bytes leave in the body: once that waits, so does the piece.
        let mut m = Main::new(World::new());
        m.credits_bodies = false;
        let id = m.verify(params(
            plan(json!({ "swarm": FILE_512K }), "/file.bin", json!([])),
            "GET",
            None,
        ));
        m.run_until(Duration::from_secs(2), |_| false);
        assert!(m.got[&id].body.len() <= WINDOW);
        // A piece still open, its credit spent or not: one byte past it.
        let (&get, f) = m
            .flows
            .iter_mut()
            .find(|(_, f)| f.body.len() - f.at > f.room)
            .unwrap_or_else(|| panic!("no piece waits for credit: {:?} {:?}", m.got[&id], m.asked));
        let n = f.room + 1;
        let bytes = f.body[f.at..f.at + n].to_vec();
        f.at += n;
        for part in bytes.chunks(MAX_DATA) {
            m.core.send_raw(&stream_frame(KIND_DATA, get, part));
        }
        assert_eq!(m.core.exit_code(Duration::from_secs(10)), 76);
        let stderr = m.core.stderr();
        assert!(stderr.contains("window_overrun"), "{stderr}");
    }

    #[test]
    fn main_gone_mid_body_ends_the_core() {
        let mut m = Main::new(World::new());
        m.credits_bodies = false;
        let id = m.verify(ipfs("/img/photo.jpg", false));
        m.run_until(Duration::from_secs(2), |m| m.got[&id].body.len() >= WINDOW);
        assert_eq!(m.got[&id].body.len(), WINDOW);
        // Main crashes: stdin closes with a body half sent and pieces open.
        // The core stops its dweb thread and hashing pool and exits.
        m.core.close_stdin();
        assert_eq!(m.core.exit_code(Duration::from_secs(10)), 0);
    }

    #[test]
    fn at_protocol_1_stream_frames_and_dweb_methods_are_unknown() {
        let (_dir, data, locks) = dirs();
        let mut core = spawn("serve", &data, &locks, &[]);
        core.hello();
        let reply = core.call_shell(2, "dweb.verify", swarm("/index.html"));
        assert_eq!(reply["error"]["code"], "unknown_method", "{reply}");
        core.send_raw(&stream_frame(KIND_STREAM_CREDIT, 2, &1u32.to_be_bytes()));
        assert_eq!(core.exit_code(Duration::from_secs(10)), 76);
        assert!(core.stderr().contains("unknown_frame_kind"));
    }
}
