//! Design 0006 end to end: `dweb.open`'s plans and `chain.html`'s
//! documents, the real binary with the test playing main. Main answers the
//! core's `shell.*` requests from scripts: naming's from the `quorum-agree`
//! replay scenario's recordings, chain data's from the documents below.

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
            Wire::Credit => {}
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
